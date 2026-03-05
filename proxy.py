#!/usr/bin/env python3
"""
TEE-Verifying Forward Proxy for NEAR AI Inference

A local HTTP proxy that forwards requests to *.completions.near.ai backends
over TLS, verifying each backend's certificate is bound to an Intel TDX TEE.

On first contact with a backend (or when its cert changes), the proxy runs
full TDX attestation on the SAME connection before sending any client data.
Once verified, the SPKI hash is cached and subsequent requests skip attestation.

Usage:
    python proxy.py [--port 8080] [--host 127.0.0.1]

    # Then use it as your OpenAI base URL:
    curl http://localhost:8080/v1/chat/completions \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $API_KEY" \
      -d '{"model":"zai-org/GLM-5-FP8","messages":[{"role":"user","content":"Hi"}],"max_tokens":16}'
"""

import argparse
import asyncio
import http.client
import json
import logging
import secrets
import ssl
import time
from hashlib import sha256

import aiohttp
import aiohttp.web
import dcap_qvl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("tee-proxy")

# ---------------------------------------------------------------------------
# Endpoint discovery: model name -> *.completions.near.ai domain
# ---------------------------------------------------------------------------

ENDPOINTS_URL = "https://completions.near.ai/endpoints"
ENDPOINTS_TTL = 300  # seconds

_model_to_domain: dict[str, str] = {}
_endpoints_ts: float = 0


async def refresh_endpoints():
    global _model_to_domain, _endpoints_ts
    async with aiohttp.ClientSession() as s:
        async with s.get(ENDPOINTS_URL) as r:
            data = await r.json()
    mapping = {}
    for ep in data.get("endpoints", []):
        for model in ep.get("models", []):
            mapping[model] = ep["domain"]
    _model_to_domain = mapping
    _endpoints_ts = time.monotonic()
    log.info("Loaded %d model→domain mappings", len(mapping))


async def resolve_domain(model: str) -> str:
    if time.monotonic() - _endpoints_ts > ENDPOINTS_TTL:
        await refresh_endpoints()
    domain = _model_to_domain.get(model)
    if not domain:
        raise ValueError(f"Unknown model: {model}")
    return domain


# ---------------------------------------------------------------------------
# SPKI hash computation
# ---------------------------------------------------------------------------

def compute_spki_hash(cert_der: bytes) -> str:
    """SHA-256 of SubjectPublicKeyInfo DER bytes (hex)."""
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki).hexdigest()


# ---------------------------------------------------------------------------
# TEE attestation verification
# ---------------------------------------------------------------------------

_spki_cache: dict[str, set[str]] = {}  # domain -> set of verified SPKI hashes
_verify_locks: dict[str, asyncio.Lock] = {}


async def _verify_attestation(attestation: dict, nonce: str, live_spki: str) -> None:
    """Verify TDX quote and report data bindings. Raises on failure."""
    tls_fp = attestation.get("tls_cert_fingerprint")
    if not tls_fp:
        raise RuntimeError("Attestation missing tls_cert_fingerprint")

    # 1. Verify Intel TDX quote
    quote_bytes = bytes.fromhex(attestation["intel_quote"])
    result = await dcap_qvl.get_collateral_and_verify(quote_bytes)
    result_json = json.loads(result.to_json())
    td10 = result_json["report"]["TD10"]
    report_data = bytes.fromhex(td10["report_data"].removeprefix("0x"))

    # 2. Verify report data binds signing address + TLS fingerprint + nonce
    signing_algo = attestation.get("signing_algo", "ecdsa").lower()
    addr = attestation["signing_address"]
    addr_bytes = bytes.fromhex(addr.removeprefix("0x") if signing_algo == "ecdsa" else addr)
    fp_bytes = bytes.fromhex(tls_fp)

    expected = sha256(addr_bytes + fp_bytes).digest()
    if report_data[:32] != expected:
        raise RuntimeError("Report data does not bind signing address + TLS fingerprint")
    if report_data[32:].hex() != nonce:
        raise RuntimeError("Report data nonce mismatch")

    # 3. Verify live SPKI matches attested fingerprint
    if live_spki != tls_fp:
        raise RuntimeError(f"Live SPKI {live_spki} != attested {tls_fp}")


def _connect(domain: str) -> tuple[http.client.HTTPSConnection, str]:
    """TLS handshake only — no HTTP data sent. Returns (conn, spki_hash)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = http.client.HTTPSConnection(domain, 443, context=ctx, timeout=300)
    conn.connect()

    cert_der = conn.sock.getpeercert(binary_form=True)
    if not cert_der:
        conn.close()
        raise RuntimeError("No certificate from server")

    return conn, compute_spki_hash(cert_der)


def _fetch_attestation(conn: http.client.HTTPSConnection, domain: str, nonce: str) -> dict:
    """Fetch attestation report over an existing connection. No new TLS handshake."""
    path = (
        "/v1/attestation/report"
        f"?include_tls_fingerprint=true&nonce={nonce}&signing_algo=ecdsa"
    )
    conn.request("GET", path, headers={"Host": domain, "Connection": "keep-alive"})
    resp = conn.getresponse()
    body = resp.read()
    if resp.status != 200:
        raise RuntimeError(f"Attestation HTTP {resp.status}: {body.decode()}")
    return json.loads(body)


def _send_request(
    conn: http.client.HTTPSConnection, method: str, path: str,
    headers: dict, body: bytes | None,
) -> tuple[int, dict[str, str], http.client.HTTPResponse]:
    """Send the client's request over an already-verified connection."""
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    return resp.status, dict(resp.getheaders()), resp


def _read_chunk(resp: http.client.HTTPResponse, size: int = 65536) -> bytes:
    """Read up to `size` bytes from the response. Returns b'' at EOF."""
    return resp.read(size)


# ---------------------------------------------------------------------------
# Proxy handler
#
# Request flow on a SINGLE backend connection:
#
#   1. connect()          — TLS handshake, extract SPKI  (no HTTP data sent)
#   2. GET /attestation   — only if SPKI not in cache    (verification data only)
#   3. verify TDX quote   — async, uses dcap-qvl
#   4. request()          — send client's actual request (only after verification)
#   5. stream response    — forward chunks back to client
#
# Using one connection for steps 1-5 guarantees we verify the exact backend
# we're talking to, even with DNS round-robin.
# ---------------------------------------------------------------------------

async def proxy_handler(request: aiohttp.web.Request) -> aiohttp.web.StreamResponse:
    # --- Determine backend domain ---
    domain = request.headers.get("X-Backend-Domain")
    body = await request.read() if request.can_read_body else None

    if not domain:
        if body:
            try:
                model = json.loads(body).get("model", "")
            except (json.JSONDecodeError, AttributeError):
                model = ""
            if model:
                try:
                    domain = await resolve_domain(model)
                except ValueError as e:
                    return aiohttp.web.json_response(
                        {"error": {"message": str(e)}}, status=400
                    )

    if not domain:
        return aiohttp.web.json_response(
            {"error": {"message": "Set X-Backend-Domain header or include model in JSON body"}},
            status=400,
        )

    # --- Phase 1: TLS handshake (no HTTP data sent yet) ---
    try:
        conn, live_spki = await asyncio.to_thread(_connect, domain)
    except Exception as e:
        return aiohttp.web.json_response(
            {"error": {"message": f"Backend connection failed: {e}"}}, status=502
        )

    try:
        # --- Phase 2: Verify SPKI (fetch attestation on same connection if needed) ---
        if live_spki not in _spki_cache.get(domain, set()):
            if domain not in _verify_locks:
                _verify_locks[domain] = asyncio.Lock()

            async with _verify_locks[domain]:
                # Double-check after acquiring lock
                if live_spki not in _spki_cache.get(domain, set()):
                    nonce = secrets.token_hex(32)
                    log.info("Verifying %s (spki=%s…)", domain, live_spki[:16])

                    attestation = await asyncio.to_thread(
                        _fetch_attestation, conn, domain, nonce
                    )
                    await _verify_attestation(attestation, nonce, live_spki)

                    _spki_cache.setdefault(domain, set()).add(live_spki)
                    log.info("Verified  %s (spki=%s…)", domain, live_spki[:16])

        # --- Phase 3: Send client request (only after verification) ---
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "x-backend-domain", "transfer-encoding")
        }
        fwd_headers["Host"] = domain
        if body:
            fwd_headers["Content-Length"] = str(len(body))

        status, resp_headers, backend_resp = await asyncio.to_thread(
            _send_request, conn, request.method, request.path_qs, fwd_headers, body
        )

        # --- Phase 4: Stream response back to client ---
        filtered = {
            k: v for k, v in resp_headers.items()
            if k.lower() not in ("transfer-encoding", "content-encoding", "content-length", "connection")
        }
        response = aiohttp.web.StreamResponse(status=status, headers=filtered)
        await response.prepare(request)

        while True:
            chunk = await asyncio.to_thread(_read_chunk, backend_resp)
            if not chunk:
                break
            await response.write(chunk)

        await response.write_eof()
        return response

    except RuntimeError as e:
        log.warning("Verification failed for %s: %s", domain, e)
        return aiohttp.web.json_response(
            {"error": {"message": f"TEE verification failed for {domain}: {e}"}},
            status=502,
        )
    except Exception as e:
        log.warning("Proxy error for %s: %s", domain, e)
        return aiohttp.web.json_response(
            {"error": {"message": f"Proxy error: {e}"}},
            status=502,
        )
    finally:
        await asyncio.to_thread(conn.close)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="TEE-verifying forward proxy")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    app = aiohttp.web.Application()
    app.router.add_route("*", "/{path_info:.*}", proxy_handler)

    log.info("Listening on http://%s:%d", args.host, args.port)
    log.info("Forwarding to *.completions.near.ai with TEE certificate verification")
    aiohttp.web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
