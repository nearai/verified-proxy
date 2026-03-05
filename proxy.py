#!/usr/bin/env python3
"""
TEE-Verifying Forward Proxy for NEAR AI Inference

A local HTTP proxy that forwards requests to *.completions.near.ai backends
over TLS, verifying each backend's certificate is bound to an Intel TDX TEE.

On first contact with a backend (or when its cert changes), the proxy runs
full TDX attestation. Once verified, the SPKI hash is cached and subsequent
requests just compare the live cert against the cache.

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

_spki_cache: dict[str, str] = {}  # domain -> verified SPKI hash
_verify_locks: dict[str, asyncio.Lock] = {}


def _fetch_attestation_and_spki(
    hostname: str, port: int, nonce: str
) -> tuple[dict, str]:
    """Single TLS connection: extract live SPKI + fetch attestation report."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = http.client.HTTPSConnection(hostname, port, context=ctx, timeout=60)
    conn.connect()

    cert_der = conn.sock.getpeercert(binary_form=True)
    if not cert_der:
        conn.close()
        raise RuntimeError("No certificate from server")
    live_spki = compute_spki_hash(cert_der)

    path = (
        "/v1/attestation/report"
        f"?include_tls_fingerprint=true&nonce={nonce}&signing_algo=ecdsa"
    )
    conn.request("GET", path, headers={"Host": hostname})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    if resp.status != 200:
        raise RuntimeError(f"Attestation HTTP {resp.status}: {body.decode()}")

    return json.loads(body), live_spki


async def verify_backend(domain: str) -> str:
    """Run full TDX attestation for a backend. Returns verified SPKI hash."""
    nonce = secrets.token_hex(32)

    attestation, live_spki = await asyncio.to_thread(
        _fetch_attestation_and_spki, domain, 443, nonce
    )

    tls_fp = attestation.get("tls_cert_fingerprint")
    if not tls_fp:
        raise RuntimeError("Attestation missing tls_cert_fingerprint")

    # 1. Verify Intel TDX quote
    quote_bytes = bytes.fromhex(attestation["intel_quote"])
    result = await dcap_qvl.get_collateral_and_verify(quote_bytes)
    result_json = json.loads(result.to_json())
    td10 = result_json["report"]["TD10"]
    report_data_hex = td10["report_data"]

    # 2. Verify report data binds signing address + TLS fingerprint + nonce
    report_data = bytes.fromhex(report_data_hex.removeprefix("0x"))

    signing_algo = attestation.get("signing_algo", "ecdsa").lower()
    addr = attestation["signing_address"]
    addr_bytes = bytes.fromhex(addr.removeprefix("0x") if signing_algo == "ecdsa" else addr)
    fp_bytes = bytes.fromhex(tls_fp)

    expected_hash = sha256(addr_bytes + fp_bytes).digest()
    if report_data[:32] != expected_hash:
        raise RuntimeError("Report data does not bind signing address + TLS fingerprint")
    if report_data[32:].hex() != nonce:
        raise RuntimeError("Report data nonce mismatch")

    # 3. Verify live SPKI matches attested fingerprint
    if live_spki != tls_fp:
        raise RuntimeError(f"Live SPKI {live_spki} != attested {tls_fp}")

    log.info("Verified %s  spki=%s…", domain, live_spki[:16])
    return live_spki


async def ensure_verified(domain: str, live_spki: str) -> None:
    """Check cache or run attestation. Raises on failure."""
    if _spki_cache.get(domain) == live_spki:
        return

    if domain not in _verify_locks:
        _verify_locks[domain] = asyncio.Lock()

    async with _verify_locks[domain]:
        # Double-check after lock
        if _spki_cache.get(domain) == live_spki:
            return
        verified = await verify_backend(domain)
        if verified != live_spki:
            raise RuntimeError(
                f"Verified SPKI {verified} doesn't match connection SPKI {live_spki}"
            )
        _spki_cache[domain] = verified


# ---------------------------------------------------------------------------
# Proxy handler
# ---------------------------------------------------------------------------

_backend_ssl = ssl.create_default_context()
_backend_ssl.check_hostname = False
_backend_ssl.verify_mode = ssl.CERT_NONE


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

    # --- Forward request to backend ---
    url = f"https://{domain}{request.path_qs}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    headers["Host"] = domain
    headers.pop("X-Backend-Domain", None)

    connector = aiohttp.TCPConnector(ssl=_backend_ssl)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request(
                request.method, url, headers=headers, data=body, timeout=aiohttp.ClientTimeout(total=300),
            ) as backend_resp:
                # --- Extract live SPKI from TLS connection ---
                transport = backend_resp.connection.transport
                ssl_obj = transport.get_extra_info("ssl_object")
                cert_der = ssl_obj.getpeercert(binary_form=True)
                live_spki = compute_spki_hash(cert_der)

                # --- Verify TEE attestation if SPKI is new ---
                await ensure_verified(domain, live_spki)

                # --- Stream response back to client ---
                resp = aiohttp.web.StreamResponse(
                    status=backend_resp.status,
                    headers={
                        k: v
                        for k, v in backend_resp.headers.items()
                        if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
                    },
                )
                await resp.prepare(request)
                async for chunk in backend_resp.content.iter_any():
                    await resp.write(chunk)
                await resp.write_eof()
                return resp
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
