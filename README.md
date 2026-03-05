# verified-proxy

A local forward proxy that verifies NEAR AI inference backends are running inside Intel TDX Trusted Execution Environments (TEEs) before forwarding your requests.

## What it does

When you send a request through the proxy, it:

1. Resolves the model name to a `*.completions.near.ai` backend domain
2. Connects to the backend over TLS and extracts the certificate's SPKI hash
3. If the SPKI hash is new (first request or cert rotation), runs **full TEE attestation**:
   - Fetches an attestation report from the backend (single TLS connection)
   - Verifies the Intel TDX quote using `dcap-qvl`
   - Checks that the TDX report data cryptographically binds the signing key and TLS certificate to the TEE
   - Confirms the live certificate matches the attested fingerprint
4. Caches the verified SPKI hash — subsequent requests skip attestation
5. Forwards the request and streams the response back

Trust comes from Intel TDX hardware attestation, not from Certificate Authority trust chains.

## Quick start

```bash
pip install -r requirements.txt
python proxy.py
```

Then point any OpenAI-compatible client at `http://localhost:8080`:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{
    "model": "zai-org/GLM-5-FP8",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 64
  }'
```

### Python (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-api-key",
)

response = client.chat.completions.create(
    model="zai-org/GLM-5-FP8",
    messages=[{"role": "user", "content": "Hello"}],
    max_tokens=64,
)
print(response.choices[0].message.content)
```

## How routing works

The proxy determines which backend to forward to in two ways:

1. **Model name** (default) — Parses the `model` field from the JSON request body and looks up the corresponding `*.completions.near.ai` domain via the public endpoint discovery API (`GET https://completions.near.ai/endpoints`).

2. **Explicit domain** — Set the `X-Backend-Domain` header to target a specific backend directly:
   ```bash
   curl http://localhost:8080/v1/chat/completions \
     -H "X-Backend-Domain: glm-5.completions.near.ai" \
     -H "Content-Type: application/json" \
     -d '{"model": "zai-org/GLM-5-FP8", "messages": [{"role": "user", "content": "Hi"}]}'
   ```

All paths are forwarded transparently (`/v1/chat/completions`, `/v1/models`, etc.).

## How verification works

All steps happen on a **single TCP connection** to the backend. This guarantees verification and request forwarding target the exact same server (no DNS round-robin mismatch), and that **no client data is sent before verification completes**.

```
Client                     verified-proxy                  *.completions.near.ai (TEE)
  |                             |                                    |
  |-- POST /v1/chat/completions |                                    |
  |   model: GLM-5-FP8         |                                    |
  |                             |-- resolve model → domain           |
  |                             |                                    |
  |                             |== TLS handshake ==================>|
  |                             |   (no HTTP data sent yet)          |
  |                             |   extract SPKI from cert           |
  |                             |                                    |
  |                             |   SPKI in cache?                   |
  |                             |   ├─ yes → skip to step 4          |
  |                             |   └─ no  → verify on same conn:    |
  |                             |                                    |
  |                             |-- GET /attestation/report -------->|
  |                             |<-- attestation JSON ---------------|
  |                             |                                    |
  |                             |   Verify (local, no network):      |
  |                             |   ├─ Intel TDX quote (dcap-qvl)    |
  |                             |   ├─ report_data binds signing     |
  |                             |   │  address + TLS cert + nonce    |
  |                             |   └─ live SPKI == attested SPKI    |
  |                             |   Cache verified SPKI              |
  |                             |                                    |
  |                             |-- Forward client request --------->|
  |                             |   (only after verification)        |
  |<--- Stream response --------|<--- Stream response ---------------|
```

### What gets verified

| Check | What it proves |
|-------|---------------|
| Intel TDX quote | Attestation comes from genuine Intel TDX hardware |
| Report data binding | The signing key and TLS certificate are bound to this specific TEE |
| SPKI match | The live TLS connection terminates inside the TEE |
| Nonce | The attestation is fresh (not replayed) |

### Security guarantee

**No client data is sent before verification.** The proxy uses `http.client.HTTPSConnection` which separates TLS handshake (`connect()`) from HTTP request sending (`request()`). The sequence is:

1. `connect()` — TLS handshake completes, certificate is available
2. Extract SPKI hash from the certificate
3. If uncached: `GET /v1/attestation/report` on the same connection → full TDX verification
4. Only after verification: `request()` sends the client's actual HTTP request

Steps 1-4 all happen on the same TCP connection, so there is no possibility of DNS round-robin routing you to a different (unverified) backend between verification and request.

### When re-verification happens

- **First request** to a backend — full attestation (~5-10 seconds)
- **Certificate rotation** — new SPKI detected, triggers re-attestation on the same connection
- **DNS round-robin** — each unique backend SPKI is verified and cached independently
- **Cached SPKI match** — no attestation needed, request forwarded immediately

## CLI options

```
python proxy.py [--port PORT] [--host HOST]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--host` | `127.0.0.1` | Address to bind to |

## Requirements

- Python 3.11+
- `aiohttp` — HTTP server and client
- `dcap-qvl` — Intel TDX quote verification
- `cryptography` — X.509 certificate parsing and SPKI hash computation
