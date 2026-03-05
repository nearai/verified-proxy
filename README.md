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

```
Client                     verified-proxy                  *.completions.near.ai (TEE)
  |                             |                                    |
  |-- POST /v1/chat/completions |                                    |
  |   model: GLM-5-FP8         |                                    |
  |                             |-- resolve model → domain           |
  |                             |                                    |
  |                             |== TLS connect (no CA check) ======>|
  |                             |   extract SPKI from cert           |
  |                             |                                    |
  |                             |   SPKI in cache? ─── yes ──> forward request
  |                             |       |                            |
  |                             |       no                           |
  |                             |       |                            |
  |                             |   Single TLS connection:           |
  |                             |   ├─ extract live SPKI hash        |
  |                             |   └─ GET /v1/attestation/report    |
  |                             |                                    |
  |                             |   Verify:                          |
  |                             |   ├─ Intel TDX quote (dcap-qvl)    |
  |                             |   ├─ report_data binds signing     |
  |                             |   │  address + TLS cert + nonce    |
  |                             |   └─ live SPKI == attested SPKI    |
  |                             |                                    |
  |                             |   Cache verified SPKI              |
  |                             |                                    |
  |                             |-- Forward original request ------->|
  |<--- Stream response --------|<--- Stream response ---------------|
```

### What gets verified

| Check | What it proves |
|-------|---------------|
| Intel TDX quote | Attestation comes from genuine Intel TDX hardware |
| Report data binding | The signing key and TLS certificate are bound to this specific TEE |
| SPKI match | The live TLS connection terminates inside the TEE |
| Nonce | The attestation is fresh (not replayed) |

### When re-verification happens

- **First request** to a backend — full attestation (~5-10 seconds)
- **Certificate rotation** — detected automatically, triggers re-attestation
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
