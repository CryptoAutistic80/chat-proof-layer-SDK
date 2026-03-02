# Proof Layer SDK (PoC)

Rust-first PoC for cryptographically verifiable AI interaction bundles.

## Why This Is Needed

AI systems are increasingly used in workflows where people later need to answer simple but high-stakes questions:

- What exactly did we send to the model?
- What exactly came back?
- Has that record been changed since it was created?
- Can a third party verify this without trusting our server?

Normal logs are useful, but they are not tamper-evident by default. This project adds a proof layer that turns an AI run into a signed evidence package so teams can validate integrity later, including offline.

## How We Achieve It (Plain English)

At a high level, we do four things:

1. Capture the run inputs/outputs and artefacts.
2. Canonicalize and hash that data in a deterministic way.
3. Build a single integrity root (Merkle commitment) and sign it with Ed25519.
4. Package everything into `bundle.pkg` so anyone with the public key can verify it.

That means verification does not depend on trusting this service at verification time. If any byte of header data, artefact data, or signature is changed, verification fails.

## Verification Guarantees

The PoC is built to provide practical integrity guarantees:

- Deterministic canonicalization (RFC 8785 style) for stable hashing across runtimes.
- Strict digest parsing and algorithm checks.
- Tamper detection for header fields, artefact bytes, manifest, and signature.
- Offline verification with only `bundle.pkg` + public key.

What it does **not** claim: model determinism or legal finality. It proves what was captured and sealed in one execution, not that the model would produce the same output again.

## Workspace

- `packages/core-rust` (`proof-layer-core`): canonicalization, hashing, Merkle commitment, Ed25519 JWS sign/verify, bundle build/verify logic.
- `packages/cli` (`proofctl`): keygen, create bundle package, verify package offline, inspect package.
- `packages/proof-service`: Axum service with `sled` metadata storage and local artifact storage.
- `packages/sdk-node`: Node proof client + OpenAI/Anthropic-style wrappers + tool/OTel helpers.
- `packages/sdk-python`: Python proof client + wrappers + decorator + callback/tool/OTel helpers.
- `web-demo`: Vite + React single-page demo UI.
- `examples/`: runnable Node/Python/agent-simulated example scripts.

## Quick Start

```bash
# 1) Generate dev keys
cargo run -p proofctl -- keygen --out ./keys

# 2) Create a capture JSON file (see docs/proof_bundle_schema.md)
# 3) Create a bundle package
cargo run -p proofctl -- create \
  --input ./capture.json \
  --artefact prompt.json=./prompt.json \
  --artefact response.json=./response.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg

# Optional deterministic inputs for reproducible vectors:
# --bundle-id PLFIXED0001 --created-at 2026-03-02T00:00:00Z --signing-kid kid-dev-01

# 4) Verify offline
cargo run -p proofctl -- verify --in ./bundle.pkg --key ./keys/verify.pub

# 5) Inspect
cargo run -p proofctl -- inspect --in ./bundle.pkg --format human
```

## Run Proof Service

```bash
export PROOF_SIGNING_KEY_PATH=./keys/signing.pem
export PROOF_SIGNING_KEY_ID=kid-dev-01
export PROOF_SERVICE_ADDR=0.0.0.0:8080
cargo run -p proof-service
```

Or run with Docker:

```bash
docker compose up --build
```

### Service Endpoints

- `GET /healthz`
- `POST /v1/bundles`
- `GET /v1/bundles/{bundle_id}`
- `GET /v1/bundles/{bundle_id}/artefacts/{name}`
- `POST /v1/verify` (supports inline bundle+artefacts or packaged `bundle.pkg`)

### `POST /v1/bundles` request

```json
{
  "capture": {
    "actor": {
      "issuer": "proof-layer-local",
      "app_id": "demo",
      "env": "dev",
      "signing_key_id": "kid-dev-01"
    },
    "subject": {
      "request_id": "req_123",
      "thread_id": "thr_1",
      "user_ref": "hmac_sha256:abc"
    },
    "model": {
      "provider": "anthropic",
      "model": "claude-sonnet-4-6",
      "parameters": { "temperature": 0.2 }
    },
    "inputs": {
      "messages_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "outputs": {
      "assistant_text_commitment": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    "trace": {
      "otel_genai_semconv_version": "1.0.0",
      "trace_commitment": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "policy": {
      "redactions": [],
      "encryption": { "enabled": false }
    }
  },
  "artefacts": [
    {
      "name": "prompt.json",
      "content_type": "application/json",
      "data_base64": "eyJ0ZXh0IjoiaGVsbG8ifQ=="
    }
  ]
}
```

### `POST /v1/verify` request (inline mode)

```json
{
  "bundle": { "...": "proof_bundle.json contents" },
  "artefacts": [
    { "name": "prompt.json", "data_base64": "..." },
    { "name": "response.json", "data_base64": "..." }
  ],
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n..."
}
```

### `POST /v1/verify` request (package mode)

```json
{
  "bundle_pkg_base64": "<base64 of bundle.pkg bytes>",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n..."
}
```

## SDK And Demo

Run Node SDK tests:

```bash
cd packages/sdk-node
npm install
npm test
```

Run Python SDK tests:

```bash
cd packages/sdk-python
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

Run examples (with proof-service running):

```bash
node examples/node-basic/run.mjs
python3 examples/python-basic/run.py
python3 examples/agent-simulated/run.py
```

Run the web demo:

```bash
cd web-demo
npm install
npm run dev
```

## Notes

- Proof package is gzip-compressed JSON (`bundle.pkg`) containing named files (`proof_bundle.json`, `proof_bundle.canonical.json`, `proof_bundle.sig`, `artefacts/*`, `manifest.json`).
- Canonicalization and signing semantics follow `docs/architecture.md` and `docs/proof_bundle_schema.md`.
- Verification is designed to work offline with `bundle.pkg` + public key.
- JSON Schema: `docs/proof_bundle.schema.json`.
- Test matrix: `docs/verification-test-matrix.md`.
- Deterministic fixture inputs: `fixtures/golden/`.
