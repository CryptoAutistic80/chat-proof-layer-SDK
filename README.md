# Proof Layer SDK

Rust-first SDK and service for cryptographically verifiable AI interaction evidence bundles.

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

The current implementation provides practical integrity guarantees:

- Deterministic canonicalization (RFC 8785 style) for stable hashing across runtimes.
- Strict digest parsing and algorithm checks.
- Tamper detection for header fields, artefact bytes, manifest, and signature.
- Offline verification with only `bundle.pkg` + public key.

What it does **not** claim: model determinism or legal finality. It proves what was captured and sealed in one execution, not that the model would produce the same output again.

## Workspace

- `crates/core` (`proof-layer-core`): RFC 8785 canonicalization, hashing, Merkle commitment + inclusion proofs, Ed25519 JWS sign/verify, v1.0 evidence bundle build/verify logic, and v0.1 -> v1.0 migration helpers.
- `crates/cli` (`proofctl`): keygen, create bundle package, verify package offline, inspect package, query vault state, and download vault-assembled evidence packs.
- `crates/vault` (`proof-service`): Axum service with SQLite metadata storage, retention scanning, pack assembly, and local artifact storage.
- `crates/napi` (`proof-layer-napi`): native TypeScript/Node bridge over the Rust core for canonicalization, hashing, Merkle root computation, JWS sign/verify, and offline bundle verification.
- `crates/pyo3` (`proof-layer-pyo3`): native Python bridge over the Rust core for the same canonicalization, hashing, Merkle root, JWS sign/verify, and offline bundle verification surface.
- `sdks/typescript`: the TypeScript npm SDK package (`@proof-layer/sdk`), with shared v1 evidence helpers, `ProofLayer`, vault/local sealing clients, typed builders for all evidence items currently implemented in Rust core (`llm_interaction`, `tool_call`, `retrieval`, `human_oversight`, `policy_decision`, `risk_assessment`, `data_governance`, `technical_doc`), provider wrappers, generic/Vercel AI adapters, and tool/OTel helpers over the Rust NAPI module.
- `packages/sdk-python`: Python vault client, local sealing client, wrappers, decorator, and callback/tool/OTel helpers, backed by the Rust PyO3 module for integrity-sensitive operations.
- `web-demo`: Vite + React single-page demo UI.
- `examples/`: runnable TypeScript/Python/agent-simulated example scripts.

## Quick Start

```bash
# 1) Generate dev keys
cargo run -p proofctl -- keygen --out ./keys

# 2) Create a capture JSON file.
#    `proofctl create` accepts either the legacy PoC capture shape or the v1.0 `CaptureEvent` shape.
# 3) Create a bundle package
cargo run -p proofctl -- create \
  --input ./capture.json \
  --artefact prompt.json=./prompt.json \
  --artefact response.json=./response.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg

# Optional deterministic inputs for reproducible vectors:
# --bundle-id PLFIXED0001 --created-at 2026-03-02T00:00:00Z --signing-kid kid-dev-01
# Optional v1 override flags during migration:
# --system-id system-123 --retention-class runtime_logs --evidence-type llm_interaction

# 4) Verify offline
cargo run -p proofctl -- verify --in ./bundle.pkg --key ./keys/verify.pub

# 5) Inspect
cargo run -p proofctl -- inspect --in ./bundle.pkg --format human

# Richer inspect output
cargo run -p proofctl -- inspect --in ./bundle.pkg --show-items --show-merkle

# Assemble and download a vault export pack
cargo run -p proofctl -- pack \
  --type runtime-logs \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./runtime-logs.pack

# Query vault bundle inventory
cargo run -p proofctl -- vault query \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --has-receipt

# Show a system summary
cargo run -p proofctl -- vault systems \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123
```

## Run Proof Service

```bash
# Optional: copy and edit the sample file first.
cp ./vault.toml.example ./vault.toml

# `proof-service` auto-loads `./vault.toml` when present.
# Env vars still override file settings.
export PROOF_SIGNING_KEY_PATH=./keys/signing.pem
cargo run -p proof-service
```

Or run with Docker:

```bash
docker compose up --build
```

Supported runtime config knobs:

- `vault.toml` sections: `[server]`, `[signing]`, `[storage]`, `[timestamp]`, `[transparency]`, `[retention]`, and `[[retention.policies]]`
- `PROOF_SERVICE_CONFIG_PATH=/path/to/vault.toml` to point at a non-default file
- env overrides for `PROOF_SERVICE_ADDR`, `PROOF_SERVICE_STORAGE_DIR`, `PROOF_SERVICE_DB_PATH`, `PROOF_SIGNING_KEY_PATH`, `PROOF_SIGNING_KEY_ID`, `PROOF_SERVICE_MAX_PAYLOAD_BYTES`, `PROOF_SERVICE_RETENTION_GRACE_DAYS`, and `PROOF_SERVICE_RETENTION_SCAN_INTERVAL_HOURS`

Current file-config limitations:

- `signing.algorithm` must be `ed25519`
- `storage.metadata_backend` must be `sqlite`
- `storage.blob_backend` must be `filesystem`
- TLS, PostgreSQL, and S3 config are parsed but fail fast as not implemented

### Service Endpoints

- `GET /healthz`
- `GET /readyz`
- `POST /v1/bundles`
- `GET /v1/bundles?system_id=&role=&type=&has_timestamp=&has_receipt=&assurance_level=&from=&to=&page=&limit=`
- `GET /v1/bundles/{bundle_id}`
- `DELETE /v1/bundles/{bundle_id}`
- `GET /v1/bundles/{bundle_id}/artefacts/{name}`
- `POST /v1/bundles/{bundle_id}/legal-hold`
- `DELETE /v1/bundles/{bundle_id}/legal-hold`
- `POST /v1/bundles/{bundle_id}/timestamp`
- `POST /v1/bundles/{bundle_id}/anchor`
- `GET /v1/audit-trail?action=&bundle_id=&pack_id=&page=&limit=`
- `GET /v1/config`
- `PUT /v1/config/retention`
- `PUT /v1/config/timestamp`
- `PUT /v1/config/transparency`
- `GET /v1/systems`
- `GET /v1/systems/{system_id}/summary`
- `POST /v1/packs`
- `GET /v1/packs/{pack_id}`
- `GET /v1/packs/{pack_id}/manifest`
- `GET /v1/packs/{pack_id}/export`
- `GET /v1/retention/status`
- `POST /v1/retention/scan`
- `POST /v1/verify` (supports inline bundle+artefacts or packaged `bundle.pkg`)
- `POST /v1/verify/timestamp`
- `POST /v1/verify/receipt`

### `POST /v1/bundles` request

```json
{
  "capture": {
    "actor": {
      "issuer": "proof-layer-local",
      "app_id": "demo",
      "env": "dev",
      "signing_key_id": "kid-dev-01",
      "role": "provider"
    },
    "subject": {
      "request_id": "req_123",
      "thread_id": "thr_1",
      "user_ref": "hmac_sha256:abc",
      "model_id": "anthropic:claude-sonnet-4-6"
    },
    "context": {
      "provider": "anthropic",
      "model": "claude-sonnet-4-6",
      "parameters": { "temperature": 0.2 },
      "trace_commitment": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "otel_genai_semconv_version": "1.0.0"
    },
    "items": [
      {
        "type": "llm_interaction",
        "data": {
          "provider": "anthropic",
          "model": "claude-sonnet-4-6",
          "parameters": { "temperature": 0.2 },
          "input_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "output_commitment": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "trace_commitment": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "trace_semconv_version": "1.0.0"
        }
      }
    ],
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

Run TypeScript SDK tests:

```bash
cd sdks/typescript
npm install
npm test
```

Run Python SDK tests:

```bash
cd packages/sdk-python
python3 ./scripts/build_native.py
python -m unittest discover -s tests -v
```

Run examples (with proof-service running):

```bash
node examples/typescript/run.mjs
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
- Bundles now serialize as `bundle_version: "1.0"` with typed `items` plus `context`.
- `proofctl create` and `POST /v1/bundles` accept either the legacy PoC capture shape or the v1.0 capture shape during migration.
- `proofctl create` also supports Phase 2 migration overrides such as `--system-id`, `--retention-class`, and `--evidence-type`.
- `proofctl create` now supports `--timestamp-url <tsa>` and can attach an RFC 3161 token before packaging.
- `proofctl create --transparency-log <rekor>` now anchors the RFC 3161 token into Rekor before packaging; this currently requires `--timestamp-url`.
- `proofctl verify --check-timestamp` now validates RFC 3161 tokens against the UTF-8 bytes of `integrity.bundle_root`, and `--check-receipt` now validates Rekor RFC 3161 receipts against the same bundle root.
- `proofctl verify` now reports the bundle assurance level as `signed`, `timestamped`, or `transparency_anchored`.
- `proofctl inspect` now supports `--show-items` and `--show-merkle`.
- `proofctl pack` now requests pack assembly from the vault and downloads the resulting `pl-evidence-pack-v1` archive.
- `proofctl vault status|query|retention|systems|export` now covers the main vault read/query/export flows from the plan without requiring manual `curl`.
- The vault now persists metadata in SQLite, computes bundle expiry from seeded retention policies, derives per-item `obligation_ref` tags, exposes retention scan/status endpoints, supports legal holds, and indexes evidence items for `/v1/bundles` filtering.
- The vault now exposes `GET /v1/systems` and `GET /v1/systems/{system_id}/summary` for system-level evidence rollups across role, item type, retention class, assurance level, and model usage.
- `/v1/bundles` now also supports assurance-oriented filtering through `has_timestamp`, `has_receipt`, and `assurance_level=signed|timestamped|transparency_anchored`, and bundle summaries now report the computed assurance level.
- Retention scans now soft-delete expired bundles, skip held bundles, and hard-delete previously soft-deleted bundles after the configured grace period (`PROOF_SERVICE_RETENTION_GRACE_DAYS`, default `30`).
- The vault now keeps an append-only audit trail and exposes it via `/v1/audit-trail`; current actions include bundle create/read/verify/delete, legal hold changes, retention scans, and pack create/read/export events.
- The vault now exposes `GET /v1/config`, `PUT /v1/config/retention`, `PUT /v1/config/timestamp`, and `PUT /v1/config/transparency`; retention, timestamp, and transparency settings are persisted in SQLite, and active-bundle `expires_at` values are recalculated for updated active retention classes.
- `POST /v1/bundles/{bundle_id}/timestamp` now uses the configured RFC 3161 provider to timestamp an existing stored bundle and persist the token back into bundle JSON.
- `POST /v1/bundles/{bundle_id}/anchor` now uses the configured Rekor provider to anchor an existing timestamped bundle and persist the receipt back into bundle JSON; `scitt` remains a stubbed provider choice.
- `POST /v1/verify/timestamp` and `POST /v1/verify/receipt` now verify assurance artefacts either directly (`bundle_root` + token/receipt) or by stored `bundle_id`.
- Timestamp verification currently checks CMS signature integrity and message-imprint binding, but it does not yet validate TSA certificate chains, revocation, or qualified/eIDAS trust status.
- Transparency verification currently checks Rekor receipt structure, entry UUID to leaf-hash binding, the Merkle inclusion proof against the advertised Rekor root hash, and the embedded RFC 3161 token binding to `integrity.bundle_root`, but it does not yet verify Rekor signed-entry-timestamp signatures.
- Pack assembly is now available through `/v1/packs`; packs apply an initial heuristic curation profile (`pack-rules-v1`) based on actor role, evidence item types, retention class, and derived obligation refs, then export matching bundles as embedded `bundle.pkg` files plus a manifest.
- Pack redaction/selective disclosure is still not implemented; current exports remain full bundle packages.
- Vault startup now supports `vault.toml` + env override configuration and an automatic background retention scan loop; PostgreSQL/S3/TLS remain future work.
- Canonicalization and signing semantics follow `docs/architecture.md`.
- Verification is designed to work offline with `bundle.pkg` + public key.
- JSON Schemas: `schemas/evidence_bundle.schema.json`, `schemas/capture_event.schema.json`, `schemas/evidence_item.schema.json`, `schemas/evidence_pack.schema.json`.
- Test matrix: `docs/verification-test-matrix.md`.
- Deterministic fixture inputs: `fixtures/golden/`.
