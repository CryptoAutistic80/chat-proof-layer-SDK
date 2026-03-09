# Proof Layer SDK

Rust-first SDK and evidence vault for tamper-evident AI interaction records.

Proof Layer turns an AI run into a signed, portable evidence package that can be verified later, including offline. It is built for teams that need more than ordinary logs: auditability, selective disclosure, retention controls, and cryptographic verification of what was captured.

## What This Project Does

- Captures AI interaction evidence as typed `CaptureEvent` / `EvidenceBundle` data.
- Canonicalizes and hashes that data deterministically.
- Builds a Merkle commitment over bundle content and signs the bundle root with Ed25519.
- Packages the result as `bundle.pkg` for offline verification.
- Supports RFC 3161 timestamping and transparency anchoring.
- Supports selective disclosure with verifiable redacted packages.
- Provides a vault service for storage, retention, audit, export packs, backup, and restore.
- Exposes native TypeScript and Python SDKs over the Rust core.

## What Works Today

Current implemented surface:

- Rust core for canonicalization, hashing, signing, verification, timestamping, transparency, disclosure, and backup-envelope crypto.
- `proofctl` CLI for keygen, create, verify, inspect, disclose, vault query/export/backup/restore flows.
- `proof-service` vault with SQLite storage, filesystem blobs, TLS, bearer auth, single-tenant enforcement, retention, legal holds, audit log, metrics, backup, restore layout export, and pack assembly.
- TypeScript SDK in `sdks/typescript` published as `@proof-layer/sdk`.
- Python SDK in `packages/sdk-python` published as `proof-layer-sdk-python`.
- Web demo in `web-demo` aligned to the live vault API.

Important current limits:

- PostgreSQL and S3 are parsed in config but not implemented.
- Full EU trusted-list / archival eIDAS trust evaluation is not implemented yet.
- SCITT is a bounded draft-aligned implementation, not full COSE/CCF interoperability.
- Multitenancy is bounded single-tenant enforcement today, not a full multi-org isolation model.

## Why This Exists

Normal logs answer "what happened?" but not "can an independent party verify this record was not changed?"

This project is for cases where those questions matter:

- What exactly was sent to the model?
- What exactly came back?
- Which supporting artefacts were part of that run?
- Has the record changed since it was sealed?
- Can a third party verify the record without trusting our server?

Proof Layer does not claim model determinism or legal finality. It proves what was captured and sealed for one execution.

## Architecture At A Glance

| Layer | Path | Purpose |
| --- | --- | --- |
| Core | `crates/core` | Canonicalization, hashing, Merkle commitments, signing, verification, timestamping, transparency, disclosure |
| CLI | `crates/cli` | `proofctl` create/verify/disclose/inspect plus vault operations |
| Vault | `crates/vault` | `proof-service` with SQLite metadata, local blob storage, retention, audit, packs, backup |
| TypeScript bridge | `crates/napi` | Native N-API bindings over the Rust core |
| Python bridge | `crates/pyo3` | Native PyO3 bindings over the Rust core |
| TS SDK | `sdks/typescript` | `@proof-layer/sdk`, local/vault clients, providers, evidence helpers, OTel helpers |
| Python SDK | `packages/sdk-python` | `proof-layer-sdk-python`, local/vault clients, providers, decorators, helpers |
| Demo | `web-demo` | Vite + React demo against the vault API |

## Evidence And Assurance Model

Evidence currently implemented in core and SDKs includes:

- `llm_interaction`
- `tool_call`
- `retrieval`
- `human_oversight`
- `policy_decision`
- `risk_assessment`
- `data_governance`
- `technical_doc`
- `model_evaluation`
- `adversarial_test`
- `training_provenance`
- `literacy_attestation`
- `incident_report`
- `conformity_assessment`
- `declaration`
- `registration`

Assurance levels:

- `signed`
- `timestamped`
- `transparency_anchored`

Bundle root algorithms:

- New bundles default to `pl-merkle-sha256-v4`
- Verification still accepts legacy `pl-merkle-sha256-v1`, `pl-merkle-sha256-v2`, and `pl-merkle-sha256-v3`

Selective disclosure:

- Full bundles are packaged as `bundle.pkg`
- Redacted bundles are packaged as `pl-bundle-disclosure-pkg-v1`
- Disclosure supports item-level selection, optional artefact inclusion, top-level field redaction, and nested JSON-pointer path redaction on v4 bundles

## Quick Start

### 1. Prerequisites

- Rust toolchain
- Node 20+ for the TypeScript SDK and demo
- Python 3.10+ for the Python SDK

### 2. Build A Bundle Offline

```bash
# Generate a dev signing keypair
cargo run -p proofctl -- keygen --out ./keys

# Create a bundle package from capture + artefacts
cargo run -p proofctl -- create \
  --input ./capture.json \
  --artefact prompt.json=./prompt.json \
  --artefact response.json=./response.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg

# Verify offline
cargo run -p proofctl -- verify --in ./bundle.pkg --key ./keys/verify.pub

# Produce a selective-disclosure package for item 0
cargo run -p proofctl -- disclose \
  --in ./bundle.pkg \
  --items 0 \
  --out ./bundle.disclosure.pkg

# Verify the redacted package
cargo run -p proofctl -- verify --in ./bundle.disclosure.pkg --key ./keys/verify.pub
```

Notes:

- `proofctl create` accepts both the legacy PoC capture shape and the current v1.0 `CaptureEvent` shape.
- Migration overrides are available, for example `--system-id`, `--retention-class`, and `--evidence-type`.
- Deterministic fixture inputs live under `fixtures/golden/`.

### 3. Optional Trust-Aware Assurance

Attach timestamp + transparency during create:

```bash
cargo run -p proofctl -- create \
  --input ./capture.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg \
  --timestamp-url http://timestamp.digicert.com \
  --timestamp-assurance qualified \
  --timestamp-policy-oid 1.2.3.4 \
  --timestamp-trust-anchor ./tsa-root.pem \
  --timestamp-crl ./tsa.crl.pem \
  --timestamp-ocsp-url http://ocsp.example.test \
  --timestamp-qualified-signer ./tsa-signer.pem \
  --transparency-log https://rekor.sigstore.dev \
  --transparency-public-key ./rekor.pub
```

Verify with assurance checks:

```bash
cargo run -p proofctl -- verify \
  --in ./bundle.pkg \
  --key ./keys/verify.pub \
  --check-timestamp \
  --timestamp-assurance qualified \
  --timestamp-trust-anchor ./tsa-root.pem \
  --timestamp-crl ./tsa.crl.pem \
  --timestamp-ocsp-url http://ocsp.example.test \
  --timestamp-qualified-signer ./tsa-signer.pem \
  --timestamp-policy-oid 1.2.3.4 \
  --check-receipt \
  --transparency-public-key ./rekor.pub
```

### 4. Run The Vault

```bash
cp ./vault.toml.example ./vault.toml
export PROOF_SIGNING_KEY_PATH=./keys/signing.pem
cargo run -p proof-service
```

Or with Docker:

```bash
docker compose up --build
```

The service auto-loads `./vault.toml` when present. Environment variables still override file settings.

### 5. Query, Export, And Backup Through The CLI

```bash
# Inspect a bundle
cargo run -p proofctl -- inspect --in ./bundle.pkg --show-items --show-merkle

# Query vault bundles
cargo run -p proofctl -- vault query \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123

# Export a full pack
cargo run -p proofctl -- pack \
  --type runtime-logs \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./runtime-logs.pack

# Export a disclosure-format pack using a built-in policy
cargo run -p proofctl -- pack \
  --type runtime-logs \
  --bundle-format disclosure \
  --disclosure-policy regulator_minimum \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./runtime-logs-disclosure.pack

# Preview disclosure selection before export
cargo run -p proofctl -- vault disclosure-preview \
  --vault-url http://127.0.0.1:8080 \
  --bundle-id BUNDLE_ID \
  --type runtime-logs \
  --disclosure-template-profile privacy_review \
  --disclosure-template-name privacy_review_internal \
  --disclosure-group metadata

# Download a backup
cargo run -p proofctl -- vault backup \
  --vault-url http://127.0.0.1:8080 \
  --out ./vault-backup.tar.gz

# Restore a backup layout offline
cargo run -p proofctl -- vault restore \
  --in ./vault-backup.tar.gz \
  --out-dir ./restored-vault
```

## Vault Service

### Runtime Capabilities

- SQLite metadata backend
- Filesystem blob backend
- Optional HTTPS via PEM cert/key
- Optional bearer auth for `/v1/*`
- Optional bounded single-tenant enforcement
- Retention policies, legal holds, soft-delete, grace-period hard-delete
- Audit trail
- Prometheus-style `/metrics`
- Scheduled local backups with optional XChaCha20-Poly1305 envelope encryption
- Offline restore layout via `proofctl vault restore`

### Main Config Sections

`vault.toml` supports:

- `[server]`
- `[auth]` and `[[auth.api_keys]]`
- `[tenant]`
- `[signing]`
- `[storage]`
- `[backup]` and `[backup.encryption]`
- `[timestamp]`
- `[transparency]`
- `[retention]` and `[[retention.policies]]`

Useful environment overrides:

- `PROOF_SERVICE_CONFIG_PATH`
- `PROOF_SERVICE_ADDR`
- `PROOF_SERVICE_TLS_CERT_PATH`
- `PROOF_SERVICE_TLS_KEY_PATH`
- `PROOF_SERVICE_API_KEY`
- `PROOF_SERVICE_API_KEY_LABEL`
- `PROOF_SERVICE_ORGANIZATION_ID`
- `PROOF_SERVICE_DB_PATH`
- `PROOF_SERVICE_STORAGE_DIR`
- `PROOF_SERVICE_BACKUP_DIR`
- `PROOF_SERVICE_BACKUP_INTERVAL_HOURS`
- `PROOF_SERVICE_BACKUP_RETENTION_COUNT`
- `PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_B64`
- `PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_PATH`
- `PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_ID`
- `PROOF_SIGNING_KEY_PATH`
- `PROOF_SIGNING_KEY_ID`

Current backend limits:

- `signing.algorithm` must be `ed25519`
- `storage.metadata_backend` must be `sqlite`
- `storage.blob_backend` must be `filesystem`
- PostgreSQL and S3 config currently fail fast as not implemented

Operational behavior:

- When auth is enabled, `/v1/*` requires `Authorization: Bearer <token>`.
- `proofctl` picks up the bearer token from `PROOF_SERVICE_API_KEY`.
- `/healthz`, `/readyz`, and `/metrics` stay open for infrastructure checks and scraping.
- When `organization_id` is configured, the vault runs in bounded single-tenant mode and rejects bundle writes scoped to a different org.

### Main Endpoints

Health and ops:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /v1/config`
- `PUT /v1/config/retention`
- `PUT /v1/config/timestamp`
- `PUT /v1/config/transparency`
- `PUT /v1/config/disclosure`
- `GET /v1/audit-trail`
- `GET /v1/retention/status`
- `POST /v1/retention/scan`
- `POST /v1/backup`

Bundles and assurance:

- `POST /v1/bundles`
- `GET /v1/bundles`
- `GET /v1/bundles/{bundle_id}`
- `DELETE /v1/bundles/{bundle_id}`
- `GET /v1/bundles/{bundle_id}/artefacts/{name}`
- `POST /v1/bundles/{bundle_id}/legal-hold`
- `DELETE /v1/bundles/{bundle_id}/legal-hold`
- `POST /v1/bundles/{bundle_id}/timestamp`
- `POST /v1/bundles/{bundle_id}/anchor`
- `POST /v1/verify`
- `POST /v1/verify/timestamp`
- `POST /v1/verify/receipt`

Disclosure and packs:

- `POST /v1/disclosure/preview`
- `GET /v1/disclosure/templates`
- `POST /v1/disclosure/templates/render`
- `POST /v1/packs`
- `GET /v1/packs/{pack_id}`
- `GET /v1/packs/{pack_id}/manifest`
- `GET /v1/packs/{pack_id}/export`

System rollups:

- `GET /v1/systems`
- `GET /v1/systems/{system_id}/summary`

### Example API Payloads

`POST /v1/bundles`

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

`POST /v1/verify` using a packaged bundle:

```json
{
  "bundle_pkg_base64": "<base64 of bundle.pkg bytes>",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n..."
}
```

## SDKs

### TypeScript

Path: `sdks/typescript`

- Package name: `@proof-layer/sdk`
- Native Rust-backed N-API module
- Local and vault clients
- `ProofLayer` facade
- Provider wrappers for OpenAI, Anthropic, generic, and Vercel AI style flows
- Evidence builders, disclosure-policy helpers, and OTel helpers

Basic loop:

```bash
cd sdks/typescript
npm install
npm test
```

Build a checked tarball:

```bash
npm run pack:smoke
```

### Python

Path: `packages/sdk-python`

- Package name: `proof-layer-sdk-python`
- Native Rust-backed PyO3 module
- Local and vault clients
- `ProofLayer` facade
- Provider wrappers, decorators, disclosure-policy helpers, and OTel helpers

Basic loop:

```bash
cd packages/sdk-python
python3 ./scripts/build_native.py
python -m unittest discover -s tests -v
```

Build a checked wheel:

```bash
python3 ./scripts/build_dist.py
```

### Unified SDK Artifact Build

```bash
python3 ./scripts/build_sdk_artifacts.py --profile release
```

This produces:

- a checked npm tarball at `sdks/typescript/dist/artifacts/*.tgz`
- a checked platform-tagged wheel at `packages/sdk-python/dist/*.whl`

GitHub Actions builds the same artifacts through:

- `.github/workflows/sdk-artifacts.yml`
- `.github/workflows/sdk-release.yml`

## Demo And Examples

Examples:

- `node examples/typescript/run.mjs`
- `python3 examples/python-basic/run.py`
- `python3 examples/agent-simulated/run.py`

Web demo:

```bash
cd web-demo
npm install
npm run dev
```

The demo now uses the live vault API rather than the old PoC simulator. It can:

- read `/v1/config` and `/v1/disclosure/templates`
- create a real `llm_interaction` bundle through `POST /v1/bundles`
- optionally timestamp and anchor that bundle
- preview disclosure output
- export full or disclosure-format packs
- fetch system summaries
- verify through `POST /v1/verify` when given a public key PEM

## Docs Map

- [Architecture](docs/architecture.md)
- [Proof Bundle Schema](docs/proof_bundle_schema.md)
- [Threat Model](docs/threat_model.md)
- [Verification Test Matrix](docs/verification-test-matrix.md)
- [Golden Fixtures](fixtures/golden/README.md)
- [TypeScript SDK README](sdks/typescript/README.md)
- [Python SDK README](packages/sdk-python/README.md)
- [Full Technical Plan](plan.md)
- [Progress Summary](PROGRESS_SUMMARY.md)

JSON schemas:

- `schemas/evidence_bundle.schema.json`
- `schemas/redacted_bundle.schema.json`
- `schemas/capture_event.schema.json`
- `schemas/evidence_item.schema.json`
- `schemas/evidence_pack.schema.json`

## Current Caveats

- Full offline verification works with a full or disclosure package plus the public key.
- RFC 3161 verification supports trust anchors, CRLs, live OCSP, policy OIDs, and TSA signer allowlists, but full EU trusted-list ingestion and archival OCSP evidence handling are still future work.
- Rekor verification checks receipt structure, entry binding, inclusion proof, and signed-entry-timestamp signature when a trusted public key is configured.
- The current SCITT path is intentionally bounded and draft-aligned.
- SQLite is the production-default path in this repo today; PostgreSQL and S3 are future expansion paths, not current backends.
