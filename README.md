# Proof Layer SDK

Rust-first SDK for **proving chat assistant interactions** as tamper-evident, portable records.

Proof Layer’s **primary path** is chatbot evidence capture: record a chat session, seal it as a signed bundle, and verify that transcript later (including offline). The vault and broader compliance surfaces still exist, but they are explicitly advanced paths.

## Primary Use Case: Prove Chat Assistant Interactions

Use this repo when you need to answer, with cryptographic evidence:

- What prompts/messages were sent in a chat session?
- What assistant outputs were returned?
- Which chat artefacts were included in the sealed record?
- Has anything in that transcript bundle changed since sealing?
- Can another party verify the transcript proof without trusting your server?

The canonical starter example is:

- `examples/python-chat-proof/run.py`
- `examples/bundles/chat-session.bundle.json`

## Chatbot-First Quick Start

For a full chatbot-first walkthrough, see `get_started.md`. Short version:

1. Generate a keypair.
2. Run the chat proof example.
3. Verify the transcript bundle.
4. (Optional) Export a selective-disclosure bundle.

```bash
# 1) Generate a local signing keypair
cargo run -p proofctl -- generate-keypair --out ./keys

# 2) Run chatbot example (creates chat bundle artefacts)
python3 examples/python-chat-proof/run.py

# 3) Verify transcript proof
cargo run -p proofctl -- verify-bundle \
  --in ./examples/bundles/chat-session.bundle.json \
  --key ./keys/verify.pub

# 4) Optional disclosure export
cargo run -p proofctl -- disclose \
  --in ./examples/bundles/chat-session.bundle.json \
  --items 0 \
  --out ./chat-session.disclosure.pkg
```

## Scope Guardrails (Chatbot-First Version)

Intentionally **in scope** for the primary path:

- Capturing chatbot interactions (`llm_interaction`) and related chat artefacts.
- Deterministic canonicalization, hashing, Merkle commitments, signing, and verification.
- Local/offline transcript proof verification.
- Optional selective disclosure of chat evidence.

Intentionally **out of scope** for the chatbot-first path:

- Acting as a full legal/compliance determination engine.
- Guaranteeing model determinism or output correctness.
- Replacing enterprise records management systems.
- Requiring vault deployment for basic transcript proof workflows.
- Making non-chat governance packs the default onboarding experience.

## Advanced/Legacy Capabilities (Not Primary Path)

> **Not primary path:** The features below are supported, but not the recommended entry point for new adopters focused on chatbot transcript proof.

- Optional vault service (`proof-service`) for storage, retention, audit, export, backup, and restore.
- Broader compliance/readiness profiles (Annex IV, provider governance, conformity, FRIA, incident response, post-market monitoring).
- Additional SDK/provider integrations and non-chat evidence workflows.
- Demo site (`web-demo`) for walkthroughs and API exercises.

If you are starting fresh, complete the chatbot flow first (`get_started.md`) before using these advanced paths.

## Compatibility Matrix (Chatbot Focus v1)

| Status | Surface | Support level | Import path / docs |
| --- | --- | --- | --- |
| **chatbot-first stable** | Chat transcript capture + verification (`ProofLayer.capture`, `start_chat_session/startChatSession`, `LocalChatProofSession`, chat provider wrappers) | Fully supported as the primary onboarding path for v1 and future minors. | Default SDK entrypoints (`proofsdk`, `@proof-layer/sdk`) and `get_started.md`. |
| **advanced supported** | Non-chat lifecycle/compliance capture builders, tooling helpers, local/native helpers, vault/completeness operations | Supported, but designated advanced. New adopters should use these only after chatbot flows are in place. | `proofsdk.advanced` and `@proof-layer/sdk/advanced`; see `docs/migration/chatbot-focus-v1.md`. |
| **legacy/deprecated** | Non-chat APIs imported from default SDK surface (`proofsdk.<non-chat>`, `@proof-layer/sdk` non-chat builders/helpers) | Runtime deprecation warnings in v1; compatibility maintained during transition window only. | Migrate to advanced imports above; timeline in `docs/migration/chatbot-focus-v1.md`. |

## Root Docs Example Ordering

Chatbot-first references in root docs:

- `examples/python-chat-proof/run.py`
- `examples/bundles/chat-session.bundle.json`
- Chat session disclosure artefacts produced from that bundle

### Appendix: Advanced/Legacy References (Not Primary Path)

- `examples/python-annex-iv/run.py`
- `examples/python-compliance/run.py`
- `examples/python-incident-response/run.py`
- `examples/typescript-compliance/run.mjs`
- `examples/typescript-monitoring/run.mjs`
- `examples/typescript-gpai/run.mjs`
- `examples/python-basic/run.py`
- `examples/agent-simulated/run.py`

## Why This Exists

Normal logs answer “what happened?” but not “can an independent party verify this chat transcript was not changed?”

Proof Layer does not claim legal finality. It proves what was captured and sealed for one chat execution.

### Key Loading Modes (CLI)

`proofctl create` and `proofctl verify-bundle` accept exactly one key source:

- `--key <path>`: PEM from disk (recommended).
- `--key-env <ENV_VAR>`: PEM from an environment variable.
- `--key-kms-uri <uri>`: KMS/HSM adapter placeholder (currently returns not implemented).

Unsafe-mode restrictions are explicit:

- `create --key-env ...` requires both `--unsafe-allow-env-key` and `PROOFCTL_UNSAFE_MODE=1`.
- `verify-bundle --key-env ...` is allowed without unsafe mode because it loads public verify keys only.

Key utility commands:

```bash
cargo run -p proofctl -- key inspect --in ./keys/signing.pem
cargo run -p proofctl -- key export-public --in ./keys/signing.pem --out ./keys/verify.pub
```

Example with an SDK-first compliance profile stamped at create time:

```bash
cargo run -p proofctl -- create \
  --input ./fixtures/golden/capture.json \
  --artefact prompt.json=./fixtures/golden/prompt.json \
  --artefact response.json=./fixtures/golden/response.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg \
  --role deployer \
  --system-id support-assistant \
  --intended-use "Internal reviewer assistance" \
  --prohibited-practice-screening screened_no_prohibited_use \
  --risk-tier limited_risk \
  --gpai-status downstream_integrator \
  --deployment-context internal_operations
```

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

If you are anchoring to a SCITT service instead of Rekor, switch the provider and pick the new default-friendly format explicitly:

```bash
cargo run -p proofctl -- create \
  --input ./capture.json \
  --key ./keys/signing.pem \
  --out ./bundle.pkg \
  --timestamp-url http://timestamp.digicert.com \
  --transparency-provider scitt \
  --transparency-log https://scitt.example.test/entries \
  --scitt-format cose_ccf \
  --transparency-public-key ./scitt-service.pub
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
  --receipt-live-check best_effort \
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
cp ./vault.toml.example ./vault.toml
docker compose up --build
```

That starts the vault on `http://127.0.0.1:8080` and the demo site on `http://127.0.0.1:5173`.

The compose stack mounts `./vault.toml`, `./keys`, and `./storage`, and sets `PROOF_SIGNING_KEY_PATH=/app/keys/signing.pem`, so the vault exposes the matching public verify key from `./keys/verify.pub` through `/v1/config`.

The service auto-loads `./vault.toml` when present. Environment variables still override file settings.

The vault also exposes `POST /v1/completeness/evaluate` for advisory readiness checks against stored full bundles, inline full bundles, or stored packs with pack-scoped completeness support. The TypeScript and Python SDK facades mirror that as `evaluateCompleteness(...)` and `evaluate_completeness(...)`.

For pack responses, the legacy `completeness_*` fields remain the per-bundle aggregate view. New `pack_completeness_*` fields carry the true synthesized pack-level readiness result where supported for `annex_iv`, `conformity`, `fundamental_rights`, `annex_xi`, `incident_response`, `post_market_monitoring`, and `provider_governance`.
Pack summaries and manifests may now include `pack_completeness_profile`, `pack_completeness_status`, `pack_completeness_pass_count`, `pack_completeness_warn_count`, and `pack_completeness_fail_count`.

For `annex_iv`, the current pack-scoped pass count is `8` because `annex_iv_governance_v1` now evaluates the full governance set curated by the pack.
For `conformity`, the current pack-scoped pass count is `3` because `conformity_v1` evaluates the conformity assessment, declaration, and registration artefacts curated by that pack.
For `provider_governance`, the current pack-scoped pass count is `8` because `provider_governance_v1` evaluates the provider-side governance set curated by that pack, including corrective action follow-up.
For `fundamental_rights`, the current pack-scoped pass count is `2` because `fundamental_rights_v1` currently evaluates the deployer-side assessment and oversight rule families.
For `incident_response`, the current pack-scoped pass count is `10` because `incident_response_v1` evaluates the incident context, triage, oversight, corrective-action, authority-reporting, and correspondence families curated by that pack.
For `post_market_monitoring`, the current pack-scoped pass count is `6` because `post_market_monitoring_v1` evaluates the required monitoring, incident, corrective-action, authority-reporting, and deadline rule families.

```json
{
  "profile": "gpai_provider_v1",
  "pack_id": "01JPACKEXAMPLE1234567890ABCD"
}
```

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

# Export a provider governance pack with QMS / release evidence
cargo run -p proofctl -- pack \
  --type provider-governance \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./provider-governance.pack

# Export an Annex IV high-risk governance pack
cargo run -p proofctl -- pack \
  --type annex-iv \
  --vault-url http://127.0.0.1:8080 \
  --system-id hiring-assistant \
  --out ./annex-iv.pack

# Export a deployer-side FRIA / fundamental rights pack
cargo run -p proofctl -- pack \
  --type fundamental-rights \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./fundamental-rights.pack

# Export a monitoring / authority-reporting pack
cargo run -p proofctl -- pack \
  --type post-market-monitoring \
  --vault-url http://127.0.0.1:8080 \
  --system-id system-123 \
  --out ./post-market-monitoring.pack

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

### 6. High-Risk Governance Workflow

The repo now includes a checked Annex IV acceptance scenario under `fixtures/golden/annex_iv_governance/` plus end-to-end SDK examples for a provider-side employment screening system.

The intended flow is:

1. capture governance bundles for `technical_doc`, `risk_assessment`, `data_governance`, `instructions_for_use`, `human_oversight`, `qms_record`, `standards_alignment`, and `post_market_monitoring`
2. create an `annex_iv` full pack
3. preview the `annex_iv_redacted` disclosure policy
4. create an `annex_iv` disclosure pack
5. verify the exported package members

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
- When `transparency.provider = "scitt"`, `transparency.scitt_format` may be `legacy_json` or `cose_ccf`; new receipts should use `cose_ccf`.

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
- `POST /v1/completeness/evaluate`
- `POST /v1/packs`
- `GET /v1/packs/{pack_id}`
- `GET /v1/packs/{pack_id}/manifest`
- `GET /v1/packs/{pack_id}/export`

System rollups:

- `GET /v1/systems`
- `GET /v1/systems/{system_id}/summary`

`POST /v1/verify/timestamp` and `POST /v1/verify/receipt` now return both the low-level cryptographic result and a plain-English `assessment` block.
For receipt verification, `live_check_mode` can be `off`, `best_effort`, or `required`.

Plain-English trust levels:

- `structural`: the timestamp or receipt matches the proof, but stronger trust was not proven.
- `trusted`: the matching proof also chained to a trusted signer or trusted log/service key.
- `qualified`: the stronger qualified timestamp path passed too.

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

Install surfaces today:

- local repo build: `cd sdks/typescript && npm install && npm run build`
- checked release tarball: install the OS-matching `.tgz` asset attached to `sdk-v*` GitHub releases

The TypeScript package is still distributed as an OS-specific release tarball because it currently embeds a platform-specific native N-API module. Public npm publishing is intentionally not enabled until that native packaging model is generalized.

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

Install surfaces today:

- local repo build: `cd packages/sdk-python && python3 ./scripts/build_native.py`
- checked release wheel: install the matching `.whl` asset attached to `sdk-v*` GitHub releases

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

Release contract checks:

- `python3 ./scripts/generate_schemas.py --check`
- `python3 ./scripts/check_release_metadata.py`

## Demo And Examples

Examples:

- `npm --prefix sdks/typescript build && node examples/typescript-compliance/run.mjs`
- `npm --prefix sdks/typescript build && node examples/typescript-monitoring/run.mjs`
- `node examples/typescript/run.mjs`
- `python3 packages/sdk-python/scripts/build_native.py && python3 examples/python-annex-iv/run.py`
- `python3 packages/sdk-python/scripts/build_native.py && python3 examples/python-compliance/run.py`
- `python3 packages/sdk-python/scripts/build_native.py && python3 examples/python-incident-response/run.py`
- `python3 examples/python-basic/run.py`
- `python3 examples/agent-simulated/run.py`

The Annex IV and other compliance examples assume `proof-service` is running locally or `PROOF_SERVICE_URL` points at a reachable vault.

Optional demo frontend:

```bash
cd web-demo
npm install
npm run dev
```

The demo frontend can connect to a local `proof-service` instance. It is there to illustrate the workflow and exercise the API, not to act as the production compliance surface. It includes:

- landing and use-case pages for explanation
- integrated docs under `/docs/*`
- a guided demo for scenario walkthroughs
- an advanced playground for deeper workflow control
- an Annex IV-oriented readiness check card backed by the completeness API

When connected to a running vault, the interactive workflow can:

- read `/v1/config` and `/v1/disclosure/templates`
- create a real `llm_interaction` bundle through `POST /v1/bundles`
- optionally timestamp and anchor that bundle
- preview disclosure output
- export full or disclosure-format packs
- fetch system summaries
- verify through `POST /v1/verify` when given a public key PEM

Start with:

- `/` for the landing and overview pages
- `/guided` for the walkthrough flow
- `/playground` for the advanced technical flow
- `/docs` for the integrated documentation section

## Docs Map

- [Architecture](docs/architecture.md)
- [EU AI Act Fork Executive Summary](docs/eu_ai_act_fork_executive_summary.md)
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
- `schemas/verification_assessment.schema.json`
- `schemas/verify_timestamp_response.schema.json`
- `schemas/verify_receipt_response.schema.json`
- `schemas/schema_manifest.json`

## Current Caveats

- Full offline verification works with a full or disclosure package plus the public key.
- RFC 3161 verification supports trust anchors, CRLs, live OCSP, policy OIDs, and TSA signer allowlists, but full EU trusted-list ingestion and archival OCSP evidence handling are still future work.
- Rekor verification checks receipt structure, entry binding, inclusion proof, signed-entry-timestamp signature, and optional live log consistency / freshness when requested.
- SCITT now writes the COSE/CCF-style receipt body by default and keeps legacy JSON read compatibility, but broader interop and trust-list work are still future work.
- SQLite is the production-default path in this repo today; PostgreSQL and S3 are future expansion paths, not current backends.
