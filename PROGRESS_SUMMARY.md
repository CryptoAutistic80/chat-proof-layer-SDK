## March 6, 2026

Completed:

- Migrated the Rust workspace to `crates/core`, `crates/cli`, and `crates/vault`.
- Rebuilt the Rust core around a v1.0 `EvidenceBundle` schema with typed evidence items and `context`.
- Added v0.1 -> v1.0 migration helpers so legacy capture payloads still build valid v1 bundles.
- Extended Merkle support with inclusion-proof generation and verification.
- Updated `proofctl` and `proof-service` to accept both legacy capture JSON and v1 capture JSON.
- Regenerated the deterministic golden fixture set for `bundle_version: "1.0"`.
- Added the next Phase 2 CLI slice:
  `proofctl create --system-id/--retention-class/--evidence-type`,
  `proofctl verify --check-timestamp/--check-receipt`,
  and `proofctl inspect --show-items/--show-merkle`.
- Migrated vault metadata storage from `sled` to SQLite and added `/readyz` plus basic `/v1/bundles` query filtering on role/type/date fields.
- Added the first retention engine slice: seeded retention policies, computed `expires_at`, `/v1/retention/status`, and `/v1/retention/scan` soft-delete flow.
- Hardened retention with legal holds, manual `DELETE /v1/bundles/{id}` soft-delete semantics, and grace-period hard-delete of artefact blobs + metadata after retention scan.
- Added the first audit-trail slice:
  append-only `audit_log` persistence,
  `GET /v1/audit-trail`,
  and logging for bundle, retention, legal-hold, verify, and pack actions.
- Added the first configuration slice:
  `GET /v1/config`,
  `PUT /v1/config/retention`,
  SQLite-backed retention policy upserts,
  and active-bundle expiry refresh when updated policies remain enabled.
- Completed the remaining config-plane slice:
  `PUT /v1/config/timestamp`,
  `PUT /v1/config/transparency`,
  persisted timestamp/transparency provider settings in SQLite,
  and returned those settings from `GET /v1/config`.
- Added the first real assurance slice:
  `crates/core/src/timestamp/` with RFC 3161 request/verify support,
  `proofctl create --timestamp-url`,
  `proofctl verify --check-timestamp`,
  and vault `POST /v1/bundles/{id}/timestamp` backed by persisted timestamp config.
- Added the next assurance slice:
  `crates/core/src/transparency/` with Rekor RFC 3161 receipt submission/verification,
  `proofctl create --transparency-log`,
  `proofctl verify --check-receipt` plus assurance-level output,
  and vault `POST /v1/bundles/{id}/anchor` backed by persisted transparency config.
- Hardened Rekor receipt verification to check entry UUID to leaf-hash binding and verify Merkle inclusion proofs against the advertised Rekor root hash.
- Added the next vault assurance slice:
  `POST /v1/verify/timestamp`,
  `POST /v1/verify/receipt`,
  direct-or-by-`bundle_id` assurance verification in the service,
  and assurance-aware `/v1/bundles` filtering on `has_timestamp`, `has_receipt`, and computed assurance level.
- Added the next vault runtime slice:
  `vault.toml` startup configuration support with env-var overrides,
  startup sync into persisted retention/timestamp/transparency config,
  a configurable background retention scan interval,
  and a checked-in `vault.toml.example` wired into `docker compose`.
- Added the next query/ops slice:
  vault `GET /v1/systems` and `GET /v1/systems/{id}/summary` rollups,
  plus `proofctl vault status|query|retention|systems|export` wrappers over the main vault read/export flows.
- Added the first native TypeScript SDK slice:
  new `crates/napi` NAPI-RS bridge over the Rust core,
  native npm exports for canonicalization/hash/Merkle root/JWS sign+verify/local bundle build/offline bundle verification,
  and the TypeScript SDK now routes integrity-sensitive operations through that native module instead of duplicating them in JavaScript.
- Added the first native Python SDK slice:
  new `crates/pyo3` PyO3 bridge over the Rust core,
  native Python exports for canonicalization/hash/Merkle root/JWS sign+verify/local bundle build/offline bundle verification,
  and `packages/sdk-python` now routes integrity-sensitive operations through that native module instead of duplicating them in Python.
- Added the next SDK ergonomics slice:
  `LocalProofLayerClient` implementations in both Node and Python,
  provider-wrapper compatibility with local sealing clients,
  and deterministic local-client tests proving the golden fixture can be built without the vault service.
- Corrected the npm package shape to be TypeScript-first:
  package name now `@proof-layer/sdk`,
  typed `src/*.ts` sources plus `tsconfig.json`,
  compiled `dist/` output for tests/package exports,
  and Node test coverage now runs against the built TypeScript output rather than source `.js` files.
- Added the first higher-level TypeScript SDK facade:
  `ProofLayer` with local-or-vault transport selection,
  `capture(...)` for local/remote `llm_interaction` sealing,
  provider-specific `withProofLayer(...)` helpers,
  and the repo layout now matches the plan at `sdks/typescript/` instead of the old `packages/sdk-node/` path.
- Added the next TypeScript SDK surface-hardening slice:
  shared `evidence.ts` helpers for v1 `llm_interaction` capture assembly,
  normalized provider wrappers so they emit the same v1 capture shape as `ProofLayer.capture(...)`,
  generic and Vercel-AI-style wrappers plus provider index exports,
  and `@proof-layer/sdk/otel` with `ProofLayerExporter` and typed OTel helper exports.
- Added the next TypeScript lifecycle slice:
  typed `evidence.ts` builders for `risk_assessment`, `data_governance`, and `technical_doc`,
  matching `ProofLayer.captureRiskAssessment(...)`, `captureDataGovernance(...)`, and `captureTechnicalDoc(...)` convenience methods,
  default evidence artefact generation for those lifecycle items,
  and test coverage proving those bundles seal locally through the Rust-native path.
- Completed the current Rust-core evidence coverage in the TypeScript SDK:
  added typed builders for `tool_call`, `retrieval`, `human_oversight`, and `policy_decision`,
  matching `ProofLayer` convenience methods for those evidence types,
  and default artefact generation plus local sealing tests for the expanded evidence catalog.
- Added the Python parity slice:
  new `proofsdk.evidence` shared request builders for all evidence item types currently implemented in Rust core,
  a higher-level `proofsdk.ProofLayer` facade with local-or-vault transport selection plus capture helpers,
  updated OpenAI-like / Anthropic-like wrappers and decorator helpers to emit the same v1 capture shape,
  and Python tests covering raw builders, the facade, and `with_proof_layer(...)` wrapper attachment.
- Expanded the implemented evidence catalog toward the plan:
  added first-class `literacy_attestation` and `incident_report` item types in Rust core,
  extended vault indexing/pack curation so `ai_literacy` and `incident_response` can match those types directly,
  and exposed matching builders plus `ProofLayer` capture helpers in both the TypeScript and Python SDKs.
- Added the first pack export slice:
  `POST /v1/packs`,
  `GET /v1/packs/{id}`,
  `GET /v1/packs/{id}/manifest`,
  `GET /v1/packs/{id}/export`,
  plus `proofctl pack --type/--vault-url/--system-id/--from/--to --out`.
- Added the next pack hardening slice:
  derived `obligation_ref` tagging for indexed evidence items,
  pack-type curation rules (`pack-rules-v1`) based on actor role/item type/retention class,
  and manifest-level match reasons for why each bundle was included.
- Restored a clean Rust verification loop: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` both pass.

Still outstanding from `plan.md`:

- JSON schema coverage is now started, with timestamp and Rekor transparency receipt coverage added, but richer export/archive schemas are still incomplete.
- The vault now uses SQLite with legal-hold-aware retention, audit logging, file/env/runtime configuration, background retention scanning, curated pack export, and RFC 3161 bundle timestamp attachment, but PostgreSQL and redacted/Annex-complete pack assembly are not built yet.
- The CLI now covers the main vault operational read paths, but there is still no `proofctl disclose` flow.
- TypeScript and Python now both have native FFI bridges, local sealing paths, and higher-level `ProofLayer` facades, but there is still no shared native build/release pipeline for SDK artifacts.
- SCITT receipts and selective disclosure CLI flows remain future phases.
- The broader plan evidence catalog still has several future-phase gaps in Rust core, especially `model_evaluation`, `adversarial_test`, `training_provenance`, and conformity/declaration/registration evidence.
- RFC 3161 verification currently checks CMS signature integrity and message-imprint binding, but TSA certificate-chain / revocation trust validation and eIDAS-qualified trust policy are still outstanding.
- Rekor verification currently checks receipt structure, entry UUID to leaf-hash binding, Merkle inclusion proofs, and embedded RFC 3161 token binding, but not Rekor SET signature validation.
