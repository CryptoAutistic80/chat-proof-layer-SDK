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
- Added the next GPAI evidence slice:
  first-class `model_evaluation`, `adversarial_test`, and `training_provenance` item types in Rust core,
  direct Annex XI / systemic-risk pack curation and obligation tagging in the vault,
  and matching builder/facade coverage in both the TypeScript and Python SDKs.
- Added the GPAI retention-model cleanup:
  a dedicated seeded `gpai_documentation` retention class,
  an explicit retention `expiry_mode` with `until_withdrawn` semantics in the vault,
  SDK defaults so GPAI builders use that class automatically,
  and a fix for retention-status aggregation so empty policy rows no longer count as active bundles.
- Added the conformity evidence slice:
  first-class `conformity_assessment`, `declaration`, and `registration` item types in Rust core,
  a real `conformity` pack profile in the vault with market-surveillance-oriented curation,
  and matching builder/facade coverage in both the TypeScript and Python SDKs.
- Added the next trust-hardening slice:
  trust-aware RFC 3161 verification against configured PEM trust anchors in Rust core,
  Rekor SET signature + `logID` verification against a configured PEM log public key,
  `proofctl verify --timestamp-trust-anchor/--transparency-public-key`,
  and vault config/verify/attach flows that automatically use persisted trust material when present.
- Added the next assurance-policy slice:
  RFC 3161 policy OID constraints in Rust core,
  local `proofctl create` trust-aware timestamp/receipt attachment parity,
  `proofctl verify --timestamp-policy-oid`,
  and persisted vault timestamp policy configuration through `policy_oids`.
- Added the next qualified-assurance slice:
  operational `standard` / `qualified` timestamp assurance profiles in Rust core,
  `proofctl create|verify --timestamp-assurance`,
  vault enforcement of `timestamp.assurance = "qualified"` via trust anchors, policy OIDs, CRLs, and TSA signer checks,
  and receipt verification updates so timestamp-profile checks do not incorrectly require a Rekor log key.
- Added the next timestamp trust-hardening slice:
  CRL-backed TSA revocation checks in Rust core,
  TSA signer certificate-profile enforcement for time stamping,
  `proofctl create|verify --timestamp-crl`,
  and persisted vault timestamp CRL configuration through `crl_pems` / `crl_paths`.
- Added the next qualified TSA pinning slice:
  operator-supplied TSA signer allowlists in Rust core,
  `proofctl create|verify --timestamp-qualified-signer`,
  persisted vault timestamp signer-pin configuration through `qualified_signer_pems` / `qualified_signer_paths`,
  and `qualified` assurance now requires the signer certificate to match that configured allowlist in addition to chain / CRL / policy checks.
- Added the next timestamp trust-hardening slice:
  optional live OCSP checks for TSA signer certificates in Rust core,
  `proofctl create|verify --timestamp-ocsp-url`,
  persisted vault timestamp OCSP configuration through `ocsp_responder_urls`,
  and OCSP verification now checks responder signatures, current response validity, and revocation times relative to `genTime`.
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
- Closed the explicit SCITT stub:
  `crates/core/src/transparency/` now supports a bounded draft-aligned SCITT statement/receipt path,
  `proofctl create --transparency-provider scitt --transparency-log <url>` can attach those receipts locally,
  and vault `POST /v1/bundles/{id}/anchor` now works with `transparency.provider = "scitt"` using the same trust-policy surface.
- Added the first selective-disclosure slice:
  a new `pl-merkle-sha256-v2` commitment model with separate header/item/artefact-metadata leaves for new bundles,
  legacy `pl-merkle-sha256-v1` verification compatibility,
  core redacted-bundle verification with Merkle inclusion proofs,
  and `proofctl disclose --items ...` plus `proofctl verify` auto-detection for disclosure packages.
- Added the harder field-redaction slice:
  new bundles now default to `pl-merkle-sha256-v3`,
  v3 item leaves commit to `{item_type, field_digests}` instead of the full item JSON,
  legacy `pl-merkle-sha256-v1` and compatibility `pl-merkle-sha256-v2` verification remain supported,
  `proofctl disclose --redact-field <item_index>:<field>` can now hide selected top-level item fields while preserving Merkle verification,
  and the TypeScript/Python local disclosure helpers plus golden fixtures are aligned to the new v3 commitment model.
- Added the nested path-redaction slice:
  new bundles now default to `pl-merkle-sha256-v4`,
  v4 item leaves commit to `{item_type, container_kinds, path_digests}` so nested `item.data` JSON-pointer paths can be selectively hidden,
  legacy `pl-merkle-sha256-v1`, `pl-merkle-sha256-v2`, and `pl-merkle-sha256-v3` verification remain supported,
  `proofctl disclose --redact-field <item_index>:<field-or-json-pointer>` now supports nested path redaction on v4 bundles,
  and vault disclosure policies can carry the same selectors through preview/manifests/pack export.
- Added disclosure-policy authoring helpers:
  `proofctl vault disclosure-template` now emits starter policy JSON for `regulator_minimum`, `annex_iv_redacted`, `incident_summary`, `runtime_minimum`, and `privacy_review`,
  the CLI template command can layer reusable redaction groups like `commitments`, `metadata`, `parameters`, and `operational_metrics`,
  and the TypeScript / Python SDKs now expose matching local builder helpers so callers can compose policy JSON without manually hand-writing selector maps.
- Added vault-side disclosure-template discovery/rendering:
  the service now exposes `GET /v1/disclosure/templates` and `POST /v1/disclosure/templates/render`,
  `proofctl vault disclosure-templates` can list the built-in template catalog and `proofctl vault disclosure-template --vault-url ...` can render starter policy JSON through the service,
  and the TypeScript / Python vault clients plus `ProofLayer` facades now expose `getDisclosureTemplates` / `renderDisclosureTemplate` and `get_disclosure_templates` / `render_disclosure_template`.
- Closed the next disclosure-policy ergonomics gap:
  `POST /v1/packs` and `POST /v1/disclosure/preview` now accept inline `disclosure_template` render requests,
  `proofctl pack`, `proofctl vault export`, and `proofctl vault disclosure-preview` now expose `--disclosure-template-profile`, `--disclosure-template-name`, and repeatable `--disclosure-group`,
  and the TypeScript / Python vault clients plus `ProofLayer` facades can now request template-based pack exports and disclosure previews directly without first saving policy JSON.
- Added the first local SDK artifact pipeline:
  `sdks/typescript` now has `npm run pack:smoke` to build and verify an npm tarball containing `dist/*` plus `native/proof-layer-napi.node`,
  `packages/sdk-python` now has `python3 ./scripts/build_dist.py` to build and verify a platform-tagged wheel containing `proofsdk/_native*` plus `py.typed`,
  and the repo root now has `python3 ./scripts/build_sdk_artifacts.py` to run both artifact builds together.
- Added CI-backed multi-platform SDK artifact workflows:
  `.github/workflows/sdk-artifacts.yml` now builds checked npm tarballs and Python wheels on Linux, macOS, and Windows for PRs, pushes, and manual runs,
  `.github/workflows/sdk-release.yml` rebuilds those artifacts in `release` mode for `sdk-v*` tags or manual dispatch,
  and release runs attach the generated `.tgz` and `.whl` files to the GitHub release.
- Added the next vault runtime hardening slice:
  optional HTTPS serving via `[server].tls_cert` / `[server].tls_key` or `PROOF_SERVICE_TLS_CERT_PATH` / `PROOF_SERVICE_TLS_KEY_PATH`,
  startup loading of PEM cert/key pairs through `axum-server` + rustls,
  and `GET /v1/config` now reports whether TLS is currently enabled.
- Added the next vault auth slice:
  optional bearer API-key auth via `[auth]` / `[[auth.api_keys]]` or `PROOF_SERVICE_API_KEY`,
  protection of `/v1/*` while leaving `/healthz` and `/readyz` open,
  audit-log actor labels now use the authenticated principal label instead of the generic `api` marker,
  and `proofctl` now automatically uses `PROOF_SERVICE_API_KEY` for vault HTTP calls.
- Added the bounded single-tenant vault slice:
  optional `[tenant].organization_id` / `PROOF_SERVICE_ORGANIZATION_ID` enforcement,
  startup rejection when existing bundle rows belong to a different organization,
  automatic stamping of new captures when `actor.organization_id` is omitted,
  rejection of explicit org mismatches at bundle-create time,
  and `GET /v1/config` / `proofctl vault status` now report tenant enforcement state.
- Added the first observability slice:
  open `/metrics` Prometheus-text scraping backed by live SQLite bundle/pack/audit counts plus auth/TLS/tenant runtime gauges,
  `proofctl vault metrics` as a thin wrapper over that endpoint,
  and regression coverage proving the metrics surface stays open even when `/v1/*` bearer auth is enabled.
- Added the first backup/export slice for SQLite pilots:
  authenticated `POST /v1/backup` returns a `.tar.gz` archive containing a consistent `VACUUM INTO` metadata snapshot,
  current non-secret vault config JSON,
  and filesystem artefact/pack-export storage,
  while `proofctl vault backup --out ...` downloads that archive without manual `curl`.
- Extended pack export into the selective-disclosure path:
  `POST /v1/packs` now accepts `bundle_format = "full" | "disclosure"`,
  vault `GET /v1/packs/{id}/export` can emit redacted disclosure-package members selected by pack curation rules,
  vault `POST /v1/verify` now accepts those disclosure packages,
  and `proofctl pack` / `proofctl vault export` now expose `--bundle-format <full|disclosure>`.
- Added the first disclosure-policy control slice:
  vault `PUT /v1/config/disclosure` now persists named disclosure profiles,
  disclosure-pack assembly can reference `disclosure_policy` on `POST /v1/packs`,
  default profiles now include `regulator_minimum`, `annex_iv_redacted`, and `incident_summary`,
  pack manifests now record selected disclosure policies plus disclosed artefact metadata entries,
  and `proofctl` / the TypeScript and Python SDK pack helpers now surface `disclosure_policy`.
- Closed the next disclosure gap:
  disclosure policies now support `include_artefact_bytes`,
  `annex_iv_redacted` exports now include selected artefact files in disclosure packages,
  local `proofctl disclose` now supports `--artefacts ...`,
  and the TypeScript / Python SDK vault clients now expose disclosure-config read/update helpers.
- Added the next disclosure-authoring slice:
  disclosure policies now support allowed/excluded obligation-ref filters,
  the vault now exposes `POST /v1/disclosure/preview` for named or inline policy previews against stored bundles,
  `proofctl vault disclosure-preview` surfaces that flow on the CLI,
  and the TypeScript / Python SDK clients now expose `previewDisclosure` / `preview_disclosure`.
- Added the next vault disclosure-policy slice:
  disclosure policies now support `redacted_fields_by_item_type`,
  vault previews now report per-item field/path redactions,
  disclosure-pack manifests now record the resulting item field/path redaction map,
  and vault disclosure-pack exports now apply those selectors through the core disclosure path.
- Restored a clean Rust verification loop: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` both pass.

Still outstanding from `plan.md`:

- JSON schema coverage is now started, with timestamp and Rekor transparency receipt coverage added, but richer export/archive schemas are still incomplete.
- The vault now uses SQLite with legal-hold-aware retention, audit logging, file/env/runtime configuration, background retention scanning, curated pack export, redacted disclosure-pack export, RFC 3161 bundle timestamp attachment, and transparency anchoring, but PostgreSQL and Annex-complete artefact/redaction policy assembly are not built yet.
- The vault now also supports optional bearer auth with per-principal audit labels on `/v1/*` plus bounded single-tenant org enforcement; broader multi-tenant org isolation and per-query tenant filtering are still future work.
- The vault now exposes a useful Prometheus-style `/metrics` surface, but it still does not emit OTLP traces/metrics, external log shipping, or richer per-route latency histograms.
- The vault now supports one-shot backup export for SQLite deployments, but it still does not have a matching restore/import flow, scheduled backups, remote backup targets, or backup encryption/key management.
- TypeScript and Python now both have native FFI bridges, local sealing paths, higher-level `ProofLayer` facades, a local artifact build path for npm tarballs and platform-tagged wheels, and CI-backed multi-platform GitHub artifact builds, but there is still no automated publish step to npm or PyPI.
- TypeScript and Python SDKs now expose local redacted-bundle helpers (`disclose` / `verifyRedactedBundle` in TypeScript, `disclose` / `verify_redacted_bundle` in Python), including top-level field redaction for local v3 bundles and nested JSON-pointer path redaction for local v4 bundles, plus vault pack helpers for `bundle_format = "full" | "disclosure"` with `disclosure_policy` or inline `disclosure_template`, vault disclosure-config read/update helpers, and disclosure-preview helpers.
- The main remaining gaps are no longer the evidence catalog itself; they are the harder later-phase items like deeper trust policy work, fuller SCITT interoperability, alternative storage backends, and automated npm/PyPI/prebuilt release publishing hardening.
- RFC 3161 verification now supports signer-chain validation against configured PEM trust anchors, optional `TSTInfo.policy` OID enforcement, CRL-based revocation checking, optional live OCSP checks, qualified TSA signer allowlist matching, and operational `qualified` profile gating, but full eIDAS-qualified trust-list evaluation and archival OCSP evidence handling are still outstanding.
- Rekor verification now supports SET signature validation and `logID` binding against a configured PEM log public key; live-log consistency checks beyond the stored inclusion proof remain future work.
- The current SCITT path is intentionally bounded: it verifies a draft-aligned canonical JSON statement/receipt contract, not a full interoperable COSE/CCF profile.
