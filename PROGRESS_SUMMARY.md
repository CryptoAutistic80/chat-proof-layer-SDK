## March 22, 2026

Completed:

- Expanded `annex_iv_governance_v1` so it now assesses the full eight-family Annex IV governance bundle, adding `qms_record`, `standards_alignment`, and `post_market_monitoring` minimum-field checks.
- Added a new advisory `fundamental_rights_v1` completeness profile for deployer-side FRIA workflows, covering structured `fundamental_rights_assessment` and linked `human_oversight` evidence.
- Wired that profile through Rust core, `proofctl assess`, vault pack readiness for `fundamental_rights`, the TypeScript/Python SDK surfaces, the checked schemas, docs, and the web demo readiness copy.
- Added checked FRIA completeness fixtures plus stronger TypeScript/Python builder/native coverage, and refreshed the Python FRIA example to emit the fuller structured assessment shape and print pack readiness.
- Added a shared assurance-reporting layer in Rust core with plain-English trust levels, stable check IDs, and additive `assessment` payloads for timestamp and receipt verification.
- Updated vault `POST /v1/verify/timestamp` and `POST /v1/verify/receipt` to return those assessments, plus additive receipt `live_check_mode` support with `off`, `best_effort`, and `required`.
- Added opt-in Rekor live-log consistency and freshness verification against the current tree head and entry body.
- Upgraded the SCITT path so new receipts default to the newer COSE/CCF-style body format while keeping legacy JSON receipt verification compatibility.
- Extended the CLI, TypeScript SDK, Python SDK, docs, demo wording, and schema set to surface the new trust/reporting model consistently.

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
- Added the matching offline restore/import slice:
  `proofctl vault restore --in backup.tar.gz --out-dir ./restored-vault` now validates the backup manifest/config,
  rejects duplicate or path-traversing archive entries,
  stages extraction into a fresh directory,
  and restores `metadata/metadata.db`, `storage/*`, and `config/vault_config.json` without touching a live service.
- Added the next SQLite pilot-ops slice:
  scheduled local backups via `[backup]` / `PROOF_SERVICE_BACKUP_*`,
  background archive export with retention-count pruning,
  `GET /v1/config` / `proofctl vault status` backup-state reporting,
  and archive exclusion for `storage/backups/*` so scheduled backups do not recursively capture themselves.
- Added the next backup-hardening slice:
  optional backup encryption via `[backup.encryption]` / `PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_*`,
  shared XChaCha20-Poly1305 archive envelope logic in `proof-layer-core`,
  encrypted `POST /v1/backup` and scheduled backup export when configured,
  and `proofctl vault restore --backup-key ...` / env-based offline decryption support.
- Refreshed `web-demo` into a real investor-facing vault workflow:
  it now loads live capability state from `/v1/config` and `/v1/disclosure/templates`,
  creates a v1.0 `llm_interaction` bundle with prompt/response/trace artefacts through `POST /v1/bundles`,
  can optionally drive timestamping, transparency anchoring, disclosure preview, pack export, and system-summary lookup end to end,
  and exports either full or disclosure-format `runtime_logs` packs using built-in disclosure templates instead of the old client-side PoC package simulator.
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
- Rebuilt `web-demo` into a dedicated route-based playground:
  separate `/playground`, `/results`, `/examination`, and `/exports` pages now sit on top of a shared `DemoContext`,
  the demo can run either `synthetic_demo_capture` or vault-mediated `live_provider_capture`,
  fixed presets now cover investor summary, deployer runtime log, incident review, and Annex IV filing,
  recent runs can be revisited across results/examination/export routes,
  and empty disclosure/export cases now explain themselves instead of surfacing generic workflow failures.
- Added the demo-provider backend surface in the vault:
  `GET /v1/config` now reports demo capture modes plus per-provider live availability,
  `POST /v1/demo/provider-response` now centralizes synthetic and live OpenAI/Anthropic response generation without exposing provider keys to the browser,
  and the OpenAI live path is tuned for `gpt-5-mini` style models so the demo returns visible text instead of exhausting output tokens on reasoning.
- Added the next demo-usability slice:
  the playground now distinguishes `Vault API key (auth only)` from a demo-only `Temporary provider API key`,
  live mode can now run even when the vault was not started with `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` by sending a one-off provider key only to `POST /v1/demo/provider-response`,
  the vault never persists that temporary provider key in config, bundles, or audit payloads,
  and the UI now explains that the vault API key is only needed when bearer auth is enabled.
- Added verification coverage for the new playground flow:
  vault tests now cover the demo provider-response endpoint,
  `web-demo` now has Vitest coverage for routes/presets/export eligibility,
  and a Playwright smoke test verifies the synthetic route flow from Playground to Results, Examination, and Exports.
- Reframed `web-demo` into a demo-oriented site with narrative pages:
  the old demo-first shell is replaced by a business-first landing page plus use-case pages,
  integrated docs routes under `/docs/*`,
  a guided demo entrypoint at `/guided`,
  and business-language run pages for `/what-happened`, `/what-you-can-prove`, and `/what-you-can-share`.
- Preserved the technical evaluation path inside that demo site:
  the advanced playground still exposes the full vault-backed configuration surface,
  while the guided flow now hides most proof-system controls behind a simpler scenario-first experience.
- Added the supporting narrative/content layer:
  preset metadata now includes business reason/outcome text,
  the site now uses a shared proof-record glossary and plain-English narrative summaries,
  and the recent-runs / assurance / export cards now use business-first labels with technical detail pushed lower in the hierarchy.
- Extended browser verification coverage for the new surface:
  Vitest now checks the landing page, guided demo defaults, integrated docs routing, and the new empty-export wording,
  and the Playwright smoke now runs from `/` through Guided Demo, What Happened, What You Can Prove, What You Can Share, and Docs.
- Polished the outward-facing site copy for investor and partner use:
  the main demo and narrative surfaces no longer describe the product in development-history terms,
  empty disclosure/export states now explain the business outcome instead of sounding like internal workflow diagnostics,
  and the advanced playground keeps the technical detail without framing the public site as an engineering artifact.
- Added forwarded-host support for the demo site dev server:
  `web-demo/vite.config.js` now explicitly allows the active ngrok host plus `.ngrok-free.dev`,
  and it also accepts extra forwarded hosts through `WEB_DEMO_ALLOWED_HOSTS` for shareable preview sessions.
- Restored a clean Rust verification loop: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` both pass.

## March 14, 2026

Completed:

- Aligned the repo narrative around the real product shape:
  the primary surface is now clearly the SDK, CLI, and local verification path,
  the vault is framed as the optional paid or self-hosted service layer,
  and `web-demo` is now consistently described as demo-only collateral rather than the production compliance interface.
- Added an SDK-first compliance context model:
  first-class `ComplianceProfile` support now exists in the shared schema,
  the actor-role model now covers more of the AI Act role surface,
  and both the TypeScript and Python `ProofLayer` facades can apply a default compliance profile across captures.
- Added the missing governance evidence layer:
  first-class support now exists for `instructions_for_use`, `qms_record`, `fundamental_rights_assessment`, `standards_alignment`, `post_market_monitoring`, `corrective_action`, `downstream_documentation`, `copyright_policy`, and `training_summary`,
  with matching builder and facade coverage in both SDKs.
- Added role- and profile-aware export slices in the vault:
  `provider_governance` now curates provider-side governance evidence,
  `fundamental_rights` now curates deployer-side FRIA evidence and requires `compliance_profile.fria_required = true`,
  and those pack families are wired through both the vault API and `proofctl pack`.
- Extended the CLI create path so classification data can be attached at seal time:
  `proofctl create` now accepts actor-role and compliance-profile overrides,
  including intended-use, risk-tier, GPAI status, deployment context, and FRIA-related fields,
  so local SDK/CLI capture can carry the same classification context as vault-backed flows.
- Added the first authority-reporting evidence slice:
  first-class `authority_notification`, `authority_submission`, `reporting_deadline`, and `regulator_correspondence` item types now exist in Rust core,
  with matching TypeScript/Python builders, `ProofLayer` capture helpers, disclosure-policy support, and vault indexing.
- Added the next operational monitoring/export slice:
  the vault now supports a dedicated `post_market_monitoring` pack profile,
  `incident_response` now includes the authority-reporting artefacts in addition to internal incident/corrective-action material,
  and both pack families have explicit manifest/match-rule regression coverage.
- Added end-to-end compliance examples for the new flows:
  `examples/typescript-compliance` demonstrates provider-governance capture and export,
  `examples/python-compliance` demonstrates deployer-side FRIA capture and export,
  `examples/typescript-monitoring` demonstrates post-market monitoring plus authority submission,
  and `examples/python-incident-response` demonstrates incident response plus authority notification/deadline/correspondence.
- Refreshed the onboarding and architecture docs to match implemented behavior:
  `README.md`, `get_started.md`, `docs/architecture.md`, SDK READMEs, and the integrated demo docs now mention the new evidence types, new pack families, the compliance-profile flow, and the new end-to-end examples.
- Revalidated the current matrix after the compliance/gov/export additions:
  `cargo test --workspace`,
  `npm --prefix sdks/typescript test`,
  `PYTHONPATH=packages/sdk-python python3 -m unittest discover -s packages/sdk-python/tests`,
  and `npm --prefix web-demo test` all pass,
  and the new TypeScript/Python monitoring and incident-response examples were also run successfully against a temporary local `proof-service` instance.

Still outstanding from `plan.md`:

- JSON schema coverage is now started, with timestamp and Rekor transparency receipt coverage added, but richer export/archive schemas are still incomplete.
- The vault now uses SQLite with legal-hold-aware retention, audit logging, file/env/runtime configuration, background retention scanning, curated pack export, redacted disclosure-pack export, RFC 3161 bundle timestamp attachment, and transparency anchoring, but PostgreSQL and Annex-complete artefact/redaction policy assembly are not built yet.
- The vault now also supports optional bearer auth with per-principal audit labels on `/v1/*` plus bounded single-tenant org enforcement; broader multi-tenant org isolation and per-query tenant filtering are still future work.
- The vault now exposes a useful Prometheus-style `/metrics` surface, but it still does not emit OTLP traces/metrics, external log shipping, or richer per-route latency histograms.
- SQLite pilots now have matched backup export, optional backup encryption, scheduled local backup rotation, and offline restore/import flows, but there is still no live in-place restore endpoint or remote backup targets.
- TypeScript and Python now both have native FFI bridges, local sealing paths, higher-level `ProofLayer` facades, a local artifact build path for npm tarballs and platform-tagged wheels, and CI-backed multi-platform GitHub artifact builds, but there is still no automated publish step to npm or PyPI.
- TypeScript and Python SDKs now expose local redacted-bundle helpers (`disclose` / `verifyRedactedBundle` in TypeScript, `disclose` / `verify_redacted_bundle` in Python), including top-level field redaction for local v3 bundles and nested JSON-pointer path redaction for local v4 bundles, plus vault pack helpers for `bundle_format = "full" | "disclosure"` with `disclosure_policy` or inline `disclosure_template`, vault disclosure-config read/update helpers, and disclosure-preview helpers.
- Catalog breadth is now strong, and Annex IV plus FRIA minimum-field contracts are machine-assessed; the remaining gap is broader completeness-profile coverage, alongside harder later-phase items like deeper trust-list/evidence-preservation work, alternative storage backends, and automated npm/PyPI/prebuilt release publishing hardening.
- RFC 3161 verification now supports signer-chain validation against configured PEM trust anchors, optional `TSTInfo.policy` OID enforcement, CRL-based revocation checking, optional live OCSP checks, qualified TSA signer allowlist matching, and operational `qualified` profile gating, but full eIDAS-qualified trust-list evaluation and archival OCSP evidence handling are still outstanding.
- Rekor verification now supports SET signature validation, `logID` binding against a configured PEM log public key, and opt-in live-log consistency / freshness checks; broader production hardening and provider expansion remain future work.
- The SCITT path now writes a COSE/CCF-style receipt body by default and keeps legacy JSON verification compatibility, but broader interop and trust-list work are still future work.

## March 21, 2026

Completed:

- Landed the audit-ready Annex IV governance slice:
  `annex_iv` pack curation now excludes retention-only matches, carries stable bundle ordering for the governance set, and preserves match metadata suitable for manifest assertions.
- Narrowed the built-in disclosure default for high-risk governance:
  `annex_iv_redacted` now keeps the full governance inclusion set, includes artefact metadata but not raw artefact bytes by default, and redacts governance metadata plus the sensitive `data_governance` paths for personal-data categories and safeguards.
- Hardened the SDK governance contract:
  TypeScript request types now document the recommended minimum Annex IV fields,
  Python default governance artefacts now mirror the full structured evidence payloads instead of partial subsets,
  and both SDK test suites now lock those artefact shapes in place.
- Added Annex IV vault acceptance coverage:
  dedicated tests now prove the expected governance bundle set, manifest match metadata, deterministic pack ordering, and verifiable disclosure-package exports with preserved nested path redactions.
- Added checked source fixtures and reproducible examples for the hiring-assistant scenario:
  `fixtures/golden/annex_iv_governance/` now records the governance inputs plus expected pack/disclosure summaries,
  `examples/typescript-compliance` now captures the full Annex IV governance workflow and exports both full and disclosure packs,
  and `examples/python-annex-iv` provides the matching Python walkthrough while preserving the older FRIA example separately.
- Landed advisory Annex IV readiness/completeness evaluation across the stack:
  Rust core now ships `annex_iv_governance_v1`,
  `proofctl` now exposes `assess`,
  the vault now exposes `POST /v1/completeness/evaluate` and attaches completeness summary fields to `annex_iv` pack manifests,
  TypeScript/Python now expose `evaluateCompleteness` / `evaluate_completeness`,
  and `web-demo` now shows a readiness check card for Annex IV-oriented runs.
