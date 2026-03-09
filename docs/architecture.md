# AI Output Proof Layer Architecture

## Scope

This document defines the PoC architecture for:

- Phase 1: Rust core cryptography and canonicalization
- Phase 2: Axum proof service with SQLite persistence
- Phase 5: `proofctl` offline create/verify/inspect workflows plus vault-backed pack export
- Phase 9: TypeScript and Python native bindings over the Rust core

The goal is cryptographically verifiable evidence artifacts for AI interactions, not legal proof claims.

## System Overview

The system has four main layers:

1. Provider adapters (TypeScript/Python SDKs) capture request/response/tool events.
2. Proof service (Axum) validates capture payloads, stores artifacts, constructs proof bundles, and assembles export packs.
3. Rust core implements canonicalization, hashing, Merkle commitment, signing, and verification.
4. `proofctl` performs offline package creation, inspection, verification, and pack download.

`POST /v1/verify` accepts either inline bundle payloads or a packaged `bundle.pkg` (base64).

## Components

### `crates/core`

Single-purpose modules:

- `canon/mod.rs`
- `hash.rs`
- `merkle/mod.rs`
- `schema/mod.rs`
- `sign/mod.rs`
- `verify.rs`

Core defaults:

- Canonicalization: deterministic RFC 8785-style canonical JSON writer in `crates/core/src/canon/mod.rs`
- Hash: SHA-256 (`sha2`)
- Signature: Ed25519 (`ed25519-dalek` 2.2.x, `verify_strict()`)
- IDs: ULID

### `crates/vault` (`proof-service`)

- Runtime: Rust + Axum
- Metadata persistence: SQLite via `sqlx`
- Artifact storage: local filesystem at `./storage/artefacts/{bundle_id}/{name}`
- CORS enabled for local web demo interoperability
- Current query surface: `GET /v1/bundles?system_id=&role=&type=&has_timestamp=&has_receipt=&assurance_level=&from=&to=&page=&limit=`
- System rollup surface: `GET /v1/systems`, `GET /v1/systems/{id}/summary`
- Retention operations: `DELETE /v1/bundles/{id}`, `POST /v1/bundles/{id}/legal-hold`, `DELETE /v1/bundles/{id}/legal-hold`, `GET /v1/retention/status`, `POST /v1/retention/scan`
- Timestamp operation: `POST /v1/bundles/{id}/timestamp`
- Transparency operation: `POST /v1/bundles/{id}/anchor`
- Assurance verification operations: `POST /v1/verify/timestamp`, `POST /v1/verify/receipt`
- Audit operations: `GET /v1/audit-trail?action=&bundle_id=&pack_id=&page=&limit=`
- Configuration operations: `GET /v1/config`, `PUT /v1/config/retention`, `PUT /v1/config/timestamp`, `PUT /v1/config/transparency`, `PUT /v1/config/disclosure`
- Disclosure template operations: `GET /v1/disclosure/templates`, `POST /v1/disclosure/templates/render`
- Disclosure authoring preview: `POST /v1/disclosure/preview`
- Pack export operations: `POST /v1/packs`, `GET /v1/packs/{id}`, `GET /v1/packs/{id}/manifest`, `GET /v1/packs/{id}/export`

Current SQLite tables:

- `bundles`: top-level bundle metadata plus serialized bundle JSON, canonical header bytes, expiry timestamps, soft-delete markers, and legal-hold state
- `evidence_items`: one row per evidence item for type-based filtering plus derived `obligation_ref` tags
- `artefacts`: stored artefact metadata and blob paths
- `retention_policies`: seeded retention schedules used to compute `expires_at`
- `service_config`: persisted JSON-backed runtime config for timestamp/transparency providers
- `audit_log`: append-only request/action trail with bundle/pack linkage and JSON details
- `packs`: pack manifests and export paths

### `crates/cli` (`proofctl`)

- `keygen`: generate dev key pairs
- `create`: build `bundle.pkg` from capture JSON + artifacts
- `disclose`: build item-level redacted disclosure packages with Merkle proofs
- `verify`: offline integrity and signature verification for full and disclosure packages
- `inspect`: human/JSON diagnostics
- `pack`: request a vault export pack and write the archive locally, with `full` or `disclosure` bundle members
- `vault status|metrics|backup|restore|query|retention|systems|export`: thin CLI wrappers over the vault HTTP query/export surfaces

Current pack export behavior:

- Vault pack assembly uses a heuristic curation profile (`pack-rules-v1`).
- Selection currently keys off actor role, evidence item type, retention class, and derived obligation references.
- Implemented pack families now include `conformity` alongside the Annex/runtime/risk/GPAI slices.
- Exported pack archives can now contain either full `bundle.pkg` members or redacted disclosure packages, selected with `bundle_format = "full" | "disclosure"` on pack creation.
- Disclosure-pack exports now also accept a named `disclosure_policy`, defaulting by pack type (`regulator_minimum`, `annex_iv_redacted`, `incident_summary`) and applying item-type filters plus optional artefact-metadata and artefact-byte inclusion during redaction.
- Disclosure policies can now also filter selected items by obligation reference, apply per-item-type top-level field redactions for `pl-merkle-sha256-v3` bundles, apply nested JSON-pointer path redactions for `pl-merkle-sha256-v4` bundles, and the vault exposes a preview endpoint so named or inline policies can be evaluated against a stored bundle before pack export.
- The vault now also exposes a built-in disclosure-template catalog plus a render endpoint, so CLI/SDK clients can fetch the service’s starter profiles (`regulator_minimum`, `annex_iv_redacted`, `incident_summary`, `runtime_minimum`, `privacy_review`) and render starter policy JSON with reusable redaction-group overlays before saving it into config or using it inline.
- `POST /v1/packs` and `POST /v1/disclosure/preview` now also accept inline `disclosure_template` render requests, so clients can drive export or preview directly from a built-in template profile plus optional redaction groups without persisting a named policy first.
- Current path-level disclosure covers nested `item.data` JSON-pointer leaves and subtrees; richer semantic policy authoring beyond those selectors is still a later phase.

Current retention behavior:

- Bundle creation computes `expires_at` from the retention policy table.
- Manual `DELETE /v1/bundles/{id}` is a soft-delete and is blocked by active legal holds.
- `POST /v1/retention/scan` soft-deletes expired active bundles, skips held bundles, and hard-deletes soft-deleted bundles once `deleted_at + grace_period` has passed.

Current audit behavior:

- Vault writes append-only audit rows for create/read/verify/delete/legal-hold/retention-scan, assurance verification, and pack operations.
- Audit rows use configured API-key principal labels for authenticated `/v1/*` requests and still use `system` for startup sync / background retention work.
- Audit logging is stored in SQLite and queryable through `GET /v1/audit-trail`.

Current config behavior:

- `proof-service` now supports startup config from `./vault.toml` or `PROOF_SERVICE_CONFIG_PATH`, with env vars overriding file values.
- `proof-service` can now also serve HTTPS directly when `[server].tls_cert` + `[server].tls_key` or `PROOF_SERVICE_TLS_CERT_PATH` + `PROOF_SERVICE_TLS_KEY_PATH` are configured.
- `proof-service` can also require bearer auth on `/v1/*` when `[auth]` / `[[auth.api_keys]]` or `PROOF_SERVICE_API_KEY` are configured; `/healthz` and `/readyz` stay open.
- `proof-service` now also exposes `/metrics` in Prometheus text format for infra scraping, with gauges derived from current SQLite bundle/pack/audit state plus auth/TLS/tenant runtime flags.
- `proof-service` now also exposes authenticated `POST /v1/backup`, which returns a `.tar.gz` archive containing a consistent SQLite snapshot (`VACUUM INTO`), the current non-secret config view, and filesystem blobs/pack exports for one-shot pilot backup/export.
- `proofctl vault restore` now provides the matching offline import path for that archive format, restoring into a fresh local directory instead of mutating a live service in place.
- `proof-service` can also enforce a single organization scope when `[tenant].organization_id` or `PROOF_SERVICE_ORGANIZATION_ID` is configured; new captures inherit that `actor.organization_id` when omitted, mismatches are rejected, and startup fails if stored bundles already belong to a different organization.
- `GET /v1/config` returns the active service view for payload limits, bound address, TLS enabled state, auth enabled state/principal labels, tenant enforcement state, signing algorithm/key id, storage backends, retention grace period, retention policies, and persisted timestamp/transparency provider settings.
- `GET /v1/config` also reports the retention scan interval currently active in the process.
- `PUT /v1/config/retention` upserts retention policy rows in SQLite.
- Retention policies now carry an `expiry_mode`; `fixed_days` computes `expires_at`, while `until_withdrawn` leaves bundles active until an explicit withdrawal/delete event.
- `PUT /v1/config/timestamp` persists RFC 3161 provider configuration (`enabled`, `provider`, `url`, optional `assurance`) plus optional PEM trust anchors, PEM CRLs, live OCSP responder URLs, qualified TSA signer allowlists, and expected RFC 3161 policy OIDs used for trust-aware timestamp verification.
- `PUT /v1/config/transparency` persists transparency provider configuration (`none`, `rekor`, `scitt`) plus URL when applicable and an optional transparency-service PEM public key for trust-aware receipt verification.
- `PUT /v1/config/disclosure` persists named disclosure-policy profiles used by disclosure-pack exports. Policies currently support allowed item types, excluded item types, allowed obligation refs, excluded obligation refs, `include_artefact_metadata`, `include_artefact_bytes`, and optional artefact-name allowlists.
- `GET /v1/disclosure/templates` returns the built-in disclosure-template catalog and reusable redaction-group descriptions, while `POST /v1/disclosure/templates/render` materializes starter policy JSON from a chosen template profile plus optional group overlays and explicit field/path selectors.
- `POST /v1/packs` and `POST /v1/disclosure/preview` also accept inline `disclosure_template` render requests, allowing operators to use built-in template profiles plus optional group overlays directly at export/preview time without storing a named policy first.
- Startup file config is synchronized into SQLite for retention/timestamp/transparency so the API view matches the current boot configuration.
- `POST /v1/bundles/{id}/timestamp` loads a stored active bundle, requests an RFC 3161 token over the UTF-8 bytes of `integrity.bundle_root`, stores the token in bundle JSON, and flips `has_timestamp`.
- `POST /v1/bundles/{id}/anchor` loads a stored active timestamped bundle and submits it to the configured transparency provider. For Rekor it sends an `rfc3161` entry; for the current SCITT path it sends a canonical JSON statement containing `{profile, bundle_root, timestamp}` and stores the returned service-signed receipt in bundle JSON.
- `POST /v1/verify/timestamp` and `POST /v1/verify/receipt` accept either direct assurance artefacts or a stored `bundle_id`, returning typed verification details without requiring full package verification.
- Local `proofctl create --timestamp-url/--transparency-log` now uses the same trust-policy helpers as verify mode, and `--transparency-provider <rekor|scitt>` selects the local receipt path, so assurance attachment can fail early when configured assurance profiles, anchors, CRLs, OCSP responder URLs, signer pins, policy OIDs, or transparency public keys do not match the returned artefacts.
- When timestamp trust anchors are configured, the vault verifies the RFC 3161 signer certificate chain against those anchors at `genTime`.
- When timestamp CRLs are configured, the vault also verifies that the applicable CRL is valid at `genTime`, signed by the issuer certificate, and does not revoke the TSA signer certificate.
- When timestamp OCSP responder URLs are configured, the vault also performs a live OCSP request for the TSA signer certificate, verifies the OCSP response signature against the configured trust anchors, requires the OCSP response itself to be current, and treats the signer as invalid only when the responder reports a revocation time at or before `genTime`.
- When timestamp policy OIDs are configured, the vault also requires the token `TSTInfo.policy` OID to match one of those values.
- When `timestamp.assurance == "qualified"`, the vault requires trust anchors, CRLs, expected policy OIDs, and a configured TSA signer allowlist to be present and satisfied, and it also enforces a TSA signer certificate profile suitable for time stamping, treating the result as a stricter qualified-profile check rather than a claim of full eIDAS qualified status.
- When a transparency public key is configured, the vault verifies provider-specific receipt signatures. For Rekor it verifies the signed-entry-timestamp over the canonical Rekor payload and requires `logID == sha256(SPKI_DER(public_key))`. For the current SCITT path it verifies the service signature over canonical `{entryId, registeredAt, serviceId, statementHash}` and requires `serviceId == sha256(SPKI_DER(public_key))`.
- When an updated retention policy remains active, the vault recomputes `expires_at` for existing active bundles in that class.
- The seeded `gpai_documentation` class uses `until_withdrawn`, and the GPAI SDK builders default to that class for `model_evaluation`, `adversarial_test`, and `training_provenance`.
- Transparency config is active for both Rekor RFC 3161 anchoring and the current draft-aligned SCITT statement/receipt flow. Full interoperable COSE/CCF SCITT remains future work.
- The retention engine now supports both manual `POST /v1/retention/scan` and an automatic background scan interval configured via file/env.
- `GET /v1/systems` summarizes bundle counts per `system_id`, and `GET /v1/systems/{id}/summary` expands that into role/item/retention/assurance/model breakdowns for operator-facing inventory views.

### `sdks/typescript` and `packages/sdk-python`

- `sdks/typescript` is the current TypeScript npm SDK package (`@proof-layer/sdk`).
- Its runtime loads a local NAPI module compiled from `crates/napi`.
- The first native TypeScript surface covers RFC 8785 canonicalization, SHA-256 digesting, Merkle root computation, Ed25519 JWS sign/verify, deterministic local bundle construction, and offline bundle verification.
- The package now has a shared `evidence.ts` surface for v1 `llm_interaction` capture assembly, so wrappers and direct callers seal the same bundle shape.
- The package now exposes both an HTTP vault client and a `LocalProofLayerClient` that seals bundles locally via the native module.
- The package now also exposes first-class typed helpers for all evidence item types currently implemented in Rust core, including `captureToolCall(...)`, `captureRetrieval(...)`, `captureHumanOversight(...)`, `capturePolicyDecision(...)`, `captureRiskAssessment(...)`, `captureDataGovernance(...)`, `captureTechnicalDoc(...)`, `captureModelEvaluation(...)`, `captureAdversarialTest(...)`, `captureTrainingProvenance(...)`, `captureLiteracyAttestation(...)`, `captureIncidentReport(...)`, `captureConformityAssessment(...)`, `captureDeclaration(...)`, and `captureRegistration(...)`.
- The package also now exposes a higher-level `ProofLayer` facade plus provider-specific `withProofLayer(...)` wrappers for OpenAI-like, Anthropic-like, generic async clients, and Vercel-AI-style functions.
- The TypeScript SDK now exposes `ProofLayerExporter` and OTel helpers under `@proof-layer/sdk/otel`.
- The TypeScript provider wrappers and tool helpers now call that shared surface for integrity-sensitive operations instead of reimplementing them in JavaScript.
- The repo now includes a local artifact smoke path for the TypeScript SDK: `npm run pack:smoke` builds the NAPI-backed package, produces an npm tarball under `sdks/typescript/dist/artifacts`, and verifies that the tarball contains compiled `dist/*` output plus `native/proof-layer-napi.node`. `PROOF_SDK_NATIVE_PROFILE=release` is used by default for artifact packaging.
- `packages/sdk-python` now loads a local PyO3 module compiled from `crates/pyo3` via the package build helper.
- The first native Python surface matches Node: canonicalization, SHA-256 digesting, Merkle root computation, Ed25519 JWS sign/verify, deterministic local bundle construction, and offline bundle verification.
- `packages/sdk-python` now exposes both an HTTP vault client and a `LocalProofLayerClient` that seals bundles locally via the native module.
- The Python package now also exposes a higher-level `ProofLayer` facade, shared `evidence.py` request builders for all evidence item types currently implemented in Rust core, and provider-specific `with_proof_layer(...)` wrappers for OpenAI-like and Anthropic-like clients, including GPAI evaluation/provenance/test evidence, Art 4 literacy attestations, incident-report lifecycle evidence, and the conformity/declaration/registration group.
- The Python provider wrappers, decorator helpers, and golden fixture tests now route integrity-sensitive operations through that shared Rust implementation.
- The repo now also includes a local wheel build path for the Python SDK: `python3 ./scripts/build_dist.py` builds the native PyO3 extension during wheel creation, emits a platform-tagged wheel under `packages/sdk-python/dist`, and verifies that the wheel contains `proofsdk/_native*` plus the typed package markers. Artifact packaging defaults to `PROOF_SDK_NATIVE_PROFILE=release`.
- `.github/workflows/sdk-artifacts.yml` now runs those npm tarball and Python wheel builds across Linux, macOS, and Windows on PRs, pushes, and manual dispatch; `.github/workflows/sdk-release.yml` rebuilds them and attaches the results to GitHub releases for `sdk-v*` tags.
- Tool capture and OTel GenAI export helpers for trace pipelines.
- Provider adapters remain thin and provider-shaped; integrity semantics stay in Rust core/service.

## Bundle Construction Flow (Authoritative)

1. Receive capture payload and artifact blobs.
2. Validate schema and size limits.
3. Persist artifact files via temp-file write + `fsync` + atomic rename.
4. Compute each artifact digest as `sha256:<lower_hex>`.
5. Build canonical header projection from validated payload.
6. Canonicalize header projection via RFC 8785 (strict path for untrusted raw JSON).
7. Compute `header_digest = sha256(canonical_header_bytes)`.
8. Compute `bundle_root` from the ordered digest list for the selected commitment model:
   - current default (`pl-merkle-sha256-v4`): `[header_digest, item_digest_1, ..., artefact_meta_digest_1, ...]`, where each `item_digest_n = sha256(RFC8785({"item_type": item.type, "container_kinds": {...}, "path_digests": {...}}))`
   - compatibility verification (`pl-merkle-sha256-v3`): `[header_digest, item_digest_1, ..., artefact_meta_digest_1, ...]`, where each `item_digest_n = sha256(RFC8785({"item_type": item.type, "field_digests": {...}}))`
   - compatibility verification (`pl-merkle-sha256-v2`): `[header_digest, item_digest_1, ..., artefact_meta_digest_1, ...]`, where each `item_digest_n = sha256(RFC8785(item_json))`
   - legacy verification (`pl-merkle-sha256-v1`): `[header_digest, artefact_digest_1, artefact_digest_2, ...]`
9. Sign UTF-8 bytes of `bundle_root` using Ed25519 JWS compact serialization.
10. Persist bundle metadata + indexes in SQLite and artifact bytes on disk.
11. Optionally request an RFC 3161 token over UTF-8 `bundle_root` bytes.
12. Optionally submit that RFC 3161 token to the configured transparency provider and store the returned receipt.
13. Return `bundle_id`, `bundle_root`, signature metadata, and optional assurance artefacts.

## Deterministic Byte-Level Contracts

- Canonicalization input: canonical header projection JSON bytes.
- Canonicalization output: RFC 8785 UTF-8 JSON bytes.
- `header_digest`: SHA-256 over canonical header bytes, formatted `sha256:<64 lower hex>`.
- Current default canonical header projection fields: `bundle_version`, `bundle_id`, `created_at`, `actor`, `subject`, `context`, `policy`, `item_count`, `artefact_count`.
- Legacy canonical header projection additionally included full `items` and `artefacts`.
- Current default Merkle leaves: `header_digest`, then one digest per evidence item commitment projection (`item_type` + per-field digests), then one digest per canonicalized artefact metadata record.
- Legacy Merkle leaves: `header_digest`, then one digest per artefact byte payload.
- Merkle leaves are parsed raw 32-byte digest values, never hex strings.
- Leaf hash: `H(0x00 || digest_bytes)`.
- Parent hash: `H(0x01 || left_hash || right_hash)`.
- Odd leaf count: duplicate last node at each odd level.
- `bundle_root`: `sha256:<hex(root_hash)>`.
- JWS payload: UTF-8 bytes of `bundle_root` string.

Signing input and verification input must be byte-identical.

## Canonicalization Rules and Constraints

- Reject duplicate object keys from untrusted raw JSON.
- Reject non-finite numbers and invalid numeric encodings.
- Constrain numeric precision in schema/tests to avoid cross-language drift.
- Do not canonicalize from loosely typed maps when strict raw input is available.

## Key Management

- Signing keys loaded from file or environment variables.
- Public verification keys distributed out-of-band.
- No hardcoded keys in source, tests, or configs.
- Key IDs (`kid`) included in signature metadata.

## Offline Verification Contract

A verifier needs only:

- `bundle.pkg`
- issuer public key

No network calls are required for core verification.
Timestamp and transparency checks are optional in PoC and report as skipped/missing when not requested.
If OCSP responder URLs are configured, the optional timestamp trust check becomes a live networked verification step.
Current assurance verification checks bundle-root binding, embedded RFC 3161 token validity, optional RFC 3161 policy OID constraints, optional timestamp assurance profiles (`standard` / `qualified`), optional CRL-based TSA revocation checks, optional live OCSP checks, optional qualified TSA signer allowlist matching, Rekor entry UUID to leaf-hash binding, Rekor inclusion proofs against the advertised root hash, and the current draft-aligned SCITT statement/receipt contract; it can optionally verify TSA signer chains and provider receipt signatures when trust material is configured.

Current selective-disclosure verification is also offline for `pl-merkle-sha256-v2`, `pl-merkle-sha256-v3`, and `pl-merkle-sha256-v4` bundles: `proofctl disclose` emits a redacted bundle carrying a header inclusion proof plus inclusion proofs for each disclosed item, and `proofctl verify` can validate that package without access to the original full bundle. On v3 bundles, repeatable `--redact-field <item_index>:<field>` hides selected top-level item fields; on v4 bundles, repeatable `--redact-field <item_index>:<field-or-json-pointer>` can also hide nested item-data paths while preserving item-leaf verification.

## Provider-Agnostic Boundary

Provider adapters capture and normalize provider-specific payloads, but must not change cryptographic logic.
All integrity operations must remain in the shared Rust core.

## Non-Determinism Statement

LLM outputs are non-deterministic.
The proof layer records what happened in one execution and produces verifiable evidence for that execution.
It does not claim model replay determinism.

## Security Baseline Controls

- Request and artifact size limits enforced in service and CLI.
- Artifact digest verification must occur before trust decisions.
- Plaintext artifact contents are not logged by default.
- Verification fails closed on malformed digests/signatures/algorithms.

## Out of Scope for PoC

- Full eIDAS qualified trust-list evaluation and archival OCSP evidence handling
- Full interoperable COSE/CCF SCITT
- HSM/KMS-backed keys
- WORM/cloud object lock
- Policy-driven encryption/redaction enforcement
