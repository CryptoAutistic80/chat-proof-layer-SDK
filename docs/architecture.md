# AI Output Proof Layer Architecture

## Scope

This document defines the PoC architecture for:

- Phase 1: Rust core cryptography and canonicalization
- Phase 2: Axum proof service with SQLite persistence
- Phase 5: `proofctl` offline create/verify/inspect workflows plus vault-backed pack export

The goal is cryptographically verifiable evidence artifacts for AI interactions, not legal proof claims.

## System Overview

The system has four main layers:

1. Provider adapters (Node/Python SDKs) capture request/response/tool events.
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
- Current query surface: `GET /v1/bundles?system_id=&role=&type=&from=&to=&page=&limit=`
- Retention operations: `DELETE /v1/bundles/{id}`, `POST /v1/bundles/{id}/legal-hold`, `DELETE /v1/bundles/{id}/legal-hold`, `GET /v1/retention/status`, `POST /v1/retention/scan`
- Audit operations: `GET /v1/audit-trail?action=&bundle_id=&pack_id=&page=&limit=`
- Configuration operations: `GET /v1/config`, `PUT /v1/config/retention`, `PUT /v1/config/timestamp`, `PUT /v1/config/transparency`
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
- `verify`: offline integrity and signature verification
- `inspect`: human/JSON diagnostics
- `pack`: request a vault export pack and write the archive locally

Current pack export behavior:

- Vault pack assembly uses a heuristic curation profile (`pack-rules-v1`).
- Selection currently keys off actor role, evidence item type, retention class, and derived obligation references.
- Exported pack archives still contain full `bundle.pkg` members; redaction/selective disclosure is a later phase.

Current retention behavior:

- Bundle creation computes `expires_at` from the retention policy table.
- Manual `DELETE /v1/bundles/{id}` is a soft-delete and is blocked by active legal holds.
- `POST /v1/retention/scan` soft-deletes expired active bundles, skips held bundles, and hard-deletes soft-deleted bundles once `deleted_at + grace_period` has passed.

Current audit behavior:

- Vault writes append-only audit rows for create/read/verify/delete/legal-hold/retention-scan and pack operations.
- Audit rows currently use service-side actor labels (`api`, `system`) because authn/authz is not implemented yet.
- Audit logging is stored in SQLite and queryable through `GET /v1/audit-trail`.

Current config behavior:

- `GET /v1/config` returns the active service view for payload limits, signing algorithm/key id, storage backends, retention grace period, retention policies, and persisted timestamp/transparency provider settings.
- `PUT /v1/config/retention` upserts retention policy rows in SQLite.
- `PUT /v1/config/timestamp` persists RFC 3161 provider configuration (`enabled`, `provider`, `url`, optional `assurance`) for future timestamp issuance/verification work.
- `PUT /v1/config/transparency` persists transparency provider configuration (`none`, `rekor`, `scitt`) plus URL when applicable.
- When an updated retention policy remains active, the vault recomputes `expires_at` for existing active bundles in that class.
- Assurance config is control-plane only today; enabling timestamp or transparency in config does not yet attach tokens/receipts to bundles.

### `packages/sdk-node` and `packages/sdk-python`

- Thin provider wrappers for OpenAI/Anthropic-style calls.
- Tool capture and OTel GenAI export helpers for trace pipelines.
- Provider adapters remain non-cryptographic; integrity semantics stay in Rust core/service.

## Bundle Construction Flow (Authoritative)

1. Receive capture payload and artifact blobs.
2. Validate schema and size limits.
3. Persist artifact files via temp-file write + `fsync` + atomic rename.
4. Compute each artifact digest as `sha256:<lower_hex>`.
5. Build canonical header projection from validated payload (`context`, typed `items`, artefact refs, and policy).
6. Canonicalize header projection via RFC 8785 (strict path for untrusted raw JSON).
7. Compute `header_digest = sha256(canonical_header_bytes)`.
8. Compute `bundle_root` from ordered digest list:
   - `[header_digest, artefact_digest_1, artefact_digest_2, ...]`
9. Sign UTF-8 bytes of `bundle_root` using Ed25519 JWS compact serialization.
10. Persist bundle metadata + indexes in SQLite and artifact bytes on disk.
11. Return `bundle_id`, `bundle_root`, signature metadata, and timestamp.

## Deterministic Byte-Level Contracts

- Canonicalization input: canonical header projection JSON bytes.
- Canonicalization output: RFC 8785 UTF-8 JSON bytes.
- `header_digest`: SHA-256 over canonical header bytes, formatted `sha256:<64 lower hex>`.
- Merkle leaves: parsed raw 32-byte digest values, never hex strings.
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
Timestamp and transparency checks are optional in PoC and report as skipped/missing.

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

- RFC 3161 trusted timestamping (stub only)
- SCITT/Sigstore transparency receipts
- HSM/KMS-backed keys
- WORM/cloud object lock
- Policy-driven encryption/redaction enforcement
