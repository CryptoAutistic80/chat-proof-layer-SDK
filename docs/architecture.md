# AI Output Proof Layer Architecture (PoC v0.1)

## Scope

This document defines the PoC architecture for:

- Phase 1: Rust core cryptography and canonicalization
- Phase 2: Axum proof service with `sled` persistence
- Phase 5: `proofctl` offline create/verify/inspect workflows

The goal is cryptographically verifiable evidence artifacts for AI interactions, not legal proof claims.

## System Overview

The system has four main layers:

1. Provider adapters (Node/Python SDKs) capture request/response/tool events.
2. Proof service (Axum) validates capture payloads, stores artifacts, and constructs proof bundles.
3. Rust core implements canonicalization, hashing, Merkle commitment, signing, and verification.
4. `proofctl` performs offline package creation, inspection, and verification.

`POST /v1/verify` accepts either inline bundle payloads or a packaged `bundle.pkg` (base64).

## Components

### `packages/core-rust`

Single-purpose modules:

- `canonicalize.rs`
- `hash.rs`
- `merkle.rs`
- `sign.rs`
- `verify.rs`

Core defaults:

- Canonicalization: deterministic RFC 8785-style canonical JSON writer in `core-rust` (`canonicalize.rs`)
- Hash: SHA-256 (`sha2`)
- Signature: Ed25519 (`ed25519-dalek` 2.2.x, `verify_strict()`)
- IDs: ULID

### `packages/proof-service`

- Runtime: Rust + Axum
- Metadata persistence: `sled`
- Artifact storage: local filesystem at `./storage/artefacts/{bundle_id}/{name}`
- CORS enabled for local web demo interoperability

Suggested `sled` trees:

- `bundles_by_id`: `bundle_id -> proof_bundle.json bytes`
- `idx_request_id`: `request_id|bundle_id -> bundle_id`
- `idx_created_at`: `created_at|bundle_id -> bundle_id`
- `idx_app_id`: `app_id|created_at|bundle_id -> bundle_id`

### `packages/cli` (`proofctl`)

- `keygen`: generate dev key pairs
- `create`: build `bundle.pkg` from capture JSON + artifacts
- `verify`: offline integrity and signature verification
- `inspect`: human/JSON diagnostics

### `packages/sdk-node` and `packages/sdk-python`

- Thin provider wrappers for OpenAI/Anthropic-style calls.
- Tool capture and OTel GenAI export helpers for trace pipelines.
- Provider adapters remain non-cryptographic; integrity semantics stay in Rust core/service.

## Bundle Construction Flow (Authoritative)

1. Receive capture payload and artifact blobs.
2. Validate schema and size limits.
3. Persist artifact files via temp-file write + `fsync` + atomic rename.
4. Compute each artifact digest as `sha256:<lower_hex>`.
5. Build canonical header projection from validated payload.
6. Canonicalize header projection via RFC 8785 (strict path for untrusted raw JSON).
7. Compute `header_digest = sha256(canonical_header_bytes)`.
8. Compute `bundle_root` from ordered digest list:
   - `[header_digest, artefact_digest_1, artefact_digest_2, ...]`
9. Sign UTF-8 bytes of `bundle_root` using Ed25519 JWS compact serialization.
10. Persist bundle + indexes in one `sled::Batch`, then `flush()`.
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
