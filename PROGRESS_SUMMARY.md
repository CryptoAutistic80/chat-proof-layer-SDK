# Progress Summary

Last updated: 2026-03-02

## Executive Summary

The Proof Layer PoC has been built end-to-end across Rust core, service, CLI, Node SDK, Python SDK, demo UI, examples, Docker packaging, and docs. The project now produces and verifies signed proof bundles with deterministic canonicalization and cross-language fixture coverage.

## What Has Been Accomplished

### 1) Core cryptography and integrity engine (`packages/core-rust`)

Implemented:
- Strict JSON parsing path with duplicate-key rejection for untrusted input.
- Deterministic RFC 8785-style canonicalization output path.
- SHA-256 digest helpers (`sha256:<hex>` format + strict parser).
- Merkle commitment algorithm `pl-merkle-sha256-v1`:
  - Leaf hash: `H(0x00 || digest_bytes)`
  - Parent hash: `H(0x01 || left || right)`
  - Odd-node duplication per level.
- Ed25519 JWS signing and strict verification (`verify_strict()`).
- Bundle build/verify flow with typed errors and tamper detection.

Key outcomes:
- Header digest, bundle root, and signature are deterministic for fixed inputs.
- Verification fails closed on malformed digest/signature/algorithm fields.

### 2) Proof service (`packages/proof-service`)

Implemented:
- Axum service with endpoints:
  - `GET /healthz`
  - `POST /v1/bundles`
  - `GET /v1/bundles/:bundle_id`
  - `GET /v1/bundles/:bundle_id/artefacts/:name`
  - `POST /v1/verify`
- Persistence with `sled` for metadata/indexes + filesystem artefact storage.
- Atomic artefact write pattern and payload/artefact size limits.
- `/v1/verify` supports both modes:
  - Inline bundle + artefacts
  - Package mode (`bundle_pkg_base64`)
- Package/manifest validation checks (duplicates, unlisted files, mismatches).
- CORS enabled for web-demo interoperability.

### 3) CLI (`packages/cli` / `proofctl`)

Implemented commands:
- `keygen` (dev Ed25519 keypair generation)
- `create` (build `bundle.pkg` from capture + artefacts)
- `verify` (offline verification with package + public key)
- `inspect` (human/JSON bundle inspection)

Implemented safeguards:
- Shared payload size limits.
- Path traversal rejection for artefact names.
- Package member allowlist checks.
- Manifest integrity checks.

### 4) Node SDK (`packages/sdk-node`)

Implemented:
- Proof service client (`createBundle`, `getBundle`, `getArtefact`, `verifyBundle`, `verifyPackage`).
- OpenAI-like and Anthropic-like wrapper helpers.
- Tool-call capture helper.
- OTel GenAI export helper.
- Unit tests for client/wrappers and golden fixture verification.

### 5) Python SDK (`packages/sdk-python`)

Implemented:
- Proof service client with parity to Node behavior.
- OpenAI-like and Anthropic-like wrappers.
- Decorator and LangChain-like callback helper surface.
- Tool capture + OTel export helper.
- Unit tests for client/wrappers and golden fixture verification.

### 6) Cross-language deterministic verification fixtures

Added and validated:
- Pinned golden fixtures under `fixtures/golden/`.
- Fixed bundle artefacts + expected digests/signature values.
- Cross-language assertions in Rust, Node, and Python.
- RFC canonicalization vector suite (`fixtures/golden/rfc8785_vectors.json`) validated in:
  - Rust tests
  - Node tests (`json-canonicalize`)
  - Python tests (`rfc8785`)

Result:
- Canonicalization and integrity calculations are now explicitly tested for cross-runtime drift.

### 7) Demo and examples

Implemented:
- `web-demo` React/Vite app with run + seal flow and optional verify.
- Example scripts:
  - `examples/node-basic`
  - `examples/python-basic`
  - `examples/agent-simulated`

### 8) Docker and local deployment

Implemented:
- Multi-stage `Dockerfile`.
- `docker-compose.yml` with service startup path.
- `.dockerignore`.

Validated:
- Compose config/build/up/down + health endpoint checks.

### 9) Documentation updates

Completed docs:
- `README.md` expanded with plain-English purpose/how-it-works.
- `docs/architecture.md` aligned with `sled` service architecture and package verify mode.
- `docs/proof_bundle_schema.md` aligned with gzip JSON `bundle.pkg` format.
- `docs/threat_model.md` updated to reflect controls and phase ownership.
- `docs/verification-test-matrix.md` now marks `V-001` through `V-019` implemented.

## Verification and Quality Gates Run

Executed successfully during implementation:
- `cargo fmt --all --check`
- `cargo check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cd packages/sdk-node && npm test`
- `cd packages/sdk-python && python -m unittest discover -s tests -v` (via venv)
- Docker compose config/build/smoke health checks

## Current Status Against Plan Gates

- Phase 1 gate: Met
  - Deterministic canonical bytes/digests/root/signature with tamper tests.
- Phase 2 gate: Met
  - Service uses same core crate, has payload limits, and package verify mode.
- Phase 5 gate: Met
  - Offline `create/verify/inspect` with explicit failure paths.
- Docs prerequisite: Met
  - Architecture/schema/threat model docs present and aligned.

## Known PoC Boundaries (Intentional)

Still out of scope by design:
- RFC 3161 trusted timestamping (stub only)
- Transparency receipt integration (SCITT/Sigstore)
- HSM/KMS-backed signing keys
- WORM/object-lock persistence model
- Policy-driven encryption/redaction enforcement

## Suggested Next Milestones

1. Add CI workflows to enforce all gates on every push.
2. Add fuzz/property tests for canonicalization and package parsing.
3. Add signing key rotation and key-id trust policy docs.
4. Add optional timestamp/receipt plugin interfaces behind feature flags.
