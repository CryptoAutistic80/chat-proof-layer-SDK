# Threat Model (PoC v0.1)

## Objective

Define realistic threats for the PoC proof layer and map each to concrete controls and phase ownership.
Priority is protecting evidence integrity, key material, and verifier trust.

## System Context

Main components:

- SDK adapters (Node/Python) capture provider interactions.
- Proof service (Axum) receives capture payloads and artifact blobs.
- Rust core computes canonicalization/digests/Merkle/signature.
- `sled` stores bundle metadata and indexes.
- Filesystem stores artifact blobs.
- `proofctl` verifies bundles offline.

## Security Goals

1. Detect tampering of headers, artifacts, and signatures.
2. Ensure signatures are produced and verified against deterministic bytes.
3. Prevent key leakage and unauthorized signing.
4. Prevent accidental trust in malformed/ambiguous inputs.
5. Keep proof verification possible without network dependency.

## Non-Goals (PoC)

- Trusted timestamp and transparency ecosystem guarantees
- KMS/HSM-backed key custody
- Full legal/evidentiary chain-of-custody standards

## Assets

- Signing private key
- Public verification key distribution channel
- Canonical header bytes and `header_digest`
- Artifact blobs and digests
- `bundle_root` and JWS signature
- Metadata store (`sled`) and indexes
- Verification logic in service and CLI

## Trust Boundaries

1. Untrusted client -> proof service HTTP boundary
2. Service process -> local disk (`sled` + artifacts)
3. Service process -> key material file/env
4. Bundle package -> external verifier

## Attacker Model

Assume attacker may:

- Submit malformed or adversarial JSON payloads
- Modify stored artifacts or metadata at rest
- Replay requests or resubmit stale bundles
- Swap keys/signatures or inject malformed JWS values
- Attempt denial of service via large payloads

Assume attacker does not have:

- Direct root access to host OS in baseline PoC threat assumptions
- Ability to break SHA-256 or Ed25519 primitives

## Threat Register

| ID | Threat | Impact | Mitigation | Residual Risk | Phase Owner |
|---|---|---|---|---|---|
| T1 | Duplicate JSON keys bypass canonical intent | Signature may attest ambiguous semantics | Strict raw JSON parsing path with duplicate-key rejection before `serde_json::Value` conversion | Medium | Phase 1 |
| T2 | Non-finite/edge numeric values drift across languages | Cross-language verify mismatch | Reject invalid numerics; constrain precision; maintain interop fixtures | Medium | Phase 1 |
| T3 | Digest format confusion (`sha256:` text vs raw bytes) | Invalid Merkle roots or false verification | Parse digests to `[u8;32]`; fail closed on malformed prefixes/length | Low | Phase 1 |
| T4 | Signature verification uses permissive API | Signature bypass risk | `ed25519-dalek` 2.2.x + `verify_strict()` | Low | Phase 1 |
| T5 | Key material hardcoded or leaked in logs | Unauthorized signing | Load keys from env/file only; redact key paths and secrets in logs | Medium | Phase 1/2 |
| T6 | Artifact tampering after metadata write | Broken evidence integrity | Write artifact temp file + `fsync` + atomic rename before metadata commit | Medium | Phase 2 |
| T7 | Partial metadata/index persistence in `sled` | Inconsistent retrieval/verification state | Use `sled::Batch` and `flush()` on bundle commit boundary | Medium | Phase 2 |
| T8 | Path traversal in artifact names | Arbitrary file overwrite/read | Normalize and validate relative names; reject `..` and absolute paths | Low | Phase 2/5 |
| T9 | Oversized payload/package DoS | Resource exhaustion | Configurable byte limits in service and CLI; early reject | Medium | Phase 2/5 |
| T10 | Verification trusts signature before digest checks | Misleading trust result | Verification order: canonical/header/artifact/root first, then signature | Low | Phase 5 |
| T11 | Public key substitution attack | False-positive validation | Explicit `kid` and verifier key pinning/out-of-band trust policy | Medium | Phase 5 |
| T12 | Overstated legal claims from "proof" wording | Legal/compliance risk | Consistent wording: "cryptographically verifiable evidence artifact" | Medium | Phase 6/docs |

## Required Controls Checklist

- Canonicalization rejects duplicate keys and invalid numeric forms.
- Signature verification uses strict Ed25519 verification.
- Artifact digests verified before trust decisions.
- Keys loaded from env/files, never hardcoded.
- Plaintext artifact payloads not logged by default.
- Service and CLI enforce payload size limits.

## Security Testing Strategy

1. Unit tests:
   - canonicalization vectors and negative cases
   - digest parser failures
   - Merkle deterministic vectors
   - sign/verify strictness checks
2. Tamper tests:
   - modified header
   - modified artifact bytes
   - wrong key
   - tampered JWS header/payload/signature
3. Interop tests:
   - Rust-generated fixtures verified in Node/Python
   - Node/Python-generated fixtures verified in Rust
4. CLI/service behavior tests:
   - oversized payload rejection
   - traversal path rejection
   - explicit error messages for each failed verification step

## Operational Guidance (PoC)

- Rotate dev keys regularly and never commit them.
- Back up `sled` DB and artifact storage together to maintain referential consistency.
- Keep an immutable copy of demo fixture bundles for fallback demonstrations.

## Deferred Risk Areas (v1)

- Trusted timestamping and transparency receipts
- Hardware-backed key management (HSM/KMS)
- Multi-tenant isolation and access control model
- Stronger retention/WORM guarantees
