# Verification Test Matrix (PoC v0.1)

## Purpose

Track required verification behavior across Rust core, CLI (`proofctl`), and proof service.
This matrix maps tests to pass/fail expectations and primary owning phase.

## Matrix

| ID | Scenario | Input Mutation | Expected Result | Owner |
|---|---|---|---|---|
| V-001 | Canonicalization deterministic | Same bundle verified twice | Same `header_digest` and `bundle_root` each run | Phase 1 |
| V-002 | Duplicate key rejection | Duplicate object key in untrusted raw JSON | Canonicalization parse failure | Phase 1 |
| V-003 | Non-interoperable integer rejection | Integer > `2^53-1` | Canonicalization failure (`IntegerOutOfRange`) | Phase 1 |
| V-004 | Digest parser strictness | Malformed digest (`sha256:zz`) | Validation failure before trust checks | Phase 1 |
| V-005 | Header tamper | Change `model.model` without recomputing integrity | `HeaderDigestMismatch` | Phase 1 |
| V-006 | Artefact tamper | Modify artefact bytes | `ArtefactDigestMismatch` or `ArtefactSizeMismatch` | Phase 1 |
| V-007 | Wrong key verify | Verify with non-matching public key | Signature verification failure | Phase 1 |
| V-008 | JWS tamper | Modify JWS segment/header/payload/signature | Signature verification failure | Phase 1 |
| V-009 | Unknown integrity algorithms | Set `hash=SHA-1` or wrong format/algo fields | Validation failure (`Unsupported*`) | Phase 1 |
| V-010 | Duplicate artefact names | Duplicate `artefacts[].name` | Validation failure (`DuplicateArtefactName`) | Phase 1 |
| V-011 | Path traversal artefact name | `../secret.json` | Validation failure (`InvalidArtefactName`) | Phase 1/5 |
| V-012 | Oversized CLI capture input | `capture.json` > max bytes | `proofctl create` fails early | Phase 5 |
| V-013 | Oversized CLI artefact | artefact file > max bytes | `proofctl create` fails early | Phase 5 |
| V-014 | Oversized service artefact | base64 artefact > max bytes | `POST /v1/bundles` fails `400` | Phase 2 |
| V-015 | Offline verify package integrity | Verify with `bundle.pkg` + public key only | Valid without network access | Phase 5 |
| V-016 | Manifest mismatch | Change packaged file but leave manifest unchanged | `manifest_ok=false`, verify fails | Phase 5 |
| V-017 | Duplicate package member name | Two package entries share same `name` | Package parse failure before verify | Phase 5 |
| V-018 | Unlisted package member | Add file not listed in `manifest.json` | `manifest_ok=false`, verify fails | Phase 5 |
| V-019 | Service package verify mode | Submit `bundle_pkg_base64` + public key to `/v1/verify` | Valid package returns `valid=true`; manifest tamper returns invalid | Phase 2/5 |

## Execution Notes

- `proofctl` size limit env vars:
- `PROOFCTL_MAX_PAYLOAD_BYTES`
- fallback: `PROOF_MAX_PAYLOAD_BYTES`
- default: `10_485_760` bytes (10 MiB)

- proof service size limit env vars:
- `PROOF_SERVICE_MAX_PAYLOAD_BYTES`
- default: `10_485_760` bytes (10 MiB)

## Coverage Status

- Implemented in code:
- V-001, V-002, V-003, V-004, V-005, V-006, V-007, V-008, V-009, V-010, V-011, V-012, V-013, V-014, V-015, V-016, V-017, V-018, V-019
- `V-001` cross-language canonicalization vectors are pinned in `fixtures/golden/rfc8785_vectors.json` and asserted by Rust/Node/Python tests.

- Still recommended as follow-up:
- None currently.
