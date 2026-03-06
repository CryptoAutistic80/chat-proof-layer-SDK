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

- JSON schema coverage is now started, but timestamp/transparency and richer export/archive schemas are not implemented.
- The vault now uses SQLite with legal-hold-aware retention, append-only audit logging, and curated pack export, but PostgreSQL, configurable retention policy updates, and redacted/Annex-complete pack assembly are not built yet.
- Node and Python SDKs are still HTTP-client based; NAPI-RS and PyO3 bindings are not built yet.
- RFC 3161 timestamping, transparency receipts, and selective disclosure CLI flows remain future phases.
