## March 6, 2026

Completed:

- Migrated the Rust workspace to `crates/core`, `crates/cli`, and `crates/vault`.
- Rebuilt the Rust core around a v1.0 `EvidenceBundle` schema with typed evidence items and `context`.
- Added v0.1 -> v1.0 migration helpers so legacy capture payloads still build valid v1 bundles.
- Extended Merkle support with inclusion-proof generation and verification.
- Updated `proofctl` and `proof-service` to accept both legacy capture JSON and v1 capture JSON.
- Regenerated the deterministic golden fixture set for `bundle_version: "1.0"`.
- Restored a clean Rust verification loop: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` both pass.

Still outstanding from `plan.md`:

- JSON schema coverage is now started, but the full pack/timestamp/transparency schemas are not implemented.
- The vault is still `sled`-backed; SQLite/PostgreSQL, retention policies, and pack assembly are not built yet.
- Node and Python SDKs are still HTTP-client based; NAPI-RS and PyO3 bindings are not built yet.
- RFC 3161 timestamping, transparency receipts, selective disclosure CLI flows, and evidence pack export remain future phases.
