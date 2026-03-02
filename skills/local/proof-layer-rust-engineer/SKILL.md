---
name: proof-layer-rust-engineer
description: Expert Rust engineering workflow for building and hardening the AI Output Proof Layer PoC in proof-layer-poc-plan.md. Use when implementing or reviewing Rust crates for canonicalization (RFC 8785), hashing, Merkle commitments, Ed25519 signing/verification, Axum proof services, SQLx persistence, CLI workflows, cross-language interoperability with Node/Python SDKs, and security/test readiness before demos or partner reviews.
---

# Proof Layer Rust Engineer

## Objective

Implement the Rust-heavy portions of the AI Output Proof Layer quickly without sacrificing cryptographic correctness, interop, or demo reliability.

## Load Context In This Order

1. Read `proof-layer-poc-plan.md` at repo root.
2. If present, read `docs/architecture.md`, `docs/proof_bundle_schema.md`, and `docs/threat_model.md`.
3. Read `references/resource-index.md` in this skill for standards, crate docs, and compliance anchors.

## Execution Workflow

### 1. Convert Request Into Phase-Aligned Scope

Map work to plan phases before coding:

- Phase 1: Rust core (`canonicalize`, `hash`, `merkle`, `sign`, `verify`)
- Phase 2: Rust Axum service path (if chosen instead of Node Fastify)
- Phase 5: `proofctl` CLI

State which phase(s) you are touching and list acceptance checks from the plan.

### 2. Choose Safe Defaults

Use these defaults unless the repository already enforces alternatives:

- Canonicalization: `serde_json_canonicalizer`
- Hash: `sha2` (`Sha256`)
- Signatures: `ed25519-dalek` `2.2.x`, `verify_strict()`
- API: `axum`
- Storage: `sqlx` + SQLite for PoC
- CLI: `clap` derive
- IDs: `ulid`

If you deviate, justify with concrete tradeoffs.

### 3. Implement Core Deterministically

For every integrity-affecting function:

- Define exact byte-level input and output contracts.
- Avoid hidden serialization transforms.
- Reject invalid or ambiguous inputs early (NaN/Infinity, malformed digests, unsupported algorithms).
- Prefer explicit newtypes/structs over free-form maps for signed payloads.

Always keep signing input and verification input byte-identical.

### 4. Test Before Integrating

Create or extend tests in this sequence:

1. Unit tests for core algorithms.
2. Negative/tamper tests (modified header, artefact, key, signature).
3. Cross-language fixtures (Rust-generated bundles verified by Node/Python and vice versa when SDKs are available).
4. CLI golden-path and failure-path tests.

If full interop is not possible yet, leave deterministic fixtures and TODO markers tied to a specific phase dependency.

### 5. Document Credibility Anchors

When touching architecture/schema docs, ensure these stay explicit:

- What is signed (canonical bytes hash, not raw JSON text).
- Bundle root construction order and encoding.
- Offline verification requirements.
- Provider-agnostic adapter boundary.
- Non-determinism statement (record/replay of evidence, not output determinism).

## Required Security and Correctness Checks

Run these checks whenever applicable:

- Canonicalization rejects duplicate keys and non-finite numbers.
- Signature verification uses strict key and signature validation.
- Artefact digests are validated before trust decisions.
- Keys are loaded from env/files and never hardcoded.
- Logs never include plaintext artefact content by default.
- Large payload limits are enforced in services and CLIs.

If any check is skipped, state why and what follow-up is required.

## Rust Code Quality Rules

- Keep modules single-purpose (`canonicalize.rs`, `hash.rs`, `merkle.rs`, `sign.rs`, `verify.rs`).
- Return typed errors with actionable context; avoid `unwrap()` in library code.
- Prefer stable APIs over pre-release crates for PoC reliability.
- Use `cargo fmt`, `cargo clippy`, and `cargo test` before marking work done.
- Use `cargo check` for fast iteration loops.

## Output Contract For This Skill

For each substantial task, report:

1. Files changed and why.
2. Verification commands run and outcomes.
3. Remaining risks, deferred items, and which plan phase owns them.

## References

- Primary references are in `references/resource-index.md`.
- If standards conflict with local plan text, follow standards for cryptographic behavior and update docs to resolve drift.
