# Executive Summary: Lean Proof Layer SDK Fork for EU AI Act Chat Compliance

## Overview

We propose a lean **Proof Layer SDK** fork that retains only the essential components needed to integrate with chat systems and meet EU AI Act obligations. The existing repository is a large, multi-language monorepo (Rust/Python/TypeScript/JavaScript) with demos, documentation, and CI. The fork removes non-essential release surfaces and keeps core runtime libraries and APIs for logging, evidencing, and management.

Per **ADR-0001** (`docs/adr/0001-scope-language-targets.md`), **v1 scope is Python + TypeScript**.

The forked SDK focuses on:

- built-in transcript logging (Article 12 record-keeping)
- automated proof generation
- human-in-the-loop hooks for oversight
- practical support for transparency, documentation, risk workflows, and incident handling

**Delivery baseline (fixed):** kickoff on **2026-04-01** with planned v1.0.0 release on **2026-06-28**, contingent on phase exit criteria and final security/compliance sign-off.

## Current Repository Structure (Snapshot)

The current `proof-layer-sdk` repository is organized as a full-stack monorepo. Core areas include:

- **Rust crates** under `crates/` (core proof engine plus wrappers, including `crates/pyo3/` and `crates/napi/`)
- **Python SDK** under `packages/sdk-python/` (`proofsdk/`, decorators, CLI, packaging)
- **TypeScript SDK** under `sdks/typescript/` (parallel API for JavaScript/TypeScript environments)
- **Web demo** under `web-demo/` (React-based integration walkthrough)
- **Scripts and CI** under `scripts/` and `.github/workflows/`
- **Examples and documentation** spread across root/docs/example locations

In summary, the current repository is broader than a minimal compliance layer.

## EU AI Act Requirements (High-Risk Chat Systems)

For high-risk and related regulated AI usage in chat contexts, an implementation should account for:

- **Transparency** (Articles 50–52)
- **Automatic logging / record-keeping** (Article 12)
- **Technical documentation** (Article 11 + Annex IV)
- **Data governance** (Article 10)
- **Human oversight** (Article 14)
- **Risk management lifecycle** (Articles 9–10)
- **Conformity assessment readiness**
- **Incident reporting and post-market handling** (including Article 62 pathways)

## Feature-to-Obligation Mapping

A minimal Proof Layer surface can support these obligations through:

- **Tamper-evident runtime logs** for chat inputs/outputs (Article 12)
- **Provenance metadata** for transparency and auditability
- **Structured evidence bundles** to support Annex IV documentation packs
- **Oversight hooks** for human review or escalation policies
- **Incident reconstruction capability** through signed session evidence

## Minimal SDK Components and API (v1)

The proposed minimal SDK includes:

- **Core API** (`ProofLayer` or equivalent)
  - initialize session
  - `log_user(...)` / `logUser(...)`
  - `log_ai(...)` / `logAI(...)`
  - finalize session and produce bundle
- **Proof generation**
  - deterministic transcript hashing
  - signature over session proof root
- **Verification utility**
  - SDK function and CLI command
- **Key management tooling**
  - key generation and secure loading helpers
- **Error handling**
  - explicit failure paths when capture or signing fails
- **Minimal dependencies**
  - only required crypto/runtime libraries
- **Packaging**
  - Python package (PyPI)
  - TypeScript package (npm)

## Scope Decision (Final)

### Supported SDKs for v1

- ✅ **Python SDK** (`proof-layer-sdk-python`)
- ✅ **TypeScript SDK** (`@proof-layer/sdk`)

### Explicit Non-goals for v1

- web demo as a production surface
- additional language wrappers beyond Python and TypeScript
- managed hosted compliance service

## Delivery Milestones and Gating Criteria (Chosen Scope)

| Phase | Milestone date | Entry criteria | Exit criteria |
| --- | --- | --- | --- |
| 1. Requirements + design lock | **2026-04-07** | ADR-0001 ratified, product/compliance owners assigned, draft v1 API boundaries documented | Frozen v1 API/scope approved by engineering + compliance, backlog split into must/should/could |
| 2. Core SDK implementation | **2026-05-05** | Phase 1 exit complete, signed architecture notes, coding standards adopted | Core session lifecycle implemented in Python + TypeScript with deterministic transcript hashing and unit tests for happy-path + failure-path behaviors |
| 3. Key management + verification tooling | **2026-05-14** | Core implementation merged behind stable interfaces | Key generation/loading helpers implemented, CLI/SDK verification path available, tamper-detection tests passing in both SDKs |
| 4. Packaging/release pipelines (PyPI + npm) | **2026-05-24** | Package metadata finalized, versioning policy approved | Reproducible build artifacts generated, signed tag dry-run succeeds, TestPyPI and npm pack/install verification succeeds |
| 5. Testing + CI hardening | **2026-06-08** | CI baseline exists and release workflow configured | Required checks green (lint, unit, integration, bundle-verify), coverage threshold met, dependency/security scan has no unresolved critical issues |
| 6. Documentation + migration guide | **2026-06-17** | APIs stable and examples validated in CI | Quickstart, migration guide, release runbook, and EU AI Act mapping docs complete and internally reviewed for both SDKs |
| 7. Security/compliance review + GA release | **2026-06-28** | All earlier phase exits complete, release candidate tagged | Security review sign-off, compliance sign-off, changelog approved, signed `v1.0.0` release published |

## Packaging and Distribution (v1)

- **Python** (`proof-layer-sdk-python`) via PyPI
- **TypeScript/JavaScript** (`@proof-layer/sdk`) via npm
- No managed hosted compliance service in v1

## Security and Privacy Considerations

- keep private signing keys out of source control
- support secure key loading from environment/KMS/HSM-compatible workflows
- enable optional redaction/masking for sensitive content before logging
- use widely vetted primitives (e.g. Ed25519 over transcript hash commitments)
- reduce dependency footprint and continuously scan dependencies

## Testing and CI

- unit tests: logging, bundle generation, verification, tamper detection
- integration tests: end-to-end chat capture flow
- CI: lint, test, coverage, packaging checks, release automation on tags
- cross-SDK parity checks on API semantics and schema compliance
- optional fuzz/property testing for robustness

## Documentation Deliverables

- Getting Started guide (Python + TypeScript)
- API reference
- concise integration examples
- migration guide from broader SDK surface
- compliance mapping checklist for developers and auditors
- architecture overview diagrams

## Governance and Maintenance

- semantic versioning and clear release branches
- contributor guidelines, issue/PR templates, and review gates
- security reporting path and patch cadence
- explicit OSS licensing and maintainer ownership

## Current vs Proposed (Condensed)

| Area | Current SDK | Proposed Minimal SDK (v1) |
| --- | --- | --- |
| Surface | Multi-language, demos, broad tooling | Compliance-focused Python + TypeScript runtime APIs |
| UI/Demo | Included | Demo remains non-release-critical |
| Logging/Proof | Present with broader abstractions | Core logging/signing emphasized |
| Key tooling | Partial | Required, explicit |
| Dependencies | Broad | Minimized in release-critical paths |
| CI/Testing | Present, mixed scope | Focused on critical assurance paths across both SDKs |
| Docs | Extensive mixed docs | concise integration + compliance guides for both SDKs |

## Next Steps (Unambiguous)

1. Ratify ADR-0001 in governance records and communicate that **v1 is Python + TypeScript**.
2. Freeze v1 API and JSON proof bundle schema shared by both SDKs.
3. Execute delivery against the dated milestone plan and phase gates.
4. Enforce go/no-go release gates: required tests green, security sign-off, compliance sign-off, signed-release verification.

This fork direction keeps only what is needed for verifiable, practical chat compliance workflows while reducing operational and maintenance complexity while supporting both major integration ecosystems.
