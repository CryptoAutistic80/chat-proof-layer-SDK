# ADR-0001: v1 Scope and Language Targets for the EU AI Act Proof Layer Fork

- **Status:** Accepted
- **Date:** 2026-03-30
- **Decision Owners:** SDK maintainers and compliance engineering lead
- **Related docs:** `docs/eu_ai_act_fork_executive_summary.md`

## Context

The fork proposal previously left language scope open between:

1. **Python only** for v1, or
2. **Python + TypeScript** for v1.

After delivery hardening work and SDK readiness checks, the team now has viable Python and TypeScript SDK surfaces, packaging pipelines, and CI coverage. The remaining risk is governance/process alignment, not technical feasibility.

## Decision

For **v1**, we will support **Python + TypeScript**.

Both SDKs are first-class release artifacts for v1.0.0:

- Python distribution: `proof-layer-sdk-python` (PyPI)
- TypeScript distribution: `@proof-layer/sdk` (npm)

## Rationale

1. **Deployment reality:** downstream integrations already use both backend (Python) and service/web (TypeScript) stacks.
2. **Parity now achievable:** both SDKs expose aligned lifecycle APIs (`start`, `log_user/logUser`, `log_ai/logAI`, `finish`).
3. **Risk reduction for adopters:** avoids forcing one language ecosystem into stopgap wrappers.
4. **Current CI coverage:** release workflows already run test/build/package checks for both SDKs.

## Options Considered

### Option A — Python only

**Pros**
- Smaller governance scope.
- Fewer release artifacts.

**Cons**
- Blocks TypeScript-native teams.
- Requires interim wrappers/adapters and creates migration churn.

### Option B — Python + TypeScript (Chosen)

**Pros**
- Immediate support for both major integration surfaces.
- Unified compliance evidence model across backend and JS/TS stacks.
- Better ecosystem adoption and lower integration friction.

**Cons**
- Larger CI matrix and release operations.
- Requires stronger parity and versioning discipline.

## Explicit Non-goals for v1

The following remain **out of scope** for v1:

1. **Web demo as a production surface** (demo remains non-release-critical).
2. **Additional language SDKs** beyond Python and TypeScript.
3. **Managed hosted compliance service** (self-hosted/SDK-first model remains primary).

## Consequences

- Release and operations documentation must define dual publish flow (PyPI + npm).
- CI release blockers must remain green for both SDKs before `sdk-v*` release tags.
- API/schema compatibility notes must include Python and TypeScript examples and migration notes.

## Follow-up

1. Update executive summary and timeline to reflect dual-SDK v1.
2. Update release runbook to include npm publishing policy and rollback paths.
3. Keep API/schema parity checks in release gates for both SDKs.
