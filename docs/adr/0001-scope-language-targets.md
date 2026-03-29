# ADR-0001: v1 Scope and Language Targets for the EU AI Act Proof Layer Fork

- **Status:** Accepted
- **Date:** 2026-03-27
- **Decision Owners:** SDK maintainers and compliance engineering lead
- **Related docs:** `docs/eu_ai_act_fork_executive_summary.md`

## Context

The fork proposal currently leaves language scope open between:

1. **Python only** for v1, or
2. **Python + TypeScript** for v1.

The team needs a single decision now so implementation planning, staffing, release sequencing, and compliance evidence work can proceed without ambiguity.

## Decision

For **v1**, we will support **Python only**.

TypeScript is explicitly deferred to a post-v1 phase (target: v1.1+), after v1 reaches production readiness and compliance evidence generation is stable.

## Rationale

1. **Fastest path to compliance readiness:** Python-only scope minimizes parallel implementation and release overhead.
2. **Lower coordination cost:** one SDK surface, one packaging pipeline, one API compatibility contract for v1.
3. **Reduced verification burden:** fewer language-specific edge cases in logging/proof parity and fewer cross-SDK tests.
4. **Staffing fit:** can be delivered by a smaller core team without adding a dedicated TypeScript maintainer in v1.

## Options Considered

### Option A — Python only (Chosen)

**Scope**
- Deliver `proof_layer_sdk` on PyPI.
- Include core proof API, verification utility, key tooling, tests, and compliance-focused docs.

**Timeline impact**
- Estimated duration: **~10–12 weeks** (about 3 months).
- Estimated effort: **~55–75 person-days**.

**Staffing impact**
- **2 core engineers** (SDK/runtime + packaging/CI) with shared ownership.
- **0.25 FTE compliance/security reviewer** during hardening and sign-off windows.
- **0.25 FTE technical writer/developer advocate** during docs/migration window.

**Pros**
- Simplest execution and governance model for v1.
- Earlier release date and lower schedule risk.

**Cons**
- JavaScript/TypeScript teams must wait for a later release or use service-based integration.

### Option B — Python + TypeScript

**Scope**
- Deliver both `proof_layer_sdk` (PyPI) and `proof-layer-sdk` (npm) with parity commitments.

**Timeline impact**
- Estimated duration: **~14–18 weeks** (about 3.5–4.5 months).
- Estimated effort: **~85–120 person-days**.

**Staffing impact**
- **3–4 engineers** (including at least one TypeScript-focused maintainer).
- **0.5 FTE compliance/security reviewer** due to expanded test/release matrix.
- **0.5 FTE technical writer/developer advocate** to support two SDK tracks.

**Pros**
- Supports both backend-heavy and web-centric integration teams from day one.

**Cons**
- Higher delivery risk and broader maintenance obligations at launch.
- More CI complexity, more release automation, more parity testing.

## Explicit Non-goals for v1

The following are **out of scope** for v1:

1. **Web demo application** (including React or other demo UIs).
2. **Extra wrappers** beyond the Python SDK (TypeScript/JavaScript and any additional language wrappers).
3. **Optional services** (e.g., Dockerized HTTP wrapper/service runtime, hosted helper APIs).

## Consequences

- Roadmap and timeline are now anchored to a Python-only delivery.
- Product and partner communications must set expectations that TypeScript support follows v1.
- CI, docs, and release checklists can optimize for one SDK artifact in v1.

## Follow-up

1. Update executive summary and project timeline to match this ADR.
2. Add a backlog epic for TypeScript v1.1 scope with parity criteria and staffing trigger.
3. Reassess language expansion only after v1 stabilization metrics are met.
