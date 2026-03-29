# Executive Summary: Lean Proof Layer SDK Fork for EU AI Act Chat Compliance

## Overview

We propose a lean **Proof Layer SDK** fork that retains only the essential components needed to integrate with chat systems and meet EU AI Act obligations. The existing repository is a large, multi-language monorepo (Rust/Python/TypeScript/JavaScript) with demos, documentation, and CI. The fork will remove non-essential surfaces and keep core runtime libraries and APIs for logging, evidencing, and management.

Per **ADR-0001** (`docs/adr/0001-scope-language-targets.md`), **v1 scope is Python-only**.

The forked SDK will focus on:

- built-in transcript logging (Article 12 record-keeping)
- automated proof generation
- human-in-the-loop hooks for oversight
- practical support for transparency, documentation, risk workflows, and incident handling

Estimated effort for v1: **~10–12 weeks** (about **55–75 person-days**) to reach production readiness, including tests, security review, and developer documentation.

## Current Repository Structure (Snapshot)

The current `proof-layer-sdk` repository is organised as a full-stack monorepo. Core areas include:

- **Rust crates** under `crates/` (core proof engine plus wrappers, including `crates/pyo3/`)
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

The proposed minimal SDK should include:

- **Core API** (`ProofLayer` or equivalent)
  - initialise session
  - `log_user(...)`
  - `log_ai(...)`
  - finalise session and produce bundle
- **Proof generation**
  - deterministic transcript hashing
  - signature over session proof root
- **Verification utility**
  - SDK function and/or CLI command
- **Key management tooling**
  - key generation and secure loading helpers
- **Error handling**
  - explicit failure paths when capture or signing fails
- **Minimal dependencies**
  - only required crypto/runtime libraries
- **Packaging**
  - Python package (PyPI)

### Illustrative Python Usage

```python
from proofsdk import ProofLayer

proof = ProofLayer.load(private_key_path="keys/sign_key.pem")

user_msg = "List the EU AI Act transparency requirements."
proof.log_user(user_msg)
ai_response = llm.chat(user_msg)
proof.log_ai(ai_response)

bundle = proof.finish_session()
send_to_compliance_server(bundle)
```

## Scope Decision (Final)

### Supported SDKs for v1

- ✅ **Python SDK only**
- ❌ TypeScript/JavaScript SDK in v1 (deferred to post-v1)

### Explicit Non-goals for v1

- web demo implementation
- extra language wrappers beyond Python
- optional service layer(s), including Dockerized HTTP wrapper APIs

## Timeline and Staffing Impact by Scope Option

| Option | Timeline | Effort | Staffing | Risk |
| --- | --- | --- | --- | --- |
| **A. Python only (chosen)** | **10–12 weeks** | **55–75 person-days** | 2 engineers + 0.25 FTE compliance/security + 0.25 FTE docs | Lower |
| B. Python + TypeScript | 14–18 weeks | 85–120 person-days | 3–4 engineers + 0.5 FTE compliance/security + 0.5 FTE docs | Higher |

## Proposed Fork Plan and Timeline (Chosen Scope)

1. **Requirements and design lock (Python-only)** (~1 week)
2. **Core Python implementation** (~3–4 weeks)
3. **Key management + verification tooling** (~1–1.5 weeks)
4. **Packaging/release pipeline (PyPI)** (~1 week)
5. **Testing and CI hardening** (~2 weeks)
6. **Documentation and migration guide** (~1.5 weeks)
7. **Security review + release readiness** (~1 week)

```mermaid
gantt
  title Forked Proof Layer SDK Plan (Python-only v1)
  dateFormat  YYYY-MM-DD
  section Planning
  Scope + Requirements Lock       :done,   des1, 2026-04-01, 5d
  section Development
  Core Python Implementation      :active, dev1, after des1, 20d
  Key Mgmt + Verification         :        dev2, after dev1, 7d
  Packaging (PyPI)                :        dev3, after dev2, 5d
  section Testing/CI
  Tests + CI Hardening            :        test1, after dev3, 10d
  section Documentation
  Docs + Migration Guide          :        doc1, after test1, 8d
  section Security/Release
  Security Review + Release       :        rel1, after doc1, 5d
```

## Packaging and Distribution (v1)

- **Python** (`proof_layer_sdk`) via PyPI
- No npm package in v1
- No Docker wrapper service in v1

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
- optional fuzz/property testing for robustness

## Documentation Deliverables

- Getting Started guide
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
| Surface | Multi-language, demos, broad tooling | Compliance-focused Python runtime and APIs |
| UI/Demo | Included | Removed from core fork |
| Logging/Proof | Present with broader abstractions | Core logging/signing only |
| Key tooling | Partial | Required, explicit |
| Dependencies | Broad | Minimized |
| CI/Testing | Present, mixed scope | Focused on critical assurance paths |
| Docs | Extensive mixed docs | concise integration + compliance guides |

## Reference Architecture

```mermaid
graph LR
    subgraph Chat Application
      User[User]
      ChatUI[Chat UI]
      AIModel[AI Model Service]
    end
    subgraph ProofLayer
      Capturer[ProofLayer SDK]
      KeyStore[Signing Keys\n(private/public)]
      BundleStore[Secure Log Storage]
    end
    User --> ChatUI
    ChatUI --> Capturer[Capture Hook]
    Capturer --> AIModel
    AIModel --> Capturer
    Capturer --> BundleStore
    Capturer -- key ops --> KeyStore
    ChatUI -.-> AIModel
```

## Integration Sequence

```mermaid
sequenceDiagram
  participant Dev as Developer Code
  participant SDK as ProofLayer SDK
  participant Chat as AI Chat Model
  participant Bundles as Evidence Storage

  Dev->>SDK: start_session()
  loop for each turn
    Dev->>SDK: log_user(prompt)
    SDK->>Chat: send prompt to AI
    Chat-->>SDK: response
    SDK->>Dev: return response
    Dev->>SDK: log_ai(response)
  end
  Dev->>SDK: finish_session()
  SDK->>Bundles: save signed evidence bundle
```

## Next Steps (Unambiguous)

1. Ratify ADR-0001 in governance records and communicate that **v1 is Python-only**.
2. Freeze Python v1 API and JSON proof bundle schema.
3. Start implementation against the 10–12 week plan and staff to the Python-only model.
4. Open a post-v1 backlog epic for TypeScript with explicit parity acceptance criteria.
5. Define go/no-go gates for release: test pass rate, security review sign-off, and packaging verification.

This fork direction keeps only what is needed for verifiable, practical chat compliance workflows while reducing operational and maintenance complexity.
