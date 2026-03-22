# EU AI Act Readiness Notes for an SDK-first Tamper-Evident AI Compliance Evidence Platform

## Implementation status note

As of March 22, 2026, the repo now has a concrete Annex IV governance acceptance slice on top of the broader platform, plus the next trust-and-transparency hardening slice: checked governance fixtures, SDK builder guidance, vault `annex_iv` curation hardening, a narrower `annex_iv_redacted` disclosure default, end-to-end TypeScript/Python examples for a provider-side employment-screening scenario, an advisory `annex_iv_governance_v1` readiness/completeness contract across Rust core, CLI, vault, SDKs, and `web-demo`, a plain-English trust-reporting layer for timestamp and receipt verification, opt-in Rekor live-log confirmation, and a newer COSE/CCF-style SCITT receipt format with legacy-read compatibility. The main remaining work is now broader profile coverage, deeper trust-list/evidence-preservation work, and release hardening rather than Annex IV minimum-field enforcement or inventing another subsystem.

## Scope and design principles

These notes assume you are building an evidence substrate that can sit underneath many AI applications and governance stacks. It captures compliance-relevant events and artefacts at runtime and across the lifecycle, seals them into portable and independently verifiable evidence bundles, and can optionally store them in a vault layer with retention, access controls, and export workflows suitable for audits, customers, and regulators. The design direction remains consistent with the original idea of an AI Output Proof Layer producing cryptographically verifiable proof bundles that can be selectively disclosed and verified outside the vendor platform.

The core regulatory target is the EU AI Act, Regulation (EU) 2024/1689. The current binding timeline is still the one that matters for roadmap decisions: entry into force on August 1, 2024; prohibited practices and AI literacy obligations from February 2, 2025; GPAI obligations from August 2, 2025; the main high-risk regime from August 2, 2026; and some Annex I pathways from August 2, 2027. A simplification proposal published on November 19, 2025 is not yet the law, so planning should continue against the current dates.

Product boundary assumptions for these notes:

- The primary product is the SDK, CLI, and local verification toolchain.
- The vault is an optional layer that can be self-hosted or later offered as a paid managed service for retention, audit, disclosure policy management, and export orchestration.
- The frontend is demo collateral and should not be treated as the production compliance surface.
- Proof Layer should be treated as infrastructure for customer AI systems, not as the customer’s AI system or GPAI model provider by default.

Design principles that follow from the Act and from audit-grade engineering:

- Evidence must be externally verifiable, not merely stored in an internal database.
- Evidence capture must be role-aware across provider, deployer, downstream integrator, and where relevant importer, distributor, authorized representative, and GPAI provider roles.
- Evidence storage must be privacy- and confidentiality-sensitive because logs and artefacts may contain personal data, trade secrets, and security-sensitive details.
- The offline path matters first. Baseline adoption should work without the vault, while the vault adds operational controls that are difficult to implement consistently in every application.

## EU AI Act requirements that drive evidence capture

### High-risk AI systems

For high-risk AI systems, the AI Act sets out a tightly coupled set of design-time and run-time obligations that translate naturally into an evidence specification.

- Article 9 requires a documented and continuously maintained risk management system. The evidence layer should support iterative risk snapshots, mitigation decisions, test evidence, and change history.
- Article 10 requires data governance and management practices for relevant datasets, including design choices, preparation, bias handling, and context-of-use fit. The evidence layer should therefore support provenance, processing lineage, approvals, and supporting artefacts.
- Article 11 and Annex IV require technical documentation before placing on the market or putting into service, and that documentation must remain current. The product therefore needs first-class documentation evidence, not just runtime logs.
- Article 12 requires automatic event logging for traceability, including support for risk detection, substantial-modification analysis, post-market monitoring, and deployer monitoring duties. Logging is a first-class legal requirement, not a nice-to-have.
- Articles 13, 14, and 15 require operationalisation of instructions for use, human oversight, and accuracy, robustness, and cybersecurity measures throughout the lifecycle. These should appear explicitly in the target evidence model and pack templates.
- Articles 17, 18, 19, 26, 27, 40, 43, 72, and 73 imply further governance artefacts around quality management, retention, deployer operations, fundamental-rights assessment where applicable, standards alignment, post-market monitoring, and incident and corrective-action handling.

These provisions imply that an AI compliance evidence platform is not just a logging pipeline. It must support lifecycle artefacts, runtime traceability, confidentiality-aware sharing, and long-lived retention in ways that remain usable in audits and regulatory review.

### GPAI models

GPAI obligations became applicable on August 2, 2025. Article 53 requires providers of general-purpose AI models to maintain Annex XI documentation, provide Annex XII downstream documentation, implement a copyright compliance policy, and publish a sufficiently detailed public summary of training content. Article 55 adds systemic-risk obligations such as state-of-the-art evaluation, adversarial testing, systemic risk mitigation, serious-incident handling, and cybersecurity protection.

Even if many customers are downstream integrators rather than model providers, the product should support GPAI evidence capture on day one because those obligations are already live.

### AI literacy

Article 4 requires providers and deployers to take measures, to their best extent, to ensure a sufficient level of AI literacy for staff and other persons dealing with AI systems on their behalf, taking into account the relevant context, role, and risk level.

For an evidence product, AI literacy is therefore a real compliance stream: training completion, role mapping, competence attestation for oversight roles, and organisation- or system-scoped reporting should be supported directly.

## Evidence taxonomy and mapping to the Act

A pragmatic taxonomy for the SDK and optional vault layer is to treat evidence as cryptographically sealed evidence items grouped into evidence packs aligned with major AI Act artefacts.

- High-risk technical file pack: technical documentation, risk management artefacts, data governance artefacts, instructions for use, human oversight design, accuracy, robustness, and cybersecurity evidence, post-market monitoring plan, and linked declaration and registration material.
- High-risk runtime log pack: system-generated logs plus derived monitoring and risk-indicator events retained for provider and deployer duties under Articles 12, 19, and 26.
- GPAI provider pack: Annex XI documentation, evaluation results, provenance, copyright-policy evidence, and training-summary evidence.
- GPAI downstream integration pack: Annex XII-style documentation for downstream system providers and integrators.
- Systemic risk pack: adversarial testing, model evaluation, incident reports, corrective measures, and cybersecurity posture evidence.
- AI literacy pack: training by role and risk context, attendance and completion evidence, and competence attestations for oversight assignees.
- Provider-governance pack: QMS records, standards or common-specification mapping, release approvals, and audit checkpoints.

To make this operational, the SDK should emit typed evidence events and artefacts with stable IDs such as `system_id`, `model_id`, `version`, and `deployment_id`. The vault layer, where used, should index them by role, obligation, system, timeframe, and retention schedule. This directly supports documentation and log retention duties.

| AI Act driver | What must be evidenced | What the SDK should capture | What the vault layer must guarantee |
|---|---|---|---|
| Art. 9 risk management | Continuous lifecycle process, testing, mitigation decisions | Risk register deltas, test attestations, mitigation approvals, foreseeable-misuse analysis snapshots | Versioned retention, integrity across revisions, exportable change history |
| Art. 10 data governance | Data origin, preparation, bias detection and mitigation, context-of-use fit | Dataset provenance references, preprocessing lineage, bias checks, approvals | Access controls, selective disclosure, retention aligned to provider duties |
| Art. 11 and Annex IV | Technical documentation before market or put-into-service and updates | Document manifests, artefact hashes, linked test evidence, standards applied list | Long-term retention, tamper evidence, audit-ready pack export |
| Art. 12 and Arts. 19 and 26 | Automatic event logging and minimum retention | Runtime event logs, monitoring events, operator overrides, system and user action traces | Append-only semantics, retention controls, time-bounded retrieval for audits |
| Arts. 13, 14, 15 | Instructions for use, oversight, declared performance, robustness, cybersecurity | Instructions artefacts, oversight events, evaluation outputs, resilience evidence | Confidentiality-aware sharing plus durable retention of supporting artefacts |
| Arts. 47, 49, 71 | Declaration, registration, CE-marking supply-chain evidence | Signed declaration artefacts, registration receipts, references to notified-body outputs where needed | Durable storage and proof of integrity for declarations and registrations |
| Art. 53 and Annex XI/XII | GPAI documentation, downstream info, training summary, copyright policy | Model doc bundles, downstream integration docs, training summary artefacts, policy artefacts | Packaging suitable for downstream sharing with confidentiality controls |
| Art. 55 | Evaluation, adversarial testing, incident reporting, cybersecurity | Evaluation runs, adversarial tests, incident event stream, mitigations | Immutable incident history and export for authorities |
| Art. 4 | Sufficient AI literacy measures tailored to role and context | Training records, role mapping, competence attestation | Retention and audit-ready reporting across systems and roles |

The consistent theme is traceability plus durable documentation. The product should make those artefacts first-class and verifiable while keeping the baseline adoption path usable as local SDK and CLI tooling.

## Current schema gaps vs. AI Act completeness

This gap discussion is grounded in the current AI Act legal anchors and Commission timeline: Regulation (EU) 2024/1689 as published on EUR-Lex, entry into force on August 1, 2024, AI literacy and prohibited-practice obligations from February 2, 2025, GPAI obligations from August 2, 2025, the main high-risk regime from August 2, 2026, and some Annex I pathways from August 2, 2027. The prioritisation below is a product inference from that legal baseline plus the current SDK/vault implementation shape, especially for GPAI compute-threshold evidence and completeness-validation expectations.

The current implementation already has broad catalog coverage: the main governance, runtime, GPAI, incident, literacy, and conformity evidence families exist; `compute_metrics` is already first-class; retention classes and pack families are operational; and the cryptographic layer is production-grade. The remaining issue is not catalog breadth. It is schema depth beyond the first shipped completeness profile set. Most lifecycle evidence types intentionally use a thin pattern of stable identifiers, status fields, and commitment hashes that push detailed structure into artefact attachments.

That design is strong for tamper evidence and backward compatibility, but it creates a real tension between commitment integrity and completeness validation. A verifier can prove that an attached artefact has not changed, but cannot tell from the schema alone whether a customer captured the minimum structured detail implied by Articles 9, 10, 13, 14, 15, 17, 27, 43, 47, 49, 53, and 55. The pragmatic design rule is therefore:

- keep the thin required spine,
- add optional typed enrichment fields to existing evidence items,
- keep rich artefacts for full narrative detail and large attachments,
- avoid any bundle-format or bundle-version reset.

### Priority ranking

| Priority | Area | Gap | Direction |
|---|---|---|---|
| `P0` | Data governance (Art. 10) | Large | Add optional structured dataset, preprocessing, bias, safeguard, and data-gap fields to `data_governance`. |
| `P0` | Broader completeness profiles | Large | Extend machine-assessed readiness beyond `annex_iv_governance_v1` so `annex_xi`, monitoring, and related packs have explicit structural contracts. |
| `P1` | Instructions for use (Art. 13) | Medium-large | Keep document-centric capture but add optional structured capability, risk, oversight, compute, and logging guidance fields. |
| `P1` | Risk detail (Art. 9) | Medium | Keep one item per risk, but add optional likelihood, affected-group, mitigation, residual-risk, owner, and test-summary structure. |
| `P1` | Human oversight (Art. 14) | Medium | Enrich `human_oversight` with actor role, anomaly/override/bias/stop-event structure instead of creating a separate stop-event type. |
| `P2` | Technical documentation (Art. 11 / Annex IV / Annex XI context) | Medium | Keep `technical_doc` document-centric, but add Annex-linked coverage and summary/linkage fields. |
| `P2` | Evaluation and adversarial detail (Art. 15 / Art. 55) | Medium | Add structured metric summaries, group performance, threat models, and test-methodology fields while leaving full reports in artefacts. |
| `P2` | QMS record depth (Art. 17) | Medium | Add optional policy, revision, dates, scope, approval, audit-summary, and improvement-action fields. |
| `P3` | Incident, FRIA, literacy, conformity polish | Small to medium | Add a small number of structured enrichment fields without changing the current item model. |
| `P3` | Runtime timestamp polish | Small | Add explicit `execution_start` / `execution_end` and retrieval database-reference fields. |

### Design implications

- `compute_metrics` is now part of the implemented evidence catalog, so the next GPAI gap is completeness-profile coverage and deeper structured enrichment rather than adding another first-class threshold type.
- `serious incident notification` and `stop event` remain structured enrichments on `authority_notification` and `human_oversight` rather than becoming new top-level item types.
- Selective disclosure remains compatible with richer nested evidence because `pl-merkle-sha256-v4` already supports JSON-pointer path redaction at `item.data` subtree level.
- The package format stays at `bundle_version: "1.0"` and the current Merkle family stays in place because all planned schema changes are additive and optional.

## Tamper-evident cryptographic design for evidence bundles

The strongest technical direction remains the same: portable evidence bundles assembled from normalised events and artefacts, sealed cryptographically, timestamped, and optionally anchored in a transparency system. The design should explicitly separate integrity guarantees from availability and retention guarantees. The SDK and core library provide the former; the optional vault primarily strengthens the latter.

### Canonicalisation and hashing

If evidence payloads include JSON, deterministic canonicalisation is required so that the same logical content produces the same byte representation for hashing and signing. RFC 8785 provides that canonical representation. The Rust core should define a single canonicalisation profile and treat the canonical bytes as the signing-input invariant across languages.

### Timestamping

RFC 3161 provides the interoperable baseline for timestamping bundle hashes, while eIDAS gives additional legal weight to qualified time stamps in some contexts. Timestamping should therefore be policy-driven: baseline RFC 3161 support for production evidence, with optional qualified-service integration for customers who need that higher-assurance path.

### Transparency anchoring

Transparency anchoring remains a useful optional layer to resist repudiation at ecosystem scale. The clean architecture is a pluggable receipt-provider interface in the Rust core so customers can choose signature plus timestamp only, Sigstore-style log anchoring, or SCITT-compatible services. This should remain optional rather than a prerequisite for basic adoption. In practice, the best operator model is offline verification by default, with optional live Rekor freshness checks when a team wants a stronger current-state signal, and a SCITT path that uses an outside-friendlier COSE/CCF-style receipt format while keeping older receipts readable.

### Selective disclosure and confidentiality

AI Act evidence often includes prompts, retrieved documents, tool outputs, and system details that may be personal data, trade secrets, or otherwise sensitive. The architecture should therefore support selective disclosure proofs so customers can share only the relevant claims and artefacts while preserving verifiability. This matters for downstream documentation, regulator exports, and incident handling.

## Rust-first SDK architecture and language strategy

The product requirement of a Rust core with TypeScript and Python at launch maps cleanly to a design where the Rust crate is the source of truth for:

- evidence object schema and canonicalisation profile,
- hashing, signing, timestamp, and verification logic,
- packaging and validation,
- plugin interfaces for timestamp, transparency, key, and encryption providers,
- a reference CLI verifier and export toolchain.

At minimum, the Rust core should expose four stable capability families:

1. Capture: normalise runtime and lifecycle events into typed evidence.
2. Seal: canonicalise, hash, sign, timestamp, and optionally anchor.
3. Verify: produce deterministic verification reports for offline or service-backed verification.
4. Export: compile AI-Act-aligned evidence packs for auditors, customers, or authorities.

TypeScript and Python should remain thin bindings over the Rust core to minimise compliance drift. The launch path should work locally first: developers can capture, seal, verify, and selectively disclose evidence without requiring the managed vault. OpenTelemetry GenAI integration remains important because it lets the product meet developers where they already instrument their systems.

## Managed Evidence Vault architecture and operational model

The vault is not merely storage; it is the optional operational boundary where you guarantee retention schedules, access control, audit trails, disclosure-policy management, and reproducible exports. A customer should still be able to adopt the SDK, CLI, and local verification path without adopting the vault on day one. The managed or self-hosted vault becomes compelling when customers need retention automation, regulated exports, auditability, or organisation-wide evidence coordination.

The main vault responsibilities derived from the AI Act are:

- retention and availability controls for provider documentation, provider and deployer logs, incident artefacts, and GPAI documentation,
- chain-of-custody semantics and auditability for declarations, registrations, documentation, and incident history,
- role- and disclosure-aware sharing that supports downstream documentation and confidentiality-sensitive exports.

The key vault workflows that map to regulatory interactions are:

- conformity-assessment export with Annex IV-aligned technical documentation and linked runtime evidence,
- declaration and registration package export,
- incident-response export for serious-incident and corrective-action handling,
- AI literacy reporting across systems, roles, and oversight assignments.

## Delivery roadmap and acceptance criteria

The roadmap should follow both the legal timeline and the product strategy. Legally, GPAI and AI literacy are already applicable, and high-risk obligations dominate from August 2, 2026. Product-wise, the build order should be SDK, CLI, and local verification first; optional managed-vault capabilities second.

### Core milestone

Definition of done for the core layer:

- RFC 8785 canonicalisation implemented and test-locked,
- RFC 3161 timestamp support and verification,
- stable evidence bundle format and deterministic signing input,
- typed capture primitives for runtime, governance, and evaluation evidence,
- offline verification report output suitable for auditors and counterparties.

### SDK launch milestone

Definition of done for the TypeScript and Python SDK launch:

- thin bindings over the Rust core,
- local capture, sealing, verification, and selective disclosure,
- OpenTelemetry integration,
- prebuilt evidence-pack templates for Article 4, Annex XI and XII, Article 12, 19, and 26 logging, and the main high-risk governance streams around instructions for use, standards alignment, post-market monitoring, and evaluation evidence.

This is where the product becomes a developer experience rather than a compliance chore.

### Optional managed-vault milestone

Definition of done for the optional managed vault:

- policy-driven retention engine,
- disclosure-policy management and confidentiality-aware export,
- Annex IV, XI, XII, incident, and conformity export workflows,
- durable indexing and audit trails,
- support for organisation-wide reporting and regulator-facing pack assembly.

### Optional transparency milestone

Definition of done for the transparency option:

- pluggable receipt providers,
- clear verifier outputs explaining which assurance level is present,
- a clean separation between mandatory integrity checks and optional ecosystem-anchoring features.

### Readiness test for August 2, 2026

By August 2, 2026, the practical test is whether a customer can use the product to demonstrate:

- logging capability and retention support under Articles 12, 19, and 26,
- Annex IV documentation completeness and currency,
- evidence of risk management, data governance, instructions for use, oversight, evaluation, and post-market monitoring controls,
- and, where the organisation is in scope, declaration, registration, and related conformity artefacts.

That is the practical definition of EU AI Act readiness for this platform: a customer can verify the local evidence package directly or, where they use the managed layer, open the vault, produce the pack, and have the proof verify cleanly and without hand-waving. The demo frontend can illustrate that workflow, but it is not the production compliance boundary.
