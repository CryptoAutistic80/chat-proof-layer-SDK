# EU AI Act Readiness Plan for a Tamper-Evident AI Compliance Evidence SDK and Evidence Vault

## Scope and design principles

This plan assumes you are building an “evidence substrate” that can sit underneath many AI applications and governance stacks: it captures compliance-relevant events and artefacts at runtime and across the lifecycle, seals them into portable, independently verifiable “evidence bundles”, and stores them in an Evidence Vault with retention, access controls, and export workflows suitable for audits, customers, and regulators. The design direction aligns with your initial concept of an AI Output Proof Layer producing cryptographically verifiable “Proof Bundles” (canonicalisation → hashing → signature → timestamp → optional transparency receipts) that can be selectively disclosed and verified outside the vendor platform. fileciteturn0file0

The core regulatory target is the EU AI Act (Regulation (EU) 2024/1689). The risk-based framing matters because evidence obligations concentrate around: (a) high-risk AI systems; (b) general-purpose AI models (GPAI), especially those with systemic risk; and (c) cross-cutting obligations like AI literacy. The entity["organization","European Commission","eu executive body"] summarises the AI Act as a risk-based legal framework and provides an official application timeline: entry into force 1 August 2024; prohibited practices and AI literacy obligations from 2 February 2025; GPAI governance/obligations from 2 August 2025; general high-risk regime from 2 August 2026; and a longer transition for some high-risk AI embedded in regulated products until 2 August 2027. citeturn10view0

Design principles that follow directly from the Act’s structure and from “audit-grade” engineering:

- Evidence must be **externally verifiable** (not merely “stored in our database”), because conformity assessment, market surveillance, incident investigations, and B2B procurement audits all benefit from independent verification pathways. citeturn25view2turn27search11  
- Evidence capture must be **role-aware** (provider vs deployer vs downstream integrator), since the Act assigns obligations across the AI value chain and differentiates what providers must design into systems versus what deployers must operate and retain. citeturn11search3turn12search1turn22view1  
- Evidence storage must be **privacy- and confidentiality-sensitive**: logs and artefacts often contain personal data, trade secrets, and security-sensitive details, while the AI Act’s own retention requirements are explicitly “without prejudice” to personal data protection law in the logging context. citeturn12search0turn11search3turn22view1  

Compliance is a drumbeat; evidence keeps time.

## EU AI Act requirements that drive evidence capture

### High-risk AI systems: lifecycle controls plus traceability

For high-risk AI systems, the AI Act sets out a tightly coupled set of design-time and run-time obligations that translate naturally into an “evidence specification”.

- **Risk management is continuous and documented across the lifecycle.** Article 9 requires a risk management system that is established, implemented, documented, and maintained, conceived as a “continuous iterative process” with steps including identification/analysis of foreseeable risks, evaluation under intended use and reasonably foreseeable misuse, and testing to verify compliance and performance. citeturn11search0  
- **Data governance and dataset quality are evidence-bearing obligations.** Article 10 requires training/validation/testing datasets (and, more broadly, datasets used in high-risk systems) to be subject to data governance and management practices covering design choices, collection, preparation (labelling/cleaning/updating/enrichment), assumptions, bias detection/mitigation, and context-of-use characteristics. citeturn17view0  
- **Technical documentation is mandatory and annex-defined.** Article 11 requires technical documentation to be prepared before placing on the market / putting into service, kept up to date, and contain at least Annex IV elements to enable competent authorities and notified bodies to assess compliance. citeturn11search1turn15search14  
- **Logging is a first-class legal requirement.** Article 12 requires high-risk AI systems to “technically allow for the automatic recording of events (logs)” over the lifetime of the system, and specifies the traceability purposes logs must support (risk detection/substantial modification, post-market monitoring, and deployer monitoring duties). citeturn14search3  
- **Human oversight, transparency/instructions, and robustness/cybersecurity require demonstrable operationalisation.** Article 13 ties transparency to deployers’ ability to interpret output and use it appropriately; Article 14 requires high-risk systems to be designed so that they can be effectively overseen by natural persons and that humans can monitor/interpret/override (with special requirements in some biometric contexts); Article 15 requires appropriate accuracy, robustness and cybersecurity “throughout their lifecycle”, including declared accuracy metrics in instructions for use. citeturn11search2turn17view2turn15search2  
- **Providers must retain documentation for long periods; logs for at least six months.** Article 18 requires providers to keep technical documentation, quality management system documentation, notified body materials (where applicable), and the EU declaration of conformity for 10 years after placing on the market/putting into service. Article 19 requires providers to keep automatically generated logs (Article 12 logs) for a period appropriate to intended purpose, at least six months, subject to other applicable law (including data protection law). citeturn12search1turn12search0  
- **Deployers also carry operational and retention duties.** Article 26 requires deployers to use high-risk systems per instructions, assign human oversight, monitor operation, manage input data (where they control it), and keep “logs automatically generated” under their control for at least six months (again, subject to other applicable law, notably data protection). citeturn11search3  

These articles imply that an “AI compliance evidence platform” is not just a logging pipeline: it must support lifecycle artefacts (documentation, risk controls, data governance evidence, oversight measures) and runtime traceability (automatic logs, monitoring, incident markers) in ways that are durable for audits and market surveillance. citeturn11search1turn14search3turn12search1turn11search3

### Conformity assessment and standards: evidence must align with audit procedures

High-risk systems are subject to conformity assessment pathways (internal control or notified body involvement depending on category and standards usage). Article 43 sets out when internal control (Annex VI) versus notified body procedures (Annex VII) apply, and it links the pathway to the application (or non-application) of harmonised standards and/or common specifications. citeturn25view2turn13search4

Article 40 establishes the “presumption of conformity” mechanism: high-risk AI systems or GPAI models conforming to harmonised standards (published in the Official Journal references) are presumed to meet covered requirements/obligations, and the Commission is obligated to issue standardisation requests for relevant requirements (including reporting/documentation processes and even resource-performance related deliverables). citeturn25view0

For an Evidence SDK/Vault, this means the product should treat “standard alignment” as data: evidence bundles should capture which harmonised standards / common specifications were applied, and produce audit exports that map artefacts to Annex IV (high-risk) and Annex XI/XII (GPAI) structures. citeturn11search1turn15search14turn25view0turn22view1

### GPAI models: evidence obligations are already in force

GPAI obligations became applicable on 2 August 2025. citeturn10view0turn23search3

Article 53 requires providers of general-purpose AI models to (a) draw up and keep up-to-date technical documentation containing at least Annex XI information and provide it to the AI Office/competent authorities upon request; (b) provide downstream documentation containing at least Annex XII elements to integrators; (c) implement a copyright compliance policy; and (d) publish a sufficiently detailed public summary of training content using a template provided by the AI Office. citeturn22view1turn21view0turn21view2turn10view0turn18search3

Article 55 adds “systemic risk” obligations: model evaluation with state-of-the-art protocols, adversarial testing, systemic risk assessment/mitigation, serious incident tracking/reporting to the AI Office, and cybersecurity protection for the model and its supporting infrastructure. citeturn20view0

Because these obligations are already applicable (March 2026), your launch architecture should support GPAI evidence capture on day one—even if many customers are not “model providers” but integrators who need Annex XII-ready documentation and provenance for downstream compliance. citeturn22view1turn21view2turn10view0

### AI literacy: a cross-cutting evidence stream already applicable

Article 4 requires providers and deployers to take measures to ensure, “to their best extent”, a sufficient level of AI literacy for staff and other persons dealing with AI systems on their behalf, taking into account knowledge/experience/training and context of use. citeturn23search0turn23search1

The Commission’s AI literacy Q&A makes two particularly relevant points for an evidence product: (1) Article 4 entered into application on 2 February 2025 (i.e., it already applies), and (2) the organisation should tailor AI literacy measures to its role (provider vs deployer) and the risk level of the AI systems involved. citeturn23search1turn23search3

For your SDK/Vault, AI literacy evidence is not “nice-to-have”; it is a compliance evidence stream that should be supported out of the box (training completion, role-based curricula, attestation of competence for oversight roles). citeturn23search0turn23search1turn11search3

## Evidence taxonomy and mapping to the Act

A production-ready plan needs a **clear evidence taxonomy** that supports: (a) what must exist (documentation/controls), (b) what must happen (runtime traceability), and (c) what must be provable later (immutability, retention, portability).

A pragmatic taxonomy for the SDK and Vault is to treat evidence as cryptographically sealed **Evidence Items** grouped into **Evidence Packs** aligned with major AI Act artefacts:

- **High-risk Technical File Pack** (Annex IV + linked articles): technical documentation, risk management artefacts, dataset governance artefacts, accuracy/robustness/cybersecurity test evidence, human oversight design, post-market monitoring plan, and links to EU declaration of conformity and registration artefacts. citeturn11search1turn15search14turn17view0turn17view2turn15search2turn27search7turn29view0  
- **High-risk Runtime Log Pack** (Article 12 + Article 19 + deployer Article 26): system-generated logs plus derived monitoring events (risk flags, suspected substantial modifications), retained per applicable periods and exportable for authorities. citeturn14search3turn12search0turn11search3  
- **GPAI Provider Pack** (Article 53 + Annex XI): model description, architecture/parameters, training/testing/validation provenance, evaluation results, acceptable use policies, distribution, and required process documentation. citeturn22view1turn21view0  
- **GPAI Downstream Integration Pack** (Article 53 + Annex XII): documentation package provided to downstream system providers to understand capabilities/limitations and comply with their own obligations. citeturn22view1turn21view2  
- **Systemic Risk Pack** (Article 55): adversarial testing evidence, model evaluation protocols/results, systemic risk register and mitigations, serious incident reports and corrective measures, and cybersecurity posture evidence. citeturn20view0turn11search17  
- **AI Literacy Pack** (Article 4): training curricula by role/system risk, attendance/completion evidence, and competence attestations for oversight assignees. citeturn23search0turn23search1turn11search3  

To make this operational, the SDK should emit *typed* evidence events/artefacts with stable IDs (system_id, model_id, version, deployment_id), and the Vault should index them by (role, obligation, system, timeframe, and retention schedule). This connects directly to the Act’s documentation and log retention requirements (10 years for provider documentation; minimum six months for logs under provider/deployer control). citeturn12search1turn12search0turn11search3

A concise mapping (illustrative rather than exhaustive):

| AI Act driver | What must be evidenced | What the SDK should capture | What the Vault must guarantee |
|---|---|---|---|
| Art. 9 risk management | Continuous lifecycle process, testing, mitigation decisions | Risk register deltas, test run attestations, mitigation approvals, “reasonably foreseeable misuse” analysis snapshots | Versioned retention, integrity across revisions, exportable change history citeturn11search0 |
| Art. 10 data governance | Data origin, preparation, bias detection/mitigation, context-of-use fit | Dataset provenance references, preprocessing pipeline hashes, bias checks, representativeness metrics, approvals | Access controls + selective disclosure; retention aligned to provider obligations citeturn17view0turn12search1 |
| Art. 11 + Annex IV | Technical documentation before market/put into service + updates | Document manifests, build artefact hashes, linked test evidence, standards applied list | Long-term retention (10 years where applicable), tamper-evidence, audit export packs citeturn11search1turn12search1turn27search7 |
| Art. 12 + Art. 19 + Art. 26 | Automatic event logging + minimum retention | Runtime event logs; “risk indicator” events; monitoring events; system/user action traces | Immutable/append-only semantics, retention controls, time-bounded retrieval for audits citeturn14search3turn12search0turn11search3 |
| Art. 47 + Annex V + Art. 49 + Art. 71 | Declaration/registration/CE-marking supply-chain evidence | Signed declaration artefact, registration payload receipts, references to notified body outputs where needed | Durable storage + proof of integrity for declarations/registration artefacts citeturn29view0turn29view1turn26search2turn26search3turn26search1 |
| Art. 53 + Annex XI/XII | GPAI documentation, downstream info, training summary, copyright policy | Model doc bundle; downstream integration doc; training summary artefact/version | Evidence packaging suitable for downstream sharing; confidentiality controls citeturn22view1turn21view0turn21view2turn18search3 |
| Art. 55 systemic risk | Evaluation, adversarial testing, incident reporting, cybersecurity | Evaluation runs + adversarial tests; incident event stream; mitigations | Immutable incident history + export for AI Office/authorities citeturn20view0turn11search17 |
| Art. 4 AI literacy | “Sufficient level” measures; context/risk tailored | Training records, role mapping, oversight-operator competence attestations | Retention + audit-ready reporting across systems and roles citeturn23search0turn23search1 |

The “melody” here is consistent: the AI Act repeatedly asks for *documented systems*, *traceability*, and *retention*—so your product should make those artefacts first-class and verifiable. citeturn10view0turn11search1turn14search3turn12search1turn22view1turn23search0

image_group{"layout":"carousel","aspect_ratio":"16:9","query":["EU AI Act risk pyramid four risk levels diagram","European Commission AI Act risk-based approach pyramid image"]}

## Tamper-evident cryptographic design for evidence bundles

Your concept already points in the strongest direction: portable “Proof Bundles” (here: Evidence Bundles) assembled from normalised events/artefacts, sealed cryptographically, timestamped, and optionally anchored in a transparency system. fileciteturn0file0

A production-ready “tamper-evident” design should explicitly separate **integrity guarantees** (what can be proven cryptographically) from **availability/retention guarantees** (what storage and governance ensure). The AI Act’s logging and documentation retention requirements create the business reason to do both. citeturn14search3turn12search1turn12search0

### Canonicalisation and hashing to make events “hashable”

If evidence payloads include JSON (likely, given cross-language SDKs), deterministic canonicalisation is required so that the same logical content produces the same byte representation for hashing/signing. RFC 8785 (JSON Canonicalization Scheme, JCS) defines a canonical representation using deterministic property sorting and constraints aligned with the I-JSON subset, producing a “hashable” JSON representation suitable for cryptographic operations. citeturn30search4turn30search0

**Recommendation:** define a single canonicalisation profile in the Rust core (e.g., RFC 8785-compliant), apply it to all structured evidence objects, and treat the canonical bytes as the signing input invariant across languages. This is the heartbeat that keeps Node/Python/other bindings in sync. citeturn30search4turn30search8turn30search24

### Timestamping for audit and legal contexts

RFC 3161 defines the Time-Stamp Protocol (TSP) and specifies request/response formats and security-relevant requirements for Time Stamping Authority operation, providing time-stamp tokens that bind a hash (“message imprint”) to a time. citeturn30search17turn30search1

For EU-facing evidentiary strength, eIDAS Article 41 establishes that an electronic time stamp shall not be denied legal effect and admissibility as evidence solely because it is electronic or not “qualified”, and that a **qualified** electronic time stamp enjoys a presumption of accuracy of date/time and integrity of the data to which the date/time are bound. citeturn30search3turn30search7

**Recommendation:** architect timestamping as a policy-driven step:
- Baseline: RFC 3161 time-stamps for bundle hashes (interoperable, widely supported). citeturn30search17  
- Optional “higher assurance”: support integration with qualified timestamp services where customers need the eIDAS presumptions in court/regulatory disputes. citeturn30search3turn30search23  

### Transparency anchoring to resist repudiation at ecosystem scale

Certificate Transparency (RFC 6962) is a canonical example of an append-only log enabling public auditing: it is designed so observers can notice suspect issuance and audit the logs themselves. citeturn30search2

Your concept’s direction—optional transparency log receipts—fits modern supply-chain integrity patterns (and is especially compelling for AI Act disputes where “who knew what, when” becomes contested). fileciteturn0file0

Two practical architectural options, both compatible with a Rust core:

- **Integrate an existing transparency log ecosystem**, e.g. entity["organization","Sigstore","open source signing project"]’s Rekor transparency log (public instance and self-managed deployments exist). The Rekor documentation positions it as a logging component with a public instance; Sigstore also documents monitoring/verification concepts around transparency logs. citeturn31search1turn31search16turn31search4  
- **Support general-purpose “signed statements + receipts” transparency services**, aligned with entity["organization","IETF","internet standards body"] SCITT architecture drafts: a transparency service registers signed statements and provides receipts; the architecture explicitly frames receipts and verification without requiring trust in a single centralised operator. citeturn31search2turn31search5  

**Recommendation:** treat transparency anchoring as a pluggable “receipt provider” interface in the Rust core so customers can choose:
- no transparency (signature + timestamp only),
- Sigstore-style log anchoring, or
- SCITT-compatible transparency services. citeturn31search1turn31search2turn30search2  

### Selective disclosure and confidentiality

AI Act evidence often includes sensitive prompts, retrieved documents, tool outputs, and model/system details—some of which may be trade secrets or personal data. Article 53 explicitly requires sharing documentation while observing intellectual property rights and protection of confidential business information/trade secrets, and Article 55 notes confidentiality handling under the Act. citeturn22view1turn20view0

**Recommendation:** implement Evidence Bundles as *manifests of claims* plus *encrypted payload envelopes*, with Merkle commitments enabling selective disclosure proofs (disclose only the necessary leaves while proving inclusion in a signed-and-timestamped root). This aligns with the Act’s twin pressures: disclose enough for compliance, limit exposure of sensitive content. citeturn22view1turn20view0turn30search4  

## Rust-first SDK architecture and language strategy

The product requirement (“Rust core + SDK; TypeScript and Python at launch; path to more languages”) maps cleanly to a design where the Rust crate is the *source of truth* for:

- evidence object schema and canonicalisation profile,
- hashing/signing/timestamp logic and verification,
- bundle packaging and validation,
- plugin interfaces (timestamp providers, transparency receipt providers, encryption/key providers),
- a reference CLI verifier and export tooling. fileciteturn0file0

### Core API shape: capture, seal, verify, export

At minimum, the Rust core should expose four stable capability families:

1. **Capture API**: normalise runtime events into a stable evidence schema (including AI/agent calls, tool calls, retrieval, human oversight actions, and policy decisions). This should be compatible with the direction of standardised GenAI observability. citeturn31search0turn31search6  
2. **Seal API**: canonicalise (RFC 8785), hash, sign, request RFC 3161 timestamps, and optionally obtain transparency receipts; output a self-contained Evidence Bundle object + detached verification material. citeturn30search4turn30search17turn31search2  
3. **Verify API**: verify signature integrity, timestamp validity, and (if present) transparency receipt inclusion/consistency proofs; produce a deterministic “verification report” object for auditors. citeturn31search2turn31search16turn30search2  
4. **Export API**: compile Evidence Packs aligned with AI Act artefacts (Annex IV / Annex XI / Annex XII, plus log retention windows) into machine-readable packages suitable for sharing with notified bodies, customers, or authorities. citeturn11search1turn21view0turn21view2turn12search1  

### TypeScript and Python bindings: minimise “compliance drift”

Key risk in multi-language compliance SDKs is semantic drift: two implementations that “mostly” match but diverge in edge cases (canonicalisation, timestamp encoding, hashing input, schema versions). RFC 8785 exists specifically to remove JSON serialization nondeterminism for hashing/signing. citeturn30search4turn30search24

**Recommendation:** make the Rust core the singular implementation for canonicalisation/hashing/signing/timestamp verification, and expose bindings that are thin:

- **TypeScript**: surface an ergonomic, async-friendly API, but push cryptographic and canonicalisation work into Rust; integrate with Node runtimes and tracing pipelines. citeturn31search0turn31search12  
- **Python**: same principle; focus Python API on instrumentation and developer ergonomics, but keep sealing/verifying in Rust to avoid reimplementing standards across runtimes. citeturn30search4turn30search17  

### Interoperability with emerging tracing standards

Your concept highlights the ecosystem convergence around traceability/observability and explicitly references OpenTelemetry GenAI semantic conventions. The entity["organization","OpenTelemetry","observability project"] specification provides semantic conventions for GenAI systems (spans/events/attributes), including an explicit event for capturing inference operation details (with opt-in handling and guidance about where to store content). citeturn31search0turn31search3turn31search6

**Recommendation:** implement a two-way mapping layer in the Rust core:

- Ingest: accept OpenTelemetry GenAI spans/events as inputs to Evidence Bundles for customers already instrumented. citeturn31search0turn31search6  
- Emit: optionally emit compliant OTel telemetry while also generating sealed Evidence Bundles, so customers get debugging observability and compliance-grade evidence in one pipeline—two harmonies on the same staff. citeturn31search12turn31search0  

## Evidence Vault architecture and operational model

The Vault is not merely storage; it is the operational boundary where you guarantee immutability semantics, retention schedules, access control and audit trails, and reproducible exports—mirroring how the AI Act expects documentation/logs to exist and be made available for long periods. citeturn12search1turn12search0turn27search11

### Vault responsibilities derived from the AI Act

1. **Retention and availability controls**  
   Providers must keep core documentation available for 10 years (Article 18), and providers/deployers must keep logs for at least six months (Articles 19 and 26), subject to overriding requirements of other applicable law. citeturn12search1turn12search0turn11search3  
   The Vault should therefore enforce policy-based retention at the Evidence Pack and Evidence Item levels, with separate retention classes for: provider technical documentation, provider logs, deployer logs, incident artefacts, and public-facing GPAI disclosures. citeturn22view1turn12search1turn11search3  

2. **Chain-of-custody semantics and auditability**  
   The Vault must preserve the tamper-evident proofs and provide verifiable exports that stand alone in audits. This is directly aligned with “formal non-compliance” triggers that include missing or incorrect EU declarations, missing CE marking, missing registration, and missing technical documentation availability. citeturn27search11turn29view0turn26search2  

3. **Role- and disclosure-aware sharing**  
   Article 53 requires downstream documentation without undermining IP/trade secrets; Article 55 and related provisions include confidentiality considerations. The Vault must support selective disclosure and redaction by policy, while preserving proof validity. citeturn22view1turn20view0turn30search4  

### Vault data model

A practical Vault model is:

- **Evidence Bundle (immutable object)**: sealed payload + verification material (signature, timestamp token(s), optional transparency receipts/checkpoints), plus a minimal metadata header. citeturn30search17turn31search2turn30search4  
- **Evidence Index (mutable index)**: searchable metadata, pointers to bundles, access control lists, retention schedules, and pack membership. The index can evolve without mutating bundle content. citeturn12search1turn12search0  
- **Evidence Pack (curated export unit)**: logical grouping aligned with AI Act artefacts (Annex IV pack, Annex XI pack, Article 12/19/26 log packs, incident packs). citeturn11search1turn21view0turn14search3turn20view0  

### Vault workflows that map to regulatory interactions

- **Conformity assessment export**: compile Annex IV technical documentation elements + linked runtime evidence that supports declared accuracy metrics, oversight measures, and post-market monitoring plans. citeturn11search1turn15search14turn15search2turn12search3  
- **Registration + declaration package**: store and export EU declaration of conformity (Article 47; Annex V contents) and evidence of EU database registration (Article 49/71) alongside applicable notified body material. citeturn29view0turn29view1turn26search2turn26search3turn12search1  
- **Incident response package**: keep track of and report serious incidents/corrective measures for systemic-risk GPAI (Article 55) and support high-risk incident reporting workflows as they mature. citeturn20view0turn11search17  
- **AI literacy evidence reporting**: generate organisation-wide and system-scoped reports demonstrating Article 4 measures (training by role, context, and system risk), with traceability to oversight assignments under Article 26 for high-risk systems. citeturn23search1turn11search3  

## Delivery roadmap and acceptance criteria

This roadmap is structured around (a) legal applicability dates, (b) highest-value evidence obligations, and (c) engineering dependencies for “tamper-evident production readiness”. The rhythm should follow the Act: GPAI and AI literacy are already applicable; high-risk system obligations become the dominant wave from 2 August 2026 (with some extensions). citeturn10view0turn22view1turn23search1

### Milestone focused on a secure, verifiable core

**Definition of done (core):**
- Canonicalisation: RFC 8785 JCS implemented and test-locked (golden vectors). citeturn30search4  
- Timestamping: RFC 3161 integration for bundle hashes; verification tooling included. citeturn30search17  
- Evidence bundle format: stable schema + versioning policy + deterministic signing input; portable verification report. citeturn30search4turn30search17  
- Basic evidence capture primitives: events for LLM calls, tool calls, retrieval, human override/approval, and policy decisions, plus packager APIs. citeturn31search6turn14search3turn17view2  

### Launch milestone for TypeScript and Python SDKs

**Definition of done (launch SDKs):**
- TypeScript and Python bindings are thin wrappers over the Rust core sealing/verifying logic, minimising duplicate implementations of canonicalisation/timestamp verification. citeturn30search4turn30search17  
- OpenTelemetry integration: ingest/emission alignment with GenAI semantic conventions (at least inference spans and tool spans; ideally the opt-in event detail capture approach). citeturn31search0turn31search3turn31search6  
- Prebuilt Evidence Pack templates for: Article 4 AI literacy, Article 53 Annex XI/XII (GPAI provider/downstream), and Article 12/19/26 logging packs. citeturn23search0turn22view1turn14search3turn12search0turn11search3  

This is where the product starts to sing: evidence capture becomes a developer experience, not a compliance chore. citeturn23search1turn22view1turn14search3

### Vault milestone for audit exports and retention

**Definition of done (Vault):**
- Retention policy engine enforcing: provider documentation 10-year retention (Article 18) and log retention minimum six months where applicable (Articles 19 and 26). citeturn12search1turn12search0turn11search3  
- Export workflows for conformity assessment-ready packs aligned to Annex IV requirements (including standards applied list, post-market monitoring plan linkage, and EU declaration of conformity inclusion). citeturn11search1turn27search7turn29view0turn25view0  
- Registration/declaration evidence support: store, index, and export Article 47 declaration artefacts (Annex V fields) and Article 49/71 registration data. citeturn29view0turn29view1turn26search2turn26search3  

### Optional “high-assurance” milestone: transparency anchoring

**Definition of done (transparency option):**
- Pluggable receipt providers supporting at least one of:
  - Sigstore Rekor anchoring pathway, and/or citeturn31search1turn31search4  
  - SCITT-style transparency service receipts aligned with draft architecture expectations. citeturn31search2turn31search5  
- Clear verifier outputs explaining which assurances are present: signature only, signature+timestamp, signature+timestamp+transparency receipt. citeturn30search17turn31search2turn30search2  

### Readiness milestone for the 2026 high-risk wave

By 2 August 2026, the operational test is whether a customer can use your product to demonstrate:

- design-time logging capability compliance (Article 12) and log retention (Articles 19/26), citeturn14search3turn12search0turn11search3  
- Annex IV technical documentation completeness and currency (Article 11), citeturn11search1turn15search14  
- evidence of risk management process (Article 9), data governance controls (Article 10), and oversight measures (Article 14), citeturn11search0turn17view0turn17view2  
- and (where the organisation is in scope) declaration/CE marking/registration artefacts and their integrity (Articles 47–49, 71). citeturn29view0turn26search1turn26search2turn26search3  

That is the practical definition of “EU AI Act readiness” for an evidence platform: when the music stops and the auditor asks, you can open the Vault, produce the pack, and the proof verifies—cleanly, cryptographically, and without hand-waving. citeturn27search11turn11search1turn14search3turn12search1turn22view1