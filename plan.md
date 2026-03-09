# Proof Layer SDK — Full Technical Implementation Plan

## Ground-up rebuild of a production-ready Tamper-Evident AI Compliance Evidence SDK & Evidence Vault

**Target**: EU AI Act (Regulation (EU) 2024/1689) compliance evidence platform
**Architecture**: Rust core → thin FFI bindings → TypeScript SDK, Python SDK, extensible to more languages
**Date**: March 2026
**Regulatory context**: GPAI obligations already applicable (Aug 2025); AI literacy already applicable (Feb 2025); high-risk system obligations apply Aug 2026–2027

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Rust Core (`proof-layer-core`)](#2-rust-core-proof-layer-core)
3. [CLI Tool (`proofctl`)](#3-cli-tool-proofctl)
4. [Evidence Vault Service](#4-evidence-vault-service)
5. [TypeScript SDK (`@proof-layer/sdk`)](#5-typescript-sdk-proof-layersdk)
6. [Python SDK (`proof-layer-sdk`)](#6-python-sdk-proof-layer-sdk)
7. [Evidence Taxonomy & EU AI Act Mapping](#7-evidence-taxonomy--eu-ai-act-mapping)
8. [Cryptographic Design](#8-cryptographic-design)
9. [Testing Strategy](#9-testing-strategy)
10. [Build, CI & Release](#10-build-ci--release)
11. [Migration from PoC](#11-migration-from-poc)
12. [Implementation Phases](#12-implementation-phases)
13. [Open Questions & Decisions](#13-open-questions--decisions)

---

## 1. Architecture Overview

### System Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Application Layer                            │
│  TypeScript SDK  │  Python SDK  │  Future: Go, Java, C#, etc.       │
├─────────────────────────────────────────────────────────────────────┤
│                        FFI / Binding Layer                          │
│  NAPI-RS (Node)  │  PyO3 (Python)  │  C ABI (future languages)     │
├─────────────────────────────────────────────────────────────────────┤
│                      Rust Core Library                              │
│  Canonicalize │ Hash │ Merkle │ Sign │ Verify │ Timestamp │ Bundle  │
│  Evidence Schema │ Selective Disclosure │ Receipt Providers          │
├─────────────────────────────────────────────────────────────────────┤
│                      Evidence Vault Service                         │
│  Axum HTTP API │ Storage Engine │ Retention Engine │ Export Engine   │
│  Index │ Access Control │ Audit Trail │ Pack Assembly                │
├─────────────────────────────────────────────────────────────────────┤
│                      Storage Backend                                │
│  Local (SQLite/sled) │ S3-compatible │ PostgreSQL (Vault metadata)  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Single implementation of cryptographic logic** — Rust core is the sole implementation of canonicalization, hashing, signing, Merkle construction, and verification. No reimplementation in JS/Python.
2. **Thin FFI bindings** — TypeScript and Python SDKs call into compiled Rust via NAPI-RS and PyO3 respectively. SDKs add ergonomics, provider wrappers, and OTel integration but never reimplement crypto.
3. **Evidence-first, not logging-first** — Every captured item is an Evidence Item with a stable schema, typed to an EU AI Act obligation, and designed for long-term retention and audit export.
4. **Offline verification always** — Any Evidence Bundle can be verified with only the bundle file and a public key. No network calls, no vendor dependency.
5. **Pluggable assurance levels** — Signature only → +RFC 3161 timestamp → +transparency receipt. Customers choose their assurance level via policy configuration.

### Workspace Layout (Target)

```
proof-layer-sdk/
├── Cargo.toml                          # Workspace root
├── crates/
│   ├── core/                           # proof-layer-core (library)
│   ├── cli/                            # proofctl (binary)
│   ├── vault/                          # Evidence Vault service (binary)
│   ├── ffi-c/                          # C ABI exports for future languages
│   ├── napi/                           # NAPI-RS bridge for Node.js
│   └── pyo3/                           # PyO3 bridge for Python
├── sdks/
│   ├── typescript/                     # @proof-layer/sdk (npm)
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── client.ts              # Vault HTTP client
│   │   │   ├── evidence.ts            # Evidence capture helpers
│   │   │   ├── providers/             # AI provider wrappers
│   │   │   ├── otel/                  # OpenTelemetry integration
│   │   │   └── types.ts              # Generated from Rust schema
│   │   ├── native/                    # NAPI-RS compiled bindings
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── python/                         # proof-layer-sdk (PyPI)
│       ├── proof_layer/
│       │   ├── __init__.py
│       │   ├── _native.pyi            # Type stubs for PyO3 module
│       │   ├── client.py              # Vault HTTP client
│       │   ├── evidence.py            # Evidence capture helpers
│       │   ├── providers/             # AI provider wrappers
│       │   └── otel/                  # OpenTelemetry integration
│       ├── pyproject.toml
│       └── tests/
├── schemas/                            # Canonical JSON schemas
│   ├── evidence_bundle.schema.json
│   ├── evidence_item.schema.json
│   ├── evidence_pack.schema.json
│   └── capture_event.schema.json
├── fixtures/
│   ├── golden/                         # Deterministic test vectors
│   └── rfc8785/                        # RFC 8785 test vectors
├── docs/
│   ├── architecture.md
│   ├── evidence_taxonomy.md
│   ├── threat_model.md
│   ├── eu_ai_act_mapping.md
│   └── api_reference.md
├── examples/
│   ├── typescript/
│   ├── python/
│   └── rust/
└── web-demo/                           # Verification UI
```

### What Changes from the PoC

| Aspect | PoC (current) | Production (target) |
|--------|--------------|---------------------|
| Directory layout | `packages/core-rust`, `packages/sdk-node` | `crates/core`, `sdks/typescript` |
| Node.js binding | HTTP client calling proof-service | NAPI-RS compiled native module |
| Python binding | HTTP client calling proof-service | PyO3 compiled native module |
| Crypto in JS/Python | `json-canonicalize` npm package used | All crypto via Rust FFI |
| Timestamping | Not implemented | RFC 3161 + optional eIDAS qualified |
| Transparency | Not implemented | Pluggable receipt providers |
| Selective disclosure | Schema placeholder only | Merkle-based selective disclosure |
| Storage | sled + filesystem | SQLite/PostgreSQL + S3-compatible |
| Retention | Not implemented | Policy engine with EU AI Act schedules |
| Evidence typing | Generic "capture" + "artefacts" | Typed Evidence Items mapped to Act articles |
| Bundle schema | `bundle_version: "0.1"` | `bundle_version: "1.0"` with migration |
| Export | CLI inspect only | Annex-aligned pack assembly + export |

---

## 2. Rust Core (`proof-layer-core`)

### Crate: `crates/core/`

This is the single source of truth for all cryptographic operations and evidence schema definitions.

### 2.1 Module Structure

```
crates/core/src/
├── lib.rs                  # Public API surface
├── schema/
│   ├── mod.rs
│   ├── evidence_bundle.rs  # EvidenceBundle struct + versioning
│   ├── evidence_item.rs    # Typed evidence items (risk, data gov, etc.)
│   ├── evidence_pack.rs    # Pack definitions aligned to Annexes
│   ├── capture_event.rs    # Runtime event capture schema
│   ├── actor.rs            # Actor/identity metadata
│   ├── policy.rs           # Redaction/encryption/retention policy
│   └── migration.rs        # Schema version migration (0.1 → 1.0)
├── canon/
│   ├── mod.rs
│   ├── jcs.rs              # RFC 8785 canonicalization
│   └── validation.rs       # Strict JSON parsing, integer range checks
├── hash.rs                 # SHA-256 + SHA-512 utilities
├── merkle/
│   ├── mod.rs
│   ├── tree.rs             # Merkle tree construction
│   ├── proof.rs            # Inclusion/exclusion proofs for selective disclosure
│   └── commitment.rs       # Root commitment computation
├── sign/
│   ├── mod.rs
│   ├── ed25519.rs          # Ed25519 JWS signing (existing)
│   ├── ecdsa.rs            # ECDSA P-256 JWS signing (for HSM compat)
│   ├── jws.rs              # JWS compact serialization
│   └── key.rs              # Key loading (PEM, PKCS#8, PKCS#11 stub)
├── timestamp/
│   ├── mod.rs
│   ├── rfc3161.rs          # RFC 3161 TSP client + response parsing
│   ├── provider.rs         # TimestampProvider trait
│   └── verify.rs           # Timestamp token verification
├── transparency/
│   ├── mod.rs
│   ├── provider.rs         # TransparencyProvider trait
│   ├── rekor.rs            # Sigstore Rekor client
│   └── scitt.rs            # SCITT receipt handling (stub)
├── disclosure/
│   ├── mod.rs
│   ├── selective.rs        # Merkle-proof selective disclosure
│   └── redaction.rs        # Field-level redaction with proof preservation
├── bundle/
│   ├── mod.rs
│   ├── build.rs            # Bundle construction orchestration
│   ├── verify.rs           # Full bundle verification
│   └── export.rs           # Serialization for transport
├── pack/
│   ├── mod.rs
│   ├── annex_iv.rs         # High-risk technical documentation pack
│   ├── annex_xi.rs         # GPAI provider pack
│   ├── annex_xii.rs        # GPAI downstream integration pack
│   ├── runtime_log.rs      # Art 12/19/26 runtime log pack
│   ├── risk_mgmt.rs        # Art 9 risk management pack
│   ├── ai_literacy.rs      # Art 4 AI literacy pack
│   ├── systemic_risk.rs    # Art 55 systemic risk pack
│   └── assembly.rs         # Pack compilation and export
├── retention/
│   ├── mod.rs
│   └── policy.rs           # Retention schedule definitions
└── error.rs                # Error types
```

### 2.2 Core Types

```rust
/// Top-level evidence bundle — the sealed, verifiable unit
pub struct EvidenceBundle {
    pub bundle_version: String,          // "1.0"
    pub bundle_id: String,               // ULID
    pub created_at: DateTime<Utc>,
    pub actor: Actor,
    pub subject: Subject,
    pub context: EvidenceContext,         // NEW: replaces model-specific fields
    pub items: Vec<EvidenceItem>,         // NEW: typed evidence items
    pub artefacts: Vec<ArtefactRef>,
    pub policy: Policy,
    pub integrity: Integrity,
    pub timestamp: Option<TimestampToken>,
    pub receipt: Option<TransparencyReceipt>,
}

/// Actor identity — who created this evidence
pub struct Actor {
    pub issuer: String,
    pub app_id: String,
    pub env: String,
    pub signing_key_id: String,
    pub role: ActorRole,                 // NEW: Provider | Deployer | Integrator
    pub organization_id: Option<String>, // NEW: for multi-tenant vaults
}

/// What the evidence is about
pub struct Subject {
    pub request_id: Option<String>,
    pub thread_id: Option<String>,
    pub user_ref: Option<String>,        // HMAC pseudonym
    pub system_id: Option<String>,       // NEW: AI system identifier
    pub model_id: Option<String>,        // NEW: model identifier
    pub deployment_id: Option<String>,   // NEW: deployment instance
    pub version: Option<String>,         // NEW: system/model version
}

/// Typed evidence item — each maps to an AI Act obligation
pub enum EvidenceItem {
    // Runtime evidence (Art 12, 19, 26)
    LlmInteraction(LlmInteractionEvidence),
    ToolCall(ToolCallEvidence),
    Retrieval(RetrievalEvidence),
    HumanOversight(HumanOversightEvidence),
    PolicyDecision(PolicyDecisionEvidence),

    // Lifecycle evidence (Art 9, 10, 11)
    RiskAssessment(RiskAssessmentEvidence),
    DataGovernance(DataGovernanceEvidence),
    TechnicalDoc(TechnicalDocEvidence),

    // GPAI evidence (Art 53, 55)
    ModelEvaluation(ModelEvaluationEvidence),
    AdversarialTest(AdversarialTestEvidence),
    TrainingProvenance(TrainingProvenanceEvidence),
    IncidentReport(IncidentReportEvidence),

    // Cross-cutting (Art 4)
    LiteracyAttestation(LiteracyAttestationEvidence),

    // Conformity (Art 43, 47, 49)
    ConformityAssessment(ConformityAssessmentEvidence),
    Declaration(DeclarationEvidence),
    Registration(RegistrationEvidence),
}

/// Each evidence item carries its own commitment
pub struct LlmInteractionEvidence {
    pub provider: String,
    pub model: String,
    pub parameters: serde_json::Value,
    pub input_commitment: String,        // sha256 of canonical input
    pub output_commitment: String,       // sha256 of canonical output
    pub token_usage: Option<TokenUsage>,
    pub latency_ms: Option<u64>,
    pub trace_id: Option<String>,        // OTel trace ID
}

/// Risk management evidence (Art 9)
pub struct RiskAssessmentEvidence {
    pub system_id: String,
    pub assessment_type: RiskAssessmentType, // Initial | Update | Periodic
    pub risk_register_commitment: String,    // hash of risk register snapshot
    pub identified_risks: u32,
    pub mitigated_risks: u32,
    pub accepted_risks: u32,
    pub assessor: String,
    pub methodology: Option<String>,
}

/// Retention policy
pub struct RetentionPolicy {
    pub class: RetentionClass,
    pub minimum_duration: Duration,
    pub legal_basis: String,             // "Art 18" | "Art 19" | "Art 26"
    pub delete_after: Option<Duration>,  // For GDPR compliance
}

pub enum RetentionClass {
    ProviderDocumentation,    // 10 years (Art 18)
    ProviderLogs,             // >= 6 months (Art 19)
    DeployerLogs,             // >= 6 months (Art 26)
    IncidentRecords,          // 10 years (linked to Art 18)
    GpaiDocumentation,       // Until model withdrawn + reasonable period
    LiteracyRecords,         // Organizational policy
}
```

### 2.3 Core API Surface

```rust
// === Capture API ===
/// Normalize a runtime event into a typed evidence item
pub fn capture_llm_interaction(event: LlmCaptureInput) -> Result<EvidenceItem>;
pub fn capture_tool_call(event: ToolCaptureInput) -> Result<EvidenceItem>;
pub fn capture_human_oversight(event: OversightInput) -> Result<EvidenceItem>;
pub fn capture_risk_assessment(event: RiskInput) -> Result<EvidenceItem>;
// ... one per EvidenceItem variant

// === Seal API ===
/// Build a complete evidence bundle from items + artefacts
pub fn build_bundle(config: BundleBuildConfig) -> Result<EvidenceBundle>;
/// Canonicalize JSON bytes per RFC 8785
pub fn canonicalize(json: &[u8]) -> Result<Vec<u8>>;
/// Compute SHA-256 digest with "sha256:" prefix
pub fn hash_sha256(data: &[u8]) -> String;
/// Build Merkle tree and return root
pub fn compute_merkle_root(digests: &[String]) -> Result<String>;
/// Sign bundle root, producing JWS compact serialization
pub fn sign(root: &str, key: &SigningKey, kid: &str) -> Result<String>;
/// Request RFC 3161 timestamp for a digest
pub async fn timestamp(digest: &str, provider: &dyn TimestampProvider) -> Result<TimestampToken>;
/// Submit to transparency log and get receipt
pub async fn anchor(bundle: &EvidenceBundle, provider: &dyn TransparencyProvider) -> Result<TransparencyReceipt>;

// === Verify API ===
/// Full verification: signature + merkle + artefacts + optional timestamp + optional receipt
pub fn verify_bundle(bundle: &EvidenceBundle, artefacts: &[Artefact], key: &VerifyingKey) -> Result<VerificationReport>;
/// Verify only the signature
pub fn verify_signature(jws: &str, key: &VerifyingKey) -> Result<()>;
/// Verify a timestamp token
pub fn verify_timestamp(token: &TimestampToken, digest: &str) -> Result<TimestampVerification>;
/// Verify a transparency receipt
pub fn verify_receipt(receipt: &TransparencyReceipt, bundle_root: &str) -> Result<ReceiptVerification>;

// === Selective Disclosure API ===
/// Generate a Merkle inclusion proof for specific items
pub fn generate_disclosure_proof(bundle: &EvidenceBundle, item_indices: &[usize]) -> Result<DisclosureProof>;
/// Verify a selective disclosure proof
pub fn verify_disclosure_proof(proof: &DisclosureProof, root: &str) -> Result<()>;
/// Redact items from a bundle while preserving verifiability
pub fn redact_bundle(bundle: &EvidenceBundle, redact_indices: &[usize]) -> Result<RedactedBundle>;

// === Export API ===
/// Compile an evidence pack for a specific Annex/obligation
pub fn assemble_pack(pack_type: PackType, items: &[EvidenceBundle]) -> Result<EvidencePack>;
/// Export a pack as a portable archive
pub fn export_pack(pack: &EvidencePack, format: ExportFormat) -> Result<Vec<u8>>;

// === Pack API ===
/// Package a bundle into a .pkg archive (gzip JSON)
pub fn package_bundle(bundle: &EvidenceBundle, artefacts: &[Artefact]) -> Result<Vec<u8>>;
/// Unpackage a .pkg archive
pub fn unpackage_bundle(pkg: &[u8]) -> Result<(EvidenceBundle, Vec<Artefact>)>;
```

### 2.4 Trait Abstractions for Pluggability

```rust
/// Timestamp provider — swappable between free RFC 3161 and qualified eIDAS TSAs
#[async_trait]
pub trait TimestampProvider: Send + Sync {
    async fn timestamp(&self, digest: &[u8]) -> Result<TimestampToken>;
    fn provider_name(&self) -> &str;
    fn assurance_level(&self) -> TimestampAssurance; // Standard | Qualified
}

/// Transparency receipt provider — swappable between none, Rekor, SCITT
#[async_trait]
pub trait TransparencyProvider: Send + Sync {
    async fn submit(&self, entry: &TransparencyEntry) -> Result<TransparencyReceipt>;
    async fn verify(&self, receipt: &TransparencyReceipt) -> Result<()>;
    fn provider_name(&self) -> &str;
}

/// Signing key provider — swappable between local keys, HSM, KMS
pub trait KeyProvider: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn public_key(&self) -> &[u8];
    fn algorithm(&self) -> SigningAlgorithm;
    fn key_id(&self) -> &str;
}

/// Storage backend — swappable for vault implementations
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn store_bundle(&self, bundle: &EvidenceBundle) -> Result<()>;
    async fn get_bundle(&self, id: &str) -> Result<Option<EvidenceBundle>>;
    async fn store_artefact(&self, bundle_id: &str, name: &str, data: &[u8]) -> Result<()>;
    async fn get_artefact(&self, bundle_id: &str, name: &str) -> Result<Option<Vec<u8>>>;
    async fn query_bundles(&self, query: BundleQuery) -> Result<Vec<EvidenceBundle>>;
    async fn delete_expired(&self, policy: &RetentionPolicy) -> Result<u64>;
}
```

### 2.5 Signing Algorithm Support

| Algorithm | Use Case | Key Format | Status |
|-----------|----------|------------|--------|
| Ed25519 (EdDSA) | Default, fast, small keys | PKCS#8 PEM | Carry from PoC |
| ECDSA P-256 | HSM/KMS compatibility | PKCS#8 PEM, PKCS#11 | New |
| ECDSA P-384 | Higher security contexts | PKCS#8 PEM | New |

### 2.6 Dependencies (Core Crate)

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
ed25519-dalek = { version = "2.2", features = ["pem"] }
p256 = { version = "0.13", features = ["ecdsa"] }
p384 = { version = "0.13", features = ["ecdsa"] }
base64ct = { version = "1.8", features = ["alloc"] }
chrono = { version = "0.4", features = ["serde"] }
ulid = "1"
thiserror = "2"
zeroize = "1"                    # Key material cleanup
reqwest = { version = "0.12", optional = true }  # For timestamp/transparency clients
tokio = { version = "1", optional = true }
x509-cert = { version = "0.2", optional = true } # RFC 3161 response parsing
cms = { version = "0.2", optional = true }        # CMS/PKCS#7 for TSP
jsonschema = { version = "0.29", optional = true }

[features]
default = ["ed25519"]
ed25519 = []
ecdsa = ["p256", "p384"]
timestamp = ["reqwest", "tokio", "x509-cert", "cms"]
transparency = ["reqwest", "tokio"]
full = ["ed25519", "ecdsa", "timestamp", "transparency"]
```

---

## 3. CLI Tool (`proofctl`)

### Crate: `crates/cli/`

Rebuild from the PoC CLI with expanded capabilities.

### 3.1 Commands

```
proofctl keygen [OPTIONS]
    --algorithm <ed25519|p256|p384>   Signing algorithm (default: ed25519)
    --out <DIR>                       Output directory for keypair

proofctl create [OPTIONS]
    --input <CAPTURE.json>            Capture event file
    --artefact <NAME>=<PATH>          Named artefact (repeatable)
    --key <SIGNING.pem>               Signing key
    --kid <KEY_ID>                    Key identifier
    --system-id <ID>                  AI system identifier
    --role <provider|deployer>        Actor role
    --evidence-type <TYPE>            Evidence item type
    --retention-class <CLASS>         Retention classification
    --timestamp-url <URL>             RFC 3161 TSA URL (optional)
    --transparency-log <URL>          Transparency log URL (optional)
    --out <BUNDLE.pkg>                Output package path
    [Deterministic flags carried from PoC: --bundle-id, --created-at]

proofctl verify [OPTIONS]
    --in <BUNDLE.pkg>                 Package to verify
    --key <VERIFY.pub>                Verification public key
    --check-timestamp                 Also verify timestamp token
    --check-receipt                   Also verify transparency receipt
    --output <human|json>             Report format (default: human)

proofctl inspect [OPTIONS]
    --in <BUNDLE.pkg>                 Package to inspect
    --format <human|json>             Output format
    --show-items                      Show evidence item details
    --show-merkle                     Show Merkle tree structure

proofctl disclose [OPTIONS]                    # NEW
    --in <BUNDLE.pkg>                 Full bundle package
    --items <INDICES>                 Comma-separated item indices to disclose
    --out <REDACTED.pkg>              Output redacted package with proofs

proofctl pack [OPTIONS]                        # NEW
    --type <annex-iv|annex-xi|...>    Pack type
    --vault-url <URL>                 Vault API endpoint
    --system-id <ID>                  Filter by system
    --from <DATE>                     Start date
    --to <DATE>                       End date
    --out <PACK.zip>                  Output pack archive

proofctl vault [SUBCOMMAND]                    # NEW
    status                            Vault health + statistics
    query --system-id <ID> ...        Query stored bundles
    export --pack-type <TYPE> ...     Export evidence pack
    retention --report                Show retention status
```

---

## 4. Evidence Vault Service

### Crate: `crates/vault/`

The Vault replaces the PoC's `proof-service` with a production-grade evidence management system.

### 4.1 API Design

```
Health
  GET  /healthz
  GET  /readyz

Evidence Bundles (v1)
  POST   /v1/bundles                    Create + seal a new bundle
  GET    /v1/bundles/{id}               Retrieve bundle by ID
  GET    /v1/bundles/{id}/artefacts/{name}   Download artefact
  POST   /v1/bundles/{id}/timestamp     Add timestamp to existing bundle
  POST   /v1/bundles/{id}/anchor        Submit to transparency log
  DELETE /v1/bundles/{id}               Soft-delete (if retention allows)

Verification
  POST   /v1/verify                     Verify bundle (inline or package)
  POST   /v1/verify/timestamp           Verify timestamp token
  POST   /v1/verify/receipt             Verify transparency receipt

Evidence Packs (v1)
  POST   /v1/packs                      Assemble a new evidence pack
  GET    /v1/packs/{id}                 Retrieve pack metadata
  GET    /v1/packs/{id}/export          Download pack archive
  GET    /v1/packs/{id}/manifest        Pack contents manifest

Query & Search
  GET    /v1/bundles?system_id=&role=&type=&from=&to=&page=&limit=
  GET    /v1/systems                    List known AI systems
  GET    /v1/systems/{id}/summary       System evidence summary

Retention & Administration
  GET    /v1/retention/status           Retention policy status
  POST   /v1/retention/scan             Trigger retention scan
  GET    /v1/audit-trail                Vault access audit log

Configuration
  GET    /v1/config                     Current vault configuration
  PUT    /v1/config/retention           Update retention policies
  PUT    /v1/config/timestamp           Configure timestamp provider
  PUT    /v1/config/transparency        Configure transparency provider
```

### 4.2 Storage Architecture

```
┌───────────────────────────────────────────┐
│              Vault Service                │
├───────────────────────────────────────────┤
│                                           │
│  ┌─────────────┐    ┌──────────────────┐  │
│  │ Metadata DB  │    │ Blob Storage     │  │
│  │ (SQLite or   │    │ (filesystem or   │  │
│  │  PostgreSQL) │    │  S3-compatible)  │  │
│  │              │    │                  │  │
│  │ - bundle idx │    │ - artefact bytes │  │
│  │ - pack idx   │    │ - package files  │  │
│  │ - retention  │    │ - export archive │  │
│  │ - audit log  │    │                  │  │
│  │ - queries    │    │                  │  │
│  └─────────────┘    └──────────────────┘  │
│                                           │
└───────────────────────────────────────────┘
```

**Metadata schema (SQLite tables):**

```sql
-- Core evidence storage
CREATE TABLE bundles (
    bundle_id       TEXT PRIMARY KEY,
    bundle_version  TEXT NOT NULL,
    created_at      TEXT NOT NULL,           -- ISO 8601
    actor_role      TEXT NOT NULL,           -- 'provider' | 'deployer' | 'integrator'
    actor_org_id    TEXT,
    system_id       TEXT,
    model_id        TEXT,
    deployment_id   TEXT,
    bundle_root     TEXT NOT NULL,
    signature_alg   TEXT NOT NULL,
    has_timestamp   BOOLEAN DEFAULT FALSE,
    has_receipt     BOOLEAN DEFAULT FALSE,
    retention_class TEXT NOT NULL,
    expires_at      TEXT,                    -- computed from retention policy
    deleted_at      TEXT,                    -- soft delete
    bundle_json     BLOB NOT NULL,          -- full serialized EvidenceBundle
    canonical_bytes BLOB NOT NULL           -- canonical header for re-verification
);

CREATE INDEX idx_bundles_system ON bundles(system_id, created_at);
CREATE INDEX idx_bundles_retention ON bundles(retention_class, expires_at);
CREATE INDEX idx_bundles_role ON bundles(actor_role, created_at);

-- Evidence item index (one row per item in each bundle)
CREATE TABLE evidence_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id       TEXT NOT NULL REFERENCES bundles(bundle_id),
    item_index      INTEGER NOT NULL,
    item_type       TEXT NOT NULL,           -- 'llm_interaction', 'risk_assessment', etc.
    obligation_ref  TEXT,                    -- 'art9', 'art12', 'art53', etc.
    item_commitment TEXT NOT NULL,
    metadata_json   TEXT                     -- searchable item-specific metadata
);

CREATE INDEX idx_items_type ON evidence_items(item_type, bundle_id);
CREATE INDEX idx_items_obligation ON evidence_items(obligation_ref, bundle_id);

-- Evidence packs
CREATE TABLE packs (
    pack_id         TEXT PRIMARY KEY,
    pack_type       TEXT NOT NULL,           -- 'annex_iv', 'annex_xi', etc.
    system_id       TEXT,
    created_at      TEXT NOT NULL,
    from_date       TEXT,
    to_date         TEXT,
    bundle_count    INTEGER NOT NULL,
    export_path     TEXT,                    -- blob storage path
    manifest_json   TEXT NOT NULL
);

-- Artefact metadata (bytes in blob storage)
CREATE TABLE artefacts (
    bundle_id       TEXT NOT NULL REFERENCES bundles(bundle_id),
    name            TEXT NOT NULL,
    digest          TEXT NOT NULL,
    size            INTEGER NOT NULL,
    content_type    TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    PRIMARY KEY (bundle_id, name)
);

-- Audit trail (append-only)
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    action          TEXT NOT NULL,           -- 'create', 'read', 'verify', 'export', 'delete'
    actor           TEXT,
    bundle_id       TEXT,
    pack_id         TEXT,
    details_json    TEXT
);

-- Retention policy configuration
CREATE TABLE retention_policies (
    retention_class TEXT PRIMARY KEY,
    min_duration_days INTEGER NOT NULL,
    max_duration_days INTEGER,              -- for GDPR delete-after
    legal_basis     TEXT NOT NULL,
    active          BOOLEAN DEFAULT TRUE
);
```

### 4.3 Retention Engine

The retention engine runs as a background task within the vault service:

1. **On bundle creation**: compute `expires_at` from `retention_class` + `created_at` + policy
2. **Periodic scan** (configurable interval, default daily):
   - Find bundles past `expires_at` with no legal hold
   - Soft-delete (set `deleted_at`, remove from active queries)
   - After grace period, hard-delete blob data
3. **Legal hold support**: bundles can be placed on hold, overriding retention expiry
4. **Retention report**: summarize counts by class, earliest/latest expiry, compliance status

### 4.4 Export Engine

Pack assembly for regulatory interactions:

```rust
pub struct ExportConfig {
    pub pack_type: PackType,
    pub system_id: String,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub include_artefacts: bool,
    pub redaction_policy: Option<RedactionPolicy>,
    pub format: ExportFormat,  // Zip | TarGz | Directory
}

pub enum PackType {
    AnnexIV,           // High-risk technical documentation
    AnnexXI,           // GPAI provider documentation
    AnnexXII,          // GPAI downstream integration
    RuntimeLogs,       // Art 12/19/26 log retention
    RiskManagement,    // Art 9 risk management evidence
    AiLiteracy,        // Art 4 literacy evidence
    SystemicRisk,      // Art 55 systemic risk evidence
    IncidentResponse,  // Art 55 + Art 73 incident evidence
    ConformityAssessment, // Art 43 conformity evidence
    Custom(String),    // User-defined pack type
}
```

### 4.5 Configuration

```toml
# vault.toml
[server]
addr = "0.0.0.0:8080"
tls_cert = "/path/to/cert.pem"     # optional
tls_key = "/path/to/key.pem"       # optional

[signing]
key_path = "/path/to/signing.pem"
key_id = "vault-prod-01"
algorithm = "ed25519"               # or "p256", "p384"

[storage]
metadata_backend = "sqlite"         # or "postgresql"
sqlite_path = "./data/vault.db"
blob_backend = "filesystem"         # or "s3"
blob_path = "./data/blobs"

[storage.s3]                        # if blob_backend = "s3"
bucket = "proof-layer-evidence"
region = "eu-west-1"
endpoint = ""                       # for MinIO/R2

[storage.postgresql]                # if metadata_backend = "postgresql"
url = "postgres://user:pass@host/db"

[timestamp]
enabled = false
provider = "rfc3161"
url = "http://timestamp.digicert.com"
# For eIDAS qualified:
# provider = "rfc3161"
# url = "https://freetsa.org/tsr"
# assurance = "qualified"

[transparency]
enabled = false
provider = "none"                   # "rekor" | "scitt" | "none"
# rekor_url = "https://rekor.sigstore.dev"

[retention]
scan_interval_hours = 24
grace_period_days = 30

[retention.policies]
provider_documentation_days = 3650  # 10 years (Art 18)
provider_logs_days = 180            # 6 months minimum (Art 19)
deployer_logs_days = 180            # 6 months minimum (Art 26)
incident_records_days = 3650        # 10 years
gpai_documentation_days = 1825     # 5 years after withdrawal
literacy_records_days = 1095        # 3 years (organizational default)

[cors]
allowed_origins = ["http://localhost:*"]
```

---

## 5. TypeScript SDK (`@proof-layer/sdk`)

### Location: `sdks/typescript/`

### 5.1 Architecture

```
sdks/typescript/
├── src/
│   ├── index.ts                # Main exports
│   ├── native.ts               # NAPI-RS binding wrapper
│   ├── client.ts               # Vault HTTP client (async)
│   ├── evidence.ts             # Evidence capture helpers
│   ├── types.ts                # TypeScript types (generated from Rust schema)
│   ├── providers/
│   │   ├── index.ts
│   │   ├── openai.ts           # OpenAI wrapper
│   │   ├── anthropic.ts        # Anthropic wrapper
│   │   ├── vercel-ai.ts        # Vercel AI SDK wrapper
│   │   └── generic.ts          # Generic LLM wrapper
│   ├── otel/
│   │   ├── index.ts
│   │   ├── exporter.ts         # OTel span exporter → evidence items
│   │   └── instrumentation.ts  # Auto-instrumentation hooks
│   └── utils/
│       └── errors.ts
├── native/                     # NAPI-RS compiled .node binary
│   └── index.d.ts              # Type declarations for native module
├── package.json
├── tsconfig.json
└── tests/
    ├── native.test.ts          # Verify native bindings work
    ├── client.test.ts          # Vault client tests
    ├── providers.test.ts       # Provider wrapper tests
    ├── golden.test.ts          # Golden fixture cross-verification
    └── e2e.test.ts             # End-to-end with vault
```

### 5.2 NAPI-RS Bridge

The `crates/napi/` crate exposes Rust core functions to Node.js:

```rust
// crates/napi/src/lib.rs
use napi_derive::napi;

#[napi]
pub fn canonicalize(json_bytes: Buffer) -> Result<Buffer> { ... }

#[napi]
pub fn hash_sha256(data: Buffer) -> String { ... }

#[napi]
pub fn compute_merkle_root(digests: Vec<String>) -> Result<String> { ... }

#[napi]
pub fn sign_bundle_root(root: String, key_pem: String, kid: String) -> Result<String> { ... }

#[napi]
pub fn verify_bundle_root(jws: String, expected_root: String, pub_key_pem: String) -> Result<bool> { ... }

#[napi]
pub fn build_bundle(config_json: String) -> Result<String> { ... }

#[napi]
pub fn verify_bundle(bundle_json: String, artefacts_json: String, pub_key_pem: String) -> Result<String> { ... }

#[napi]
pub fn package_bundle(bundle_json: String, artefacts_json: String) -> Result<Buffer> { ... }

#[napi]
pub fn unpackage_bundle(pkg: Buffer) -> Result<String> { ... }

#[napi]
pub fn generate_disclosure_proof(bundle_json: String, indices: Vec<u32>) -> Result<String> { ... }

#[napi]
pub fn verify_disclosure_proof(proof_json: String, root: String) -> Result<bool> { ... }
```

### 5.3 TypeScript API

```typescript
import { ProofLayer } from '@proof-layer/sdk';

// Initialize with vault connection
const pl = new ProofLayer({
  vaultUrl: 'https://vault.example.com',
  signingKeyPath: './keys/signing.pem',
  keyId: 'app-prod-01',
  systemId: 'my-ai-system',
  role: 'deployer',
});

// === Provider wrappers ===
import { withProofLayer } from '@proof-layer/sdk/providers/openai';

const openai = withProofLayer(new OpenAI(), pl);
// All completions are automatically captured as evidence
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }],
});
// response.proofLayer.bundleId, response.proofLayer.bundleRoot available

// === Manual evidence capture ===
const bundle = await pl.capture({
  type: 'llm_interaction',
  provider: 'anthropic',
  model: 'claude-sonnet-4-6',
  input: messages,
  output: response,
  artefacts: [
    { name: 'prompt.json', data: promptBuffer },
    { name: 'response.json', data: responseBuffer },
  ],
});

// === Lifecycle evidence ===
await pl.captureRiskAssessment({
  systemId: 'my-ai-system',
  assessmentType: 'periodic',
  riskRegister: riskRegisterData,
  assessor: 'risk-team-lead',
});

await pl.captureLiteracyAttestation({
  userId: 'user-123',
  trainingId: 'ai-literacy-2026-q1',
  role: 'oversight-operator',
  completedAt: new Date(),
});

// === Offline verification ===
import { verify } from '@proof-layer/sdk';

const report = verify(bundlePackage, publicKeyPem);
// report.signatureValid, report.merkleValid, report.timestampValid, etc.

// === OTel integration ===
import { ProofLayerExporter } from '@proof-layer/sdk/otel';

const exporter = new ProofLayerExporter(pl);
// Plugs into existing OpenTelemetry pipeline
// Converts GenAI semantic convention spans → evidence items
```

### 5.4 Build & Distribution

- NAPI-RS prebuilds for: `linux-x64-gnu`, `linux-x64-musl`, `linux-arm64-gnu`, `darwin-x64`, `darwin-arm64`, `win32-x64`
- Published to npm as `@proof-layer/sdk` with optional native bindings
- Fallback: WASM build for environments where native modules are unavailable (reduced feature set — no filesystem key loading, no timestamp client)

---

## 6. Python SDK (`proof-layer-sdk`)

### Location: `sdks/python/`

### 6.1 Architecture

```
sdks/python/
├── proof_layer/
│   ├── __init__.py             # Main exports
│   ├── _native.pyi             # Type stubs for PyO3 module
│   ├── client.py               # Vault HTTP client (async via httpx)
│   ├── evidence.py             # Evidence capture helpers
│   ├── types.py                # Pydantic models (generated from Rust schema)
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── openai.py           # OpenAI wrapper
│   │   ├── anthropic.py        # Anthropic wrapper
│   │   ├── langchain.py        # LangChain callback handler
│   │   └── generic.py          # Generic LLM wrapper
│   ├── otel/
│   │   ├── __init__.py
│   │   ├── exporter.py         # OTel span exporter → evidence items
│   │   └── instrumentation.py  # Auto-instrumentation
│   └── decorators.py           # @proof_capture decorator
├── rust/                       # PyO3 compiled .so/.pyd
├── pyproject.toml
├── tests/
│   ├── test_native.py
│   ├── test_client.py
│   ├── test_providers.py
│   ├── test_golden.py
│   └── test_e2e.py
└── README.md
```

### 6.2 PyO3 Bridge

```rust
// crates/pyo3/src/lib.rs
use pyo3::prelude::*;

#[pyfunction]
fn canonicalize(json_bytes: &[u8]) -> PyResult<Vec<u8>> { ... }

#[pyfunction]
fn hash_sha256(data: &[u8]) -> String { ... }

#[pyfunction]
fn compute_merkle_root(digests: Vec<String>) -> PyResult<String> { ... }

#[pyfunction]
fn sign_bundle_root(root: &str, key_pem: &str, kid: &str) -> PyResult<String> { ... }

#[pyfunction]
fn verify_bundle_root(jws: &str, expected_root: &str, pub_key_pem: &str) -> PyResult<bool> { ... }

#[pyfunction]
fn build_bundle(config_json: &str) -> PyResult<String> { ... }

#[pyfunction]
fn verify_bundle(bundle_json: &str, artefacts_json: &str, pub_key_pem: &str) -> PyResult<String> { ... }

// ... same surface as NAPI-RS bridge

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(hash_sha256, m)?)?;
    // ...
    Ok(())
}
```

### 6.3 Python API

```python
from proof_layer import ProofLayer, verify

# Initialize
pl = ProofLayer(
    vault_url="https://vault.example.com",
    signing_key_path="./keys/signing.pem",
    key_id="app-prod-01",
    system_id="my-ai-system",
    role="deployer",
)

# Provider wrappers
from proof_layer.providers.openai import with_proof_layer

client = with_proof_layer(OpenAI(), pl)
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
)
# response.proof_layer.bundle_id available

# Manual capture
bundle = await pl.capture(
    evidence_type="llm_interaction",
    provider="anthropic",
    model="claude-sonnet-4-6",
    input=messages,
    output=response,
    artefacts=[
        ("prompt.json", prompt_bytes),
        ("response.json", response_bytes),
    ],
)

# Decorator
@pl.capture(evidence_type="tool_call")
def search_database(query: str) -> list:
    return db.search(query)

# Lifecycle evidence
await pl.capture_risk_assessment(
    system_id="my-ai-system",
    assessment_type="periodic",
    risk_register=risk_data,
    assessor="risk-team-lead",
)

# Offline verification
report = verify(bundle_pkg_bytes, public_key_pem)

# OTel integration
from proof_layer.otel import ProofLayerExporter
```

### 6.4 Build & Distribution

- PyO3 + maturin for building wheels
- Prebuilt wheels for: `manylinux_2_28` (x86_64, aarch64), `macosx` (x86_64, arm64), `win_amd64`
- Published to PyPI as `proof-layer-sdk`
- Source distribution includes Rust source for compilation on unsupported platforms

---

## 7. Evidence Taxonomy & EU AI Act Mapping

### 7.1 Evidence Item Types → AI Act Articles

| Evidence Item Type | AI Act Article(s) | Applicable To | Retention |
|---|---|---|---|
| `llm_interaction` | Art 12, 19, 26 | All | 6mo+ (logs) |
| `tool_call` | Art 12, 19, 26 | All | 6mo+ (logs) |
| `retrieval` | Art 12, 19, 26 | All | 6mo+ (logs) |
| `human_oversight` | Art 14, 26 | High-risk | 6mo+ (logs) |
| `policy_decision` | Art 12, 14 | High-risk | 6mo+ (logs) |
| `risk_assessment` | Art 9 | High-risk | 10yr (docs) |
| `data_governance` | Art 10 | High-risk | 10yr (docs) |
| `technical_doc` | Art 11, Annex IV | High-risk | 10yr (docs) |
| `model_evaluation` | Art 53, Annex XI | GPAI | Until withdrawn+ |
| `adversarial_test` | Art 55 | GPAI systemic | Until withdrawn+ |
| `training_provenance` | Art 53, Annex XI | GPAI | Until withdrawn+ |
| `incident_report` | Art 55, 73 | High-risk, GPAI systemic | 10yr |
| `literacy_attestation` | Art 4 | All | Org policy |
| `conformity_assessment` | Art 43, Annex VI/VII | High-risk | 10yr |
| `declaration` | Art 47, Annex V | High-risk | 10yr |
| `registration` | Art 49, 71 | High-risk | 10yr |

### 7.2 Evidence Pack Types → AI Act Annexes

| Pack Type | Contents | Primary Audience |
|---|---|---|
| `annex_iv` | Technical docs, risk mgmt, data gov, accuracy tests, oversight design, post-market plan | Notified bodies, market surveillance |
| `annex_xi` | Model description, architecture, training provenance, evaluation results, use policies | AI Office, competent authorities |
| `annex_xii` | Downstream integration docs, capabilities/limitations, usage recommendations | Downstream system providers |
| `runtime_logs` | Automatic event logs, monitoring events, risk flags | Deployers, authorities |
| `risk_management` | Risk register snapshots, mitigations, test attestations | Conformity assessment |
| `ai_literacy` | Training records, role mapping, competence attestations | Authorities, internal audit |
| `systemic_risk` | Adversarial tests, evaluations, incident reports, cybersecurity evidence | AI Office |
| `incident_response` | Incident timeline, corrective measures, root cause analysis | AI Office, authorities |
| `conformity` | Declaration, CE marking evidence, registration receipts | Market surveillance |

---

## 8. Cryptographic Design

### 8.1 Bundle Integrity Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                    Evidence Bundle Construction                    │
│                                                                    │
│  1. CAPTURE         2. CANONICALIZE      3. HASH                  │
│  ┌──────────┐       ┌──────────────┐     ┌─────────────────┐     │
│  │ Evidence  │──────▶│ RFC 8785 JCS │────▶│ SHA-256 digest  │     │
│  │ Items +   │       │ canonical    │     │ per item +      │     │
│  │ Artefacts │       │ form         │     │ per artefact    │     │
│  └──────────┘       └──────────────┘     └────────┬────────┘     │
│                                                    │               │
│  4. MERKLE TREE              5. SIGN               │               │
│  ┌──────────────────┐        ┌──────────────┐      │               │
│  │ pl-merkle-sha256 │◀───────┤ All digests  │◀─────┘               │
│  │ -v1              │        │ (header +    │                      │
│  │                  │        │  artefacts)  │                      │
│  │ bundle_root ─────┼───────▶│              │                      │
│  └──────────────────┘        └──────┬───────┘                      │
│                                     │                              │
│  6. TIMESTAMP (optional)    ┌───────▼──────┐                      │
│  ┌──────────────────┐       │ Ed25519/ECDSA│                      │
│  │ RFC 3161 TSA     │◀──────│ JWS compact  │                      │
│  │ token            │       │ signature    │                      │
│  └──────────────────┘       └───────┬──────┘                      │
│                                     │                              │
│  7. TRANSPARENCY (optional)  ┌──────▼──────┐                      │
│  ┌──────────────────┐        │ Transparency│                      │
│  │ Rekor/SCITT      │◀───────│ entry       │                      │
│  │ receipt          │        │ submission  │                      │
│  └──────────────────┘        └─────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
```

### 8.2 Merkle Tree for Selective Disclosure

The Merkle tree enables revealing only specific evidence items while proving they belong to a signed bundle:

```
                    bundle_root
                   /            \
              h(01||L,R)      h(01||L,R)
             /     \          /     \
        h(00||d₁) h(00||d₂) h(00||d₃) h(00||d₄)
            │          │          │          │
     header_digest  art1_digest art2_digest item1_digest
```

**Disclosure proof for item1_digest:**
```json
{
  "disclosed_index": 3,
  "disclosed_digest": "sha256:...",
  "proof_path": [
    { "position": "left", "hash": "sha256:..." },   // sibling at level 0
    { "position": "left", "hash": "sha256:..." }     // sibling at level 1
  ],
  "bundle_root": "sha256:...",
  "signature": "eyJhbGc..."
}
```

### 8.3 Assurance Levels

| Level | Components | Legal Weight | Use Case |
|-------|-----------|-------------|----------|
| **L1: Signed** | Ed25519/ECDSA signature | Tamper detection, non-repudiation (key holder) | Internal compliance, dev/staging |
| **L2: Signed + Timestamped** | L1 + RFC 3161 token | L1 + independent time proof, admissible as evidence (eIDAS Art 41) | Production, B2B sharing |
| **L3: Signed + Qualified Timestamp** | L1 + qualified eIDAS TSA | L2 + legal presumption of accuracy (eIDAS Art 42) | Regulated contexts, court disputes |
| **L4: Full Transparency** | L2/L3 + transparency receipt | L2/L3 + public auditability, resist log deletion | Systemic risk models, public accountability |

### 8.4 Key Management

```rust
pub enum KeySource {
    /// Local PEM file (dev/testing)
    File { path: PathBuf },
    /// Environment variable (container deployments)
    EnvVar { name: String },
    /// PKCS#11 HSM (production)
    Pkcs11 { module_path: PathBuf, slot: u64, pin_env: String },
    /// Cloud KMS (managed deployments)
    CloudKms { provider: KmsProvider, key_id: String },
}

pub enum KmsProvider {
    AwsKms,
    GcpKms,
    AzureKeyVault,
}
```

---

## 9. Testing Strategy

### 9.1 Test Layers

| Layer | What | How | Where |
|-------|------|-----|-------|
| **Unit** | Individual functions (canon, hash, merkle, sign) | `#[test]` in Rust, vitest in TS, pytest in Python | `crates/*/src/**` |
| **Golden fixtures** | Cross-language determinism | Fixed inputs → expected outputs, verified in all 3 languages | `fixtures/golden/` |
| **RFC compliance** | RFC 8785 vectors, RFC 3161 format | Published test vectors | `fixtures/rfc8785/` |
| **Integration** | Vault API, pack assembly, retention | Axum test client, temp database | `crates/vault/tests/` |
| **FFI bridge** | NAPI-RS and PyO3 produce identical results to Rust | Call native bindings with golden inputs | `sdks/*/tests/` |
| **E2E** | Full flow: capture → seal → store → query → export → verify | Docker compose with vault + SDKs | `tests/e2e/` |
| **Property** | Canonicalization roundtrips, Merkle proof validity | proptest in Rust | `crates/core/tests/` |
| **Fuzz** | Malformed inputs to canon/verify/unpackage | cargo-fuzz | `fuzz/` |

### 9.2 Golden Fixture Strategy

Golden fixtures are the **cross-language correctness guarantee**. They ensure Rust, TypeScript (via NAPI), and Python (via PyO3) all produce identical cryptographic outputs.

```
fixtures/golden/
├── v1/
│   ├── capture_input.json          # Input evidence data
│   ├── artefacts/
│   │   ├── prompt.json
│   │   └── response.json
│   ├── expected/
│   │   ├── canonical_bytes.bin     # RFC 8785 output
│   │   ├── digests.json            # SHA-256 digests
│   │   ├── merkle_root.txt         # Expected Merkle root
│   │   ├── bundle.json             # Complete bundle
│   │   ├── bundle.pkg              # Packaged bundle
│   │   └── disclosure_proof.json   # Selective disclosure proof
│   └── keys/
│       ├── signing.pem             # Deterministic test key
│       └── verify.pub
└── migration/
    ├── v0.1_bundle.json            # PoC format bundle
    └── v1.0_bundle.json            # Migrated format
```

### 9.3 CI Matrix

```yaml
# Test across platforms and languages
matrix:
  os: [ubuntu-latest, macos-latest, windows-latest]
  rust: [stable, nightly]
  node: [18, 20, 22]
  python: [3.10, 3.11, 3.12, 3.13]

steps:
  - cargo test --workspace              # Rust unit + integration
  - cargo test -p proof-layer-napi      # NAPI bridge
  - cargo test -p proof-layer-pyo3      # PyO3 bridge
  - cd sdks/typescript && npm test      # TS tests via NAPI
  - cd sdks/python && pytest            # Python tests via PyO3
  - docker compose -f tests/e2e/docker-compose.yml up --abort-on-container-exit
```

---

## 10. Build, CI & Release

### 10.1 Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "crates/core",
    "crates/cli",
    "crates/vault",
    "crates/ffi-c",
    "crates/napi",
    "crates/pyo3",
]

[workspace.package]
version = "1.0.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/proof-layer/sdk"

[workspace.dependencies]
proof-layer-core = { path = "crates/core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
```

### 10.2 Release Artifacts

| Artifact | Registry | Build |
|----------|----------|-------|
| `proof-layer-core` | crates.io | `cargo publish` |
| `proofctl` | GitHub Releases | Cross-compiled binaries (linux/mac/win) |
| `proof-layer-vault` | Docker Hub / GHCR | Multi-arch Docker image |
| `@proof-layer/sdk` | npm | NAPI-RS prebuilds + JS |
| `proof-layer-sdk` | PyPI | maturin wheels + source |

### 10.3 Version Strategy

- Workspace version: single version across all crates
- SDK versions: match workspace version
- Bundle schema version: independent, with migration support
- Breaking changes: semver major bump across all packages simultaneously

---

## 11. Migration from PoC

### 11.1 What to Carry Forward

| Component | Action |
|-----------|--------|
| `canonicalize.rs` (RFC 8785) | Carry, refactor into `crates/core/src/canon/` |
| `hash.rs` (SHA-256) | Carry as-is |
| `merkle.rs` | Carry, extend with inclusion proof generation |
| `sign.rs` (Ed25519 JWS) | Carry, refactor to support multiple algorithms |
| `verify.rs` | Carry, extend for timestamp + receipt verification |
| `build.rs` (bundle construction) | Carry, refactor for new schema |
| Golden fixtures | Carry, add v1.0 fixtures alongside |
| RFC 8785 test vectors | Carry as-is |
| Web demo | Carry, update for new bundle schema |

### 11.2 What to Replace

| Component | Reason |
|-----------|--------|
| `packages/sdk-node/` (HTTP client) | Replace with NAPI-RS native bindings |
| `packages/sdk-python/` (HTTP client) | Replace with PyO3 native bindings |
| `packages/proof-service/` (Axum service) | Replace with Evidence Vault (`crates/vault/`) |
| `sled` database | Replace with SQLite (or PostgreSQL) |
| `bundle.rs` data structures | Replace with typed evidence schema |
| `json-canonicalize` npm dep | Remove — canonicalization via NAPI-RS |

### 11.3 Schema Migration (v0.1 → v1.0)

```rust
pub fn migrate_v01_to_v10(old: V01Bundle) -> Result<EvidenceBundle> {
    EvidenceBundle {
        bundle_version: "1.0".into(),
        bundle_id: old.bundle_id,
        created_at: old.created_at,
        actor: Actor {
            issuer: old.actor.issuer,
            app_id: old.actor.app_id,
            env: old.actor.env,
            signing_key_id: old.actor.signing_key_id,
            role: ActorRole::Provider, // default for migrated bundles
            organization_id: None,
        },
        subject: Subject {
            request_id: old.subject.request_id,
            thread_id: old.subject.thread_id,
            user_ref: old.subject.user_ref,
            system_id: None,
            model_id: Some(format!("{}:{}", old.model.provider, old.model.model)),
            deployment_id: None,
            version: None,
        },
        context: EvidenceContext::from_v01_model(old.model),
        items: vec![EvidenceItem::LlmInteraction(LlmInteractionEvidence {
            provider: old.model.provider,
            model: old.model.model,
            parameters: old.model.parameters,
            input_commitment: old.inputs.messages_commitment,
            output_commitment: old.outputs.assistant_text_commitment,
            token_usage: None,
            latency_ms: None,
            trace_id: None,
        })],
        artefacts: old.artefacts,
        policy: old.policy,
        // integrity must be recomputed — old bundles can be verified with old schema
        integrity: Integrity::default(),
        timestamp: None,
        receipt: None,
    }
}
```

---

## 12. Implementation Phases

### Phase 1: Foundation (Weeks 1–3)

**Goal**: Restructured workspace, core library with new schema, passing golden tests.

- [ ] Create new workspace layout (`crates/`, `sdks/`, `schemas/`, `fixtures/`)
- [ ] Port and refactor `canonicalize.rs` → `crates/core/src/canon/`
- [ ] Port `hash.rs`, `merkle.rs` → `crates/core/src/`
- [ ] Implement extended Merkle tree with inclusion proofs (`merkle/proof.rs`)
- [ ] Define v1.0 evidence schema types (`schema/` module)
- [ ] Implement schema migration v0.1 → v1.0
- [ ] Refactor `sign.rs` to support Ed25519 + ECDSA P-256/P-384 (`sign/` module)
- [ ] Refactor `verify.rs` for multi-algorithm support
- [ ] Refactor `build.rs` for new schema with typed evidence items
- [ ] Port and extend `bundle.rs` packaging/unpackaging
- [ ] Create v1.0 golden fixtures
- [ ] Ensure all Rust tests pass: `cargo test --workspace`
- [ ] Write JSON schemas for all evidence types → `schemas/`

### Phase 2: CLI Rebuild (Week 4)

**Goal**: `proofctl` rebuilt with all new commands.

- [ ] Port `keygen` with multi-algorithm support
- [ ] Port `create` with evidence type, retention class, system-id flags
- [ ] Port `verify` with timestamp and receipt check flags
- [ ] Port `inspect` with `--show-items` and `--show-merkle`
- [ ] Implement `disclose` command (selective disclosure)
- [ ] Implement `pack` command (evidence pack assembly)
- [ ] Golden fixture CLI round-trip tests
- [ ] Man page / help text for all commands

### Phase 3: FFI Bridges (Weeks 5–6)

**Goal**: NAPI-RS and PyO3 bridges compiling and passing golden tests.

- [ ] Create `crates/napi/` with NAPI-RS bindings for all core functions
- [ ] Create `crates/pyo3/` with PyO3 bindings for all core functions
- [ ] Create `crates/ffi-c/` with C ABI exports (header file generation)
- [ ] NAPI-RS prebuild CI for linux/mac/win (x64 + arm64)
- [ ] PyO3 maturin wheel CI for linux/mac/win
- [ ] Golden fixture tests: call NAPI from Node, PyO3 from Python, verify identical outputs
- [ ] Type generation: Rust schema → TypeScript types, Python type stubs

### Phase 4: TypeScript SDK (Weeks 7–8)

**Goal**: `@proof-layer/sdk` published to npm with provider wrappers and OTel.

- [ ] `native.ts` — ergonomic wrapper around NAPI-RS bindings
- [ ] `client.ts` — Vault HTTP client (async, retry, error handling)
- [ ] `evidence.ts` — capture helpers for all evidence types
- [ ] `types.ts` — generated TypeScript types
- [ ] Provider wrappers: OpenAI, Anthropic, Vercel AI SDK
- [ ] OTel integration: GenAI semantic convention exporter
- [ ] Unit tests, golden fixture tests, provider mock tests
- [ ] npm package configuration and README
- [ ] Example: `examples/typescript/`

### Phase 5: Python SDK (Weeks 8–9)

**Goal**: `proof-layer-sdk` published to PyPI with provider wrappers and OTel.

- [ ] `_native.pyi` — type stubs for PyO3 module
- [ ] `client.py` — Vault HTTP client (httpx async)
- [ ] `evidence.py` — capture helpers
- [ ] `types.py` — Pydantic models (generated)
- [ ] Provider wrappers: OpenAI, Anthropic, LangChain
- [ ] OTel integration: GenAI semantic convention exporter
- [ ] `@proof_capture` decorator
- [ ] Unit tests, golden fixture tests, provider mock tests
- [ ] pyproject.toml and README
- [ ] Example: `examples/python/`

### Phase 6: Evidence Vault (Weeks 10–13)

**Goal**: Production vault service with storage, retention, and export.

- [ ] Axum HTTP server with API routes (Section 4.1)
- [ ] SQLite storage backend (metadata + query)
- [ ] Filesystem blob storage (artefacts + packages)
- [ ] Bundle creation endpoint (capture → seal → store)
- [ ] Bundle retrieval and query endpoints
- [ ] Verification endpoints (inline, package, timestamp, receipt)
- [ ] Evidence item indexing and obligation-based queries
- [ ] Retention policy engine (configuration, scan, soft/hard delete)
- [ ] Evidence pack assembly engine (Section 4.4)
- [ ] Pack export (Annex IV, XI, XII, runtime logs, risk mgmt, literacy)
- [ ] Audit trail (append-only access log)
- [ ] Configuration file support (`vault.toml`)
- [ ] Docker image + docker-compose
- [ ] Integration tests with temp database
- [ ] PostgreSQL storage backend (optional, behind feature flag)
- [ ] S3-compatible blob storage (optional, behind feature flag)

### Phase 7: Timestamping (Week 14)

**Goal**: RFC 3161 timestamp support integrated end-to-end.

- [ ] RFC 3161 TSP client in `crates/core/src/timestamp/`
- [ ] Timestamp token parsing and verification
- [ ] `TimestampProvider` trait + built-in providers (DigiCert, FreeTSA)
- [ ] Vault integration: POST `/v1/bundles/{id}/timestamp`
- [ ] CLI: `proofctl create --timestamp-url`
- [ ] SDK: `pl.capture(..., timestamp=True)`
- [ ] Verification: `proofctl verify --check-timestamp`
- [ ] eIDAS qualified TSA configuration support

### Phase 8: Transparency Anchoring (Week 15)

**Goal**: Pluggable transparency log support.

- [ ] `TransparencyProvider` trait
- [ ] Sigstore Rekor client implementation
- [ ] SCITT receipt handling (stub, aligned with draft architecture)
- [ ] Vault integration: POST `/v1/bundles/{id}/anchor`
- [ ] CLI: `proofctl create --transparency-log`
- [ ] Verification: `proofctl verify --check-receipt`
- [ ] Verifier output explaining assurance level

### Phase 9: Selective Disclosure (Week 16)

**Goal**: Merkle-proof selective disclosure for confidential evidence sharing.

- [ ] `disclosure/selective.rs` — proof generation and verification
- [ ] `disclosure/redaction.rs` — field-level redaction
- [ ] CLI: `proofctl disclose --items 1,3 --out redacted.pkg`
- [ ] SDK: `pl.disclose(bundle, items=[1,3])`
- [ ] Vault: redacted pack export support
- [ ] Redacted bundle verification (proof path check)

### Phase 10: Hardening & Launch (Weeks 17–18)

**Goal**: Production readiness, documentation, security review.

- [ ] Security audit of cryptographic code paths
- [ ] Fuzz testing (canon, verify, unpackage)
- [ ] Property-based testing (proptest)
- [ ] Performance benchmarks (canonicalize, hash, sign, verify throughput)
- [ ] API documentation (rustdoc, typedoc, sphinx)
- [ ] Threat model update for production architecture
- [ ] EU AI Act mapping documentation with article references
- [ ] Example applications (full compliance workflow)
- [ ] Web demo update for v1.0 bundles
- [ ] Release v1.0.0 across all packages

---

## 13. Open Questions & Decisions

### Architecture Decisions Needed

1. **SQLite vs PostgreSQL for default metadata store**
   - SQLite: zero-dependency, embedded, great for single-node
   - PostgreSQL: multi-node, better query capabilities, more operational overhead
   - **Recommendation**: SQLite as default, PostgreSQL as optional feature flag

2. **NAPI-RS vs wasm-bindgen for TypeScript**
   - NAPI-RS: native performance, full feature set, platform-specific builds
   - WASM: universal, no native compilation, slightly reduced performance
   - **Recommendation**: NAPI-RS primary, WASM as fallback for restricted environments

3. **Sled vs SQLite for the Vault**
   - Sled: current PoC choice, pure Rust, but maintenance status uncertain
   - SQLite: battle-tested, excellent tooling, well-understood durability
   - **Recommendation**: SQLite (via `rusqlite`) — more predictable for production

4. **Bundle package format**
   - Current: gzip-compressed JSON archive
   - Alternative: CBOR-based for smaller payloads + binary efficiency
   - **Recommendation**: keep gzip JSON for v1.0 (debuggability), consider CBOR for v2

5. **Multi-tenancy model**
   - Single-tenant vault (one org per deployment)
   - Multi-tenant with org isolation
   - **Recommendation**: start single-tenant, add multi-tenant in v1.1

### Standards Tracking

- **SCITT**: IETF drafts still evolving — implement trait interface now, concrete implementation when RFCs stabilize
- **OpenTelemetry GenAI**: semantic conventions are stabilizing — track latest release, version-gate imports
- **EU AI Act harmonised standards**: CEN/CENELEC work ongoing — design pack schemas to be updatable as standards publish

### Compliance Timeline Alignment

| Date | AI Act Event | SDK Must Support |
|------|-------------|-----------------|
| Feb 2025 (past) | AI literacy obligations apply | Art 4 literacy evidence capture |
| Aug 2025 (past) | GPAI obligations apply | Art 53 GPAI packs, Art 55 systemic risk |
| Aug 2026 | High-risk system obligations apply | Full Annex IV packs, Art 12 logging, Art 9/10/11 evidence |
| Aug 2027 | High-risk in regulated products | Extended high-risk pack support |

---

## Summary

This plan rebuilds the Proof Layer SDK from a PoC into a production-grade system by:

1. **Keeping the Rust core as the single source of cryptographic truth** — no reimplementation across languages
2. **Replacing HTTP-client SDKs with native FFI bindings** (NAPI-RS for Node, PyO3 for Python) — eliminating "compliance drift"
3. **Upgrading from generic "proof bundles" to typed evidence items** mapped directly to EU AI Act articles
4. **Building an Evidence Vault** with retention policies, pack assembly, and audit-ready exports aligned to Annexes IV, V, XI, XII
5. **Adding production cryptographic features**: RFC 3161 timestamping, pluggable transparency anchoring, Merkle-based selective disclosure
6. **Supporting three assurance levels**: signed → timestamped → transparency-anchored, letting customers choose their evidence strength

The architecture is designed so that when the high-risk obligations hit in August 2026, a customer can open the Vault, produce the pack, and the proof verifies — cleanly, cryptographically, and without hand-waving.
