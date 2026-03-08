use anyhow::{Context, Result, anyhow, bail};
use base64ct::Encoding;
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ArtefactInput, CaptureEvent, CaptureInput, DisclosureError, EvidenceItem,
    LEGACY_BUNDLE_ROOT_ALGORITHM, ProofBundle, ReceiptVerification, RedactedBundle,
    RekorTransparencyProvider, Rfc3161HttpTimestampProvider, SCITT_TRANSPARENCY_KIND,
    ScittTransparencyProvider, TimestampAssuranceProfile, TimestampProvider, TimestampToken,
    TimestampTrustPolicy, TransparencyProvider, TransparencyReceipt, TransparencyTrustPolicy,
    anchor_bundle as anchor_bundle_receipt, build_bundle, build_inclusion_proof,
    capture_input_v01_to_event, decode_private_key_pem, decode_public_key_pem,
    encode_private_key_pem, encode_public_key_pem, redact_bundle, sha256_prefixed,
    timestamp_digest, validate_bundle_integrity_fields, validate_timestamp_trust_policy,
    verify_receipt, verify_receipt_with_policy, verify_redacted_bundle, verify_timestamp,
    verify_timestamp_with_policy,
};
use reqwest::{
    Url,
    blocking::{Client, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use tracing::info;
use ulid::Ulid;

const BUNDLE_PACKAGE_FORMAT: &str = "pl-bundle-pkg-v1";
const DISCLOSURE_PACKAGE_FORMAT: &str = "pl-bundle-disclosure-pkg-v1";
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "proofctl")]
#[command(about = "Proof Layer CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a local development Ed25519 keypair.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a proof bundle package from capture input and artefacts.
    Create(Box<CreateArgs>),
    /// Verify a proof bundle package offline.
    Verify(Box<VerifyArgs>),
    /// Produce a redacted disclosure package with Merkle proofs for selected items.
    Disclose(Box<DiscloseArgs>),
    /// Print key fields from a proof bundle package.
    Inspect {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
        #[arg(long)]
        show_items: bool,
        #[arg(long)]
        show_merkle: bool,
    },
    /// Assemble an evidence pack via the vault and download the export archive.
    Pack {
        #[arg(long = "type")]
        pack_type: PackTypeArg,
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        system_id: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "bundle-format", default_value = "full")]
        bundle_format: PackBundleFormatArg,
        #[arg(long = "disclosure-policy")]
        disclosure_policy: Option<String>,
    },
    /// Query and administer a running vault service.
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
}

#[derive(Args)]
struct CreateArgs {
    #[arg(long)]
    input: PathBuf,
    #[arg(long, value_parser = parse_artefact_arg)]
    artefact: Vec<ArtefactArg>,
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    bundle_id: Option<String>,
    #[arg(long)]
    created_at: Option<String>,
    #[arg(long, default_value = "kid-dev-01")]
    signing_kid: String,
    #[arg(long)]
    evidence_type: Option<EvidenceTypeArg>,
    #[arg(long)]
    retention_class: Option<String>,
    #[arg(long)]
    system_id: Option<String>,
    #[arg(long)]
    timestamp_url: Option<String>,
    #[arg(long)]
    transparency_log: Option<String>,
    #[arg(long = "transparency-provider", default_value = "rekor")]
    transparency_provider: TransparencyProviderArg,
    #[arg(long = "timestamp-trust-anchor")]
    timestamp_trust_anchor: Vec<PathBuf>,
    #[arg(long = "timestamp-crl")]
    timestamp_crl: Vec<PathBuf>,
    #[arg(long = "timestamp-ocsp-url")]
    timestamp_ocsp_url: Vec<String>,
    #[arg(long = "timestamp-qualified-signer")]
    timestamp_qualified_signer: Vec<PathBuf>,
    #[arg(long = "timestamp-policy-oid")]
    timestamp_policy_oid: Vec<String>,
    #[arg(long = "timestamp-assurance")]
    timestamp_assurance: Option<TimestampAssuranceArg>,
    #[arg(long = "transparency-public-key")]
    transparency_public_key: Option<PathBuf>,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value = "human")]
    format: OutputFormat,
    #[arg(long)]
    check_timestamp: bool,
    #[arg(long)]
    check_receipt: bool,
    #[arg(long = "timestamp-trust-anchor")]
    timestamp_trust_anchor: Vec<PathBuf>,
    #[arg(long = "timestamp-crl")]
    timestamp_crl: Vec<PathBuf>,
    #[arg(long = "timestamp-ocsp-url")]
    timestamp_ocsp_url: Vec<String>,
    #[arg(long = "timestamp-qualified-signer")]
    timestamp_qualified_signer: Vec<PathBuf>,
    #[arg(long = "timestamp-policy-oid")]
    timestamp_policy_oid: Vec<String>,
    #[arg(long = "timestamp-assurance")]
    timestamp_assurance: Option<TimestampAssuranceArg>,
    #[arg(long = "transparency-public-key")]
    transparency_public_key: Option<PathBuf>,
}

#[derive(Args)]
struct DiscloseArgs {
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long)]
    items: String,
    #[arg(long)]
    artefacts: Option<String>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Subcommand)]
enum VaultCommands {
    /// Check vault readiness and summarize current configuration and inventory.
    Status {
        #[arg(long)]
        vault_url: String,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// Query stored bundles via the vault API.
    Query {
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        system_id: Option<String>,
        #[arg(long)]
        role: Option<ActorRoleArg>,
        #[arg(long = "type")]
        item_type: Option<EvidenceTypeArg>,
        #[arg(long)]
        has_timestamp: bool,
        #[arg(long)]
        has_receipt: bool,
        #[arg(long)]
        assurance_level: Option<AssuranceLevelArg>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = 1)]
        page: u32,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// Show the retention policy report exposed by the vault.
    Retention {
        #[arg(long)]
        vault_url: String,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// List known systems or fetch a single system evidence summary.
    Systems {
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        system_id: Option<String>,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// Assemble and download an evidence pack via the vault.
    Export {
        #[arg(long = "type")]
        pack_type: PackTypeArg,
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        system_id: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "bundle-format", default_value = "full")]
        bundle_format: PackBundleFormatArg,
        #[arg(long = "disclosure-policy")]
        disclosure_policy: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct ArtefactArg {
    name: String,
    path: PathBuf,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum EvidenceTypeArg {
    LlmInteraction,
    ToolCall,
    Retrieval,
    HumanOversight,
    PolicyDecision,
    RiskAssessment,
    DataGovernance,
    TechnicalDoc,
    ModelEvaluation,
    AdversarialTest,
    TrainingProvenance,
    ConformityAssessment,
    Declaration,
    Registration,
    LiteracyAttestation,
    IncidentReport,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum PackTypeArg {
    AnnexIv,
    AnnexXi,
    AnnexXii,
    RuntimeLogs,
    RiskMgmt,
    AiLiteracy,
    SystemicRisk,
    IncidentResponse,
    Conformity,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum PackBundleFormatArg {
    Full,
    Disclosure,
}

impl PackBundleFormatArg {
    fn as_api_value(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Disclosure => "disclosure",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum ActorRoleArg {
    Provider,
    Deployer,
    Integrator,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum AssuranceLevelArg {
    Signed,
    Timestamped,
    TransparencyAnchored,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum TimestampAssuranceArg {
    Standard,
    Qualified,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum TransparencyProviderArg {
    Rekor,
    Scitt,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    files: Vec<ManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    name: String,
    digest: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BundlePackage {
    format: String,
    files: Vec<PackagedFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PackagedFile {
    name: String,
    data_base64: String,
}

struct DecodedPackage {
    format: String,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    package_kind: String,
    canonicalization_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_proof_ok: Option<bool>,
    artefact_integrity_ok: bool,
    signature_ok: bool,
    manifest_ok: bool,
    message: String,
    artefacts_verified: usize,
    assurance_level: AssuranceLevel,
    timestamp: OptionalCheckReport,
    receipt: OptionalCheckReport,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SealableCaptureInput {
    V10(CaptureEvent),
    Legacy(CaptureInput),
}

#[derive(Debug, Clone)]
struct CreateOverrides {
    evidence_type: Option<EvidenceTypeArg>,
    retention_class: Option<String>,
    system_id: Option<String>,
}

struct CreateCommandInput<'a> {
    input_path: &'a Path,
    artefacts: &'a [ArtefactArg],
    key_path: &'a Path,
    out_path: &'a Path,
    bundle_id: Option<&'a str>,
    created_at: Option<&'a str>,
    signing_kid: &'a str,
    overrides: &'a CreateOverrides,
    timestamp_url: Option<&'a str>,
    transparency_log: Option<&'a str>,
    transparency_provider: TransparencyProviderArg,
    timestamp_trust_anchor_paths: &'a [PathBuf],
    timestamp_crl_paths: &'a [PathBuf],
    timestamp_ocsp_urls: &'a [String],
    timestamp_qualified_signer_paths: &'a [PathBuf],
    timestamp_policy_oids: &'a [String],
    timestamp_assurance: Option<TimestampAssuranceArg>,
    transparency_public_key_path: Option<&'a Path>,
}

struct VerifyCommandInput<'a> {
    input_path: &'a Path,
    key_path: &'a Path,
    format: OutputFormat,
    check_timestamp: bool,
    check_receipt: bool,
    timestamp_trust_anchor_paths: &'a [PathBuf],
    timestamp_crl_paths: &'a [PathBuf],
    timestamp_ocsp_urls: &'a [String],
    timestamp_qualified_signer_paths: &'a [PathBuf],
    timestamp_policy_oids: &'a [String],
    timestamp_assurance: Option<TimestampAssuranceArg>,
    transparency_public_key_path: Option<&'a Path>,
}

struct VaultQueryCommandInput<'a> {
    vault_url: &'a str,
    system_id: Option<&'a str>,
    role: Option<ActorRoleArg>,
    item_type: Option<EvidenceTypeArg>,
    has_timestamp: bool,
    has_receipt: bool,
    assurance_level: Option<AssuranceLevelArg>,
    from: Option<&'a str>,
    to: Option<&'a str>,
    page: u32,
    limit: u32,
    format: OutputFormat,
}

#[derive(Clone, Copy)]
struct PackCommandInput<'a> {
    pack_type: PackTypeArg,
    bundle_format: PackBundleFormatArg,
    disclosure_policy: Option<&'a str>,
    vault_url: &'a str,
    out_path: &'a Path,
    system_id: Option<&'a str>,
    from: Option<&'a str>,
    to: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OptionalCheckState {
    Skipped,
    Missing,
    Invalid,
    Valid,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct OptionalCheckReport {
    state: OptionalCheckState,
    message: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AssuranceLevel {
    Signed,
    Timestamped,
    TransparencyAnchored,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InspectMerkleLeaf {
    index: usize,
    label: String,
    digest: String,
    proof_steps: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InspectMerkleView {
    algorithm: String,
    root: String,
    leaves: Vec<InspectMerkleLeaf>,
}

#[derive(Debug, Serialize)]
struct InspectJsonOutput<'a> {
    bundle: &'a ProofBundle,
    #[serde(skip_serializing_if = "Option::is_none")]
    merkle: Option<InspectMerkleView>,
}

#[derive(Debug, Serialize)]
struct CreatePackRequest {
    pack_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    bundle_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackSummaryResponse {
    pack_id: String,
    pack_type: String,
    created_at: String,
    system_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    bundle_format: String,
    disclosure_policy: Option<String>,
    bundle_count: usize,
    bundle_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultBundleListResponse {
    page: u32,
    limit: u32,
    items: Vec<VaultBundleSummary>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultBundleSummary {
    bundle_id: String,
    bundle_version: String,
    created_at: String,
    actor_role: String,
    system_id: Option<String>,
    model_id: Option<String>,
    bundle_root: String,
    signature_alg: String,
    retention_class: String,
    expires_at: Option<String>,
    has_legal_hold: bool,
    has_timestamp: bool,
    has_receipt: bool,
    assurance_level: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultRetentionStatusResponse {
    scanned_at: String,
    grace_period_days: i64,
    policies: Vec<VaultRetentionStatusItem>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultRetentionStatusItem {
    retention_class: String,
    min_duration_days: i64,
    max_duration_days: Option<i64>,
    legal_basis: String,
    active: bool,
    total_bundles: i64,
    active_bundles: i64,
    deleted_bundles: i64,
    held_bundles: i64,
    expired_active_bundles: i64,
    hard_delete_ready_bundles: i64,
    next_expiry: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultConfigResponse {
    service: VaultServiceConfigView,
    signing: VaultSigningConfigView,
    storage: VaultStorageConfigView,
    retention: VaultRetentionConfigView,
    timestamp: VaultTimestampConfig,
    transparency: VaultTransparencyConfig,
    audit: VaultAuditConfigView,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultServiceConfigView {
    addr: String,
    max_payload_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultSigningConfigView {
    key_id: String,
    algorithm: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultStorageConfigView {
    metadata_backend: String,
    blob_backend: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultRetentionConfigView {
    grace_period_days: i64,
    scan_interval_hours: i64,
    policies: Vec<VaultRetentionPolicyConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultRetentionPolicyConfig {
    retention_class: String,
    min_duration_days: i64,
    max_duration_days: Option<i64>,
    legal_basis: String,
    active: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultTimestampConfig {
    enabled: bool,
    provider: String,
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assurance: Option<String>,
    #[serde(default)]
    trust_anchor_pems: Vec<String>,
    #[serde(default)]
    crl_pems: Vec<String>,
    #[serde(default)]
    ocsp_responder_urls: Vec<String>,
    #[serde(default)]
    qualified_signer_pems: Vec<String>,
    #[serde(default)]
    policy_oids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultTransparencyConfig {
    enabled: bool,
    provider: String,
    url: Option<String>,
    log_public_key_pem: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultAuditConfigView {
    enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultSystemsResponse {
    items: Vec<VaultSystemListEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultSystemListEntry {
    system_id: String,
    bundle_count: i64,
    active_bundle_count: i64,
    deleted_bundle_count: i64,
    first_seen_at: Option<String>,
    latest_bundle_at: Option<String>,
    timestamped_bundle_count: i64,
    receipt_bundle_count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultSystemSummaryResponse {
    system_id: String,
    bundle_count: i64,
    active_bundle_count: i64,
    deleted_bundle_count: i64,
    first_seen_at: Option<String>,
    latest_bundle_at: Option<String>,
    timestamped_bundle_count: i64,
    receipt_bundle_count: i64,
    actor_roles: Vec<VaultFacetCount>,
    evidence_types: Vec<VaultFacetCount>,
    retention_classes: Vec<VaultFacetCount>,
    assurance_levels: Vec<VaultFacetCount>,
    model_ids: Vec<VaultFacetCount>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultFacetCount {
    value: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct VaultStatusOutput {
    ready: bool,
    service_addr: String,
    max_payload_bytes: usize,
    signing_key_id: String,
    metadata_backend: String,
    blob_backend: String,
    bundle_total: i64,
    bundle_active: i64,
    bundle_deleted: i64,
    bundle_held: i64,
    system_count: usize,
    retention_policy_count: usize,
    scan_interval_hours: i64,
    timestamp_enabled: bool,
    timestamp_provider: String,
    timestamp_assurance: Option<String>,
    timestamp_trust_anchor_count: usize,
    timestamp_ocsp_url_count: usize,
    timestamp_policy_oid_count: usize,
    transparency_enabled: bool,
    transparency_provider: String,
}

impl EvidenceTypeArg {
    fn matches_item(self, item: &EvidenceItem) -> bool {
        matches!(
            (self, item),
            (Self::LlmInteraction, EvidenceItem::LlmInteraction(_))
                | (Self::ToolCall, EvidenceItem::ToolCall(_))
                | (Self::Retrieval, EvidenceItem::Retrieval(_))
                | (Self::HumanOversight, EvidenceItem::HumanOversight(_))
                | (Self::PolicyDecision, EvidenceItem::PolicyDecision(_))
                | (Self::RiskAssessment, EvidenceItem::RiskAssessment(_))
                | (Self::DataGovernance, EvidenceItem::DataGovernance(_))
                | (Self::TechnicalDoc, EvidenceItem::TechnicalDoc(_))
                | (Self::ModelEvaluation, EvidenceItem::ModelEvaluation(_))
                | (Self::AdversarialTest, EvidenceItem::AdversarialTest(_))
                | (
                    Self::TrainingProvenance,
                    EvidenceItem::TrainingProvenance(_)
                )
                | (
                    Self::ConformityAssessment,
                    EvidenceItem::ConformityAssessment(_)
                )
                | (Self::Declaration, EvidenceItem::Declaration(_))
                | (Self::Registration, EvidenceItem::Registration(_))
                | (
                    Self::LiteracyAttestation,
                    EvidenceItem::LiteracyAttestation(_)
                )
                | (Self::IncidentReport, EvidenceItem::IncidentReport(_))
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::LlmInteraction => "llm_interaction",
            Self::ToolCall => "tool_call",
            Self::Retrieval => "retrieval",
            Self::HumanOversight => "human_oversight",
            Self::PolicyDecision => "policy_decision",
            Self::RiskAssessment => "risk_assessment",
            Self::DataGovernance => "data_governance",
            Self::TechnicalDoc => "technical_doc",
            Self::ModelEvaluation => "model_evaluation",
            Self::AdversarialTest => "adversarial_test",
            Self::TrainingProvenance => "training_provenance",
            Self::ConformityAssessment => "conformity_assessment",
            Self::Declaration => "declaration",
            Self::Registration => "registration",
            Self::LiteracyAttestation => "literacy_attestation",
            Self::IncidentReport => "incident_report",
        }
    }
}

impl PackTypeArg {
    fn as_api_value(self) -> &'static str {
        match self {
            Self::AnnexIv => "annex_iv",
            Self::AnnexXi => "annex_xi",
            Self::AnnexXii => "annex_xii",
            Self::RuntimeLogs => "runtime_logs",
            Self::RiskMgmt => "risk_mgmt",
            Self::AiLiteracy => "ai_literacy",
            Self::SystemicRisk => "systemic_risk",
            Self::IncidentResponse => "incident_response",
            Self::Conformity => "conformity",
        }
    }
}

impl ActorRoleArg {
    fn as_api_value(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Deployer => "deployer",
            Self::Integrator => "integrator",
        }
    }
}

impl AssuranceLevelArg {
    fn as_api_value(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Timestamped => "timestamped",
            Self::TransparencyAnchored => "transparency_anchored",
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "proofctl=info".to_string()))
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out } => cmd_keygen(&out),
        Commands::Create(args) => cmd_create(CreateCommandInput {
            input_path: &args.input,
            artefacts: &args.artefact,
            key_path: &args.key,
            out_path: &args.out,
            bundle_id: args.bundle_id.as_deref(),
            created_at: args.created_at.as_deref(),
            signing_kid: &args.signing_kid,
            overrides: &CreateOverrides {
                evidence_type: args.evidence_type,
                retention_class: args.retention_class.clone(),
                system_id: args.system_id.clone(),
            },
            timestamp_url: args.timestamp_url.as_deref(),
            transparency_log: args.transparency_log.as_deref(),
            transparency_provider: args.transparency_provider,
            timestamp_trust_anchor_paths: &args.timestamp_trust_anchor,
            timestamp_crl_paths: &args.timestamp_crl,
            timestamp_ocsp_urls: &args.timestamp_ocsp_url,
            timestamp_qualified_signer_paths: &args.timestamp_qualified_signer,
            timestamp_policy_oids: &args.timestamp_policy_oid,
            timestamp_assurance: args.timestamp_assurance,
            transparency_public_key_path: args.transparency_public_key.as_deref(),
        }),
        Commands::Verify(args) => cmd_verify(VerifyCommandInput {
            input_path: &args.input,
            key_path: &args.key,
            format: args.format,
            check_timestamp: args.check_timestamp,
            check_receipt: args.check_receipt,
            timestamp_trust_anchor_paths: &args.timestamp_trust_anchor,
            timestamp_crl_paths: &args.timestamp_crl,
            timestamp_ocsp_urls: &args.timestamp_ocsp_url,
            timestamp_qualified_signer_paths: &args.timestamp_qualified_signer,
            timestamp_policy_oids: &args.timestamp_policy_oid,
            timestamp_assurance: args.timestamp_assurance,
            transparency_public_key_path: args.transparency_public_key.as_deref(),
        }),
        Commands::Disclose(args) => cmd_disclose(
            &args.input,
            &args.items,
            args.artefacts.as_deref(),
            &args.out,
        ),
        Commands::Inspect {
            input,
            format,
            show_items,
            show_merkle,
        } => cmd_inspect(&input, format, show_items, show_merkle),
        Commands::Pack {
            pack_type,
            vault_url,
            out,
            system_id,
            from,
            to,
            bundle_format,
            disclosure_policy,
        } => cmd_pack(PackCommandInput {
            pack_type,
            bundle_format,
            disclosure_policy: disclosure_policy.as_deref(),
            vault_url: &vault_url,
            out_path: &out,
            system_id: system_id.as_deref(),
            from: from.as_deref(),
            to: to.as_deref(),
        }),
        Commands::Vault { command } => match command {
            VaultCommands::Status { vault_url, format } => cmd_vault_status(&vault_url, format),
            VaultCommands::Query {
                vault_url,
                system_id,
                role,
                item_type,
                has_timestamp,
                has_receipt,
                assurance_level,
                from,
                to,
                page,
                limit,
                format,
            } => cmd_vault_query(VaultQueryCommandInput {
                vault_url: &vault_url,
                system_id: system_id.as_deref(),
                role,
                item_type,
                has_timestamp,
                has_receipt,
                assurance_level,
                from: from.as_deref(),
                to: to.as_deref(),
                page,
                limit,
                format,
            }),
            VaultCommands::Retention { vault_url, format } => {
                cmd_vault_retention(&vault_url, format)
            }
            VaultCommands::Systems {
                vault_url,
                system_id,
                format,
            } => cmd_vault_systems(&vault_url, system_id.as_deref(), format),
            VaultCommands::Export {
                pack_type,
                vault_url,
                out,
                system_id,
                from,
                to,
                bundle_format,
                disclosure_policy,
            } => cmd_pack(PackCommandInput {
                pack_type,
                bundle_format,
                disclosure_policy: disclosure_policy.as_deref(),
                vault_url: &vault_url,
                out_path: &out,
                system_id: system_id.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
            }),
        },
    }
}

fn cmd_keygen(out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create output directory {}", out_dir.display()))?;

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key = signing_key.verifying_key();

    let signing_pem = encode_private_key_pem(&signing_key);
    let public_pem = encode_public_key_pem(&verifying_key);

    let signing_path = out_dir.join("signing.pem");
    let public_path = out_dir.join("verify.pub");

    fs::write(&signing_path, signing_pem)
        .with_context(|| format!("failed to write {}", signing_path.display()))?;
    fs::write(&public_path, public_pem)
        .with_context(|| format!("failed to write {}", public_path.display()))?;

    info!("wrote {}", signing_path.display());
    info!("wrote {}", public_path.display());
    Ok(())
}

fn cmd_create(args: CreateCommandInput<'_>) -> Result<()> {
    if args.artefacts.is_empty() {
        bail!("at least one --artefact name=path value is required");
    }
    if args.signing_kid.trim().is_empty() {
        bail!("signing kid must not be empty");
    }
    if args.transparency_log.is_some() && args.timestamp_url.is_none() {
        bail!(
            "--transparency-log requires --timestamp-url because Rekor anchoring submits RFC 3161 timestamp tokens"
        );
    }
    if !args.timestamp_trust_anchor_paths.is_empty() && args.timestamp_url.is_none() {
        bail!("--timestamp-trust-anchor requires --timestamp-url during local bundle creation");
    }
    if !args.timestamp_crl_paths.is_empty() && args.timestamp_url.is_none() {
        bail!("--timestamp-crl requires --timestamp-url during local bundle creation");
    }
    if !args.timestamp_ocsp_urls.is_empty() && args.timestamp_url.is_none() {
        bail!("--timestamp-ocsp-url requires --timestamp-url during local bundle creation");
    }
    if !args.timestamp_qualified_signer_paths.is_empty() && args.timestamp_url.is_none() {
        bail!("--timestamp-qualified-signer requires --timestamp-url during local bundle creation");
    }
    if !args.timestamp_policy_oids.is_empty() && args.timestamp_url.is_none() {
        bail!("--timestamp-policy-oid requires --timestamp-url during local bundle creation");
    }
    if args.timestamp_assurance.is_some() && args.timestamp_url.is_none() {
        bail!("--timestamp-assurance requires --timestamp-url during local bundle creation");
    }
    if args.transparency_public_key_path.is_some() && args.transparency_log.is_none() {
        bail!("--transparency-public-key requires --transparency-log during local bundle creation");
    }

    let max_payload_bytes = max_payload_bytes()?;
    let capture_json = fs::read(args.input_path)
        .with_context(|| format!("failed to read {}", args.input_path.display()))?;
    if capture_json.len() > max_payload_bytes {
        bail!(
            "capture input {} bytes exceeds max {} bytes",
            capture_json.len(),
            max_payload_bytes
        );
    }
    let capture: SealableCaptureInput =
        serde_json::from_slice(&capture_json).with_context(|| {
            format!(
                "failed to parse capture JSON from {}",
                args.input_path.display()
            )
        })?;
    let capture = apply_create_overrides(materialize_capture_event(capture), args.overrides)?;

    let signing_key_pem = fs::read_to_string(args.key_path)
        .with_context(|| format!("failed to read {}", args.key_path.display()))?;
    let signing_key = decode_private_key_pem(&signing_key_pem)
        .with_context(|| format!("failed to parse signing key {}", args.key_path.display()))?;
    let timestamp_trust_policy = load_timestamp_trust_policy(
        args.timestamp_trust_anchor_paths,
        args.timestamp_crl_paths,
        args.timestamp_ocsp_urls,
        args.timestamp_qualified_signer_paths,
        args.timestamp_policy_oids,
        args.timestamp_assurance,
    )?;
    let transparency_trust_policy = load_transparency_trust_policy(
        args.transparency_public_key_path,
        timestamp_trust_policy.as_ref(),
    )?;

    let mut artefact_inputs = Vec::with_capacity(args.artefacts.len());
    let mut artefact_files = BTreeMap::new();
    for artefact in args.artefacts {
        validate_artefact_name(&artefact.name)?;
        let bytes = fs::read(&artefact.path)
            .with_context(|| format!("failed to read artefact {}", artefact.path.display()))?;
        if bytes.len() > max_payload_bytes {
            bail!(
                "artefact {} is {} bytes and exceeds max {} bytes",
                artefact.name,
                bytes.len(),
                max_payload_bytes
            );
        }
        let content_type = guess_content_type(&artefact.name);
        artefact_files.insert(artefact.name.clone(), bytes.clone());
        artefact_inputs.push(ArtefactInput {
            name: artefact.name.clone(),
            content_type,
            bytes,
        });
    }

    let bundle_id = match args.bundle_id {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                bail!("bundle_id must not be empty");
            }
            trimmed.to_string()
        }
        None => generate_bundle_id(),
    };
    let created_at = parse_created_at(args.created_at)?;
    let bundle = build_bundle(
        capture,
        &artefact_inputs,
        &signing_key,
        args.signing_kid,
        &bundle_id,
        created_at,
    )?;
    let mut bundle = bundle;
    if let Some(timestamp_url) = args.timestamp_url {
        let provider = Rfc3161HttpTimestampProvider::new(timestamp_url.to_string());
        let verification =
            attach_timestamp_to_bundle(&mut bundle, &provider, timestamp_trust_policy.as_ref())?;
        info!(
            "timestamp provider={} generated_at={}",
            verification.provider.as_deref().unwrap_or("rfc3161"),
            verification.generated_at
        );
    }
    if let Some(transparency_log) = args.transparency_log {
        let verification = match args.transparency_provider {
            TransparencyProviderArg::Rekor => {
                let provider = RekorTransparencyProvider::new(transparency_log.to_string());
                attach_receipt_to_bundle(&mut bundle, &provider, transparency_trust_policy.as_ref())
            }
            TransparencyProviderArg::Scitt => {
                let provider = ScittTransparencyProvider::new(transparency_log.to_string());
                attach_receipt_to_bundle(&mut bundle, &provider, transparency_trust_policy.as_ref())
            }
        }?;
        info!(
            "transparency kind={} provider={} entry_uuid={} log_index={}",
            verification.kind,
            verification
                .provider
                .as_deref()
                .unwrap_or(verification.kind.as_str()),
            abbreviate_value(&verification.entry_uuid),
            verification.log_index
        );
    }

    let canonical_header = bundle.canonical_header_bytes()?;
    let bundle_json = serde_json::to_vec_pretty(&bundle)?;
    let signature = bundle.integrity.signature.value.as_bytes().to_vec();

    let mut package_files = BTreeMap::<String, Vec<u8>>::new();
    package_files.insert("proof_bundle.json".to_string(), bundle_json);
    package_files.insert("proof_bundle.canonical.json".to_string(), canonical_header);
    package_files.insert("proof_bundle.sig".to_string(), signature);

    for (name, bytes) in artefact_files {
        package_files.insert(format!("artefacts/{name}"), bytes);
    }

    let manifest = Manifest {
        files: package_files
            .iter()
            .map(|(name, bytes)| ManifestEntry {
                name: name.clone(),
                digest: sha256_prefixed(bytes),
                size: bytes.len() as u64,
            })
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    package_files.insert("manifest.json".to_string(), manifest_bytes);

    write_bundle_package(args.out_path, &package_files)?;
    info!("created {}", args.out_path.display());
    info!("bundle_id={}", bundle.bundle_id);
    info!("bundle_root={}", bundle.integrity.bundle_root);

    Ok(())
}

fn cmd_verify(args: VerifyCommandInput<'_>) -> Result<()> {
    let max_payload_bytes = max_payload_bytes()?;
    let package_size = fs::metadata(args.input_path)
        .with_context(|| format!("failed to stat {}", args.input_path.display()))?
        .len() as usize;
    if package_size > max_payload_bytes {
        bail!(
            "package size {} bytes exceeds max {} bytes",
            package_size,
            max_payload_bytes
        );
    }

    let key_pem = fs::read_to_string(args.key_path)
        .with_context(|| format!("failed to read {}", args.key_path.display()))?;
    let verifying_key = decode_public_key_pem(&key_pem)
        .with_context(|| format!("failed to parse public key {}", args.key_path.display()))?;
    let timestamp_trust_policy = load_timestamp_trust_policy(
        args.timestamp_trust_anchor_paths,
        args.timestamp_crl_paths,
        args.timestamp_ocsp_urls,
        args.timestamp_qualified_signer_paths,
        args.timestamp_policy_oids,
        args.timestamp_assurance,
    )?;
    let transparency_trust_policy = load_transparency_trust_policy(
        args.transparency_public_key_path,
        timestamp_trust_policy.as_ref(),
    )?;

    let package = read_package(args.input_path)?;
    let report = match package.format.as_str() {
        BUNDLE_PACKAGE_FORMAT => verify_full_package(
            &package.files,
            &verifying_key,
            args.check_timestamp,
            args.check_receipt,
            timestamp_trust_policy.as_ref(),
            transparency_trust_policy.as_ref(),
        )?,
        DISCLOSURE_PACKAGE_FORMAT => verify_disclosure_package(
            &package.files,
            &verifying_key,
            args.check_timestamp,
            args.check_receipt,
            timestamp_trust_policy.as_ref(),
            transparency_trust_policy.as_ref(),
        )?,
        other => bail!("unsupported package format {other}"),
    };

    match args.format {
        OutputFormat::Human => print_human_verify_report(&report),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    if report.canonicalization_ok
        && report.artefact_integrity_ok
        && report.signature_ok
        && report.manifest_ok
        && report.disclosure_proof_ok.unwrap_or(true)
        && (!args.check_timestamp || report.timestamp.state == OptionalCheckState::Valid)
        && (!args.check_receipt || report.receipt.state == OptionalCheckState::Valid)
    {
        Ok(())
    } else {
        bail!("verification failed")
    }
}

fn verify_full_package(
    files: &BTreeMap<String, Vec<u8>>,
    verifying_key: &ed25519_dalek::VerifyingKey,
    check_timestamp: bool,
    check_receipt: bool,
    timestamp_trust_policy: Option<&TimestampTrustPolicy>,
    transparency_trust_policy: Option<&TransparencyTrustPolicy>,
) -> Result<VerifyReport> {
    let bundle = parse_bundle_file(files)?;
    validate_bundle_integrity_fields(&bundle)?;

    let recomputed_canonical = bundle.canonical_header_bytes()?;
    let canonical_file = files
        .get("proof_bundle.canonical.json")
        .ok_or_else(|| anyhow!("package missing proof_bundle.canonical.json"))?;
    let canonicalization_ok = &recomputed_canonical == canonical_file;

    let signature_file = files
        .get("proof_bundle.sig")
        .ok_or_else(|| anyhow!("package missing proof_bundle.sig"))?;
    let signature_ok = signature_file == bundle.integrity.signature.value.as_bytes();

    let manifest_ok = verify_manifest(files)?;
    let artefacts = extract_artefacts(files)?;
    let verification = bundle.verify_with_artefacts(&artefacts, verifying_key);

    let mut failures = Vec::new();
    if !canonicalization_ok {
        failures.push("canonicalized header bytes mismatch package".to_string());
    }
    if !signature_ok {
        failures.push("proof_bundle.sig mismatch".to_string());
    }
    if !manifest_ok {
        failures.push("manifest mismatch".to_string());
    }

    let (artefact_integrity_ok, artefacts_verified) = match verification {
        Ok(summary) => (true, summary.artefact_count),
        Err(err) => {
            failures.push(format!("core verification failed: {err}"));
            (false, 0)
        }
    };

    let timestamp = evaluate_timestamp_check(&bundle, check_timestamp, timestamp_trust_policy);
    if check_timestamp && timestamp.state != OptionalCheckState::Valid {
        failures.push(timestamp.message.clone());
    }

    let receipt = evaluate_receipt_check(&bundle, check_receipt, transparency_trust_policy);
    if check_receipt && receipt.state != OptionalCheckState::Valid {
        failures.push(receipt.message.clone());
    }

    let message = if failures.is_empty() {
        "VALID".to_string()
    } else {
        format!("INVALID: {}", failures.join("; "))
    };

    Ok(VerifyReport {
        package_kind: "bundle".to_string(),
        canonicalization_ok,
        disclosure_proof_ok: None,
        artefact_integrity_ok,
        signature_ok: signature_ok && artefact_integrity_ok,
        manifest_ok,
        message,
        artefacts_verified,
        assurance_level: assurance_level(&bundle),
        timestamp,
        receipt,
    })
}

fn verify_disclosure_package(
    files: &BTreeMap<String, Vec<u8>>,
    verifying_key: &ed25519_dalek::VerifyingKey,
    check_timestamp: bool,
    check_receipt: bool,
    timestamp_trust_policy: Option<&TimestampTrustPolicy>,
    transparency_trust_policy: Option<&TransparencyTrustPolicy>,
) -> Result<VerifyReport> {
    let bundle = parse_redacted_bundle_file(files)?;
    let manifest_ok = verify_manifest(files)?;
    let artefacts = extract_artefacts(files)?;
    let verification = verify_redacted_bundle(&bundle, &artefacts, verifying_key);
    let mut failures = Vec::new();
    if !manifest_ok {
        failures.push("manifest mismatch".to_string());
    }

    let (disclosure_proof_ok, artefact_integrity_ok, artefacts_verified) = match verification {
        Ok(summary) => (
            true,
            true,
            summary.disclosed_artefact_count.min(artefacts.len()),
        ),
        Err(err) => {
            failures.push(format!("disclosure verification failed: {err}"));
            (false, false, 0)
        }
    };

    let timestamp = evaluate_timestamp_check_from_parts(
        &bundle.integrity.bundle_root,
        bundle.timestamp.as_ref(),
        check_timestamp,
        timestamp_trust_policy,
    );
    if check_timestamp && timestamp.state != OptionalCheckState::Valid {
        failures.push(timestamp.message.clone());
    }

    let receipt = evaluate_receipt_check_from_parts(
        &bundle.integrity.bundle_root,
        bundle.receipt.as_ref(),
        check_receipt,
        transparency_trust_policy,
    );
    if check_receipt && receipt.state != OptionalCheckState::Valid {
        failures.push(receipt.message.clone());
    }

    let message = if failures.is_empty() {
        "VALID".to_string()
    } else {
        format!("INVALID: {}", failures.join("; "))
    };

    Ok(VerifyReport {
        package_kind: "disclosure".to_string(),
        canonicalization_ok: disclosure_proof_ok,
        disclosure_proof_ok: Some(disclosure_proof_ok),
        artefact_integrity_ok,
        signature_ok: disclosure_proof_ok,
        manifest_ok,
        message,
        artefacts_verified,
        assurance_level: assurance_level_from_parts(
            bundle.timestamp.as_ref(),
            bundle.receipt.as_ref(),
        ),
        timestamp,
        receipt,
    })
}

fn cmd_disclose(
    input_path: &Path,
    items: &str,
    artefacts: Option<&str>,
    out_path: &Path,
) -> Result<()> {
    let max_payload_bytes = max_payload_bytes()?;
    let package_size = fs::metadata(input_path)
        .with_context(|| format!("failed to stat {}", input_path.display()))?
        .len() as usize;
    if package_size > max_payload_bytes {
        bail!(
            "package size {} bytes exceeds max {} bytes",
            package_size,
            max_payload_bytes
        );
    }

    let files = read_bundle_package(input_path)?;
    let bundle = parse_bundle_file(&files)?;
    let item_indices = parse_index_list(items)?;
    let artefact_indices = artefacts
        .map(|value| parse_index_list_for("artefacts", value))
        .transpose()?
        .unwrap_or_default();
    let redacted = redact_bundle(&bundle, &item_indices, &artefact_indices)
        .map_err(|err| map_disclosure_error("redact bundle", err))?;
    let redacted_bytes = serde_json::to_vec_pretty(&redacted)?;

    let mut package_files = BTreeMap::<String, Vec<u8>>::new();
    package_files.insert("redacted_bundle.json".to_string(), redacted_bytes);
    let source_artefacts = extract_artefacts(&files)?;
    for artefact_index in artefact_indices {
        let artefact_name = &bundle
            .artefacts
            .get(artefact_index)
            .ok_or_else(|| anyhow!("artefact index {artefact_index} out of bounds"))?
            .name;
        let artefact_bytes = source_artefacts.get(artefact_name).ok_or_else(|| {
            anyhow!(
                "input package missing selected artefact bytes for {}",
                artefact_name
            )
        })?;
        package_files.insert(
            format!("artefacts/{}", artefact_name),
            artefact_bytes.clone(),
        );
    }

    let manifest = Manifest {
        files: package_files
            .iter()
            .map(|(name, bytes)| ManifestEntry {
                name: name.clone(),
                digest: sha256_prefixed(bytes),
                size: bytes.len() as u64,
            })
            .collect(),
    };
    package_files.insert(
        "manifest.json".to_string(),
        serde_json::to_vec_pretty(&manifest)?,
    );

    write_package(out_path, DISCLOSURE_PACKAGE_FORMAT, &package_files)?;
    Ok(())
}

fn cmd_inspect(
    input_path: &Path,
    format: OutputFormat,
    show_items: bool,
    show_merkle: bool,
) -> Result<()> {
    let max_payload_bytes = max_payload_bytes()?;
    let package_size = fs::metadata(input_path)
        .with_context(|| format!("failed to stat {}", input_path.display()))?
        .len() as usize;
    if package_size > max_payload_bytes {
        bail!(
            "package size {} bytes exceeds max {} bytes",
            package_size,
            max_payload_bytes
        );
    }

    let files = read_bundle_package(input_path)?;
    let bundle = parse_bundle_file(&files)?;

    let merkle_view = if show_merkle {
        Some(build_merkle_inspect_view(&bundle)?)
    } else {
        None
    };

    match format {
        OutputFormat::Human => {
            let provider = bundle
                .primary_llm_interaction()
                .map(|item| item.provider.as_str())
                .or(bundle.context.provider.as_deref())
                .unwrap_or("n/a");
            let model = bundle
                .primary_llm_interaction()
                .map(|item| item.model.as_str())
                .or(bundle.context.model.as_deref())
                .unwrap_or("n/a");
            println!("bundle_id: {}", bundle.bundle_id);
            println!("created_at: {}", bundle.created_at);
            println!("provider: {}", provider);
            println!("model: {}", model);
            println!("items: {}", bundle.items.len());
            println!("artefacts: {}", bundle.artefacts.len());
            println!("bundle_root: {}", bundle.integrity.bundle_root);
            println!("signature.kid: {}", bundle.integrity.signature.kid);
            if show_items {
                println!();
                println!("evidence_items:");
                for (index, item) in bundle.items.iter().enumerate() {
                    println!("  {index}: {}", describe_evidence_item(item));
                }
            }
            if let Some(merkle_view) = merkle_view {
                println!();
                println!(
                    "merkle: algorithm={} root={}",
                    merkle_view.algorithm, merkle_view.root
                );
                for leaf in merkle_view.leaves {
                    println!(
                        "  [{}] {} digest={} proof_steps={}",
                        leaf.index, leaf.label, leaf.digest, leaf.proof_steps
                    );
                }
            }
        }
        OutputFormat::Json => {
            if show_merkle {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&InspectJsonOutput {
                        bundle: &bundle,
                        merkle: merkle_view,
                    })?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&bundle)?);
            }
        }
    }

    Ok(())
}

fn cmd_pack(input: PackCommandInput<'_>) -> Result<()> {
    let request = CreatePackRequest {
        pack_type: input.pack_type.as_api_value().to_string(),
        system_id: normalize_optional_cli_text("system_id", input.system_id)?,
        from: normalize_optional_cli_datetime("from", input.from)?,
        to: normalize_optional_cli_datetime("to", input.to)?,
        bundle_format: input.bundle_format.as_api_value().to_string(),
        disclosure_policy: normalize_optional_cli_text(
            "disclosure_policy",
            input.disclosure_policy,
        )?,
    };
    if let (Some(from), Some(to)) = (request.from.as_deref(), request.to.as_deref()) {
        let from = DateTime::parse_from_rfc3339(from)
            .with_context(|| format!("from must be RFC3339, got: {from}"))?;
        let to = DateTime::parse_from_rfc3339(to)
            .with_context(|| format!("to must be RFC3339, got: {to}"))?;
        if from > to {
            bail!("from must be <= to");
        }
    }

    let client = build_http_client()?;
    let create_url = join_vault_url(input.vault_url, "/v1/packs");
    let create_response = client
        .post(&create_url)
        .json(&request)
        .send()
        .with_context(|| format!("failed to call {create_url}"))?;
    let create_response = ensure_success(create_response, "pack create")?;
    let pack: PackSummaryResponse = create_response
        .json()
        .context("failed to decode pack create response")?;

    let export_url = join_vault_url(
        input.vault_url,
        &format!("/v1/packs/{}/export", pack.pack_id),
    );
    let export_response = client
        .get(&export_url)
        .send()
        .with_context(|| format!("failed to call {export_url}"))?;
    let export_response = ensure_success(export_response, "pack export download")?;
    let export_bytes = export_response
        .bytes()
        .context("failed to read pack export body")?;

    let max_payload_bytes = max_payload_bytes()?;
    if export_bytes.len() > max_payload_bytes {
        bail!(
            "pack export {} bytes exceeds max {} bytes",
            export_bytes.len(),
            max_payload_bytes
        );
    }

    let parent = input.out_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    fs::write(input.out_path, &export_bytes)
        .with_context(|| format!("failed to write {}", input.out_path.display()))?;

    info!("wrote {}", input.out_path.display());
    info!("pack_id={}", pack.pack_id);
    info!("pack_type={}", pack.pack_type);
    info!("bundle_format={}", pack.bundle_format);
    if let Some(disclosure_policy) = pack.disclosure_policy.as_deref() {
        info!("disclosure_policy={disclosure_policy}");
    }
    info!("bundle_count={}", pack.bundle_count);
    if let Some(system_id) = pack.system_id.as_deref() {
        info!("system_id={system_id}");
    }
    if let Some(from) = pack.from.as_deref() {
        info!("from={from}");
    }
    if let Some(to) = pack.to.as_deref() {
        info!("to={to}");
    }
    info!("created_at={}", pack.created_at);
    info!("bundle_ids={}", pack.bundle_ids.join(","));

    Ok(())
}

fn cmd_vault_status(vault_url: &str, format: OutputFormat) -> Result<()> {
    let client = build_http_client()?;
    require_vault_ready(&client, vault_url)?;
    let config: VaultConfigResponse = get_json(
        &client,
        build_vault_path_url(vault_url, &["v1", "config"])?,
        "vault config",
    )?;
    let retention: VaultRetentionStatusResponse = get_json(
        &client,
        build_vault_path_url(vault_url, &["v1", "retention", "status"])?,
        "vault retention status",
    )?;
    let systems: VaultSystemsResponse = get_json(
        &client,
        build_vault_path_url(vault_url, &["v1", "systems"])?,
        "vault systems",
    )?;

    let bundle_total = retention
        .policies
        .iter()
        .map(|policy| policy.total_bundles)
        .sum::<i64>();
    let bundle_active = retention
        .policies
        .iter()
        .map(|policy| policy.active_bundles)
        .sum::<i64>();
    let bundle_deleted = retention
        .policies
        .iter()
        .map(|policy| policy.deleted_bundles)
        .sum::<i64>();
    let bundle_held = retention
        .policies
        .iter()
        .map(|policy| policy.held_bundles)
        .sum::<i64>();
    let output = VaultStatusOutput {
        ready: true,
        service_addr: config.service.addr.clone(),
        max_payload_bytes: config.service.max_payload_bytes,
        signing_key_id: config.signing.key_id.clone(),
        metadata_backend: config.storage.metadata_backend.clone(),
        blob_backend: config.storage.blob_backend.clone(),
        bundle_total,
        bundle_active,
        bundle_deleted,
        bundle_held,
        system_count: systems.items.len(),
        retention_policy_count: config.retention.policies.len(),
        scan_interval_hours: config.retention.scan_interval_hours,
        timestamp_enabled: config.timestamp.enabled,
        timestamp_provider: config.timestamp.provider.clone(),
        timestamp_assurance: config.timestamp.assurance.clone(),
        timestamp_trust_anchor_count: config.timestamp.trust_anchor_pems.len(),
        timestamp_ocsp_url_count: config.timestamp.ocsp_responder_urls.len(),
        timestamp_policy_oid_count: config.timestamp.policy_oids.len(),
        transparency_enabled: config.transparency.enabled,
        transparency_provider: config.transparency.provider.clone(),
    };

    match format {
        OutputFormat::Human => print_vault_status_human(&output, &config),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
    }

    Ok(())
}

fn cmd_vault_query(args: VaultQueryCommandInput<'_>) -> Result<()> {
    let client = build_http_client()?;
    let query_url = build_vault_bundles_query_url(&args)?;
    let response: VaultBundleListResponse = get_json(&client, query_url, "vault bundle query")?;

    match args.format {
        OutputFormat::Human => print_vault_bundle_query_human(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }

    Ok(())
}

fn cmd_vault_retention(vault_url: &str, format: OutputFormat) -> Result<()> {
    let client = build_http_client()?;
    let response: VaultRetentionStatusResponse = get_json(
        &client,
        build_vault_path_url(vault_url, &["v1", "retention", "status"])?,
        "vault retention status",
    )?;

    match format {
        OutputFormat::Human => print_vault_retention_human(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }

    Ok(())
}

fn cmd_vault_systems(vault_url: &str, system_id: Option<&str>, format: OutputFormat) -> Result<()> {
    let client = build_http_client()?;

    if let Some(system_id) = system_id {
        let system_id = normalize_optional_cli_text("system_id", Some(system_id))?
            .expect("system_id was just provided");
        let response: VaultSystemSummaryResponse = get_json(
            &client,
            build_vault_path_url(vault_url, &["v1", "systems", &system_id, "summary"])?,
            "vault system summary",
        )?;
        match format {
            OutputFormat::Human => print_vault_system_summary_human(&response),
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        }
        return Ok(());
    }

    let response: VaultSystemsResponse = get_json(
        &client,
        build_vault_path_url(vault_url, &["v1", "systems"])?,
        "vault systems",
    )?;
    match format {
        OutputFormat::Human => print_vault_systems_human(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }
    Ok(())
}

fn print_vault_status_human(status: &VaultStatusOutput, config: &VaultConfigResponse) {
    println!("ready: {}", if status.ready { "yes" } else { "no" });
    println!("service.addr: {}", status.service_addr);
    println!("service.max_payload_bytes: {}", status.max_payload_bytes);
    println!("signing.key_id: {}", status.signing_key_id);
    println!(
        "storage: metadata={} blobs={}",
        status.metadata_backend, status.blob_backend
    );
    println!(
        "bundles: total={} active={} deleted={} held={}",
        status.bundle_total, status.bundle_active, status.bundle_deleted, status.bundle_held
    );
    println!("systems: {}", status.system_count);
    println!(
        "retention: policies={} grace_days={} scan_interval_hours={}",
        status.retention_policy_count,
        config.retention.grace_period_days,
        status.scan_interval_hours
    );
    println!(
        "timestamp: enabled={} provider={} assurance={} trust_anchors={} ocsp_urls={} policy_oids={}",
        status.timestamp_enabled,
        status.timestamp_provider,
        status.timestamp_assurance.as_deref().unwrap_or("n/a"),
        status.timestamp_trust_anchor_count,
        status.timestamp_ocsp_url_count,
        status.timestamp_policy_oid_count
    );
    println!(
        "transparency: enabled={} provider={}",
        status.transparency_enabled, status.transparency_provider
    );
}

fn print_vault_bundle_query_human(response: &VaultBundleListResponse) {
    println!("page: {} limit: {}", response.page, response.limit);
    if response.items.is_empty() {
        println!("no bundles matched");
        return;
    }

    for item in &response.items {
        println!(
            "{} {} system={} role={} assurance={} retention={} hold={}",
            item.bundle_id,
            item.created_at,
            item.system_id.as_deref().unwrap_or("n/a"),
            item.actor_role,
            item.assurance_level,
            item.retention_class,
            if item.has_legal_hold { "yes" } else { "no" }
        );
    }
}

fn print_vault_retention_human(response: &VaultRetentionStatusResponse) {
    println!(
        "scanned_at: {} grace_period_days: {}",
        response.scanned_at, response.grace_period_days
    );
    for policy in &response.policies {
        println!(
            "{} active={} min_days={} bundles(total={}, active={}, deleted={}, held={}) next_expiry={}",
            policy.retention_class,
            policy.active,
            policy.min_duration_days,
            policy.total_bundles,
            policy.active_bundles,
            policy.deleted_bundles,
            policy.held_bundles,
            policy.next_expiry.as_deref().unwrap_or("n/a")
        );
    }
}

fn print_vault_systems_human(response: &VaultSystemsResponse) {
    if response.items.is_empty() {
        println!("no systems found");
        return;
    }

    for item in &response.items {
        println!(
            "{} bundles={} active={} deleted={} timestamped={} anchored={} latest={}",
            item.system_id,
            item.bundle_count,
            item.active_bundle_count,
            item.deleted_bundle_count,
            item.timestamped_bundle_count,
            item.receipt_bundle_count,
            item.latest_bundle_at.as_deref().unwrap_or("n/a")
        );
    }
}

fn print_vault_system_summary_human(response: &VaultSystemSummaryResponse) {
    println!("system_id: {}", response.system_id);
    println!(
        "bundles: total={} active={} deleted={} timestamped={} anchored={}",
        response.bundle_count,
        response.active_bundle_count,
        response.deleted_bundle_count,
        response.timestamped_bundle_count,
        response.receipt_bundle_count
    );
    println!(
        "first_seen_at: {}",
        response.first_seen_at.as_deref().unwrap_or("n/a")
    );
    println!(
        "latest_bundle_at: {}",
        response.latest_bundle_at.as_deref().unwrap_or("n/a")
    );
    println!(
        "actor_roles: {}",
        format_facet_counts(&response.actor_roles)
    );
    println!(
        "evidence_types: {}",
        format_facet_counts(&response.evidence_types)
    );
    println!(
        "retention_classes: {}",
        format_facet_counts(&response.retention_classes)
    );
    println!(
        "assurance_levels: {}",
        format_facet_counts(&response.assurance_levels)
    );
    println!("model_ids: {}", format_facet_counts(&response.model_ids));
}

fn format_facet_counts(values: &[VaultFacetCount]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    values
        .iter()
        .map(|entry| format!("{}({})", entry.value, entry.count))
        .collect::<Vec<_>>()
        .join(", ")
}

fn materialize_capture_event(capture: SealableCaptureInput) -> CaptureEvent {
    match capture {
        SealableCaptureInput::V10(capture) => capture,
        SealableCaptureInput::Legacy(capture) => capture_input_v01_to_event(capture),
    }
}

fn apply_create_overrides(
    mut capture: CaptureEvent,
    overrides: &CreateOverrides,
) -> Result<CaptureEvent> {
    if let Some(system_id) = overrides.system_id.as_deref() {
        let system_id = system_id.trim();
        if system_id.is_empty() {
            bail!("system_id must not be empty");
        }
        capture.subject.system_id = Some(system_id.to_string());
    }

    if let Some(retention_class) = overrides.retention_class.as_deref() {
        let retention_class = retention_class.trim();
        if retention_class.is_empty() {
            bail!("retention_class must not be empty");
        }
        capture.policy.retention_class = Some(retention_class.to_string());
    }

    if let Some(evidence_type) = overrides.evidence_type {
        let Some(index) = capture
            .items
            .iter()
            .position(|item| evidence_type.matches_item(item))
        else {
            bail!(
                "capture event does not contain requested evidence type {}",
                evidence_type.as_str()
            );
        };
        if index != 0 {
            capture.items.swap(0, index);
        }
    }

    Ok(capture)
}

fn build_merkle_inspect_view(bundle: &ProofBundle) -> Result<InspectMerkleView> {
    let digests = bundle.commitment_digests()?;

    let mut leaves = Vec::with_capacity(digests.len());
    for (index, digest) in digests.iter().enumerate() {
        let proof = build_inclusion_proof(&digests, index)?;
        let label = if index == 0 {
            "header_digest".to_string()
        } else if index <= bundle.items.len() {
            format!("item:{index_minus_one}", index_minus_one = index - 1)
        } else if bundle.integrity.bundle_root_algorithm == LEGACY_BUNDLE_ROOT_ALGORITHM {
            format!("artefact:{}", bundle.artefacts[index - 1].name)
        } else {
            format!(
                "artefact:{}",
                bundle.artefacts[index - 1 - bundle.items.len()].name
            )
        };

        leaves.push(InspectMerkleLeaf {
            index,
            label,
            digest: digest.clone(),
            proof_steps: proof.path.len(),
        });
    }

    Ok(InspectMerkleView {
        algorithm: bundle.integrity.bundle_root_algorithm.clone(),
        root: bundle.integrity.bundle_root.clone(),
        leaves,
    })
}

fn describe_evidence_item(item: &EvidenceItem) -> String {
    match item {
        EvidenceItem::LlmInteraction(data) => format!(
            "llm_interaction provider={} model={} input={} output={}",
            data.provider,
            data.model,
            abbreviate_digest(&data.input_commitment),
            abbreviate_digest(&data.output_commitment)
        ),
        EvidenceItem::ToolCall(data) => {
            format!("tool_call tool_name={}", data.tool_name)
        }
        EvidenceItem::Retrieval(data) => format!(
            "retrieval corpus={} result={}",
            data.corpus,
            abbreviate_digest(&data.result_commitment)
        ),
        EvidenceItem::HumanOversight(data) => {
            format!("human_oversight action={}", data.action)
        }
        EvidenceItem::PolicyDecision(data) => format!(
            "policy_decision policy={} decision={}",
            data.policy_name, data.decision
        ),
        EvidenceItem::RiskAssessment(data) => format!(
            "risk_assessment risk_id={} severity={} status={}",
            data.risk_id, data.severity, data.status
        ),
        EvidenceItem::DataGovernance(data) => {
            format!("data_governance decision={}", data.decision)
        }
        EvidenceItem::TechnicalDoc(data) => {
            format!("technical_doc document_ref={}", data.document_ref)
        }
        EvidenceItem::ModelEvaluation(data) => format!(
            "model_evaluation evaluation_id={} benchmark={} status={}",
            data.evaluation_id, data.benchmark, data.status
        ),
        EvidenceItem::AdversarialTest(data) => format!(
            "adversarial_test test_id={} focus={} status={}",
            data.test_id, data.focus, data.status
        ),
        EvidenceItem::TrainingProvenance(data) => format!(
            "training_provenance dataset_ref={} stage={}",
            data.dataset_ref, data.stage
        ),
        EvidenceItem::ConformityAssessment(data) => format!(
            "conformity_assessment assessment_id={} procedure={} status={}",
            data.assessment_id, data.procedure, data.status
        ),
        EvidenceItem::Declaration(data) => format!(
            "declaration declaration_id={} jurisdiction={} status={}",
            data.declaration_id, data.jurisdiction, data.status
        ),
        EvidenceItem::Registration(data) => format!(
            "registration registration_id={} authority={} status={}",
            data.registration_id, data.authority, data.status
        ),
        EvidenceItem::LiteracyAttestation(data) => format!(
            "literacy_attestation role={} status={}",
            data.attested_role, data.status
        ),
        EvidenceItem::IncidentReport(data) => format!(
            "incident_report incident_id={} severity={} status={}",
            data.incident_id, data.severity, data.status
        ),
    }
}

fn abbreviate_digest(value: &str) -> String {
    if value.len() <= 22 {
        return value.to_string();
    }
    format!("{}...{}", &value[..15], &value[value.len() - 6..])
}

fn abbreviate_value(value: &str) -> String {
    if value.len() <= 20 {
        return value.to_string();
    }
    format!("{}...{}", &value[..12], &value[value.len() - 6..])
}

fn read_text_file(path: &Path, label: &str) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn read_text_files(paths: &[PathBuf], label: &str) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|path| read_text_file(path, label))
        .collect()
}

fn load_timestamp_trust_policy(
    trust_anchor_paths: &[PathBuf],
    crl_paths: &[PathBuf],
    ocsp_urls: &[String],
    qualified_signer_paths: &[PathBuf],
    policy_oids: &[String],
    assurance: Option<TimestampAssuranceArg>,
) -> Result<Option<TimestampTrustPolicy>> {
    let policy = TimestampTrustPolicy {
        trust_anchor_pems: read_text_files(trust_anchor_paths, "timestamp trust anchor")?,
        crl_pems: read_text_files(crl_paths, "timestamp CRL")?,
        ocsp_responder_urls: ocsp_urls
            .iter()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect(),
        qualified_signer_pems: read_text_files(
            qualified_signer_paths,
            "qualified TSA signer certificate",
        )?,
        policy_oids: policy_oids
            .iter()
            .map(|policy_oid| policy_oid.trim().to_string())
            .filter(|policy_oid| !policy_oid.is_empty())
            .collect(),
        assurance_profile: assurance.map(map_timestamp_assurance_profile),
    };
    (!policy.is_empty())
        .then_some(policy)
        .map_or(Ok(None), |policy| {
            validate_timestamp_trust_policy(&policy)?;
            Ok(Some(policy))
        })
}

fn map_timestamp_assurance_profile(assurance: TimestampAssuranceArg) -> TimestampAssuranceProfile {
    match assurance {
        TimestampAssuranceArg::Standard => TimestampAssuranceProfile::Standard,
        TimestampAssuranceArg::Qualified => TimestampAssuranceProfile::Qualified,
    }
}

fn load_transparency_trust_policy(
    public_key_path: Option<&Path>,
    timestamp_policy: Option<&TimestampTrustPolicy>,
) -> Result<Option<TransparencyTrustPolicy>> {
    let policy = TransparencyTrustPolicy {
        log_public_key_pem: public_key_path
            .map(|path| read_text_file(path, "transparency public key"))
            .transpose()?,
        timestamp: timestamp_policy.cloned().unwrap_or_default(),
    };
    (!policy.is_empty())
        .then_some(policy)
        .map_or(Ok(None), |policy| Ok(Some(policy)))
}

fn evaluate_timestamp_check(
    bundle: &ProofBundle,
    requested: bool,
    trust_policy: Option<&TimestampTrustPolicy>,
) -> OptionalCheckReport {
    evaluate_timestamp_check_from_parts(
        &bundle.integrity.bundle_root,
        bundle.timestamp.as_ref(),
        requested,
        trust_policy,
    )
}

fn evaluate_timestamp_check_from_parts(
    bundle_root: &str,
    timestamp: Option<&TimestampToken>,
    requested: bool,
    trust_policy: Option<&TimestampTrustPolicy>,
) -> OptionalCheckReport {
    if !requested {
        return OptionalCheckReport {
            state: OptionalCheckState::Skipped,
            message: if timestamp.is_some() {
                "timestamp present but not checked".to_string()
            } else {
                "timestamp not present (optional)".to_string()
            },
        };
    }

    let Some(timestamp) = timestamp else {
        return OptionalCheckReport {
            state: OptionalCheckState::Missing,
            message: "timestamp check requested but bundle has no timestamp".to_string(),
        };
    };

    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_timestamp_with_policy(timestamp, bundle_root, policy)
        }
        _ => verify_timestamp(timestamp, bundle_root),
    };

    match verification {
        Ok(verification) => OptionalCheckReport {
            state: OptionalCheckState::Valid,
            message: format!(
                "RFC 3161 token {} at {} ({} signer{})",
                timestamp_verification_label(&verification),
                verification.generated_at,
                verification.signer_count,
                if verification.signer_count == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        },
        Err(err) => OptionalCheckReport {
            state: OptionalCheckState::Invalid,
            message: format!("RFC 3161 timestamp verification failed: {err}"),
        },
    }
}

fn timestamp_verification_label(verification: &proof_layer_core::TimestampVerification) -> String {
    match verification.assurance_profile {
        Some(TimestampAssuranceProfile::Qualified) if verification.assurance_profile_verified => {
            "qualified-profile verified".to_string()
        }
        Some(TimestampAssuranceProfile::Standard) if verification.assurance_profile_verified => {
            "standard-profile verified".to_string()
        }
        _ if verification.trusted => "trusted".to_string(),
        _ => "structurally valid".to_string(),
    }
}

fn evaluate_receipt_check(
    bundle: &ProofBundle,
    requested: bool,
    trust_policy: Option<&TransparencyTrustPolicy>,
) -> OptionalCheckReport {
    evaluate_receipt_check_from_parts(
        &bundle.integrity.bundle_root,
        bundle.receipt.as_ref(),
        requested,
        trust_policy,
    )
}

fn evaluate_receipt_check_from_parts(
    bundle_root: &str,
    receipt: Option<&TransparencyReceipt>,
    requested: bool,
    trust_policy: Option<&TransparencyTrustPolicy>,
) -> OptionalCheckReport {
    if !requested {
        return OptionalCheckReport {
            state: OptionalCheckState::Skipped,
            message: if receipt.is_some() {
                "transparency receipt present but not checked".to_string()
            } else {
                "transparency receipt not present (optional)".to_string()
            },
        };
    }

    let Some(receipt) = receipt else {
        return OptionalCheckReport {
            state: OptionalCheckState::Missing,
            message: "transparency receipt check requested but bundle has no transparency receipt"
                .to_string(),
        };
    };

    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_receipt_with_policy(receipt, bundle_root, policy)
        }
        _ => verify_receipt(receipt, bundle_root),
    };

    match verification {
        Ok(verification) => OptionalCheckReport {
            state: OptionalCheckState::Valid,
            message: format!(
                "{} receipt {} at {} (entry {}, log_index {})",
                if verification.kind == SCITT_TRANSPARENCY_KIND {
                    "SCITT"
                } else {
                    "Rekor"
                },
                if verification.trusted {
                    "trusted"
                } else {
                    "structurally valid"
                },
                verification.integrated_time,
                abbreviate_value(&verification.entry_uuid),
                verification.log_index
            ),
        },
        Err(err) => OptionalCheckReport {
            state: OptionalCheckState::Invalid,
            message: format!("transparency receipt verification failed: {err}"),
        },
    }
}

fn attach_timestamp_to_bundle(
    bundle: &mut ProofBundle,
    provider: &dyn TimestampProvider,
    trust_policy: Option<&TimestampTrustPolicy>,
) -> Result<proof_layer_core::TimestampVerification> {
    if bundle.timestamp.is_some() {
        bail!("bundle already contains a timestamp token");
    }

    let token = timestamp_digest(&bundle.integrity.bundle_root, provider)
        .context("failed to request timestamp token")?;
    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_timestamp_with_policy(&token, &bundle.integrity.bundle_root, policy)
        }
        _ => verify_timestamp(&token, &bundle.integrity.bundle_root),
    }
    .context("failed to verify returned timestamp token")?;
    bundle.timestamp = Some(token);

    Ok(verification)
}

fn attach_receipt_to_bundle(
    bundle: &mut ProofBundle,
    provider: &dyn TransparencyProvider,
    trust_policy: Option<&TransparencyTrustPolicy>,
) -> Result<ReceiptVerification> {
    if bundle.receipt.is_some() {
        bail!("bundle already contains a transparency receipt");
    }

    let receipt =
        anchor_bundle_receipt(bundle, provider).context("failed to submit transparency receipt")?;
    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_receipt_with_policy(&receipt, &bundle.integrity.bundle_root, policy)
        }
        _ => verify_receipt(&receipt, &bundle.integrity.bundle_root),
    }
    .context("failed to verify returned transparency receipt")?;
    bundle.receipt = Some(receipt);

    Ok(verification)
}

fn assurance_level(bundle: &ProofBundle) -> AssuranceLevel {
    assurance_level_from_parts(bundle.timestamp.as_ref(), bundle.receipt.as_ref())
}

fn assurance_level_from_parts(
    timestamp: Option<&TimestampToken>,
    receipt: Option<&TransparencyReceipt>,
) -> AssuranceLevel {
    if receipt.is_some() {
        AssuranceLevel::TransparencyAnchored
    } else if timestamp.is_some() {
        AssuranceLevel::Timestamped
    } else {
        AssuranceLevel::Signed
    }
}

fn write_package(out_path: &Path, format: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;

    let package = BundlePackage {
        format: format.to_string(),
        files: files
            .iter()
            .map(|(name, bytes)| PackagedFile {
                name: name.clone(),
                data_base64: base64ct::Base64::encode_string(bytes),
            })
            .collect(),
    };
    let package_bytes = serde_json::to_vec_pretty(&package)?;

    let file = fs::File::create(out_path)
        .with_context(|| format!("failed to create {}", out_path.display()))?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder
        .write_all(&package_bytes)
        .context("failed to write compressed package bytes")?;
    encoder.finish().context("failed to finalize gzip stream")?;
    Ok(())
}

fn write_bundle_package(out_path: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    write_package(out_path, BUNDLE_PACKAGE_FORMAT, files)
}

fn read_package(path: &Path) -> Result<DecodedPackage> {
    let max_payload_bytes = max_payload_bytes()?;
    let file =
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut json_bytes = Vec::new();
    let mut limited_reader = decoder.take(
        max_payload_bytes
            .checked_add(1)
            .ok_or_else(|| anyhow!("payload size limit overflow"))? as u64,
    );
    limited_reader
        .read_to_end(&mut json_bytes)
        .context("failed to decompress package")?;
    if json_bytes.len() > max_payload_bytes {
        bail!(
            "decompressed package JSON is {} bytes and exceeds max {} bytes",
            json_bytes.len(),
            max_payload_bytes
        );
    }

    let package: BundlePackage =
        serde_json::from_slice(&json_bytes).context("failed to parse package JSON")?;

    let mut files = BTreeMap::new();
    for file in package.files {
        validate_package_member_name(&file.name)?;
        if files.contains_key(&file.name) {
            bail!("duplicate package file entry {}", file.name);
        }
        let bytes = base64ct::Base64::decode_vec(&file.data_base64)
            .map_err(|err| anyhow!("failed to decode package file {}: {err}", file.name))?;
        if bytes.len() > max_payload_bytes {
            bail!(
                "package member {} is {} bytes and exceeds max {} bytes",
                file.name,
                bytes.len(),
                max_payload_bytes
            );
        }
        files.insert(file.name, bytes);
    }

    Ok(DecodedPackage {
        format: package.format,
        files,
    })
}

fn read_bundle_package(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let package = read_package(path)?;
    if package.format != BUNDLE_PACKAGE_FORMAT {
        bail!("unsupported package format {}", package.format);
    }
    Ok(package.files)
}

fn parse_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<ProofBundle> {
    let bundle_json = files
        .get("proof_bundle.json")
        .ok_or_else(|| anyhow!("package missing proof_bundle.json"))?;
    let bundle: ProofBundle =
        serde_json::from_slice(bundle_json).context("failed to parse proof_bundle.json")?;
    Ok(bundle)
}

fn parse_redacted_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<RedactedBundle> {
    let bundle_json = files
        .get("redacted_bundle.json")
        .ok_or_else(|| anyhow!("package missing redacted_bundle.json"))?;
    let bundle: RedactedBundle =
        serde_json::from_slice(bundle_json).context("failed to parse redacted_bundle.json")?;
    Ok(bundle)
}

fn verify_manifest(files: &BTreeMap<String, Vec<u8>>) -> Result<bool> {
    let manifest_bytes = files
        .get("manifest.json")
        .ok_or_else(|| anyhow!("package missing manifest.json"))?;
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).context("failed to parse manifest.json")?;

    let mut seen = HashSet::new();
    for entry in manifest.files {
        if entry.name == "manifest.json" {
            return Ok(false);
        }
        validate_package_member_name(&entry.name)?;
        if !seen.insert(entry.name.clone()) {
            return Ok(false);
        }
        let bytes = files
            .get(&entry.name)
            .ok_or_else(|| anyhow!("manifest references missing file {}", entry.name))?;
        let digest = sha256_prefixed(bytes);
        if digest != entry.digest || bytes.len() as u64 != entry.size {
            return Ok(false);
        }
    }

    for name in files.keys() {
        if name == "manifest.json" {
            continue;
        }
        if !seen.contains(name) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn extract_artefacts(files: &BTreeMap<String, Vec<u8>>) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut artefacts = BTreeMap::new();
    for (name, bytes) in files {
        if let Some(stripped) = name.strip_prefix("artefacts/") {
            validate_artefact_name(stripped)?;
            artefacts.insert(stripped.to_string(), bytes.clone());
        }
    }
    Ok(artefacts)
}

fn print_human_verify_report(report: &VerifyReport) {
    println!("Package kind: {}", report.package_kind);
    println!(
        "[{}] Canonicalisation — header re-canonicalised, digest {}",
        if report.canonicalization_ok {
            "✓"
        } else {
            "✗"
        },
        if report.canonicalization_ok {
            "matches"
        } else {
            "mismatch"
        }
    );
    println!(
        "[{}] Artefact integrity — {} artefacts verified",
        if report.artefact_integrity_ok {
            "✓"
        } else {
            "✗"
        },
        report.artefacts_verified
    );
    println!(
        "[{}] Signature — {}",
        if report.signature_ok { "✓" } else { "✗" },
        if report.signature_ok {
            "Ed25519 signature valid for bundle_root"
        } else {
            "signature mismatch or invalid"
        }
    );
    println!(
        "[{}] Manifest — {}",
        if report.manifest_ok { "✓" } else { "✗" },
        if report.manifest_ok {
            "file digest and size checks pass"
        } else {
            "manifest mismatch"
        }
    );
    if let Some(disclosure_proof_ok) = report.disclosure_proof_ok {
        println!(
            "[{}] Disclosure proofs — {}",
            if disclosure_proof_ok { "✓" } else { "✗" },
            if disclosure_proof_ok {
                "selected item proofs validate against bundle_root"
            } else {
                "one or more disclosure proofs are invalid"
            }
        );
    }
    println!(
        "[{}] Timestamp — {}",
        optional_check_marker(&report.timestamp.state),
        report.timestamp.message
    );
    println!(
        "[{}] Transparency receipt — {}",
        optional_check_marker(&report.receipt.state),
        report.receipt.message
    );
    println!(
        "Assurance level: {}",
        assurance_level_label(report.assurance_level)
    );
    println!();
    println!("Verification result: {}", report.message);
}

fn optional_check_marker(state: &OptionalCheckState) -> &'static str {
    match state {
        OptionalCheckState::Valid => "✓",
        OptionalCheckState::Skipped => "–",
        OptionalCheckState::Missing | OptionalCheckState::Invalid => "✗",
    }
}

fn assurance_level_label(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Signed => "signed",
        AssuranceLevel::Timestamped => "timestamped",
        AssuranceLevel::TransparencyAnchored => "transparency_anchored",
    }
}

fn parse_artefact_arg(value: &str) -> Result<ArtefactArg, String> {
    let mut parts = value.splitn(2, '=');
    let name = parts
        .next()
        .ok_or_else(|| "missing artefact name".to_string())?
        .trim();
    let path = parts
        .next()
        .ok_or_else(|| "expected format name=path".to_string())?
        .trim();

    if name.is_empty() {
        return Err("artefact name cannot be empty".to_string());
    }
    if path.is_empty() {
        return Err("artefact path cannot be empty".to_string());
    }

    Ok(ArtefactArg {
        name: name.to_string(),
        path: PathBuf::from(path),
    })
}

fn validate_artefact_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("artefact name must not be empty");
    }
    let path = Path::new(name);
    if path.is_absolute() {
        bail!("artefact name {name} must be relative");
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!("artefact name {name} contains invalid path traversal component");
        }
    }
    Ok(())
}

fn guess_content_type(name: &str) -> String {
    if name.ends_with(".json") {
        "application/json".to_string()
    } else if name.ends_with(".txt") {
        "text/plain".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn generate_bundle_id() -> String {
    Ulid::new().to_string()
}

fn parse_created_at(value: Option<&str>) -> Result<DateTime<Utc>> {
    match value {
        Some(raw) => {
            let parsed = DateTime::parse_from_rfc3339(raw)
                .with_context(|| format!("created_at must be RFC3339, got: {raw}"))?;
            Ok(parsed.with_timezone(&Utc))
        }
        None => Ok(Utc::now()),
    }
}

fn validate_package_member_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("package member name must not be empty");
    }

    match name {
        "proof_bundle.json"
        | "proof_bundle.canonical.json"
        | "proof_bundle.sig"
        | "redacted_bundle.json"
        | "manifest.json" => Ok(()),
        _ => {
            if let Some(stripped) = name.strip_prefix("artefacts/") {
                validate_artefact_name(stripped)?;
                return Ok(());
            }
            bail!("unsupported package member name {name}");
        }
    }
}

fn parse_index_list(value: &str) -> Result<Vec<usize>> {
    parse_index_list_for("items", value)
}

fn parse_index_list_for(label: &str, value: &str) -> Result<Vec<usize>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} must not be empty");
    }

    trimmed
        .split(',')
        .map(|part| {
            let part = part.trim();
            if part.is_empty() {
                bail!("{label} must not contain empty indices");
            }
            part.parse::<usize>()
                .with_context(|| format!("invalid {label} index {part}"))
        })
        .collect()
}

fn map_disclosure_error(action: &str, err: DisclosureError) -> anyhow::Error {
    anyhow!("{action} failed: {err}")
}

fn normalize_optional_cli_text(label: &str, value: Option<&str>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                bail!("{label} must not be empty");
            }
            Ok(Some(trimmed.to_string()))
        }
        None => Ok(None),
    }
}

fn normalize_optional_cli_datetime(label: &str, value: Option<&str>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                bail!("{label} must not be empty");
            }
            let parsed = DateTime::parse_from_rfc3339(trimmed)
                .with_context(|| format!("{label} must be RFC3339, got: {trimmed}"))?;
            Ok(Some(parsed.with_timezone(&Utc).to_rfc3339()))
        }
        None => Ok(None),
    }
}

fn build_http_client() -> Result<Client> {
    Client::builder()
        .build()
        .context("failed to build HTTP client")
}

fn require_vault_ready(client: &Client, vault_url: &str) -> Result<()> {
    let response = client
        .get(join_vault_url(vault_url, "/readyz"))
        .send()
        .with_context(|| format!("failed to call {}/readyz", vault_url.trim_end_matches('/')))?;
    ensure_success(response, "vault readiness check").map(|_| ())
}

fn get_json<T: DeserializeOwned>(client: &Client, url: String, action: &str) -> Result<T> {
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, action)?;
    response
        .json()
        .with_context(|| format!("failed to decode {action} response"))
}

fn build_vault_path_url(vault_url: &str, segments: &[&str]) -> Result<String> {
    let mut url = Url::parse(&format!("{}/", vault_url.trim_end_matches('/')))
        .with_context(|| format!("invalid vault_url: {vault_url}"))?;
    {
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("vault_url must be a base URL"))?;
        path_segments.clear();
        for segment in segments {
            path_segments.push(segment);
        }
    }
    Ok(url.to_string())
}

fn build_vault_bundles_query_url(args: &VaultQueryCommandInput<'_>) -> Result<String> {
    let mut url = Url::parse(&build_vault_path_url(args.vault_url, &["v1", "bundles"])?)
        .context("failed to construct vault bundle query URL")?;
    {
        let mut query = url.query_pairs_mut();
        if let Some(system_id) = normalize_optional_cli_text("system_id", args.system_id)? {
            query.append_pair("system_id", &system_id);
        }
        if let Some(role) = args.role {
            query.append_pair("role", role.as_api_value());
        }
        if let Some(item_type) = args.item_type {
            query.append_pair("type", item_type.as_str());
        }
        if args.has_timestamp {
            query.append_pair("has_timestamp", "true");
        }
        if args.has_receipt {
            query.append_pair("has_receipt", "true");
        }
        if let Some(assurance_level) = args.assurance_level {
            query.append_pair("assurance_level", assurance_level.as_api_value());
        }
        if let Some(from) = normalize_optional_cli_datetime("from", args.from)? {
            query.append_pair("from", &from);
        }
        if let Some(to) = normalize_optional_cli_datetime("to", args.to)? {
            query.append_pair("to", &to);
        }
        query.append_pair("page", &args.page.max(1).to_string());
        query.append_pair("limit", &args.limit.clamp(1, 100).to_string());
    }
    Ok(url.to_string())
}

fn join_vault_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn ensure_success(response: Response, action: &str) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| "<unreadable response body>".to_string());
    let message = serde_json::from_str::<ErrorResponse>(&body)
        .map(|body| body.error)
        .unwrap_or(body);
    bail!("{action} failed ({status}): {message}");
}

fn max_payload_bytes() -> Result<usize> {
    let env_value = std::env::var("PROOFCTL_MAX_PAYLOAD_BYTES")
        .or_else(|_| std::env::var("PROOF_MAX_PAYLOAD_BYTES"));
    parse_payload_limit(env_value.ok().as_deref())
}

fn parse_payload_limit(value: Option<&str>) -> Result<usize> {
    if let Some(raw) = value {
        let parsed = raw
            .parse::<usize>()
            .with_context(|| format!("invalid payload size env value: {raw}"))?;
        if parsed == 0 {
            bail!("payload size limit must be > 0");
        }
        return Ok(parsed);
    }
    Ok(DEFAULT_MAX_PAYLOAD_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::{Integer, Mode, OctetString, Oid, encode::Values};
    use cryptographic_message_syntax::{
        Bytes, SignedDataBuilder, SignerBuilder,
        asn1::rfc3161::{MessageImprint, OID_CONTENT_TYPE_TST_INFO, TstInfo},
    };
    use flate2::{Compression, write::GzEncoder};
    use proof_layer_core::{
        Actor, ActorRole, EncryptionPolicy, EvidenceContext, LlmInteractionEvidence, Policy,
        REKOR_RFC3161_API_VERSION, REKOR_RFC3161_ENTRY_KIND, REKOR_TRANSPARENCY_KIND,
        RFC3161_TIMESTAMP_KIND, SCITT_STATEMENT_PROFILE, SCITT_TRANSPARENCY_KIND, Subject,
        TimestampError, TimestampToken, TransparencyReceipt,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_certificate::{
        CapturedX509Certificate, DigestAlgorithm, InMemorySigningKeyPair, KeyAlgorithm,
        X509CertificateBuilder,
    };

    fn sample_legacy_capture() -> CaptureInput {
        CaptureInput {
            actor: proof_layer_core::schema::v01::Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "dev".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
            },
            subject: proof_layer_core::schema::v01::Subject {
                request_id: "req-123".to_string(),
                thread_id: Some("thr-1".to_string()),
                user_ref: Some("hmac_sha256:abc".to_string()),
            },
            model: proof_layer_core::ModelInfo {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                parameters: json!({"temperature": 0.2}),
            },
            inputs: proof_layer_core::Inputs {
                messages_commitment:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                retrieval_commitment: None,
            },
            outputs: proof_layer_core::Outputs {
                assistant_text_commitment:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                tool_outputs_commitment: None,
            },
            trace: proof_layer_core::Trace {
                otel_genai_semconv_version: "1.0.0".to_string(),
                trace_commitment:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
            },
            policy: Policy {
                redactions: vec![],
                encryption: EncryptionPolicy { enabled: false },
                retention_class: None,
            },
        }
    }

    fn sample_event() -> CaptureEvent {
        CaptureEvent {
            actor: Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "dev".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
                role: ActorRole::Provider,
                organization_id: None,
            },
            subject: Subject {
                request_id: Some("req-123".to_string()),
                thread_id: Some("thr-1".to_string()),
                user_ref: Some("hmac_sha256:abc".to_string()),
                system_id: None,
                model_id: Some("anthropic:claude-sonnet-4-6".to_string()),
                deployment_id: None,
                version: Some("2026.03".to_string()),
            },
            context: EvidenceContext {
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4-6".to_string()),
                parameters: json!({"temperature": 0.2}),
                trace_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                otel_genai_semconv_version: Some("1.0.0".to_string()),
            },
            items: vec![EvidenceItem::LlmInteraction(LlmInteractionEvidence {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                parameters: json!({"temperature": 0.2}),
                input_commitment:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                retrieval_commitment: None,
                output_commitment:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                tool_outputs_commitment: None,
                token_usage: None,
                latency_ms: Some(42),
                trace_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                trace_semconv_version: Some("1.0.0".to_string()),
            })],
            policy: Policy {
                redactions: vec![],
                encryption: EncryptionPolicy { enabled: false },
                retention_class: None,
            },
        }
    }

    fn sample_bundle() -> ProofBundle {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        build_bundle(
            sample_event(),
            &[ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"hello":"world"}"#.to_vec(),
            }],
            &signing_key,
            "kid-dev-01",
            "01JNFVDSM64DJN8SNMZP63YQC8",
            parse_created_at(Some("2026-03-02T00:00:00Z")).unwrap(),
        )
        .unwrap()
    }

    struct StaticTimestampProvider {
        token: TimestampToken,
    }

    impl TimestampProvider for StaticTimestampProvider {
        fn timestamp(&self, _digest: &str) -> Result<TimestampToken, TimestampError> {
            Ok(self.token.clone())
        }
    }

    struct StaticTransparencyProvider {
        receipt: TransparencyReceipt,
    }

    impl TransparencyProvider for StaticTransparencyProvider {
        fn submit(
            &self,
            _entry: &proof_layer_core::TransparencyEntry,
        ) -> std::result::Result<TransparencyReceipt, proof_layer_core::TransparencyError> {
            Ok(self.receipt.clone())
        }
    }

    fn build_test_timestamp_token(digest: &str, provider: Option<&str>) -> TimestampToken {
        let signed_data_der = build_test_signed_data_der(digest);
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: base64ct::Base64::encode_string(&signed_data_der),
        }
    }

    fn build_test_rekor_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let body_bytes = serde_json::to_vec(&json!({
            "kind": REKOR_RFC3161_ENTRY_KIND,
            "apiVersion": REKOR_RFC3161_API_VERSION,
            "spec": {
                "tsr": {
                    "content": token.token_base64,
                }
            }
        }))
        .unwrap();
        let entry_uuid = rekor_leaf_hash_hex(&body_bytes);
        let mut log_entry = serde_json::Map::new();
        log_entry.insert(
            entry_uuid.clone(),
            json!({
                "body": base64ct::Base64::encode_string(&body_bytes),
                "integratedTime": 1772802000_i64,
                "logID": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 0,
                        "treeSize": 1,
                        "rootHash": entry_uuid,
                        "hashes": []
                    },
                    "signedEntryTimestamp": base64ct::Base64::encode_string(b"rekor-set")
                }
            }),
        );
        TransparencyReceipt {
            kind: REKOR_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: json!({
                "log_url": "https://rekor.sigstore.dev",
                "entry_uuid": entry_uuid,
                "log_entry": log_entry
            }),
        }
    }

    fn build_test_scitt_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let statement_bytes = proof_layer_core::canonicalize_value(&json!({
            "bundle_root": bundle_root,
            "profile": SCITT_STATEMENT_PROFILE,
            "timestamp": token,
        }))
        .unwrap();
        let statement_hash = sha256_prefixed(&statement_bytes);

        TransparencyReceipt {
            kind: SCITT_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: json!({
                "service_url": "https://scitt.example.test/entries",
                "entry_id": "entry-scitt-001",
                "service_id": "abababababababababababababababababababababababababababababababab",
                "registered_at": "2026-03-06T13:15:00Z",
                "statement_b64": base64ct::Base64::encode_string(&statement_bytes),
                "statement_hash": statement_hash,
                "receipt_b64": base64ct::Base64::encode_string(b"scitt-receipt"),
            }),
        }
    }

    fn rekor_leaf_hash_hex(body_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(body_bytes);
        hex::encode(hasher.finalize())
    }

    fn build_test_signed_data_der(digest: &str) -> Vec<u8> {
        let (certificate, signing_key) = build_test_certificate();
        let tst_info_der = build_test_tst_info_der(digest);

        SignedDataBuilder::default()
            .content_inline(tst_info_der)
            .content_type(Oid(Bytes::copy_from_slice(
                OID_CONTENT_TYPE_TST_INFO.as_ref(),
            )))
            .certificate(certificate.clone())
            .signer(SignerBuilder::new(&signing_key, certificate))
            .build_der()
            .unwrap()
    }

    fn build_test_tst_info_der(digest: &str) -> Vec<u8> {
        let mut imprint_hasher = DigestAlgorithm::Sha256.digester();
        imprint_hasher.update(digest.as_bytes());
        let imprint = imprint_hasher.finish();

        let tst_info = TstInfo {
            version: Integer::from(1),
            policy: Oid(Bytes::copy_from_slice(&[42, 3, 4])),
            message_imprint: MessageImprint {
                hash_algorithm: DigestAlgorithm::Sha256.into(),
                hashed_message: OctetString::new(Bytes::copy_from_slice(imprint.as_ref())),
            },
            serial_number: Integer::from(42),
            gen_time: chrono::DateTime::parse_from_rfc3339("2026-03-06T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
                .into(),
            accuracy: None,
            ordering: Some(false),
            nonce: Some(Integer::from(7)),
            tsa: None,
            extensions: None,
        };

        let mut der = Vec::new();
        tst_info
            .encode_ref()
            .write_encoded(Mode::Der, &mut der)
            .unwrap();
        der
    }

    fn build_test_certificate() -> (CapturedX509Certificate, InMemorySigningKeyPair) {
        let mut builder = X509CertificateBuilder::default();
        builder
            .subject()
            .append_common_name_utf8_string("proof-layer-test-tsa")
            .unwrap();
        builder.subject().append_country_utf8_string("GB").unwrap();
        builder
            .create_with_random_keypair(KeyAlgorithm::Ed25519)
            .unwrap()
    }

    #[test]
    fn artefact_arg_parser_accepts_name_and_path() {
        let parsed = parse_artefact_arg("prompt.json=./prompt.json").unwrap();
        assert_eq!(parsed.name, "prompt.json");
        assert_eq!(parsed.path, PathBuf::from("./prompt.json"));
    }

    #[test]
    fn artefact_name_rejects_traversal() {
        let err = validate_artefact_name("../secret.txt").unwrap_err();
        assert!(err.to_string().contains("invalid path traversal"));
    }

    #[test]
    fn artefact_name_rejects_empty() {
        let err = validate_artefact_name("  ").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_payload_limit_defaults() {
        let limit = parse_payload_limit(None).unwrap();
        assert_eq!(limit, DEFAULT_MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn parse_payload_limit_rejects_zero() {
        let err = parse_payload_limit(Some("0")).unwrap_err();
        assert!(err.to_string().contains("must be > 0"));
    }

    #[test]
    fn parse_created_at_accepts_rfc3339() {
        let parsed = parse_created_at(Some("2026-03-02T00:00:00Z")).unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-03-02T00:00:00+00:00");
    }

    #[test]
    fn parse_created_at_rejects_invalid_value() {
        let err = parse_created_at(Some("not-a-date")).unwrap_err();
        assert!(err.to_string().contains("RFC3339"));
    }

    #[test]
    fn pack_type_maps_to_vault_api_value() {
        assert_eq!(PackTypeArg::AnnexIv.as_api_value(), "annex_iv");
        assert_eq!(PackTypeArg::RuntimeLogs.as_api_value(), "runtime_logs");
    }

    #[test]
    fn pack_datetime_normalization_rejects_invalid_value() {
        let err = normalize_optional_cli_datetime("from", Some("not-a-date")).unwrap_err();
        assert!(err.to_string().contains("RFC3339"));
    }

    #[test]
    fn pack_command_accepts_disclosure_policy_arg() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "pack",
            "--type",
            "annex-iv",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--out",
            "./out.pkg",
            "--bundle-format",
            "disclosure",
            "--disclosure-policy",
            "annex_iv_redacted",
        ])
        .unwrap();

        match cli.command {
            Commands::Pack {
                disclosure_policy,
                bundle_format,
                ..
            } => {
                assert_eq!(bundle_format, PackBundleFormatArg::Disclosure);
                assert_eq!(disclosure_policy.as_deref(), Some("annex_iv_redacted"));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn join_vault_url_strips_trailing_slash() {
        let joined = join_vault_url("http://127.0.0.1:8080/", "/v1/packs");
        assert_eq!(joined, "http://127.0.0.1:8080/v1/packs");
    }

    #[test]
    fn build_vault_bundles_query_url_encodes_filters() {
        let url = build_vault_bundles_query_url(&VaultQueryCommandInput {
            vault_url: "http://127.0.0.1:8080/",
            system_id: Some("system-123"),
            role: Some(ActorRoleArg::Provider),
            item_type: Some(EvidenceTypeArg::LlmInteraction),
            has_timestamp: true,
            has_receipt: false,
            assurance_level: Some(AssuranceLevelArg::Timestamped),
            from: Some("2026-03-01T00:00:00Z"),
            to: Some("2026-03-06T00:00:00Z"),
            page: 2,
            limit: 25,
            format: OutputFormat::Human,
        })
        .unwrap();

        assert!(url.starts_with("http://127.0.0.1:8080/v1/bundles?"));
        assert!(url.contains("system_id=system-123"));
        assert!(url.contains("role=provider"));
        assert!(url.contains("type=llm_interaction"));
        assert!(url.contains("has_timestamp=true"));
        assert!(url.contains("assurance_level=timestamped"));
        assert!(url.contains("page=2"));
        assert!(url.contains("limit=25"));
    }

    #[test]
    fn build_vault_path_url_encodes_path_segments() {
        let url = build_vault_path_url(
            "http://127.0.0.1:8080",
            &["v1", "systems", "a/b", "summary"],
        )
        .unwrap();
        assert_eq!(url, "http://127.0.0.1:8080/v1/systems/a%2Fb/summary");
    }

    #[test]
    fn create_overrides_apply_system_and_retention() {
        let event = apply_create_overrides(
            materialize_capture_event(SealableCaptureInput::Legacy(sample_legacy_capture())),
            &CreateOverrides {
                evidence_type: Some(EvidenceTypeArg::LlmInteraction),
                retention_class: Some("runtime_logs".to_string()),
                system_id: Some("system-123".to_string()),
            },
        )
        .unwrap();

        assert_eq!(event.subject.system_id.as_deref(), Some("system-123"));
        assert_eq!(
            event.policy.retention_class.as_deref(),
            Some("runtime_logs")
        );
        assert!(matches!(
            event.items.first(),
            Some(EvidenceItem::LlmInteraction(_))
        ));
    }

    #[test]
    fn create_overrides_reject_missing_evidence_type() {
        let mut event = sample_event();
        event.items = vec![EvidenceItem::TechnicalDoc(
            proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "doc-1".to_string(),
                section: None,
                commitment: None,
            },
        )];

        let err = apply_create_overrides(
            event,
            &CreateOverrides {
                evidence_type: Some(EvidenceTypeArg::LlmInteraction),
                retention_class: None,
                system_id: None,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not contain requested evidence type llm_interaction")
        );
    }

    #[test]
    fn merkle_inspect_view_includes_header_leaf() {
        let bundle = sample_bundle();
        let view = build_merkle_inspect_view(&bundle).unwrap();

        assert_eq!(view.root, bundle.integrity.bundle_root);
        assert_eq!(view.leaves[0].label, "header_digest");
        assert_eq!(view.leaves[0].digest, bundle.integrity.header_digest);
        assert_eq!(view.leaves[1].label, "item:0");
        assert_eq!(
            view.leaves.len(),
            1 + bundle.items.len() + bundle.artefacts.len()
        );
    }

    #[test]
    fn parse_index_list_accepts_comma_separated_indices() {
        let indices = parse_index_list("0, 2,5").unwrap();
        assert_eq!(indices, vec![0, 2, 5]);
    }

    #[test]
    fn disclose_command_produces_verifiable_redacted_package() {
        let bundle = sample_bundle();
        let artefact_bytes = br#"{"hello":"world"}"#.to_vec();

        let mut package_files = BTreeMap::<String, Vec<u8>>::new();
        package_files.insert(
            "proof_bundle.json".to_string(),
            serde_json::to_vec_pretty(&bundle).unwrap(),
        );
        package_files.insert(
            "proof_bundle.canonical.json".to_string(),
            bundle.canonical_header_bytes().unwrap(),
        );
        package_files.insert(
            "proof_bundle.sig".to_string(),
            bundle.integrity.signature.value.as_bytes().to_vec(),
        );
        package_files.insert("artefacts/prompt.json".to_string(), artefact_bytes);

        let manifest = Manifest {
            files: package_files
                .iter()
                .map(|(name, bytes)| ManifestEntry {
                    name: name.clone(),
                    digest: sha256_prefixed(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
        };
        package_files.insert(
            "manifest.json".to_string(),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );

        let tmp_dir = std::env::temp_dir().join(format!("proofctl-disclose-test-{}", Ulid::new()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let bundle_path = tmp_dir.join("bundle.pkg");
        let disclosure_path = tmp_dir.join("bundle.disclosure.pkg");

        write_bundle_package(&bundle_path, &package_files).unwrap();
        cmd_disclose(&bundle_path, "0", None, &disclosure_path).unwrap();

        let package = read_package(&disclosure_path).unwrap();
        assert_eq!(package.format, DISCLOSURE_PACKAGE_FORMAT);
        let redacted = parse_redacted_bundle_file(&package.files).unwrap();
        assert_eq!(redacted.disclosed_items.len(), 1);
        assert!(redacted.disclosed_artefacts.is_empty());
        assert_eq!(redacted.disclosed_items[0].index, 0);

        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let report =
            verify_disclosure_package(&package.files, &verifying_key, false, false, None, None)
                .unwrap();
        assert_eq!(report.package_kind, "disclosure");
        assert_eq!(report.disclosure_proof_ok, Some(true));
        assert!(report.canonicalization_ok);
        assert!(report.signature_ok);
        assert!(report.manifest_ok);
        assert_eq!(report.message, "VALID");

        fs::remove_dir_all(&tmp_dir).unwrap();
    }

    #[test]
    fn disclose_roundtrip_can_include_selected_artefact_bytes() {
        let bundle = sample_bundle();
        let artefact_bytes = br#"{"hello":"world"}"#.to_vec();
        let mut package_files = BTreeMap::<String, Vec<u8>>::new();
        package_files.insert(
            "proof_bundle.json".to_string(),
            serde_json::to_vec_pretty(&bundle).unwrap(),
        );
        package_files.insert(
            "proof_bundle.canonical.json".to_string(),
            bundle.canonical_header_bytes().unwrap(),
        );
        package_files.insert(
            "proof_bundle.sig".to_string(),
            bundle.integrity.signature.value.as_bytes().to_vec(),
        );
        package_files.insert("artefacts/prompt.json".to_string(), artefact_bytes.clone());

        let manifest = Manifest {
            files: package_files
                .iter()
                .map(|(name, bytes)| ManifestEntry {
                    name: name.clone(),
                    digest: sha256_prefixed(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
        };
        package_files.insert(
            "manifest.json".to_string(),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );

        let tmp_dir =
            std::env::temp_dir().join(format!("proofctl-disclose-artefact-{}", Ulid::new()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let bundle_path = tmp_dir.join("bundle.pkg");
        let disclosure_path = tmp_dir.join("bundle.disclosure.pkg");

        write_bundle_package(&bundle_path, &package_files).unwrap();
        cmd_disclose(&bundle_path, "0", Some("0"), &disclosure_path).unwrap();

        let package = read_package(&disclosure_path).unwrap();
        assert_eq!(package.format, DISCLOSURE_PACKAGE_FORMAT);
        assert_eq!(
            package
                .files
                .get("artefacts/prompt.json")
                .map(Vec::as_slice),
            Some(artefact_bytes.as_slice())
        );
        let redacted = parse_redacted_bundle_file(&package.files).unwrap();
        assert_eq!(redacted.disclosed_items.len(), 1);
        assert_eq!(redacted.disclosed_artefacts.len(), 1);
        assert_eq!(redacted.disclosed_artefacts[0].meta.name, "prompt.json");

        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let report =
            verify_disclosure_package(&package.files, &verifying_key, false, false, None, None)
                .unwrap();
        assert_eq!(report.package_kind, "disclosure");
        assert!(report.manifest_ok);
        assert!(report.signature_ok);
        assert_eq!(report.artefacts_verified, 1);
        assert_eq!(report.message, "VALID");

        fs::remove_dir_all(&tmp_dir).unwrap();
    }

    #[test]
    fn optional_check_reports_missing_invalid_and_valid_states() {
        let missing = evaluate_timestamp_check(&sample_bundle(), true, None);
        assert_eq!(missing.state, OptionalCheckState::Missing);

        let mut bundle = sample_bundle();
        bundle.timestamp = Some(build_test_timestamp_token(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some("test-tsa"),
        ));
        let invalid = evaluate_timestamp_check(&bundle, true, None);
        assert_eq!(invalid.state, OptionalCheckState::Invalid);

        let missing_receipt = evaluate_receipt_check(&bundle, true, None);
        assert_eq!(missing_receipt.state, OptionalCheckState::Missing);

        bundle.receipt = Some(build_test_rekor_receipt(
            &bundle.integrity.bundle_root,
            Some("rekor"),
        ));
        let valid_receipt = evaluate_receipt_check(&bundle, true, None);
        assert_eq!(valid_receipt.state, OptionalCheckState::Valid);

        bundle.receipt = Some(build_test_rekor_receipt(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some("rekor"),
        ));
        let invalid_receipt = evaluate_receipt_check(&bundle, true, None);
        assert_eq!(invalid_receipt.state, OptionalCheckState::Invalid);
    }

    #[test]
    fn attach_timestamp_to_bundle_sets_verifiable_token() {
        let mut bundle = sample_bundle();
        let provider = StaticTimestampProvider {
            token: build_test_timestamp_token(&bundle.integrity.bundle_root, Some("test-tsa")),
        };

        let verification = attach_timestamp_to_bundle(&mut bundle, &provider, None).unwrap();
        assert_eq!(verification.provider.as_deref(), Some("test-tsa"));
        assert!(bundle.timestamp.is_some());

        let timestamp_report = evaluate_timestamp_check(&bundle, true, None);
        assert_eq!(timestamp_report.state, OptionalCheckState::Valid);
        assert!(
            timestamp_report
                .message
                .contains("RFC 3161 token structurally valid")
        );
    }

    #[test]
    fn attach_receipt_to_bundle_sets_verifiable_receipt() {
        let mut bundle = sample_bundle();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        let provider = StaticTransparencyProvider {
            receipt: build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor")),
        };

        let verification = attach_receipt_to_bundle(&mut bundle, &provider, None).unwrap();
        assert_eq!(verification.provider.as_deref(), Some("rekor"));
        assert_eq!(verification.log_index, 0);
        assert!(bundle.receipt.is_some());

        let receipt_report = evaluate_receipt_check(&bundle, true, None);
        assert_eq!(receipt_report.state, OptionalCheckState::Valid);
        assert!(
            receipt_report
                .message
                .contains("Rekor receipt structurally valid")
        );
    }

    #[test]
    fn evaluate_receipt_check_reports_scitt_receipts() {
        let mut bundle = sample_bundle();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        bundle.receipt = Some(build_test_scitt_receipt(
            &bundle.integrity.bundle_root,
            Some("scitt"),
        ));

        let receipt_report = evaluate_receipt_check(&bundle, true, None);
        assert_eq!(receipt_report.state, OptionalCheckState::Valid);
        assert!(
            receipt_report
                .message
                .contains("SCITT receipt structurally valid")
        );
    }

    #[test]
    fn verify_manifest_rejects_unlisted_file() {
        let bundle_bytes = br#"{"bundle":"ok"}"#.to_vec();
        let signature_bytes = br#"sig"#.to_vec();

        let manifest = Manifest {
            files: vec![ManifestEntry {
                name: "proof_bundle.json".to_string(),
                digest: sha256_prefixed(&bundle_bytes),
                size: bundle_bytes.len() as u64,
            }],
        };

        let mut files = BTreeMap::new();
        files.insert("proof_bundle.json".to_string(), bundle_bytes);
        files.insert("proof_bundle.sig".to_string(), signature_bytes);
        files.insert(
            "manifest.json".to_string(),
            serde_json::to_vec(&manifest).unwrap(),
        );

        assert!(!verify_manifest(&files).unwrap());
    }

    #[test]
    fn read_bundle_package_rejects_duplicate_file_entries() {
        let package = BundlePackage {
            format: "pl-bundle-pkg-v1".to_string(),
            files: vec![
                PackagedFile {
                    name: "proof_bundle.json".to_string(),
                    data_base64: base64ct::Base64::encode_string(br#"{}"#),
                },
                PackagedFile {
                    name: "proof_bundle.json".to_string(),
                    data_base64: base64ct::Base64::encode_string(br#"{}"#),
                },
            ],
        };

        let package_bytes = serde_json::to_vec(&package).unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("proofctl-duplicate-members-{nonce}.pkg"));
        {
            let file = fs::File::create(&path).unwrap();
            let mut encoder = GzEncoder::new(file, Compression::default());
            encoder.write_all(&package_bytes).unwrap();
            encoder.finish().unwrap();
        }

        let err = read_bundle_package(&path).unwrap_err();
        assert!(err.to_string().contains("duplicate package file entry"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn package_member_rejects_empty_artefact_name() {
        let err = validate_package_member_name("artefacts/").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }
}
