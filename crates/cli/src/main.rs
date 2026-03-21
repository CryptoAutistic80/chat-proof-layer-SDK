use anyhow::{Context, Result, anyhow, bail};
use base64ct::Encoding;
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ActorRole, ArtefactInput, CaptureEvent, CaptureInput, DisclosureError, EvidenceItem,
    LEGACY_BUNDLE_ROOT_ALGORITHM, ProofBundle, ReceiptVerification, RedactedBundle,
    RekorTransparencyProvider, Rfc3161HttpTimestampProvider, SCITT_TRANSPARENCY_KIND,
    ScittTransparencyProvider, TimestampAssuranceProfile, TimestampProvider, TimestampToken,
    TimestampTrustPolicy, TransparencyProvider, TransparencyReceipt, TransparencyTrustPolicy,
    anchor_bundle as anchor_bundle_receipt, build_bundle, build_inclusion_proof,
    capture_input_v01_to_event, decode_backup_encryption_key, decode_private_key_pem,
    decode_public_key_pem, decrypt_backup_archive, encode_private_key_pem, encode_public_key_pem,
    redact_bundle, redact_bundle_with_field_redactions, sha256_prefixed, timestamp_digest,
    validate_bundle_integrity_fields, validate_timestamp_trust_policy, verify_receipt,
    verify_receipt_with_policy, verify_redacted_bundle, verify_timestamp,
    verify_timestamp_with_policy,
};
use reqwest::{
    Url,
    blocking::{Client, RequestBuilder, Response},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use tar::Archive as TarArchive;
use tracing::info;
use ulid::Ulid;

const BUNDLE_PACKAGE_FORMAT: &str = "pl-bundle-pkg-v1";
const DISCLOSURE_PACKAGE_FORMAT: &str = "pl-bundle-disclosure-pkg-v1";
const VAULT_BACKUP_FORMAT: &str = "pl-vault-backup-v1";
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
        #[arg(long = "disclosure-template-profile")]
        disclosure_template_profile: Option<DisclosurePolicyTemplateArg>,
        #[arg(long = "disclosure-template-name")]
        disclosure_template_name: Option<String>,
        #[arg(long = "disclosure-group")]
        disclosure_redaction_group: Vec<DisclosureRedactionGroupArg>,
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
    role: Option<ActorRoleArg>,
    #[arg(long)]
    intended_use: Option<String>,
    #[arg(long)]
    prohibited_practice_screening: Option<String>,
    #[arg(long)]
    risk_tier: Option<String>,
    #[arg(long)]
    high_risk_domain: Option<String>,
    #[arg(long)]
    gpai_status: Option<String>,
    #[arg(long)]
    systemic_risk: Option<bool>,
    #[arg(long)]
    fria_required: Option<bool>,
    #[arg(long)]
    deployment_context: Option<String>,
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
    #[arg(long = "redact-field")]
    redact_field: Vec<String>,
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
    /// Fetch the Prometheus metrics surface exposed by the vault.
    Metrics {
        #[arg(long)]
        vault_url: String,
    },
    /// Export a vault backup archive for SQLite-based deployments.
    Backup {
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore a previously exported vault backup archive into a fresh local directory.
    Restore {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "out-dir")]
        out_dir: PathBuf,
        #[arg(long = "backup-key")]
        backup_key: Option<PathBuf>,
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
        #[arg(long = "disclosure-template-profile")]
        disclosure_template_profile: Option<DisclosurePolicyTemplateArg>,
        #[arg(long = "disclosure-template-name")]
        disclosure_template_name: Option<String>,
        #[arg(long = "disclosure-group")]
        disclosure_redaction_group: Vec<DisclosureRedactionGroupArg>,
    },
    /// Preview how a named or inline disclosure policy would redact a stored bundle.
    DisclosurePreview {
        #[arg(long)]
        vault_url: String,
        #[arg(long)]
        bundle_id: String,
        #[arg(long = "type")]
        pack_type: Option<PackTypeArg>,
        #[arg(long = "disclosure-policy")]
        disclosure_policy: Option<String>,
        #[arg(long = "disclosure-policy-file")]
        disclosure_policy_file: Option<PathBuf>,
        #[arg(long = "disclosure-template-profile")]
        disclosure_template_profile: Option<DisclosurePolicyTemplateArg>,
        #[arg(long = "disclosure-template-name")]
        disclosure_template_name: Option<String>,
        #[arg(long = "disclosure-group")]
        disclosure_redaction_group: Vec<DisclosureRedactionGroupArg>,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// List built-in disclosure policy templates and reusable redaction groups from the vault.
    DisclosureTemplates {
        #[arg(long)]
        vault_url: String,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// Generate a starter disclosure policy JSON template locally or via the vault.
    DisclosureTemplate {
        #[arg(long)]
        vault_url: Option<String>,
        #[arg(long)]
        profile: DisclosurePolicyTemplateArg,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "group")]
        redaction_group: Vec<DisclosureRedactionGroupArg>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
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
    InstructionsForUse,
    QmsRecord,
    FundamentalRightsAssessment,
    StandardsAlignment,
    PostMarketMonitoring,
    CorrectiveAction,
    AuthorityNotification,
    AuthoritySubmission,
    ReportingDeadline,
    RegulatorCorrespondence,
    ModelEvaluation,
    AdversarialTest,
    TrainingProvenance,
    DownstreamDocumentation,
    CopyrightPolicy,
    TrainingSummary,
    ConformityAssessment,
    Declaration,
    Registration,
    LiteracyAttestation,
    IncidentReport,
    ComputeMetrics,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum PackTypeArg {
    AnnexIv,
    AnnexXi,
    AnnexXii,
    FundamentalRights,
    ProviderGovernance,
    PostMarketMonitoring,
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum DisclosurePolicyTemplateArg {
    RegulatorMinimum,
    AnnexIvRedacted,
    IncidentSummary,
    RuntimeMinimum,
    PrivacyReview,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum DisclosureRedactionGroupArg {
    Commitments,
    Metadata,
    Parameters,
    OperationalMetrics,
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
    Importer,
    Distributor,
    AuthorizedRepresentative,
    GpaiProvider,
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
    role: Option<ActorRoleArg>,
    intended_use: Option<String>,
    prohibited_practice_screening: Option<String>,
    risk_tier: Option<String>,
    high_risk_domain: Option<String>,
    gpai_status: Option<String>,
    systemic_risk: Option<bool>,
    fria_required: Option<bool>,
    deployment_context: Option<String>,
}

impl CreateOverrides {
    fn has_compliance_profile_overrides(&self) -> bool {
        self.intended_use.is_some()
            || self.prohibited_practice_screening.is_some()
            || self.risk_tier.is_some()
            || self.high_risk_domain.is_some()
            || self.gpai_status.is_some()
            || self.systemic_risk.is_some()
            || self.fria_required.is_some()
            || self.deployment_context.is_some()
    }
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
    disclosure_template_profile: Option<DisclosurePolicyTemplateArg>,
    disclosure_template_name: Option<&'a str>,
    disclosure_redaction_groups: &'a [DisclosureRedactionGroupArg],
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

struct DisclosureTemplateCliInput<'a> {
    profile: Option<DisclosurePolicyTemplateArg>,
    name: Option<&'a str>,
    groups: &'a [DisclosureRedactionGroupArg],
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
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_template: Option<DisclosureTemplateRenderRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DisclosurePolicyConfig {
    name: String,
    #[serde(default)]
    allowed_item_types: Vec<String>,
    #[serde(default)]
    excluded_item_types: Vec<String>,
    #[serde(default)]
    allowed_obligation_refs: Vec<String>,
    #[serde(default)]
    excluded_obligation_refs: Vec<String>,
    #[serde(default)]
    include_artefact_metadata: bool,
    #[serde(default)]
    include_artefact_bytes: bool,
    #[serde(default)]
    artefact_names: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    redacted_fields_by_item_type: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize)]
struct DisclosurePreviewRequest {
    bundle_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<DisclosurePolicyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_template: Option<DisclosureTemplateRenderRequest>,
}

#[derive(Debug, Serialize)]
struct DisclosureTemplateRenderRequest {
    profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redaction_groups: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    redacted_fields_by_item_type: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DisclosureTemplateCatalogResponse {
    templates: Vec<DisclosureTemplateResponse>,
    redaction_groups: Vec<DisclosureRedactionGroupInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DisclosureTemplateResponse {
    profile: String,
    description: String,
    #[serde(default)]
    default_redaction_groups: Vec<String>,
    policy: DisclosurePolicyConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DisclosureRedactionGroupInfo {
    name: String,
    description: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct DisclosurePreviewResponse {
    bundle_id: String,
    policy_name: String,
    pack_type: Option<String>,
    #[serde(default)]
    candidate_item_indices: Vec<usize>,
    #[serde(default)]
    disclosed_item_indices: Vec<usize>,
    #[serde(default)]
    disclosed_item_types: Vec<String>,
    #[serde(default)]
    disclosed_item_obligation_refs: Vec<String>,
    #[serde(default)]
    disclosed_item_field_redactions: BTreeMap<usize, Vec<String>>,
    #[serde(default)]
    disclosed_artefact_indices: Vec<usize>,
    #[serde(default)]
    disclosed_artefact_names: Vec<String>,
    #[serde(default)]
    disclosed_artefact_bytes_included: bool,
}

const ALL_DISCLOSURE_ITEM_TYPES: &[&str] = &[
    "llm_interaction",
    "tool_call",
    "retrieval",
    "human_oversight",
    "policy_decision",
    "risk_assessment",
    "data_governance",
    "technical_doc",
    "instructions_for_use",
    "qms_record",
    "fundamental_rights_assessment",
    "standards_alignment",
    "post_market_monitoring",
    "corrective_action",
    "authority_notification",
    "authority_submission",
    "reporting_deadline",
    "regulator_correspondence",
    "model_evaluation",
    "adversarial_test",
    "training_provenance",
    "downstream_documentation",
    "copyright_policy",
    "training_summary",
    "conformity_assessment",
    "declaration",
    "registration",
    "literacy_attestation",
    "incident_report",
    "compute_metrics",
];

fn annex_iv_default_redactions() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        (
            "data_governance".to_string(),
            vec![
                "/bias_metrics".to_string(),
                "/personal_data_categories".to_string(),
                "/safeguards".to_string(),
            ],
        ),
        (
            "instructions_for_use".to_string(),
            vec![
                "/accuracy_metrics".to_string(),
                "/compute_requirements".to_string(),
                "/log_management_guidance".to_string(),
            ],
        ),
    ])
}

fn incident_summary_default_redactions() -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([
        (
            "incident_report".to_string(),
            vec!["/root_cause_summary".to_string()],
        ),
        (
            "adversarial_test".to_string(),
            vec![
                "/threat_model".to_string(),
                "/affected_components".to_string(),
            ],
        ),
    ])
}

fn disclosure_policy_template_name(profile: DisclosurePolicyTemplateArg) -> &'static str {
    match profile {
        DisclosurePolicyTemplateArg::RegulatorMinimum => "regulator_minimum",
        DisclosurePolicyTemplateArg::AnnexIvRedacted => "annex_iv_redacted",
        DisclosurePolicyTemplateArg::IncidentSummary => "incident_summary",
        DisclosurePolicyTemplateArg::RuntimeMinimum => "runtime_minimum",
        DisclosurePolicyTemplateArg::PrivacyReview => "privacy_review",
    }
}

fn build_cli_disclosure_template_request(
    input: DisclosureTemplateCliInput<'_>,
) -> Result<Option<DisclosureTemplateRenderRequest>> {
    if input.profile.is_none() {
        if input.name.is_some() || !input.groups.is_empty() {
            bail!(
                "--disclosure-template-name and --disclosure-group require --disclosure-template-profile"
            );
        }
        return Ok(None);
    }

    Ok(Some(DisclosureTemplateRenderRequest {
        profile: disclosure_policy_template_name(input.profile.expect("checked above")).to_string(),
        name: normalize_optional_cli_text("disclosure_template_name", input.name)?,
        redaction_groups: input
            .groups
            .iter()
            .map(|group| group.to_possible_value().unwrap().get_name().to_string())
            .collect(),
        redacted_fields_by_item_type: BTreeMap::new(),
    }))
}

fn disclosure_policy_template(
    profile: DisclosurePolicyTemplateArg,
    name: Option<&str>,
    groups: &[DisclosureRedactionGroupArg],
) -> DisclosurePolicyConfig {
    let mut policy = match profile {
        DisclosurePolicyTemplateArg::RegulatorMinimum => DisclosurePolicyConfig {
            name: disclosure_policy_template_name(profile).to_string(),
            allowed_item_types: Vec::new(),
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: false,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: BTreeMap::new(),
        },
        DisclosurePolicyTemplateArg::AnnexIvRedacted => DisclosurePolicyConfig {
            name: disclosure_policy_template_name(profile).to_string(),
            allowed_item_types: vec![
                "technical_doc".to_string(),
                "risk_assessment".to_string(),
                "data_governance".to_string(),
                "instructions_for_use".to_string(),
                "human_oversight".to_string(),
            ],
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: true,
            include_artefact_bytes: true,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: annex_iv_default_redactions(),
        },
        DisclosurePolicyTemplateArg::IncidentSummary => DisclosurePolicyConfig {
            name: disclosure_policy_template_name(profile).to_string(),
            allowed_item_types: vec![
                "incident_report".to_string(),
                "authority_notification".to_string(),
                "authority_submission".to_string(),
                "reporting_deadline".to_string(),
                "regulator_correspondence".to_string(),
                "risk_assessment".to_string(),
                "policy_decision".to_string(),
                "human_oversight".to_string(),
                "adversarial_test".to_string(),
            ],
            excluded_item_types: vec![
                "llm_interaction".to_string(),
                "retrieval".to_string(),
                "tool_call".to_string(),
            ],
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: false,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: incident_summary_default_redactions(),
        },
        DisclosurePolicyTemplateArg::RuntimeMinimum => DisclosurePolicyConfig {
            name: disclosure_policy_template_name(profile).to_string(),
            allowed_item_types: vec![
                "llm_interaction".to_string(),
                "tool_call".to_string(),
                "retrieval".to_string(),
                "policy_decision".to_string(),
                "human_oversight".to_string(),
            ],
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: false,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: BTreeMap::new(),
        },
        DisclosurePolicyTemplateArg::PrivacyReview => DisclosurePolicyConfig {
            name: disclosure_policy_template_name(profile).to_string(),
            allowed_item_types: vec![
                "llm_interaction".to_string(),
                "risk_assessment".to_string(),
                "incident_report".to_string(),
                "policy_decision".to_string(),
                "human_oversight".to_string(),
            ],
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: false,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: BTreeMap::new(),
        },
    };

    if let Some(name) = name {
        policy.name = name.to_string();
    }

    let mut all_groups = match profile {
        DisclosurePolicyTemplateArg::RuntimeMinimum => vec![
            DisclosureRedactionGroupArg::Commitments,
            DisclosureRedactionGroupArg::Parameters,
            DisclosureRedactionGroupArg::OperationalMetrics,
        ],
        DisclosurePolicyTemplateArg::PrivacyReview => vec![
            DisclosureRedactionGroupArg::Commitments,
            DisclosureRedactionGroupArg::Metadata,
            DisclosureRedactionGroupArg::Parameters,
            DisclosureRedactionGroupArg::OperationalMetrics,
        ],
        _ => Vec::new(),
    };
    all_groups.extend_from_slice(groups);
    apply_disclosure_redaction_groups(&mut policy, &all_groups);

    policy
}

fn apply_disclosure_redaction_groups(
    policy: &mut DisclosurePolicyConfig,
    groups: &[DisclosureRedactionGroupArg],
) {
    let item_types = if policy.allowed_item_types.is_empty() {
        ALL_DISCLOSURE_ITEM_TYPES
            .iter()
            .map(|item_type| (*item_type).to_string())
            .collect::<Vec<_>>()
    } else {
        policy.allowed_item_types.clone()
    };

    for item_type in item_types {
        for group in groups {
            for selector in disclosure_redaction_group_selectors(&item_type, *group) {
                let bucket = policy
                    .redacted_fields_by_item_type
                    .entry(item_type.clone())
                    .or_default();
                if !bucket.contains(&selector.to_string()) {
                    bucket.push(selector.to_string());
                }
            }
        }
    }
}

fn disclosure_redaction_group_selectors(
    item_type: &str,
    group: DisclosureRedactionGroupArg,
) -> &'static [&'static str] {
    match group {
        DisclosureRedactionGroupArg::Commitments => match item_type {
            "llm_interaction" => &[
                "input_commitment",
                "retrieval_commitment",
                "output_commitment",
                "tool_outputs_commitment",
                "trace_commitment",
            ],
            "tool_call" => &["input_commitment", "output_commitment"],
            "retrieval" => &["result_commitment", "query_commitment"],
            "human_oversight" => &["notes_commitment"],
            "policy_decision" => &["rationale_commitment"],
            "technical_doc" => &["commitment"],
            "instructions_for_use" => &["commitment"],
            "qms_record" => &["record_commitment"],
            "fundamental_rights_assessment" => &["report_commitment"],
            "standards_alignment" => &["mapping_commitment"],
            "post_market_monitoring" => &["report_commitment"],
            "corrective_action" => &["record_commitment"],
            "authority_notification" => &["report_commitment"],
            "authority_submission" => &["document_commitment"],
            "reporting_deadline" => &[],
            "regulator_correspondence" => &["message_commitment"],
            "model_evaluation" => &["report_commitment"],
            "adversarial_test" => &["report_commitment"],
            "training_provenance" => &["record_commitment"],
            "downstream_documentation" => &["commitment"],
            "copyright_policy" => &["commitment"],
            "training_summary" => &["commitment"],
            "conformity_assessment" => &["report_commitment"],
            "declaration" => &["document_commitment"],
            "registration" => &["receipt_commitment"],
            "literacy_attestation" => &["attestation_commitment"],
            "incident_report" => &["report_commitment"],
            "compute_metrics" => &[],
            _ => &[],
        },
        DisclosureRedactionGroupArg::Metadata => match item_type {
            "tool_call"
            | "retrieval"
            | "policy_decision"
            | "risk_assessment"
            | "data_governance"
            | "instructions_for_use"
            | "qms_record"
            | "fundamental_rights_assessment"
            | "standards_alignment"
            | "post_market_monitoring"
            | "corrective_action"
            | "authority_notification"
            | "authority_submission"
            | "reporting_deadline"
            | "regulator_correspondence"
            | "model_evaluation"
            | "adversarial_test"
            | "training_provenance"
            | "downstream_documentation"
            | "copyright_policy"
            | "training_summary"
            | "conformity_assessment"
            | "declaration"
            | "literacy_attestation"
            | "incident_report"
            | "compute_metrics" => &["/metadata"],
            _ => &[],
        },
        DisclosureRedactionGroupArg::Parameters => match item_type {
            "llm_interaction" => &["/parameters"],
            _ => &[],
        },
        DisclosureRedactionGroupArg::OperationalMetrics => match item_type {
            "llm_interaction" => &["/token_usage", "/latency_ms", "/trace_semconv_version"],
            _ => &[],
        },
    }
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
struct VaultBackupManifest {
    format: String,
    backup_id: String,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultConfigResponse {
    service: VaultServiceConfigView,
    signing: VaultSigningConfigView,
    storage: VaultStorageConfigView,
    retention: VaultRetentionConfigView,
    backup: VaultBackupConfigView,
    timestamp: VaultTimestampConfig,
    transparency: VaultTransparencyConfig,
    auth: VaultAuthConfigView,
    audit: VaultAuditConfigView,
    tenant: VaultTenantConfigView,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultServiceConfigView {
    addr: String,
    max_payload_bytes: usize,
    tls_enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultAuthConfigView {
    enabled: bool,
    scheme: String,
    principal_labels: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultTenantConfigView {
    organization_id: Option<String>,
    enforced: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultBackupConfigView {
    enabled: bool,
    directory: String,
    interval_hours: i64,
    retention_count: usize,
    encryption: VaultBackupEncryptionConfigView,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultBackupEncryptionConfigView {
    enabled: bool,
    algorithm: Option<String>,
    key_id: Option<String>,
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
    tls_enabled: bool,
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
    backup_enabled: bool,
    backup_directory: String,
    backup_interval_hours: i64,
    backup_retention_count: usize,
    backup_encryption_enabled: bool,
    backup_encryption_algorithm: Option<String>,
    backup_encryption_key_id: Option<String>,
    timestamp_enabled: bool,
    timestamp_provider: String,
    timestamp_assurance: Option<String>,
    timestamp_trust_anchor_count: usize,
    timestamp_ocsp_url_count: usize,
    timestamp_policy_oid_count: usize,
    transparency_enabled: bool,
    transparency_provider: String,
    auth_enabled: bool,
    auth_scheme: String,
    auth_principal_count: usize,
    tenant_organization_id: Option<String>,
    tenant_enforced: bool,
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
                | (
                    Self::InstructionsForUse,
                    EvidenceItem::InstructionsForUse(_)
                )
                | (Self::QmsRecord, EvidenceItem::QmsRecord(_))
                | (
                    Self::FundamentalRightsAssessment,
                    EvidenceItem::FundamentalRightsAssessment(_)
                )
                | (
                    Self::StandardsAlignment,
                    EvidenceItem::StandardsAlignment(_)
                )
                | (
                    Self::PostMarketMonitoring,
                    EvidenceItem::PostMarketMonitoring(_)
                )
                | (Self::CorrectiveAction, EvidenceItem::CorrectiveAction(_))
                | (
                    Self::AuthorityNotification,
                    EvidenceItem::AuthorityNotification(_)
                )
                | (
                    Self::AuthoritySubmission,
                    EvidenceItem::AuthoritySubmission(_)
                )
                | (Self::ReportingDeadline, EvidenceItem::ReportingDeadline(_))
                | (
                    Self::RegulatorCorrespondence,
                    EvidenceItem::RegulatorCorrespondence(_)
                )
                | (Self::ModelEvaluation, EvidenceItem::ModelEvaluation(_))
                | (Self::AdversarialTest, EvidenceItem::AdversarialTest(_))
                | (
                    Self::TrainingProvenance,
                    EvidenceItem::TrainingProvenance(_)
                )
                | (
                    Self::DownstreamDocumentation,
                    EvidenceItem::DownstreamDocumentation(_)
                )
                | (Self::CopyrightPolicy, EvidenceItem::CopyrightPolicy(_))
                | (Self::TrainingSummary, EvidenceItem::TrainingSummary(_))
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
                | (Self::ComputeMetrics, EvidenceItem::ComputeMetrics(_))
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
            Self::InstructionsForUse => "instructions_for_use",
            Self::QmsRecord => "qms_record",
            Self::FundamentalRightsAssessment => "fundamental_rights_assessment",
            Self::StandardsAlignment => "standards_alignment",
            Self::PostMarketMonitoring => "post_market_monitoring",
            Self::CorrectiveAction => "corrective_action",
            Self::AuthorityNotification => "authority_notification",
            Self::AuthoritySubmission => "authority_submission",
            Self::ReportingDeadline => "reporting_deadline",
            Self::RegulatorCorrespondence => "regulator_correspondence",
            Self::ModelEvaluation => "model_evaluation",
            Self::AdversarialTest => "adversarial_test",
            Self::TrainingProvenance => "training_provenance",
            Self::DownstreamDocumentation => "downstream_documentation",
            Self::CopyrightPolicy => "copyright_policy",
            Self::TrainingSummary => "training_summary",
            Self::ConformityAssessment => "conformity_assessment",
            Self::Declaration => "declaration",
            Self::Registration => "registration",
            Self::LiteracyAttestation => "literacy_attestation",
            Self::IncidentReport => "incident_report",
            Self::ComputeMetrics => "compute_metrics",
        }
    }
}

impl PackTypeArg {
    fn as_api_value(self) -> &'static str {
        match self {
            Self::AnnexIv => "annex_iv",
            Self::AnnexXi => "annex_xi",
            Self::AnnexXii => "annex_xii",
            Self::FundamentalRights => "fundamental_rights",
            Self::ProviderGovernance => "provider_governance",
            Self::PostMarketMonitoring => "post_market_monitoring",
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
            Self::Importer => "importer",
            Self::Distributor => "distributor",
            Self::AuthorizedRepresentative => "authorized_representative",
            Self::GpaiProvider => "gpai_provider",
        }
    }

    fn as_schema_role(self) -> ActorRole {
        match self {
            Self::Provider => ActorRole::Provider,
            Self::Deployer => ActorRole::Deployer,
            Self::Integrator => ActorRole::Integrator,
            Self::Importer => ActorRole::Importer,
            Self::Distributor => ActorRole::Distributor,
            Self::AuthorizedRepresentative => ActorRole::AuthorizedRepresentative,
            Self::GpaiProvider => ActorRole::GpaiProvider,
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
                role: args.role,
                intended_use: args.intended_use.clone(),
                prohibited_practice_screening: args.prohibited_practice_screening.clone(),
                risk_tier: args.risk_tier.clone(),
                high_risk_domain: args.high_risk_domain.clone(),
                gpai_status: args.gpai_status.clone(),
                systemic_risk: args.systemic_risk,
                fria_required: args.fria_required,
                deployment_context: args.deployment_context.clone(),
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
            &args.redact_field,
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
            disclosure_template_profile,
            disclosure_template_name,
            disclosure_redaction_group,
        } => cmd_pack(PackCommandInput {
            pack_type,
            bundle_format,
            disclosure_policy: disclosure_policy.as_deref(),
            disclosure_template_profile,
            disclosure_template_name: disclosure_template_name.as_deref(),
            disclosure_redaction_groups: &disclosure_redaction_group,
            vault_url: &vault_url,
            out_path: &out,
            system_id: system_id.as_deref(),
            from: from.as_deref(),
            to: to.as_deref(),
        }),
        Commands::Vault { command } => match command {
            VaultCommands::Status { vault_url, format } => cmd_vault_status(&vault_url, format),
            VaultCommands::Metrics { vault_url } => cmd_vault_metrics(&vault_url),
            VaultCommands::Backup { vault_url, out } => cmd_vault_backup(&vault_url, &out),
            VaultCommands::Restore {
                input,
                out_dir,
                backup_key,
            } => cmd_vault_restore(&input, &out_dir, backup_key.as_deref()),
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
                disclosure_template_profile,
                disclosure_template_name,
                disclosure_redaction_group,
            } => cmd_pack(PackCommandInput {
                pack_type,
                bundle_format,
                disclosure_policy: disclosure_policy.as_deref(),
                disclosure_template_profile,
                disclosure_template_name: disclosure_template_name.as_deref(),
                disclosure_redaction_groups: &disclosure_redaction_group,
                vault_url: &vault_url,
                out_path: &out,
                system_id: system_id.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
            }),
            VaultCommands::DisclosurePreview {
                vault_url,
                bundle_id,
                pack_type,
                disclosure_policy,
                disclosure_policy_file,
                disclosure_template_profile,
                disclosure_template_name,
                disclosure_redaction_group,
                format,
            } => cmd_vault_disclosure_preview(
                &vault_url,
                &bundle_id,
                pack_type,
                disclosure_policy.as_deref(),
                disclosure_policy_file.as_deref(),
                DisclosureTemplateCliInput {
                    profile: disclosure_template_profile,
                    name: disclosure_template_name.as_deref(),
                    groups: &disclosure_redaction_group,
                },
                format,
            ),
            VaultCommands::DisclosureTemplates { vault_url, format } => {
                cmd_vault_disclosure_templates(&vault_url, format)
            }
            VaultCommands::DisclosureTemplate {
                vault_url,
                profile,
                name,
                redaction_group,
                out,
                format,
            } => cmd_vault_disclosure_template(
                vault_url.as_deref(),
                profile,
                name.as_deref(),
                &redaction_group,
                out.as_deref(),
                format,
            ),
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
    redact_fields: &[String],
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
    let field_redactions = parse_field_redactions(redact_fields)?;
    let redacted = if field_redactions.is_empty() {
        redact_bundle(&bundle, &item_indices, &artefact_indices)
    } else {
        redact_bundle_with_field_redactions(
            &bundle,
            &item_indices,
            &artefact_indices,
            &field_redactions,
        )
    }
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
    let disclosure_template = build_cli_disclosure_template_request(DisclosureTemplateCliInput {
        profile: input.disclosure_template_profile,
        name: input.disclosure_template_name,
        groups: input.disclosure_redaction_groups,
    })?;
    if input.disclosure_policy.is_some() && disclosure_template.is_some() {
        bail!("provide either --disclosure-policy or --disclosure-template-profile, not both");
    }
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
        disclosure_template,
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
    let create_response = with_cli_api_key(client.post(&create_url))
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
    let export_response = with_cli_api_key(client.get(&export_url))
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

fn cmd_vault_disclosure_preview(
    vault_url: &str,
    bundle_id: &str,
    pack_type: Option<PackTypeArg>,
    disclosure_policy: Option<&str>,
    disclosure_policy_file: Option<&Path>,
    disclosure_template: DisclosureTemplateCliInput<'_>,
    format: OutputFormat,
) -> Result<()> {
    let selection_count = usize::from(disclosure_policy.is_some())
        + usize::from(disclosure_policy_file.is_some())
        + usize::from(disclosure_template.profile.is_some());
    if selection_count > 1 {
        bail!(
            "provide only one of --disclosure-policy, --disclosure-policy-file, or --disclosure-template-profile"
        );
    }

    let request = DisclosurePreviewRequest {
        bundle_id: normalize_required_cli_text("bundle_id", bundle_id)?,
        pack_type: pack_type.map(|value| value.as_api_value().to_string()),
        disclosure_policy: normalize_optional_cli_text("disclosure_policy", disclosure_policy)?,
        policy: disclosure_policy_file
            .map(load_disclosure_policy_file)
            .transpose()?,
        disclosure_template: build_cli_disclosure_template_request(disclosure_template)?,
    };

    let client = build_http_client()?;
    let url = join_vault_url(vault_url, "/v1/disclosure/preview");
    let response = with_cli_api_key(client.post(&url))
        .json(&request)
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, "disclosure preview")?;
    let preview: DisclosurePreviewResponse = response
        .json()
        .context("failed to decode disclosure preview response")?;

    match format {
        OutputFormat::Human => print_disclosure_preview_human(&preview),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&preview)?),
    }

    Ok(())
}

fn cmd_vault_disclosure_templates(vault_url: &str, format: OutputFormat) -> Result<()> {
    let client = build_http_client()?;
    let url = join_vault_url(vault_url, "/v1/disclosure/templates");
    let response = with_cli_api_key(client.get(&url))
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, "list disclosure templates")?;
    let catalog: DisclosureTemplateCatalogResponse = response
        .json()
        .context("failed to decode disclosure template catalog")?;

    match format {
        OutputFormat::Human => print_disclosure_template_catalog_human(&catalog),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&catalog)?),
    }

    Ok(())
}

fn cmd_vault_disclosure_template(
    vault_url: Option<&str>,
    profile: DisclosurePolicyTemplateArg,
    name: Option<&str>,
    groups: &[DisclosureRedactionGroupArg],
    out_path: Option<&Path>,
    format: OutputFormat,
) -> Result<()> {
    let rendered = if let Some(vault_url) = vault_url {
        render_vault_disclosure_template(vault_url, profile, name, groups)?
    } else {
        DisclosureTemplateResponse {
            profile: disclosure_policy_template_name(profile).to_string(),
            description: String::new(),
            default_redaction_groups: match profile {
                DisclosurePolicyTemplateArg::RuntimeMinimum => vec![
                    "commitments".to_string(),
                    "parameters".to_string(),
                    "operational_metrics".to_string(),
                ],
                DisclosurePolicyTemplateArg::PrivacyReview => vec![
                    "commitments".to_string(),
                    "metadata".to_string(),
                    "parameters".to_string(),
                    "operational_metrics".to_string(),
                ],
                _ => Vec::new(),
            },
            policy: disclosure_policy_template(
                profile,
                normalize_optional_cli_text("name", name)?.as_deref(),
                groups,
            ),
        }
    };
    let policy = rendered.policy;
    let json = serde_json::to_string_pretty(&policy)?;

    if let Some(out_path) = out_path {
        fs::write(out_path, format!("{json}\n"))
            .with_context(|| format!("failed to write {}", out_path.display()))?;
    }

    match format {
        OutputFormat::Human => {
            println!("profile: {}", rendered.profile);
            println!("name: {}", policy.name);
            if let Some(vault_url) = vault_url {
                println!("source: {}", vault_url);
            } else {
                println!("source: local");
            }
            if !rendered.default_redaction_groups.is_empty() {
                println!(
                    "default_groups: {}",
                    rendered.default_redaction_groups.join(",")
                );
            }
            if !groups.is_empty() {
                println!(
                    "groups: {}",
                    groups
                        .iter()
                        .map(|group| group.to_possible_value().unwrap().get_name().to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            if let Some(out_path) = out_path {
                println!("wrote: {}", out_path.display());
            }
            println!("{json}");
        }
        OutputFormat::Json => println!("{json}"),
    }

    Ok(())
}

fn render_vault_disclosure_template(
    vault_url: &str,
    profile: DisclosurePolicyTemplateArg,
    name: Option<&str>,
    groups: &[DisclosureRedactionGroupArg],
) -> Result<DisclosureTemplateResponse> {
    let request = DisclosureTemplateRenderRequest {
        profile: disclosure_policy_template_name(profile).to_string(),
        name: normalize_optional_cli_text("name", name)?,
        redaction_groups: groups
            .iter()
            .map(|group| group.to_possible_value().unwrap().get_name().to_string())
            .collect(),
        redacted_fields_by_item_type: BTreeMap::new(),
    };

    let client = build_http_client()?;
    let url = join_vault_url(vault_url, "/v1/disclosure/templates/render");
    let response = with_cli_api_key(client.post(&url))
        .json(&request)
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, "render disclosure template")?;
    response
        .json()
        .context("failed to decode disclosure template render response")
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
        tls_enabled: config.service.tls_enabled,
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
        backup_enabled: config.backup.enabled,
        backup_directory: config.backup.directory.clone(),
        backup_interval_hours: config.backup.interval_hours,
        backup_retention_count: config.backup.retention_count,
        backup_encryption_enabled: config.backup.encryption.enabled,
        backup_encryption_algorithm: config.backup.encryption.algorithm.clone(),
        backup_encryption_key_id: config.backup.encryption.key_id.clone(),
        timestamp_enabled: config.timestamp.enabled,
        timestamp_provider: config.timestamp.provider.clone(),
        timestamp_assurance: config.timestamp.assurance.clone(),
        timestamp_trust_anchor_count: config.timestamp.trust_anchor_pems.len(),
        timestamp_ocsp_url_count: config.timestamp.ocsp_responder_urls.len(),
        timestamp_policy_oid_count: config.timestamp.policy_oids.len(),
        transparency_enabled: config.transparency.enabled,
        transparency_provider: config.transparency.provider.clone(),
        auth_enabled: config.auth.enabled,
        auth_scheme: config.auth.scheme.clone(),
        auth_principal_count: config.auth.principal_labels.len(),
        tenant_organization_id: config.tenant.organization_id.clone(),
        tenant_enforced: config.tenant.enforced,
    };

    match format {
        OutputFormat::Human => print_vault_status_human(&output, &config),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
    }

    Ok(())
}

fn cmd_vault_metrics(vault_url: &str) -> Result<()> {
    let client = build_http_client()?;
    let metrics = get_text(
        &client,
        join_vault_url(vault_url, "/metrics"),
        "vault metrics scrape",
    )?;
    print!("{metrics}");
    if !metrics.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn cmd_vault_backup(vault_url: &str, out_path: &Path) -> Result<()> {
    let client = build_http_client()?;
    let response = with_cli_api_key(client.post(join_vault_url(vault_url, "/v1/backup")))
        .send()
        .with_context(|| {
            format!(
                "failed to call {}/v1/backup",
                vault_url.trim_end_matches('/')
            )
        })?;
    let response = ensure_success(response, "vault backup export")?;
    let bytes = response
        .bytes()
        .context("failed to read vault backup archive response")?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(out_path, bytes.as_ref())
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    println!("{}", out_path.display());
    Ok(())
}

fn cmd_vault_restore(
    input_path: &Path,
    out_dir: &Path,
    backup_key_path: Option<&Path>,
) -> Result<()> {
    let archive_bytes =
        fs::read(input_path).with_context(|| format!("failed to read {}", input_path.display()))?;
    let backup_key = load_backup_decryption_key(backup_key_path)?;
    let layout = restore_vault_backup_archive(&archive_bytes, out_dir, backup_key.as_ref())?;
    println!("restored: {}", layout.root_dir.display());
    println!("metadata_db: {}", layout.metadata_db.display());
    println!("storage_dir: {}", layout.storage_dir.display());
    println!("config_json: {}", layout.config_json.display());
    Ok(())
}

#[derive(Debug)]
struct RestoredVaultLayout {
    root_dir: PathBuf,
    metadata_db: PathBuf,
    storage_dir: PathBuf,
    config_json: PathBuf,
}

fn restore_vault_backup_archive(
    bytes: &[u8],
    out_dir: &Path,
    backup_key: Option<&[u8; 32]>,
) -> Result<RestoredVaultLayout> {
    if out_dir.exists() {
        let mut entries = fs::read_dir(out_dir)
            .with_context(|| format!("failed to inspect {}", out_dir.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!(
                "restore target {} must not already contain files",
                out_dir.display()
            );
        }
    }

    let parent = out_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let staging_dir = parent.join(format!(".proof-layer-restore-{}", generate_bundle_id()));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("failed to clear {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("failed to create {}", staging_dir.display()))?;

    let decrypted_bytes = decrypt_backup_archive(bytes, backup_key)
        .map_err(|err| anyhow!("failed to decode backup archive: {err}"))?;
    let archive_bytes = decrypted_bytes.as_deref().unwrap_or(bytes);

    let restore_result =
        extract_vault_backup_archive(archive_bytes, &staging_dir).and_then(|layout| {
            validate_restored_vault_layout(&layout)?;
            if out_dir.exists() {
                fs::remove_dir(out_dir)
                    .with_context(|| format!("failed to clear empty {}", out_dir.display()))?;
            }
            fs::rename(&staging_dir, out_dir).with_context(|| {
                format!(
                    "failed to move restored vault from {} to {}",
                    staging_dir.display(),
                    out_dir.display()
                )
            })?;
            Ok(RestoredVaultLayout {
                root_dir: out_dir.to_path_buf(),
                metadata_db: out_dir.join("metadata/metadata.db"),
                storage_dir: out_dir.join("storage"),
                config_json: out_dir.join("config/vault_config.json"),
            })
        });

    if restore_result.is_err() {
        match fs::remove_dir_all(&staging_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }

    restore_result
}

fn extract_vault_backup_archive(bytes: &[u8], target_dir: &Path) -> Result<RestoredVaultLayout> {
    fs::create_dir_all(target_dir.join("storage"))
        .with_context(|| format!("failed to create {}", target_dir.join("storage").display()))?;
    let mut archive = TarArchive::new(GzDecoder::new(std::io::Cursor::new(bytes)));
    let mut seen_paths = HashSet::new();
    let mut manifest_bytes = None;
    let mut config_bytes = None;
    let mut metadata_present = false;

    for entry in archive
        .entries()
        .context("failed to list backup archive entries")?
    {
        let mut entry = entry.context("failed to read backup archive entry")?;
        let raw_path = String::from_utf8_lossy(entry.path_bytes().as_ref()).to_string();
        validate_artefact_name(&raw_path)
            .with_context(|| format!("invalid backup archive entry path {raw_path}"))?;
        if !seen_paths.insert(raw_path.clone()) {
            bail!("duplicate backup archive entry {raw_path}");
        }

        let destination = target_dir.join(&raw_path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .with_context(|| format!("failed to read backup archive entry {raw_path}"))?;
        fs::write(&destination, &contents)
            .with_context(|| format!("failed to write {}", destination.display()))?;

        match raw_path.as_str() {
            "manifest.json" => manifest_bytes = Some(contents),
            "config/vault_config.json" => config_bytes = Some(contents),
            "metadata/metadata.db" => metadata_present = true,
            _ => {}
        }
    }

    let manifest_bytes = manifest_bytes.context("backup archive missing manifest.json")?;
    let manifest: VaultBackupManifest =
        serde_json::from_slice(&manifest_bytes).context("failed to decode backup manifest.json")?;
    if manifest.format != VAULT_BACKUP_FORMAT {
        bail!(
            "unsupported backup archive format {}, expected {}",
            manifest.format,
            VAULT_BACKUP_FORMAT
        );
    }
    if !metadata_present {
        bail!("backup archive missing metadata/metadata.db");
    }
    let config_bytes = config_bytes.context("backup archive missing config/vault_config.json")?;
    let _: VaultConfigResponse =
        serde_json::from_slice(&config_bytes).context("failed to decode backup config JSON")?;

    Ok(RestoredVaultLayout {
        root_dir: target_dir.to_path_buf(),
        metadata_db: target_dir.join("metadata/metadata.db"),
        storage_dir: target_dir.join("storage"),
        config_json: target_dir.join("config/vault_config.json"),
    })
}

fn load_backup_decryption_key(backup_key_path: Option<&Path>) -> Result<Option<[u8; 32]>> {
    let key_base64 = if let Some(path) = backup_key_path {
        Some(
            fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?
                .trim()
                .to_string(),
        )
    } else if let Some(value) = env::var("PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_B64")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(value)
    } else if let Some(path) = env::var("PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        Some(
            fs::read_to_string(&path)
                .with_context(|| format!("failed to read {path}"))?
                .trim()
                .to_string(),
        )
    } else {
        None
    };

    key_base64
        .map(|value| {
            decode_backup_encryption_key(&value)
                .map_err(|err| anyhow!("invalid backup decryption key: {err}"))
        })
        .transpose()
}

fn validate_restored_vault_layout(layout: &RestoredVaultLayout) -> Result<()> {
    if !layout.metadata_db.is_file() {
        bail!(
            "restored metadata database is missing at {}",
            layout.metadata_db.display()
        );
    }
    if !layout.storage_dir.is_dir() {
        bail!(
            "restored storage directory is missing at {}",
            layout.storage_dir.display()
        );
    }
    if !layout.config_json.is_file() {
        bail!(
            "restored config JSON is missing at {}",
            layout.config_json.display()
        );
    }
    Ok(())
}

fn print_disclosure_preview_human(response: &DisclosurePreviewResponse) {
    println!("bundle_id: {}", response.bundle_id);
    println!("policy: {}", response.policy_name);
    println!(
        "pack_type: {}",
        response.pack_type.as_deref().unwrap_or("none")
    );
    println!(
        "candidate_items: {}",
        format_indices(&response.candidate_item_indices)
    );
    println!(
        "disclosed_items: {}",
        format_indices(&response.disclosed_item_indices)
    );
    println!(
        "disclosed_item_types: {}",
        format_csv(&response.disclosed_item_types)
    );
    println!(
        "disclosed_obligation_refs: {}",
        format_csv(&response.disclosed_item_obligation_refs)
    );
    if !response.disclosed_item_field_redactions.is_empty() {
        println!(
            "disclosed_item_field_redactions: {}",
            serde_json::to_string(&response.disclosed_item_field_redactions)
                .unwrap_or_else(|_| "{}".to_string())
        );
    }
    println!(
        "disclosed_artefacts: {}",
        format_csv(&response.disclosed_artefact_names)
    );
    println!(
        "artefact_bytes_included: {}",
        if response.disclosed_artefact_bytes_included {
            "yes"
        } else {
            "no"
        }
    );
}

fn print_disclosure_template_catalog_human(catalog: &DisclosureTemplateCatalogResponse) {
    println!("templates:");
    for template in &catalog.templates {
        println!("  - {}", template.profile);
        println!("    description: {}", template.description);
        println!("    policy_name: {}", template.policy.name);
        if !template.default_redaction_groups.is_empty() {
            println!(
                "    default_groups: {}",
                template.default_redaction_groups.join(",")
            );
        }
        if !template.policy.allowed_item_types.is_empty() {
            println!(
                "    allowed_item_types: {}",
                template.policy.allowed_item_types.join(",")
            );
        }
        if template.policy.include_artefact_metadata {
            println!(
                "    artefacts: metadata{}",
                if template.policy.include_artefact_bytes {
                    "+bytes"
                } else {
                    ""
                }
            );
        }
    }

    println!("redaction_groups:");
    for group in &catalog.redaction_groups {
        println!("  - {}: {}", group.name, group.description);
    }
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
    println!(
        "service.tls_enabled: {}",
        if status.tls_enabled { "yes" } else { "no" }
    );
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
        "backup: enabled={} interval_hours={} retention_count={} directory={}",
        if status.backup_enabled { "yes" } else { "no" },
        status.backup_interval_hours,
        status.backup_retention_count,
        status.backup_directory
    );
    println!(
        "backup.encryption: enabled={} algorithm={} key_id={}",
        if status.backup_encryption_enabled {
            "yes"
        } else {
            "no"
        },
        status
            .backup_encryption_algorithm
            .as_deref()
            .unwrap_or("n/a"),
        status.backup_encryption_key_id.as_deref().unwrap_or("n/a")
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
    println!(
        "auth: enabled={} scheme={} principals={}",
        status.auth_enabled, status.auth_scheme, status.auth_principal_count
    );
    println!(
        "tenant: enforced={} organization_id={}",
        if status.tenant_enforced { "yes" } else { "no" },
        status.tenant_organization_id.as_deref().unwrap_or("n/a")
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

    if let Some(role) = overrides.role {
        capture.actor.role = role.as_schema_role();
    }

    if overrides.has_compliance_profile_overrides() || capture.compliance_profile.is_some() {
        let mut profile = capture.compliance_profile.take().unwrap_or_default();

        if let Some(intended_use) =
            normalize_optional_cli_text("intended_use", overrides.intended_use.as_deref())?
        {
            profile.intended_use = Some(intended_use);
        }
        if let Some(screening) = normalize_optional_cli_text(
            "prohibited_practice_screening",
            overrides.prohibited_practice_screening.as_deref(),
        )? {
            profile.prohibited_practice_screening = Some(screening);
        }
        if let Some(risk_tier) =
            normalize_optional_cli_text("risk_tier", overrides.risk_tier.as_deref())?
        {
            profile.risk_tier = Some(risk_tier);
        }
        if let Some(high_risk_domain) =
            normalize_optional_cli_text("high_risk_domain", overrides.high_risk_domain.as_deref())?
        {
            profile.high_risk_domain = Some(high_risk_domain);
        }
        if let Some(gpai_status) =
            normalize_optional_cli_text("gpai_status", overrides.gpai_status.as_deref())?
        {
            profile.gpai_status = Some(gpai_status);
        }
        if let Some(systemic_risk) = overrides.systemic_risk {
            profile.systemic_risk = Some(systemic_risk);
        }
        if let Some(fria_required) = overrides.fria_required {
            profile.fria_required = Some(fria_required);
        }
        if let Some(deployment_context) = normalize_optional_cli_text(
            "deployment_context",
            overrides.deployment_context.as_deref(),
        )? {
            profile.deployment_context = Some(deployment_context);
        }

        capture.compliance_profile = Some(profile);
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
        EvidenceItem::InstructionsForUse(data) => format!(
            "instructions_for_use document_ref={} version={}",
            data.document_ref,
            data.version.as_deref().unwrap_or("n/a")
        ),
        EvidenceItem::QmsRecord(data) => format!(
            "qms_record record_id={} process={} status={}",
            data.record_id, data.process, data.status
        ),
        EvidenceItem::FundamentalRightsAssessment(data) => format!(
            "fundamental_rights_assessment assessment_id={} status={}",
            data.assessment_id, data.status
        ),
        EvidenceItem::StandardsAlignment(data) => format!(
            "standards_alignment standard_ref={} status={}",
            data.standard_ref, data.status
        ),
        EvidenceItem::PostMarketMonitoring(data) => format!(
            "post_market_monitoring plan_id={} status={}",
            data.plan_id, data.status
        ),
        EvidenceItem::CorrectiveAction(data) => format!(
            "corrective_action action_id={} status={}",
            data.action_id, data.status
        ),
        EvidenceItem::AuthorityNotification(data) => format!(
            "authority_notification notification_id={} authority={} status={}",
            data.notification_id, data.authority, data.status
        ),
        EvidenceItem::AuthoritySubmission(data) => format!(
            "authority_submission submission_id={} authority={} status={}",
            data.submission_id, data.authority, data.status
        ),
        EvidenceItem::ReportingDeadline(data) => format!(
            "reporting_deadline deadline_id={} authority={} status={}",
            data.deadline_id, data.authority, data.status
        ),
        EvidenceItem::RegulatorCorrespondence(data) => format!(
            "regulator_correspondence correspondence_id={} authority={} status={}",
            data.correspondence_id, data.authority, data.status
        ),
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
        EvidenceItem::DownstreamDocumentation(data) => format!(
            "downstream_documentation document_ref={} audience={} status={}",
            data.document_ref, data.audience, data.status
        ),
        EvidenceItem::CopyrightPolicy(data) => format!(
            "copyright_policy policy_ref={} status={}",
            data.policy_ref, data.status
        ),
        EvidenceItem::TrainingSummary(data) => format!(
            "training_summary summary_ref={} status={}",
            data.summary_ref, data.status
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
        EvidenceItem::ComputeMetrics(data) => format!(
            "compute_metrics compute_id={} threshold_status={}",
            data.compute_id, data.threshold_status
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

fn parse_field_redactions(values: &[String]) -> Result<BTreeMap<usize, Vec<String>>> {
    let mut field_redactions = BTreeMap::<usize, Vec<String>>::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("redact-field entries must not be empty");
        }
        let (index, field) = trimmed.split_once(':').ok_or_else(|| {
            anyhow!("redact-field must be <item_index>:<field-or-path>, got {trimmed}")
        })?;
        let index = index
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid item index in redact-field {trimmed}"))?;
        let field = field.trim();
        if field.is_empty() {
            bail!("redact-field must specify a field or JSON pointer after ':', got {trimmed}");
        }
        field_redactions
            .entry(index)
            .or_default()
            .push(field.to_string());
    }
    Ok(field_redactions)
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

fn normalize_required_cli_text(label: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(trimmed.to_string())
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

fn load_disclosure_policy_file(path: &Path) -> Result<DisclosurePolicyConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read disclosure policy file {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse disclosure policy file {}", path.display()))
}

fn format_csv(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn format_indices(values: &[usize]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn build_http_client() -> Result<Client> {
    Client::builder()
        .build()
        .context("failed to build HTTP client")
}

fn cli_api_key() -> Option<String> {
    env::var("PROOF_SERVICE_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn with_cli_api_key(builder: RequestBuilder) -> RequestBuilder {
    if let Some(api_key) = cli_api_key() {
        builder.bearer_auth(api_key)
    } else {
        builder
    }
}

fn require_vault_ready(client: &Client, vault_url: &str) -> Result<()> {
    let response = with_cli_api_key(client.get(join_vault_url(vault_url, "/readyz")))
        .send()
        .with_context(|| format!("failed to call {}/readyz", vault_url.trim_end_matches('/')))?;
    ensure_success(response, "vault readiness check").map(|_| ())
}

fn get_json<T: DeserializeOwned>(client: &Client, url: String, action: &str) -> Result<T> {
    let response = with_cli_api_key(client.get(&url))
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, action)?;
    response
        .json()
        .with_context(|| format!("failed to decode {action} response"))
}

fn get_text(client: &Client, url: String, action: &str) -> Result<String> {
    let response = with_cli_api_key(client.get(&url))
        .send()
        .with_context(|| format!("failed to call {url}"))?;
    let response = ensure_success(response, action)?;
    response
        .text()
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
        Actor, ActorRole, ComplianceProfile, EncryptionPolicy, EvidenceContext,
        LlmInteractionEvidence, Policy, REKOR_RFC3161_API_VERSION, REKOR_RFC3161_ENTRY_KIND,
        REKOR_TRANSPARENCY_KIND, RFC3161_TIMESTAMP_KIND, SCITT_STATEMENT_PROFILE,
        SCITT_TRANSPARENCY_KIND, Subject, TimestampError, TimestampToken, TransparencyReceipt,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
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
            compliance_profile: None,
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
                execution_start: None,
                execution_end: None,
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

    fn sample_vault_config_response() -> VaultConfigResponse {
        VaultConfigResponse {
            service: VaultServiceConfigView {
                addr: "127.0.0.1:8080".to_string(),
                max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
                tls_enabled: true,
            },
            signing: VaultSigningConfigView {
                key_id: "kid-dev-01".to_string(),
                algorithm: "ed25519".to_string(),
            },
            storage: VaultStorageConfigView {
                metadata_backend: "sqlite".to_string(),
                blob_backend: "filesystem".to_string(),
            },
            retention: VaultRetentionConfigView {
                grace_period_days: 30,
                scan_interval_hours: 24,
                policies: vec![VaultRetentionPolicyConfig {
                    retention_class: "runtime_logs".to_string(),
                    min_duration_days: 3650,
                    max_duration_days: None,
                    legal_basis: "eu_ai_act_article_12_19_26".to_string(),
                    active: true,
                }],
            },
            backup: VaultBackupConfigView {
                enabled: true,
                directory: "/var/lib/proof-layer/backups".to_string(),
                interval_hours: 6,
                retention_count: 8,
                encryption: VaultBackupEncryptionConfigView {
                    enabled: true,
                    algorithm: Some(
                        proof_layer_core::VAULT_BACKUP_ENCRYPTION_ALGORITHM.to_string(),
                    ),
                    key_id: Some("backup-key-01".to_string()),
                },
            },
            timestamp: VaultTimestampConfig {
                enabled: false,
                provider: "rfc3161".to_string(),
                url: "http://timestamp.digicert.com".to_string(),
                assurance: None,
                trust_anchor_pems: Vec::new(),
                crl_pems: Vec::new(),
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: Vec::new(),
                policy_oids: Vec::new(),
            },
            transparency: VaultTransparencyConfig {
                enabled: false,
                provider: "none".to_string(),
                url: None,
                log_public_key_pem: None,
            },
            auth: VaultAuthConfigView {
                enabled: true,
                scheme: "bearer".to_string(),
                principal_labels: vec!["ops".to_string()],
            },
            audit: VaultAuditConfigView { enabled: true },
            tenant: VaultTenantConfigView {
                organization_id: Some("org-demo".to_string()),
                enforced: true,
            },
        }
    }

    fn append_test_tar_file(
        builder: &mut tar::Builder<GzEncoder<Vec<u8>>>,
        path: &str,
        bytes: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, std::io::Cursor::new(bytes))
            .unwrap();
    }

    fn build_test_backup_archive() -> Vec<u8> {
        let manifest = VaultBackupManifest {
            format: VAULT_BACKUP_FORMAT.to_string(),
            backup_id: "backup-01".to_string(),
            created_at: "2026-03-09T12:00:00Z".to_string(),
        };
        let config = sample_vault_config_response();

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        append_test_tar_file(
            &mut builder,
            "manifest.json",
            &serde_json::to_vec(&manifest).unwrap(),
        );
        append_test_tar_file(
            &mut builder,
            "config/vault_config.json",
            &serde_json::to_vec(&config).unwrap(),
        );
        append_test_tar_file(&mut builder, "metadata/metadata.db", b"sqlite-snapshot");
        append_test_tar_file(
            &mut builder,
            "storage/artefacts/bundle-01/prompt.json",
            br#"{"prompt":"hello"}"#,
        );
        append_test_tar_file(
            &mut builder,
            "storage/packs/pack-01/evidence_pack.pkg",
            b"pack-bytes",
        );

        builder.into_inner().unwrap().finish().unwrap()
    }

    fn build_test_encrypted_backup_archive(key: &[u8; 32]) -> Vec<u8> {
        proof_layer_core::encrypt_backup_archive(
            &build_test_backup_archive(),
            key,
            Some("backup-key-test"),
        )
        .unwrap()
    }

    fn build_test_backup_archive_with_entry(path: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        append_test_tar_file(
            &mut builder,
            "manifest.json",
            &serde_json::to_vec(&VaultBackupManifest {
                format: VAULT_BACKUP_FORMAT.to_string(),
                backup_id: "backup-01".to_string(),
                created_at: "2026-03-09T12:00:00Z".to_string(),
            })
            .unwrap(),
        );
        append_test_tar_file(
            &mut builder,
            "config/vault_config.json",
            &serde_json::to_vec(&sample_vault_config_response()).unwrap(),
        );
        append_test_tar_file(&mut builder, "metadata/metadata.db", b"sqlite-snapshot");
        append_test_tar_file(&mut builder, path, b"bad");
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn rewrite_backup_archive_entry_path(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
        let mut tar_bytes = Vec::new();
        decoder.read_to_end(&mut tar_bytes).unwrap();
        let offset = tar_bytes
            .windows(from.len())
            .position(|window| window == from.as_bytes())
            .unwrap();
        tar_bytes[offset..offset + from.len()].copy_from_slice(to.as_bytes());
        let header_start = offset - (offset % 512);
        for byte in &mut tar_bytes[header_start + 148..header_start + 156] {
            *byte = b' ';
        }
        let checksum: u32 = tar_bytes[header_start..header_start + 512]
            .iter()
            .map(|byte| u32::from(*byte))
            .sum();
        let checksum_field = format!("{checksum:06o}\0 ");
        tar_bytes[header_start + 148..header_start + 156]
            .copy_from_slice(checksum_field.as_bytes());

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
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
        assert_eq!(
            PackTypeArg::FundamentalRights.as_api_value(),
            "fundamental_rights"
        );
        assert_eq!(
            PackTypeArg::ProviderGovernance.as_api_value(),
            "provider_governance"
        );
        assert_eq!(
            PackTypeArg::PostMarketMonitoring.as_api_value(),
            "post_market_monitoring"
        );
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
    fn pack_command_accepts_disclosure_template_args() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "pack",
            "--type",
            "runtime-logs",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--out",
            "./out.pkg",
            "--bundle-format",
            "disclosure",
            "--disclosure-template-profile",
            "runtime_minimum",
            "--disclosure-template-name",
            "runtime_template_pack",
            "--disclosure-group",
            "metadata",
        ])
        .unwrap();

        match cli.command {
            Commands::Pack {
                disclosure_policy,
                disclosure_template_profile,
                disclosure_template_name,
                disclosure_redaction_group,
                ..
            } => {
                assert_eq!(disclosure_policy, None);
                assert_eq!(
                    disclosure_template_profile,
                    Some(DisclosurePolicyTemplateArg::RuntimeMinimum)
                );
                assert_eq!(
                    disclosure_template_name.as_deref(),
                    Some("runtime_template_pack")
                );
                assert_eq!(
                    disclosure_redaction_group,
                    vec![DisclosureRedactionGroupArg::Metadata]
                );
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_disclosure_preview_command_accepts_named_policy_arg() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "disclosure-preview",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--bundle-id",
            "B1",
            "--type",
            "annex-iv",
            "--disclosure-policy",
            "annex_iv_redacted",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command:
                    VaultCommands::DisclosurePreview {
                        bundle_id,
                        pack_type,
                        disclosure_policy,
                        ..
                    },
            } => {
                assert_eq!(bundle_id, "B1");
                assert_eq!(pack_type, Some(PackTypeArg::AnnexIv));
                assert_eq!(disclosure_policy.as_deref(), Some("annex_iv_redacted"));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_disclosure_preview_command_accepts_template_args() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "disclosure-preview",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--bundle-id",
            "B1",
            "--disclosure-template-profile",
            "privacy_review",
            "--disclosure-template-name",
            "privacy_review_internal",
            "--disclosure-group",
            "metadata",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command:
                    VaultCommands::DisclosurePreview {
                        disclosure_policy,
                        disclosure_policy_file,
                        disclosure_template_profile,
                        disclosure_template_name,
                        disclosure_redaction_group,
                        ..
                    },
            } => {
                assert_eq!(disclosure_policy, None);
                assert_eq!(disclosure_policy_file, None);
                assert_eq!(
                    disclosure_template_profile,
                    Some(DisclosurePolicyTemplateArg::PrivacyReview)
                );
                assert_eq!(
                    disclosure_template_name.as_deref(),
                    Some("privacy_review_internal")
                );
                assert_eq!(
                    disclosure_redaction_group,
                    vec![DisclosureRedactionGroupArg::Metadata]
                );
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_disclosure_template_command_accepts_profile_and_groups() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "disclosure-template",
            "--profile",
            "runtime_minimum",
            "--group",
            "metadata",
            "--group",
            "commitments",
            "--name",
            "runtime_custom",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command:
                    VaultCommands::DisclosureTemplate {
                        profile,
                        redaction_group,
                        name,
                        ..
                    },
            } => {
                assert_eq!(profile, DisclosurePolicyTemplateArg::RuntimeMinimum);
                assert_eq!(
                    redaction_group,
                    vec![
                        DisclosureRedactionGroupArg::Metadata,
                        DisclosureRedactionGroupArg::Commitments,
                    ]
                );
                assert_eq!(name.as_deref(), Some("runtime_custom"));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn build_cli_disclosure_template_request_requires_profile_when_grouped() {
        let err = build_cli_disclosure_template_request(DisclosureTemplateCliInput {
            profile: None,
            name: None,
            groups: &[DisclosureRedactionGroupArg::Metadata],
        })
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("--disclosure-template-name and --disclosure-group require --disclosure-template-profile"));
    }

    #[test]
    fn build_cli_disclosure_template_request_serializes_template_profile() {
        let template = build_cli_disclosure_template_request(DisclosureTemplateCliInput {
            profile: Some(DisclosurePolicyTemplateArg::RuntimeMinimum),
            name: Some("runtime_template"),
            groups: &[DisclosureRedactionGroupArg::Metadata],
        })
        .unwrap()
        .unwrap();
        assert_eq!(template.profile, "runtime_minimum");
        assert_eq!(template.name.as_deref(), Some("runtime_template"));
        assert_eq!(template.redaction_groups, vec!["metadata"]);
    }

    #[test]
    fn vault_disclosure_templates_command_accepts_vault_url() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "disclosure-templates",
            "--vault-url",
            "http://127.0.0.1:8080",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command: VaultCommands::DisclosureTemplates { vault_url, .. },
            } => assert_eq!(vault_url, "http://127.0.0.1:8080"),
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_metrics_command_accepts_vault_url() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "metrics",
            "--vault-url",
            "http://127.0.0.1:8080",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command: VaultCommands::Metrics { vault_url },
            } => assert_eq!(vault_url, "http://127.0.0.1:8080"),
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_backup_command_accepts_out_path() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "backup",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--out",
            "/tmp/vault-backup.tar.gz",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command: VaultCommands::Backup { vault_url, out },
            } => {
                assert_eq!(vault_url, "http://127.0.0.1:8080");
                assert_eq!(out, PathBuf::from("/tmp/vault-backup.tar.gz"));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn vault_restore_command_accepts_out_dir() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "restore",
            "--in",
            "/tmp/vault-backup.tar.gz",
            "--out-dir",
            "/tmp/restored-vault",
            "--backup-key",
            "/tmp/backup.key",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command:
                    VaultCommands::Restore {
                        input,
                        out_dir,
                        backup_key,
                    },
            } => {
                assert_eq!(input, PathBuf::from("/tmp/vault-backup.tar.gz"));
                assert_eq!(out_dir, PathBuf::from("/tmp/restored-vault"));
                assert_eq!(backup_key, Some(PathBuf::from("/tmp/backup.key")));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn restore_vault_backup_archive_extracts_expected_layout() {
        let base = std::env::temp_dir().join(format!(
            "proofctl-restore-test-{}",
            generate_bundle_id().to_ascii_lowercase()
        ));
        let out_dir = base.join("restored");
        let archive = build_test_backup_archive();

        let layout = restore_vault_backup_archive(&archive, &out_dir, None).unwrap();

        assert_eq!(layout.root_dir, out_dir);
        assert!(layout.metadata_db.is_file());
        assert!(layout.storage_dir.is_dir());
        assert!(layout.config_json.is_file());
        assert_eq!(
            fs::read_to_string(out_dir.join("storage/artefacts/bundle-01/prompt.json")).unwrap(),
            "{\"prompt\":\"hello\"}"
        );
        let manifest: VaultBackupManifest =
            serde_json::from_slice(&fs::read(out_dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest.format, VAULT_BACKUP_FORMAT);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn restore_vault_backup_archive_rejects_path_traversal() {
        let base = std::env::temp_dir().join(format!(
            "proofctl-restore-bad-test-{}",
            generate_bundle_id().to_ascii_lowercase()
        ));
        let out_dir = base.join("restored");
        let archive = rewrite_backup_archive_entry_path(
            &build_test_backup_archive_with_entry("xx/escape.txt"),
            "xx/escape.txt",
            "../escape.txt",
        );

        let err = restore_vault_backup_archive(&archive, &out_dir, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid backup archive entry path ../escape.txt")
        );

        if base.exists() {
            fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn restore_vault_backup_archive_can_decrypt_encrypted_archives() {
        let base = std::env::temp_dir().join(format!(
            "proofctl-restore-encrypted-test-{}",
            generate_bundle_id().to_ascii_lowercase()
        ));
        let out_dir = base.join("restored");
        let key = [17_u8; 32];
        let archive = build_test_encrypted_backup_archive(&key);

        let layout = restore_vault_backup_archive(&archive, &out_dir, Some(&key)).unwrap();

        assert_eq!(layout.root_dir, out_dir);
        assert!(layout.metadata_db.is_file());
        assert!(layout.storage_dir.is_dir());
        assert!(layout.config_json.is_file());

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn restore_vault_backup_archive_rejects_missing_key_for_encrypted_archives() {
        let base = std::env::temp_dir().join(format!(
            "proofctl-restore-encrypted-bad-test-{}",
            generate_bundle_id().to_ascii_lowercase()
        ));
        let out_dir = base.join("restored");
        let archive = build_test_encrypted_backup_archive(&[18_u8; 32]);

        let err = restore_vault_backup_archive(&archive, &out_dir, None).unwrap_err();
        assert!(err.to_string().contains("decryption key is required"));

        if base.exists() {
            fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn vault_disclosure_template_command_accepts_optional_vault_url() {
        let cli = Cli::try_parse_from([
            "proofctl",
            "vault",
            "disclosure-template",
            "--vault-url",
            "http://127.0.0.1:8080",
            "--profile",
            "privacy_review",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                command:
                    VaultCommands::DisclosureTemplate {
                        vault_url, profile, ..
                    },
            } => {
                assert_eq!(vault_url.as_deref(), Some("http://127.0.0.1:8080"));
                assert_eq!(profile, DisclosurePolicyTemplateArg::PrivacyReview);
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
                role: None,
                intended_use: None,
                prohibited_practice_screening: None,
                risk_tier: None,
                high_risk_domain: None,
                gpai_status: None,
                systemic_risk: None,
                fria_required: None,
                deployment_context: None,
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
    fn create_overrides_apply_role_and_compliance_profile() {
        let event = apply_create_overrides(
            materialize_capture_event(SealableCaptureInput::Legacy(sample_legacy_capture())),
            &CreateOverrides {
                evidence_type: Some(EvidenceTypeArg::LlmInteraction),
                retention_class: Some("runtime_logs".to_string()),
                system_id: Some("system-123".to_string()),
                role: Some(ActorRoleArg::Deployer),
                intended_use: Some("Internal reviewer assistance".to_string()),
                prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
                risk_tier: Some("limited_risk".to_string()),
                high_risk_domain: Some("none".to_string()),
                gpai_status: Some("downstream_integrator".to_string()),
                systemic_risk: Some(false),
                fria_required: Some(false),
                deployment_context: Some("internal_operations".to_string()),
            },
        )
        .unwrap();

        assert_eq!(event.actor.role, ActorRole::Deployer);
        assert_eq!(event.subject.system_id.as_deref(), Some("system-123"));
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.intended_use.as_deref()),
            Some("Internal reviewer assistance")
        );
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.gpai_status.as_deref()),
            Some("downstream_integrator")
        );
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.systemic_risk),
            Some(false)
        );
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.fria_required),
            Some(false)
        );
    }

    #[test]
    fn create_overrides_merge_existing_compliance_profile() {
        let mut event = sample_event();
        event.compliance_profile = Some(ComplianceProfile {
            risk_tier: Some("high_risk".to_string()),
            ..ComplianceProfile::default()
        });

        let event = apply_create_overrides(
            event,
            &CreateOverrides {
                evidence_type: None,
                retention_class: None,
                system_id: None,
                role: Some(ActorRoleArg::AuthorizedRepresentative),
                intended_use: Some("Public sector eligibility screening".to_string()),
                prohibited_practice_screening: None,
                risk_tier: None,
                high_risk_domain: None,
                gpai_status: None,
                systemic_risk: None,
                fria_required: Some(true),
                deployment_context: None,
            },
        )
        .unwrap();

        assert_eq!(event.actor.role, ActorRole::AuthorizedRepresentative);
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.intended_use.as_deref()),
            Some("Public sector eligibility screening")
        );
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.risk_tier.as_deref()),
            Some("high_risk")
        );
        assert_eq!(
            event
                .compliance_profile
                .as_ref()
                .and_then(|profile| profile.fria_required),
            Some(true)
        );
    }

    #[test]
    fn create_overrides_reject_missing_evidence_type() {
        let mut event = sample_event();
        event.items = vec![EvidenceItem::TechnicalDoc(
            proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "doc-1".to_string(),
                section: None,
                commitment: None,
                annex_iv_sections: Vec::new(),
                system_description_summary: None,
                model_description_summary: None,
                capabilities_and_limitations: None,
                design_choices_summary: None,
                evaluation_metrics_summary: None,
                human_oversight_design_summary: None,
                post_market_monitoring_plan_ref: None,
                simplified_tech_doc: None,
            },
        )];

        let err = apply_create_overrides(
            event,
            &CreateOverrides {
                evidence_type: Some(EvidenceTypeArg::LlmInteraction),
                retention_class: None,
                system_id: None,
                role: None,
                intended_use: None,
                prohibited_practice_screening: None,
                risk_tier: None,
                high_risk_domain: None,
                gpai_status: None,
                systemic_risk: None,
                fria_required: None,
                deployment_context: None,
            },
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not contain requested evidence type llm_interaction")
        );
    }

    #[test]
    fn create_overrides_reject_empty_intended_use() {
        let err = apply_create_overrides(
            sample_event(),
            &CreateOverrides {
                evidence_type: None,
                retention_class: None,
                system_id: None,
                role: None,
                intended_use: Some("   ".to_string()),
                prohibited_practice_screening: None,
                risk_tier: None,
                high_risk_domain: None,
                gpai_status: None,
                systemic_risk: None,
                fria_required: None,
                deployment_context: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("intended_use must not be empty"));
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
    fn parse_field_redactions_groups_entries_by_item_index() {
        let parsed = parse_field_redactions(&[
            "0:output_commitment".to_string(),
            "0:/parameters/temperature".to_string(),
            "2:metadata".to_string(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            BTreeMap::from([
                (
                    0usize,
                    vec![
                        "output_commitment".to_string(),
                        "/parameters/temperature".to_string(),
                    ],
                ),
                (2usize, vec!["metadata".to_string()]),
            ])
        );
    }

    #[test]
    fn disclosure_policy_template_builds_runtime_minimum_redactions() {
        let policy =
            disclosure_policy_template(DisclosurePolicyTemplateArg::RuntimeMinimum, None, &[]);
        assert_eq!(policy.name, "runtime_minimum");
        assert_eq!(
            policy.redacted_fields_by_item_type.get("llm_interaction"),
            Some(&vec![
                "input_commitment".to_string(),
                "retrieval_commitment".to_string(),
                "output_commitment".to_string(),
                "tool_outputs_commitment".to_string(),
                "trace_commitment".to_string(),
                "/parameters".to_string(),
                "/token_usage".to_string(),
                "/latency_ms".to_string(),
                "/trace_semconv_version".to_string(),
            ])
        );
        assert_eq!(
            policy.redacted_fields_by_item_type.get("tool_call"),
            Some(&vec![
                "input_commitment".to_string(),
                "output_commitment".to_string(),
            ])
        );
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
        cmd_disclose(&bundle_path, "0", None, &[], &disclosure_path).unwrap();

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
        cmd_disclose(&bundle_path, "0", Some("0"), &[], &disclosure_path).unwrap();

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
    fn disclose_command_supports_field_level_redaction() {
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

        let tmp_dir =
            std::env::temp_dir().join(format!("proofctl-disclose-fields-{}", Ulid::new()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let bundle_path = tmp_dir.join("bundle.pkg");
        let disclosure_path = tmp_dir.join("bundle.disclosure.pkg");

        write_bundle_package(&bundle_path, &package_files).unwrap();
        cmd_disclose(
            &bundle_path,
            "0",
            None,
            &["0:output_commitment".to_string()],
            &disclosure_path,
        )
        .unwrap();

        let package = read_package(&disclosure_path).unwrap();
        let redacted = parse_redacted_bundle_file(&package.files).unwrap();
        assert!(redacted.disclosed_items[0].item.is_none());
        let field_redacted_item = redacted.disclosed_items[0]
            .field_redacted_item
            .as_ref()
            .unwrap();
        assert_eq!(
            field_redacted_item.redacted_paths,
            vec!["/output_commitment".to_string()]
        );

        fs::remove_dir_all(&tmp_dir).unwrap();
    }

    #[test]
    fn disclose_command_supports_nested_path_redaction() {
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

        let tmp_dir = std::env::temp_dir().join(format!("proofctl-disclose-paths-{}", Ulid::new()));
        fs::create_dir_all(&tmp_dir).unwrap();
        let bundle_path = tmp_dir.join("bundle.pkg");
        let disclosure_path = tmp_dir.join("bundle.disclosure.pkg");

        write_bundle_package(&bundle_path, &package_files).unwrap();
        cmd_disclose(
            &bundle_path,
            "0",
            None,
            &["0:/parameters/temperature".to_string()],
            &disclosure_path,
        )
        .unwrap();

        let package = read_package(&disclosure_path).unwrap();
        let redacted = parse_redacted_bundle_file(&package.files).unwrap();
        let field_redacted_item = redacted.disclosed_items[0]
            .field_redacted_item
            .as_ref()
            .unwrap();
        assert_eq!(
            field_redacted_item.redacted_paths,
            vec!["/parameters/temperature".to_string()]
        );
        assert_eq!(
            field_redacted_item
                .container_kinds
                .get("/parameters")
                .map(String::as_str),
            Some("object")
        );

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
