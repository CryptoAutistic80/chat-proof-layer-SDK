use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use base64ct::{Base64, Encoding};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ArtefactInput, BuildBundleError, CaptureEvent, CaptureInput, CheckState, CompletenessProfile,
    CompletenessReport, CompletenessStatus, EvidenceContext, EvidenceItem, Integrity, Policy,
    ProofBundle, ReceiptAssessment, ReceiptLiveCheckMode, ReceiptVerification, RedactedBundle,
    RekorTransparencyProvider, Rfc3161HttpTimestampProvider, ScittFormat, ScittStatementSigner,
    ScittTransparencyProvider, TimestampAssessment, TimestampAssuranceProfile, TimestampToken,
    TimestampTrustPolicy, TimestampVerification, TransparencyReceipt, TransparencyTrustPolicy,
    VAULT_BACKUP_ENCRYPTION_ALGORITHM, anchor_bundle as anchor_bundle_receipt,
    assess_receipt_error, assess_receipt_verification, assess_timestamp_error,
    assess_timestamp_verification, build_bundle, canonicalize_value, decode_backup_encryption_key,
    decode_private_key_pem, decode_public_key_pem, encode_public_key_pem, encrypt_backup_archive,
    evaluate_completeness, redact_bundle, redact_bundle_with_field_redactions, sha256_prefixed,
    timestamp_digest, validate_bundle_integrity_fields, validate_timestamp_trust_policy,
    validate_transparency_trust_policy, verify_receipt, verify_receipt_with_live_check,
    verify_receipt_with_policy, verify_receipt_with_policy_and_live_check, verify_redacted_bundle,
    verify_timestamp, verify_timestamp_with_policy,
};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{
    FromRow, QueryBuilder, Row, Sqlite, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env,
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    path::{Component, Path as FsPath, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tar::{Builder as TarBuilder, Header as TarHeader};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use ulid::Ulid;

const DEFAULT_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_RETENTION_GRACE_PERIOD_DAYS: i64 = 30;
const DEFAULT_RETENTION_SCAN_INTERVAL_HOURS: i64 = 24;
const DEFAULT_BACKUP_INTERVAL_HOURS: i64 = 0;
const DEFAULT_BACKUP_RETENTION_COUNT: usize = 7;
const DEFAULT_BACKUP_ENCRYPTION_KEY_ID: &str = "backup-key-01";
const DEFAULT_CONFIG_PATH: &str = "./vault.toml";
const DEFAULT_AUTH_PRINCIPAL_LABEL: &str = "api";
const PACKAGE_FORMAT: &str = "pl-bundle-pkg-v1";
const DISCLOSURE_PACKAGE_FORMAT: &str = "pl-bundle-disclosure-pkg-v1";
const PACK_EXPORT_FORMAT: &str = "pl-evidence-pack-v1";
const PACK_EXPORT_FILE_NAME: &str = "evidence_pack.pkg";
const VAULT_BACKUP_FORMAT: &str = "pl-vault-backup-v1";
const PACK_CURATION_PROFILE: &str = "pack-rules-v1";
const PACK_BUNDLE_FORMAT_FULL: &str = "full";
const PACK_BUNDLE_FORMAT_DISCLOSURE: &str = "disclosure";
const AUDIT_ACTOR_API: &str = "api";
const AUDIT_ACTOR_SYSTEM: &str = "system";
const SERVICE_CONFIG_KEY_TIMESTAMP: &str = "timestamp";
const SERVICE_CONFIG_KEY_TRANSPARENCY: &str = "transparency";
const SERVICE_CONFIG_KEY_DISCLOSURE: &str = "disclosure";
const DEFAULT_TIMESTAMP_PROVIDER: &str = "rfc3161";
const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";
const DEFAULT_TRANSPARENCY_PROVIDER: &str = "none";
const DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM: &str = "regulator_minimum";
const DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED: &str = "annex_iv_redacted";
const DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY: &str = "incident_summary";
const DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM: &str = "runtime_minimum";
const DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW: &str = "privacy_review";
const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";
const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    addr: String,
    tls_enabled: bool,
    auth_config: Option<RuntimeAuthConfig>,
    tenant_organization_id: Option<String>,
    storage_dir: PathBuf,
    db_path: PathBuf,
    backup_dir: PathBuf,
    signing_key: Arc<SigningKey>,
    signing_kid: String,
    signing_key_ephemeral: bool,
    metadata_backend: String,
    blob_backend: String,
    max_payload_bytes: usize,
    retention_grace_period_days: i64,
    retention_scan_interval_hours: i64,
    backup_interval_hours: i64,
    backup_retention_count: usize,
    backup_encryption: Option<RuntimeBackupEncryptionConfig>,
    demo_providers: Arc<DemoProviderRegistry>,
}

#[derive(Clone, Default)]
struct DemoProviderRegistry {
    openai: Option<Arc<dyn DemoProviderClient>>,
    anthropic: Option<Arc<dyn DemoProviderClient>>,
}

#[async_trait]
trait DemoProviderClient: Send + Sync {
    async fn generate(&self, request: &DemoProviderResponseRequest)
    -> Result<DemoProviderResponse>;
}

struct OpenAiDemoClient {
    http: Client,
    api_key: String,
}

struct AnthropicDemoClient {
    http: Client,
    api_key: String,
}

#[derive(Debug, Clone)]
struct VaultRuntimeConfig {
    addr: SocketAddr,
    storage_dir: PathBuf,
    db_path: PathBuf,
    backup_dir: PathBuf,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    auth_config: Option<RuntimeAuthConfig>,
    tenant_organization_id: Option<String>,
    signing_key_path: Option<PathBuf>,
    signing_kid: String,
    metadata_backend: String,
    blob_backend: String,
    max_payload_bytes: usize,
    retention_grace_period_days: i64,
    retention_scan_interval_hours: i64,
    backup_interval_hours: i64,
    backup_retention_count: usize,
    backup_encryption: Option<RuntimeBackupEncryptionConfig>,
    retention_policies: Vec<RetentionPolicyConfig>,
    timestamp_config: Option<TimestampConfig>,
    transparency_config: Option<TransparencyConfig>,
    config_path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultFileConfig {
    #[serde(default)]
    server: VaultServerFileConfig,
    #[serde(default)]
    auth: Option<VaultAuthFileConfig>,
    #[serde(default)]
    tenant: Option<VaultTenantFileConfig>,
    #[serde(default)]
    signing: VaultSigningFileConfig,
    #[serde(default)]
    storage: VaultStorageFileConfig,
    #[serde(default)]
    timestamp: Option<VaultTimestampFileConfig>,
    #[serde(default)]
    transparency: Option<VaultTransparencyFileConfig>,
    #[serde(default)]
    backup: VaultBackupFileConfig,
    #[serde(default)]
    retention: VaultRetentionFileConfig,
}

#[derive(Debug, Default, Deserialize)]
struct VaultServerFileConfig {
    addr: Option<String>,
    max_payload_bytes: Option<usize>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultAuthFileConfig {
    enabled: Option<bool>,
    #[serde(default)]
    api_keys: Vec<VaultApiKeyFileConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct VaultApiKeyFileConfig {
    key: String,
    label: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultTenantFileConfig {
    organization_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultSigningFileConfig {
    key_path: Option<String>,
    key_id: Option<String>,
    algorithm: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultStorageFileConfig {
    metadata_backend: Option<String>,
    sqlite_path: Option<String>,
    blob_backend: Option<String>,
    blob_path: Option<String>,
    s3: Option<VaultS3FileConfig>,
    postgresql: Option<VaultPostgresFileConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultS3FileConfig {
    bucket: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultPostgresFileConfig {
    url: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct VaultTimestampFileConfig {
    enabled: Option<bool>,
    provider: Option<String>,
    url: Option<String>,
    assurance: Option<String>,
    #[serde(default)]
    trust_anchor_pems: Vec<String>,
    #[serde(default)]
    trust_anchor_paths: Vec<String>,
    #[serde(default)]
    crl_pems: Vec<String>,
    #[serde(default)]
    crl_paths: Vec<String>,
    #[serde(default)]
    ocsp_responder_urls: Vec<String>,
    #[serde(default)]
    qualified_signer_pems: Vec<String>,
    #[serde(default)]
    qualified_signer_paths: Vec<String>,
    #[serde(default)]
    policy_oids: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct VaultTransparencyFileConfig {
    enabled: Option<bool>,
    provider: Option<String>,
    url: Option<String>,
    rekor_url: Option<String>,
    scitt_format: Option<String>,
    log_public_key_pem: Option<String>,
    log_public_key_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultBackupFileConfig {
    directory: Option<String>,
    interval_hours: Option<i64>,
    retention_count: Option<usize>,
    #[serde(default)]
    encryption: Option<VaultBackupEncryptionFileConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultBackupEncryptionFileConfig {
    enabled: Option<bool>,
    key_base64: Option<String>,
    key_path: Option<String>,
    key_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultRetentionFileConfig {
    grace_period_days: Option<i64>,
    scan_interval_hours: Option<i64>,
    #[serde(default)]
    policies: Vec<RetentionPolicyConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreateBundleRequest {
    capture: SealableCaptureInput,
    artefacts: Vec<InlineArtefact>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DemoCaptureMode {
    Synthetic,
    Live,
}

impl DemoCaptureMode {
    fn response_source(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic_demo_capture",
            Self::Live => "live_provider_capture",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DemoProviderName {
    Openai,
    Anthropic,
}

impl DemoProviderName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DemoProviderResponseRequest {
    mode: DemoCaptureMode,
    provider: DemoProviderName,
    model: String,
    system_prompt: String,
    user_prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_api_key: Option<String>,
    #[serde(default = "default_demo_temperature")]
    temperature: f64,
    #[serde(default = "default_demo_max_tokens")]
    max_tokens: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DemoProviderResponse {
    capture_mode: String,
    provider: String,
    model: String,
    output_text: String,
    usage: DemoTokenUsage,
    latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_request_id: Option<String>,
    prompt_payload: Value,
    response_payload: Value,
    trace_payload: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DemoTokenUsage {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum SealableCaptureInput {
    V10(CaptureEvent),
    Legacy(CaptureInput),
}

#[derive(Debug, Deserialize, Serialize)]
struct InlineArtefact {
    name: String,
    content_type: String,
    data_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateBundleResponse {
    bundle_id: String,
    bundle_root: String,
    signature: String,
    created_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum VerifyRequest {
    Inline(Box<InlineVerifyRequest>),
    Package(Box<PackageVerifyRequest>),
}

#[derive(Debug, Deserialize, Serialize)]
struct InlineVerifyRequest {
    bundle: ProofBundle,
    artefacts: Vec<InlineVerifyArtefact>,
    public_key_pem: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PackageVerifyRequest {
    bundle_pkg_base64: String,
    public_key_pem: String,
}

#[derive(Debug)]
struct DecodedPackage {
    format: String,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InlineVerifyArtefact {
    name: String,
    data_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct BundlePackage {
    format: String,
    files: Vec<PackagedFile>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PackagedFile {
    name: String,
    data_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    files: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ManifestEntry {
    name: String,
    digest: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyResponse {
    valid: bool,
    message: String,
    artefacts_verified: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum VerifyTimestampRequest {
    BundleId {
        bundle_id: String,
    },
    Direct {
        bundle_root: String,
        timestamp: TimestampToken,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum VerifyReceiptRequest {
    BundleId {
        bundle_id: String,
        #[serde(default)]
        live_check_mode: ReceiptLiveCheckMode,
    },
    Direct {
        bundle_root: String,
        receipt: TransparencyReceipt,
        #[serde(default)]
        live_check_mode: ReceiptLiveCheckMode,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyTimestampResponse {
    valid: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<TimestampVerification>,
    assessment: TimestampAssessment,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyReceiptResponse {
    valid: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<ReceiptVerification>,
    assessment: ReceiptAssessment,
}

#[derive(Debug, Deserialize)]
struct BundleQuery {
    system_id: Option<String>,
    role: Option<String>,
    #[serde(rename = "type")]
    item_type: Option<String>,
    has_timestamp: Option<bool>,
    has_receipt: Option<bool>,
    assurance_level: Option<String>,
    from: Option<String>,
    to: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct AuditTrailQuery {
    action: Option<String>,
    bundle_id: Option<String>,
    pack_id: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListSystemsResponse {
    items: Vec<SystemListEntry>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct SystemListEntry {
    system_id: String,
    bundle_count: i64,
    active_bundle_count: i64,
    deleted_bundle_count: i64,
    first_seen_at: Option<String>,
    latest_bundle_at: Option<String>,
    timestamped_bundle_count: i64,
    receipt_bundle_count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemSummaryResponse {
    system_id: String,
    bundle_count: i64,
    active_bundle_count: i64,
    deleted_bundle_count: i64,
    first_seen_at: Option<String>,
    latest_bundle_at: Option<String>,
    timestamped_bundle_count: i64,
    receipt_bundle_count: i64,
    actor_roles: Vec<SystemFacetCount>,
    evidence_types: Vec<SystemFacetCount>,
    retention_classes: Vec<SystemFacetCount>,
    assurance_levels: Vec<SystemFacetCount>,
    model_ids: Vec<SystemFacetCount>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct SystemFacetCount {
    value: String,
    count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ListBundlesResponse {
    page: u32,
    limit: u32,
    items: Vec<BundleSummary>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct BundleSummary {
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

#[derive(Debug, Serialize, Deserialize)]
struct RetentionStatusResponse {
    scanned_at: String,
    grace_period_days: i64,
    policies: Vec<RetentionStatusItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RetentionStatusItem {
    retention_class: String,
    #[serde(default)]
    expiry_mode: RetentionExpiryMode,
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

#[derive(Debug, Serialize, Deserialize)]
struct RetentionScanResponse {
    scanned_at: String,
    grace_period_days: i64,
    soft_deleted: u64,
    hard_deleted: u64,
    held_skipped: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeleteBundleResponse {
    bundle_id: String,
    deleted_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TimestampBundleResponse {
    bundle_id: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    generated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnchorBundleResponse {
    bundle_id: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    entry_uuid: String,
    integrated_time: String,
    log_index: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct LegalHoldRequest {
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditTrailResponse {
    page: u32,
    limit: u32,
    items: Vec<AuditLogEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditLogEntry {
    id: i64,
    timestamp: String,
    action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_id: Option<String>,
    details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultConfigResponse {
    service: VaultServiceConfigView,
    signing: VaultSigningConfigView,
    storage: VaultStorageConfigView,
    retention: RetentionConfigView,
    backup: VaultBackupConfigView,
    timestamp: TimestampConfig,
    transparency: TransparencyConfig,
    disclosure: DisclosureConfig,
    audit: AuditConfigView,
    auth: VaultAuthConfigView,
    tenant: VaultTenantConfigView,
    demo: VaultDemoConfigView,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultServiceConfigView {
    addr: String,
    max_payload_bytes: usize,
    tls_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultAuthConfigView {
    enabled: bool,
    scheme: String,
    principal_labels: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultTenantConfigView {
    organization_id: Option<String>,
    enforced: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultDemoConfigView {
    capture_modes: Vec<String>,
    providers: VaultDemoProvidersConfigView,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultDemoProvidersConfigView {
    openai: VaultDemoProviderReadiness,
    anthropic: VaultDemoProviderReadiness,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultDemoProviderReadiness {
    live_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBackupConfigView {
    enabled: bool,
    directory: String,
    interval_hours: i64,
    retention_count: usize,
    encryption: VaultBackupEncryptionConfigView,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBackupEncryptionConfigView {
    enabled: bool,
    algorithm: Option<String>,
    key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultMetricsSnapshot {
    bundle_total: i64,
    bundle_active: i64,
    bundle_deleted: i64,
    bundle_held: i64,
    bundle_timestamped: i64,
    bundle_receipted: i64,
    pack_total: i64,
    audit_log_total: i64,
    retention_policy_total: i64,
    disclosure_policy_total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBackupManifest {
    format: String,
    backup_id: String,
    created_at: String,
    metrics: VaultMetricsSnapshot,
}

#[derive(Debug)]
struct ScheduledBackupResult {
    file_name: String,
    pruned_count: usize,
}

#[derive(Debug, Clone)]
struct RuntimeBackupEncryptionConfig {
    key: Arc<[u8; 32]>,
    key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultSigningConfigView {
    key_id: String,
    algorithm: String,
    public_key_pem: String,
    ephemeral: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultStorageConfigView {
    metadata_backend: String,
    blob_backend: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RetentionConfigView {
    grace_period_days: i64,
    scan_interval_hours: i64,
    policies: Vec<RetentionPolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionPolicyConfig {
    retention_class: String,
    #[serde(default)]
    expiry_mode: RetentionExpiryMode,
    min_duration_days: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_duration_days: Option<i64>,
    legal_basis: String,
    active: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum RetentionExpiryMode {
    #[default]
    FixedDays,
    UntilWithdrawn,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TimestampConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TransparencyConfig {
    enabled: bool,
    provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scitt_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_public_key_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DisclosureConfig {
    policies: Vec<DisclosurePolicyConfig>,
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

#[derive(Debug, Serialize, Deserialize)]
struct AuditConfigView {
    enabled: bool,
}

#[derive(Debug, Clone)]
struct RuntimeAuthConfig {
    principals: Arc<Vec<ApiKeyPrincipal>>,
}

#[derive(Debug, Clone)]
struct ApiKeyPrincipal {
    key: String,
    label: String,
}

#[derive(Debug, Clone)]
struct AuthenticatedActor {
    label: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct UpdateRetentionConfigRequest {
    policies: Vec<RetentionPolicyConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdateRetentionConfigResponse {
    updated: usize,
    policies: Vec<RetentionPolicyConfig>,
}

#[derive(Debug, FromRow)]
struct StoredServiceConfigRow {
    config_json: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegalHoldResponse {
    bundle_id: String,
    active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    placed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CreatePackRequest {
    pack_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bundle_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(default = "default_pack_bundle_format")]
    bundle_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_template: Option<DisclosureTemplateRenderRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DisclosurePreviewRequest {
    bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<DisclosurePolicyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_template: Option<DisclosureTemplateRenderRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EvaluateCompletenessRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle: Option<ProofBundle>,
    profile: CompletenessProfile,
}

#[derive(Debug, Deserialize, Serialize)]
struct DisclosureTemplateRenderRequest {
    profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    redaction_groups: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    redacted_fields_by_item_type: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DisclosureTemplateCatalogResponse {
    templates: Vec<DisclosureTemplateResponse>,
    redaction_groups: Vec<DisclosureRedactionGroupResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DisclosureTemplateResponse {
    profile: String,
    description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    default_redaction_groups: Vec<String>,
    policy: DisclosurePolicyConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DisclosureRedactionGroupResponse {
    name: String,
    description: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisclosurePreviewResponse {
    bundle_id: String,
    policy_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    candidate_item_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_item_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_item_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_item_obligation_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    disclosed_item_field_redactions: BTreeMap<usize, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_artefact_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_artefact_names: Vec<String>,
    #[serde(default)]
    disclosed_artefact_bytes_included: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PackSummaryResponse {
    pack_id: String,
    pack_type: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(default = "default_pack_bundle_format")]
    bundle_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_profile: Option<CompletenessProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_status: Option<CompletenessStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_profile: Option<CompletenessProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_status: Option<CompletenessStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_pass_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_warn_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_fail_count: Option<usize>,
    bundle_count: usize,
    bundle_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackManifest {
    pack_id: String,
    pack_type: String,
    curation_profile: String,
    generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(default = "default_pack_bundle_format")]
    bundle_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_profile: Option<CompletenessProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_pass_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_warn_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_fail_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_profile: Option<CompletenessProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_status: Option<CompletenessStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_pass_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_warn_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pack_completeness_fail_count: Option<usize>,
    bundle_ids: Vec<String>,
    bundles: Vec<PackBundleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackBundleEntry {
    bundle_id: String,
    created_at: String,
    actor_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    retention_class: String,
    item_types: Vec<String>,
    #[serde(default = "default_pack_bundle_format")]
    bundle_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_item_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_item_types: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    disclosed_item_field_redactions: BTreeMap<usize, Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_artefact_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    disclosed_artefact_names: Vec<String>,
    #[serde(default)]
    disclosed_artefact_bytes_included: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    obligation_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completeness_status: Option<CompletenessStatus>,
    matched_rules: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidencePackArchive {
    format: String,
    manifest: PackManifest,
    files: Vec<PackagedFile>,
}

#[derive(Debug, FromRow)]
struct PackSourceBundleRow {
    bundle_id: String,
    created_at: String,
    actor_role: String,
    system_id: Option<String>,
    model_id: Option<String>,
    retention_class: String,
    bundle_json: String,
}

#[derive(Debug, FromRow)]
struct StoredPackRow {
    pack_id: String,
    pack_type: String,
    created_at: String,
    system_id: Option<String>,
    from_date: Option<String>,
    to_date: Option<String>,
    bundle_count: i64,
    export_path: String,
    manifest_json: String,
    pack_completeness_report_json: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredPackArtefactRow {
    name: String,
    storage_path: String,
}

#[derive(Debug, FromRow)]
struct BundleRetentionRow {
    bundle_id: String,
    deleted_at: Option<String>,
    legal_hold_reason: Option<String>,
    legal_hold_until: Option<String>,
}

#[derive(Debug, FromRow)]
struct StoredAuditLogRow {
    id: i64,
    timestamp: String,
    action: String,
    actor: Option<String>,
    bundle_id: Option<String>,
    pack_id: Option<String>,
    details_json: String,
}

#[derive(Debug, Clone, FromRow)]
struct StoredRetentionPolicyRow {
    retention_class: String,
    expiry_mode: String,
    min_duration_days: i64,
    max_duration_days: Option<i64>,
    legal_basis: String,
    active: bool,
}

#[derive(Debug)]
struct PackArtefactBytes {
    name: String,
    bytes: Vec<u8>,
}

struct PackProfile {
    pack_type: &'static str,
    allowed_roles: &'static [&'static str],
    item_types: &'static [&'static str],
    retention_classes: &'static [&'static str],
    obligation_refs: &'static [&'static str],
    requires_fria: Option<bool>,
}

struct CuratedPackBundle {
    row: PackSourceBundleRow,
    bundle: ProofBundle,
    item_types: Vec<String>,
    obligation_refs: Vec<String>,
    disclosed_item_indices: Vec<usize>,
    disclosed_item_types: Vec<String>,
    disclosed_item_field_redactions: BTreeMap<usize, Vec<String>>,
    disclosed_artefact_indices: Vec<usize>,
    disclosed_artefact_names: Vec<String>,
    disclosed_artefact_bytes_included: bool,
    matched_rules: Vec<String>,
}

const ANNEX_IV_ITEM_PRIORITY: &[&str] = &[
    "technical_doc",
    "risk_assessment",
    "data_governance",
    "instructions_for_use",
    "human_oversight",
    "qms_record",
    "standards_alignment",
    "post_market_monitoring",
    "corrective_action",
];

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG")
                .unwrap_or_else(|_| "proof_service=info,tower_http=info".to_string()),
        )
        .without_time()
        .init();

    let runtime_config = load_vault_runtime_config()?;
    let addr = runtime_config.addr;
    let storage_dir = runtime_config.storage_dir.clone();
    fs::create_dir_all(&storage_dir)
        .with_context(|| format!("failed to create storage dir {}", storage_dir.display()))?;
    fs::create_dir_all(&runtime_config.backup_dir).with_context(|| {
        format!(
            "failed to create backup dir {}",
            runtime_config.backup_dir.display()
        )
    })?;

    let db = open_sqlite_pool(&runtime_config.db_path).await?;
    initialize_sqlite_schema(&db).await?;
    validate_existing_bundle_organization_scope(
        &db,
        runtime_config.tenant_organization_id.as_deref(),
    )
    .await?;
    seed_default_retention_policies(&db).await?;
    seed_default_disclosure_config(&db).await?;
    apply_runtime_config_to_db(&db, &runtime_config).await?;
    backfill_bundle_expiries(&db).await?;
    backfill_item_obligation_refs(&db).await?;

    let (signing_key, signing_key_ephemeral) =
        load_signing_key(runtime_config.signing_key_path.as_deref())?;
    let demo_providers = build_demo_provider_registry()?;

    let state = AppState {
        db,
        addr: addr.to_string(),
        tls_enabled: runtime_config.tls_cert_path.is_some(),
        auth_config: runtime_config.auth_config.clone(),
        tenant_organization_id: runtime_config.tenant_organization_id.clone(),
        storage_dir,
        db_path: runtime_config.db_path.clone(),
        backup_dir: runtime_config.backup_dir.clone(),
        signing_key: Arc::new(signing_key),
        signing_kid: runtime_config.signing_kid.clone(),
        signing_key_ephemeral,
        metadata_backend: runtime_config.metadata_backend.clone(),
        blob_backend: runtime_config.blob_backend.clone(),
        max_payload_bytes: runtime_config.max_payload_bytes,
        retention_grace_period_days: runtime_config.retention_grace_period_days,
        retention_scan_interval_hours: runtime_config.retention_scan_interval_hours,
        backup_interval_hours: runtime_config.backup_interval_hours,
        backup_retention_count: runtime_config.backup_retention_count,
        backup_encryption: runtime_config.backup_encryption.clone(),
        demo_providers,
    };

    let tls_enabled = state.tls_enabled;
    maybe_spawn_retention_scan_task(state.clone());
    maybe_spawn_backup_task(state.clone());
    let app = build_router(state, runtime_config.max_payload_bytes);

    info!(
        "proof-service listening on {}://{addr} using config source {}",
        if tls_enabled { "https" } else { "http" },
        runtime_config
            .config_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "env/defaults".to_string())
    );
    if let (Some(cert_path), Some(key_path)) = (
        runtime_config.tls_cert_path.as_deref(),
        runtime_config.tls_key_path.as_deref(),
    ) {
        let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .with_context(|| {
                format!(
                    "failed to load TLS certificate {} and key {}",
                    cert_path.display(),
                    key_path.display()
                )
            })?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    Ok(())
}

fn build_router(state: AppState, max_payload_bytes: usize) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let mut api_router = Router::new()
        .route("/v1/bundles", get(list_bundles).post(create_bundle))
        .route(
            "/v1/bundles/{bundle_id}",
            get(get_bundle).delete(delete_bundle),
        )
        .route(
            "/v1/bundles/{bundle_id}/artefacts/{name}",
            get(get_artefact),
        )
        .route(
            "/v1/bundles/{bundle_id}/legal-hold",
            post(set_legal_hold).delete(release_legal_hold),
        )
        .route("/v1/bundles/{bundle_id}/timestamp", post(timestamp_bundle))
        .route("/v1/bundles/{bundle_id}/anchor", post(anchor_bundle))
        .route("/v1/audit-trail", get(list_audit_trail))
        .route("/v1/config", get(get_config))
        .route("/v1/config/retention", put(update_retention_config))
        .route("/v1/config/timestamp", put(update_timestamp_config))
        .route("/v1/config/transparency", put(update_transparency_config))
        .route("/v1/config/disclosure", put(update_disclosure_config))
        .route(
            "/v1/demo/provider-response",
            post(generate_demo_provider_response),
        )
        .route("/v1/disclosure/templates", get(list_disclosure_templates))
        .route(
            "/v1/disclosure/templates/render",
            post(render_disclosure_template),
        )
        .route("/v1/disclosure/preview", post(preview_disclosure))
        .route("/v1/completeness/evaluate", post(evaluate_completeness_api))
        .route("/v1/systems", get(list_systems))
        .route("/v1/systems/{system_id}/summary", get(get_system_summary))
        .route("/v1/packs", post(create_pack))
        .route("/v1/packs/{pack_id}", get(get_pack))
        .route("/v1/packs/{pack_id}/manifest", get(get_pack_manifest))
        .route("/v1/packs/{pack_id}/export", get(get_pack_export))
        .route("/v1/backup", post(export_backup))
        .route("/v1/retention/status", get(retention_status))
        .route("/v1/retention/scan", post(retention_scan))
        .route("/v1/verify", post(verify_bundle))
        .route("/v1/verify/timestamp", post(verify_timestamp_token))
        .route("/v1/verify/receipt", post(verify_transparency_receipt))
        .with_state(state.clone());

    if state.auth_config.is_some() {
        api_router = api_router.layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key_auth,
        ));
    }

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .merge(api_router)
        .layer(cors)
        .layer(DefaultBodyLimit::max(max_payload_bytes))
        .with_state(state)
}

fn load_vault_runtime_config() -> Result<VaultRuntimeConfig> {
    let env_vars = env::vars().collect::<BTreeMap<_, _>>();
    let config_path = resolve_config_path(&env_vars);
    let file_config = match config_path.as_deref() {
        Some(path) => load_vault_file_config(path)?,
        None => VaultFileConfig::default(),
    };
    build_vault_runtime_config(file_config, config_path.as_deref(), &env_vars)
}

fn resolve_config_path(env_vars: &BTreeMap<String, String>) -> Option<PathBuf> {
    if let Some(path) = env_vars
        .get("PROOF_SERVICE_CONFIG_PATH")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return Some(PathBuf::from(path));
    }

    let default_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    default_path.exists().then_some(default_path)
}

fn load_vault_file_config(path: &FsPath) -> Result<VaultFileConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read vault config {}", path.display()))?;
    toml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn build_vault_runtime_config(
    file_config: VaultFileConfig,
    config_path: Option<&FsPath>,
    env_vars: &BTreeMap<String, String>,
) -> Result<VaultRuntimeConfig> {
    validate_file_config_capabilities(&file_config)?;

    let config_base_dir = config_path
        .and_then(FsPath::parent)
        .unwrap_or_else(|| FsPath::new("."));
    let addr_raw = env_value(env_vars, "PROOF_SERVICE_ADDR")
        .map(ToOwned::to_owned)
        .or(file_config.server.addr.clone())
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let addr = addr_raw
        .parse()
        .with_context(|| format!("failed to parse service addr {addr_raw}"))?;

    let max_payload_bytes = env_value(env_vars, "PROOF_SERVICE_MAX_PAYLOAD_BYTES")
        .map(parse_max_payload_bytes)
        .transpose()?
        .or(file_config.server.max_payload_bytes)
        .unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES);
    let tls_cert_path = env_value(env_vars, "PROOF_SERVICE_TLS_CERT_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .server
                .tls_cert
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        });
    let tls_key_path = env_value(env_vars, "PROOF_SERVICE_TLS_KEY_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .server
                .tls_key
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        });
    if tls_cert_path.is_some() != tls_key_path.is_some() {
        bail!("server TLS requires both certificate and key paths");
    }

    let metadata_backend = normalize_backend(
        file_config.storage.metadata_backend.as_deref(),
        "sqlite",
        "storage.metadata_backend",
    )?;
    if metadata_backend != "sqlite" {
        bail!("storage.metadata_backend={metadata_backend} is not implemented yet");
    }

    let blob_backend = normalize_backend(
        file_config.storage.blob_backend.as_deref(),
        "filesystem",
        "storage.blob_backend",
    )?;
    if blob_backend != "filesystem" {
        bail!("storage.blob_backend={blob_backend} is not implemented yet");
    }

    let storage_dir = env_value(env_vars, "PROOF_SERVICE_STORAGE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .storage
                .blob_path
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        })
        .unwrap_or_else(|| PathBuf::from("./storage"));
    let backup_dir = env_value(env_vars, "PROOF_SERVICE_BACKUP_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .backup
                .directory
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        })
        .unwrap_or_else(|| storage_dir.join("backups"));

    let db_path = env_value(env_vars, "PROOF_SERVICE_DB_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .storage
                .sqlite_path
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        })
        .unwrap_or_else(|| storage_dir.join("metadata.db"));

    let signing_algorithm = file_config
        .signing
        .algorithm
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ed25519");
    if !signing_algorithm.eq_ignore_ascii_case("ed25519") {
        bail!("signing.algorithm={signing_algorithm} is not implemented yet");
    }

    let signing_key_path = env_value(env_vars, "PROOF_SIGNING_KEY_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            file_config
                .signing
                .key_path
                .as_deref()
                .map(|value| resolve_path_from_config(config_base_dir, value))
        });
    let signing_kid = env_value(env_vars, "PROOF_SIGNING_KEY_ID")
        .map(ToOwned::to_owned)
        .or(file_config.signing.key_id.clone())
        .unwrap_or_else(|| "kid-dev-01".to_string());

    let retention_grace_period_days = env_value(env_vars, "PROOF_SERVICE_RETENTION_GRACE_DAYS")
        .map(parse_retention_grace_period_days)
        .transpose()?
        .or(file_config.retention.grace_period_days)
        .unwrap_or(DEFAULT_RETENTION_GRACE_PERIOD_DAYS);
    let retention_scan_interval_hours =
        env_value(env_vars, "PROOF_SERVICE_RETENTION_SCAN_INTERVAL_HOURS")
            .map(parse_retention_scan_interval_hours)
            .transpose()?
            .or(file_config.retention.scan_interval_hours)
            .unwrap_or(DEFAULT_RETENTION_SCAN_INTERVAL_HOURS);
    let backup_interval_hours = env_value(env_vars, "PROOF_SERVICE_BACKUP_INTERVAL_HOURS")
        .map(parse_backup_interval_hours)
        .transpose()?
        .or(file_config.backup.interval_hours)
        .unwrap_or(DEFAULT_BACKUP_INTERVAL_HOURS);
    let backup_retention_count = env_value(env_vars, "PROOF_SERVICE_BACKUP_RETENTION_COUNT")
        .map(parse_backup_retention_count)
        .transpose()?
        .or(file_config.backup.retention_count)
        .unwrap_or(DEFAULT_BACKUP_RETENTION_COUNT);
    let backup_encryption =
        resolve_backup_encryption_config(config_base_dir, file_config.backup.encryption, env_vars)?;

    let retention_policies = file_config
        .retention
        .policies
        .into_iter()
        .map(|policy| {
            validate_retention_policy_config(&policy)?;
            Ok(policy)
        })
        .collect::<Result<Vec<_>>>()?;

    let auth_config = resolve_auth_runtime_config(file_config.auth, env_vars)?;
    let tenant_organization_id = resolve_tenant_organization_id(file_config.tenant, env_vars);
    let timestamp_config = resolve_timestamp_file_config(config_base_dir, file_config.timestamp)?;
    let transparency_config =
        resolve_transparency_file_config(config_base_dir, file_config.transparency)?;

    Ok(VaultRuntimeConfig {
        addr,
        storage_dir,
        db_path,
        backup_dir,
        tls_cert_path,
        tls_key_path,
        auth_config,
        tenant_organization_id,
        signing_key_path,
        signing_kid,
        metadata_backend,
        blob_backend,
        max_payload_bytes,
        retention_grace_period_days,
        retention_scan_interval_hours,
        backup_interval_hours,
        backup_retention_count,
        backup_encryption,
        retention_policies,
        timestamp_config,
        transparency_config,
        config_path: config_path.map(FsPath::to_path_buf),
    })
}

fn validate_file_config_capabilities(file_config: &VaultFileConfig) -> Result<()> {
    if let Some(s3) = file_config.storage.s3.as_ref() {
        let configured = s3.bucket.is_some() || s3.region.is_some() || s3.endpoint.is_some();
        if configured {
            bail!("storage.s3 is not implemented yet");
        }
    }
    if let Some(postgresql) = file_config.storage.postgresql.as_ref()
        && postgresql.url.is_some()
    {
        bail!("storage.postgresql is not implemented yet");
    }

    Ok(())
}

fn env_value<'a>(env_vars: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    env_vars.get(key).map(|value| value.as_str())
}

fn resolve_auth_runtime_config(
    file_config: Option<VaultAuthFileConfig>,
    env_vars: &BTreeMap<String, String>,
) -> Result<Option<RuntimeAuthConfig>> {
    let env_key = env_value(env_vars, "PROOF_SERVICE_API_KEY")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let env_label = env_value(env_vars, "PROOF_SERVICE_API_KEY_LABEL")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_AUTH_PRINCIPAL_LABEL)
        .to_string();

    let mut enabled = false;
    let principals = if let Some(key) = env_key {
        enabled = true;
        vec![ApiKeyPrincipal {
            key,
            label: env_label,
        }]
    } else if let Some(config) = file_config {
        enabled = config.enabled.unwrap_or(!config.api_keys.is_empty());
        config
            .api_keys
            .into_iter()
            .enumerate()
            .map(|(index, principal)| {
                let key = principal.key.trim();
                if key.is_empty() {
                    bail!("auth.api_keys[{index}].key must not be empty");
                }
                let label = principal
                    .label
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(DEFAULT_AUTH_PRINCIPAL_LABEL)
                    .to_string();
                Ok(ApiKeyPrincipal {
                    key: key.to_string(),
                    label,
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    if enabled && principals.is_empty() {
        bail!("auth.enabled=true requires at least one configured API key");
    }
    if !enabled {
        return Ok(None);
    }

    Ok(Some(RuntimeAuthConfig {
        principals: Arc::new(principals),
    }))
}

fn resolve_tenant_organization_id(
    file_config: Option<VaultTenantFileConfig>,
    env_vars: &BTreeMap<String, String>,
) -> Option<String> {
    let raw = env_value(env_vars, "PROOF_SERVICE_ORGANIZATION_ID")
        .map(ToOwned::to_owned)
        .or_else(|| file_config.and_then(|config| config.organization_id));
    normalize_optional_string(raw)
}

fn resolve_backup_encryption_config(
    base_dir: &FsPath,
    file_config: Option<VaultBackupEncryptionFileConfig>,
    env_vars: &BTreeMap<String, String>,
) -> Result<Option<RuntimeBackupEncryptionConfig>> {
    let env_key_base64 = env_value(env_vars, "PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_B64")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let env_key_path = env_value(env_vars, "PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_PATH")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let env_key_id = env_value(env_vars, "PROOF_SERVICE_BACKUP_ENCRYPTION_KEY_ID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let file_enabled = file_config
        .as_ref()
        .and_then(|config| config.enabled)
        .unwrap_or(false);
    let file_key_base64 = file_config
        .as_ref()
        .and_then(|config| normalize_optional_string(config.key_base64.clone()));
    let file_key_path = file_config
        .as_ref()
        .and_then(|config| config.key_path.as_deref())
        .map(|path| resolve_path_from_config(base_dir, path));
    let key_id = env_key_id
        .or_else(|| file_config.and_then(|config| normalize_optional_string(config.key_id)))
        .unwrap_or_else(|| DEFAULT_BACKUP_ENCRYPTION_KEY_ID.to_string());

    let key_base64 = if let Some(key_base64) = env_key_base64 {
        Some(key_base64)
    } else if let Some(path) = env_key_path.or(file_key_path) {
        Some(
            fs::read_to_string(&path)
                .with_context(|| {
                    format!("failed to read backup encryption key {}", path.display())
                })?
                .trim()
                .to_string(),
        )
    } else {
        file_key_base64
    };

    let enabled = key_base64.is_some() || file_enabled;
    if !enabled {
        return Ok(None);
    }

    let key_base64 = key_base64.ok_or_else(|| {
        anyhow::anyhow!("backup encryption requires a base64-encoded 32-byte key")
    })?;
    let key = decode_backup_encryption_key(&key_base64)
        .map_err(|err| anyhow::anyhow!("invalid backup encryption key: {err}"))?;

    Ok(Some(RuntimeBackupEncryptionConfig {
        key: Arc::new(key),
        key_id,
    }))
}

fn normalize_backend(raw: Option<&str>, default_value: &str, field: &str) -> Result<String> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_value)
        .to_ascii_lowercase();
    if value.chars().any(char::is_whitespace) {
        bail!("{field} must not contain whitespace");
    }
    Ok(value)
}

fn resolve_path_from_config(base_dir: &FsPath, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn read_config_text_file(base_dir: &FsPath, raw_path: &str, label: &str) -> Result<String> {
    let path = resolve_path_from_config(base_dir, raw_path);
    fs::read_to_string(&path).with_context(|| format!("failed to read {label} {}", path.display()))
}

fn resolve_timestamp_file_config(
    base_dir: &FsPath,
    file_config: Option<VaultTimestampFileConfig>,
) -> Result<Option<TimestampConfig>> {
    let Some(file_config) = file_config else {
        return Ok(None);
    };

    let mut config = default_timestamp_config();
    if let Some(enabled) = file_config.enabled {
        config.enabled = enabled;
    }
    if let Some(provider) = file_config.provider {
        config.provider = provider;
    }
    if let Some(url) = file_config.url {
        config.url = url;
    }
    if file_config.assurance.is_some() {
        config.assurance = file_config.assurance;
    }
    config.trust_anchor_pems.extend(
        file_config
            .trust_anchor_pems
            .into_iter()
            .filter(|pem| !pem.trim().is_empty()),
    );
    config.crl_pems.extend(
        file_config
            .crl_pems
            .into_iter()
            .filter(|pem| !pem.trim().is_empty()),
    );
    config.ocsp_responder_urls.extend(
        file_config
            .ocsp_responder_urls
            .into_iter()
            .filter(|url| !url.trim().is_empty()),
    );
    config.qualified_signer_pems.extend(
        file_config
            .qualified_signer_pems
            .into_iter()
            .filter(|pem| !pem.trim().is_empty()),
    );
    config.policy_oids.extend(
        file_config
            .policy_oids
            .into_iter()
            .filter(|policy_oid| !policy_oid.trim().is_empty()),
    );
    for path in file_config.trust_anchor_paths {
        config.trust_anchor_pems.push(read_config_text_file(
            base_dir,
            &path,
            "timestamp trust anchor",
        )?);
    }
    for path in file_config.crl_paths {
        config
            .crl_pems
            .push(read_config_text_file(base_dir, &path, "timestamp CRL")?);
    }
    for path in file_config.qualified_signer_paths {
        config.qualified_signer_pems.push(read_config_text_file(
            base_dir,
            &path,
            "qualified TSA signer certificate",
        )?);
    }

    validate_timestamp_config(config).map(Some)
}

fn resolve_transparency_file_config(
    base_dir: &FsPath,
    file_config: Option<VaultTransparencyFileConfig>,
) -> Result<Option<TransparencyConfig>> {
    let Some(file_config) = file_config else {
        return Ok(None);
    };

    let mut config = default_transparency_config();
    if let Some(enabled) = file_config.enabled {
        config.enabled = enabled;
    }
    if let Some(provider) = file_config.provider {
        config.provider = provider;
    }
    if let Some(url) = file_config.url.or(file_config.rekor_url) {
        config.url = Some(url);
    }
    config.scitt_format =
        normalize_optional_string(file_config.scitt_format).map(|value| value.to_ascii_lowercase());
    config.log_public_key_pem = normalize_optional_string(file_config.log_public_key_pem);
    if let Some(path) = file_config.log_public_key_path {
        config.log_public_key_pem = Some(read_config_text_file(
            base_dir,
            &path,
            "transparency public key",
        )?);
    }

    validate_transparency_config(config).map(Some)
}

async fn apply_runtime_config_to_db(db: &SqlitePool, config: &VaultRuntimeConfig) -> Result<()> {
    for policy in &config.retention_policies {
        upsert_retention_policy(db, policy).await?;
        if policy.active {
            refresh_active_bundle_expiries_for_class(db, &policy.retention_class).await?;
        }
    }

    if let Some(timestamp) = config.timestamp_config.as_ref() {
        upsert_service_config(db, SERVICE_CONFIG_KEY_TIMESTAMP, timestamp).await?;
    }
    if let Some(transparency) = config.transparency_config.as_ref() {
        upsert_service_config(db, SERVICE_CONFIG_KEY_TRANSPARENCY, transparency).await?;
    }

    if !config.retention_policies.is_empty()
        || config.timestamp_config.is_some()
        || config.transparency_config.is_some()
    {
        append_audit_log(
            db,
            "startup_config_sync",
            Some(AUDIT_ACTOR_SYSTEM),
            None,
            None,
            serde_json::json!({
                "config_path": config.config_path.as_ref().map(|path| path.display().to_string()),
                "retention_classes": config
                    .retention_policies
                    .iter()
                    .map(|policy| policy.retention_class.clone())
                    .collect::<Vec<_>>(),
                "timestamp_seeded": config.timestamp_config.is_some(),
                "transparency_seeded": config.transparency_config.is_some(),
            }),
        )
        .await?;
    }

    Ok(())
}

fn maybe_spawn_retention_scan_task(state: AppState) {
    if state.retention_scan_interval_hours <= 0 {
        info!("background retention scan disabled");
        return;
    }

    let interval = Duration::from_secs(
        u64::try_from(state.retention_scan_interval_hours)
            .unwrap_or_default()
            .saturating_mul(60 * 60),
    );
    info!(
        "background retention scan enabled every {} hour(s)",
        state.retention_scan_interval_hours
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match perform_retention_scan(&state).await {
                Ok(result) => info!(
                    "background retention scan soft_deleted={} hard_deleted={} held_skipped={}",
                    result.soft_deleted, result.hard_deleted, result.held_skipped
                ),
                Err(err) => error!("background retention scan failed: {err:#}"),
            }
        }
    });
}

fn maybe_spawn_backup_task(state: AppState) {
    if state.backup_interval_hours <= 0 {
        info!("background backup export disabled");
        return;
    }

    let interval = Duration::from_secs(
        u64::try_from(state.backup_interval_hours)
            .unwrap_or_default()
            .saturating_mul(60 * 60),
    );
    info!(
        "background backup export enabled every {} hour(s), keeping {} archive(s)",
        state.backup_interval_hours, state.backup_retention_count
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match perform_scheduled_backup(&state).await {
                Ok(result) => info!(
                    "background backup export created={} pruned={}",
                    result.file_name, result.pruned_count
                ),
                Err(err) => error!("background backup export failed: {err:#}"),
            }
        }
    });
}

async fn require_api_key_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(auth_config) = state.auth_config.as_ref() else {
        return next.run(request).await;
    };

    match authenticate_request(request.headers(), auth_config) {
        Ok(actor) => {
            request.extensions_mut().insert(actor);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

fn authenticate_request(
    headers: &HeaderMap,
    auth_config: &RuntimeAuthConfig,
) -> Result<AuthenticatedActor, ApiError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;

    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized("authorization header must use Bearer"))?;

    let principal = auth_config
        .principals
        .iter()
        .find(|principal| principal.key == token)
        .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;

    Ok(AuthenticatedActor {
        label: principal.label.clone(),
    })
}

fn request_actor_label(actor: &Option<Extension<AuthenticatedActor>>) -> &str {
    actor
        .as_ref()
        .map(|actor| actor.0.label.as_str())
        .unwrap_or(AUDIT_ACTOR_API)
}

async fn validate_existing_bundle_organization_scope(
    db: &SqlitePool,
    tenant_organization_id: Option<&str>,
) -> Result<()> {
    let Some(tenant_organization_id) = tenant_organization_id else {
        return Ok(());
    };

    let mismatch: Option<(String, String)> = sqlx::query_as(
        "SELECT bundle_id, actor_org_id
         FROM bundles
         WHERE actor_org_id IS NOT NULL
           AND actor_org_id <> ?
         ORDER BY bundle_id ASC
         LIMIT 1",
    )
    .bind(tenant_organization_id)
    .fetch_optional(db)
    .await
    .context("failed to validate existing bundle organization scope")?;

    if let Some((bundle_id, actor_org_id)) = mismatch {
        bail!(
            "bundle {bundle_id} is scoped to organization_id={actor_org_id}, which conflicts with tenant.organization_id={tenant_organization_id}"
        );
    }

    Ok(())
}

fn build_tenant_scoped_capture(
    capture: SealableCaptureInput,
    tenant_organization_id: Option<&str>,
) -> Result<CaptureEvent> {
    let mut event = match capture {
        SealableCaptureInput::V10(event) => event,
        SealableCaptureInput::Legacy(capture) => {
            proof_layer_core::capture_input_v01_to_event(capture)
        }
    };

    let actor_org_id = normalize_optional_string(event.actor.organization_id.take());
    if let Some(tenant_organization_id) = tenant_organization_id {
        if let Some(actor_org_id) = actor_org_id {
            if actor_org_id != tenant_organization_id {
                bail!(
                    "capture actor.organization_id={} does not match tenant.organization_id={tenant_organization_id}",
                    actor_org_id
                );
            }
            event.actor.organization_id = Some(actor_org_id);
        } else {
            event.actor.organization_id = Some(tenant_organization_id.to_string());
        }
    } else {
        event.actor.organization_id = actor_org_id;
    }

    Ok(event)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    Ok((StatusCode::OK, "ok"))
}

async fn metrics(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let snapshot = load_vault_metrics_snapshot(&state)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let body = render_prometheus_metrics(&state, &snapshot);
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

async fn load_vault_metrics_snapshot(state: &AppState) -> Result<VaultMetricsSnapshot> {
    let now = Utc::now().to_rfc3339();
    let (
        bundle_total,
        bundle_active,
        bundle_deleted,
        bundle_held,
        bundle_timestamped,
        bundle_receipted,
    ): (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) AS bundle_total,
            COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS bundle_active,
            COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS bundle_deleted,
            COALESCE(SUM(CASE
                WHEN legal_hold_reason IS NOT NULL
                 AND (legal_hold_until IS NULL OR legal_hold_until > ?)
                THEN 1 ELSE 0 END), 0) AS bundle_held,
            COALESCE(SUM(CASE WHEN has_timestamp = 1 THEN 1 ELSE 0 END), 0) AS bundle_timestamped,
            COALESCE(SUM(CASE WHEN has_receipt = 1 THEN 1 ELSE 0 END), 0) AS bundle_receipted
         FROM bundles",
    )
    .bind(&now)
    .fetch_one(&state.db)
    .await
    .context("failed to load bundle metrics snapshot")?;

    let pack_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM packs")
        .fetch_one(&state.db)
        .await
        .context("failed to load pack metrics snapshot")?;
    let audit_log_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&state.db)
        .await
        .context("failed to load audit metrics snapshot")?;
    let retention_policy_total = load_retention_policies(&state.db).await?.len() as i64;
    let disclosure_policy_total = load_disclosure_config(&state.db).await?.policies.len() as i64;

    Ok(VaultMetricsSnapshot {
        bundle_total,
        bundle_active,
        bundle_deleted,
        bundle_held,
        bundle_timestamped,
        bundle_receipted,
        pack_total,
        audit_log_total,
        retention_policy_total,
        disclosure_policy_total,
    })
}

fn render_prometheus_metrics(state: &AppState, snapshot: &VaultMetricsSnapshot) -> String {
    let mut body = String::new();
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_up",
        "Whether the vault process is up.",
        1,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_tls_enabled",
        "Whether HTTPS is enabled on the vault listener.",
        bool_to_metric_value(state.tls_enabled),
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_auth_enabled",
        "Whether bearer API-key auth is enabled for /v1 routes.",
        bool_to_metric_value(state.auth_config.is_some()),
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_tenant_enforced",
        "Whether single-tenant organization enforcement is enabled.",
        bool_to_metric_value(state.tenant_organization_id.is_some()),
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_max_payload_bytes",
        "Configured maximum request payload size in bytes.",
        state.max_payload_bytes as i64,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_retention_scan_interval_hours",
        "Configured retention scan interval in hours.",
        state.retention_scan_interval_hours,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_total",
        "Total stored bundles, including soft-deleted rows.",
        snapshot.bundle_total,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_active",
        "Stored bundles that are not soft-deleted.",
        snapshot.bundle_active,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_deleted",
        "Stored bundles that are soft-deleted.",
        snapshot.bundle_deleted,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_held",
        "Stored bundles currently under legal hold.",
        snapshot.bundle_held,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_timestamped",
        "Stored bundles with an attached RFC 3161 timestamp token.",
        snapshot.bundle_timestamped,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_bundle_receipted",
        "Stored bundles with an attached transparency receipt.",
        snapshot.bundle_receipted,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_pack_total",
        "Total assembled evidence packs.",
        snapshot.pack_total,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_audit_log_total",
        "Total append-only audit log rows.",
        snapshot.audit_log_total,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_retention_policy_total",
        "Configured retention policy count.",
        snapshot.retention_policy_total,
    );
    write_prometheus_gauge(
        &mut body,
        "proof_layer_vault_disclosure_policy_total",
        "Configured disclosure policy count.",
        snapshot.disclosure_policy_total,
    );
    body
}

fn write_prometheus_gauge(body: &mut String, name: &str, help: &str, value: i64) {
    body.push_str("# HELP ");
    body.push_str(name);
    body.push(' ');
    body.push_str(help);
    body.push('\n');
    body.push_str("# TYPE ");
    body.push_str(name);
    body.push_str(" gauge\n");
    body.push_str(name);
    body.push(' ');
    body.push_str(&value.to_string());
    body.push('\n');
}

fn bool_to_metric_value(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

async fn export_backup(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, ApiError> {
    let backup_export = create_vault_backup_archive(&state)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "export_backup",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "backup_id": backup_export.backup_id,
            "file_name": backup_export.file_name,
            "bytes": backup_export.archive_bytes.len(),
            "bundle_total": backup_export.manifest.metrics.bundle_total,
            "pack_total": backup_export.manifest.metrics.pack_total,
            "encrypted": backup_export.encrypted,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        [
            (
                header::CONTENT_TYPE,
                if backup_export.encrypted {
                    "application/octet-stream".to_string()
                } else {
                    "application/gzip".to_string()
                },
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", backup_export.file_name),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (
                header::HeaderName::from_static("x-proof-layer-backup-encrypted"),
                if backup_export.encrypted {
                    "true"
                } else {
                    "false"
                }
                .to_string(),
            ),
        ],
        backup_export.archive_bytes,
    ))
}

struct VaultBackupArchive {
    backup_id: String,
    file_name: String,
    archive_bytes: Vec<u8>,
    manifest: VaultBackupManifest,
    encrypted: bool,
}

async fn create_vault_backup_archive(state: &AppState) -> Result<VaultBackupArchive> {
    let backup_id = generate_bundle_id();
    let created_at = Utc::now().to_rfc3339();
    let metrics = load_vault_metrics_snapshot(state).await?;
    let manifest = VaultBackupManifest {
        format: VAULT_BACKUP_FORMAT.to_string(),
        backup_id: backup_id.clone(),
        created_at,
        metrics,
    };
    let config = build_vault_config_response(state).await?;
    let snapshot_dir = std::env::temp_dir().join(format!("proof-layer-backup-{backup_id}"));
    fs::create_dir_all(&snapshot_dir).with_context(|| {
        format!(
            "failed to create backup temp dir {}",
            snapshot_dir.display()
        )
    })?;
    let snapshot_db_path = snapshot_dir.join("metadata.db");
    snapshot_sqlite_database(&state.db, &snapshot_db_path).await?;

    let archive_result = build_backup_archive_bytes(
        &manifest,
        &config,
        &snapshot_db_path,
        &state.storage_dir,
        &state.db_path,
        &state.backup_dir,
    );

    match fs::remove_dir_all(&snapshot_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "failed to remove backup temp dir {}",
                snapshot_dir.display()
            )));
        }
    }

    let mut archive_bytes = archive_result?;
    let encrypted = state.backup_encryption.is_some();
    if let Some(encryption) = state.backup_encryption.as_ref() {
        archive_bytes = encrypt_backup_archive(
            &archive_bytes,
            encryption.key.as_ref(),
            Some(&encryption.key_id),
        )
        .map_err(|err| anyhow::anyhow!("failed to encrypt backup archive: {err}"))?;
    }

    let file_name = if encrypted {
        format!("proof-layer-vault-backup-{backup_id}.tar.gz.enc")
    } else {
        format!("proof-layer-vault-backup-{backup_id}.tar.gz")
    };
    Ok(VaultBackupArchive {
        backup_id,
        file_name,
        archive_bytes,
        manifest,
        encrypted,
    })
}

async fn perform_scheduled_backup(state: &AppState) -> Result<ScheduledBackupResult> {
    fs::create_dir_all(&state.backup_dir).with_context(|| {
        format!(
            "failed to create scheduled backup dir {}",
            state.backup_dir.display()
        )
    })?;

    let backup_export = create_vault_backup_archive(state).await?;
    let archive_path = state.backup_dir.join(&backup_export.file_name);
    persist_backup_archive(&archive_path, &backup_export.archive_bytes)?;
    let pruned_count = prune_backup_archives(&state.backup_dir, state.backup_retention_count)?;

    append_audit_log(
        &state.db,
        "scheduled_backup",
        Some(AUDIT_ACTOR_SYSTEM),
        None,
        None,
        serde_json::json!({
            "backup_id": backup_export.backup_id,
            "file_name": backup_export.file_name,
            "path": archive_path.display().to_string(),
            "bytes": backup_export.archive_bytes.len(),
            "bundle_total": backup_export.manifest.metrics.bundle_total,
            "pack_total": backup_export.manifest.metrics.pack_total,
            "encrypted": backup_export.encrypted,
            "pruned_count": pruned_count,
        }),
    )
    .await?;

    Ok(ScheduledBackupResult {
        file_name: backup_export.file_name,
        pruned_count,
    })
}

async fn snapshot_sqlite_database(db: &SqlitePool, destination: &FsPath) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create sqlite snapshot dir {}", parent.display())
        })?;
    }
    match fs::remove_file(destination) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "failed to clear sqlite snapshot destination {}",
                destination.display()
            )));
        }
    }

    let escaped_path = destination.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{escaped_path}'"))
        .execute(db)
        .await
        .with_context(|| {
            format!(
                "failed to create sqlite snapshot at {}",
                destination.display()
            )
        })?;
    Ok(())
}

fn build_backup_archive_bytes(
    manifest: &VaultBackupManifest,
    config: &VaultConfigResponse,
    snapshot_db_path: &FsPath,
    storage_dir: &FsPath,
    db_path: &FsPath,
    backup_dir: &FsPath,
) -> Result<Vec<u8>> {
    let mut builder = TarBuilder::new(GzEncoder::new(Vec::new(), Compression::default()));

    let manifest_json = serde_json::to_vec_pretty(manifest)?;
    append_bytes_to_tar(&mut builder, "manifest.json", &manifest_json)?;

    let config_json = serde_json::to_vec_pretty(config)?;
    append_bytes_to_tar(&mut builder, "config/vault_config.json", &config_json)?;

    append_path_to_tar(&mut builder, snapshot_db_path, "metadata/metadata.db")?;
    append_directory_to_tar(
        &mut builder,
        storage_dir,
        storage_dir,
        "storage",
        &[db_path, backup_dir],
    )?;

    let encoder = builder
        .into_inner()
        .context("failed to finish tar archive")?;
    encoder
        .finish()
        .context("failed to finish backup gzip stream")
}

fn persist_backup_archive(path: &FsPath, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| FsPath::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create backup dir {}", parent.display()))?;

    let tmp_path = path.with_extension(format!("tmp-{}", generate_bundle_id()));
    let mut file = File::create(&tmp_path)
        .with_context(|| format!("failed to create temp backup {}", tmp_path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write temp backup {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temp backup {}", tmp_path.display()))?;

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to atomically rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn append_bytes_to_tar<W: Write>(
    builder: &mut TarBuilder<W>,
    archive_path: &str,
    bytes: &[u8],
) -> Result<()> {
    let mut header = TarHeader::new_gnu();
    header.set_mode(0o644);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, archive_path, std::io::Cursor::new(bytes))
        .with_context(|| format!("failed to append {archive_path} to backup archive"))?;
    Ok(())
}

fn append_path_to_tar<W: Write>(
    builder: &mut TarBuilder<W>,
    source_path: &FsPath,
    archive_path: &str,
) -> Result<()> {
    builder
        .append_path_with_name(source_path, archive_path)
        .with_context(|| {
            format!(
                "failed to append {} as {archive_path} to backup archive",
                source_path.display()
            )
        })?;
    Ok(())
}

fn append_directory_to_tar<W: Write>(
    builder: &mut TarBuilder<W>,
    root_dir: &FsPath,
    current_dir: &FsPath,
    archive_prefix: &str,
    exclude_paths: &[&FsPath],
) -> Result<()> {
    let mut entries = fs::read_dir(current_dir)
        .with_context(|| format!("failed to read backup dir {}", current_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list backup dir {}", current_dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if should_exclude_backup_path(&path, exclude_paths) {
            continue;
        }
        if path.is_dir() {
            append_directory_to_tar(builder, root_dir, &path, archive_prefix, exclude_paths)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root_dir)
            .with_context(|| format!("failed to relativize {}", path.display()))?;
        let archive_path = format!(
            "{archive_prefix}/{}",
            relative.to_string_lossy().replace('\\', "/")
        );
        append_path_to_tar(builder, &path, &archive_path)?;
    }

    Ok(())
}

fn should_exclude_backup_path(path: &FsPath, exclude_paths: &[&FsPath]) -> bool {
    exclude_paths
        .iter()
        .any(|exclude| path == *exclude || path.starts_with(exclude))
}

fn prune_backup_archives(backup_dir: &FsPath, keep_count: usize) -> Result<usize> {
    let mut archives = fs::read_dir(backup_dir)
        .with_context(|| format!("failed to read backup dir {}", backup_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list backup dir {}", backup_dir.display()))?
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            let file_name = path.file_name()?.to_str()?;
            (path.is_file()
                && file_name.starts_with("proof-layer-vault-backup-")
                && (file_name.ends_with(".tar.gz") || file_name.ends_with(".tar.gz.enc")))
            .then_some((file_name.to_string(), path))
        })
        .collect::<Vec<_>>();
    archives.sort_by(|left, right| right.0.cmp(&left.0));

    let mut pruned_count = 0usize;
    for (_, path) in archives.into_iter().skip(keep_count) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove old backup {}", path.display()))?;
        pruned_count += 1;
    }

    Ok(pruned_count)
}

async fn create_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<CreateBundleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if request.artefacts.is_empty() {
        return Err(ApiError::bad_request("artefacts must not be empty"));
    }

    let mut artefacts = Vec::with_capacity(request.artefacts.len());
    for artefact in request.artefacts {
        validate_artefact_name(&artefact.name).map_err(ApiError::bad_request_anyhow)?;
        let bytes = Base64::decode_vec(&artefact.data_base64)
            .map_err(|err| ApiError::bad_request(format!("invalid base64 artefact data: {err}")))?;
        if bytes.len() > state.max_payload_bytes {
            return Err(ApiError::bad_request(format!(
                "artefact {} is {} bytes and exceeds max {} bytes",
                artefact.name,
                bytes.len(),
                state.max_payload_bytes
            )));
        }

        artefacts.push(ArtefactInput {
            name: artefact.name,
            content_type: artefact.content_type,
            bytes,
        });
    }

    let capture =
        build_tenant_scoped_capture(request.capture, state.tenant_organization_id.as_deref())
            .map_err(ApiError::bad_request_anyhow)?;
    let bundle_id = generate_bundle_id();
    let bundle = build_bundle(
        capture,
        &artefacts,
        &state.signing_key,
        &state.signing_kid,
        &bundle_id,
        Utc::now(),
    )
    .map_err(map_build_bundle_error)?;

    resolve_bundle_expiry(&state.db, &bundle)
        .await
        .map_err(ApiError::bad_request_anyhow)?;
    persist_artefacts(&state.storage_dir, &bundle_id, &artefacts)
        .map_err(ApiError::internal_anyhow)?;
    persist_bundle_metadata(&state.db, &state.storage_dir, &bundle)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "create_bundle",
        Some(request_actor_label(&actor)),
        Some(&bundle.bundle_id),
        None,
        serde_json::json!({
            "artefact_count": bundle.artefacts.len(),
            "item_count": bundle.items.len(),
            "retention_class": bundle.policy.retention_class.clone().unwrap_or_else(|| "unspecified".to_string()),
            "system_id": bundle.subject.system_id.clone(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateBundleResponse {
            bundle_id: bundle.bundle_id.clone(),
            bundle_root: bundle.integrity.bundle_root.clone(),
            signature: bundle.integrity.signature.value.clone(),
            created_at: bundle.created_at.clone(),
        }),
    ))
}

async fn list_bundles(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Query(query): Query<BundleQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let now = Utc::now().to_rfc3339();
    let assurance_level = normalize_assurance_level_filter(query.assurance_level.as_deref())
        .map_err(ApiError::bad_request_anyhow)?;
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = i64::from((page - 1) * limit);

    let mut builder = QueryBuilder::<Sqlite>::new(
        "SELECT DISTINCT \
            b.bundle_id, \
            b.bundle_version, \
            b.created_at, \
            b.actor_role, \
            b.system_id, \
            b.model_id, \
            b.bundle_root, \
            b.signature_alg, \
            b.retention_class, \
            b.expires_at, \
            CASE WHEN b.legal_hold_reason IS NOT NULL AND (b.legal_hold_until IS NULL OR b.legal_hold_until > ",
    );
    builder.push_bind(&now);
    builder.push(
        ") THEN TRUE ELSE FALSE END AS has_legal_hold, \
            b.has_timestamp, \
            b.has_receipt, \
            CASE \
                WHEN b.has_receipt THEN 'transparency_anchored' \
                WHEN b.has_timestamp THEN 'timestamped' \
                ELSE 'signed' \
            END AS assurance_level \
         FROM bundles b ",
    );

    if query.item_type.is_some() {
        builder.push(" JOIN evidence_items i ON i.bundle_id = b.bundle_id ");
    }

    builder.push(" WHERE b.deleted_at IS NULL ");

    if let Some(system_id) = query.system_id.as_deref() {
        builder.push(" AND b.system_id = ");
        builder.push_bind(system_id);
    }
    if let Some(role) = query.role.as_deref() {
        builder.push(" AND b.actor_role = ");
        builder.push_bind(role);
    }
    if let Some(item_type) = query.item_type.as_deref() {
        builder.push(" AND i.item_type = ");
        builder.push_bind(item_type);
    }
    if let Some(has_timestamp) = query.has_timestamp {
        builder.push(" AND b.has_timestamp = ");
        builder.push_bind(has_timestamp);
    }
    if let Some(has_receipt) = query.has_receipt {
        builder.push(" AND b.has_receipt = ");
        builder.push_bind(has_receipt);
    }
    if let Some(assurance_level) = assurance_level.as_deref() {
        builder.push(
            " AND CASE \
                WHEN b.has_receipt THEN 'transparency_anchored' \
                WHEN b.has_timestamp THEN 'timestamped' \
                ELSE 'signed' \
            END = ",
        );
        builder.push_bind(assurance_level);
    }
    if let Some(from) = query.from.as_deref() {
        builder.push(" AND b.created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = query.to.as_deref() {
        builder.push(" AND b.created_at <= ");
        builder.push_bind(to);
    }

    builder.push(" ORDER BY b.created_at DESC, b.bundle_id DESC LIMIT ");
    builder.push_bind(i64::from(limit));
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let items = builder
        .build_query_as::<BundleSummary>()
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "list_bundles",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "page": page,
            "limit": limit,
            "result_count": items.len(),
            "filters": {
                "system_id": query.system_id,
                "role": query.role,
                "item_type": query.item_type,
                "has_timestamp": query.has_timestamp,
                "has_receipt": query.has_receipt,
                "assurance_level": assurance_level,
                "from": query.from,
                "to": query.to,
            }
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(ListBundlesResponse { page, limit, items }),
    ))
}

async fn retention_status(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, ApiError> {
    let now = Utc::now().to_rfc3339();
    let hard_delete_before =
        (Utc::now() - chrono::Duration::days(state.retention_grace_period_days)).to_rfc3339();
    let rows = sqlx::query(
        "SELECT
            p.retention_class,
            p.expiry_mode,
            p.min_duration_days,
            p.max_duration_days,
            p.legal_basis,
            p.active,
            COUNT(b.bundle_id) AS total_bundles,
            COALESCE(SUM(CASE WHEN b.bundle_id IS NOT NULL AND b.deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS active_bundles,
            COALESCE(SUM(CASE WHEN b.bundle_id IS NOT NULL AND b.deleted_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS deleted_bundles,
            COALESCE(SUM(CASE WHEN b.bundle_id IS NOT NULL AND b.legal_hold_reason IS NOT NULL AND (b.legal_hold_until IS NULL OR b.legal_hold_until > ?) THEN 1 ELSE 0 END), 0) AS held_bundles,
            COALESCE(SUM(CASE WHEN b.bundle_id IS NOT NULL AND b.deleted_at IS NULL AND b.expires_at IS NOT NULL AND b.expires_at <= ? AND NOT (b.legal_hold_reason IS NOT NULL AND (b.legal_hold_until IS NULL OR b.legal_hold_until > ?)) THEN 1 ELSE 0 END), 0) AS expired_active_bundles,
            COALESCE(SUM(CASE WHEN b.bundle_id IS NOT NULL AND b.deleted_at IS NOT NULL AND b.deleted_at <= ? AND NOT (b.legal_hold_reason IS NOT NULL AND (b.legal_hold_until IS NULL OR b.legal_hold_until > ?)) THEN 1 ELSE 0 END), 0) AS hard_delete_ready_bundles,
            MIN(CASE WHEN b.bundle_id IS NOT NULL AND b.deleted_at IS NULL THEN b.expires_at END) AS next_expiry
         FROM retention_policies p
         LEFT JOIN bundles b ON b.retention_class = p.retention_class
         GROUP BY
            p.retention_class,
            p.min_duration_days,
            p.max_duration_days,
            p.legal_basis,
            p.active
         ORDER BY p.retention_class",
    )
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .bind(&hard_delete_before)
    .bind(&now)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::internal_anyhow)?;

    let mut policies = Vec::with_capacity(rows.len());
    for row in rows {
        policies.push(RetentionStatusItem {
            retention_class: row
                .try_get("retention_class")
                .map_err(ApiError::internal_anyhow)?,
            expiry_mode: parse_retention_expiry_mode(
                &row.try_get::<String, _>("expiry_mode")
                    .map_err(ApiError::internal_anyhow)?,
            )
            .map_err(ApiError::internal_anyhow)?,
            min_duration_days: row
                .try_get("min_duration_days")
                .map_err(ApiError::internal_anyhow)?,
            max_duration_days: row
                .try_get("max_duration_days")
                .map_err(ApiError::internal_anyhow)?,
            legal_basis: row
                .try_get("legal_basis")
                .map_err(ApiError::internal_anyhow)?,
            active: row.try_get("active").map_err(ApiError::internal_anyhow)?,
            total_bundles: row
                .try_get("total_bundles")
                .map_err(ApiError::internal_anyhow)?,
            active_bundles: row
                .try_get("active_bundles")
                .map_err(ApiError::internal_anyhow)?,
            deleted_bundles: row
                .try_get("deleted_bundles")
                .map_err(ApiError::internal_anyhow)?,
            held_bundles: row
                .try_get("held_bundles")
                .map_err(ApiError::internal_anyhow)?,
            expired_active_bundles: row
                .try_get("expired_active_bundles")
                .map_err(ApiError::internal_anyhow)?,
            hard_delete_ready_bundles: row
                .try_get("hard_delete_ready_bundles")
                .map_err(ApiError::internal_anyhow)?,
            next_expiry: row
                .try_get("next_expiry")
                .map_err(ApiError::internal_anyhow)?,
        });
    }

    append_audit_log(
        &state.db,
        "retention_status",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "policy_count": policies.len(),
            "grace_period_days": state.retention_grace_period_days,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(RetentionStatusResponse {
            scanned_at: now,
            grace_period_days: state.retention_grace_period_days,
            policies,
        }),
    ))
}

async fn retention_scan(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let response = perform_retention_scan(&state)
        .await
        .map_err(ApiError::internal_anyhow)?;
    Ok((StatusCode::OK, Json(response)))
}

async fn perform_retention_scan(state: &AppState) -> Result<RetentionScanResponse> {
    let now = Utc::now().to_rfc3339();
    let hard_delete_before =
        (Utc::now() - chrono::Duration::days(state.retention_grace_period_days)).to_rfc3339();
    let held_skipped: i64 = sqlx::query_scalar(
        "SELECT COUNT(bundle_id)
         FROM bundles
         WHERE legal_hold_reason IS NOT NULL
           AND (legal_hold_until IS NULL OR legal_hold_until > ?)
           AND (
                (deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?)
                OR (deleted_at IS NOT NULL AND deleted_at <= ?)
           )",
    )
    .bind(&now)
    .bind(&now)
    .bind(&hard_delete_before)
    .fetch_one(&state.db)
    .await
    .context("failed to count legal-hold retention candidates")?;

    let soft_delete_result = sqlx::query(
        "UPDATE bundles
         SET deleted_at = ?
         WHERE deleted_at IS NULL
           AND expires_at IS NOT NULL
           AND expires_at <= ?
           AND NOT (
                legal_hold_reason IS NOT NULL
                AND (legal_hold_until IS NULL OR legal_hold_until > ?)
           )",
    )
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    .context("failed to soft-delete expired bundles")?;
    let hard_deleted = hard_delete_bundles(state, &hard_delete_before, &now).await?;
    append_audit_log(
        &state.db,
        "retention_scan",
        Some(AUDIT_ACTOR_SYSTEM),
        None,
        None,
        serde_json::json!({
            "grace_period_days": state.retention_grace_period_days,
            "soft_deleted": soft_delete_result.rows_affected(),
            "hard_deleted": hard_deleted,
            "held_skipped": held_skipped,
        }),
    )
    .await
    .context("failed to append retention scan audit row")?;

    Ok(RetentionScanResponse {
        scanned_at: now,
        grace_period_days: state.retention_grace_period_days,
        soft_deleted: soft_delete_result.rows_affected(),
        hard_deleted,
        held_skipped: held_skipped as u64,
    })
}

async fn list_audit_trail(
    State(state): State<AppState>,
    _actor: Option<Extension<AuthenticatedActor>>,
    Query(query): Query<AuditTrailQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = i64::from((page - 1) * limit);

    let mut builder = QueryBuilder::<Sqlite>::new(
        "SELECT
            id,
            timestamp,
            action,
            actor,
            bundle_id,
            pack_id,
            details_json
         FROM audit_log
         WHERE 1 = 1",
    );

    if let Some(action) = query.action.as_deref() {
        builder.push(" AND action = ");
        builder.push_bind(action);
    }
    if let Some(bundle_id) = query.bundle_id.as_deref() {
        builder.push(" AND bundle_id = ");
        builder.push_bind(bundle_id);
    }
    if let Some(pack_id) = query.pack_id.as_deref() {
        builder.push(" AND pack_id = ");
        builder.push_bind(pack_id);
    }

    builder.push(" ORDER BY id DESC LIMIT ");
    builder.push_bind(i64::from(limit));
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let rows = builder
        .build_query_as::<StoredAuditLogRow>()
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;

    let items = rows
        .into_iter()
        .map(map_audit_log_row)
        .collect::<Result<Vec<_>>>()
        .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(AuditTrailResponse { page, limit, items }),
    ))
}

async fn list_systems(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, ApiError> {
    let items = sqlx::query_as::<_, SystemListEntry>(
        "SELECT
            system_id,
            COUNT(bundle_id) AS bundle_count,
            COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS active_bundle_count,
            COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS deleted_bundle_count,
            MIN(created_at) AS first_seen_at,
            MAX(created_at) AS latest_bundle_at,
            COALESCE(SUM(CASE WHEN has_timestamp THEN 1 ELSE 0 END), 0) AS timestamped_bundle_count,
            COALESCE(SUM(CASE WHEN has_receipt THEN 1 ELSE 0 END), 0) AS receipt_bundle_count
         FROM bundles
         WHERE system_id IS NOT NULL
           AND TRIM(system_id) <> ''
         GROUP BY system_id
         ORDER BY latest_bundle_at DESC, system_id ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "list_systems",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "system_count": items.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(ListSystemsResponse { items })))
}

async fn get_system_summary(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(system_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let system_id = normalize_system_id_path(&system_id).map_err(ApiError::bad_request_anyhow)?;
    let base = load_system_summary_base(&state.db, &system_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("system not found"))?;
    let actor_roles = load_system_facet_counts(
        &state.db,
        &system_id,
        "SELECT
            actor_role AS value,
            COUNT(bundle_id) AS count
         FROM bundles
         WHERE system_id = ?
         GROUP BY actor_role
         ORDER BY count DESC, value ASC",
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    let evidence_types = load_system_facet_counts(
        &state.db,
        &system_id,
        "SELECT
            i.item_type AS value,
            COUNT(*) AS count
         FROM bundles b
         JOIN evidence_items i ON i.bundle_id = b.bundle_id
         WHERE b.system_id = ?
         GROUP BY i.item_type
         ORDER BY count DESC, value ASC",
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    let retention_classes = load_system_facet_counts(
        &state.db,
        &system_id,
        "SELECT
            retention_class AS value,
            COUNT(bundle_id) AS count
         FROM bundles
         WHERE system_id = ?
         GROUP BY retention_class
         ORDER BY count DESC, value ASC",
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    let assurance_levels = load_system_facet_counts(
        &state.db,
        &system_id,
        "SELECT
            CASE
                WHEN has_receipt THEN 'transparency_anchored'
                WHEN has_timestamp THEN 'timestamped'
                ELSE 'signed'
            END AS value,
            COUNT(bundle_id) AS count
         FROM bundles
         WHERE system_id = ?
         GROUP BY value
         ORDER BY count DESC, value ASC",
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    let model_ids = load_system_facet_counts(
        &state.db,
        &system_id,
        "SELECT
            COALESCE(model_id, 'unknown') AS value,
            COUNT(bundle_id) AS count
         FROM bundles
         WHERE system_id = ?
         GROUP BY value
         ORDER BY count DESC, value ASC",
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    let summary = SystemSummaryResponse {
        system_id: base.system_id.clone(),
        bundle_count: base.bundle_count,
        active_bundle_count: base.active_bundle_count,
        deleted_bundle_count: base.deleted_bundle_count,
        first_seen_at: base.first_seen_at,
        latest_bundle_at: base.latest_bundle_at,
        timestamped_bundle_count: base.timestamped_bundle_count,
        receipt_bundle_count: base.receipt_bundle_count,
        actor_roles,
        evidence_types,
        retention_classes,
        assurance_levels,
        model_ids,
    };

    append_audit_log(
        &state.db,
        "get_system_summary",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "system_id": summary.system_id,
            "bundle_count": summary.bundle_count,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(summary)))
}

async fn get_config(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, ApiError> {
    let response = build_vault_config_response(&state)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "get_config",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "retention_policy_count": response.retention.policies.len(),
            "disclosure_policy_count": response.disclosure.policies.len(),
            "demo_openai_live_enabled": response.demo.providers.openai.live_enabled,
            "demo_anthropic_live_enabled": response.demo.providers.anthropic.live_enabled,
            "grace_period_days": response.retention.grace_period_days,
            "scan_interval_hours": response.retention.scan_interval_hours,
            "backup_enabled": response.backup.enabled,
            "backup_interval_hours": response.backup.interval_hours,
            "backup_retention_count": response.backup.retention_count,
            "backup_encryption_enabled": response.backup.encryption.enabled,
            "backup_encryption_key_id": response.backup.encryption.key_id,
            "timestamp_enabled": response.timestamp.enabled,
            "timestamp_provider": &response.timestamp.provider,
            "transparency_enabled": response.transparency.enabled,
            "transparency_provider": &response.transparency.provider,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn update_retention_config(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<UpdateRetentionConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request =
        validate_update_retention_config_request(request).map_err(ApiError::bad_request_anyhow)?;

    for policy in &request.policies {
        upsert_retention_policy(&state.db, policy)
            .await
            .map_err(ApiError::internal_anyhow)?;
        if policy.active {
            refresh_active_bundle_expiries_for_class(&state.db, &policy.retention_class)
                .await
                .map_err(ApiError::internal_anyhow)?;
        }
    }

    let policies = load_retention_policies(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "update_retention_config",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "updated": request.policies.len(),
            "classes": request
                .policies
                .iter()
                .map(|policy| policy.retention_class.clone())
                .collect::<Vec<_>>(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(UpdateRetentionConfigResponse {
            updated: request.policies.len(),
            policies,
        }),
    ))
}

async fn update_timestamp_config(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<TimestampConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let config = validate_timestamp_config(request).map_err(ApiError::bad_request_anyhow)?;
    upsert_service_config(&state.db, SERVICE_CONFIG_KEY_TIMESTAMP, &config)
        .await
        .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "update_timestamp_config",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "enabled": config.enabled,
            "provider": &config.provider,
            "url": &config.url,
            "assurance": &config.assurance,
            "trust_anchor_count": config.trust_anchor_pems.len(),
            "crl_count": config.crl_pems.len(),
            "ocsp_url_count": config.ocsp_responder_urls.len(),
            "qualified_signer_count": config.qualified_signer_pems.len(),
            "policy_oid_count": config.policy_oids.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(config)))
}

async fn update_transparency_config(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<TransparencyConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let config = validate_transparency_config(request).map_err(ApiError::bad_request_anyhow)?;
    upsert_service_config(&state.db, SERVICE_CONFIG_KEY_TRANSPARENCY, &config)
        .await
        .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "update_transparency_config",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "enabled": config.enabled,
            "provider": &config.provider,
            "url": &config.url,
            "scitt_format": &config.scitt_format,
            "has_log_public_key": config.log_public_key_pem.is_some(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(config)))
}

async fn update_disclosure_config(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<DisclosureConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let config = validate_disclosure_config(request).map_err(ApiError::bad_request_anyhow)?;
    upsert_service_config(&state.db, SERVICE_CONFIG_KEY_DISCLOSURE, &config)
        .await
        .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "update_disclosure_config",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "policy_count": config.policies.len(),
            "policies": config
                .policies
                .iter()
                .map(|policy| policy.name.clone())
                .collect::<Vec<_>>(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(config)))
}

async fn generate_demo_provider_response(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<DemoProviderResponseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request =
        validate_demo_provider_response_request(request).map_err(ApiError::bad_request_anyhow)?;
    let provider_key_source = if request.provider_api_key.is_some() {
        "temporary_request"
    } else {
        "vault_config"
    };
    let response = match request.mode {
        DemoCaptureMode::Synthetic => build_synthetic_demo_provider_response(&request),
        DemoCaptureMode::Live => resolve_demo_provider_client(&state.demo_providers, &request)
            .map_err(ApiError::bad_request_anyhow)?
            .generate(&request)
            .await
            .map_err(ApiError::internal_anyhow)?,
    };

    append_audit_log(
        &state.db,
        "generate_demo_provider_response",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "mode": request.mode,
            "provider": request.provider,
            "model": request.model.clone(),
            "capture_mode": response.capture_mode.clone(),
            "provider_key_source": provider_key_source,
            "provider_request_id": response.provider_request_id.clone(),
            "total_tokens": response.usage.total_tokens,
            "latency_ms": response.latency_ms,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn list_disclosure_templates(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
) -> Result<impl IntoResponse, ApiError> {
    let response = disclosure_template_catalog().map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "list_disclosure_templates",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "template_count": response.templates.len(),
            "redaction_group_count": response.redaction_groups.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn render_disclosure_template(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<DisclosureTemplateRenderRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request = normalize_disclosure_template_render_request(request)
        .map_err(ApiError::bad_request_anyhow)?;
    let response =
        build_disclosure_template_response(&request).map_err(ApiError::bad_request_anyhow)?;

    append_audit_log(
        &state.db,
        "render_disclosure_template",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "profile": response.profile.clone(),
            "name": response.policy.name.clone(),
            "redaction_group_count": request.redaction_groups.len(),
            "redacted_item_type_count": request.redacted_fields_by_item_type.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn preview_disclosure(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<DisclosurePreviewRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request =
        normalize_disclosure_preview_request(request).map_err(ApiError::bad_request_anyhow)?;
    let bundle = load_active_bundle(&state.db, &request.bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;
    let default_policy_name = request
        .pack_type
        .as_deref()
        .map(default_disclosure_policy_name)
        .or(Some(DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM));
    let policy = resolve_named_or_inline_disclosure_policy(
        &state.db,
        request.disclosure_policy.as_deref(),
        request.policy,
        request.disclosure_template.as_ref(),
        default_policy_name,
    )
    .await
    .map_err(ApiError::bad_request_anyhow)?;
    let response =
        build_disclosure_preview_response(&bundle, request.pack_type.as_deref(), &policy)
            .map_err(ApiError::bad_request_anyhow)?;

    append_audit_log(
        &state.db,
        "preview_disclosure",
        Some(request_actor_label(&actor)),
        Some(&bundle.bundle_id),
        None,
        serde_json::json!({
            "pack_type": response.pack_type.clone(),
            "policy_name": response.policy_name.clone(),
            "disclosed_item_count": response.disclosed_item_indices.len(),
            "disclosed_artefact_count": response.disclosed_artefact_indices.len(),
            "disclosed_artefact_bytes_included": response.disclosed_artefact_bytes_included,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn evaluate_completeness_api(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<EvaluateCompletenessRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let EvaluateCompletenessRequest {
        bundle_id,
        pack_id,
        bundle,
        profile,
    } = request;
    let selection_count = usize::from(bundle_id.is_some())
        + usize::from(pack_id.is_some())
        + usize::from(bundle.is_some());
    if selection_count != 1 {
        return Err(ApiError::bad_request(
            "provide exactly one of bundle_id, bundle, or pack_id",
        ));
    }

    let (report, audit_bundle_id, audit_pack_id) = if let Some(pack_id) = pack_id {
        let row = load_pack_row(&state.db, &pack_id)
            .await
            .map_err(ApiError::internal_anyhow)?
            .ok_or_else(|| ApiError::not_found("pack not found"))?;
        let manifest = parse_pack_manifest(&row).map_err(ApiError::internal_anyhow)?;
        let pack_profile = manifest
            .pack_completeness_profile
            .ok_or_else(|| ApiError::conflict("pack does not have pack-scoped completeness"))?;
        if pack_profile != profile {
            return Err(ApiError::bad_request(
                "requested profile does not match pack completeness profile",
            ));
        }
        let report = parse_pack_completeness_report(&row)
            .map_err(ApiError::internal_anyhow)?
            .ok_or_else(|| {
                ApiError::conflict(
                    "pack-scoped completeness report unavailable for this pack; recreate the pack",
                )
            })?;
        (report, None, Some(pack_id))
    } else {
        let bundle = if let Some(bundle_id) = bundle_id.as_deref() {
            load_active_bundle(&state.db, bundle_id)
                .await
                .map_err(ApiError::internal_anyhow)?
                .ok_or_else(|| ApiError::not_found("bundle not found"))?
        } else {
            bundle.expect("selection_count ensures bundle is present")
        };
        let report = evaluate_completeness(&bundle, profile);
        (report, Some(bundle.bundle_id), None)
    };

    append_audit_log(
        &state.db,
        "evaluate_completeness",
        Some(request_actor_label(&actor)),
        audit_bundle_id.as_deref(),
        audit_pack_id.as_deref(),
        serde_json::json!({
            "profile": report.profile,
            "status": report.status,
            "pass_count": report.pass_count,
            "warn_count": report.warn_count,
            "fail_count": report.fail_count,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(report)))
}

fn build_pack_completeness_bundle(
    pack_id: &str,
    created_at: &str,
    requested_system_id: Option<&str>,
    curated_rows: &[CuratedPackBundle],
) -> ProofBundle {
    let first_bundle = &curated_rows
        .first()
        .expect("pack completeness requires at least one curated bundle")
        .bundle;
    let mut subject = first_bundle.subject.clone();
    if let Some(system_id) = requested_system_id {
        subject.system_id = Some(system_id.to_string());
    }

    ProofBundle {
        bundle_version: first_bundle.bundle_version.clone(),
        bundle_id: pack_id.to_string(),
        created_at: created_at.to_string(),
        actor: first_bundle.actor.clone(),
        subject,
        compliance_profile: curated_rows
            .iter()
            .find_map(|curated| curated.bundle.compliance_profile.clone()),
        context: EvidenceContext::default(),
        items: curated_rows
            .iter()
            .flat_map(|curated| curated.bundle.items.iter().cloned())
            .collect(),
        artefacts: curated_rows
            .iter()
            .flat_map(|curated| curated.bundle.artefacts.iter().cloned())
            .collect(),
        policy: Policy::default(),
        integrity: Integrity::default(),
        timestamp: None,
        receipt: None,
    }
}

fn parse_pack_completeness_report(row: &StoredPackRow) -> Result<Option<CompletenessReport>> {
    let Some(report_json) = row.pack_completeness_report_json.as_deref() else {
        return Ok(None);
    };
    let report: CompletenessReport = serde_json::from_str(report_json).with_context(|| {
        format!(
            "failed to parse pack completeness report for pack {}",
            row.pack_id
        )
    })?;
    if report.bundle_id != row.pack_id {
        bail!("pack completeness report id mismatch for {}", row.pack_id);
    }
    Ok(Some(report))
}

async fn delete_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_bundle_retention_row(&state.db, &bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;

    let now = Utc::now().to_rfc3339();
    if legal_hold_is_active(
        row.legal_hold_reason.as_deref(),
        row.legal_hold_until.as_deref(),
        &now,
    ) {
        return Err(ApiError::conflict(
            "bundle has an active legal hold and cannot be deleted",
        ));
    }

    let was_already_deleted = row.deleted_at.is_some();
    let deleted_at = if let Some(deleted_at) = row.deleted_at {
        deleted_at
    } else {
        sqlx::query("UPDATE bundles SET deleted_at = ? WHERE bundle_id = ?")
            .bind(&now)
            .bind(&bundle_id)
            .execute(&state.db)
            .await
            .map_err(ApiError::internal_anyhow)?;
        now
    };
    append_audit_log(
        &state.db,
        "delete_bundle",
        Some(request_actor_label(&actor)),
        Some(&bundle_id),
        None,
        serde_json::json!({
            "deleted_at": deleted_at.clone(),
            "was_already_deleted": was_already_deleted,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(DeleteBundleResponse {
            bundle_id,
            deleted_at,
        }),
    ))
}

async fn timestamp_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut bundle = load_active_bundle(&state.db, &bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;
    if bundle.timestamp.is_some() {
        return Err(ApiError::conflict("bundle already has a timestamp token"));
    }

    let config = load_timestamp_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    if !config.enabled {
        return Err(ApiError::conflict(
            "timestamping is disabled in vault config",
        ));
    }

    let bundle_root = bundle.integrity.bundle_root.clone();
    let provider =
        Rfc3161HttpTimestampProvider::with_label(config.url.clone(), config.provider.clone());
    let token = tokio::task::spawn_blocking(move || timestamp_digest(&bundle_root, &provider))
        .await
        .map_err(ApiError::internal_anyhow)?
        .map_err(ApiError::internal_anyhow)?;
    let timestamp_policy = timestamp_trust_policy(&config);

    let verification =
        apply_timestamp_token_to_bundle(&mut bundle, token, timestamp_policy.as_ref())
            .map_err(ApiError::internal_anyhow)?;
    persist_bundle_timestamp(&state.db, &bundle)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "timestamp_bundle",
        Some(request_actor_label(&actor)),
        Some(&bundle.bundle_id),
        None,
        serde_json::json!({
            "kind": bundle.timestamp.as_ref().map(|token| token.kind.clone()),
            "provider": bundle.timestamp.as_ref().and_then(|token| token.provider.clone()),
            "generated_at": verification.generated_at,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    let timestamp = bundle
        .timestamp
        .as_ref()
        .expect("timestamp was just applied");
    Ok((
        StatusCode::OK,
        Json(TimestampBundleResponse {
            bundle_id: bundle.bundle_id,
            kind: timestamp.kind.clone(),
            provider: timestamp.provider.clone(),
            generated_at: verification.generated_at,
        }),
    ))
}

async fn anchor_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut bundle = load_active_bundle(&state.db, &bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;
    if bundle.receipt.is_some() {
        return Err(ApiError::conflict(
            "bundle already has a transparency receipt",
        ));
    }
    if bundle.timestamp.is_none() {
        return Err(ApiError::conflict(
            "bundle must be timestamped before transparency anchoring",
        ));
    }

    let config = load_transparency_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let timestamp_config = load_timestamp_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    if !config.enabled {
        return Err(ApiError::conflict(
            "transparency anchoring is disabled in vault config",
        ));
    }

    let receipt = match config.provider.as_str() {
        "rekor" => {
            let url = config.url.clone().ok_or_else(|| {
                ApiError::internal_anyhow(anyhow::anyhow!(
                    "transparency config enabled for rekor without url"
                ))
            })?;
            let provider_label = config.provider.clone();
            let bundle_for_submission = bundle.clone();
            tokio::task::spawn_blocking(move || {
                let provider = RekorTransparencyProvider::with_label(url, provider_label);
                anchor_bundle_receipt(&bundle_for_submission, &provider)
            })
            .await
            .map_err(ApiError::internal_anyhow)?
            .map_err(ApiError::internal_anyhow)?
        }
        "scitt" => {
            let url = config.url.clone().ok_or_else(|| {
                ApiError::internal_anyhow(anyhow::anyhow!(
                    "transparency config enabled for scitt without url"
                ))
            })?;
            let provider_label = config.provider.clone();
            let scitt_format = parse_scitt_format(config.scitt_format.as_deref());
            let bundle_for_submission = bundle.clone();
            let signing_key = state.signing_key.clone();
            let signing_kid = state.signing_kid.clone();
            tokio::task::spawn_blocking(move || {
                let provider = ScittTransparencyProvider::with_statement_signer(
                    url,
                    provider_label,
                    scitt_format,
                    ScittStatementSigner {
                        signing_key,
                        key_id: signing_kid,
                    },
                );
                anchor_bundle_receipt(&bundle_for_submission, &provider)
            })
            .await
            .map_err(ApiError::internal_anyhow)?
            .map_err(ApiError::internal_anyhow)?
        }
        _ => {
            return Err(ApiError::conflict(
                "transparency anchoring is disabled in vault config",
            ));
        }
    };
    let transparency_policy = transparency_trust_policy(&config, &timestamp_config);

    let verification = apply_receipt_to_bundle(&mut bundle, receipt, transparency_policy.as_ref())
        .map_err(ApiError::internal_anyhow)?;
    persist_bundle_receipt(&state.db, &bundle)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "anchor_bundle",
        Some(request_actor_label(&actor)),
        Some(&bundle.bundle_id),
        None,
        serde_json::json!({
            "kind": bundle.receipt.as_ref().map(|receipt| receipt.kind.clone()),
            "provider": bundle.receipt.as_ref().and_then(|receipt| receipt.provider.clone()),
            "entry_uuid": verification.entry_uuid,
            "integrated_time": verification.integrated_time,
            "log_index": verification.log_index,
            "log_url": verification.log_url,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    let receipt = bundle.receipt.as_ref().expect("receipt was just applied");
    Ok((
        StatusCode::OK,
        Json(AnchorBundleResponse {
            bundle_id: bundle.bundle_id,
            kind: receipt.kind.clone(),
            provider: receipt.provider.clone(),
            entry_uuid: verification.entry_uuid,
            integrated_time: verification.integrated_time,
            log_index: verification.log_index,
        }),
    ))
}

async fn set_legal_hold(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
    Json(request): Json<LegalHoldRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_bundle_retention_row(&state.db, &bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;

    let now = Utc::now().to_rfc3339();
    let reason =
        normalize_legal_hold_reason(&request.reason).map_err(ApiError::bad_request_anyhow)?;
    let until = normalize_legal_hold_until(request.until.as_deref(), &now)
        .map_err(ApiError::bad_request_anyhow)?;

    sqlx::query(
        "UPDATE bundles
         SET legal_hold_reason = ?,
             legal_hold_until = ?,
             legal_hold_placed_at = ?
         WHERE bundle_id = ?",
    )
    .bind(&reason)
    .bind(until.as_deref())
    .bind(&now)
    .bind(&bundle_id)
    .execute(&state.db)
    .await
    .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "set_legal_hold",
        Some(request_actor_label(&actor)),
        Some(&bundle_id),
        None,
        serde_json::json!({
            "reason": reason.clone(),
            "until": until.clone(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(LegalHoldResponse {
            bundle_id: row.bundle_id,
            active: true,
            reason: Some(reason),
            placed_at: Some(now),
            until,
        }),
    ))
}

async fn release_legal_hold(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_bundle_retention_row(&state.db, &bundle_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("bundle not found"))?;

    sqlx::query(
        "UPDATE bundles
         SET legal_hold_reason = NULL,
             legal_hold_until = NULL,
             legal_hold_placed_at = NULL
         WHERE bundle_id = ?",
    )
    .bind(&bundle_id)
    .execute(&state.db)
    .await
    .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "release_legal_hold",
        Some(request_actor_label(&actor)),
        Some(&bundle_id),
        None,
        serde_json::json!({
            "had_active_hold": legal_hold_is_active(
                row.legal_hold_reason.as_deref(),
                row.legal_hold_until.as_deref(),
                &Utc::now().to_rfc3339(),
            ),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((
        StatusCode::OK,
        Json(LegalHoldResponse {
            bundle_id: row.bundle_id,
            active: false,
            reason: None,
            placed_at: None,
            until: None,
        }),
    ))
}

async fn create_pack(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<CreatePackRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request = normalize_create_pack_request(request).map_err(ApiError::bad_request_anyhow)?;
    let profile = pack_profile(&request.pack_type).map_err(ApiError::bad_request_anyhow)?;
    let disclosure_policy = resolve_pack_disclosure_policy(&state.db, &request)
        .await
        .map_err(ApiError::bad_request_anyhow)?;
    let rows = query_pack_source_bundles(&state.db, &request)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let curated_rows = curate_pack_bundles(&profile, rows, disclosure_policy.as_ref())
        .map_err(ApiError::internal_anyhow)?;

    if curated_rows.is_empty() {
        return Err(ApiError::bad_request(
            "pack query matched no bundles after curation/disclosure rules",
        ));
    }

    let pack_id = generate_bundle_id();
    let created_at = Utc::now().to_rfc3339();
    let disclosure_policy_name = disclosure_policy.as_ref().map(|policy| policy.name.clone());
    let completeness_profile = bundle_completeness_profile_for_pack(&request.pack_type);
    let pack_completeness_profile = pack_completeness_profile_for_pack(&request.pack_type);
    let manifest_system_id = request
        .system_id
        .clone()
        .or_else(|| infer_curated_system_id(&curated_rows));
    let pack_completeness_report = pack_completeness_profile.map(|profile| {
        let bundle = build_pack_completeness_bundle(
            &pack_id,
            &created_at,
            manifest_system_id.as_deref(),
            &curated_rows,
        );
        evaluate_completeness(&bundle, profile)
    });
    let mut completeness_pass_count = 0usize;
    let mut completeness_warn_count = 0usize;
    let mut completeness_fail_count = 0usize;
    let mut bundle_ids = Vec::with_capacity(curated_rows.len());
    let mut bundle_entries = Vec::with_capacity(curated_rows.len());
    let mut files = Vec::with_capacity(curated_rows.len());

    for curated in curated_rows {
        let completeness_status = completeness_profile.map(|profile| {
            let report = evaluate_completeness(&curated.bundle, profile);
            match report.status {
                CompletenessStatus::Pass => completeness_pass_count += 1,
                CompletenessStatus::Warn => completeness_warn_count += 1,
                CompletenessStatus::Fail => completeness_fail_count += 1,
            }
            report.status
        });
        let package_name = pack_bundle_file_name(&curated.row.bundle_id, &request.bundle_format);
        let package_bytes = match request.bundle_format.as_str() {
            PACK_BUNDLE_FORMAT_FULL => {
                let artefacts = load_pack_artefacts(&state.db, &curated.bundle.bundle_id)
                    .await
                    .map_err(ApiError::internal_anyhow)?;
                build_bundle_package_bytes(
                    &curated.bundle,
                    curated.row.bundle_json.as_bytes(),
                    &artefacts,
                )
                .map_err(ApiError::internal_anyhow)?
            }
            PACK_BUNDLE_FORMAT_DISCLOSURE => {
                let disclosed_artefacts = if curated.disclosed_artefact_bytes_included {
                    load_selected_pack_artefacts(
                        &state.db,
                        &curated.bundle,
                        &curated.row.bundle_id,
                        &curated.disclosed_artefact_indices,
                    )
                    .await
                    .map_err(ApiError::internal_anyhow)?
                } else {
                    Vec::new()
                };
                build_disclosure_package_bytes(
                    &curated.bundle,
                    &curated.disclosed_item_indices,
                    &curated.disclosed_item_field_redactions,
                    &curated.disclosed_artefact_indices,
                    &disclosed_artefacts,
                )
                .map_err(|err| {
                    ApiError::internal_anyhow(err.context(format!(
                        "failed to build disclosure package for bundle {}",
                        curated.row.bundle_id
                    )))
                })?
            }
            _ => unreachable!("bundle_format should be normalized"),
        };

        bundle_ids.push(curated.row.bundle_id.clone());
        bundle_entries.push(PackBundleEntry {
            bundle_id: curated.row.bundle_id.clone(),
            created_at: curated.row.created_at,
            actor_role: curated.row.actor_role,
            system_id: curated.row.system_id,
            model_id: curated.row.model_id,
            retention_class: curated.row.retention_class,
            item_types: curated.item_types,
            bundle_format: request.bundle_format.clone(),
            package_name: Some(package_name.clone()),
            disclosed_item_indices: curated.disclosed_item_indices,
            disclosed_item_types: curated.disclosed_item_types,
            disclosed_item_field_redactions: curated.disclosed_item_field_redactions,
            disclosed_artefact_indices: curated.disclosed_artefact_indices,
            disclosed_artefact_names: curated.disclosed_artefact_names,
            disclosed_artefact_bytes_included: curated.disclosed_artefact_bytes_included,
            obligation_refs: curated.obligation_refs,
            completeness_status,
            matched_rules: curated.matched_rules,
        });
        files.push(PackagedFile {
            name: package_name,
            data_base64: Base64::encode_string(&package_bytes),
        });
    }

    let manifest = PackManifest {
        pack_id: pack_id.clone(),
        pack_type: request.pack_type.clone(),
        curation_profile: PACK_CURATION_PROFILE.to_string(),
        generated_at: created_at.clone(),
        system_id: manifest_system_id,
        from: request.from.clone(),
        to: request.to.clone(),
        bundle_format: request.bundle_format.clone(),
        disclosure_policy: disclosure_policy_name.clone(),
        completeness_profile,
        completeness_pass_count: completeness_profile.map(|_| completeness_pass_count),
        completeness_warn_count: completeness_profile.map(|_| completeness_warn_count),
        completeness_fail_count: completeness_profile.map(|_| completeness_fail_count),
        pack_completeness_profile,
        pack_completeness_status: pack_completeness_report
            .as_ref()
            .map(|report| report.status),
        pack_completeness_pass_count: pack_completeness_report
            .as_ref()
            .map(|report| report.pass_count),
        pack_completeness_warn_count: pack_completeness_report
            .as_ref()
            .map(|report| report.warn_count),
        pack_completeness_fail_count: pack_completeness_report
            .as_ref()
            .map(|report| report.fail_count),
        bundle_ids,
        bundles: bundle_entries,
    };
    let archive = EvidencePackArchive {
        format: PACK_EXPORT_FORMAT.to_string(),
        manifest: manifest.clone(),
        files,
    };
    let export_bytes = gzip_json_bytes(&archive).map_err(ApiError::internal_anyhow)?;
    let export_path = pack_export_path(&state.storage_dir, &pack_id);
    persist_pack_export(&export_path, &export_bytes).map_err(ApiError::internal_anyhow)?;
    persist_pack_metadata(
        &state.db,
        &manifest,
        pack_completeness_report.as_ref(),
        &export_path,
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "create_pack",
        Some(request_actor_label(&actor)),
        None,
        Some(&pack_id),
        serde_json::json!({
            "pack_type": manifest.pack_type.clone(),
            "bundle_format": manifest.bundle_format.clone(),
            "disclosure_policy": manifest.disclosure_policy.clone(),
            "completeness_profile": manifest.completeness_profile,
            "completeness_pass_count": manifest.completeness_pass_count,
            "completeness_warn_count": manifest.completeness_warn_count,
            "completeness_fail_count": manifest.completeness_fail_count,
            "pack_completeness_profile": manifest.pack_completeness_profile,
            "pack_completeness_status": manifest.pack_completeness_status,
            "pack_completeness_pass_count": manifest.pack_completeness_pass_count,
            "pack_completeness_warn_count": manifest.pack_completeness_warn_count,
            "pack_completeness_fail_count": manifest.pack_completeness_fail_count,
            "bundle_count": manifest.bundle_ids.len(),
            "system_id": manifest.system_id.clone(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::CREATED, Json(pack_summary(&manifest))))
}

async fn get_pack(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(pack_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_pack_row(&state.db, &pack_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("pack not found"))?;
    let manifest = parse_pack_manifest(&row).map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "get_pack",
        Some(request_actor_label(&actor)),
        None,
        Some(&pack_id),
        serde_json::json!({
            "pack_type": manifest.pack_type.clone(),
            "bundle_count": manifest.bundle_ids.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    Ok((StatusCode::OK, Json(pack_summary(&manifest))))
}

async fn get_pack_manifest(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(pack_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_pack_row(&state.db, &pack_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("pack not found"))?;
    let manifest = parse_pack_manifest(&row).map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "get_pack_manifest",
        Some(request_actor_label(&actor)),
        None,
        Some(&pack_id),
        serde_json::json!({
            "bundle_count": manifest.bundle_ids.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    Ok((StatusCode::OK, Json(manifest)))
}

async fn get_pack_export(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(pack_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let row = load_pack_row(&state.db, &pack_id)
        .await
        .map_err(ApiError::internal_anyhow)?
        .ok_or_else(|| ApiError::not_found("pack not found"))?;

    let bytes = match fs::read(&row.export_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(ApiError::not_found("pack export not found"));
        }
        Err(err) => {
            return Err(ApiError::internal_anyhow(anyhow::Error::new(err).context(
                format!("failed to read pack export {}", row.export_path),
            )));
        }
    };
    append_audit_log(
        &state.db,
        "get_pack_export",
        Some(request_actor_label(&actor)),
        None,
        Some(&pack_id),
        serde_json::json!({
            "size": bytes.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, bytes))
}

async fn get_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path(bundle_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let value =
        sqlx::query("SELECT bundle_json FROM bundles WHERE bundle_id = ? AND deleted_at IS NULL")
            .bind(&bundle_id)
            .fetch_optional(&state.db)
            .await
            .map_err(ApiError::internal_anyhow)?
            .ok_or_else(|| ApiError::not_found("bundle not found"))?;

    let bundle_json: String = value
        .try_get("bundle_json")
        .map_err(ApiError::internal_anyhow)?;
    let bundle: ProofBundle =
        serde_json::from_str(&bundle_json).map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "get_bundle",
        Some(request_actor_label(&actor)),
        Some(&bundle_id),
        None,
        serde_json::json!({
            "item_count": bundle.items.len(),
            "artefact_count": bundle.artefacts.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;
    Ok((StatusCode::OK, Json(bundle)))
}

async fn get_artefact(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Path((bundle_id, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    validate_artefact_name(&name).map_err(ApiError::bad_request_anyhow)?;

    let path = artefact_path(&state.storage_dir, &bundle_id, &name)
        .map_err(ApiError::bad_request_anyhow)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Err(ApiError::not_found("artefact not found"));
        }
        Err(err) => {
            return Err(ApiError::internal_anyhow(
                anyhow::Error::new(err)
                    .context(format!("failed to read artefact {}", path.display())),
            ));
        }
    };
    append_audit_log(
        &state.db,
        "get_artefact",
        Some(request_actor_label(&actor)),
        Some(&bundle_id),
        None,
        serde_json::json!({
            "name": name,
            "size": bytes.len(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, bytes))
}

async fn verify_bundle(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<VerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let response = match request {
        VerifyRequest::Inline(request) => verify_inline_request(*request, state.max_payload_bytes)?,
        VerifyRequest::Package(request) => {
            verify_package_request(*request, state.max_payload_bytes)?
        }
    };
    append_audit_log(
        &state.db,
        "verify_bundle",
        Some(request_actor_label(&actor)),
        None,
        None,
        serde_json::json!({
            "valid": response.valid,
            "artefacts_verified": response.artefacts_verified,
            "message": response.message.clone(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn verify_timestamp_token(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<VerifyTimestampRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (bundle_id, bundle_root, timestamp) =
        resolve_timestamp_verification_target(&state.db, request)
            .await
            .map_err(ApiError::bad_request_anyhow)?;
    let timestamp_config = load_timestamp_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let timestamp_policy = timestamp_trust_policy(&timestamp_config);

    let response = match match timestamp_policy.as_ref() {
        Some(policy) => verify_timestamp_with_policy(&timestamp, &bundle_root, policy),
        None => verify_timestamp(&timestamp, &bundle_root),
    } {
        Ok(verification) => {
            let assessment =
                assess_timestamp_verification(&verification, timestamp_policy.as_ref());
            VerifyTimestampResponse {
                valid: true,
                message: format!("VALID: {} {}", assessment.headline, assessment.summary),
                verification: Some(verification),
                assessment,
            }
        }
        Err(err) => {
            let assessment = assess_timestamp_error(&err, timestamp_policy.as_ref());
            VerifyTimestampResponse {
                valid: false,
                message: format!("INVALID: {}", assessment.summary),
                verification: None,
                assessment,
            }
        }
    };
    append_audit_log(
        &state.db,
        "verify_timestamp",
        Some(request_actor_label(&actor)),
        bundle_id.as_deref(),
        None,
        serde_json::json!({
            "valid": response.valid,
            "message": response.message.clone(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

async fn verify_transparency_receipt(
    State(state): State<AppState>,
    actor: Option<Extension<AuthenticatedActor>>,
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (bundle_id, bundle_root, receipt, live_check_mode) =
        resolve_receipt_verification_target(&state.db, request)
            .await
            .map_err(ApiError::bad_request_anyhow)?;
    let timestamp_config = load_timestamp_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let transparency_config = load_transparency_config(&state.db)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let transparency_policy = transparency_trust_policy(&transparency_config, &timestamp_config);

    let response = match match transparency_policy.as_ref() {
        Some(policy) if live_check_mode == ReceiptLiveCheckMode::Off => {
            verify_receipt_with_policy(&receipt, &bundle_root, policy)
        }
        Some(policy) => verify_receipt_with_policy_and_live_check(
            &receipt,
            &bundle_root,
            policy,
            live_check_mode,
        ),
        None if live_check_mode == ReceiptLiveCheckMode::Off => {
            verify_receipt(&receipt, &bundle_root)
        }
        None => verify_receipt_with_live_check(&receipt, &bundle_root, live_check_mode),
    } {
        Ok(verification) => {
            let assessment =
                assess_receipt_verification(&verification, transparency_policy.as_ref());
            VerifyReceiptResponse {
                valid: true,
                message: format!("VALID: {} {}", assessment.headline, assessment.summary),
                verification: Some(verification),
                assessment,
            }
        }
        Err(err) => {
            let live_check = if live_check_mode == ReceiptLiveCheckMode::Off {
                None
            } else {
                Some(proof_layer_core::ReceiptLiveVerification {
                    mode: live_check_mode,
                    state: CheckState::Fail,
                    checked_at: Utc::now().to_rfc3339(),
                    summary: err.to_string(),
                    current_tree_size: None,
                    current_root_hash: None,
                    entry_retrieved: None,
                    consistency_verified: None,
                })
            };
            let assessment = assess_receipt_error(&err, transparency_policy.as_ref(), live_check);
            VerifyReceiptResponse {
                valid: false,
                message: format!("INVALID: {}", assessment.summary),
                verification: None,
                assessment,
            }
        }
    };
    append_audit_log(
        &state.db,
        "verify_receipt",
        Some(request_actor_label(&actor)),
        bundle_id.as_deref(),
        None,
        serde_json::json!({
            "valid": response.valid,
            "message": response.message.clone(),
            "live_check_mode": live_check_mode,
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(response)))
}

fn verify_inline_request(
    request: InlineVerifyRequest,
    max_payload_bytes: usize,
) -> Result<VerifyResponse, ApiError> {
    validate_bundle_integrity_fields(&request.bundle).map_err(ApiError::bad_request_anyhow)?;

    let verifying_key = decode_public_key_pem(&request.public_key_pem)
        .map_err(|err| ApiError::bad_request(format!("invalid public key: {err}")))?;

    let mut artefacts = BTreeMap::new();
    for artefact in request.artefacts {
        validate_artefact_name(&artefact.name).map_err(ApiError::bad_request_anyhow)?;
        let bytes = Base64::decode_vec(&artefact.data_base64)
            .map_err(|err| ApiError::bad_request(format!("invalid base64 artefact data: {err}")))?;
        if bytes.len() > max_payload_bytes {
            return Err(ApiError::bad_request(format!(
                "artefact {} is {} bytes and exceeds max {} bytes",
                artefact.name,
                bytes.len(),
                max_payload_bytes
            )));
        }
        artefacts.insert(artefact.name, bytes);
    }

    let outcome = request
        .bundle
        .verify_with_artefacts(&artefacts, &verifying_key);
    let response = match outcome {
        Ok(summary) => VerifyResponse {
            valid: true,
            message: "VALID".to_string(),
            artefacts_verified: summary.artefact_count,
        },
        Err(err) => VerifyResponse {
            valid: false,
            message: format!("INVALID: {err}"),
            artefacts_verified: 0,
        },
    };
    Ok(response)
}

fn verify_package_request(
    request: PackageVerifyRequest,
    max_payload_bytes: usize,
) -> Result<VerifyResponse, ApiError> {
    let package_bytes = Base64::decode_vec(&request.bundle_pkg_base64)
        .map_err(|err| ApiError::bad_request(format!("invalid bundle package base64: {err}")))?;
    if package_bytes.len() > max_payload_bytes {
        return Err(ApiError::bad_request(format!(
            "bundle package {} bytes exceeds max {} bytes",
            package_bytes.len(),
            max_payload_bytes
        )));
    }

    let verifying_key = decode_public_key_pem(&request.public_key_pem)
        .map_err(|err| ApiError::bad_request(format!("invalid public key: {err}")))?;
    let package = read_package_from_bytes(&package_bytes, max_payload_bytes)
        .map_err(ApiError::bad_request_anyhow)?;

    match package.format.as_str() {
        PACKAGE_FORMAT => verify_full_package_request(&package.files, &verifying_key),
        DISCLOSURE_PACKAGE_FORMAT => {
            verify_disclosure_package_request(&package.files, &verifying_key)
        }
        other => Err(ApiError::bad_request(format!(
            "unsupported package format {other}"
        ))),
    }
}

fn verify_full_package_request(
    files: &BTreeMap<String, Vec<u8>>,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<VerifyResponse, ApiError> {
    let bundle = parse_bundle_file(files).map_err(ApiError::bad_request_anyhow)?;
    validate_bundle_integrity_fields(&bundle).map_err(ApiError::bad_request_anyhow)?;

    let recomputed_canonical = bundle
        .canonical_header_bytes()
        .map_err(ApiError::bad_request_anyhow)?;
    let canonical_file = files
        .get("proof_bundle.canonical.json")
        .ok_or_else(|| ApiError::bad_request("package missing proof_bundle.canonical.json"))?;
    let canonicalization_ok = &recomputed_canonical == canonical_file;

    let signature_file = files
        .get("proof_bundle.sig")
        .ok_or_else(|| ApiError::bad_request("package missing proof_bundle.sig"))?;
    let signature_file_ok = signature_file == bundle.integrity.signature.value.as_bytes();

    let manifest_ok = verify_manifest(files).map_err(ApiError::bad_request_anyhow)?;
    let artefacts = extract_artefacts(files).map_err(ApiError::bad_request_anyhow)?;
    let core_outcome = bundle.verify_with_artefacts(&artefacts, verifying_key);

    let mut failures = Vec::new();
    if !canonicalization_ok {
        failures.push("canonicalized header bytes mismatch package".to_string());
    }
    if !signature_file_ok {
        failures.push("proof_bundle.sig mismatch".to_string());
    }
    if !manifest_ok {
        failures.push("manifest mismatch".to_string());
    }

    let (core_ok, artefacts_verified) = match core_outcome {
        Ok(summary) => (true, summary.artefact_count),
        Err(err) => {
            failures.push(format!("core verification failed: {err}"));
            (false, 0)
        }
    };

    let valid = canonicalization_ok && signature_file_ok && manifest_ok && core_ok;
    let message = if valid {
        "VALID".to_string()
    } else {
        format!("INVALID: {}", failures.join("; "))
    };

    Ok(VerifyResponse {
        valid,
        message,
        artefacts_verified,
    })
}

fn verify_disclosure_package_request(
    files: &BTreeMap<String, Vec<u8>>,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<VerifyResponse, ApiError> {
    let bundle = parse_redacted_bundle_file(files).map_err(ApiError::bad_request_anyhow)?;
    let manifest_ok = verify_manifest(files).map_err(ApiError::bad_request_anyhow)?;
    let artefacts = extract_artefacts(files).map_err(ApiError::bad_request_anyhow)?;
    let core_outcome = verify_redacted_bundle(&bundle, &artefacts, verifying_key);

    let mut failures = Vec::new();
    if !manifest_ok {
        failures.push("manifest mismatch".to_string());
    }

    let (core_ok, artefacts_verified) = match core_outcome {
        Ok(summary) => (true, summary.disclosed_artefact_count.min(artefacts.len())),
        Err(err) => {
            failures.push(format!("disclosure verification failed: {err}"));
            (false, 0)
        }
    };

    let valid = manifest_ok && core_ok;
    let message = if valid {
        "VALID".to_string()
    } else {
        format!("INVALID: {}", failures.join("; "))
    };

    Ok(VerifyResponse {
        valid,
        message,
        artefacts_verified,
    })
}

async fn resolve_timestamp_verification_target(
    db: &SqlitePool,
    request: VerifyTimestampRequest,
) -> Result<(Option<String>, String, TimestampToken)> {
    match request {
        VerifyTimestampRequest::BundleId { bundle_id } => {
            let bundle = load_active_bundle(db, &bundle_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("bundle not found"))?;
            let timestamp = bundle
                .timestamp
                .ok_or_else(|| anyhow::anyhow!("bundle has no timestamp token"))?;
            Ok((Some(bundle_id), bundle.integrity.bundle_root, timestamp))
        }
        VerifyTimestampRequest::Direct {
            bundle_root,
            timestamp,
        } => Ok((None, bundle_root, timestamp)),
    }
}

async fn resolve_receipt_verification_target(
    db: &SqlitePool,
    request: VerifyReceiptRequest,
) -> Result<(
    Option<String>,
    String,
    TransparencyReceipt,
    ReceiptLiveCheckMode,
)> {
    match request {
        VerifyReceiptRequest::BundleId {
            bundle_id,
            live_check_mode,
        } => {
            let bundle = load_active_bundle(db, &bundle_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("bundle not found"))?;
            let receipt = bundle
                .receipt
                .ok_or_else(|| anyhow::anyhow!("bundle has no transparency receipt"))?;
            Ok((
                Some(bundle_id),
                bundle.integrity.bundle_root,
                receipt,
                live_check_mode,
            ))
        }
        VerifyReceiptRequest::Direct {
            bundle_root,
            receipt,
            live_check_mode,
        } => Ok((None, bundle_root, receipt, live_check_mode)),
    }
}

fn read_package_from_bytes(
    package_bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<DecodedPackage> {
    let decoder = GzDecoder::new(std::io::Cursor::new(package_bytes));
    let mut limited_reader = decoder.take(
        max_payload_bytes
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("payload size limit overflow"))? as u64,
    );

    let mut json_bytes = Vec::new();
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

        let bytes = Base64::decode_vec(&file.data_base64)
            .map_err(|err| anyhow::anyhow!("failed to decode package file {}: {err}", file.name))?;
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

fn parse_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<ProofBundle> {
    let bundle_json = files
        .get("proof_bundle.json")
        .ok_or_else(|| anyhow::anyhow!("package missing proof_bundle.json"))?;
    let bundle: ProofBundle =
        serde_json::from_slice(bundle_json).context("failed to parse proof_bundle.json")?;
    Ok(bundle)
}

fn parse_redacted_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<RedactedBundle> {
    let bundle_json = files
        .get("redacted_bundle.json")
        .ok_or_else(|| anyhow::anyhow!("package missing redacted_bundle.json"))?;
    let bundle: RedactedBundle =
        serde_json::from_slice(bundle_json).context("failed to parse redacted_bundle.json")?;
    Ok(bundle)
}

fn verify_manifest(files: &BTreeMap<String, Vec<u8>>) -> Result<bool> {
    let manifest_bytes = files
        .get("manifest.json")
        .ok_or_else(|| anyhow::anyhow!("package missing manifest.json"))?;
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
            .ok_or_else(|| anyhow::anyhow!("manifest references missing file {}", entry.name))?;
        let digest = sha256_prefixed(bytes);
        if digest != entry.digest || bytes.len() as u64 != entry.size {
            return Ok(false);
        }
    }

    for file_name in files.keys() {
        if file_name == "manifest.json" {
            continue;
        }
        if !seen.contains(file_name) {
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

fn normalize_create_pack_request(mut request: CreatePackRequest) -> Result<CreatePackRequest> {
    request.pack_type = normalize_pack_type(&request.pack_type)?;
    request.bundle_ids = normalize_bundle_ids(&request.bundle_ids)?;
    request.system_id = normalize_optional_nonempty("system_id", request.system_id)?;
    request.from = normalize_optional_rfc3339("from", request.from)?;
    request.to = normalize_optional_rfc3339("to", request.to)?;
    request.bundle_format = normalize_pack_bundle_format(&request.bundle_format)?;
    request.disclosure_policy =
        normalize_optional_nonempty("disclosure_policy", request.disclosure_policy)?;
    request.disclosure_template = request
        .disclosure_template
        .map(normalize_disclosure_template_render_request)
        .transpose()?;

    if let (Some(from), Some(to)) = (request.from.as_deref(), request.to.as_deref()) {
        let from = chrono::DateTime::parse_from_rfc3339(from)
            .with_context(|| format!("from must be RFC3339, got {from}"))?;
        let to = chrono::DateTime::parse_from_rfc3339(to)
            .with_context(|| format!("to must be RFC3339, got {to}"))?;
        if from > to {
            bail!("from must be <= to");
        }
    }
    if !request.bundle_ids.is_empty()
        && (request.system_id.is_some() || request.from.is_some() || request.to.is_some())
    {
        bail!("bundle_ids cannot be combined with system_id, from, or to");
    }
    if request.bundle_format == PACK_BUNDLE_FORMAT_FULL
        && (request.disclosure_policy.is_some() || request.disclosure_template.is_some())
    {
        bail!("disclosure_policy or disclosure_template requires bundle_format=disclosure");
    }
    if request.disclosure_policy.is_some() && request.disclosure_template.is_some() {
        bail!("provide either disclosure_policy or disclosure_template, not both");
    }

    Ok(request)
}

fn normalize_bundle_ids(values: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();

    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("bundle_ids must not contain empty values");
        }
        if seen.insert(trimmed.to_string()) {
            normalized.push(trimmed.to_string());
        }
    }

    Ok(normalized)
}

fn normalize_disclosure_template_render_request(
    mut request: DisclosureTemplateRenderRequest,
) -> Result<DisclosureTemplateRenderRequest> {
    request.profile = normalize_disclosure_template_profile(&request.profile)?.to_string();
    request.name = normalize_optional_nonempty("name", request.name)?;
    request.redaction_groups = normalize_disclosure_redaction_groups(&request.redaction_groups)?;
    let policy_name = request
        .name
        .as_deref()
        .unwrap_or(&request.profile)
        .to_string();
    request.redacted_fields_by_item_type = normalize_disclosure_item_field_redactions(
        &request.redacted_fields_by_item_type,
        &policy_name,
    )?;
    Ok(request)
}

fn normalize_disclosure_preview_request(
    mut request: DisclosurePreviewRequest,
) -> Result<DisclosurePreviewRequest> {
    request.bundle_id = request.bundle_id.trim().to_string();
    if request.bundle_id.is_empty() {
        bail!("bundle_id must not be empty");
    }
    request.pack_type = match request.pack_type {
        Some(pack_type) => Some(normalize_pack_type(&pack_type)?),
        None => None,
    };
    request.disclosure_policy =
        normalize_optional_nonempty("disclosure_policy", request.disclosure_policy)?;
    request.disclosure_template = request
        .disclosure_template
        .map(normalize_disclosure_template_render_request)
        .transpose()?;
    request.policy = request
        .policy
        .map(validate_single_disclosure_policy)
        .transpose()?;
    let selection_count = usize::from(request.disclosure_policy.is_some())
        + usize::from(request.policy.is_some())
        + usize::from(request.disclosure_template.is_some());
    if selection_count > 1 {
        bail!("provide only one of disclosure_policy, policy, or disclosure_template");
    }
    Ok(request)
}

fn normalize_pack_bundle_format(raw: &str) -> Result<String> {
    let normalized = raw.trim().replace('-', "_");
    if normalized.is_empty() {
        bail!("bundle_format must not be empty");
    }

    match normalized.as_str() {
        PACK_BUNDLE_FORMAT_FULL | PACK_BUNDLE_FORMAT_DISCLOSURE => Ok(normalized),
        _ => bail!("unsupported bundle_format {}", raw.trim()),
    }
}

fn default_pack_bundle_format() -> String {
    PACK_BUNDLE_FORMAT_FULL.to_string()
}

fn normalize_pack_type(raw: &str) -> Result<String> {
    let normalized = raw.trim().replace('-', "_");
    if normalized.is_empty() {
        bail!("pack_type must not be empty");
    }

    match normalized.as_str() {
        "annex_iv"
        | "annex_xi"
        | "annex_xii"
        | "runtime_logs"
        | "risk_mgmt"
        | "ai_literacy"
        | "fundamental_rights"
        | "provider_governance"
        | "post_market_monitoring"
        | "systemic_risk"
        | "incident_response"
        | "conformity" => Ok(normalized),
        _ => bail!("unsupported pack_type {}", raw.trim()),
    }
}

fn normalize_optional_nonempty(label: &str, value: Option<String>) -> Result<Option<String>> {
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

fn normalize_optional_rfc3339(label: &str, value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                bail!("{label} must not be empty");
            }
            let parsed = chrono::DateTime::parse_from_rfc3339(trimmed)
                .with_context(|| format!("{label} must be RFC3339, got {trimmed}"))?;
            Ok(Some(parsed.with_timezone(&Utc).to_rfc3339()))
        }
        None => Ok(None),
    }
}

fn pack_summary(manifest: &PackManifest) -> PackSummaryResponse {
    PackSummaryResponse {
        pack_id: manifest.pack_id.clone(),
        pack_type: manifest.pack_type.clone(),
        created_at: manifest.generated_at.clone(),
        system_id: manifest.system_id.clone(),
        from: manifest.from.clone(),
        to: manifest.to.clone(),
        bundle_format: manifest.bundle_format.clone(),
        disclosure_policy: manifest.disclosure_policy.clone(),
        completeness_profile: manifest.completeness_profile,
        completeness_status: aggregate_manifest_completeness_status(manifest),
        pack_completeness_profile: manifest.pack_completeness_profile,
        pack_completeness_status: manifest.pack_completeness_status,
        pack_completeness_pass_count: manifest.pack_completeness_pass_count,
        pack_completeness_warn_count: manifest.pack_completeness_warn_count,
        pack_completeness_fail_count: manifest.pack_completeness_fail_count,
        bundle_count: manifest.bundle_ids.len(),
        bundle_ids: manifest.bundle_ids.clone(),
    }
}

fn bundle_completeness_profile_for_pack(pack_type: &str) -> Option<CompletenessProfile> {
    match pack_type {
        "annex_iv" => Some(CompletenessProfile::AnnexIvGovernanceV1),
        "conformity" => Some(CompletenessProfile::ConformityV1),
        "fundamental_rights" => Some(CompletenessProfile::FundamentalRightsV1),
        "annex_xi" => Some(CompletenessProfile::GpaiProviderV1),
        "incident_response" => Some(CompletenessProfile::IncidentResponseV1),
        "post_market_monitoring" => Some(CompletenessProfile::PostMarketMonitoringV1),
        "provider_governance" => Some(CompletenessProfile::ProviderGovernanceV1),
        _ => None,
    }
}

fn pack_completeness_profile_for_pack(pack_type: &str) -> Option<CompletenessProfile> {
    match pack_type {
        // annex_iv pack completeness now aligns with the eight governance
        // rule families curated by the pack itself.
        "annex_iv" => Some(CompletenessProfile::AnnexIvGovernanceV1),
        // conformity packs align with the three provider-side market-placement
        // artefacts curated by the pack itself.
        "conformity" => Some(CompletenessProfile::ConformityV1),
        // fundamental_rights packs can contain incident/supporting items, but the
        // current deployer-side readiness profile evaluates the assessment and
        // oversight rule families.
        "fundamental_rights" => Some(CompletenessProfile::FundamentalRightsV1),
        "annex_xi" => Some(CompletenessProfile::GpaiProviderV1),
        // incident_response packs align with the ten structured evidence families
        // curated for triage, escalation, authority reporting, and follow-up.
        "incident_response" => Some(CompletenessProfile::IncidentResponseV1),
        // post_market_monitoring packs can include extra correspondence items, but
        // the current readiness profile evaluates the six required monitoring and
        // authority-reporting rule families.
        "post_market_monitoring" => Some(CompletenessProfile::PostMarketMonitoringV1),
        // provider_governance packs align with the eight provider-side governance
        // families curated by the pack, including corrective action follow-up.
        "provider_governance" => Some(CompletenessProfile::ProviderGovernanceV1),
        _ => None,
    }
}

fn aggregate_manifest_completeness_status(manifest: &PackManifest) -> Option<CompletenessStatus> {
    if manifest.completeness_profile.is_none() {
        return None;
    }
    if manifest.completeness_fail_count.unwrap_or_default() > 0 {
        Some(CompletenessStatus::Fail)
    } else if manifest.completeness_warn_count.unwrap_or_default() > 0 {
        Some(CompletenessStatus::Warn)
    } else if manifest.completeness_pass_count.unwrap_or_default() > 0 {
        Some(CompletenessStatus::Pass)
    } else {
        None
    }
}

fn pack_profile(pack_type: &str) -> Result<PackProfile> {
    match pack_type {
        "annex_iv" => Ok(PackProfile {
            pack_type: "annex_iv",
            allowed_roles: &[],
            item_types: &[
                "technical_doc",
                "risk_assessment",
                "data_governance",
                "instructions_for_use",
                "qms_record",
                "standards_alignment",
                "post_market_monitoring",
                "corrective_action",
                "human_oversight",
            ],
            retention_classes: &["technical_doc", "risk_mgmt"],
            obligation_refs: &[
                "art11_annex_iv",
                "art9",
                "art10",
                "art13",
                "art14",
                "art17",
                "art40_43",
                "art72",
                "art20_73",
            ],
            requires_fria: None,
        }),
        "annex_xi" => Ok(PackProfile {
            pack_type: "annex_xi",
            allowed_roles: &["provider"],
            item_types: &[
                "llm_interaction",
                "retrieval",
                "policy_decision",
                "technical_doc",
                "risk_assessment",
                "model_evaluation",
                "training_provenance",
                "compute_metrics",
                "copyright_policy",
                "training_summary",
            ],
            retention_classes: &["technical_doc", "risk_mgmt", "gpai_documentation"],
            obligation_refs: &[
                "art11_annex_iv",
                "art9",
                "art12_19_26",
                "art53_annex_xi",
                "art53_copyright",
                "art53_training_summary",
                "art51_compute_threshold",
            ],
            requires_fria: None,
        }),
        "annex_xii" => Ok(PackProfile {
            pack_type: "annex_xii",
            allowed_roles: &["provider", "integrator"],
            item_types: &[
                "llm_interaction",
                "human_oversight",
                "policy_decision",
                "technical_doc",
                "downstream_documentation",
                "instructions_for_use",
            ],
            retention_classes: &["technical_doc", "gpai_documentation"],
            obligation_refs: &["art11_annex_iv", "art13", "art14", "art53_annex_xii"],
            requires_fria: None,
        }),
        "fundamental_rights" => Ok(PackProfile {
            pack_type: "fundamental_rights",
            allowed_roles: &["deployer"],
            item_types: &[
                "fundamental_rights_assessment",
                "human_oversight",
                "policy_decision",
                "incident_report",
                "corrective_action",
            ],
            retention_classes: &["risk_mgmt", "technical_doc"],
            obligation_refs: &["art27", "art14", "art9", "art20_73", "art55_73"],
            requires_fria: Some(true),
        }),
        "provider_governance" => Ok(PackProfile {
            pack_type: "provider_governance",
            allowed_roles: &["provider"],
            item_types: &[
                "technical_doc",
                "risk_assessment",
                "data_governance",
                "instructions_for_use",
                "qms_record",
                "standards_alignment",
                "post_market_monitoring",
                "corrective_action",
            ],
            retention_classes: &["technical_doc", "risk_mgmt"],
            obligation_refs: &[
                "art11_annex_iv",
                "art9",
                "art10",
                "art13",
                "art17",
                "art40_43",
                "art72",
                "art20_73",
            ],
            requires_fria: None,
        }),
        "post_market_monitoring" => Ok(PackProfile {
            pack_type: "post_market_monitoring",
            allowed_roles: &[],
            item_types: &[
                "post_market_monitoring",
                "incident_report",
                "corrective_action",
                "authority_notification",
                "authority_submission",
                "reporting_deadline",
                "regulator_correspondence",
            ],
            retention_classes: &["runtime_logs", "risk_mgmt", "technical_doc"],
            obligation_refs: &[
                "art12_19_26",
                "art72",
                "art20_73",
                "art55_73",
                "art73_notification",
                "art73_submission",
                "art73_deadline",
                "art73_correspondence",
            ],
            requires_fria: None,
        }),
        "runtime_logs" => Ok(PackProfile {
            pack_type: "runtime_logs",
            allowed_roles: &[],
            item_types: &[
                "llm_interaction",
                "tool_call",
                "retrieval",
                "human_oversight",
                "policy_decision",
            ],
            retention_classes: &["runtime_logs"],
            obligation_refs: &["art12_19_26"],
            requires_fria: None,
        }),
        "risk_mgmt" => Ok(PackProfile {
            pack_type: "risk_mgmt",
            allowed_roles: &[],
            item_types: &["risk_assessment", "policy_decision", "human_oversight"],
            retention_classes: &["risk_mgmt"],
            obligation_refs: &["art9"],
            requires_fria: None,
        }),
        "ai_literacy" => Ok(PackProfile {
            pack_type: "ai_literacy",
            allowed_roles: &[],
            item_types: &["literacy_attestation"],
            retention_classes: &["ai_literacy"],
            obligation_refs: &["art4"],
            requires_fria: None,
        }),
        "systemic_risk" => Ok(PackProfile {
            pack_type: "systemic_risk",
            allowed_roles: &["provider"],
            item_types: &[
                "risk_assessment",
                "llm_interaction",
                "technical_doc",
                "policy_decision",
                "model_evaluation",
                "adversarial_test",
                "incident_report",
                "compute_metrics",
            ],
            retention_classes: &["risk_mgmt", "technical_doc", "gpai_documentation"],
            obligation_refs: &[
                "art9",
                "art11_annex_iv",
                "art53_annex_xi",
                "art55",
                "art55_73",
                "art51_compute_threshold",
            ],
            requires_fria: None,
        }),
        "incident_response" => Ok(PackProfile {
            pack_type: "incident_response",
            allowed_roles: &[],
            item_types: &[
                "incident_report",
                "risk_assessment",
                "human_oversight",
                "policy_decision",
                "corrective_action",
                "authority_notification",
                "authority_submission",
                "reporting_deadline",
                "regulator_correspondence",
                "technical_doc",
            ],
            retention_classes: &["risk_mgmt", "technical_doc"],
            obligation_refs: &[
                "art9",
                "art11_annex_iv",
                "art14",
                "art20_73",
                "art55_73",
                "art73_notification",
                "art73_submission",
                "art73_deadline",
                "art73_correspondence",
            ],
            requires_fria: None,
        }),
        "conformity" => Ok(PackProfile {
            pack_type: "conformity",
            allowed_roles: &["provider"],
            item_types: &["conformity_assessment", "declaration", "registration"],
            retention_classes: &["technical_doc"],
            obligation_refs: &["art43_annex_vi_vii", "art47_annex_v", "art49_71"],
            requires_fria: None,
        }),
        _ => bail!("unsupported pack_type {pack_type}"),
    }
}

async fn resolve_pack_disclosure_policy(
    db: &SqlitePool,
    request: &CreatePackRequest,
) -> Result<Option<DisclosurePolicyConfig>> {
    if request.bundle_format != PACK_BUNDLE_FORMAT_DISCLOSURE {
        return Ok(None);
    }

    resolve_named_or_inline_disclosure_policy(
        db,
        request.disclosure_policy.as_deref(),
        None,
        request.disclosure_template.as_ref(),
        Some(default_disclosure_policy_name(&request.pack_type)),
    )
    .await
    .map(Some)
}

fn default_disclosure_policy_name(pack_type: &str) -> &'static str {
    match pack_type {
        "annex_iv" => DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED,
        "post_market_monitoring" => DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY,
        "incident_response" => DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY,
        _ => DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM,
    }
}

async fn resolve_named_or_inline_disclosure_policy(
    db: &SqlitePool,
    disclosure_policy_name: Option<&str>,
    inline_policy: Option<DisclosurePolicyConfig>,
    disclosure_template: Option<&DisclosureTemplateRenderRequest>,
    default_policy_name: Option<&str>,
) -> Result<DisclosurePolicyConfig> {
    let selection_count = usize::from(disclosure_policy_name.is_some())
        + usize::from(inline_policy.is_some())
        + usize::from(disclosure_template.is_some());
    if selection_count > 1 {
        bail!("provide only one of disclosure_policy, policy, or disclosure_template");
    }

    if let Some(policy) = inline_policy {
        return validate_single_disclosure_policy(policy);
    }
    if let Some(template) = disclosure_template {
        return build_disclosure_template_response(template).map(|response| response.policy);
    }

    let policy_name = disclosure_policy_name
        .or(default_policy_name)
        .ok_or_else(|| {
            anyhow::anyhow!("disclosure_policy is required when no default policy is available")
        })?;
    load_named_disclosure_policy(db, policy_name).await
}

async fn load_named_disclosure_policy(
    db: &SqlitePool,
    policy_name: &str,
) -> Result<DisclosurePolicyConfig> {
    let config = load_disclosure_config(db).await?;
    config
        .policies
        .into_iter()
        .find(|policy| policy.name == policy_name)
        .ok_or_else(|| anyhow::anyhow!("unknown disclosure_policy {}", policy_name))
}

fn curate_pack_bundles(
    profile: &PackProfile,
    rows: Vec<PackSourceBundleRow>,
    disclosure_policy: Option<&DisclosurePolicyConfig>,
) -> Result<Vec<CuratedPackBundle>> {
    let mut curated = Vec::new();

    for row in rows {
        let bundle: ProofBundle =
            serde_json::from_str(&row.bundle_json).context("failed to parse stored bundle JSON")?;
        let item_types = bundle_item_types(&bundle);
        let obligation_refs = bundle_obligation_refs(&bundle);
        let bundle_role = actor_role_name(&bundle);
        let bundle_fria_required = bundle
            .compliance_profile
            .as_ref()
            .and_then(|profile| profile.fria_required);

        if !profile.allowed_roles.is_empty() && !profile.allowed_roles.contains(&bundle_role) {
            continue;
        }
        if let Some(required_fria) = profile.requires_fria {
            if bundle_fria_required != Some(required_fria) {
                continue;
            }
        }

        let matched_item_types = item_types
            .iter()
            .filter(|item_type| profile.item_types.contains(&item_type.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let matched_obligation_refs = obligation_refs
            .iter()
            .filter(|obligation_ref| profile.obligation_refs.contains(&obligation_ref.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let retention_class = bundle
            .policy
            .retention_class
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        let matched_retention = profile
            .retention_classes
            .contains(&retention_class.as_str());

        let matched_governance_content =
            !matched_item_types.is_empty() || !matched_obligation_refs.is_empty();
        let allow_retention_only_match = profile.pack_type != "annex_iv";

        if !matched_governance_content && (!matched_retention || !allow_retention_only_match) {
            continue;
        }

        let candidate_disclosed_item_indices =
            select_disclosed_item_indices(profile, &bundle, &retention_class);
        let disclosed_item_indices = apply_disclosure_policy_to_items(
            disclosure_policy,
            &bundle,
            &candidate_disclosed_item_indices,
        );
        let disclosed_item_field_redactions = build_disclosed_item_field_redactions(
            disclosure_policy,
            &bundle,
            &disclosed_item_indices,
        )?;
        let disclosed_item_types = disclosed_item_indices
            .iter()
            .map(|index| evidence_item_type(&bundle.items[*index]).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let disclosed_artefact_indices =
            select_disclosed_artefact_indices(disclosure_policy, &bundle);
        let disclosed_artefact_names = disclosed_artefact_indices
            .iter()
            .map(|index| bundle.artefacts[*index].name.clone())
            .collect::<Vec<_>>();
        let disclosed_artefact_bytes_included = disclosure_policy
            .map(|policy| policy.include_artefact_bytes)
            .unwrap_or(false)
            && !disclosed_artefact_indices.is_empty();

        if disclosure_policy.is_some()
            && disclosed_item_indices.is_empty()
            && disclosed_artefact_indices.is_empty()
        {
            continue;
        }

        let mut matched_rules = Vec::new();
        matched_rules.push(format!("pack_type:{}", profile.pack_type));
        matched_rules.push(format!("actor_role:{bundle_role}"));
        if let Some(required_fria) = profile.requires_fria {
            matched_rules.push(format!("compliance_profile.fria_required:{required_fria}"));
        }
        for item_type in matched_item_types {
            matched_rules.push(format!("item_type:{item_type}"));
        }
        for obligation_ref in matched_obligation_refs {
            matched_rules.push(format!("obligation_ref:{obligation_ref}"));
        }
        if matched_retention {
            matched_rules.push(format!("retention_class:{retention_class}"));
        }
        if let Some(policy) = disclosure_policy {
            matched_rules.push(format!("disclosure_policy:{}", policy.name));
        }

        curated.push(CuratedPackBundle {
            row,
            bundle,
            item_types,
            obligation_refs,
            disclosed_item_indices,
            disclosed_item_types,
            disclosed_item_field_redactions,
            disclosed_artefact_indices,
            disclosed_artefact_names,
            disclosed_artefact_bytes_included,
            matched_rules,
        });
    }

    if profile.pack_type == "annex_iv" {
        curated.sort_by(|left, right| {
            annex_iv_bundle_priority(&left.item_types)
                .cmp(&annex_iv_bundle_priority(&right.item_types))
                .then_with(|| left.row.created_at.cmp(&right.row.created_at))
                .then_with(|| left.row.bundle_id.cmp(&right.row.bundle_id))
        });
    }

    Ok(curated)
}

fn annex_iv_bundle_priority(item_types: &[String]) -> usize {
    ANNEX_IV_ITEM_PRIORITY
        .iter()
        .position(|expected| item_types.iter().any(|actual| actual == expected))
        .unwrap_or(ANNEX_IV_ITEM_PRIORITY.len())
}

fn infer_curated_system_id(curated_rows: &[CuratedPackBundle]) -> Option<String> {
    let mut system_ids = curated_rows
        .iter()
        .filter_map(|curated| curated.row.system_id.as_deref());
    let first = system_ids.next()?;
    if system_ids.all(|system_id| system_id == first) {
        Some(first.to_string())
    } else {
        None
    }
}

fn apply_disclosure_policy_to_items(
    disclosure_policy: Option<&DisclosurePolicyConfig>,
    bundle: &ProofBundle,
    candidate_indices: &[usize],
) -> Vec<usize> {
    let Some(policy) = disclosure_policy else {
        return candidate_indices.to_vec();
    };

    let allowed = policy
        .allowed_item_types
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let excluded = policy
        .excluded_item_types
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let allowed_obligation_refs = policy
        .allowed_obligation_refs
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let excluded_obligation_refs = policy
        .excluded_obligation_refs
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();

    candidate_indices
        .iter()
        .copied()
        .filter(|index| {
            let item_type = evidence_item_type(&bundle.items[*index]);
            let obligation_ref = evidence_item_obligation_ref(bundle, &bundle.items[*index]);
            let obligation_ref_allowed = allowed_obligation_refs.is_empty()
                || obligation_ref
                    .map(|value| allowed_obligation_refs.contains(value))
                    .unwrap_or(false);
            let obligation_ref_excluded = obligation_ref
                .map(|value| excluded_obligation_refs.contains(value))
                .unwrap_or(false);
            (allowed.is_empty() || allowed.contains(item_type))
                && !excluded.contains(item_type)
                && obligation_ref_allowed
                && !obligation_ref_excluded
        })
        .collect()
}

fn build_disclosed_item_field_redactions(
    disclosure_policy: Option<&DisclosurePolicyConfig>,
    bundle: &ProofBundle,
    disclosed_item_indices: &[usize],
) -> Result<BTreeMap<usize, Vec<String>>> {
    let Some(policy) = disclosure_policy else {
        return Ok(BTreeMap::new());
    };

    let mut field_redactions = BTreeMap::new();
    for index in disclosed_item_indices {
        let item_type = evidence_item_type(&bundle.items[*index]);
        let Some(fields) = policy.redacted_fields_by_item_type.get(item_type) else {
            continue;
        };
        let applicable_fields = filter_present_redaction_selectors(&bundle.items[*index], fields)?;
        if applicable_fields.is_empty() {
            continue;
        }
        if bundle.integrity.bundle_root_algorithm != proof_layer_core::BUNDLE_ROOT_ALGORITHM_V3
            && bundle.integrity.bundle_root_algorithm != proof_layer_core::BUNDLE_ROOT_ALGORITHM_V4
        {
            bail!(
                "bundle {} uses {} and cannot satisfy field/path redactions for item type {}",
                bundle.bundle_id,
                bundle.integrity.bundle_root_algorithm,
                item_type
            );
        }
        if bundle.integrity.bundle_root_algorithm == proof_layer_core::BUNDLE_ROOT_ALGORITHM_V3
            && applicable_fields.iter().any(|field| field.starts_with('/'))
        {
            bail!(
                "bundle {} uses {} and cannot satisfy nested path redactions for item type {}",
                bundle.bundle_id,
                bundle.integrity.bundle_root_algorithm,
                item_type
            );
        }
        field_redactions.insert(*index, applicable_fields);
    }

    Ok(field_redactions)
}

fn filter_present_redaction_selectors(
    item: &EvidenceItem,
    selectors: &[String],
) -> Result<Vec<String>> {
    let value = serde_json::to_value(item)?;
    let data = value
        .get("data")
        .ok_or_else(|| anyhow::anyhow!("evidence item must serialize data"))?;
    let data_object = data
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("evidence item data must serialize as an object"))?;

    Ok(selectors
        .iter()
        .filter(|selector| {
            if selector.starts_with('/') {
                data.pointer(selector).is_some()
            } else {
                data_object.contains_key(selector.as_str())
            }
        })
        .cloned()
        .collect())
}

fn select_disclosed_artefact_indices(
    disclosure_policy: Option<&DisclosurePolicyConfig>,
    bundle: &ProofBundle,
) -> Vec<usize> {
    let Some(policy) = disclosure_policy else {
        return Vec::new();
    };
    if !policy.include_artefact_metadata {
        return Vec::new();
    }

    if policy.artefact_names.is_empty() {
        return (0..bundle.artefacts.len()).collect();
    }

    let included = policy
        .artefact_names
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();

    bundle
        .artefacts
        .iter()
        .enumerate()
        .filter_map(|(index, artefact)| included.contains(artefact.name.as_str()).then_some(index))
        .collect()
}

fn build_disclosure_preview_response(
    bundle: &ProofBundle,
    pack_type: Option<&str>,
    policy: &DisclosurePolicyConfig,
) -> Result<DisclosurePreviewResponse> {
    let candidate_item_indices = if let Some(pack_type) = pack_type {
        let profile = pack_profile(pack_type)?;
        let retention_class = bundle
            .policy
            .retention_class
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        select_disclosed_item_indices(&profile, bundle, &retention_class)
    } else {
        (0..bundle.items.len()).collect()
    };
    let disclosed_item_indices =
        apply_disclosure_policy_to_items(Some(policy), bundle, &candidate_item_indices);
    let disclosed_item_field_redactions =
        build_disclosed_item_field_redactions(Some(policy), bundle, &disclosed_item_indices)?;
    let disclosed_item_types = disclosed_item_indices
        .iter()
        .map(|index| evidence_item_type(&bundle.items[*index]).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let disclosed_item_obligation_refs = disclosed_item_indices
        .iter()
        .filter_map(|index| evidence_item_obligation_ref(bundle, &bundle.items[*index]))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let disclosed_artefact_indices = select_disclosed_artefact_indices(Some(policy), bundle);
    let disclosed_artefact_names = disclosed_artefact_indices
        .iter()
        .map(|index| bundle.artefacts[*index].name.clone())
        .collect::<Vec<_>>();
    let disclosed_artefact_bytes_included =
        policy.include_artefact_bytes && !disclosed_artefact_indices.is_empty();

    Ok(DisclosurePreviewResponse {
        bundle_id: bundle.bundle_id.clone(),
        policy_name: policy.name.clone(),
        pack_type: pack_type.map(str::to_string),
        candidate_item_indices,
        disclosed_item_indices,
        disclosed_item_types,
        disclosed_item_obligation_refs,
        disclosed_item_field_redactions,
        disclosed_artefact_indices,
        disclosed_artefact_names,
        disclosed_artefact_bytes_included,
    })
}

async fn query_pack_source_bundles(
    db: &SqlitePool,
    request: &CreatePackRequest,
) -> Result<Vec<PackSourceBundleRow>> {
    let mut builder = QueryBuilder::<Sqlite>::new(
        "SELECT
            bundle_id,
            created_at,
            actor_role,
            system_id,
            model_id,
            retention_class,
            bundle_json
         FROM bundles
         WHERE deleted_at IS NULL",
    );

    if !request.bundle_ids.is_empty() {
        builder.push(" AND bundle_id IN (");
        let mut separated = builder.separated(", ");
        for bundle_id in &request.bundle_ids {
            separated.push_bind(bundle_id);
        }
        separated.push_unseparated(")");
    }
    if let Some(system_id) = request.system_id.as_deref() {
        builder.push(" AND system_id = ");
        builder.push_bind(system_id);
    }
    if let Some(from) = request.from.as_deref() {
        builder.push(" AND created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = request.to.as_deref() {
        builder.push(" AND created_at <= ");
        builder.push_bind(to);
    }

    builder.push(" ORDER BY created_at ASC, bundle_id ASC");

    let rows = builder
        .build_query_as::<PackSourceBundleRow>()
        .fetch_all(db)
        .await
        .context("failed to fetch bundles for pack assembly")?;

    if !request.bundle_ids.is_empty() {
        let found_bundle_ids = rows
            .iter()
            .map(|row| row.bundle_id.as_str())
            .collect::<BTreeSet<_>>();
        let missing_bundle_ids = request
            .bundle_ids
            .iter()
            .filter(|bundle_id| !found_bundle_ids.contains(bundle_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_bundle_ids.is_empty() {
            bail!("unknown bundle_ids: {}", missing_bundle_ids.join(", "));
        }
    }

    Ok(rows)
}

async fn load_pack_artefacts(db: &SqlitePool, bundle_id: &str) -> Result<Vec<PackArtefactBytes>> {
    let rows = sqlx::query_as::<_, StoredPackArtefactRow>(
        "SELECT name, storage_path
         FROM artefacts
         WHERE bundle_id = ?
         ORDER BY name ASC",
    )
    .bind(bundle_id)
    .fetch_all(db)
    .await
    .with_context(|| format!("failed to load artefact metadata for bundle {bundle_id}"))?;

    let mut artefacts = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes = fs::read(&row.storage_path)
            .with_context(|| format!("failed to read artefact {}", row.storage_path))?;
        artefacts.push(PackArtefactBytes {
            name: row.name,
            bytes,
        });
    }

    Ok(artefacts)
}

async fn load_selected_pack_artefacts(
    db: &SqlitePool,
    bundle: &ProofBundle,
    bundle_id: &str,
    artefact_indices: &[usize],
) -> Result<Vec<PackArtefactBytes>> {
    if artefact_indices.is_empty() {
        return Ok(Vec::new());
    }

    let artefacts = load_pack_artefacts(db, bundle_id).await?;
    let artefacts_by_name = artefacts
        .into_iter()
        .map(|artefact| (artefact.name.clone(), artefact))
        .collect::<BTreeMap<_, _>>();

    let mut selected = Vec::with_capacity(artefact_indices.len());
    for index in artefact_indices {
        let artefact_name = &bundle
            .artefacts
            .get(*index)
            .ok_or_else(|| anyhow::anyhow!("artefact index {index} out of bounds"))?
            .name;
        let artefact = artefacts_by_name.get(artefact_name).ok_or_else(|| {
            anyhow::anyhow!(
                "selected disclosure artefact {} missing from stored bundle {}",
                artefact_name,
                bundle_id
            )
        })?;
        selected.push(PackArtefactBytes {
            name: artefact.name.clone(),
            bytes: artefact.bytes.clone(),
        });
    }

    Ok(selected)
}

fn build_bundle_package_bytes(
    bundle: &ProofBundle,
    bundle_json_bytes: &[u8],
    artefacts: &[PackArtefactBytes],
) -> Result<Vec<u8>> {
    let mut package_files = BTreeMap::<String, Vec<u8>>::new();
    package_files.insert("proof_bundle.json".to_string(), bundle_json_bytes.to_vec());
    package_files.insert(
        "proof_bundle.canonical.json".to_string(),
        bundle.canonical_header_bytes()?,
    );
    package_files.insert(
        "proof_bundle.sig".to_string(),
        bundle.integrity.signature.value.as_bytes().to_vec(),
    );

    for artefact in artefacts {
        package_files.insert(
            format!("artefacts/{}", artefact.name),
            artefact.bytes.clone(),
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

    let package = BundlePackage {
        format: PACKAGE_FORMAT.to_string(),
        files: package_files
            .into_iter()
            .map(|(name, bytes)| PackagedFile {
                name,
                data_base64: Base64::encode_string(&bytes),
            })
            .collect(),
    };

    gzip_json_bytes(&package)
}

fn build_disclosure_package_bytes(
    bundle: &ProofBundle,
    item_indices: &[usize],
    item_field_redactions: &BTreeMap<usize, Vec<String>>,
    artefact_indices: &[usize],
    disclosed_artefacts: &[PackArtefactBytes],
) -> Result<Vec<u8>> {
    let redacted = if item_field_redactions.is_empty() {
        redact_bundle(bundle, item_indices, artefact_indices)
    } else {
        redact_bundle_with_field_redactions(
            bundle,
            item_indices,
            artefact_indices,
            item_field_redactions,
        )
    }
    .context("failed to redact bundle for disclosure package")?;
    let mut package_files = BTreeMap::<String, Vec<u8>>::new();
    package_files.insert(
        "redacted_bundle.json".to_string(),
        serde_json::to_vec_pretty(&redacted)?,
    );
    for artefact in disclosed_artefacts {
        package_files.insert(
            format!("artefacts/{}", artefact.name),
            artefact.bytes.clone(),
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

    let package = BundlePackage {
        format: DISCLOSURE_PACKAGE_FORMAT.to_string(),
        files: package_files
            .into_iter()
            .map(|(name, bytes)| PackagedFile {
                name,
                data_base64: Base64::encode_string(&bytes),
            })
            .collect(),
    };

    gzip_json_bytes(&package)
}

fn gzip_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json_bytes = serde_json::to_vec_pretty(value)?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json_bytes)
        .context("failed to write gzip archive")?;
    encoder.finish().context("failed to finalize gzip archive")
}

fn bundle_obligation_refs(bundle: &ProofBundle) -> Vec<String> {
    let mut refs = BTreeSet::new();
    for item in &bundle.items {
        if let Some(obligation_ref) = evidence_item_obligation_ref(bundle, item) {
            refs.insert(obligation_ref.to_string());
        }
    }
    refs.into_iter().collect()
}

fn select_disclosed_item_indices(
    profile: &PackProfile,
    bundle: &ProofBundle,
    retention_class: &str,
) -> Vec<usize> {
    let mut indices = bundle
        .items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let item_type = evidence_item_type(item);
            let item_matches = profile.item_types.contains(&item_type);
            let obligation_matches = evidence_item_obligation_ref(bundle, item)
                .map(|obligation_ref| profile.obligation_refs.contains(&obligation_ref))
                .unwrap_or(false);
            if item_matches || obligation_matches {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if indices.is_empty() && profile.retention_classes.contains(&retention_class) {
        indices.extend(0..bundle.items.len());
    }

    indices
}

fn evidence_item_obligation_ref(bundle: &ProofBundle, item: &EvidenceItem) -> Option<&'static str> {
    match item {
        EvidenceItem::TechnicalDoc(_) => Some("art11_annex_iv"),
        EvidenceItem::RiskAssessment(_) => Some("art9"),
        EvidenceItem::DataGovernance(_) => Some("art10"),
        EvidenceItem::InstructionsForUse(_) => Some("art13"),
        EvidenceItem::HumanOversight(_) => Some("art14"),
        EvidenceItem::QmsRecord(_) => Some("art17"),
        EvidenceItem::FundamentalRightsAssessment(_) => Some("art27"),
        EvidenceItem::StandardsAlignment(_) => Some("art40_43"),
        EvidenceItem::PostMarketMonitoring(_) => Some("art72"),
        EvidenceItem::CorrectiveAction(_) => Some("art20_73"),
        EvidenceItem::AuthorityNotification(_) => Some("art73_notification"),
        EvidenceItem::AuthoritySubmission(_) => Some("art73_submission"),
        EvidenceItem::ReportingDeadline(_) => Some("art73_deadline"),
        EvidenceItem::RegulatorCorrespondence(_) => Some("art73_correspondence"),
        EvidenceItem::ModelEvaluation(_) => Some("art53_annex_xi"),
        EvidenceItem::AdversarialTest(_) => Some("art55"),
        EvidenceItem::TrainingProvenance(_) => Some("art53_annex_xi"),
        EvidenceItem::DownstreamDocumentation(_) => Some("art53_annex_xii"),
        EvidenceItem::CopyrightPolicy(_) => Some("art53_copyright"),
        EvidenceItem::TrainingSummary(_) => Some("art53_training_summary"),
        EvidenceItem::ComputeMetrics(_) => Some("art51_compute_threshold"),
        EvidenceItem::ConformityAssessment(_) => Some("art43_annex_vi_vii"),
        EvidenceItem::Declaration(_) => Some("art47_annex_v"),
        EvidenceItem::Registration(_) => Some("art49_71"),
        EvidenceItem::LiteracyAttestation(_) => Some("art4"),
        EvidenceItem::IncidentReport(_) => Some("art55_73"),
        EvidenceItem::LlmInteraction(_)
        | EvidenceItem::ToolCall(_)
        | EvidenceItem::Retrieval(_) => match bundle.policy.retention_class.as_deref() {
            Some("runtime_logs") => Some("art12_19_26"),
            _ => None,
        },
        EvidenceItem::PolicyDecision(_) => match bundle.policy.retention_class.as_deref() {
            Some("risk_mgmt") => Some("art9"),
            Some("runtime_logs") => Some("art12_19_26"),
            Some("ai_literacy") => Some("art4"),
            _ => None,
        },
    }
}

fn bundle_item_types(bundle: &ProofBundle) -> Vec<String> {
    let mut types = BTreeSet::new();
    for item in &bundle.items {
        types.insert(evidence_item_type(item).to_string());
    }
    types.into_iter().collect()
}

fn pack_bundle_file_name(bundle_id: &str, bundle_format: &str) -> String {
    match bundle_format {
        PACK_BUNDLE_FORMAT_DISCLOSURE => format!("bundles/{bundle_id}.disclosure.pkg"),
        _ => format!("bundles/{bundle_id}.pkg"),
    }
}

fn pack_export_path(base: &FsPath, pack_id: &str) -> PathBuf {
    base.join("packs").join(pack_id).join(PACK_EXPORT_FILE_NAME)
}

fn persist_pack_export(path: &FsPath, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| FsPath::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create pack export dir {}", parent.display()))?;

    let tmp_path = path.with_extension(format!("tmp-{}", generate_bundle_id()));
    let mut file = File::create(&tmp_path)
        .with_context(|| format!("failed to create temp export {}", tmp_path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write temp export {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temp export {}", tmp_path.display()))?;

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to atomically rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

async fn persist_pack_metadata(
    db: &SqlitePool,
    manifest: &PackManifest,
    pack_completeness_report: Option<&CompletenessReport>,
    export_path: &FsPath,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO packs (
            pack_id,
            pack_type,
            system_id,
            created_at,
            from_date,
            to_date,
            bundle_count,
            export_path,
            manifest_json,
            pack_completeness_report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&manifest.pack_id)
    .bind(&manifest.pack_type)
    .bind(manifest.system_id.as_deref())
    .bind(&manifest.generated_at)
    .bind(manifest.from.as_deref())
    .bind(manifest.to.as_deref())
    .bind(manifest.bundle_ids.len() as i64)
    .bind(export_path.to_string_lossy().to_string())
    .bind(serde_json::to_string(manifest)?)
    .bind(
        pack_completeness_report
            .map(serde_json::to_string)
            .transpose()?,
    )
    .execute(db)
    .await
    .with_context(|| format!("failed to insert pack {}", manifest.pack_id))?;
    Ok(())
}

async fn load_pack_row(db: &SqlitePool, pack_id: &str) -> Result<Option<StoredPackRow>> {
    sqlx::query_as::<_, StoredPackRow>(
        "SELECT
            pack_id,
            pack_type,
            created_at,
            system_id,
            from_date,
            to_date,
            bundle_count,
            export_path,
            manifest_json,
            pack_completeness_report_json
         FROM packs
         WHERE pack_id = ?",
    )
    .bind(pack_id)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load pack {pack_id}"))
}

fn parse_pack_manifest(row: &StoredPackRow) -> Result<PackManifest> {
    let manifest: PackManifest = serde_json::from_str(&row.manifest_json)
        .with_context(|| format!("failed to parse manifest for pack {}", row.pack_id))?;

    if manifest.pack_id != row.pack_id {
        bail!("pack manifest id mismatch for {}", row.pack_id);
    }
    if manifest.pack_type != row.pack_type {
        bail!("pack manifest type mismatch for {}", row.pack_id);
    }
    if manifest.curation_profile != PACK_CURATION_PROFILE {
        bail!(
            "pack manifest curation profile mismatch for {}",
            row.pack_id
        );
    }
    if manifest.generated_at != row.created_at {
        bail!("pack manifest created_at mismatch for {}", row.pack_id);
    }
    if manifest.system_id != row.system_id
        || manifest.from != row.from_date
        || manifest.to != row.to_date
    {
        bail!("pack manifest filters mismatch for {}", row.pack_id);
    }
    if manifest.bundle_ids.len() as i64 != row.bundle_count {
        bail!("pack manifest bundle_count mismatch for {}", row.pack_id);
    }

    Ok(manifest)
}

fn apply_timestamp_token_to_bundle(
    bundle: &mut ProofBundle,
    token: TimestampToken,
    trust_policy: Option<&TimestampTrustPolicy>,
) -> Result<TimestampVerification> {
    if bundle.timestamp.is_some() {
        bail!("bundle already has a timestamp token");
    }

    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_timestamp_with_policy(&token, &bundle.integrity.bundle_root, policy)?
        }
        _ => verify_timestamp(&token, &bundle.integrity.bundle_root)?,
    };
    bundle.timestamp = Some(token);
    Ok(verification)
}

fn apply_receipt_to_bundle(
    bundle: &mut ProofBundle,
    receipt: TransparencyReceipt,
    trust_policy: Option<&TransparencyTrustPolicy>,
) -> Result<ReceiptVerification> {
    if bundle.receipt.is_some() {
        bail!("bundle already has a transparency receipt");
    }

    let verification = match trust_policy {
        Some(policy) if !policy.is_empty() => {
            verify_receipt_with_policy(&receipt, &bundle.integrity.bundle_root, policy)?
        }
        _ => verify_receipt(&receipt, &bundle.integrity.bundle_root)?,
    };
    bundle.receipt = Some(receipt);
    Ok(verification)
}

fn timestamp_trust_policy(config: &TimestampConfig) -> Option<TimestampTrustPolicy> {
    let policy = TimestampTrustPolicy {
        trust_anchor_pems: config.trust_anchor_pems.clone(),
        crl_pems: config.crl_pems.clone(),
        ocsp_responder_urls: config.ocsp_responder_urls.clone(),
        qualified_signer_pems: config.qualified_signer_pems.clone(),
        policy_oids: config.policy_oids.clone(),
        assurance_profile: parse_timestamp_assurance_profile(config.assurance.as_deref()),
    };
    (!policy.is_empty()).then_some(policy)
}

fn parse_timestamp_assurance_profile(value: Option<&str>) -> Option<TimestampAssuranceProfile> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("standard") => Some(TimestampAssuranceProfile::Standard),
        Some("qualified") => Some(TimestampAssuranceProfile::Qualified),
        _ => None,
    }
}

fn parse_scitt_format(value: Option<&str>) -> ScittFormat {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("legacy_json") => ScittFormat::LegacyJson,
        _ => ScittFormat::CoseCcf,
    }
}

fn transparency_trust_policy(
    transparency: &TransparencyConfig,
    timestamp: &TimestampConfig,
) -> Option<TransparencyTrustPolicy> {
    let policy = TransparencyTrustPolicy {
        log_public_key_pem: transparency.log_public_key_pem.clone(),
        timestamp: timestamp_trust_policy(timestamp).unwrap_or_default(),
    };
    (!policy.is_empty()).then_some(policy)
}

fn map_audit_log_row(row: StoredAuditLogRow) -> Result<AuditLogEntry> {
    Ok(AuditLogEntry {
        id: row.id,
        timestamp: row.timestamp,
        action: row.action,
        actor: row.actor,
        bundle_id: row.bundle_id,
        pack_id: row.pack_id,
        details: serde_json::from_str(&row.details_json).with_context(|| {
            format!("failed to parse audit_log.details_json for row {}", row.id)
        })?,
    })
}

async fn append_audit_log(
    db: &SqlitePool,
    action: &str,
    actor: Option<&str>,
    bundle_id: Option<&str>,
    pack_id: Option<&str>,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (
            timestamp,
            action,
            actor,
            bundle_id,
            pack_id,
            details_json
        ) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(action)
    .bind(actor)
    .bind(bundle_id)
    .bind(pack_id)
    .bind(serde_json::to_string(&details)?)
    .execute(db)
    .await
    .with_context(|| format!("failed to append audit log action {action}"))?;
    Ok(())
}

async fn load_system_summary_base(
    db: &SqlitePool,
    system_id: &str,
) -> Result<Option<SystemListEntry>> {
    sqlx::query_as::<_, SystemListEntry>(
        "SELECT
            system_id,
            COUNT(bundle_id) AS bundle_count,
            COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS active_bundle_count,
            COALESCE(SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS deleted_bundle_count,
            MIN(created_at) AS first_seen_at,
            MAX(created_at) AS latest_bundle_at,
            COALESCE(SUM(CASE WHEN has_timestamp THEN 1 ELSE 0 END), 0) AS timestamped_bundle_count,
            COALESCE(SUM(CASE WHEN has_receipt THEN 1 ELSE 0 END), 0) AS receipt_bundle_count
         FROM bundles
         WHERE system_id = ?
         GROUP BY system_id",
    )
    .bind(system_id)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load system summary for {system_id}"))
}

async fn load_system_facet_counts(
    db: &SqlitePool,
    system_id: &str,
    query: &str,
) -> Result<Vec<SystemFacetCount>> {
    sqlx::query_as::<_, SystemFacetCount>(query)
        .bind(system_id)
        .fetch_all(db)
        .await
        .with_context(|| format!("failed to load system facet counts for {system_id}"))
}

fn normalize_system_id_path(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("system_id must not be empty");
    }
    Ok(value.to_string())
}

async fn build_vault_config_response(state: &AppState) -> Result<VaultConfigResponse> {
    Ok(VaultConfigResponse {
        service: VaultServiceConfigView {
            addr: state.addr.clone(),
            max_payload_bytes: state.max_payload_bytes,
            tls_enabled: state.tls_enabled,
        },
        signing: VaultSigningConfigView {
            key_id: state.signing_kid.clone(),
            algorithm: "ed25519".to_string(),
            public_key_pem: encode_public_key_pem(&state.signing_key.verifying_key()),
            ephemeral: state.signing_key_ephemeral,
        },
        storage: VaultStorageConfigView {
            metadata_backend: state.metadata_backend.clone(),
            blob_backend: state.blob_backend.clone(),
        },
        retention: RetentionConfigView {
            grace_period_days: state.retention_grace_period_days,
            scan_interval_hours: state.retention_scan_interval_hours,
            policies: load_retention_policies(&state.db).await?,
        },
        backup: VaultBackupConfigView {
            enabled: state.backup_interval_hours > 0,
            directory: state.backup_dir.display().to_string(),
            interval_hours: state.backup_interval_hours,
            retention_count: state.backup_retention_count,
            encryption: VaultBackupEncryptionConfigView {
                enabled: state.backup_encryption.is_some(),
                algorithm: state
                    .backup_encryption
                    .as_ref()
                    .map(|_| VAULT_BACKUP_ENCRYPTION_ALGORITHM.to_string()),
                key_id: state
                    .backup_encryption
                    .as_ref()
                    .map(|config| config.key_id.clone()),
            },
        },
        timestamp: load_timestamp_config(&state.db).await?,
        transparency: load_transparency_config(&state.db).await?,
        disclosure: load_disclosure_config(&state.db).await?,
        audit: AuditConfigView { enabled: true },
        auth: VaultAuthConfigView {
            enabled: state.auth_config.is_some(),
            scheme: "bearer".to_string(),
            principal_labels: state
                .auth_config
                .as_ref()
                .map(|config| {
                    config
                        .principals
                        .iter()
                        .map(|principal| principal.label.clone())
                        .collect()
                })
                .unwrap_or_default(),
        },
        tenant: VaultTenantConfigView {
            organization_id: state.tenant_organization_id.clone(),
            enforced: state.tenant_organization_id.is_some(),
        },
        demo: VaultDemoConfigView {
            capture_modes: vec!["synthetic".to_string(), "live".to_string()],
            providers: VaultDemoProvidersConfigView {
                openai: VaultDemoProviderReadiness {
                    live_enabled: state.demo_providers.openai.is_some(),
                },
                anthropic: VaultDemoProviderReadiness {
                    live_enabled: state.demo_providers.anthropic.is_some(),
                },
            },
        },
    })
}

impl DemoProviderRegistry {
    fn provider_for(&self, provider: DemoProviderName) -> Option<Arc<dyn DemoProviderClient>> {
        match provider {
            DemoProviderName::Openai => self.openai.clone(),
            DemoProviderName::Anthropic => self.anthropic.clone(),
        }
    }
}

fn build_temporary_demo_provider_client(
    provider: DemoProviderName,
    api_key: String,
) -> Result<Arc<dyn DemoProviderClient>> {
    match provider {
        DemoProviderName::Openai => {
            Ok(Arc::new(OpenAiDemoClient::new(api_key)?) as Arc<dyn DemoProviderClient>)
        }
        DemoProviderName::Anthropic => {
            Ok(Arc::new(AnthropicDemoClient::new(api_key)?) as Arc<dyn DemoProviderClient>)
        }
    }
}

fn resolve_demo_provider_client(
    registry: &DemoProviderRegistry,
    request: &DemoProviderResponseRequest,
) -> Result<Arc<dyn DemoProviderClient>> {
    if let Some(api_key) = request.provider_api_key.clone() {
        return build_temporary_demo_provider_client(request.provider, api_key);
    }
    registry.provider_for(request.provider).ok_or_else(|| {
        anyhow!(
            "{} live mode requires either vault configuration or a temporary provider_api_key",
            request.provider.as_str()
        )
    })
}

impl OpenAiDemoClient {
    fn new(api_key: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build OpenAI demo HTTP client")?;
        Ok(Self { http, api_key })
    }
}

impl AnthropicDemoClient {
    fn new(api_key: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build Anthropic demo HTTP client")?;
        Ok(Self { http, api_key })
    }
}

#[async_trait]
impl DemoProviderClient for OpenAiDemoClient {
    async fn generate(
        &self,
        request: &DemoProviderResponseRequest,
    ) -> Result<DemoProviderResponse> {
        let prompt_payload = serde_json::json!({
            "model": request.model.clone(),
            "input": [
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": request.system_prompt.clone(),
                        }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": request.user_prompt.clone(),
                        }
                    ]
                }
            ],
            "reasoning": {
                "effort": "minimal"
            },
            "text": {
                "verbosity": "low"
            },
            "max_output_tokens": request.max_tokens,
        });
        let started_at = Instant::now();
        let response = self
            .http
            .post(OPENAI_RESPONSES_URL)
            .bearer_auth(&self.api_key)
            .json(&prompt_payload)
            .send()
            .await
            .context("failed to call OpenAI responses API")?;
        let status = response.status();
        let header_request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let response_payload: Value = response
            .json()
            .await
            .context("failed to decode OpenAI responses payload")?;
        if !status.is_success() {
            bail!(
                "OpenAI live capture failed: {}",
                extract_provider_error_message(&response_payload, status.as_u16())
            );
        }

        let output_text = extract_openai_output_text(&response_payload)
            .ok_or_else(|| anyhow!("OpenAI response did not contain output text"))?;
        let usage = demo_usage_from_openai_payload(&response_payload);
        let provider_request_id = header_request_id.or_else(|| {
            response_payload
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        Ok(build_demo_provider_response(
            request,
            output_text,
            usage,
            started_at.elapsed().as_millis() as u64,
            provider_request_id,
            prompt_payload,
            response_payload,
        ))
    }
}

#[async_trait]
impl DemoProviderClient for AnthropicDemoClient {
    async fn generate(
        &self,
        request: &DemoProviderResponseRequest,
    ) -> Result<DemoProviderResponse> {
        let prompt_payload = serde_json::json!({
            "model": request.model.clone(),
            "system": request.system_prompt.clone(),
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [
                {
                    "role": "user",
                    "content": request.user_prompt.clone(),
                }
            ]
        });
        let started_at = Instant::now();
        let response = self
            .http
            .post(ANTHROPIC_MESSAGES_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .json(&prompt_payload)
            .send()
            .await
            .context("failed to call Anthropic messages API")?;
        let status = response.status();
        let response_payload: Value = response
            .json()
            .await
            .context("failed to decode Anthropic messages payload")?;
        if !status.is_success() {
            bail!(
                "Anthropic live capture failed: {}",
                extract_provider_error_message(&response_payload, status.as_u16())
            );
        }

        let output_text = extract_anthropic_output_text(&response_payload)
            .ok_or_else(|| anyhow!("Anthropic response did not contain text content"))?;
        let usage = demo_usage_from_anthropic_payload(&response_payload);
        let provider_request_id = response_payload
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(build_demo_provider_response(
            request,
            output_text,
            usage,
            started_at.elapsed().as_millis() as u64,
            provider_request_id,
            prompt_payload,
            response_payload,
        ))
    }
}

fn default_demo_temperature() -> f64 {
    0.2
}

fn default_demo_max_tokens() -> u32 {
    256
}

fn validate_demo_provider_response_request(
    mut request: DemoProviderResponseRequest,
) -> Result<DemoProviderResponseRequest> {
    request.model = request.model.trim().to_string();
    request.system_prompt = request.system_prompt.trim().to_string();
    request.user_prompt = request.user_prompt.trim().to_string();
    request.provider_api_key = request
        .provider_api_key
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if request.model.is_empty() {
        bail!("model must not be empty");
    }
    if request.system_prompt.is_empty() {
        bail!("system_prompt must not be empty");
    }
    if request.user_prompt.is_empty() {
        bail!("user_prompt must not be empty");
    }
    if !request.temperature.is_finite() {
        bail!("temperature must be finite");
    }
    if request.temperature < 0.0 {
        bail!("temperature must be >= 0");
    }
    if request.max_tokens == 0 {
        bail!("max_tokens must be > 0");
    }

    Ok(request)
}

fn build_synthetic_demo_provider_response(
    request: &DemoProviderResponseRequest,
) -> DemoProviderResponse {
    let output_text = build_mock_response(
        request.provider,
        &request.system_prompt,
        &request.user_prompt,
        &request.model,
    );
    let input_tokens =
        estimate_demo_tokens(&request.system_prompt) + estimate_demo_tokens(&request.user_prompt);
    let output_tokens = estimate_demo_tokens(&output_text).max(24);
    let usage = DemoTokenUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
    };
    let prompt_payload = serde_json::json!({
        "provider": request.provider.as_str(),
        "model": request.model.clone(),
        "mode": "synthetic",
        "messages": [
            {
                "role": "system",
                "content": request.system_prompt.clone(),
            },
            {
                "role": "user",
                "content": request.user_prompt.clone(),
            }
        ],
        "temperature": request.temperature,
        "max_tokens": request.max_tokens,
    });
    let response_payload = serde_json::json!({
        "provider": request.provider.as_str(),
        "model": request.model.clone(),
        "output": output_text.clone(),
        "usage": usage.clone(),
        "response_source": request.mode.response_source(),
    });

    build_demo_provider_response(
        request,
        output_text,
        usage,
        180,
        None,
        prompt_payload,
        response_payload,
    )
}

fn build_mock_response(
    provider: DemoProviderName,
    system_prompt: &str,
    user_prompt: &str,
    model: &str,
) -> String {
    let lead = match provider {
        DemoProviderName::Anthropic => "Anthropic",
        DemoProviderName::Openai => "OpenAI",
    };
    let prompt_excerpt = user_prompt.trim().chars().take(180).collect::<String>();
    let policy_note = system_prompt.trim().chars().take(70).collect::<String>();
    [
        format!("Synthetic {lead} {model} demo response."),
        "Proof Layer can show investors a complete assurance workflow for one AI interaction: capture the prompt and output, seal them into a signed bundle, verify integrity later, preview policy-driven disclosure, and export a pack from the vault.".to_string(),
        "The commercial point is controlled evidence handling rather than chat quality. A reviewer can prove what was captured, decide what to reveal, and hand over a regulator-oriented package without exposing every internal artefact by default.".to_string(),
        format!(
            "Prompt focus: {}",
            if prompt_excerpt.is_empty() {
                "No prompt provided."
            } else {
                &prompt_excerpt
            }
        ),
        format!(
            "Grounding note: {}",
            if policy_note.is_empty() {
                "No system guidance provided."
            } else {
                &policy_note
            }
        ),
    ]
    .join("\n\n")
}

fn estimate_demo_tokens(text: &str) -> u64 {
    ((text.chars().count() as u64) / 4).max(1)
}

fn build_demo_provider_response(
    request: &DemoProviderResponseRequest,
    output_text: String,
    usage: DemoTokenUsage,
    latency_ms: u64,
    provider_request_id: Option<String>,
    prompt_payload: Value,
    response_payload: Value,
) -> DemoProviderResponse {
    DemoProviderResponse {
        capture_mode: request.mode.response_source().to_string(),
        provider: request.provider.as_str().to_string(),
        model: request.model.clone(),
        output_text,
        usage: usage.clone(),
        latency_ms,
        provider_request_id: provider_request_id.clone(),
        prompt_payload,
        response_payload,
        trace_payload: serde_json::json!({
            "request_id": provider_request_id.clone().unwrap_or_else(|| Ulid::new().to_string()),
            "provider": request.provider.as_str(),
            "model": request.model.clone(),
            "capture_mode": request.mode.response_source(),
            "generated_at": Utc::now().to_rfc3339(),
            "latency_ms": latency_ms,
            "usage": usage,
        }),
    }
}

fn extract_provider_error_message(payload: &Value, status_code: u16) -> String {
    payload
        .get("error")
        .and_then(|value| value.get("message").or(Some(value)))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            payload
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("provider returned HTTP {status_code}"))
}

fn extract_openai_output_text(payload: &Value) -> Option<String> {
    if let Some(text) = payload.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    if let Some(output) = payload.get("output").and_then(Value::as_array) {
        let mut parts = Vec::new();
        for item in output {
            if let Some(content) = item.get("content").and_then(Value::as_array) {
                for block in content {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        parts.push(text.to_string());
                    } else if let Some(text) = block
                        .get("text")
                        .and_then(|value| value.get("value"))
                        .and_then(Value::as_str)
                    {
                        parts.push(text.to_string());
                    }
                }
            }
        }
        if !parts.is_empty() {
            return Some(parts.join("\n\n"));
        }
    }
    payload
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn extract_anthropic_output_text(payload: &Value) -> Option<String> {
    let mut parts = Vec::new();
    let content = payload.get("content").and_then(Value::as_array)?;
    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("text")
            && let Some(text) = block.get("text").and_then(Value::as_str)
        {
            parts.push(text.to_string());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

fn demo_usage_from_openai_payload(payload: &Value) -> DemoTokenUsage {
    let usage = payload.get("usage").cloned().unwrap_or(Value::Null);
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .or_else(|| usage.get("output_text_tokens").and_then(Value::as_u64))
        .unwrap_or(0);
    let total_tokens = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(input_tokens + output_tokens);
    DemoTokenUsage {
        input_tokens,
        output_tokens,
        total_tokens,
    }
}

fn demo_usage_from_anthropic_payload(payload: &Value) -> DemoTokenUsage {
    let usage = payload.get("usage").cloned().unwrap_or(Value::Null);
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    DemoTokenUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
    }
}

fn validate_update_retention_config_request(
    request: UpdateRetentionConfigRequest,
) -> Result<UpdateRetentionConfigRequest> {
    if request.policies.is_empty() {
        bail!("retention config request must include at least one policy");
    }

    let mut seen = HashSet::new();
    for policy in &request.policies {
        validate_retention_policy_config(policy)?;
        if !seen.insert(policy.retention_class.clone()) {
            bail!(
                "duplicate retention_class in request: {}",
                policy.retention_class
            );
        }
    }

    Ok(request)
}

fn normalize_disclosure_template_profile(raw: &str) -> Result<&'static str> {
    let normalized = raw.trim().replace('-', "_").to_ascii_lowercase();
    match normalized.as_str() {
        DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM
        | DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED
        | DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY
        | DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM
        | DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW => Ok(match normalized.as_str() {
            DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM => {
                DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM
            }
            DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED => {
                DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED
            }
            DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY => {
                DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY
            }
            DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM => DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM,
            DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW => DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW,
            _ => unreachable!(),
        }),
        _ => bail!("unsupported disclosure template profile {}", raw.trim()),
    }
}

fn normalize_disclosure_redaction_groups(values: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let group = value.trim().replace('-', "_").to_ascii_lowercase();
        if group.is_empty() {
            continue;
        }
        disclosure_redaction_group_description(&group)?;
        if seen.insert(group.clone()) {
            normalized.push(group);
        }
    }
    Ok(normalized)
}

fn validate_retention_policy_config(policy: &RetentionPolicyConfig) -> Result<()> {
    if policy.retention_class.trim().is_empty() {
        bail!("retention_class must not be empty");
    }
    if policy.legal_basis.trim().is_empty() {
        bail!("legal_basis must not be empty");
    }
    if policy.min_duration_days < 0 {
        bail!("min_duration_days must be >= 0");
    }
    if let Some(max_duration_days) = policy.max_duration_days
        && max_duration_days < policy.min_duration_days
    {
        bail!("max_duration_days must be >= min_duration_days");
    }
    if policy.expiry_mode == RetentionExpiryMode::UntilWithdrawn
        && policy.max_duration_days.is_some()
    {
        bail!("until_withdrawn retention policies must not set max_duration_days");
    }
    Ok(())
}

fn validate_timestamp_config(mut config: TimestampConfig) -> Result<TimestampConfig> {
    config.provider = config.provider.trim().to_ascii_lowercase();
    config.url = config.url.trim().to_string();
    config.assurance =
        normalize_optional_string(config.assurance).map(|value| value.to_ascii_lowercase());
    config.trust_anchor_pems = config
        .trust_anchor_pems
        .into_iter()
        .filter_map(|pem| {
            let trimmed = pem.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect();
    config.crl_pems = config
        .crl_pems
        .into_iter()
        .filter_map(|pem| {
            let trimmed = pem.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect();
    config.ocsp_responder_urls = config
        .ocsp_responder_urls
        .into_iter()
        .filter_map(|url| {
            let trimmed = url.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect();
    config.qualified_signer_pems = config
        .qualified_signer_pems
        .into_iter()
        .filter_map(|pem| {
            let trimmed = pem.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect();
    config.policy_oids = config
        .policy_oids
        .into_iter()
        .filter_map(|policy_oid| {
            let trimmed = policy_oid.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .collect();

    if config.provider != DEFAULT_TIMESTAMP_PROVIDER {
        bail!("timestamp provider must be {}", DEFAULT_TIMESTAMP_PROVIDER);
    }
    if config.url.is_empty() {
        bail!("timestamp url must not be empty");
    }
    validate_http_url(&config.url, "timestamp url")?;

    if let Some(assurance) = &config.assurance
        && assurance != "standard"
        && assurance != "qualified"
    {
        bail!("timestamp assurance must be standard or qualified");
    }
    validate_timestamp_trust_policy(&TimestampTrustPolicy {
        trust_anchor_pems: config.trust_anchor_pems.clone(),
        crl_pems: config.crl_pems.clone(),
        ocsp_responder_urls: config.ocsp_responder_urls.clone(),
        qualified_signer_pems: config.qualified_signer_pems.clone(),
        policy_oids: config.policy_oids.clone(),
        assurance_profile: parse_timestamp_assurance_profile(config.assurance.as_deref()),
    })
    .map_err(anyhow::Error::from)?;

    Ok(config)
}

fn validate_transparency_config(mut config: TransparencyConfig) -> Result<TransparencyConfig> {
    config.provider = config.provider.trim().to_ascii_lowercase();
    config.url = normalize_optional_string(config.url);
    config.scitt_format =
        normalize_optional_string(config.scitt_format).map(|value| value.to_ascii_lowercase());
    config.log_public_key_pem = normalize_optional_string(config.log_public_key_pem);

    match config.provider.as_str() {
        "none" => {
            if config.enabled {
                bail!("transparency provider none cannot be enabled");
            }
            if config.url.is_some() {
                bail!("transparency url must be omitted when provider is none");
            }
            if config.scitt_format.is_some() {
                bail!("transparency scitt_format must be omitted when provider is none");
            }
            if config.log_public_key_pem.is_some() {
                bail!("transparency log public key must be omitted when provider is none");
            }
        }
        "rekor" => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("transparency url is required when provider is configured")
            })?;
            validate_http_url(url, "transparency url")?;
            if config.scitt_format.is_some() {
                bail!("transparency scitt_format is only valid when provider is scitt");
            }
        }
        "scitt" => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("transparency url is required when provider is configured")
            })?;
            validate_http_url(url, "transparency url")?;
            if let Some(format) = config.scitt_format.as_deref()
                && format != "legacy_json"
                && format != "cose_ccf"
            {
                bail!("transparency scitt_format must be legacy_json or cose_ccf");
            }
        }
        _ => bail!("transparency provider must be one of none, rekor, or scitt"),
    }
    validate_transparency_trust_policy(&TransparencyTrustPolicy {
        log_public_key_pem: config.log_public_key_pem.clone(),
        timestamp: TimestampTrustPolicy::default(),
    })
    .map_err(anyhow::Error::from)?;

    Ok(config)
}

fn validate_disclosure_config(mut config: DisclosureConfig) -> Result<DisclosureConfig> {
    if config.policies.is_empty() {
        bail!("disclosure config must include at least one policy");
    }

    let mut seen_policy_names = HashSet::new();
    for policy in &mut config.policies {
        policy.name = policy.name.trim().to_string();
        if policy.name.is_empty() {
            bail!("disclosure policy name must not be empty");
        }
        if !seen_policy_names.insert(policy.name.clone()) {
            bail!("duplicate disclosure policy name {}", policy.name);
        }

        policy.allowed_item_types = normalize_disclosure_item_types(
            &policy.allowed_item_types,
            "allowed_item_types",
            &policy.name,
        )?;
        policy.excluded_item_types = normalize_disclosure_item_types(
            &policy.excluded_item_types,
            "excluded_item_types",
            &policy.name,
        )?;
        policy.allowed_obligation_refs = normalize_disclosure_obligation_refs(
            &policy.allowed_obligation_refs,
            "allowed_obligation_refs",
            &policy.name,
        )?;
        policy.excluded_obligation_refs = normalize_disclosure_obligation_refs(
            &policy.excluded_obligation_refs,
            "excluded_obligation_refs",
            &policy.name,
        )?;
        policy.redacted_fields_by_item_type = normalize_disclosure_item_field_redactions(
            &policy.redacted_fields_by_item_type,
            &policy.name,
        )?;
        let allowed = policy
            .allowed_item_types
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        for item_type in &policy.excluded_item_types {
            if allowed.contains(item_type) {
                bail!(
                    "disclosure policy {} includes {} in both allowed_item_types and excluded_item_types",
                    policy.name,
                    item_type
                );
            }
        }
        let allowed_obligation_refs = policy
            .allowed_obligation_refs
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        for obligation_ref in &policy.excluded_obligation_refs {
            if allowed_obligation_refs.contains(obligation_ref) {
                bail!(
                    "disclosure policy {} includes {} in both allowed_obligation_refs and excluded_obligation_refs",
                    policy.name,
                    obligation_ref
                );
            }
        }
        for item_type in policy.redacted_fields_by_item_type.keys() {
            if allowed.contains(item_type) || policy.allowed_item_types.is_empty() {
                continue;
            }
            bail!(
                "disclosure policy {} defines redacted fields for {} but that item type is not allowed by allowed_item_types",
                policy.name,
                item_type
            );
        }

        policy.artefact_names = policy
            .artefact_names
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut seen_artefact_names = HashSet::new();
        for name in &policy.artefact_names {
            validate_artefact_name(name)?;
            if !seen_artefact_names.insert(name.clone()) {
                bail!(
                    "disclosure policy {} includes duplicate artefact name {}",
                    policy.name,
                    name
                );
            }
        }
        if !policy.include_artefact_metadata && !policy.artefact_names.is_empty() {
            bail!(
                "disclosure policy {} cannot set artefact_names when include_artefact_metadata is false",
                policy.name
            );
        }
        if policy.include_artefact_bytes && !policy.include_artefact_metadata {
            bail!(
                "disclosure policy {} cannot set include_artefact_bytes when include_artefact_metadata is false",
                policy.name
            );
        }
    }

    Ok(config)
}

fn validate_single_disclosure_policy(
    policy: DisclosurePolicyConfig,
) -> Result<DisclosurePolicyConfig> {
    let config = validate_disclosure_config(DisclosureConfig {
        policies: vec![policy],
    })?;
    config
        .policies
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("validated disclosure config unexpectedly empty"))
}

fn normalize_disclosure_item_types(
    values: &[String],
    field_name: &str,
    policy_name: &str,
) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for value in values {
        let item_type = value.trim().to_ascii_lowercase();
        if item_type.is_empty() {
            continue;
        }
        if !is_known_evidence_item_type(&item_type) {
            bail!(
                "disclosure policy {} has unsupported {} entry {}",
                policy_name,
                field_name,
                item_type
            );
        }
        if seen.insert(item_type.clone()) {
            normalized.push(item_type);
        }
    }

    Ok(normalized)
}

fn normalize_disclosure_obligation_refs(
    values: &[String],
    field_name: &str,
    policy_name: &str,
) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for value in values {
        let obligation_ref = value.trim().to_ascii_lowercase();
        if obligation_ref.is_empty() {
            continue;
        }
        if !is_known_obligation_ref(&obligation_ref) {
            bail!(
                "disclosure policy {} has unsupported {} entry {}",
                policy_name,
                field_name,
                obligation_ref
            );
        }
        if seen.insert(obligation_ref.clone()) {
            normalized.push(obligation_ref);
        }
    }

    Ok(normalized)
}

fn normalize_disclosure_item_field_redactions(
    value: &BTreeMap<String, Vec<String>>,
    policy_name: &str,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut normalized = BTreeMap::new();
    for (item_type, fields) in value {
        let item_type = item_type.trim().to_ascii_lowercase();
        if item_type.is_empty() {
            continue;
        }
        if !is_known_evidence_item_type(&item_type) {
            bail!(
                "disclosure policy {} has unsupported redacted_fields_by_item_type key {}",
                policy_name,
                item_type
            );
        }
        let mut seen = HashSet::new();
        let mut normalized_fields = Vec::new();
        for field in fields {
            let field = field.trim().to_string();
            if field.is_empty() {
                continue;
            }
            if !is_supported_redaction_selector(&item_type, &field) {
                bail!(
                    "disclosure policy {} has unsupported redacted field/path {} for item type {}",
                    policy_name,
                    field,
                    item_type
                );
            }
            if seen.insert(field.clone()) {
                normalized_fields.push(field);
            }
        }
        if !normalized_fields.is_empty() {
            normalized.insert(item_type, normalized_fields);
        }
    }

    Ok(normalized)
}

fn is_known_evidence_item_type(item_type: &str) -> bool {
    matches!(
        item_type,
        "llm_interaction"
            | "tool_call"
            | "retrieval"
            | "human_oversight"
            | "policy_decision"
            | "risk_assessment"
            | "data_governance"
            | "technical_doc"
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
            | "registration"
            | "literacy_attestation"
            | "incident_report"
            | "compute_metrics"
    )
}

fn known_item_fields(item_type: &str) -> &'static [&'static str] {
    match item_type {
        "llm_interaction" => &[
            "provider",
            "model",
            "parameters",
            "input_commitment",
            "retrieval_commitment",
            "output_commitment",
            "tool_outputs_commitment",
            "token_usage",
            "latency_ms",
            "trace_commitment",
            "trace_semconv_version",
            "execution_start",
            "execution_end",
        ],
        "tool_call" => &[
            "tool_name",
            "input_commitment",
            "output_commitment",
            "metadata",
            "execution_start",
            "execution_end",
        ],
        "retrieval" => &[
            "corpus",
            "result_commitment",
            "query_commitment",
            "database_reference",
            "metadata",
            "execution_start",
            "execution_end",
        ],
        "human_oversight" => &[
            "action",
            "reviewer",
            "notes_commitment",
            "actor_role",
            "anomaly_detected",
            "override_action",
            "interpretation_guidance_followed",
            "automation_bias_detected",
            "two_person_verification",
            "stop_triggered",
            "stop_reason",
        ],
        "policy_decision" => &[
            "policy_name",
            "decision",
            "rationale_commitment",
            "metadata",
        ],
        "risk_assessment" => &[
            "risk_id",
            "severity",
            "status",
            "summary",
            "metadata",
            "risk_description",
            "likelihood",
            "affected_groups",
            "mitigation_measures",
            "residual_risk_level",
            "risk_owner",
            "vulnerable_groups_considered",
            "test_results_summary",
        ],
        "data_governance" => &[
            "decision",
            "dataset_ref",
            "metadata",
            "dataset_name",
            "dataset_version",
            "source_description",
            "collection_period",
            "geographical_scope",
            "preprocessing_operations",
            "bias_detection_methodology",
            "bias_metrics",
            "mitigation_actions",
            "data_gaps",
            "personal_data_categories",
            "safeguards",
        ],
        "technical_doc" => &[
            "document_ref",
            "section",
            "commitment",
            "annex_iv_sections",
            "system_description_summary",
            "model_description_summary",
            "capabilities_and_limitations",
            "design_choices_summary",
            "evaluation_metrics_summary",
            "human_oversight_design_summary",
            "post_market_monitoring_plan_ref",
            "simplified_tech_doc",
        ],
        "instructions_for_use" => &[
            "document_ref",
            "version",
            "section",
            "commitment",
            "metadata",
            "provider_identity",
            "intended_purpose",
            "system_capabilities",
            "accuracy_metrics",
            "foreseeable_risks",
            "explainability_capabilities",
            "human_oversight_guidance",
            "compute_requirements",
            "service_lifetime",
            "log_management_guidance",
        ],
        "qms_record" => &[
            "record_id",
            "process",
            "status",
            "record_commitment",
            "metadata",
            "policy_name",
            "revision",
            "effective_date",
            "expiry_date",
            "scope",
            "approval_commitment",
            "audit_results_summary",
            "continuous_improvement_actions",
        ],
        "fundamental_rights_assessment" => &[
            "assessment_id",
            "status",
            "scope",
            "report_commitment",
            "metadata",
            "legal_basis",
            "affected_rights",
            "stakeholder_consultation_summary",
            "mitigation_plan_summary",
            "assessor",
        ],
        "standards_alignment" => &[
            "standard_ref",
            "status",
            "scope",
            "mapping_commitment",
            "metadata",
        ],
        "post_market_monitoring" => &[
            "plan_id",
            "status",
            "summary",
            "report_commitment",
            "metadata",
        ],
        "corrective_action" => &[
            "action_id",
            "status",
            "summary",
            "due_at",
            "record_commitment",
            "metadata",
        ],
        "authority_notification" => &[
            "notification_id",
            "authority",
            "status",
            "incident_id",
            "due_at",
            "report_commitment",
            "metadata",
        ],
        "authority_submission" => &[
            "submission_id",
            "authority",
            "status",
            "channel",
            "submitted_at",
            "document_commitment",
            "metadata",
        ],
        "reporting_deadline" => &[
            "deadline_id",
            "authority",
            "obligation_ref",
            "due_at",
            "status",
            "incident_id",
            "metadata",
        ],
        "regulator_correspondence" => &[
            "correspondence_id",
            "authority",
            "direction",
            "status",
            "occurred_at",
            "message_commitment",
            "metadata",
        ],
        "model_evaluation" => &[
            "evaluation_id",
            "benchmark",
            "status",
            "summary",
            "report_commitment",
            "metadata",
            "metrics_summary",
            "group_performance",
            "evaluation_methodology",
        ],
        "adversarial_test" => &[
            "test_id",
            "focus",
            "status",
            "finding_severity",
            "report_commitment",
            "metadata",
            "threat_model",
            "test_methodology",
            "attack_classes",
            "affected_components",
        ],
        "training_provenance" => &[
            "dataset_ref",
            "stage",
            "lineage_ref",
            "record_commitment",
            "metadata",
            "compute_metrics_ref",
            "training_dataset_summary",
            "consortium_context",
        ],
        "downstream_documentation" => &[
            "document_ref",
            "audience",
            "status",
            "commitment",
            "metadata",
        ],
        "copyright_policy" => &[
            "policy_ref",
            "status",
            "jurisdiction",
            "commitment",
            "metadata",
        ],
        "training_summary" => &[
            "summary_ref",
            "status",
            "audience",
            "commitment",
            "metadata",
        ],
        "conformity_assessment" => &[
            "assessment_id",
            "procedure",
            "status",
            "report_commitment",
            "metadata",
            "assessment_body",
            "certificate_ref",
        ],
        "declaration" => &[
            "declaration_id",
            "jurisdiction",
            "status",
            "document_commitment",
            "metadata",
            "signatory",
            "document_version",
        ],
        "registration" => &[
            "registration_id",
            "authority",
            "status",
            "receipt_commitment",
            "metadata",
            "registration_number",
            "submitted_at",
        ],
        "literacy_attestation" => &[
            "attested_role",
            "status",
            "training_ref",
            "attestation_commitment",
            "metadata",
            "completion_date",
            "training_provider",
            "certificate_digest",
        ],
        "incident_report" => &[
            "incident_id",
            "severity",
            "status",
            "occurred_at",
            "summary",
            "report_commitment",
            "metadata",
            "detection_method",
            "root_cause_summary",
            "corrective_action_ref",
            "authority_notification_required",
            "authority_notification_status",
        ],
        "compute_metrics" => &[
            "compute_id",
            "training_flops_estimate",
            "threshold_basis_ref",
            "threshold_value",
            "threshold_status",
            "estimation_methodology",
            "measured_at",
            "compute_resources_summary",
            "consortium_context",
            "metadata",
        ],
        _ => &[],
    }
}

fn is_supported_redaction_selector(item_type: &str, selector: &str) -> bool {
    if let Some(stripped) = selector.strip_prefix('/') {
        let mut segments = stripped.split('/');
        let Some(first_segment) = segments.next() else {
            return false;
        };
        let top_level = unescape_json_pointer_segment(first_segment);
        if top_level.is_empty() {
            return false;
        }
        return known_item_fields(item_type).contains(&top_level.as_str());
    }

    known_item_fields(item_type).contains(&selector)
}

fn unescape_json_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn is_known_obligation_ref(obligation_ref: &str) -> bool {
    matches!(
        obligation_ref,
        "art11_annex_iv"
            | "art9"
            | "art10"
            | "art51_compute_threshold"
            | "art13"
            | "art14"
            | "art17"
            | "art27"
            | "art40_43"
            | "art72"
            | "art20_73"
            | "art53_annex_xi"
            | "art53_annex_xii"
            | "art53_copyright"
            | "art53_training_summary"
            | "art55"
            | "art43_annex_vi_vii"
            | "art47_annex_v"
            | "art49_71"
            | "art4"
            | "art55_73"
            | "art12_19_26"
    )
}

fn validate_http_url(value: &str, field_name: &str) -> Result<()> {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        bail!("{field_name} must start with http:// or https://");
    }
    Ok(())
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_assurance_level_filter(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    match normalized.as_str() {
        "signed" | "timestamped" | "transparency_anchored" => Ok(Some(normalized)),
        _ => bail!("assurance_level must be one of signed, timestamped, or transparency_anchored"),
    }
}

fn default_timestamp_config() -> TimestampConfig {
    TimestampConfig {
        enabled: false,
        provider: DEFAULT_TIMESTAMP_PROVIDER.to_string(),
        url: DEFAULT_TIMESTAMP_URL.to_string(),
        assurance: None,
        trust_anchor_pems: Vec::new(),
        crl_pems: Vec::new(),
        ocsp_responder_urls: Vec::new(),
        qualified_signer_pems: Vec::new(),
        policy_oids: Vec::new(),
    }
}

fn default_transparency_config() -> TransparencyConfig {
    TransparencyConfig {
        enabled: false,
        provider: DEFAULT_TRANSPARENCY_PROVIDER.to_string(),
        url: None,
        scitt_format: None,
        log_public_key_pem: None,
    }
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
        ("risk_assessment".to_string(), vec!["/metadata".to_string()]),
        (
            "data_governance".to_string(),
            vec![
                "/metadata".to_string(),
                "/personal_data_categories".to_string(),
                "/safeguards".to_string(),
            ],
        ),
        (
            "instructions_for_use".to_string(),
            vec!["/metadata".to_string()],
        ),
        ("qms_record".to_string(), vec!["/metadata".to_string()]),
        (
            "standards_alignment".to_string(),
            vec!["/metadata".to_string()],
        ),
        (
            "post_market_monitoring".to_string(),
            vec!["/metadata".to_string()],
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

fn disclosure_template_catalog() -> Result<DisclosureTemplateCatalogResponse> {
    let templates = [
        DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM,
        DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED,
        DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY,
        DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM,
        DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW,
    ]
    .into_iter()
    .map(|profile| {
        build_disclosure_template_response(&DisclosureTemplateRenderRequest {
            profile: profile.to_string(),
            name: None,
            redaction_groups: Vec::new(),
            redacted_fields_by_item_type: BTreeMap::new(),
        })
    })
    .collect::<Result<Vec<_>>>()?;

    Ok(DisclosureTemplateCatalogResponse {
        templates,
        redaction_groups: disclosure_redaction_groups()
            .into_iter()
            .map(|(name, description)| DisclosureRedactionGroupResponse {
                name: name.to_string(),
                description: description.to_string(),
            })
            .collect(),
    })
}

fn build_disclosure_template_response(
    request: &DisclosureTemplateRenderRequest,
) -> Result<DisclosureTemplateResponse> {
    let default_redaction_groups = disclosure_template_default_redaction_groups(&request.profile);
    let mut policy = disclosure_policy_template(
        &request.profile,
        request.name.as_deref(),
        &request.redaction_groups,
    )?;
    if !request.redacted_fields_by_item_type.is_empty() {
        for (item_type, selectors) in &request.redacted_fields_by_item_type {
            let bucket = policy
                .redacted_fields_by_item_type
                .entry(item_type.clone())
                .or_default();
            for selector in selectors {
                if !bucket.contains(selector) {
                    bucket.push(selector.clone());
                }
            }
        }
        policy = validate_single_disclosure_policy(policy)?;
    }

    Ok(DisclosureTemplateResponse {
        profile: request.profile.clone(),
        description: disclosure_template_description(&request.profile)?.to_string(),
        default_redaction_groups,
        policy,
    })
}

fn disclosure_policy_template(
    profile: &str,
    name: Option<&str>,
    groups: &[String],
) -> Result<DisclosurePolicyConfig> {
    let profile = normalize_disclosure_template_profile(profile)?;
    let mut policy = match profile {
        DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM => DisclosurePolicyConfig {
            name: profile.to_string(),
            allowed_item_types: Vec::new(),
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: false,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: BTreeMap::new(),
        },
        DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED => DisclosurePolicyConfig {
            name: profile.to_string(),
            allowed_item_types: vec![
                "technical_doc".to_string(),
                "risk_assessment".to_string(),
                "data_governance".to_string(),
                "instructions_for_use".to_string(),
                "human_oversight".to_string(),
                "qms_record".to_string(),
                "standards_alignment".to_string(),
                "post_market_monitoring".to_string(),
                "corrective_action".to_string(),
            ],
            excluded_item_types: Vec::new(),
            allowed_obligation_refs: Vec::new(),
            excluded_obligation_refs: Vec::new(),
            include_artefact_metadata: true,
            include_artefact_bytes: false,
            artefact_names: Vec::new(),
            redacted_fields_by_item_type: annex_iv_default_redactions(),
        },
        DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY => DisclosurePolicyConfig {
            name: profile.to_string(),
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
        DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM => DisclosurePolicyConfig {
            name: profile.to_string(),
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
        DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW => DisclosurePolicyConfig {
            name: profile.to_string(),
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
        _ => unreachable!(),
    };

    if let Some(name) = name {
        policy.name = name.to_string();
    }

    let mut all_groups = disclosure_template_default_redaction_groups(profile);
    all_groups.extend(groups.iter().cloned());
    apply_disclosure_redaction_groups(&mut policy, &all_groups)?;
    validate_single_disclosure_policy(policy)
}

fn disclosure_template_description(profile: &str) -> Result<&'static str> {
    match normalize_disclosure_template_profile(profile)? {
        DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM => {
            Ok("Minimal disclosure suitable for broad regulator or verifier review.")
        }
        DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED => {
            Ok("Annex IV-oriented documentation disclosure with artefact payload inclusion.")
        }
        DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY => {
            Ok("Incident-focused disclosure that excludes raw runtime interaction traces.")
        }
        DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM => {
            Ok("Runtime evidence disclosure with standard commitment and telemetry redactions.")
        }
        DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW => {
            Ok("Privacy review disclosure with metadata, commitment, and operational redactions.")
        }
        _ => unreachable!(),
    }
}

fn disclosure_template_default_redaction_groups(profile: &str) -> Vec<String> {
    match profile {
        DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM => vec![
            "commitments".to_string(),
            "parameters".to_string(),
            "operational_metrics".to_string(),
        ],
        DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW => vec![
            "commitments".to_string(),
            "metadata".to_string(),
            "parameters".to_string(),
            "operational_metrics".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn disclosure_redaction_groups() -> [(&'static str, &'static str); 4] {
    [
        (
            "commitments",
            "Hide digest/commitment fields while preserving proof-bearing metadata.",
        ),
        (
            "metadata",
            "Hide nested metadata blobs commonly used for internal reviewer/operator context.",
        ),
        (
            "parameters",
            "Hide model/runtime parameter objects such as temperature or top_p.",
        ),
        (
            "operational_metrics",
            "Hide token counts, latency, and trace semantic-convention metadata.",
        ),
    ]
}

fn apply_disclosure_redaction_groups(
    policy: &mut DisclosurePolicyConfig,
    groups: &[String],
) -> Result<()> {
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
            for selector in disclosure_redaction_group_selectors(&item_type, group)? {
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

    Ok(())
}

fn disclosure_redaction_group_description(group: &str) -> Result<&'static str> {
    disclosure_redaction_groups()
        .into_iter()
        .find_map(|(name, description)| (name == group).then_some(description))
        .ok_or_else(|| anyhow::anyhow!("unsupported disclosure redaction group {group}"))
}

fn disclosure_redaction_group_selectors(
    item_type: &str,
    group: &str,
) -> Result<&'static [&'static str]> {
    match group {
        "commitments" => Ok(match item_type {
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
        }),
        "metadata" => Ok(match item_type {
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
        }),
        "parameters" => Ok(match item_type {
            "llm_interaction" => &["/parameters"],
            _ => &[],
        }),
        "operational_metrics" => Ok(match item_type {
            "llm_interaction" => &["/token_usage", "/latency_ms", "/trace_semconv_version"],
            _ => &[],
        }),
        _ => Err(anyhow::anyhow!(
            "unsupported disclosure redaction group {group}"
        )),
    }
}

fn default_disclosure_config() -> DisclosureConfig {
    DisclosureConfig {
        policies: vec![
            DisclosurePolicyConfig {
                name: DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM.to_string(),
                allowed_item_types: Vec::new(),
                excluded_item_types: Vec::new(),
                allowed_obligation_refs: Vec::new(),
                excluded_obligation_refs: Vec::new(),
                include_artefact_metadata: false,
                include_artefact_bytes: false,
                artefact_names: Vec::new(),
                redacted_fields_by_item_type: BTreeMap::new(),
            },
            DisclosurePolicyConfig {
                name: DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED.to_string(),
                allowed_item_types: vec![
                    "technical_doc".to_string(),
                    "risk_assessment".to_string(),
                    "data_governance".to_string(),
                    "instructions_for_use".to_string(),
                    "human_oversight".to_string(),
                    "qms_record".to_string(),
                    "standards_alignment".to_string(),
                    "post_market_monitoring".to_string(),
                    "corrective_action".to_string(),
                ],
                excluded_item_types: Vec::new(),
                allowed_obligation_refs: Vec::new(),
                excluded_obligation_refs: Vec::new(),
                include_artefact_metadata: true,
                include_artefact_bytes: false,
                artefact_names: Vec::new(),
                redacted_fields_by_item_type: annex_iv_default_redactions(),
            },
            DisclosurePolicyConfig {
                name: DEFAULT_DISCLOSURE_POLICY_INCIDENT_SUMMARY.to_string(),
                allowed_item_types: vec![
                    "incident_report".to_string(),
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
        ],
    }
}

async fn load_timestamp_config(db: &SqlitePool) -> Result<TimestampConfig> {
    match load_service_config::<TimestampConfig>(db, SERVICE_CONFIG_KEY_TIMESTAMP).await? {
        Some(config) => validate_timestamp_config(config),
        None => Ok(default_timestamp_config()),
    }
}

async fn load_transparency_config(db: &SqlitePool) -> Result<TransparencyConfig> {
    match load_service_config::<TransparencyConfig>(db, SERVICE_CONFIG_KEY_TRANSPARENCY).await? {
        Some(config) => validate_transparency_config(config),
        None => Ok(default_transparency_config()),
    }
}

async fn load_disclosure_config(db: &SqlitePool) -> Result<DisclosureConfig> {
    match load_service_config::<DisclosureConfig>(db, SERVICE_CONFIG_KEY_DISCLOSURE).await? {
        Some(config) => validate_disclosure_config(config),
        None => Ok(default_disclosure_config()),
    }
}

async fn load_service_config<T>(db: &SqlitePool, key: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let row = sqlx::query_as::<_, StoredServiceConfigRow>(
        "SELECT config_json FROM service_config WHERE config_key = ?",
    )
    .bind(key)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load service config {key}"))?;

    row.map(|row| {
        serde_json::from_str(&row.config_json)
            .with_context(|| format!("failed to parse service config {key}"))
    })
    .transpose()
}

async fn upsert_service_config<T>(db: &SqlitePool, key: &str, value: &T) -> Result<()>
where
    T: Serialize,
{
    let config_json = serde_json::to_string(value)
        .with_context(|| format!("failed to serialize service config {key}"))?;
    sqlx::query(
        "INSERT INTO service_config (
            config_key,
            config_json,
            updated_at
        ) VALUES (?, ?, ?)
        ON CONFLICT(config_key) DO UPDATE SET
            config_json = excluded.config_json,
            updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(config_json)
    .bind(Utc::now().to_rfc3339())
    .execute(db)
    .await
    .with_context(|| format!("failed to upsert service config {key}"))?;
    Ok(())
}

async fn load_retention_policies(db: &SqlitePool) -> Result<Vec<RetentionPolicyConfig>> {
    let rows = sqlx::query_as::<_, StoredRetentionPolicyRow>(
        "SELECT
            retention_class,
            expiry_mode,
            min_duration_days,
            max_duration_days,
            legal_basis,
            active
         FROM retention_policies
         ORDER BY retention_class ASC",
    )
    .fetch_all(db)
    .await
    .context("failed to load retention policies")?;

    rows.into_iter()
        .map(|row| {
            Ok(RetentionPolicyConfig {
                retention_class: row.retention_class,
                expiry_mode: parse_retention_expiry_mode(&row.expiry_mode)?,
                min_duration_days: row.min_duration_days,
                max_duration_days: row.max_duration_days,
                legal_basis: row.legal_basis,
                active: row.active,
            })
        })
        .collect::<Result<Vec<_>>>()
}

async fn load_active_bundle(db: &SqlitePool, bundle_id: &str) -> Result<Option<ProofBundle>> {
    let bundle_json: Option<String> = sqlx::query_scalar(
        "SELECT bundle_json FROM bundles WHERE bundle_id = ? AND deleted_at IS NULL",
    )
    .bind(bundle_id)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load bundle {bundle_id}"))?;

    bundle_json
        .map(|bundle_json| {
            serde_json::from_str(&bundle_json)
                .with_context(|| format!("failed to parse bundle_json for {bundle_id}"))
        })
        .transpose()
}

async fn upsert_retention_policy(db: &SqlitePool, policy: &RetentionPolicyConfig) -> Result<()> {
    sqlx::query(
        "INSERT INTO retention_policies (
            retention_class,
            expiry_mode,
            min_duration_days,
            max_duration_days,
            legal_basis,
            active
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(retention_class) DO UPDATE SET
            expiry_mode = excluded.expiry_mode,
            min_duration_days = excluded.min_duration_days,
            max_duration_days = excluded.max_duration_days,
            legal_basis = excluded.legal_basis,
            active = excluded.active",
    )
    .bind(policy.retention_class.trim())
    .bind(retention_expiry_mode_value(policy.expiry_mode))
    .bind(policy.min_duration_days)
    .bind(policy.max_duration_days)
    .bind(policy.legal_basis.trim())
    .bind(policy.active)
    .execute(db)
    .await
    .with_context(|| {
        format!(
            "failed to upsert retention policy {}",
            policy.retention_class
        )
    })?;
    Ok(())
}

async fn refresh_active_bundle_expiries_for_class(
    db: &SqlitePool,
    retention_class: &str,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT bundle_id, created_at
         FROM bundles
         WHERE deleted_at IS NULL
           AND retention_class = ?",
    )
    .bind(retention_class)
    .fetch_all(db)
    .await
    .with_context(|| {
        format!(
            "failed to fetch active bundles for retention class {}",
            retention_class
        )
    })?;

    for row in rows {
        let bundle_id: String = row.try_get("bundle_id")?;
        let created_at: String = row.try_get("created_at")?;
        let expires_at = resolve_expires_at(db, retention_class, &created_at).await?;
        sqlx::query("UPDATE bundles SET expires_at = ? WHERE bundle_id = ?")
            .bind(expires_at)
            .bind(&bundle_id)
            .execute(db)
            .await
            .with_context(|| {
                format!(
                    "failed to refresh expires_at for bundle {} in class {}",
                    bundle_id, retention_class
                )
            })?;
    }

    Ok(())
}

fn parse_retention_grace_period_days(raw: &str) -> Result<i64> {
    let days = raw
        .trim()
        .parse::<i64>()
        .with_context(|| format!("invalid PROOF_SERVICE_RETENTION_GRACE_DAYS value {raw}"))?;
    if days < 0 {
        bail!("PROOF_SERVICE_RETENTION_GRACE_DAYS must be >= 0");
    }
    Ok(days)
}

fn parse_retention_scan_interval_hours(raw: &str) -> Result<i64> {
    let hours = raw.trim().parse::<i64>().with_context(|| {
        format!("invalid PROOF_SERVICE_RETENTION_SCAN_INTERVAL_HOURS value {raw}")
    })?;
    if hours < 0 {
        bail!("PROOF_SERVICE_RETENTION_SCAN_INTERVAL_HOURS must be >= 0");
    }
    Ok(hours)
}

fn parse_backup_interval_hours(raw: &str) -> Result<i64> {
    let hours = raw
        .trim()
        .parse::<i64>()
        .with_context(|| format!("invalid PROOF_SERVICE_BACKUP_INTERVAL_HOURS value {raw}"))?;
    if hours < 0 {
        bail!("PROOF_SERVICE_BACKUP_INTERVAL_HOURS must be >= 0");
    }
    Ok(hours)
}

fn parse_backup_retention_count(raw: &str) -> Result<usize> {
    let count = raw
        .trim()
        .parse::<usize>()
        .with_context(|| format!("invalid PROOF_SERVICE_BACKUP_RETENTION_COUNT value {raw}"))?;
    if count == 0 {
        bail!("PROOF_SERVICE_BACKUP_RETENTION_COUNT must be >= 1");
    }
    Ok(count)
}

fn parse_max_payload_bytes(raw: &str) -> Result<usize> {
    raw.trim()
        .parse::<usize>()
        .with_context(|| format!("invalid PROOF_SERVICE_MAX_PAYLOAD_BYTES value {raw}"))
}

fn normalize_legal_hold_reason(raw: &str) -> Result<String> {
    let reason = raw.trim();
    if reason.is_empty() {
        bail!("legal hold reason must not be empty");
    }
    Ok(reason.to_string())
}

fn normalize_legal_hold_until(value: Option<&str>, now: &str) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let until = value.trim();
    if until.is_empty() {
        bail!("legal hold until must not be empty");
    }

    let parsed_until = chrono::DateTime::parse_from_rfc3339(until)
        .with_context(|| format!("legal hold until must be RFC3339, got {until}"))?
        .with_timezone(&Utc);
    let parsed_now = chrono::DateTime::parse_from_rfc3339(now)
        .with_context(|| format!("current timestamp must be RFC3339, got {now}"))?
        .with_timezone(&Utc);
    if parsed_until <= parsed_now {
        bail!("legal hold until must be in the future");
    }

    Ok(Some(parsed_until.to_rfc3339()))
}

fn legal_hold_is_active(reason: Option<&str>, until: Option<&str>, now: &str) -> bool {
    let Some(reason) = reason else {
        return false;
    };
    if reason.trim().is_empty() {
        return false;
    }

    match until {
        Some(until) => chrono::DateTime::parse_from_rfc3339(until)
            .ok()
            .zip(chrono::DateTime::parse_from_rfc3339(now).ok())
            .map(|(until, now)| until.with_timezone(&Utc) > now.with_timezone(&Utc))
            .unwrap_or(false),
        None => true,
    }
}

async fn load_bundle_retention_row(
    db: &SqlitePool,
    bundle_id: &str,
) -> Result<Option<BundleRetentionRow>> {
    sqlx::query_as::<_, BundleRetentionRow>(
        "SELECT
            bundle_id,
            deleted_at,
            legal_hold_reason,
            legal_hold_until
         FROM bundles
         WHERE bundle_id = ?",
    )
    .bind(bundle_id)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load bundle retention state for {bundle_id}"))
}

async fn hard_delete_bundles(state: &AppState, hard_delete_before: &str, now: &str) -> Result<u64> {
    let rows = sqlx::query(
        "SELECT bundle_id
         FROM bundles
         WHERE deleted_at IS NOT NULL
           AND deleted_at <= ?
           AND NOT (
                legal_hold_reason IS NOT NULL
                AND (legal_hold_until IS NULL OR legal_hold_until > ?)
           )
         ORDER BY bundle_id ASC",
    )
    .bind(hard_delete_before)
    .bind(now)
    .fetch_all(&state.db)
    .await
    .context("failed to fetch hard-delete bundle candidates")?;

    let mut hard_deleted = 0_u64;
    for row in rows {
        let bundle_id: String = row.try_get("bundle_id")?;
        delete_bundle_storage(&state.db, &state.storage_dir, &bundle_id).await?;
        sqlx::query("DELETE FROM bundles WHERE bundle_id = ?")
            .bind(&bundle_id)
            .execute(&state.db)
            .await
            .with_context(|| format!("failed to delete bundle metadata for {bundle_id}"))?;
        hard_deleted += 1;
    }

    Ok(hard_deleted)
}

async fn delete_bundle_storage(
    db: &SqlitePool,
    storage_dir: &FsPath,
    bundle_id: &str,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT storage_path
         FROM artefacts
         WHERE bundle_id = ?",
    )
    .bind(bundle_id)
    .fetch_all(db)
    .await
    .with_context(|| format!("failed to load artefact paths for {bundle_id}"))?;

    for row in rows {
        let storage_path: String = row.try_get("storage_path")?;
        match fs::remove_file(&storage_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("failed to remove artefact {storage_path}")));
            }
        }
    }

    let bundle_dir = storage_dir.join("artefacts").join(bundle_id);
    match fs::remove_dir_all(&bundle_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "failed to remove artefact directory {}",
                bundle_dir.display()
            )));
        }
    }

    Ok(())
}

fn load_signing_key(signing_key_path: Option<&FsPath>) -> Result<(SigningKey, bool)> {
    if let Some(path) = signing_key_path {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read signing key {}", path.display()))?;
        let key = decode_private_key_pem(&contents)
            .with_context(|| format!("failed to parse private key at {}", path.display()))?;
        return Ok((key, false));
    }

    warn!("no signing key configured, generating ephemeral signing key");
    let secret = rand::random::<[u8; 32]>();
    Ok((SigningKey::from_bytes(&secret), true))
}

fn build_demo_provider_registry() -> Result<Arc<DemoProviderRegistry>> {
    let openai = env::var("OPENAI_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(OpenAiDemoClient::new)
        .transpose()?
        .map(|client| Arc::new(client) as Arc<dyn DemoProviderClient>);
    let anthropic = env::var("ANTHROPIC_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(AnthropicDemoClient::new)
        .transpose()?
        .map(|client| Arc::new(client) as Arc<dyn DemoProviderClient>);

    Ok(Arc::new(DemoProviderRegistry { openai, anthropic }))
}

fn persist_artefacts(base: &FsPath, bundle_id: &str, artefacts: &[ArtefactInput]) -> Result<()> {
    let bundle_dir = base.join("artefacts").join(bundle_id);
    fs::create_dir_all(&bundle_dir)
        .with_context(|| format!("failed to create artefact dir {}", bundle_dir.display()))?;

    for artefact in artefacts {
        let path = artefact_path(base, bundle_id, &artefact.name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create parent {}", parent.display()))?;
        }

        let tmp_path = path.with_extension(format!("tmp-{}", generate_bundle_id()));
        let mut file = File::create(&tmp_path)
            .with_context(|| format!("failed to create temp artefact {}", tmp_path.display()))?;
        file.write_all(&artefact.bytes)
            .with_context(|| format!("failed to write temp artefact {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temp artefact {}", tmp_path.display()))?;

        fs::rename(&tmp_path, &path).with_context(|| {
            format!(
                "failed to atomically rename {} to {}",
                tmp_path.display(),
                path.display()
            )
        })?;
    }

    Ok(())
}

async fn persist_bundle_metadata(
    db: &SqlitePool,
    storage_dir: &FsPath,
    bundle: &ProofBundle,
) -> Result<()> {
    let bundle_json = serde_json::to_string(bundle)?;
    let canonical_bytes = bundle.canonical_header_bytes()?;
    let retention_class = bundle
        .policy
        .retention_class
        .clone()
        .unwrap_or_else(|| "unspecified".to_string());
    let expires_at = resolve_bundle_expiry(db, bundle).await?;

    let mut tx = db
        .begin()
        .await
        .context("failed to begin sqlite transaction")?;

    sqlx::query(
        "INSERT INTO bundles (
            bundle_id,
            bundle_version,
            created_at,
            actor_role,
            actor_org_id,
            system_id,
            model_id,
            deployment_id,
            request_id,
            app_id,
            bundle_root,
            signature_alg,
            has_timestamp,
            has_receipt,
            retention_class,
            expires_at,
            deleted_at,
            bundle_json,
            canonical_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
    )
    .bind(&bundle.bundle_id)
    .bind(&bundle.bundle_version)
    .bind(&bundle.created_at)
    .bind(actor_role_name(bundle))
    .bind(bundle.actor.organization_id.as_deref())
    .bind(bundle.subject.system_id.as_deref())
    .bind(bundle.subject.model_id.as_deref())
    .bind(bundle.subject.deployment_id.as_deref())
    .bind(bundle.subject.request_id.as_deref())
    .bind(&bundle.actor.app_id)
    .bind(&bundle.integrity.bundle_root)
    .bind(&bundle.integrity.signature.alg)
    .bind(bundle.timestamp.is_some())
    .bind(bundle.receipt.is_some())
    .bind(&retention_class)
    .bind(expires_at)
    .bind(&bundle_json)
    .bind(canonical_bytes)
    .execute(&mut *tx)
    .await
    .context("failed to insert bundle row")?;

    for (index, item) in bundle.items.iter().enumerate() {
        let item_value = serde_json::to_value(item)?;
        let item_commitment = sha256_prefixed(&canonicalize_value(&item_value)?);
        let metadata_json = serde_json::to_string(&item_value)?;
        let obligation_ref = evidence_item_obligation_ref(bundle, item);

        sqlx::query(
            "INSERT INTO evidence_items (
                bundle_id,
                item_index,
                item_type,
                obligation_ref,
                item_commitment,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&bundle.bundle_id)
        .bind(index as i64)
        .bind(evidence_item_type(item))
        .bind(obligation_ref)
        .bind(item_commitment)
        .bind(metadata_json)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to insert evidence item index {index}"))?;
    }

    for artefact in &bundle.artefacts {
        let storage_path = artefact_path(storage_dir, &bundle.bundle_id, &artefact.name)?;
        sqlx::query(
            "INSERT INTO artefacts (
                bundle_id,
                name,
                digest,
                size,
                content_type,
                storage_path
            ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&bundle.bundle_id)
        .bind(&artefact.name)
        .bind(&artefact.digest)
        .bind(artefact.size as i64)
        .bind(&artefact.content_type)
        .bind(storage_path.to_string_lossy().to_string())
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to insert artefact metadata {}", artefact.name))?;
    }

    tx.commit()
        .await
        .context("failed to commit sqlite transaction")?;
    Ok(())
}

async fn persist_bundle_timestamp(db: &SqlitePool, bundle: &ProofBundle) -> Result<()> {
    let bundle_json = serde_json::to_string(bundle)?;
    sqlx::query(
        "UPDATE bundles
         SET has_timestamp = ?, bundle_json = ?
         WHERE bundle_id = ?",
    )
    .bind(bundle.timestamp.is_some())
    .bind(bundle_json)
    .bind(&bundle.bundle_id)
    .execute(db)
    .await
    .with_context(|| format!("failed to update timestamp for bundle {}", bundle.bundle_id))?;
    Ok(())
}

async fn persist_bundle_receipt(db: &SqlitePool, bundle: &ProofBundle) -> Result<()> {
    let bundle_json = serde_json::to_string(bundle)?;
    sqlx::query(
        "UPDATE bundles
         SET has_receipt = ?, bundle_json = ?
         WHERE bundle_id = ?",
    )
    .bind(bundle.receipt.is_some())
    .bind(bundle_json)
    .bind(&bundle.bundle_id)
    .execute(db)
    .await
    .with_context(|| format!("failed to update receipt for bundle {}", bundle.bundle_id))?;
    Ok(())
}

fn map_build_bundle_error(err: BuildBundleError) -> ApiError {
    match err {
        BuildBundleError::EmptyArtefacts
        | BuildBundleError::EmptyArtefactName
        | BuildBundleError::DuplicateArtefactName(_) => ApiError::bad_request(err.to_string()),
        _ => ApiError::internal_anyhow(err),
    }
}

fn actor_role_name(bundle: &ProofBundle) -> &'static str {
    match bundle.actor.role {
        proof_layer_core::ActorRole::Provider => "provider",
        proof_layer_core::ActorRole::Deployer => "deployer",
        proof_layer_core::ActorRole::Integrator => "integrator",
        proof_layer_core::ActorRole::Importer => "importer",
        proof_layer_core::ActorRole::Distributor => "distributor",
        proof_layer_core::ActorRole::AuthorizedRepresentative => "authorized_representative",
        proof_layer_core::ActorRole::GpaiProvider => "gpai_provider",
    }
}

fn evidence_item_type(item: &EvidenceItem) -> &'static str {
    match item {
        EvidenceItem::LlmInteraction(_) => "llm_interaction",
        EvidenceItem::ToolCall(_) => "tool_call",
        EvidenceItem::Retrieval(_) => "retrieval",
        EvidenceItem::HumanOversight(_) => "human_oversight",
        EvidenceItem::PolicyDecision(_) => "policy_decision",
        EvidenceItem::RiskAssessment(_) => "risk_assessment",
        EvidenceItem::DataGovernance(_) => "data_governance",
        EvidenceItem::TechnicalDoc(_) => "technical_doc",
        EvidenceItem::InstructionsForUse(_) => "instructions_for_use",
        EvidenceItem::QmsRecord(_) => "qms_record",
        EvidenceItem::FundamentalRightsAssessment(_) => "fundamental_rights_assessment",
        EvidenceItem::StandardsAlignment(_) => "standards_alignment",
        EvidenceItem::PostMarketMonitoring(_) => "post_market_monitoring",
        EvidenceItem::CorrectiveAction(_) => "corrective_action",
        EvidenceItem::AuthorityNotification(_) => "authority_notification",
        EvidenceItem::AuthoritySubmission(_) => "authority_submission",
        EvidenceItem::ReportingDeadline(_) => "reporting_deadline",
        EvidenceItem::RegulatorCorrespondence(_) => "regulator_correspondence",
        EvidenceItem::ModelEvaluation(_) => "model_evaluation",
        EvidenceItem::AdversarialTest(_) => "adversarial_test",
        EvidenceItem::TrainingProvenance(_) => "training_provenance",
        EvidenceItem::DownstreamDocumentation(_) => "downstream_documentation",
        EvidenceItem::CopyrightPolicy(_) => "copyright_policy",
        EvidenceItem::TrainingSummary(_) => "training_summary",
        EvidenceItem::ConformityAssessment(_) => "conformity_assessment",
        EvidenceItem::Declaration(_) => "declaration",
        EvidenceItem::Registration(_) => "registration",
        EvidenceItem::LiteracyAttestation(_) => "literacy_attestation",
        EvidenceItem::IncidentReport(_) => "incident_report",
        EvidenceItem::ComputeMetrics(_) => "compute_metrics",
    }
}

fn retention_expiry_mode_value(mode: RetentionExpiryMode) -> &'static str {
    match mode {
        RetentionExpiryMode::FixedDays => "fixed_days",
        RetentionExpiryMode::UntilWithdrawn => "until_withdrawn",
    }
}

fn parse_retention_expiry_mode(value: &str) -> Result<RetentionExpiryMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fixed_days" => Ok(RetentionExpiryMode::FixedDays),
        "until_withdrawn" => Ok(RetentionExpiryMode::UntilWithdrawn),
        other => bail!("unsupported retention expiry_mode {other}"),
    }
}

async fn resolve_expires_at(
    db: &SqlitePool,
    retention_class: &str,
    created_at: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT min_duration_days, expiry_mode
         FROM retention_policies
         WHERE retention_class = ? AND active = TRUE",
    )
    .bind(retention_class)
    .fetch_optional(db)
    .await
    .with_context(|| format!("failed to load retention policy {retention_class}"))?
    .with_context(|| format!("unknown retention policy {retention_class}"))?;
    let min_duration_days: i64 = row.try_get("min_duration_days").with_context(|| {
        format!("retention policy {retention_class} is missing min_duration_days")
    })?;
    let expiry_mode_raw: String = row
        .try_get("expiry_mode")
        .with_context(|| format!("retention policy {retention_class} is missing expiry_mode"))?;
    if parse_retention_expiry_mode(&expiry_mode_raw)? == RetentionExpiryMode::UntilWithdrawn {
        return Ok(None);
    }

    let created_at = chrono::DateTime::parse_from_rfc3339(created_at)
        .with_context(|| format!("bundle created_at must be RFC3339, got {created_at}"))?
        .with_timezone(&Utc);
    let expires_at = created_at + chrono::Duration::days(min_duration_days);
    Ok(Some(expires_at.to_rfc3339()))
}

async fn resolve_bundle_expiry(db: &SqlitePool, bundle: &ProofBundle) -> Result<Option<String>> {
    let retention_class = bundle
        .policy
        .retention_class
        .as_deref()
        .unwrap_or("unspecified");
    resolve_expires_at(db, retention_class, &bundle.created_at).await
}

fn artefact_path(base: &FsPath, bundle_id: &str, name: &str) -> Result<PathBuf> {
    validate_artefact_name(name)?;
    Ok(base.join("artefacts").join(bundle_id).join(name))
}

fn validate_artefact_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("artefact name must not be empty");
    }

    let path = FsPath::new(name);
    if path.is_absolute() {
        bail!("artefact name must be relative");
    }

    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!("artefact name contains path traversal segment");
        }
    }

    Ok(())
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

fn generate_bundle_id() -> String {
    Ulid::new().to_string()
}

async fn open_sqlite_pool(path: &FsPath) -> Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create sqlite parent dir {}", parent.display()))?;
    }

    let options = SqliteConnectOptions::from_str("sqlite://")
        .context("failed to construct sqlite connect options")?
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true);

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .with_context(|| format!("failed to open sqlite db {}", path.display()))
}

async fn initialize_sqlite_schema(db: &SqlitePool) -> Result<()> {
    let statements = [
        "CREATE TABLE IF NOT EXISTS bundles (
            bundle_id TEXT PRIMARY KEY,
            bundle_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            actor_org_id TEXT,
            system_id TEXT,
            model_id TEXT,
            deployment_id TEXT,
            request_id TEXT,
            app_id TEXT NOT NULL,
            bundle_root TEXT NOT NULL,
            signature_alg TEXT NOT NULL,
            has_timestamp BOOLEAN NOT NULL DEFAULT FALSE,
            has_receipt BOOLEAN NOT NULL DEFAULT FALSE,
            retention_class TEXT NOT NULL,
            expires_at TEXT,
            deleted_at TEXT,
            legal_hold_reason TEXT,
            legal_hold_until TEXT,
            legal_hold_placed_at TEXT,
            bundle_json TEXT NOT NULL,
            canonical_bytes BLOB NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_bundles_system ON bundles(system_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_role ON bundles(actor_role, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_request ON bundles(request_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_app ON bundles(app_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_retention ON bundles(retention_class, expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_legal_hold ON bundles(legal_hold_until, deleted_at)",
        "CREATE TABLE IF NOT EXISTS evidence_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
            item_index INTEGER NOT NULL,
            item_type TEXT NOT NULL,
            obligation_ref TEXT,
            item_commitment TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_items_type ON evidence_items(item_type, bundle_id)",
        "CREATE INDEX IF NOT EXISTS idx_items_obligation ON evidence_items(obligation_ref, bundle_id)",
        "CREATE TABLE IF NOT EXISTS artefacts (
            bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            digest TEXT NOT NULL,
            size INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            PRIMARY KEY (bundle_id, name)
        )",
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT,
            bundle_id TEXT,
            pack_id TEXT,
            details_json TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_bundle ON audit_log(bundle_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_pack ON audit_log(pack_id, id)",
        "CREATE TABLE IF NOT EXISTS packs (
            pack_id TEXT PRIMARY KEY,
            pack_type TEXT NOT NULL,
            system_id TEXT,
            created_at TEXT NOT NULL,
            from_date TEXT,
            to_date TEXT,
            bundle_count INTEGER NOT NULL,
            export_path TEXT NOT NULL,
            manifest_json TEXT NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_packs_type ON packs(pack_type, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_packs_system ON packs(system_id, created_at)",
        "CREATE TABLE IF NOT EXISTS retention_policies (
            retention_class TEXT PRIMARY KEY,
            expiry_mode TEXT NOT NULL DEFAULT 'fixed_days',
            min_duration_days INTEGER NOT NULL,
            max_duration_days INTEGER,
            legal_basis TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT TRUE
        )",
        "CREATE TABLE IF NOT EXISTS service_config (
            config_key TEXT PRIMARY KEY,
            config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
    ];

    for statement in statements {
        sqlx::query(statement)
            .execute(db)
            .await
            .with_context(|| format!("failed to execute sqlite schema statement: {statement}"))?;
    }

    ensure_sqlite_column(db, "bundles", "expires_at", "TEXT").await?;
    ensure_sqlite_column(db, "bundles", "legal_hold_reason", "TEXT").await?;
    ensure_sqlite_column(db, "bundles", "legal_hold_until", "TEXT").await?;
    ensure_sqlite_column(db, "bundles", "legal_hold_placed_at", "TEXT").await?;
    ensure_sqlite_column(db, "packs", "pack_completeness_report_json", "TEXT").await?;
    ensure_sqlite_column(
        db,
        "retention_policies",
        "expiry_mode",
        "TEXT NOT NULL DEFAULT 'fixed_days'",
    )
    .await?;

    Ok(())
}

async fn ensure_sqlite_column(
    db: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let rows = sqlx::query(&pragma)
        .fetch_all(db)
        .await
        .with_context(|| format!("failed to inspect sqlite table {table}"))?;

    let exists = rows.iter().any(|row| {
        row.try_get::<String, _>("name")
            .map(|name| name == column)
            .unwrap_or(false)
    });

    if !exists {
        let alter = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        sqlx::query(&alter)
            .execute(db)
            .await
            .with_context(|| format!("failed to add sqlite column {table}.{column}"))?;
    }

    Ok(())
}

async fn seed_default_retention_policies(db: &SqlitePool) -> Result<()> {
    let defaults: [(&str, RetentionExpiryMode, i64, Option<i64>, &str); 6] = [
        (
            "unspecified",
            RetentionExpiryMode::FixedDays,
            365_i64,
            None,
            "operational_default",
        ),
        (
            "runtime_logs",
            RetentionExpiryMode::FixedDays,
            3650_i64,
            None,
            "eu_ai_act_article_12_19_26",
        ),
        (
            "risk_mgmt",
            RetentionExpiryMode::FixedDays,
            3650_i64,
            None,
            "eu_ai_act_article_9",
        ),
        (
            "technical_doc",
            RetentionExpiryMode::FixedDays,
            3650_i64,
            None,
            "eu_ai_act_annex_iv",
        ),
        (
            "gpai_documentation",
            RetentionExpiryMode::UntilWithdrawn,
            0_i64,
            None,
            "eu_ai_act_article_53_until_withdrawn",
        ),
        (
            "ai_literacy",
            RetentionExpiryMode::FixedDays,
            1095_i64,
            None,
            "eu_ai_act_article_4",
        ),
    ];

    for (retention_class, expiry_mode, min_duration_days, max_duration_days, legal_basis) in
        defaults
    {
        sqlx::query(
            "INSERT INTO retention_policies (
                retention_class,
                expiry_mode,
                min_duration_days,
                max_duration_days,
                legal_basis,
                active
            ) VALUES (?, ?, ?, ?, ?, TRUE)
            ON CONFLICT(retention_class) DO NOTHING",
        )
        .bind(retention_class)
        .bind(retention_expiry_mode_value(expiry_mode))
        .bind(min_duration_days)
        .bind(max_duration_days)
        .bind(legal_basis)
        .execute(db)
        .await
        .with_context(|| format!("failed to seed retention policy {retention_class}"))?;
    }

    Ok(())
}

async fn seed_default_disclosure_config(db: &SqlitePool) -> Result<()> {
    if load_service_config::<DisclosureConfig>(db, SERVICE_CONFIG_KEY_DISCLOSURE)
        .await?
        .is_none()
    {
        upsert_service_config(
            db,
            SERVICE_CONFIG_KEY_DISCLOSURE,
            &default_disclosure_config(),
        )
        .await?;
    }

    Ok(())
}

async fn backfill_bundle_expiries(db: &SqlitePool) -> Result<()> {
    let rows = sqlx::query(
        "SELECT bundle_id, created_at, retention_class
         FROM bundles
         WHERE expires_at IS NULL",
    )
    .fetch_all(db)
    .await
    .context("failed to fetch bundles missing expires_at")?;

    for row in rows {
        let bundle_id: String = row.try_get("bundle_id")?;
        let created_at: String = row.try_get("created_at")?;
        let retention_class: String = row.try_get("retention_class")?;
        let expires_at = resolve_expires_at(db, &retention_class, &created_at).await?;

        sqlx::query("UPDATE bundles SET expires_at = ? WHERE bundle_id = ?")
            .bind(expires_at)
            .bind(&bundle_id)
            .execute(db)
            .await
            .with_context(|| format!("failed to backfill expires_at for bundle {bundle_id}"))?;
    }

    Ok(())
}

async fn backfill_item_obligation_refs(db: &SqlitePool) -> Result<()> {
    let rows = sqlx::query(
        "SELECT DISTINCT b.bundle_id, b.bundle_json
         FROM bundles b
         JOIN evidence_items i ON i.bundle_id = b.bundle_id
         WHERE i.obligation_ref IS NULL",
    )
    .fetch_all(db)
    .await
    .context("failed to fetch bundles missing obligation_ref values")?;

    for row in rows {
        let bundle_id: String = row.try_get("bundle_id")?;
        let bundle_json: String = row.try_get("bundle_json")?;
        let bundle: ProofBundle = serde_json::from_str(&bundle_json)
            .with_context(|| format!("failed to parse bundle_json for {bundle_id}"))?;

        for (index, item) in bundle.items.iter().enumerate() {
            let obligation_ref = evidence_item_obligation_ref(&bundle, item);
            if obligation_ref.is_none() {
                continue;
            }

            sqlx::query(
                "UPDATE evidence_items
                 SET obligation_ref = ?
                 WHERE bundle_id = ?
                   AND item_index = ?
                   AND obligation_ref IS NULL",
            )
            .bind(obligation_ref)
            .bind(&bundle_id)
            .bind(index as i64)
            .execute(db)
            .await
            .with_context(|| {
                format!(
                    "failed to backfill obligation_ref for bundle {} item {}",
                    bundle_id, index
                )
            })?;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn bad_request_anyhow(err: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.into().to_string(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn internal_anyhow(err: impl Into<anyhow::Error>) -> Self {
        let err = err.into();
        error!("internal error: {err:#}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use bcder::{Integer, Mode, OctetString, Oid, encode::Values};
    use cryptographic_message_syntax::{
        Bytes, SignedDataBuilder, SignerBuilder,
        asn1::rfc3161::{MessageImprint, OID_CONTENT_TYPE_TST_INFO, TstInfo},
    };
    use flate2::{Compression, read::GzDecoder, write::GzEncoder};
    use p256::{
        ecdsa::{Signature, SigningKey as P256SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
        pkcs8::{EncodePublicKey, LineEnding},
    };
    use proof_layer_core::{
        REKOR_RFC3161_API_VERSION, REKOR_RFC3161_ENTRY_KIND, REKOR_TRANSPARENCY_KIND,
        RFC3161_TIMESTAMP_KIND, SCITT_STATEMENT_PROFILE, SCITT_TRANSPARENCY_KIND, TimestampToken,
        TransparencyReceipt, decrypt_backup_archive, encode_public_key_pem, sha256_prefixed,
    };
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use tower::ServiceExt;
    use x509_certificate::{
        CapturedX509Certificate, DigestAlgorithm, InMemorySigningKeyPair, KeyAlgorithm,
        X509CertificateBuilder, certificate::KeyUsage,
    };

    fn sample_capture() -> CaptureInput {
        CaptureInput {
            actor: proof_layer_core::schema::v01::Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "test".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
            },
            subject: proof_layer_core::schema::v01::Subject {
                request_id: "req-test-1".to_string(),
                thread_id: Some("thr-test-1".to_string()),
                user_ref: Some("hmac_sha256:test".to_string()),
            },
            model: proof_layer_core::ModelInfo {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                parameters: serde_json::json!({"temperature": 0.2}),
            },
            inputs: proof_layer_core::bundle::Inputs {
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
            policy: proof_layer_core::Policy {
                redactions: vec![],
                encryption: proof_layer_core::EncryptionPolicy { enabled: false },
                retention_class: None,
            },
        }
    }

    fn sample_event_with_system(system_id: &str) -> CaptureEvent {
        let mut event = proof_layer_core::capture_input_v01_to_event(sample_capture());
        event.subject.system_id = Some(system_id.to_string());
        event
    }

    fn sample_event_with_profile(
        system_id: &str,
        role: proof_layer_core::ActorRole,
        items: Vec<EvidenceItem>,
        retention_class: Option<&str>,
    ) -> CaptureEvent {
        let mut event = sample_event_with_system(system_id);
        event.actor.role = role;
        event.items = items;
        event.policy.retention_class = retention_class.map(str::to_string);
        event
    }

    fn hiring_assistant_compliance_profile() -> proof_layer_core::ComplianceProfile {
        proof_layer_core::ComplianceProfile {
            intended_use: Some("Recruiter support for first-pass candidate review".to_string()),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("high_risk".to_string()),
            high_risk_domain: Some("employment".to_string()),
            gpai_status: None,
            systemic_risk: None,
            fria_required: None,
            deployment_context: Some("eu_market_placement".to_string()),
            metadata: serde_json::json!({
                "owner": "quality-team",
                "market": "eu",
            }),
        }
    }

    fn gpai_provider_compliance_profile() -> proof_layer_core::ComplianceProfile {
        proof_layer_core::ComplianceProfile {
            intended_use: Some("General-purpose text and workflow assistance".to_string()),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("gpai".to_string()),
            high_risk_domain: None,
            gpai_status: Some("provider".to_string()),
            systemic_risk: Some(true),
            fria_required: None,
            deployment_context: Some("eu_market_placement".to_string()),
            metadata: serde_json::json!({
                "owner": "foundation-governance",
                "market": "eu",
            }),
        }
    }

    fn post_market_monitoring_compliance_profile() -> proof_layer_core::ComplianceProfile {
        proof_layer_core::ComplianceProfile {
            intended_use: Some("Claims triage support with human review".to_string()),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("high_risk".to_string()),
            high_risk_domain: None,
            gpai_status: None,
            systemic_risk: None,
            fria_required: None,
            deployment_context: Some("eu_market_placement".to_string()),
            metadata: serde_json::json!({
                "owner": "safety-ops",
                "market": "eu",
            }),
        }
    }

    fn incident_response_compliance_profile() -> proof_layer_core::ComplianceProfile {
        proof_layer_core::ComplianceProfile {
            intended_use: Some("Public-sector benefit eligibility review".to_string()),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("high_risk".to_string()),
            high_risk_domain: None,
            gpai_status: None,
            systemic_risk: None,
            fria_required: Some(true),
            deployment_context: Some("public_sector".to_string()),
            metadata: serde_json::json!({
                "owner": "incident-ops",
                "market": "eu",
            }),
        }
    }

    fn conformity_compliance_profile() -> proof_layer_core::ComplianceProfile {
        proof_layer_core::ComplianceProfile {
            intended_use: Some(
                "High-risk employment screening system market placement".to_string(),
            ),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("high_risk".to_string()),
            high_risk_domain: Some("employment".to_string()),
            gpai_status: None,
            systemic_risk: None,
            fria_required: None,
            deployment_context: Some("eu_market_placement".to_string()),
            metadata: serde_json::json!({
                "owner": "conformity-team",
                "market": "eu",
            }),
        }
    }

    fn annex_iv_governance_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "hiring-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("hiring-model-v3".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(hiring_assistant_compliance_profile());
        event
    }

    fn gpai_provider_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "foundation-model-alpha",
            proof_layer_core::ActorRole::Provider,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("foundation-model-alpha-v5".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(gpai_provider_compliance_profile());
        event
    }

    fn post_market_monitoring_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "claims-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("claims-model-v2".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(post_market_monitoring_compliance_profile());
        event
    }

    fn incident_response_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "benefits-review",
            proof_layer_core::ActorRole::Deployer,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("eligibility-ranker-v2".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(incident_response_compliance_profile());
        event
    }

    fn provider_governance_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "hiring-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("hiring-model-v3".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(hiring_assistant_compliance_profile());
        event
    }

    fn conformity_event(
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
    ) -> CaptureEvent {
        let mut event = sample_event_with_profile(
            "system-conformity",
            proof_layer_core::ActorRole::Provider,
            vec![item],
            Some(retention_class),
        );
        event.subject.request_id = Some(request_id.to_string());
        event.subject.model_id = Some("conformity-file-v1".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(conformity_compliance_profile());
        event
    }

    async fn create_annex_iv_governance_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(annex_iv_governance_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    async fn create_gpai_provider_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(gpai_provider_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    async fn create_post_market_monitoring_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(post_market_monitoring_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    async fn create_incident_response_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(incident_response_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    async fn create_provider_governance_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(provider_governance_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    async fn create_conformity_bundle(
        app: &Router,
        item: EvidenceItem,
        retention_class: &str,
        request_id: &str,
        artefact_name: &str,
        artefact_bytes: &[u8],
    ) -> CreateBundleResponse {
        create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(conformity_event(
                    item,
                    retention_class,
                    request_id,
                )),
                artefacts: vec![InlineArtefact {
                    name: artefact_name.to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(artefact_bytes),
                }],
            },
        )
        .await
    }

    struct AnnexIvScenarioBundles {
        technical_doc: CreateBundleResponse,
        risk_assessment: CreateBundleResponse,
        data_governance: CreateBundleResponse,
        instructions_for_use: CreateBundleResponse,
        human_oversight: CreateBundleResponse,
        qms_record: CreateBundleResponse,
        standards_alignment: CreateBundleResponse,
        post_market_monitoring: CreateBundleResponse,
        runtime_logs: CreateBundleResponse,
        other_system_risk: CreateBundleResponse,
    }

    struct ProviderGovernanceScenarioBundles {
        technical_doc: CreateBundleResponse,
        risk_assessment: CreateBundleResponse,
        data_governance: CreateBundleResponse,
        instructions_for_use: CreateBundleResponse,
        qms_record: CreateBundleResponse,
        standards_alignment: CreateBundleResponse,
        post_market_monitoring: CreateBundleResponse,
        corrective_action: CreateBundleResponse,
        other_system_risk: CreateBundleResponse,
    }

    struct ConformityScenarioBundles {
        conformity_assessment: CreateBundleResponse,
        declaration: CreateBundleResponse,
        registration: CreateBundleResponse,
        other_system_bundle: CreateBundleResponse,
    }

    struct GpaiProviderScenarioBundles {
        technical_doc: CreateBundleResponse,
        model_evaluation: CreateBundleResponse,
        training_provenance: CreateBundleResponse,
        compute_metrics: CreateBundleResponse,
        copyright_policy: CreateBundleResponse,
        training_summary: CreateBundleResponse,
        other_system_bundle: CreateBundleResponse,
    }

    struct FundamentalRightsScenarioBundles {
        assessment: CreateBundleResponse,
        human_oversight: CreateBundleResponse,
    }

    struct PostMarketMonitoringScenarioBundles {
        monitoring: CreateBundleResponse,
        incident_report: CreateBundleResponse,
        corrective_action: CreateBundleResponse,
        authority_notification: CreateBundleResponse,
        authority_submission: CreateBundleResponse,
        reporting_deadline: CreateBundleResponse,
        regulator_correspondence: CreateBundleResponse,
        other_system_bundle: CreateBundleResponse,
    }

    struct IncidentResponseScenarioBundles {
        technical_doc: CreateBundleResponse,
        risk_assessment: CreateBundleResponse,
        human_oversight: CreateBundleResponse,
        policy_decision: CreateBundleResponse,
        incident_report: CreateBundleResponse,
        corrective_action: CreateBundleResponse,
        authority_notification: CreateBundleResponse,
        authority_submission: CreateBundleResponse,
        reporting_deadline: CreateBundleResponse,
        regulator_correspondence: CreateBundleResponse,
        other_system_bundle: CreateBundleResponse,
    }

    async fn create_annex_iv_scenario(app: &Router) -> AnnexIvScenarioBundles {
        let technical_doc = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "annex-iv/system-card".to_string(),
                section: Some("system_overview".to_string()),
                commitment: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
                annex_iv_sections: vec!["section_2".to_string(), "section_3".to_string()],
                system_description_summary: Some(
                    "Ranks candidates for recruiter review.".to_string(),
                ),
                model_description_summary: Some("Fine-tuned ranking model.".to_string()),
                capabilities_and_limitations: Some(
                    "Advisory only for first-pass screening.".to_string(),
                ),
                design_choices_summary: Some(
                    "Human review is required before employment decisions.".to_string(),
                ),
                evaluation_metrics_summary: Some(
                    "Precision and subgroup parity are reviewed monthly.".to_string(),
                ),
                human_oversight_design_summary: Some(
                    "Recruiters must review every adverse or borderline case.".to_string(),
                ),
                post_market_monitoring_plan_ref: Some("pmm://hiring-assistant/2026.03".to_string()),
                simplified_tech_doc: None,
            }),
            "technical_doc",
            "req-annex-iv-tech-doc",
            "technical_doc.json",
            br#"{"document_ref":"annex-iv/system-card"}"#,
        )
        .await;

        let risk_assessment = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                risk_id: "risk-001".to_string(),
                severity: "high".to_string(),
                status: "mitigated".to_string(),
                summary: Some("Bias and over-reliance risk reviewed.".to_string()),
                risk_description: Some(
                    "Potential unfair ranking of borderline candidates.".to_string(),
                ),
                likelihood: Some("medium".to_string()),
                affected_groups: vec!["job_applicants".to_string()],
                mitigation_measures: vec![
                    "mandatory human review".to_string(),
                    "monthly subgroup parity review".to_string(),
                ],
                residual_risk_level: Some("low".to_string()),
                risk_owner: Some("quality-team".to_string()),
                vulnerable_groups_considered: Some(true),
                test_results_summary: Some(
                    "No blocking disparity found in March review.".to_string(),
                ),
                metadata: serde_json::json!({
                    "internal_notes": "Escalate if parity delta exceeds 5%",
                }),
            }),
            "risk_mgmt",
            "req-annex-iv-risk",
            "risk_assessment.json",
            br#"{"risk_id":"risk-001"}"#,
        )
        .await;

        let data_governance = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::DataGovernance(proof_layer_core::schema::DataGovernanceEvidence {
                decision: "approved_with_restrictions".to_string(),
                dataset_ref: Some("dataset://hiring-assistant/training-v3".to_string()),
                dataset_name: Some("hiring-assistant-training".to_string()),
                dataset_version: Some("2026.03".to_string()),
                source_description: Some(
                    "Curated applicant and recruiter-feedback corpus.".to_string(),
                ),
                collection_period: Some(proof_layer_core::schema::DateRange {
                    start: Some("2024-01-01".to_string()),
                    end: Some("2025-12-31".to_string()),
                }),
                geographical_scope: vec!["EU".to_string()],
                preprocessing_operations: vec![
                    "deduplication".to_string(),
                    "pii_minimization".to_string(),
                    "label_review".to_string(),
                ],
                bias_detection_methodology: Some(
                    "Quarterly protected-group parity review.".to_string(),
                ),
                bias_metrics: vec![proof_layer_core::schema::MetricSummary {
                    name: "selection_rate_gap".to_string(),
                    value: "0.04".to_string(),
                    unit: Some("ratio".to_string()),
                    methodology: None,
                }],
                mitigation_actions: vec![
                    "oversample underrepresented profiles".to_string(),
                    "human review on borderline scores".to_string(),
                ],
                data_gaps: vec!["limited historic data for niche technical roles".to_string()],
                personal_data_categories: vec![
                    "employment_history".to_string(),
                    "education_history".to_string(),
                ],
                safeguards: vec![
                    "pseudonymization".to_string(),
                    "role-based dataset access".to_string(),
                ],
                metadata: serde_json::json!({
                    "owner": "data-governance-board",
                }),
            }),
            "technical_doc",
            "req-annex-iv-data",
            "data_governance.json",
            br#"{"dataset_ref":"dataset://hiring-assistant/training-v3"}"#,
        )
        .await;

        let instructions_for_use = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::InstructionsForUse(
                proof_layer_core::schema::InstructionsForUseEvidence {
                    document_ref: "docs://hiring-assistant/operator-handbook".to_string(),
                    version: Some("2026.03".to_string()),
                    section: Some("human-review-required".to_string()),
                    commitment: Some(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    ),
                    provider_identity: Some("Proof Layer Hiring Systems Ltd.".to_string()),
                    intended_purpose: Some(
                        "Recruiter support for first-pass candidate review".to_string(),
                    ),
                    system_capabilities: vec![
                        "candidate_summary".to_string(),
                        "borderline_case_flagging".to_string(),
                    ],
                    accuracy_metrics: vec![proof_layer_core::schema::MetricSummary {
                        name: "review_precision".to_string(),
                        value: "0.91".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: None,
                    }],
                    foreseeable_risks: vec!["automation bias".to_string()],
                    explainability_capabilities: Vec::new(),
                    human_oversight_guidance: vec![
                        "Review every negative or borderline recommendation.".to_string(),
                    ],
                    compute_requirements: vec!["4 vCPU".to_string(), "8GB RAM".to_string()],
                    service_lifetime: Some("12 months".to_string()),
                    log_management_guidance: vec![
                        "Retain runtime logs for post-market monitoring.".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "distribution": "internal_only",
                    }),
                },
            ),
            "technical_doc",
            "req-annex-iv-ifu",
            "instructions_for_use.json",
            br#"{"document_ref":"docs://hiring-assistant/operator-handbook"}"#,
        )
        .await;

        let human_oversight = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::HumanOversight(proof_layer_core::schema::HumanOversightEvidence {
                action: "manual_case_review_required".to_string(),
                reviewer: Some("quality-panel".to_string()),
                notes_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                actor_role: Some("human_reviewer".to_string()),
                anomaly_detected: Some(true),
                override_action: Some("escalate_to_recruiter".to_string()),
                interpretation_guidance_followed: Some(true),
                automation_bias_detected: Some(false),
                two_person_verification: Some(true),
                stop_triggered: Some(false),
                stop_reason: Some(
                    "No emergency stop was required for this review path.".to_string(),
                ),
            }),
            "risk_mgmt",
            "req-annex-iv-oversight",
            "human_oversight.json",
            br#"{"action":"manual_case_review_required"}"#,
        )
        .await;

        let qms_record = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::QmsRecord(proof_layer_core::schema::QmsRecordEvidence {
                record_id: "qms-release-approval-42".to_string(),
                process: "release_approval".to_string(),
                status: "approved".to_string(),
                record_commitment: Some(
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                ),
                policy_name: Some("Hiring Assistant Release Governance".to_string()),
                revision: Some("3.1".to_string()),
                effective_date: Some("2026-03-01".to_string()),
                expiry_date: None,
                scope: Some("EU provider release control".to_string()),
                approval_commitment: None,
                audit_results_summary: Some(
                    "Release gate approved after compliance review.".to_string(),
                ),
                continuous_improvement_actions: vec!["monitor subgroup parity monthly".to_string()],
                metadata: serde_json::json!({
                    "owner": "quality-lead",
                }),
            }),
            "technical_doc",
            "req-annex-iv-qms",
            "qms_record.json",
            br#"{"record_id":"qms-release-approval-42"}"#,
        )
        .await;

        let standards_alignment = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::StandardsAlignment(
                proof_layer_core::schema::StandardsAlignmentEvidence {
                    standard_ref: "harmonized://eu-ai-act/annex-iv".to_string(),
                    status: "aligned".to_string(),
                    scope: Some("high-risk technical documentation".to_string()),
                    mapping_commitment: Some(
                        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "compliance-mapping-team",
                    }),
                },
            ),
            "technical_doc",
            "req-annex-iv-standards",
            "standards_alignment.json",
            br#"{"standard_ref":"harmonized://eu-ai-act/annex-iv"}"#,
        )
        .await;

        let post_market_monitoring = create_annex_iv_governance_bundle(
            app,
            EvidenceItem::PostMarketMonitoring(
                proof_layer_core::schema::PostMarketMonitoringEvidence {
                    plan_id: "pmm-42".to_string(),
                    status: "active".to_string(),
                    summary: Some("Weekly drift review with escalation thresholds.".to_string()),
                    report_commitment: Some(
                        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "safety-ops",
                    }),
                },
            ),
            "risk_mgmt",
            "req-annex-iv-pmm",
            "post_market_monitoring.json",
            br#"{"plan_id":"pmm-42"}"#,
        )
        .await;

        let runtime_logs = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "hiring-assistant",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("hiring-assistant").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        let other_system_risk = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "other-hiring-system",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::RiskAssessment(
                        proof_layer_core::schema::RiskAssessmentEvidence {
                            risk_id: "risk-other".to_string(),
                            severity: "high".to_string(),
                            status: "open".to_string(),
                            summary: Some("unrelated system".to_string()),
                            risk_description: None,
                            likelihood: None,
                            affected_groups: Vec::new(),
                            mitigation_measures: Vec::new(),
                            residual_risk_level: None,
                            risk_owner: None,
                            vulnerable_groups_considered: None,
                            test_results_summary: None,
                            metadata: serde_json::Value::Null,
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "risk_assessment.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"risk_id":"risk-other"}"#),
                }],
            },
        )
        .await;

        AnnexIvScenarioBundles {
            technical_doc,
            risk_assessment,
            data_governance,
            instructions_for_use,
            human_oversight,
            qms_record,
            standards_alignment,
            post_market_monitoring,
            runtime_logs,
            other_system_risk,
        }
    }

    async fn create_provider_governance_scenario(
        app: &Router,
    ) -> ProviderGovernanceScenarioBundles {
        let technical_doc = create_provider_governance_bundle(
            app,
            EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "annex-iv/system-card".to_string(),
                section: Some("system_overview".to_string()),
                commitment: Some(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                ),
                annex_iv_sections: vec!["section_2".to_string(), "section_3".to_string()],
                system_description_summary: Some(
                    "Ranks candidates for recruiter review.".to_string(),
                ),
                model_description_summary: Some("Fine-tuned ranking model.".to_string()),
                capabilities_and_limitations: Some(
                    "Advisory only for first-pass screening.".to_string(),
                ),
                design_choices_summary: Some(
                    "Human review is required before employment decisions.".to_string(),
                ),
                evaluation_metrics_summary: Some(
                    "Precision and subgroup parity are reviewed monthly.".to_string(),
                ),
                human_oversight_design_summary: Some(
                    "Recruiters must review every adverse or borderline case.".to_string(),
                ),
                post_market_monitoring_plan_ref: Some("pmm://hiring-assistant/2026.03".to_string()),
                simplified_tech_doc: None,
            }),
            "technical_doc",
            "req-provider-governance-tech-doc",
            "technical_doc.json",
            br#"{"document_ref":"annex-iv/system-card"}"#,
        )
        .await;

        let risk_assessment = create_provider_governance_bundle(
            app,
            EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                risk_id: "risk-001".to_string(),
                severity: "high".to_string(),
                status: "mitigated".to_string(),
                summary: Some("Bias and over-reliance risk reviewed.".to_string()),
                risk_description: Some(
                    "Potential unfair ranking of borderline candidates.".to_string(),
                ),
                likelihood: Some("medium".to_string()),
                affected_groups: vec!["job_applicants".to_string()],
                mitigation_measures: vec![
                    "mandatory human review".to_string(),
                    "monthly subgroup parity review".to_string(),
                ],
                residual_risk_level: Some("low".to_string()),
                risk_owner: Some("quality-team".to_string()),
                vulnerable_groups_considered: Some(true),
                test_results_summary: Some(
                    "No blocking disparity found in March review.".to_string(),
                ),
                metadata: serde_json::json!({
                    "owner": "quality-team",
                }),
            }),
            "risk_mgmt",
            "req-provider-governance-risk",
            "risk_assessment.json",
            br#"{"risk_id":"risk-001"}"#,
        )
        .await;

        let data_governance = create_provider_governance_bundle(
            app,
            EvidenceItem::DataGovernance(proof_layer_core::schema::DataGovernanceEvidence {
                decision: "approved_with_restrictions".to_string(),
                dataset_ref: Some("dataset://hiring-assistant/training-v3".to_string()),
                dataset_name: Some("hiring-assistant-training".to_string()),
                dataset_version: Some("2026.03".to_string()),
                source_description: Some(
                    "Curated applicant and recruiter-feedback corpus.".to_string(),
                ),
                collection_period: Some(proof_layer_core::schema::DateRange {
                    start: Some("2024-01-01".to_string()),
                    end: Some("2025-12-31".to_string()),
                }),
                geographical_scope: vec!["EU".to_string()],
                preprocessing_operations: vec![
                    "deduplication".to_string(),
                    "pii_minimization".to_string(),
                    "label_review".to_string(),
                ],
                bias_detection_methodology: Some(
                    "Quarterly protected-group parity review.".to_string(),
                ),
                bias_metrics: vec![proof_layer_core::schema::MetricSummary {
                    name: "selection_rate_gap".to_string(),
                    value: "0.04".to_string(),
                    unit: Some("ratio".to_string()),
                    methodology: None,
                }],
                mitigation_actions: vec![
                    "oversample underrepresented profiles".to_string(),
                    "human review on borderline scores".to_string(),
                ],
                data_gaps: vec!["limited historic data for niche technical roles".to_string()],
                personal_data_categories: vec![
                    "employment_history".to_string(),
                    "education_history".to_string(),
                ],
                safeguards: vec![
                    "pseudonymization".to_string(),
                    "role-based dataset access".to_string(),
                ],
                metadata: serde_json::json!({
                    "owner": "data-governance-board",
                }),
            }),
            "risk_mgmt",
            "req-provider-governance-data",
            "data_governance.json",
            br#"{"dataset_ref":"dataset://hiring-assistant/training-v3"}"#,
        )
        .await;

        let instructions_for_use = create_provider_governance_bundle(
            app,
            EvidenceItem::InstructionsForUse(
                proof_layer_core::schema::InstructionsForUseEvidence {
                    document_ref: "docs://hiring-assistant/operator-handbook".to_string(),
                    version: Some("2026.03".to_string()),
                    section: Some("human-review-required".to_string()),
                    commitment: None,
                    provider_identity: Some("Proof Layer Hiring Systems Ltd.".to_string()),
                    intended_purpose: Some(
                        "Recruiter support for first-pass candidate review".to_string(),
                    ),
                    system_capabilities: vec![
                        "candidate_summary".to_string(),
                        "borderline_case_flagging".to_string(),
                    ],
                    accuracy_metrics: vec![proof_layer_core::schema::MetricSummary {
                        name: "review_precision".to_string(),
                        value: "0.91".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: None,
                    }],
                    foreseeable_risks: vec!["automation bias".to_string()],
                    explainability_capabilities: Vec::new(),
                    human_oversight_guidance: vec![
                        "Review every negative or borderline recommendation.".to_string(),
                    ],
                    compute_requirements: vec!["4 vCPU".to_string(), "8GB RAM".to_string()],
                    service_lifetime: Some("12 months".to_string()),
                    log_management_guidance: vec![
                        "Retain runtime logs for post-market monitoring.".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "distribution": "internal_only",
                    }),
                },
            ),
            "technical_doc",
            "req-provider-governance-ifu",
            "instructions_for_use.json",
            br#"{"document_ref":"docs://hiring-assistant/operator-handbook"}"#,
        )
        .await;

        let qms_record = create_provider_governance_bundle(
            app,
            EvidenceItem::QmsRecord(proof_layer_core::schema::QmsRecordEvidence {
                record_id: "qms-release-approval-42".to_string(),
                process: "release_approval".to_string(),
                status: "approved".to_string(),
                record_commitment: Some(
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                ),
                policy_name: Some("Hiring Assistant Release Governance".to_string()),
                revision: Some("3.1".to_string()),
                effective_date: Some("2026-03-01".to_string()),
                expiry_date: None,
                scope: Some("EU provider release control".to_string()),
                approval_commitment: None,
                audit_results_summary: Some(
                    "Release gate approved after compliance review.".to_string(),
                ),
                continuous_improvement_actions: vec!["monitor subgroup parity monthly".to_string()],
                metadata: serde_json::json!({
                    "owner": "quality-lead",
                }),
            }),
            "technical_doc",
            "req-provider-governance-qms",
            "qms_record.json",
            br#"{"record_id":"qms-release-approval-42"}"#,
        )
        .await;

        let standards_alignment = create_provider_governance_bundle(
            app,
            EvidenceItem::StandardsAlignment(
                proof_layer_core::schema::StandardsAlignmentEvidence {
                    standard_ref: "harmonized://eu-ai-act/annex-iv".to_string(),
                    status: "aligned".to_string(),
                    scope: Some("high-risk technical documentation".to_string()),
                    mapping_commitment: Some(
                        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "compliance-mapping-team",
                    }),
                },
            ),
            "technical_doc",
            "req-provider-governance-standards",
            "standards_alignment.json",
            br#"{"standard_ref":"harmonized://eu-ai-act/annex-iv"}"#,
        )
        .await;

        let post_market_monitoring = create_provider_governance_bundle(
            app,
            EvidenceItem::PostMarketMonitoring(
                proof_layer_core::schema::PostMarketMonitoringEvidence {
                    plan_id: "pmm-42".to_string(),
                    status: "active".to_string(),
                    summary: Some("Weekly drift review with escalation thresholds.".to_string()),
                    report_commitment: Some(
                        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "safety-ops",
                    }),
                },
            ),
            "risk_mgmt",
            "req-provider-governance-pmm",
            "post_market_monitoring.json",
            br#"{"plan_id":"pmm-42"}"#,
        )
        .await;

        let corrective_action = create_provider_governance_bundle(
            app,
            EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                action_id: "ca-hiring-42".to_string(),
                status: "in_progress".to_string(),
                summary: Some(
                    "Tighten the ranking fallback rules and route borderline cases to manual review."
                        .to_string(),
                ),
                due_at: Some("2026-03-10T12:00:00Z".to_string()),
                record_commitment: Some(
                    "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                        .to_string(),
                ),
                metadata: serde_json::json!({
                    "owner": "quality-team",
                }),
            }),
            "risk_mgmt",
            "req-provider-governance-corrective-action",
            "corrective_action.json",
            br#"{"action_id":"ca-hiring-42"}"#,
        )
        .await;

        let other_system_risk = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "other-hiring-system",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::RiskAssessment(
                        proof_layer_core::schema::RiskAssessmentEvidence {
                            risk_id: "risk-other".to_string(),
                            severity: "high".to_string(),
                            status: "open".to_string(),
                            summary: Some("unrelated system".to_string()),
                            risk_description: None,
                            likelihood: None,
                            affected_groups: Vec::new(),
                            mitigation_measures: Vec::new(),
                            residual_risk_level: None,
                            risk_owner: None,
                            vulnerable_groups_considered: None,
                            test_results_summary: None,
                            metadata: serde_json::Value::Null,
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "risk_assessment.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"risk_id":"risk-other"}"#),
                }],
            },
        )
        .await;

        ProviderGovernanceScenarioBundles {
            technical_doc,
            risk_assessment,
            data_governance,
            instructions_for_use,
            qms_record,
            standards_alignment,
            post_market_monitoring,
            corrective_action,
            other_system_risk,
        }
    }

    async fn create_conformity_scenario(app: &Router) -> ConformityScenarioBundles {
        let conformity_assessment = create_conformity_bundle(
            app,
            EvidenceItem::ConformityAssessment(
                proof_layer_core::schema::ConformityAssessmentEvidence {
                    assessment_id: "conf-assess-42".to_string(),
                    procedure: "annex_vii_quality_management".to_string(),
                    status: "completed".to_string(),
                    report_commitment: Some(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    assessment_body: Some("notified_body_eu_1234".to_string()),
                    certificate_ref: Some("cert://eu/nb-1234/conf-assess-42".to_string()),
                    metadata: serde_json::json!({
                        "owner": "conformity-team",
                    }),
                },
            ),
            "technical_doc",
            "req-conformity-assessment",
            "conformity_assessment.json",
            br#"{"assessment_id":"conf-assess-42"}"#,
        )
        .await;

        let declaration = create_conformity_bundle(
            app,
            EvidenceItem::Declaration(proof_layer_core::schema::DeclarationEvidence {
                declaration_id: "decl-42".to_string(),
                jurisdiction: "eu".to_string(),
                status: "issued".to_string(),
                document_commitment: Some(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                ),
                signatory: Some("head_of_compliance".to_string()),
                document_version: Some("2026.03".to_string()),
                metadata: serde_json::json!({
                    "annex": "v",
                }),
            }),
            "technical_doc",
            "req-conformity-declaration",
            "declaration.json",
            br#"{"declaration_id":"decl-42"}"#,
        )
        .await;

        let registration = create_conformity_bundle(
            app,
            EvidenceItem::Registration(proof_layer_core::schema::RegistrationEvidence {
                registration_id: "reg-42".to_string(),
                authority: "eu_database".to_string(),
                status: "submitted".to_string(),
                receipt_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                registration_number: Some("EU-REG-49-42".to_string()),
                submitted_at: Some("2026-03-12T15:00:00Z".to_string()),
                metadata: serde_json::json!({
                    "owner": "conformity-team",
                }),
            }),
            "technical_doc",
            "req-conformity-registration",
            "registration.json",
            br#"{"registration_id":"reg-42"}"#,
        )
        .await;

        let other_system_bundle = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "other-system-conformity",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::Declaration(
                        proof_layer_core::schema::DeclarationEvidence {
                            declaration_id: "decl-other".to_string(),
                            jurisdiction: "eu".to_string(),
                            status: "issued".to_string(),
                            document_commitment: Some(
                                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                    .to_string(),
                            ),
                            signatory: Some("other-signatory".to_string()),
                            document_version: Some("2026.03".to_string()),
                            metadata: serde_json::json!({"annex": "v"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "other-declaration.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"declaration_id":"decl-other"}"#),
                }],
            },
        )
        .await;

        ConformityScenarioBundles {
            conformity_assessment,
            declaration,
            registration,
            other_system_bundle,
        }
    }

    async fn create_post_market_monitoring_scenario(
        app: &Router,
    ) -> PostMarketMonitoringScenarioBundles {
        let monitoring = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::PostMarketMonitoring(
                proof_layer_core::schema::PostMarketMonitoringEvidence {
                    plan_id: "pmm-claims-2026-03".to_string(),
                    status: "active".to_string(),
                    summary: Some(
                        "Weekly drift review with escalation thresholds for adverse outcomes."
                            .to_string(),
                    ),
                    report_commitment: Some(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "safety-ops",
                        "market": "eu",
                    }),
                },
            ),
            "risk_mgmt",
            "req-monitoring-plan",
            "post_market_monitoring.json",
            br#"{"plan_id":"pmm-claims-2026-03"}"#,
        )
        .await;

        let incident_report = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::IncidentReport(proof_layer_core::schema::IncidentReportEvidence {
                incident_id: "inc-claims-42".to_string(),
                severity: "serious".to_string(),
                status: "open".to_string(),
                occurred_at: Some("2026-03-08T07:15:00Z".to_string()),
                summary: Some(
                    "Potentially adverse recommendation surfaced in a sensitive claims case."
                        .to_string(),
                ),
                report_commitment: Some(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                ),
                detection_method: Some("post_market_monitoring".to_string()),
                root_cause_summary: Some(
                    "Missing-document threshold was too permissive for a narrow claims segment."
                        .to_string(),
                ),
                corrective_action_ref: Some("ca-claims-42".to_string()),
                authority_notification_required: Some(true),
                authority_notification_status: Some("drafted".to_string()),
                metadata: serde_json::json!({
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-monitoring-incident",
            "incident_report.json",
            br#"{"incident_id":"inc-claims-42"}"#,
        )
        .await;

        let corrective_action = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                action_id: "ca-claims-42".to_string(),
                status: "in_progress".to_string(),
                summary: Some(
                    "Tighten the missing-document threshold and route borderline claims to manual review."
                        .to_string(),
                ),
                due_at: Some("2026-03-10T12:00:00Z".to_string()),
                record_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                metadata: serde_json::json!({
                    "owner": "safety-ops",
                }),
            }),
            "risk_mgmt",
            "req-monitoring-corrective-action",
            "corrective_action.json",
            br#"{"action_id":"ca-claims-42"}"#,
        )
        .await;

        let authority_notification = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::AuthorityNotification(
                proof_layer_core::schema::AuthorityNotificationEvidence {
                    notification_id: "notif-claims-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    status: "drafted".to_string(),
                    incident_id: Some("inc-claims-42".to_string()),
                    due_at: Some("2026-03-10T12:00:00Z".to_string()),
                    report_commitment: Some(
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "channel": "portal",
                    }),
                },
            ),
            "risk_mgmt",
            "req-monitoring-authority-notification",
            "authority_notification.json",
            br#"{"notification_id":"notif-claims-42"}"#,
        )
        .await;

        let authority_submission = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::AuthoritySubmission(
                proof_layer_core::schema::AuthoritySubmissionEvidence {
                    submission_id: "sub-claims-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    status: "submitted".to_string(),
                    channel: Some("portal".to_string()),
                    submitted_at: Some("2026-03-08T09:30:00Z".to_string()),
                    document_commitment: Some(
                        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "incident_id": "inc-claims-42",
                    }),
                },
            ),
            "risk_mgmt",
            "req-monitoring-authority-submission",
            "authority_submission.json",
            br#"{"submission_id":"sub-claims-42"}"#,
        )
        .await;

        let reporting_deadline = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::ReportingDeadline(proof_layer_core::schema::ReportingDeadlineEvidence {
                deadline_id: "deadline-claims-42".to_string(),
                authority: "eu_ai_office".to_string(),
                obligation_ref: "art73_notification".to_string(),
                due_at: "2026-03-10T12:00:00Z".to_string(),
                status: "open".to_string(),
                incident_id: Some("inc-claims-42".to_string()),
                metadata: serde_json::json!({
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-monitoring-deadline",
            "reporting_deadline.json",
            br#"{"deadline_id":"deadline-claims-42"}"#,
        )
        .await;

        let regulator_correspondence = create_post_market_monitoring_bundle(
            app,
            EvidenceItem::RegulatorCorrespondence(
                proof_layer_core::schema::RegulatorCorrespondenceEvidence {
                    correspondence_id: "corr-claims-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    direction: "outbound".to_string(),
                    status: "sent".to_string(),
                    occurred_at: Some("2026-03-08T10:00:00Z".to_string()),
                    message_commitment: Some(
                        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "reference": "inc-claims-42",
                    }),
                },
            ),
            "risk_mgmt",
            "req-monitoring-correspondence",
            "regulator_correspondence.json",
            br#"{"correspondence_id":"corr-claims-42"}"#,
        )
        .await;

        let other_system_bundle = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "claims-assistant-other",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::PostMarketMonitoring(
                        proof_layer_core::schema::PostMarketMonitoringEvidence {
                            plan_id: "pmm-other-2026-03".to_string(),
                            status: "active".to_string(),
                            summary: Some("Unrelated system monitoring plan.".to_string()),
                            report_commitment: Some(
                                "sha256:0101010101010101010101010101010101010101010101010101010101010101"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({
                                "owner": "other-team",
                            }),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "other-monitoring.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"plan_id":"pmm-other-2026-03"}"#),
                }],
            },
        )
        .await;

        PostMarketMonitoringScenarioBundles {
            monitoring,
            incident_report,
            corrective_action,
            authority_notification,
            authority_submission,
            reporting_deadline,
            regulator_correspondence,
            other_system_bundle,
        }
    }

    async fn create_incident_response_scenario(app: &Router) -> IncidentResponseScenarioBundles {
        let technical_doc = create_incident_response_bundle(
            app,
            EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "docs://benefits-review/incident-response-context".to_string(),
                section: Some("incident_context".to_string()),
                commitment: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
                annex_iv_sections: Vec::new(),
                system_description_summary: Some(
                    "Public-sector benefit eligibility workflow with incident triage and regulator-facing escalation controls."
                        .to_string(),
                ),
                model_description_summary: Some(
                    "Advisory eligibility review assistant that prepares summaries for human case officers."
                        .to_string(),
                ),
                capabilities_and_limitations: Some(
                    "Flags incomplete or high-risk cases, but it does not finalize benefit determinations."
                        .to_string(),
                ),
                design_choices_summary: Some(
                    "Incident-response records capture triage, escalation, notification, and follow-up decisions in one reviewable file."
                        .to_string(),
                ),
                evaluation_metrics_summary: Some(
                    "Appeal-rate, false-negative, and escalation-timeliness checks are reviewed after reportable incidents."
                        .to_string(),
                ),
                human_oversight_design_summary: Some(
                    "Human case officers review adverse or borderline recommendations before any public-service outcome is finalized."
                        .to_string(),
                ),
                post_market_monitoring_plan_ref: Some(
                    "incident://benefits-review/triage-playbook-2026-03".to_string(),
                ),
                simplified_tech_doc: Some(true),
            }),
            "technical_doc",
            "req-incident-response-tech-doc",
            "technical_doc.json",
            br#"{"document_ref":"docs://benefits-review/incident-response-context"}"#,
        )
        .await;

        let risk_assessment = create_incident_response_bundle(
            app,
            EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                risk_id: "risk-benefits-incident-001".to_string(),
                severity: "high".to_string(),
                status: "mitigated".to_string(),
                summary: Some(
                    "Incident-response risk for adverse public-service recommendations is tracked in the response file."
                        .to_string(),
                ),
                risk_description: Some(
                    "A borderline threshold could over-rely on incomplete evidence and surface adverse recommendations without sufficient escalation."
                        .to_string(),
                ),
                likelihood: Some("medium".to_string()),
                affected_groups: vec![
                    "benefit_applicants".to_string(),
                    "case_officers".to_string(),
                ],
                mitigation_measures: vec![
                    "mandatory manual review for borderline or adverse recommendations"
                        .to_string(),
                    "escalation to incident operations when an affected person could receive an adverse outcome"
                        .to_string(),
                    "authority-notification and corrective-action workflow when serious incidents are suspected"
                        .to_string(),
                ],
                residual_risk_level: Some("medium".to_string()),
                risk_owner: Some("incident-ops".to_string()),
                vulnerable_groups_considered: Some(true),
                test_results_summary: Some(
                    "Replay and reviewer-agreement checks are acceptable only when the escalation workflow remains active."
                        .to_string(),
                ),
                metadata: serde_json::json!({
                    "reviewer": "rights-review-team",
                }),
            }),
            "risk_mgmt",
            "req-incident-response-risk",
            "risk_assessment.json",
            br#"{"risk_id":"risk-benefits-incident-001"}"#,
        )
        .await;

        let human_oversight = create_incident_response_bundle(
            app,
            EvidenceItem::HumanOversight(proof_layer_core::schema::HumanOversightEvidence {
                action: "manual_case_review_required".to_string(),
                reviewer: Some("rights-panel".to_string()),
                notes_commitment: Some(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                actor_role: Some("case_reviewer".to_string()),
                anomaly_detected: Some(true),
                override_action: Some("route_to_manual_review".to_string()),
                interpretation_guidance_followed: Some(true),
                automation_bias_detected: Some(false),
                two_person_verification: Some(false),
                stop_triggered: Some(false),
                stop_reason: Some(
                    "Human escalation handled the affected public-service case without a global stop."
                        .to_string(),
                ),
            }),
            "risk_mgmt",
            "req-incident-response-oversight",
            "human_oversight.json",
            br#"{"action":"manual_case_review_required"}"#,
        )
        .await;

        let policy_decision = create_incident_response_bundle(
            app,
            EvidenceItem::PolicyDecision(proof_layer_core::schema::PolicyDecisionEvidence {
                policy_name: "incident_reportability_triage".to_string(),
                decision: "notify_and_continue_manual_review".to_string(),
                rationale_commitment: Some(
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                        .to_string(),
                ),
                metadata: serde_json::json!({
                    "article": "73",
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-incident-response-policy",
            "policy_decision.json",
            br#"{"policy_name":"incident_reportability_triage"}"#,
        )
        .await;

        let incident_report = create_incident_response_bundle(
            app,
            EvidenceItem::IncidentReport(proof_layer_core::schema::IncidentReportEvidence {
                incident_id: "inc-benefits-42".to_string(),
                severity: "serious".to_string(),
                status: "open".to_string(),
                occurred_at: Some("2026-03-07T18:30:00Z".to_string()),
                summary: Some(
                    "Potentially adverse recommendation surfaced in a public-service case."
                        .to_string(),
                ),
                report_commitment: Some(
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                        .to_string(),
                ),
                detection_method: Some("human_review_escalation".to_string()),
                root_cause_summary: Some(
                    "A borderline-case threshold was too permissive for a narrow benefits cohort."
                        .to_string(),
                ),
                corrective_action_ref: Some("ca-benefits-42".to_string()),
                authority_notification_required: Some(true),
                authority_notification_status: Some("drafted".to_string()),
                metadata: serde_json::json!({
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-incident-response-incident",
            "incident_report.json",
            br#"{"incident_id":"inc-benefits-42"}"#,
        )
        .await;

        let corrective_action = create_incident_response_bundle(
            app,
            EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                action_id: "ca-benefits-42".to_string(),
                status: "in_progress".to_string(),
                summary: Some(
                    "Tighten the borderline threshold and route similar cases to manual review."
                        .to_string(),
                ),
                due_at: Some("2026-03-09T18:00:00Z".to_string()),
                record_commitment: Some(
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                        .to_string(),
                ),
                metadata: serde_json::json!({
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-incident-response-corrective-action",
            "corrective_action.json",
            br#"{"action_id":"ca-benefits-42"}"#,
        )
        .await;

        let authority_notification = create_incident_response_bundle(
            app,
            EvidenceItem::AuthorityNotification(
                proof_layer_core::schema::AuthorityNotificationEvidence {
                    notification_id: "notif-benefits-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    status: "drafted".to_string(),
                    incident_id: Some("inc-benefits-42".to_string()),
                    due_at: Some("2026-03-09T12:00:00Z".to_string()),
                    report_commitment: Some(
                        "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "channel": "portal",
                    }),
                },
            ),
            "risk_mgmt",
            "req-incident-response-authority-notification",
            "authority_notification.json",
            br#"{"notification_id":"notif-benefits-42"}"#,
        )
        .await;

        let authority_submission = create_incident_response_bundle(
            app,
            EvidenceItem::AuthoritySubmission(
                proof_layer_core::schema::AuthoritySubmissionEvidence {
                    submission_id: "sub-benefits-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    status: "submitted".to_string(),
                    channel: Some("portal".to_string()),
                    submitted_at: Some("2026-03-08T09:45:00Z".to_string()),
                    document_commitment: Some(
                        "sha256:7777777777777777777777777777777777777777777777777777777777777777"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "incident-ops",
                    }),
                },
            ),
            "risk_mgmt",
            "req-incident-response-authority-submission",
            "authority_submission.json",
            br#"{"submission_id":"sub-benefits-42"}"#,
        )
        .await;

        let reporting_deadline = create_incident_response_bundle(
            app,
            EvidenceItem::ReportingDeadline(proof_layer_core::schema::ReportingDeadlineEvidence {
                deadline_id: "deadline-benefits-42".to_string(),
                authority: "eu_ai_office".to_string(),
                obligation_ref: "art73_notification".to_string(),
                due_at: "2026-03-09T12:00:00Z".to_string(),
                status: "open".to_string(),
                incident_id: Some("inc-benefits-42".to_string()),
                metadata: serde_json::json!({
                    "owner": "incident-ops",
                }),
            }),
            "risk_mgmt",
            "req-incident-response-deadline",
            "reporting_deadline.json",
            br#"{"deadline_id":"deadline-benefits-42"}"#,
        )
        .await;

        let regulator_correspondence = create_incident_response_bundle(
            app,
            EvidenceItem::RegulatorCorrespondence(
                proof_layer_core::schema::RegulatorCorrespondenceEvidence {
                    correspondence_id: "corr-benefits-42".to_string(),
                    authority: "eu_ai_office".to_string(),
                    direction: "outbound".to_string(),
                    status: "sent".to_string(),
                    occurred_at: Some("2026-03-08T10:00:00Z".to_string()),
                    message_commitment: Some(
                        "sha256:8888888888888888888888888888888888888888888888888888888888888888"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "incident-ops",
                        "reference": "inc-benefits-42",
                    }),
                },
            ),
            "risk_mgmt",
            "req-incident-response-correspondence",
            "regulator_correspondence.json",
            br#"{"correspondence_id":"corr-benefits-42"}"#,
        )
        .await;

        let other_system_bundle = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "other-benefits-system",
                    proof_layer_core::ActorRole::Deployer,
                    vec![EvidenceItem::IncidentReport(
                        proof_layer_core::schema::IncidentReportEvidence {
                            incident_id: "inc-other-42".to_string(),
                            severity: "serious".to_string(),
                            status: "open".to_string(),
                            occurred_at: Some("2026-03-07T18:30:00Z".to_string()),
                            summary: Some("Unrelated system incident.".to_string()),
                            report_commitment: Some(
                                "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                                    .to_string(),
                            ),
                            detection_method: Some("human_review_escalation".to_string()),
                            root_cause_summary: Some("Other workflow.".to_string()),
                            corrective_action_ref: Some("ca-other-42".to_string()),
                            authority_notification_required: Some(true),
                            authority_notification_status: Some("drafted".to_string()),
                            metadata: serde_json::json!({
                                "owner": "other-team",
                            }),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "other-incident.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"incident_id":"inc-other-42"}"#),
                }],
            },
        )
        .await;

        IncidentResponseScenarioBundles {
            technical_doc,
            risk_assessment,
            human_oversight,
            policy_decision,
            incident_report,
            corrective_action,
            authority_notification,
            authority_submission,
            reporting_deadline,
            regulator_correspondence,
            other_system_bundle,
        }
    }

    async fn create_gpai_provider_scenario(app: &Router) -> GpaiProviderScenarioBundles {
        let technical_doc = create_gpai_provider_bundle(
            app,
            EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                document_ref: "annex-xi/foundation-model-alpha/system-card".to_string(),
                section: Some("model_overview".to_string()),
                commitment: Some(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                ),
                annex_iv_sections: Vec::new(),
                system_description_summary: Some(
                    "General-purpose provider-controlled model service.".to_string(),
                ),
                model_description_summary: None,
                capabilities_and_limitations: Some(
                    "Supports drafting and summarization with known hallucination limits."
                        .to_string(),
                ),
                design_choices_summary: Some(
                    "Provider policy filters and release gates apply before deployment."
                        .to_string(),
                ),
                evaluation_metrics_summary: Some(
                    "Provider benchmarks cover multilingual quality, safety, and subgroup performance."
                        .to_string(),
                ),
                human_oversight_design_summary: None,
                post_market_monitoring_plan_ref: None,
                simplified_tech_doc: Some(false),
            }),
            "technical_doc",
            "req-gpai-tech-doc",
            "technical_doc.json",
            br#"{"document_ref":"annex-xi/foundation-model-alpha/system-card"}"#,
        )
        .await;

        let model_evaluation = create_gpai_provider_bundle(
            app,
            EvidenceItem::ModelEvaluation(proof_layer_core::schema::ModelEvaluationEvidence {
                evaluation_id: "eval-foundation-alpha-v5".to_string(),
                benchmark: "provider-release-suite-2026q1".to_string(),
                status: "passed".to_string(),
                summary: Some("Release benchmark suite met provider thresholds.".to_string()),
                report_commitment: Some(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                metrics_summary: vec![proof_layer_core::schema::MetricSummary {
                    name: "instruction_following".to_string(),
                    value: "0.93".to_string(),
                    unit: Some("ratio".to_string()),
                    methodology: Some("Provider release suite average.".to_string()),
                }],
                group_performance: vec![proof_layer_core::schema::GroupMetricSummary {
                    group: "eu_languages".to_string(),
                    metrics: vec![proof_layer_core::schema::MetricSummary {
                        name: "quality_score".to_string(),
                        value: "0.91".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: Some("Held-out multilingual review set.".to_string()),
                    }],
                }],
                evaluation_methodology: Some(
                    "Held-out multilingual and safety benchmark suites.".to_string(),
                ),
                metadata: serde_json::json!({"owner": "provider-evals"}),
            }),
            "gpai_documentation",
            "req-gpai-eval",
            "model_evaluation.json",
            br#"{"evaluation_id":"eval-foundation-alpha-v5"}"#,
        )
        .await;

        let training_provenance = create_gpai_provider_bundle(
            app,
            EvidenceItem::TrainingProvenance(
                proof_layer_core::schema::TrainingProvenanceEvidence {
                    dataset_ref: "dataset://foundation-model-alpha/pretrain-v5".to_string(),
                    stage: "pretraining".to_string(),
                    lineage_ref: None,
                    record_commitment: Some(
                        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                            .to_string(),
                    ),
                    compute_metrics_ref: Some("compute-foundation-alpha-v5".to_string()),
                    training_dataset_summary: Some(
                        "Curated multilingual web, code, and licensed reference corpora."
                            .to_string(),
                    ),
                    consortium_context: Some("Single-provider training program".to_string()),
                    metadata: serde_json::json!({"source": "provider-registry"}),
                },
            ),
            "gpai_documentation",
            "req-gpai-training",
            "training_provenance.json",
            br#"{"dataset_ref":"dataset://foundation-model-alpha/pretrain-v5"}"#,
        )
        .await;

        let compute_metrics = create_gpai_provider_bundle(
            app,
            EvidenceItem::ComputeMetrics(proof_layer_core::schema::ComputeMetricsEvidence {
                compute_id: "compute-foundation-alpha-v5".to_string(),
                training_flops_estimate: "1.2e25".to_string(),
                threshold_basis_ref: "art51_systemic_risk_threshold".to_string(),
                threshold_value: "1e25".to_string(),
                threshold_status: "above_threshold".to_string(),
                estimation_methodology: Some(
                    "Cluster scheduler logs and accelerator utilization rollup.".to_string(),
                ),
                measured_at: Some("2026-03-10T12:00:00Z".to_string()),
                compute_resources_summary: vec![
                    proof_layer_core::schema::MetricSummary {
                        name: "gpu_hours".to_string(),
                        value: "42000".to_string(),
                        unit: Some("hours".to_string()),
                        methodology: Some("Provider training cluster accounting.".to_string()),
                    },
                    proof_layer_core::schema::MetricSummary {
                        name: "accelerator_count".to_string(),
                        value: "2048".to_string(),
                        unit: Some("gpus".to_string()),
                        methodology: Some("Peak provisioned accelerator count.".to_string()),
                    },
                ],
                consortium_context: Some("Single-provider training program".to_string()),
                metadata: serde_json::json!({"owner": "foundation-ops"}),
            }),
            "gpai_documentation",
            "req-gpai-compute",
            "compute_metrics.json",
            br#"{"compute_id":"compute-foundation-alpha-v5"}"#,
        )
        .await;

        let copyright_policy = create_gpai_provider_bundle(
            app,
            EvidenceItem::CopyrightPolicy(proof_layer_core::schema::CopyrightPolicyEvidence {
                policy_ref: "copyright://foundation-model-alpha/policy-v2".to_string(),
                status: "published".to_string(),
                jurisdiction: Some("eu".to_string()),
                commitment: Some(
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                        .to_string(),
                ),
                metadata: serde_json::json!({"scope": "training data intake"}),
            }),
            "gpai_documentation",
            "req-gpai-copyright",
            "copyright_policy.json",
            br#"{"policy_ref":"copyright://foundation-model-alpha/policy-v2"}"#,
        )
        .await;

        let training_summary = create_gpai_provider_bundle(
            app,
            EvidenceItem::TrainingSummary(proof_layer_core::schema::TrainingSummaryEvidence {
                summary_ref: "summary://foundation-model-alpha/training-v5".to_string(),
                status: "published".to_string(),
                audience: Some("public".to_string()),
                commitment: Some(
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                        .to_string(),
                ),
                metadata: serde_json::json!({"owner": "provider-disclosures"}),
            }),
            "gpai_documentation",
            "req-gpai-summary",
            "training_summary.json",
            br#"{"summary_ref":"summary://foundation-model-alpha/training-v5"}"#,
        )
        .await;

        let other_system_bundle = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "other-foundation-model",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::TrainingProvenance(
                        proof_layer_core::schema::TrainingProvenanceEvidence {
                            dataset_ref: "dataset://other/pretrain-v1".to_string(),
                            stage: "pretraining".to_string(),
                            lineage_ref: Some("lineage://other/provider".to_string()),
                            record_commitment: None,
                            compute_metrics_ref: Some("compute-other-v1".to_string()),
                            training_dataset_summary: Some("Other provider dataset.".to_string()),
                            consortium_context: None,
                            metadata: serde_json::json!({"source": "other-registry"}),
                        },
                    )],
                    Some("gpai_documentation"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "other-training-provenance.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"dataset":"other"}"#),
                }],
            },
        )
        .await;

        GpaiProviderScenarioBundles {
            technical_doc,
            model_evaluation,
            training_provenance,
            compute_metrics,
            copyright_policy,
            training_summary,
            other_system_bundle,
        }
    }

    async fn create_fundamental_rights_scenario(app: &Router) -> FundamentalRightsScenarioBundles {
        let compliance_profile = proof_layer_core::ComplianceProfile {
            intended_use: Some("Public-sector benefit eligibility review".to_string()),
            prohibited_practice_screening: Some("screened_no_prohibited_use".to_string()),
            risk_tier: Some("high_risk".to_string()),
            high_risk_domain: None,
            gpai_status: None,
            systemic_risk: None,
            fria_required: Some(true),
            deployment_context: Some("public_sector".to_string()),
            metadata: serde_json::json!({
                "owner": "rights-review-team",
                "market": "eu",
            }),
        };

        let mut assessment_event = sample_event_with_profile(
            "benefits-review",
            proof_layer_core::ActorRole::Deployer,
            vec![EvidenceItem::FundamentalRightsAssessment(
                proof_layer_core::schema::FundamentalRightsAssessmentEvidence {
                    assessment_id: "fria-2026-03".to_string(),
                    status: "completed".to_string(),
                    scope: Some("Public-sector benefit eligibility review".to_string()),
                    report_commitment: Some(
                        "sha256:ababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcd"
                            .to_string(),
                    ),
                    legal_basis: Some(
                        "GDPR Art. 22 and public-service review safeguards".to_string(),
                    ),
                    affected_rights: vec![
                        "equal treatment".to_string(),
                        "access to public services".to_string(),
                        "explanation".to_string(),
                    ],
                    stakeholder_consultation_summary: Some(
                        "Legal, service-operations, and rights-review stakeholders approved the workflow."
                            .to_string(),
                    ),
                    mitigation_plan_summary: Some(
                        "Borderline cases require human review and documented justification before any outcome is finalized."
                            .to_string(),
                    ),
                    assessor: Some("rights-review-team".to_string()),
                    metadata: serde_json::json!({
                        "owner": "benefits-review",
                    }),
                },
            )],
            Some("technical_doc"),
        );
        assessment_event.compliance_profile = Some(compliance_profile.clone());
        let assessment = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(assessment_event),
                artefacts: vec![InlineArtefact {
                    name: "fria-report.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(
                        br#"{"assessment":"Borderline cases require human review."}"#,
                    ),
                }],
            },
        )
        .await;

        let mut oversight_event = sample_event_with_profile(
            "benefits-review",
            proof_layer_core::ActorRole::Deployer,
            vec![EvidenceItem::HumanOversight(
                proof_layer_core::schema::HumanOversightEvidence {
                    action: "manual_case_review_required".to_string(),
                    reviewer: Some("rights-panel".to_string()),
                    notes_commitment: Some(
                        "sha256:cdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdabab"
                            .to_string(),
                    ),
                    actor_role: Some("case_reviewer".to_string()),
                    anomaly_detected: Some(true),
                    override_action: Some("route_to_manual_review".to_string()),
                    interpretation_guidance_followed: Some(true),
                    automation_bias_detected: Some(false),
                    two_person_verification: Some(false),
                    stop_triggered: Some(false),
                    stop_reason: Some(
                        "No automatic stop; human escalation handles borderline outcomes."
                            .to_string(),
                    ),
                },
            )],
            Some("risk_mgmt"),
        );
        oversight_event.compliance_profile = Some(compliance_profile);
        let human_oversight = create_bundle_response(
            app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(oversight_event),
                artefacts: vec![InlineArtefact {
                    name: "oversight-notes.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(
                        br#"{"reason":"Borderline case routed for manual review."}"#,
                    ),
                }],
            },
        )
        .await;

        FundamentalRightsScenarioBundles {
            assessment,
            human_oversight,
        }
    }

    fn fixture_annex_iv_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "hiring-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![
                EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                    document_ref: "annex-iv/system-card".to_string(),
                    section: Some("system_overview".to_string()),
                    commitment: Some(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    annex_iv_sections: vec!["section_2".to_string(), "section_3".to_string()],
                    system_description_summary: Some(
                        "Ranks candidates for recruiter review.".to_string(),
                    ),
                    model_description_summary: Some("Fine-tuned ranking model.".to_string()),
                    capabilities_and_limitations: Some(
                        "Advisory only for first-pass screening.".to_string(),
                    ),
                    design_choices_summary: Some(
                        "Human review is required before employment decisions.".to_string(),
                    ),
                    evaluation_metrics_summary: Some(
                        "Precision and subgroup parity are reviewed monthly.".to_string(),
                    ),
                    human_oversight_design_summary: Some(
                        "Recruiters must review every adverse or borderline case.".to_string(),
                    ),
                    post_market_monitoring_plan_ref: Some(
                        "pmm://hiring-assistant/2026.03".to_string(),
                    ),
                    simplified_tech_doc: None,
                }),
                EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                    risk_id: "risk-001".to_string(),
                    severity: "high".to_string(),
                    status: "mitigated".to_string(),
                    summary: Some("Bias and over-reliance risk reviewed.".to_string()),
                    risk_description: Some(
                        "Potential unfair ranking of borderline candidates.".to_string(),
                    ),
                    likelihood: Some("medium".to_string()),
                    affected_groups: vec!["job_applicants".to_string()],
                    mitigation_measures: vec![
                        "mandatory human review".to_string(),
                        "monthly subgroup parity review".to_string(),
                    ],
                    residual_risk_level: Some("low".to_string()),
                    risk_owner: Some("quality-team".to_string()),
                    vulnerable_groups_considered: Some(true),
                    test_results_summary: Some(
                        "No blocking disparity found in March review.".to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "quality-team",
                    }),
                }),
                EvidenceItem::DataGovernance(proof_layer_core::schema::DataGovernanceEvidence {
                    decision: "approved".to_string(),
                    dataset_ref: Some("dataset://candidates/2026-03".to_string()),
                    dataset_name: None,
                    dataset_version: Some("2026.03".to_string()),
                    source_description: Some(
                        "EU recruitment applicant and hiring outcome corpus.".to_string(),
                    ),
                    collection_period: Some(proof_layer_core::schema::DateRange {
                        start: Some("2025-01-01".to_string()),
                        end: Some("2025-12-31".to_string()),
                    }),
                    geographical_scope: vec!["EU".to_string()],
                    preprocessing_operations: vec![
                        "deduplication".to_string(),
                        "feature scaling".to_string(),
                    ],
                    bias_detection_methodology: Some(
                        "Subgroup parity review across protected attributes.".to_string(),
                    ),
                    bias_metrics: vec![proof_layer_core::schema::MetricSummary {
                        name: "selection_rate_ratio".to_string(),
                        value: "0.96".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: Some("Measured on March validation set.".to_string()),
                    }],
                    mitigation_actions: vec!["rebalance training sample".to_string()],
                    data_gaps: vec!["low historical volume for niche roles".to_string()],
                    personal_data_categories: vec![
                        "employment_history".to_string(),
                        "education".to_string(),
                    ],
                    safeguards: vec![
                        "role-based access".to_string(),
                        "retention caps".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "owner": "data-governance",
                    }),
                }),
                EvidenceItem::InstructionsForUse(
                    proof_layer_core::schema::InstructionsForUseEvidence {
                        document_ref: "ifu://hiring-assistant/2026.03".to_string(),
                        version: Some("2026.03".to_string()),
                        section: Some("operator_guidance".to_string()),
                        commitment: Some(
                            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .to_string(),
                        ),
                        provider_identity: Some("Proof Layer Labs".to_string()),
                        intended_purpose: Some(
                            "Assist recruiters with first-pass candidate screening.".to_string(),
                        ),
                        system_capabilities: vec![
                            "candidate ranking".to_string(),
                            "confidence banding".to_string(),
                        ],
                        accuracy_metrics: vec![proof_layer_core::schema::MetricSummary {
                            name: "precision_at_10".to_string(),
                            value: "0.87".to_string(),
                            unit: Some("ratio".to_string()),
                            methodology: Some("Measured on validation cohort.".to_string()),
                        }],
                        foreseeable_risks: vec!["automation bias".to_string()],
                        explainability_capabilities: vec!["reason codes".to_string()],
                        human_oversight_guidance: vec![
                            "review all adverse recommendations".to_string(),
                        ],
                        compute_requirements: vec!["cpu-only inference".to_string()],
                        service_lifetime: Some("12 months".to_string()),
                        log_management_guidance: vec![
                            "retain audit logs for 12 months".to_string(),
                        ],
                        metadata: serde_json::json!({
                            "distribution": "internal_only",
                        }),
                    },
                ),
                EvidenceItem::HumanOversight(proof_layer_core::schema::HumanOversightEvidence {
                    action: "manual_review".to_string(),
                    reviewer: Some("reviewer-123".to_string()),
                    notes_commitment: Some(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_string(),
                    ),
                    actor_role: Some("recruiter".to_string()),
                    anomaly_detected: Some(false),
                    override_action: Some("none".to_string()),
                    interpretation_guidance_followed: Some(true),
                    automation_bias_detected: Some(false),
                    two_person_verification: Some(false),
                    stop_triggered: Some(false),
                    stop_reason: Some(
                        "No emergency stop was required for this review path.".to_string(),
                    ),
                }),
                EvidenceItem::QmsRecord(proof_layer_core::schema::QmsRecordEvidence {
                    record_id: "qms-release-approval-42".to_string(),
                    process: "release_approval".to_string(),
                    status: "approved".to_string(),
                    record_commitment: Some(
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .to_string(),
                    ),
                    policy_name: Some("Hiring Assistant Release Governance".to_string()),
                    revision: Some("3.1".to_string()),
                    effective_date: Some("2026-03-01".to_string()),
                    expiry_date: None,
                    scope: Some("EU provider release control".to_string()),
                    approval_commitment: None,
                    audit_results_summary: Some(
                        "Release gate approved after compliance review.".to_string(),
                    ),
                    continuous_improvement_actions: vec![
                        "monitor subgroup parity monthly".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "owner": "quality-lead",
                    }),
                }),
                EvidenceItem::StandardsAlignment(
                    proof_layer_core::schema::StandardsAlignmentEvidence {
                        standard_ref: "harmonized://eu-ai-act/annex-iv".to_string(),
                        status: "aligned".to_string(),
                        scope: Some("high-risk technical documentation".to_string()),
                        mapping_commitment: Some(
                            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "compliance-mapping-team",
                        }),
                    },
                ),
                EvidenceItem::PostMarketMonitoring(
                    proof_layer_core::schema::PostMarketMonitoringEvidence {
                        plan_id: "pmm-42".to_string(),
                        status: "active".to_string(),
                        summary: Some(
                            "Weekly drift review with escalation thresholds.".to_string(),
                        ),
                        report_commitment: Some(
                            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "safety-ops",
                        }),
                    },
                ),
            ],
            Some("annex_iv"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-annex-iv-inline".to_string());
        event.subject.model_id = Some("hiring-model-v3".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(hiring_assistant_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "annex_iv_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"annex_iv_governance_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JPGG4QFZZ0X0P3N2JDMQ6K3V",
            chrono::DateTime::parse_from_rfc3339("2026-03-02T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn fixture_gpai_provider_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "foundation-model-alpha",
            proof_layer_core::ActorRole::Provider,
            vec![
                EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                    document_ref: "annex-xi/foundation-model-alpha/system-card".to_string(),
                    section: Some("model_overview".to_string()),
                    commitment: Some(
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    annex_iv_sections: Vec::new(),
                    system_description_summary: Some(
                        "General-purpose provider-controlled model service.".to_string(),
                    ),
                    model_description_summary: None,
                    capabilities_and_limitations: Some(
                        "Supports drafting and summarization with known hallucination limits."
                            .to_string(),
                    ),
                    design_choices_summary: Some(
                        "Provider policy filters and release gates apply before deployment."
                            .to_string(),
                    ),
                    evaluation_metrics_summary: Some(
                        "Provider benchmarks cover multilingual quality, safety, and subgroup performance."
                            .to_string(),
                    ),
                    human_oversight_design_summary: None,
                    post_market_monitoring_plan_ref: None,
                    simplified_tech_doc: Some(false),
                }),
                EvidenceItem::ModelEvaluation(proof_layer_core::schema::ModelEvaluationEvidence {
                    evaluation_id: "eval-foundation-alpha-v5".to_string(),
                    benchmark: "provider-release-suite-2026q1".to_string(),
                    status: "passed".to_string(),
                    summary: Some(
                        "Release benchmark suite met provider thresholds.".to_string(),
                    ),
                    report_commitment: Some(
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    metrics_summary: vec![proof_layer_core::schema::MetricSummary {
                        name: "instruction_following".to_string(),
                        value: "0.93".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: Some("Provider release suite average.".to_string()),
                    }],
                    group_performance: vec![proof_layer_core::schema::GroupMetricSummary {
                        group: "eu_languages".to_string(),
                        metrics: vec![proof_layer_core::schema::MetricSummary {
                            name: "quality_score".to_string(),
                            value: "0.91".to_string(),
                            unit: Some("ratio".to_string()),
                            methodology: Some("Held-out multilingual review set.".to_string()),
                        }],
                    }],
                    evaluation_methodology: Some(
                        "Held-out multilingual and safety benchmark suites.".to_string(),
                    ),
                    metadata: serde_json::json!({"owner": "provider-evals"}),
                }),
                EvidenceItem::TrainingProvenance(
                    proof_layer_core::schema::TrainingProvenanceEvidence {
                        dataset_ref: "dataset://foundation-model-alpha/pretrain-v5".to_string(),
                        stage: "pretraining".to_string(),
                        lineage_ref: None,
                        record_commitment: Some(
                            "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                                .to_string(),
                        ),
                        compute_metrics_ref: Some("compute-foundation-alpha-v5".to_string()),
                        training_dataset_summary: Some(
                            "Curated multilingual web, code, and licensed reference corpora."
                                .to_string(),
                        ),
                        consortium_context: Some("Single-provider training program".to_string()),
                        metadata: serde_json::json!({"source": "provider-registry"}),
                    },
                ),
                EvidenceItem::ComputeMetrics(proof_layer_core::schema::ComputeMetricsEvidence {
                    compute_id: "compute-foundation-alpha-v5".to_string(),
                    training_flops_estimate: "1.2e25".to_string(),
                    threshold_basis_ref: "art51_systemic_risk_threshold".to_string(),
                    threshold_value: "1e25".to_string(),
                    threshold_status: "above_threshold".to_string(),
                    estimation_methodology: Some(
                        "Cluster scheduler logs and accelerator utilization rollup.".to_string(),
                    ),
                    measured_at: Some("2026-03-10T12:00:00Z".to_string()),
                    compute_resources_summary: vec![
                        proof_layer_core::schema::MetricSummary {
                            name: "gpu_hours".to_string(),
                            value: "42000".to_string(),
                            unit: Some("hours".to_string()),
                            methodology: Some("Provider training cluster accounting.".to_string()),
                        },
                        proof_layer_core::schema::MetricSummary {
                            name: "accelerator_count".to_string(),
                            value: "2048".to_string(),
                            unit: Some("gpus".to_string()),
                            methodology: Some("Peak provisioned accelerator count.".to_string()),
                        },
                    ],
                    consortium_context: Some("Single-provider training program".to_string()),
                    metadata: serde_json::json!({"owner": "foundation-ops"}),
                }),
                EvidenceItem::CopyrightPolicy(
                    proof_layer_core::schema::CopyrightPolicyEvidence {
                        policy_ref: "copyright://foundation-model-alpha/policy-v2".to_string(),
                        status: "published".to_string(),
                        jurisdiction: Some("eu".to_string()),
                        commitment: Some(
                            "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({"scope": "training data intake"}),
                    },
                ),
                EvidenceItem::TrainingSummary(proof_layer_core::schema::TrainingSummaryEvidence {
                    summary_ref: "summary://foundation-model-alpha/training-v5".to_string(),
                    status: "published".to_string(),
                    audience: Some("public".to_string()),
                    commitment: Some(
                        "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({"owner": "provider-disclosures"}),
                }),
            ],
            Some("gpai_documentation"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-gpai-inline".to_string());
        event.subject.model_id = Some("foundation-model-alpha-v5".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(gpai_provider_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "gpai_provider_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"gpai_provider_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JQ0JP7DPC7GRQYTF6MAVVXQJ",
            chrono::DateTime::parse_from_rfc3339("2026-03-21T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn fixture_post_market_monitoring_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "claims-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![
                EvidenceItem::PostMarketMonitoring(
                    proof_layer_core::schema::PostMarketMonitoringEvidence {
                        plan_id: "pmm-claims-2026-03".to_string(),
                        status: "active".to_string(),
                        summary: Some(
                            "Weekly drift review with escalation thresholds for adverse outcomes."
                                .to_string(),
                        ),
                        report_commitment: Some(
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "safety-ops",
                            "market": "eu",
                        }),
                    },
                ),
                EvidenceItem::IncidentReport(proof_layer_core::schema::IncidentReportEvidence {
                    incident_id: "inc-claims-42".to_string(),
                    severity: "serious".to_string(),
                    status: "open".to_string(),
                    occurred_at: Some("2026-03-08T07:15:00Z".to_string()),
                    summary: Some(
                        "Potentially adverse recommendation surfaced in a sensitive claims case."
                            .to_string(),
                    ),
                    report_commitment: Some(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    ),
                    detection_method: Some("post_market_monitoring".to_string()),
                    root_cause_summary: Some(
                        "Missing-document threshold was too permissive for a narrow claims segment."
                            .to_string(),
                    ),
                    corrective_action_ref: Some("ca-claims-42".to_string()),
                    authority_notification_required: Some(true),
                    authority_notification_status: Some("drafted".to_string()),
                    metadata: serde_json::json!({
                        "owner": "incident-ops",
                    }),
                }),
                EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                    action_id: "ca-claims-42".to_string(),
                    status: "in_progress".to_string(),
                    summary: Some(
                        "Tighten the missing-document threshold and route borderline claims to manual review."
                            .to_string(),
                    ),
                    due_at: Some("2026-03-10T12:00:00Z".to_string()),
                    record_commitment: Some(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "safety-ops",
                    }),
                }),
                EvidenceItem::AuthorityNotification(
                    proof_layer_core::schema::AuthorityNotificationEvidence {
                        notification_id: "notif-claims-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        status: "drafted".to_string(),
                        incident_id: Some("inc-claims-42".to_string()),
                        due_at: Some("2026-03-10T12:00:00Z".to_string()),
                        report_commitment: Some(
                            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "channel": "portal",
                        }),
                    },
                ),
                EvidenceItem::AuthoritySubmission(
                    proof_layer_core::schema::AuthoritySubmissionEvidence {
                        submission_id: "sub-claims-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        status: "submitted".to_string(),
                        channel: Some("portal".to_string()),
                        submitted_at: Some("2026-03-08T09:30:00Z".to_string()),
                        document_commitment: Some(
                            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "incident_id": "inc-claims-42",
                        }),
                    },
                ),
                EvidenceItem::ReportingDeadline(
                    proof_layer_core::schema::ReportingDeadlineEvidence {
                        deadline_id: "deadline-claims-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        obligation_ref: "art73_notification".to_string(),
                        due_at: "2026-03-10T12:00:00Z".to_string(),
                        status: "open".to_string(),
                        incident_id: Some("inc-claims-42".to_string()),
                        metadata: serde_json::json!({
                            "owner": "incident-ops",
                        }),
                    },
                ),
            ],
            Some("risk_mgmt"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-monitoring-inline".to_string());
        event.subject.model_id = Some("claims-model-v2".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(post_market_monitoring_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "post_market_monitoring_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"post_market_monitoring_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JQ1Y6WT5JFTRF4W6QZPNM2E1",
            chrono::DateTime::parse_from_rfc3339("2026-03-22T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn fixture_incident_response_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "benefits-review",
            proof_layer_core::ActorRole::Deployer,
            vec![
                EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                    document_ref: "docs://benefits-review/incident-response-context".to_string(),
                    section: Some("incident_context".to_string()),
                    commitment: Some(
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                    ),
                    annex_iv_sections: Vec::new(),
                    system_description_summary: Some(
                        "Public-sector benefit eligibility workflow with incident triage and regulator-facing escalation controls."
                            .to_string(),
                    ),
                    model_description_summary: Some(
                        "Advisory eligibility review assistant that prepares summaries for human case officers."
                            .to_string(),
                    ),
                    capabilities_and_limitations: Some(
                        "Flags incomplete or high-risk cases, but it does not finalize benefit determinations."
                            .to_string(),
                    ),
                    design_choices_summary: Some(
                        "Incident-response records capture triage, escalation, notification, and follow-up decisions in one reviewable file."
                            .to_string(),
                    ),
                    evaluation_metrics_summary: Some(
                        "Appeal-rate, false-negative, and escalation-timeliness checks are reviewed after reportable incidents."
                            .to_string(),
                    ),
                    human_oversight_design_summary: Some(
                        "Human case officers review adverse or borderline recommendations before any public-service outcome is finalized."
                            .to_string(),
                    ),
                    post_market_monitoring_plan_ref: Some(
                        "incident://benefits-review/triage-playbook-2026-03".to_string(),
                    ),
                    simplified_tech_doc: Some(true),
                }),
                EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                    risk_id: "risk-benefits-incident-001".to_string(),
                    severity: "high".to_string(),
                    status: "mitigated".to_string(),
                    summary: Some(
                        "Incident-response risk for adverse public-service recommendations is tracked in the response file."
                            .to_string(),
                    ),
                    risk_description: Some(
                        "A borderline threshold could over-rely on incomplete evidence and surface adverse recommendations without sufficient escalation."
                            .to_string(),
                    ),
                    likelihood: Some("medium".to_string()),
                    affected_groups: vec![
                        "benefit_applicants".to_string(),
                        "case_officers".to_string(),
                    ],
                    mitigation_measures: vec![
                        "mandatory manual review for borderline or adverse recommendations"
                            .to_string(),
                        "escalation to incident operations when an affected person could receive an adverse outcome"
                            .to_string(),
                        "authority-notification and corrective-action workflow when serious incidents are suspected"
                            .to_string(),
                    ],
                    residual_risk_level: Some("medium".to_string()),
                    risk_owner: Some("incident-ops".to_string()),
                    vulnerable_groups_considered: Some(true),
                    test_results_summary: Some(
                        "Replay and reviewer-agreement checks are acceptable only when the escalation workflow remains active."
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "reviewer": "rights-review-team",
                    }),
                }),
                EvidenceItem::HumanOversight(proof_layer_core::schema::HumanOversightEvidence {
                    action: "manual_case_review_required".to_string(),
                    reviewer: Some("rights-panel".to_string()),
                    notes_commitment: Some(
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .to_string(),
                    ),
                    actor_role: Some("case_reviewer".to_string()),
                    anomaly_detected: Some(true),
                    override_action: Some("route_to_manual_review".to_string()),
                    interpretation_guidance_followed: Some(true),
                    automation_bias_detected: Some(false),
                    two_person_verification: Some(false),
                    stop_triggered: Some(false),
                    stop_reason: Some(
                        "Human escalation handled the affected public-service case without a global stop."
                            .to_string(),
                    ),
                }),
                EvidenceItem::PolicyDecision(proof_layer_core::schema::PolicyDecisionEvidence {
                    policy_name: "incident_reportability_triage".to_string(),
                    decision: "notify_and_continue_manual_review".to_string(),
                    rationale_commitment: Some(
                        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "article": "73",
                        "owner": "incident-ops",
                    }),
                }),
                EvidenceItem::IncidentReport(proof_layer_core::schema::IncidentReportEvidence {
                    incident_id: "inc-benefits-42".to_string(),
                    severity: "serious".to_string(),
                    status: "open".to_string(),
                    occurred_at: Some("2026-03-07T18:30:00Z".to_string()),
                    summary: Some(
                        "Potentially adverse recommendation surfaced in a public-service case."
                            .to_string(),
                    ),
                    report_commitment: Some(
                        "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                            .to_string(),
                    ),
                    detection_method: Some("human_review_escalation".to_string()),
                    root_cause_summary: Some(
                        "A borderline-case threshold was too permissive for a narrow benefits cohort."
                            .to_string(),
                    ),
                    corrective_action_ref: Some("ca-benefits-42".to_string()),
                    authority_notification_required: Some(true),
                    authority_notification_status: Some("drafted".to_string()),
                    metadata: serde_json::json!({
                        "owner": "incident-ops",
                    }),
                }),
                EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                    action_id: "ca-benefits-42".to_string(),
                    status: "in_progress".to_string(),
                    summary: Some(
                        "Tighten the borderline threshold and route similar cases to manual review."
                            .to_string(),
                    ),
                    due_at: Some("2026-03-09T18:00:00Z".to_string()),
                    record_commitment: Some(
                        "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "incident-ops",
                    }),
                }),
                EvidenceItem::AuthorityNotification(
                    proof_layer_core::schema::AuthorityNotificationEvidence {
                        notification_id: "notif-benefits-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        status: "drafted".to_string(),
                        incident_id: Some("inc-benefits-42".to_string()),
                        due_at: Some("2026-03-09T12:00:00Z".to_string()),
                        report_commitment: Some(
                            "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "channel": "portal",
                        }),
                    },
                ),
                EvidenceItem::AuthoritySubmission(
                    proof_layer_core::schema::AuthoritySubmissionEvidence {
                        submission_id: "sub-benefits-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        status: "submitted".to_string(),
                        channel: Some("portal".to_string()),
                        submitted_at: Some("2026-03-08T09:45:00Z".to_string()),
                        document_commitment: Some(
                            "sha256:7777777777777777777777777777777777777777777777777777777777777777"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "incident-ops",
                        }),
                    },
                ),
                EvidenceItem::ReportingDeadline(
                    proof_layer_core::schema::ReportingDeadlineEvidence {
                        deadline_id: "deadline-benefits-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        obligation_ref: "art73_notification".to_string(),
                        due_at: "2026-03-09T12:00:00Z".to_string(),
                        status: "open".to_string(),
                        incident_id: Some("inc-benefits-42".to_string()),
                        metadata: serde_json::json!({
                            "owner": "incident-ops",
                        }),
                    },
                ),
                EvidenceItem::RegulatorCorrespondence(
                    proof_layer_core::schema::RegulatorCorrespondenceEvidence {
                        correspondence_id: "corr-benefits-42".to_string(),
                        authority: "eu_ai_office".to_string(),
                        direction: "outbound".to_string(),
                        status: "sent".to_string(),
                        occurred_at: Some("2026-03-08T10:00:00Z".to_string()),
                        message_commitment: Some(
                            "sha256:8888888888888888888888888888888888888888888888888888888888888888"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "incident-ops",
                            "reference": "inc-benefits-42",
                        }),
                    },
                ),
            ],
            Some("risk_mgmt"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-incident-response-inline".to_string());
        event.subject.model_id = Some("eligibility-ranker-v2".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(incident_response_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "incident_response_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"incident_response_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JQ4Q6R7JABP9FTJ3Q5H2E2Y4",
            chrono::DateTime::parse_from_rfc3339("2026-03-22T18:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn fixture_provider_governance_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "hiring-assistant",
            proof_layer_core::ActorRole::Provider,
            vec![
                EvidenceItem::TechnicalDoc(proof_layer_core::schema::TechnicalDocEvidence {
                    document_ref: "annex-iv/system-card".to_string(),
                    section: Some("system_overview".to_string()),
                    commitment: Some(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    annex_iv_sections: vec!["section_2".to_string(), "section_3".to_string()],
                    system_description_summary: Some(
                        "Ranks candidates for recruiter review.".to_string(),
                    ),
                    model_description_summary: Some("Fine-tuned ranking model.".to_string()),
                    capabilities_and_limitations: Some(
                        "Advisory only for first-pass screening.".to_string(),
                    ),
                    design_choices_summary: Some(
                        "Human review is required before employment decisions.".to_string(),
                    ),
                    evaluation_metrics_summary: Some(
                        "Precision and subgroup parity are reviewed monthly.".to_string(),
                    ),
                    human_oversight_design_summary: Some(
                        "Recruiters must review every adverse or borderline case.".to_string(),
                    ),
                    post_market_monitoring_plan_ref: Some(
                        "pmm://hiring-assistant/2026.03".to_string(),
                    ),
                    simplified_tech_doc: None,
                }),
                EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                    risk_id: "risk-001".to_string(),
                    severity: "high".to_string(),
                    status: "mitigated".to_string(),
                    summary: Some("Bias and over-reliance risk reviewed.".to_string()),
                    risk_description: Some(
                        "Potential unfair ranking of borderline candidates.".to_string(),
                    ),
                    likelihood: Some("medium".to_string()),
                    affected_groups: vec!["job_applicants".to_string()],
                    mitigation_measures: vec![
                        "mandatory human review".to_string(),
                        "monthly subgroup parity review".to_string(),
                    ],
                    residual_risk_level: Some("low".to_string()),
                    risk_owner: Some("quality-team".to_string()),
                    vulnerable_groups_considered: Some(true),
                    test_results_summary: Some(
                        "No blocking disparity found in March review.".to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "quality-team",
                    }),
                }),
                EvidenceItem::DataGovernance(proof_layer_core::schema::DataGovernanceEvidence {
                    decision: "approved_with_restrictions".to_string(),
                    dataset_ref: Some("dataset://hiring-assistant/training-v3".to_string()),
                    dataset_name: Some("hiring-assistant-training".to_string()),
                    dataset_version: Some("2026.03".to_string()),
                    source_description: Some(
                        "Curated applicant and recruiter-feedback corpus.".to_string(),
                    ),
                    collection_period: Some(proof_layer_core::schema::DateRange {
                        start: Some("2024-01-01".to_string()),
                        end: Some("2025-12-31".to_string()),
                    }),
                    geographical_scope: vec!["EU".to_string()],
                    preprocessing_operations: vec![
                        "deduplication".to_string(),
                        "pii_minimization".to_string(),
                        "label_review".to_string(),
                    ],
                    bias_detection_methodology: Some(
                        "Quarterly protected-group parity review.".to_string(),
                    ),
                    bias_metrics: vec![proof_layer_core::schema::MetricSummary {
                        name: "selection_rate_gap".to_string(),
                        value: "0.04".to_string(),
                        unit: Some("ratio".to_string()),
                        methodology: None,
                    }],
                    mitigation_actions: vec![
                        "oversample underrepresented profiles".to_string(),
                        "human review on borderline scores".to_string(),
                    ],
                    data_gaps: vec!["limited historic data for niche technical roles".to_string()],
                    personal_data_categories: vec![
                        "employment_history".to_string(),
                        "education_history".to_string(),
                    ],
                    safeguards: vec![
                        "pseudonymization".to_string(),
                        "role-based dataset access".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "owner": "data-governance-board",
                    }),
                }),
                EvidenceItem::InstructionsForUse(
                    proof_layer_core::schema::InstructionsForUseEvidence {
                        document_ref: "docs://hiring-assistant/operator-handbook".to_string(),
                        version: Some("2026.03".to_string()),
                        section: Some("human-review-required".to_string()),
                        commitment: None,
                        provider_identity: Some("Proof Layer Hiring Systems Ltd.".to_string()),
                        intended_purpose: Some(
                            "Recruiter support for first-pass candidate review".to_string(),
                        ),
                        system_capabilities: vec![
                            "candidate_summary".to_string(),
                            "borderline_case_flagging".to_string(),
                        ],
                        accuracy_metrics: vec![proof_layer_core::schema::MetricSummary {
                            name: "review_precision".to_string(),
                            value: "0.91".to_string(),
                            unit: Some("ratio".to_string()),
                            methodology: None,
                        }],
                        foreseeable_risks: vec!["automation bias".to_string()],
                        explainability_capabilities: Vec::new(),
                        human_oversight_guidance: vec![
                            "Review every negative or borderline recommendation.".to_string(),
                        ],
                        compute_requirements: vec!["4 vCPU".to_string(), "8GB RAM".to_string()],
                        service_lifetime: Some("12 months".to_string()),
                        log_management_guidance: vec![
                            "Retain runtime logs for post-market monitoring.".to_string(),
                        ],
                        metadata: serde_json::json!({
                            "distribution": "internal_only",
                        }),
                    },
                ),
                EvidenceItem::QmsRecord(proof_layer_core::schema::QmsRecordEvidence {
                    record_id: "qms-release-approval-42".to_string(),
                    process: "release_approval".to_string(),
                    status: "approved".to_string(),
                    record_commitment: Some(
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .to_string(),
                    ),
                    policy_name: Some("Hiring Assistant Release Governance".to_string()),
                    revision: Some("3.1".to_string()),
                    effective_date: Some("2026-03-01".to_string()),
                    expiry_date: None,
                    scope: Some("EU provider release control".to_string()),
                    approval_commitment: None,
                    audit_results_summary: Some(
                        "Release gate approved after compliance review.".to_string(),
                    ),
                    continuous_improvement_actions: vec![
                        "monitor subgroup parity monthly".to_string(),
                    ],
                    metadata: serde_json::json!({
                        "owner": "quality-lead",
                    }),
                }),
                EvidenceItem::StandardsAlignment(
                    proof_layer_core::schema::StandardsAlignmentEvidence {
                        standard_ref: "harmonized://eu-ai-act/annex-iv".to_string(),
                        status: "aligned".to_string(),
                        scope: Some("high-risk technical documentation".to_string()),
                        mapping_commitment: Some(
                            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "compliance-mapping-team",
                        }),
                    },
                ),
                EvidenceItem::PostMarketMonitoring(
                    proof_layer_core::schema::PostMarketMonitoringEvidence {
                        plan_id: "pmm-42".to_string(),
                        status: "active".to_string(),
                        summary: Some("Weekly drift review with escalation thresholds.".to_string()),
                        report_commitment: Some(
                            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                .to_string(),
                        ),
                        metadata: serde_json::json!({
                            "owner": "safety-ops",
                        }),
                    },
                ),
                EvidenceItem::CorrectiveAction(proof_layer_core::schema::CorrectiveActionEvidence {
                    action_id: "ca-hiring-42".to_string(),
                    status: "in_progress".to_string(),
                    summary: Some(
                        "Tighten the ranking fallback rules and route borderline cases to manual review."
                            .to_string(),
                    ),
                    due_at: Some("2026-03-10T12:00:00Z".to_string()),
                    record_commitment: Some(
                        "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                            .to_string(),
                    ),
                    metadata: serde_json::json!({
                        "owner": "quality-team",
                    }),
                }),
            ],
            Some("technical_doc"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-provider-governance-inline".to_string());
        event.subject.model_id = Some("hiring-model-v3".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(hiring_assistant_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "provider_governance_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"provider_governance_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JQ2XKDP0VQGK3CZ3KQ68MBV1",
            chrono::DateTime::parse_from_rfc3339("2026-03-22T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    fn fixture_conformity_bundle() -> ProofBundle {
        let event = sample_event_with_profile(
            "system-conformity",
            proof_layer_core::ActorRole::Provider,
            vec![
                EvidenceItem::ConformityAssessment(
                    proof_layer_core::schema::ConformityAssessmentEvidence {
                        assessment_id: "conf-assess-42".to_string(),
                        procedure: "annex_vii_quality_management".to_string(),
                        status: "completed".to_string(),
                        report_commitment: Some(
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string(),
                        ),
                        assessment_body: Some("notified_body_eu_1234".to_string()),
                        certificate_ref: Some("cert://eu/nb-1234/conf-assess-42".to_string()),
                        metadata: serde_json::json!({
                            "owner": "conformity-team",
                        }),
                    },
                ),
                EvidenceItem::Declaration(proof_layer_core::schema::DeclarationEvidence {
                    declaration_id: "decl-42".to_string(),
                    jurisdiction: "eu".to_string(),
                    status: "issued".to_string(),
                    document_commitment: Some(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    ),
                    signatory: Some("head_of_compliance".to_string()),
                    document_version: Some("2026.03".to_string()),
                    metadata: serde_json::json!({
                        "annex": "v",
                    }),
                }),
                EvidenceItem::Registration(proof_layer_core::schema::RegistrationEvidence {
                    registration_id: "reg-42".to_string(),
                    authority: "eu_database".to_string(),
                    status: "submitted".to_string(),
                    receipt_commitment: Some(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_string(),
                    ),
                    registration_number: Some("EU-REG-49-42".to_string()),
                    submitted_at: Some("2026-03-12T15:00:00Z".to_string()),
                    metadata: serde_json::json!({
                        "owner": "conformity-team",
                    }),
                }),
            ],
            Some("technical_doc"),
        );
        let mut event = event;
        event.subject.request_id = Some("req-conformity-inline".to_string());
        event.subject.model_id = Some("conformity-file-v1".to_string());
        event.subject.version = Some("2026.03".to_string());
        event.compliance_profile = Some(conformity_compliance_profile());

        build_bundle(
            event,
            &[ArtefactInput {
                name: "conformity_overview.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"profile":"conformity_v1"}"#.to_vec(),
            }],
            &SigningKey::from_bytes(&[7_u8; 32]),
            "kid-dev-01",
            "01JQ34M7Q0K9QTYTZ39VY2P7H2",
            chrono::DateTime::parse_from_rfc3339("2026-03-22T15:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap()
    }

    async fn test_state(max_payload_bytes: usize) -> AppState {
        let storage_dir = std::env::temp_dir().join(format!(
            "proof-service-test-storage-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let backup_dir = storage_dir.join("backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let db_path = storage_dir.join("metadata.db");
        let db = open_sqlite_pool(&db_path).await.unwrap();
        initialize_sqlite_schema(&db).await.unwrap();
        seed_default_retention_policies(&db).await.unwrap();
        seed_default_disclosure_config(&db).await.unwrap();
        backfill_bundle_expiries(&db).await.unwrap();
        backfill_item_obligation_refs(&db).await.unwrap();
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        AppState {
            db,
            addr: DEFAULT_ADDR.to_string(),
            tls_enabled: false,
            auth_config: None,
            tenant_organization_id: None,
            storage_dir,
            db_path,
            backup_dir,
            signing_key: Arc::new(signing_key),
            signing_kid: "kid-dev-01".to_string(),
            signing_key_ephemeral: false,
            metadata_backend: "sqlite".to_string(),
            blob_backend: "filesystem".to_string(),
            max_payload_bytes,
            retention_grace_period_days: DEFAULT_RETENTION_GRACE_PERIOD_DAYS,
            retention_scan_interval_hours: DEFAULT_RETENTION_SCAN_INTERVAL_HOURS,
            backup_interval_hours: DEFAULT_BACKUP_INTERVAL_HOURS,
            backup_retention_count: DEFAULT_BACKUP_RETENTION_COUNT,
            backup_encryption: None,
            demo_providers: Arc::new(DemoProviderRegistry::default()),
        }
    }

    async fn test_state_with_auth(
        max_payload_bytes: usize,
        principals: &[(&str, &str)],
    ) -> AppState {
        let mut state = test_state(max_payload_bytes).await;
        state.auth_config = Some(RuntimeAuthConfig {
            principals: Arc::new(
                principals
                    .iter()
                    .map(|(key, label)| ApiKeyPrincipal {
                        key: (*key).to_string(),
                        label: (*label).to_string(),
                    })
                    .collect(),
            ),
        });
        state
    }

    async fn test_state_with_tenant(max_payload_bytes: usize, tenant_org_id: &str) -> AppState {
        let mut state = test_state(max_payload_bytes).await;
        state.tenant_organization_id = Some(tenant_org_id.to_string());
        state
    }

    struct FakeDemoClient {
        response: DemoProviderResponse,
    }

    #[async_trait]
    impl DemoProviderClient for FakeDemoClient {
        async fn generate(
            &self,
            _request: &DemoProviderResponseRequest,
        ) -> Result<DemoProviderResponse> {
            Ok(self.response.clone())
        }
    }

    async fn test_state_with_demo_provider(
        max_payload_bytes: usize,
        provider: DemoProviderName,
        response: DemoProviderResponse,
    ) -> AppState {
        let mut state = test_state(max_payload_bytes).await;
        let client = Arc::new(FakeDemoClient { response }) as Arc<dyn DemoProviderClient>;
        state.demo_providers = Arc::new(match provider {
            DemoProviderName::Openai => DemoProviderRegistry {
                openai: Some(client),
                anthropic: None,
            },
            DemoProviderName::Anthropic => DemoProviderRegistry {
                openai: None,
                anthropic: Some(client),
            },
        });
        state
    }

    fn build_test_timestamp_token(digest: &str, provider: Option<&str>) -> TimestampToken {
        let signed_data_der = build_test_signed_data_der(digest);
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: Base64::encode_string(&signed_data_der),
        }
    }

    fn build_test_rekor_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let body_bytes = serde_json::to_vec(&serde_json::json!({
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
            serde_json::json!({
                "body": Base64::encode_string(&body_bytes),
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
                    "signedEntryTimestamp": Base64::encode_string(b"rekor-set")
                }
            }),
        );
        TransparencyReceipt {
            kind: REKOR_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: serde_json::json!({
                "log_url": "https://rekor.sigstore.dev",
                "entry_uuid": entry_uuid,
                "log_entry": log_entry
            }),
        }
    }

    fn build_test_scitt_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let statement_bytes = canonicalize_value(&serde_json::json!({
            "bundle_root": bundle_root,
            "profile": SCITT_STATEMENT_PROFILE,
            "timestamp": token,
        }))
        .unwrap();
        let statement_hash = sha256_prefixed(&statement_bytes);

        TransparencyReceipt {
            kind: SCITT_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: serde_json::json!({
                "service_url": "https://scitt.example.test/entries",
                "entry_id": "entry-scitt-001",
                "service_id": "abababababababababababababababababababababababababababababababab",
                "registered_at": "2026-03-06T13:15:00Z",
                "statement_b64": Base64::encode_string(&statement_bytes),
                "statement_hash": statement_hash,
                "receipt_b64": Base64::encode_string(b"scitt-receipt"),
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
        builder.constraint_not_ca();
        builder.key_usage(KeyUsage::DigitalSignature);
        builder.add_extension_der_data(
            Oid(Bytes::copy_from_slice(&[85, 29, 37])),
            true,
            [
                0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
            ],
        );
        builder
            .create_with_random_keypair(KeyAlgorithm::Ed25519)
            .unwrap()
    }

    fn test_timestamp_crl_pem() -> String {
        r#"-----BEGIN X509 CRL-----
MIHmMIGNAgEBMAoGCCqGSM49BAMCMCwxHTAbBgNVBAMMFHByb29mLWxheWVyLXRl
c3QtdHNhMQswCQYDVQQGEwJHQhcNMjYwMzA3MjE1MTI3WhcNMjYwNDA2MjE1MTI3
WqAwMC4wHwYDVR0jBBgwFoAUpFIKiTRJ7cMFxu7WWuwKitJqAaMwCwYDVR0UBAQC
AhAAMAoGCCqGSM49BAMCA0gAMEUCIDgOKS2Yghk4zHOJTpUFBiiCjEvlrEwml/S+
lbMJi3Q4AiEA9D8MwQFYMn4s0CXt3fdhssaMf69SlNwNKpMpVVWs54A=
-----END X509 CRL-----
"#
        .to_string()
    }

    fn build_package_bytes(
        bundle: &ProofBundle,
        artefacts: &[(&str, &[u8])],
        tamper_manifest: bool,
    ) -> Vec<u8> {
        let mut files = BTreeMap::<String, Vec<u8>>::new();
        files.insert(
            "proof_bundle.json".to_string(),
            serde_json::to_vec_pretty(bundle).unwrap(),
        );
        files.insert(
            "proof_bundle.canonical.json".to_string(),
            bundle.canonical_header_bytes().unwrap(),
        );
        files.insert(
            "proof_bundle.sig".to_string(),
            bundle.integrity.signature.value.as_bytes().to_vec(),
        );
        for (name, bytes) in artefacts {
            files.insert(format!("artefacts/{name}"), (*bytes).to_vec());
        }

        let mut manifest_entries = files
            .iter()
            .map(|(name, bytes)| ManifestEntry {
                name: name.clone(),
                digest: sha256_prefixed(bytes),
                size: bytes.len() as u64,
            })
            .collect::<Vec<_>>();
        if tamper_manifest {
            manifest_entries[0].digest =
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string();
        }
        files.insert(
            "manifest.json".to_string(),
            serde_json::to_vec_pretty(&Manifest {
                files: manifest_entries,
            })
            .unwrap(),
        );

        let package = BundlePackage {
            format: PACKAGE_FORMAT.to_string(),
            files: files
                .into_iter()
                .map(|(name, bytes)| PackagedFile {
                    name,
                    data_base64: Base64::encode_string(&bytes),
                })
                .collect(),
        };
        let package_json = serde_json::to_vec_pretty(&package).unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&package_json).unwrap();
        encoder.finish().unwrap()
    }

    fn decode_pack_archive(bytes: &[u8]) -> EvidencePackArchive {
        let mut decoder = GzDecoder::new(std::io::Cursor::new(bytes));
        let mut json = Vec::new();
        decoder.read_to_end(&mut json).unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    fn decode_backup_archive(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = tar::Archive::new(decoder);
        let mut files = BTreeMap::new();

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).unwrap();
            files.insert(path, contents);
        }

        files
    }

    async fn create_bundle_response(
        app: &Router,
        payload: &CreateBundleRequest,
    ) -> CreateBundleResponse {
        create_bundle_response_with_token(app, payload, None).await
    }

    async fn create_bundle_response_with_token(
        app: &Router,
        payload: &CreateBundleRequest,
        bearer_token: Option<&str>,
    ) -> CreateBundleResponse {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap();
        let mut request = request;
        if let Some(bearer_token) = bearer_token {
            request.headers_mut().insert(
                header::AUTHORIZATION,
                format!("Bearer {bearer_token}").parse().unwrap(),
            );
        }
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn build_vault_runtime_config_merges_file_settings_and_env_overrides() {
        let config_dir = std::env::temp_dir().join(format!(
            "proof-service-config-test-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("vault.toml");
        let backup_key_path = config_dir.join("keys/backup.key");
        std::fs::create_dir_all(backup_key_path.parent().unwrap()).unwrap();
        std::fs::write(&backup_key_path, Base64::encode_string(&[11_u8; 32])).unwrap();
        let (tsa_certificate, _) = build_test_certificate();
        let file_config = VaultFileConfig {
            server: VaultServerFileConfig {
                addr: Some("127.0.0.1:8181".to_string()),
                max_payload_bytes: Some(2048),
                tls_cert: Some("./tls/server.crt".to_string()),
                tls_key: Some("./tls/server.key".to_string()),
            },
            auth: Some(VaultAuthFileConfig {
                enabled: Some(true),
                api_keys: vec![VaultApiKeyFileConfig {
                    key: "test-api-key".to_string(),
                    label: Some("ops".to_string()),
                }],
            }),
            tenant: Some(VaultTenantFileConfig {
                organization_id: Some("org-demo".to_string()),
            }),
            signing: VaultSigningFileConfig {
                key_path: Some("./keys/signing.pem".to_string()),
                key_id: Some("file-kid".to_string()),
                algorithm: Some("ed25519".to_string()),
            },
            storage: VaultStorageFileConfig {
                metadata_backend: Some("sqlite".to_string()),
                sqlite_path: Some("./data/vault.db".to_string()),
                blob_backend: Some("filesystem".to_string()),
                blob_path: Some("./data/blobs".to_string()),
                s3: None,
                postgresql: None,
            },
            timestamp: Some(VaultTimestampFileConfig {
                enabled: Some(true),
                provider: Some("rfc3161".to_string()),
                url: Some("https://tsa.example.test".to_string()),
                assurance: Some("qualified".to_string()),
                trust_anchor_pems: vec![tsa_certificate.encode_pem()],
                trust_anchor_paths: Vec::new(),
                crl_pems: vec![test_timestamp_crl_pem()],
                crl_paths: Vec::new(),
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: vec![tsa_certificate.encode_pem()],
                qualified_signer_paths: Vec::new(),
                policy_oids: vec!["1.2.3.4".to_string()],
            }),
            transparency: Some(VaultTransparencyFileConfig {
                enabled: Some(true),
                provider: Some("rekor".to_string()),
                url: None,
                rekor_url: Some("https://rekor.example.test".to_string()),
                scitt_format: None,
                log_public_key_pem: None,
                log_public_key_path: None,
            }),
            backup: VaultBackupFileConfig {
                directory: Some("./scheduled-backups".to_string()),
                interval_hours: Some(4),
                retention_count: Some(9),
                encryption: Some(VaultBackupEncryptionFileConfig {
                    enabled: Some(true),
                    key_base64: None,
                    key_path: Some("./keys/backup.key".to_string()),
                    key_id: Some("backup-key-file".to_string()),
                }),
            },
            retention: VaultRetentionFileConfig {
                grace_period_days: Some(21),
                scan_interval_hours: Some(12),
                policies: vec![RetentionPolicyConfig {
                    retention_class: "runtime_logs".to_string(),
                    expiry_mode: RetentionExpiryMode::FixedDays,
                    min_duration_days: 3650,
                    max_duration_days: None,
                    legal_basis: "eu_ai_act_article_12_19_26".to_string(),
                    active: true,
                }],
            },
        };
        let env_vars = BTreeMap::from([
            ("PROOF_SERVICE_ADDR".to_string(), "0.0.0.0:9090".to_string()),
            (
                "PROOF_SERVICE_RETENTION_SCAN_INTERVAL_HOURS".to_string(),
                "6".to_string(),
            ),
            (
                "PROOF_SERVICE_BACKUP_RETENTION_COUNT".to_string(),
                "5".to_string(),
            ),
        ]);

        let runtime =
            build_vault_runtime_config(file_config, Some(config_path.as_path()), &env_vars)
                .unwrap();

        assert_eq!(runtime.addr, SocketAddr::from(([0, 0, 0, 0], 9090)));
        assert_eq!(runtime.max_payload_bytes, 2048);
        assert_eq!(
            runtime.tls_cert_path.as_ref(),
            Some(&config_dir.join("tls/server.crt"))
        );
        assert_eq!(
            runtime.tls_key_path.as_ref(),
            Some(&config_dir.join("tls/server.key"))
        );
        assert_eq!(
            runtime
                .auth_config
                .as_ref()
                .map(|config| config.principals[0].label.as_str()),
            Some("ops")
        );
        assert_eq!(runtime.tenant_organization_id.as_deref(), Some("org-demo"));
        assert_eq!(runtime.signing_kid, "file-kid");
        let expected_signing_key_path = config_dir.join("keys/signing.pem");
        assert_eq!(
            runtime.signing_key_path.as_ref(),
            Some(&expected_signing_key_path)
        );
        assert_eq!(runtime.metadata_backend, "sqlite");
        assert_eq!(runtime.blob_backend, "filesystem");
        assert_eq!(runtime.storage_dir, config_dir.join("data/blobs"));
        assert_eq!(runtime.db_path, config_dir.join("data/vault.db"));
        assert_eq!(runtime.backup_dir, config_dir.join("scheduled-backups"));
        assert_eq!(runtime.retention_grace_period_days, 21);
        assert_eq!(runtime.retention_scan_interval_hours, 6);
        assert_eq!(runtime.backup_interval_hours, 4);
        assert_eq!(runtime.backup_retention_count, 5);
        assert_eq!(
            runtime
                .backup_encryption
                .as_ref()
                .map(|config| config.key_id.as_str()),
            Some("backup-key-file")
        );
        assert_eq!(runtime.retention_policies.len(), 1);
        assert_eq!(
            runtime
                .timestamp_config
                .as_ref()
                .map(|config| config.url.as_str()),
            Some("https://tsa.example.test")
        );
        assert_eq!(
            runtime
                .transparency_config
                .as_ref()
                .and_then(|config| config.url.as_deref()),
            Some("https://rekor.example.test")
        );
    }

    #[test]
    fn build_vault_runtime_config_rejects_unimplemented_backends() {
        let file_config = VaultFileConfig {
            storage: VaultStorageFileConfig {
                metadata_backend: Some("postgresql".to_string()),
                ..VaultStorageFileConfig::default()
            },
            ..VaultFileConfig::default()
        };

        let err = build_vault_runtime_config(file_config, None, &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    fn build_vault_runtime_config_rejects_partial_tls_configuration() {
        let file_config = VaultFileConfig {
            server: VaultServerFileConfig {
                tls_cert: Some("./tls/server.crt".to_string()),
                tls_key: None,
                ..VaultServerFileConfig::default()
            },
            ..VaultFileConfig::default()
        };

        let err = build_vault_runtime_config(file_config, None, &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("both certificate and key"));
    }

    #[test]
    fn build_vault_runtime_config_rejects_enabled_auth_without_keys() {
        let file_config = VaultFileConfig {
            auth: Some(VaultAuthFileConfig {
                enabled: Some(true),
                api_keys: Vec::new(),
            }),
            ..VaultFileConfig::default()
        };

        let err = build_vault_runtime_config(file_config, None, &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("at least one configured API key"));
    }

    #[test]
    fn artefact_name_rejects_traversal() {
        let err = validate_artefact_name("../secret").unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[tokio::test]
    async fn readyz_checks_sqlite_health() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request = Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_prometheus_snapshot() {
        let state = test_state_with_tenant(DEFAULT_MAX_PAYLOAD_BYTES, "org-demo").await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"metrics"}"#),
                }],
            },
        )
        .await;

        let request = Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics = String::from_utf8(body.to_vec()).unwrap();
        assert!(metrics.contains("proof_layer_vault_up 1"));
        assert!(metrics.contains("proof_layer_vault_tenant_enforced 1"));
        assert!(metrics.contains("proof_layer_vault_bundle_total 1"));
        assert!(metrics.contains("proof_layer_vault_bundle_active 1"));
        assert!(metrics.contains("proof_layer_vault_disclosure_policy_total 3"));
    }

    #[tokio::test]
    async fn backup_endpoint_exports_snapshot_archive() {
        let state = test_state_with_tenant(DEFAULT_MAX_PAYLOAD_BYTES, "org-demo").await;
        let db = state.db.clone();
        std::fs::write(
            state.backup_dir.join("should-not-be-archived.txt"),
            b"exclude-me",
        )
        .unwrap();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"backup"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: None,
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);

        let backup_req = Request::builder()
            .method("POST")
            .uri("/v1/backup")
            .body(Body::empty())
            .unwrap();
        let backup_res = app.clone().oneshot(backup_req).await.unwrap();
        assert_eq!(backup_res.status(), StatusCode::OK);
        assert_eq!(
            backup_res.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
        assert!(
            backup_res
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("proof-layer-vault-backup-")
        );
        let body = axum::body::to_bytes(backup_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let files = decode_backup_archive(&body);
        assert!(files.contains_key("manifest.json"));
        assert!(files.contains_key("config/vault_config.json"));
        assert!(files.contains_key("metadata/metadata.db"));
        assert!(
            files.keys()
                .any(|name| name.ends_with(&format!("artefacts/{}/prompt.json", created.bundle_id)))
        );
        assert!(
            files
                .keys()
                .any(|name| name.ends_with(PACK_EXPORT_FILE_NAME))
        );
        assert!(
            files
                .keys()
                .all(|name| !name.contains("storage/backups/should-not-be-archived.txt"))
        );

        let manifest: VaultBackupManifest =
            serde_json::from_slice(files.get("manifest.json").unwrap()).unwrap();
        assert_eq!(manifest.format, VAULT_BACKUP_FORMAT);
        assert_eq!(manifest.metrics.bundle_total, 1);
        assert_eq!(manifest.metrics.pack_total, 1);

        let config: VaultConfigResponse =
            serde_json::from_slice(files.get("config/vault_config.json").unwrap()).unwrap();
        assert_eq!(config.tenant.organization_id.as_deref(), Some("org-demo"));

        let actor: Option<String> = sqlx::query_scalar(
            "SELECT actor FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("export_backup")
        .fetch_optional(&db)
        .await
        .unwrap();
        assert_eq!(actor.as_deref(), Some(AUDIT_ACTOR_API));
    }

    #[tokio::test]
    async fn backup_endpoint_can_encrypt_snapshot_archive() {
        let mut state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let backup_key = [29_u8; 32];
        state.backup_encryption = Some(RuntimeBackupEncryptionConfig {
            key: Arc::new(backup_key),
            key_id: "backup-key-test".to_string(),
        });
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"encrypted"}"#),
                }],
            },
        )
        .await;

        let backup_req = Request::builder()
            .method("POST")
            .uri("/v1/backup")
            .body(Body::empty())
            .unwrap();
        let backup_res = app.oneshot(backup_req).await.unwrap();
        assert_eq!(backup_res.status(), StatusCode::OK);
        assert_eq!(
            backup_res.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            backup_res
                .headers()
                .get("x-proof-layer-backup-encrypted")
                .unwrap(),
            "true"
        );
        assert!(
            backup_res
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with(".tar.gz.enc\"")
        );
        let body = axum::body::to_bytes(backup_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let decrypted = decrypt_backup_archive(&body, Some(&backup_key))
            .unwrap()
            .unwrap();
        let files = decode_backup_archive(&decrypted);
        assert!(files.contains_key("manifest.json"));

        let config: VaultConfigResponse =
            serde_json::from_slice(files.get("config/vault_config.json").unwrap()).unwrap();
        assert!(config.backup.encryption.enabled);
        assert_eq!(
            config.backup.encryption.key_id.as_deref(),
            Some("backup-key-test")
        );
    }

    #[tokio::test]
    async fn scheduled_backups_persist_archives_and_prune_old_ones() {
        let mut state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        state.backup_interval_hours = 2;
        state.backup_retention_count = 2;
        std::fs::write(state.backup_dir.join("scheduled-marker.txt"), b"skip-me").unwrap();
        let db = state.db.clone();
        let backup_dir = state.backup_dir.clone();
        let app = build_router(state.clone(), DEFAULT_MAX_PAYLOAD_BYTES);

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"scheduled-backup"}"#),
                }],
            },
        )
        .await;

        let first = perform_scheduled_backup(&state).await.unwrap();
        assert_eq!(first.pruned_count, 0);
        let second = perform_scheduled_backup(&state).await.unwrap();
        assert_eq!(second.pruned_count, 0);
        let third = perform_scheduled_backup(&state).await.unwrap();
        assert_eq!(third.pruned_count, 1);

        let mut archives = std::fs::read_dir(&backup_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.starts_with("proof-layer-vault-backup-")
                                && (name.ends_with(".tar.gz") || name.ends_with(".tar.gz.enc"))
                        })
            })
            .collect::<Vec<_>>();
        archives.sort();
        assert_eq!(archives.len(), 2);
        assert!(
            archives
                .iter()
                .all(|path| path.file_name().unwrap() != first.file_name.as_str())
        );

        let files = decode_backup_archive(&std::fs::read(archives.last().unwrap()).unwrap());
        assert!(files.contains_key("manifest.json"));
        assert!(files.contains_key("metadata/metadata.db"));
        assert!(
            files
                .keys()
                .all(|name| !name.contains("storage/backups/scheduled-marker.txt"))
        );

        let audit_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'scheduled_backup'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(audit_count, 3);
    }

    #[tokio::test]
    async fn v1_routes_require_bearer_auth_when_configured() {
        let state =
            test_state_with_auth(DEFAULT_MAX_PAYLOAD_BYTES, &[("secret-token", "ops")]).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let health_request = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let health_response = app.clone().oneshot(health_request).await.unwrap();
        assert_eq!(health_response.status(), StatusCode::OK);

        let metrics_request = Request::builder()
            .method("GET")
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let metrics_response = app.clone().oneshot(metrics_request).await.unwrap();
        assert_eq!(metrics_response.status(), StatusCode::OK);

        let backup_request = Request::builder()
            .method("POST")
            .uri("/v1/backup")
            .body(Body::empty())
            .unwrap();
        let backup_response = app.clone().oneshot(backup_request).await.unwrap();
        assert_eq!(backup_response.status(), StatusCode::UNAUTHORIZED);

        let config_request = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let config_response = app.clone().oneshot(config_request).await.unwrap();
        assert_eq!(config_response.status(), StatusCode::UNAUTHORIZED);

        let wrong_request = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let wrong_response = app.clone().oneshot(wrong_request).await.unwrap();
        assert_eq!(wrong_response.status(), StatusCode::UNAUTHORIZED);

        let auth_request = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .header("authorization", "Bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let auth_response = app.clone().oneshot(auth_request).await.unwrap();
        assert_eq!(auth_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(auth_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        assert!(config.auth.enabled);
        assert_eq!(config.auth.principal_labels, vec!["ops".to_string()]);
    }

    #[tokio::test]
    async fn authenticated_principal_label_is_written_to_audit_log() {
        let state =
            test_state_with_auth(DEFAULT_MAX_PAYLOAD_BYTES, &[("secret-token", "ops")]).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response_with_token(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"auth"}"#),
                }],
            },
            Some("secret-token"),
        )
        .await;

        let actor: Option<String> = sqlx::query_scalar(
            "SELECT actor FROM audit_log WHERE action = ? AND bundle_id = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("create_bundle")
        .bind(&created.bundle_id)
        .fetch_optional(&db)
        .await
        .unwrap();
        assert_eq!(actor.as_deref(), Some("ops"));
    }

    #[tokio::test]
    async fn create_bundle_injects_tenant_organization_id_when_missing() {
        let state = test_state_with_tenant(DEFAULT_MAX_PAYLOAD_BYTES, "org-demo").await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"tenant"}"#),
                }],
            },
        )
        .await;

        let actor_org_id: Option<String> =
            sqlx::query_scalar("SELECT actor_org_id FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(actor_org_id.as_deref(), Some("org-demo"));
    }

    #[tokio::test]
    async fn create_bundle_rejects_mismatched_tenant_organization_id() {
        let state = test_state_with_tenant(DEFAULT_MAX_PAYLOAD_BYTES, "org-demo").await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let mut event = sample_event_with_system("tenant-system");
        event.actor.organization_id = Some("org-other".to_string());

        let request = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreateBundleRequest {
                    capture: SealableCaptureInput::V10(event),
                    artefacts: vec![InlineArtefact {
                        name: "prompt.json".to_string(),
                        content_type: "application/json".to_string(),
                        data_base64: Base64::encode_string(br#"{"prompt":"tenant"}"#),
                    }],
                })
                .unwrap(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            error
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap()
                .contains("does not match tenant.organization_id=org-demo")
        );
    }

    #[tokio::test]
    async fn validate_existing_bundle_organization_scope_rejects_conflicting_rows() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();

        let mut event = sample_event_with_system("tenant-system");
        event.actor.organization_id = Some("org-other".to_string());
        let artefacts = vec![ArtefactInput {
            name: "prompt.json".to_string(),
            content_type: "application/json".to_string(),
            bytes: br#"{"prompt":"tenant"}"#.to_vec(),
        }];
        let bundle = build_bundle(
            event,
            &artefacts,
            &state.signing_key,
            "kid-dev-01",
            &generate_bundle_id(),
            Utc::now(),
        )
        .unwrap();

        persist_bundle_metadata(&db, &state.storage_dir, &bundle)
            .await
            .unwrap();

        let err = validate_existing_bundle_organization_scope(&db, Some("org-demo"))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("conflicts with tenant.organization_id=org-demo")
        );
    }

    #[tokio::test]
    async fn create_get_verify_flow_works() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let prompt_bytes = br#"{"prompt":"hello"}"#.to_vec();
        let response_bytes = br#"{"response":"world"}"#.to_vec();
        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![
                InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&prompt_bytes),
                },
                InlineArtefact {
                    name: "response.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&response_bytes),
                },
            ],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_response: CreateBundleResponse = serde_json::from_slice(&create_body).unwrap();
        assert!(!create_response.bundle_id.is_empty());
        assert!(create_response.bundle_root.starts_with("sha256:"));

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/bundles/{}", create_response.bundle_id))
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: ProofBundle = serde_json::from_slice(&get_body).unwrap();

        let artefact_req = Request::builder()
            .method("GET")
            .uri(format!(
                "/v1/bundles/{}/artefacts/prompt.json",
                create_response.bundle_id
            ))
            .body(Body::empty())
            .unwrap();
        let artefact_res = app.clone().oneshot(artefact_req).await.unwrap();
        assert_eq!(artefact_res.status(), StatusCode::OK);
        let artefact_body = axum::body::to_bytes(artefact_res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(artefact_body.to_vec(), prompt_bytes);

        let verify_payload = VerifyRequest::Inline(Box::new(InlineVerifyRequest {
            bundle,
            artefacts: vec![
                InlineVerifyArtefact {
                    name: "prompt.json".to_string(),
                    data_base64: Base64::encode_string(&prompt_bytes),
                },
                InlineVerifyArtefact {
                    name: "response.json".to_string(),
                    data_base64: Base64::encode_string(&response_bytes),
                },
            ],
            public_key_pem,
        }));

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
            .unwrap();
        let verify_res = app.clone().oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let verify_body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&verify_body).unwrap();
        assert!(verify_response.valid);
        assert_eq!(verify_response.artefacts_verified, 2);
    }

    #[tokio::test]
    async fn verify_package_flow_works() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let prompt_bytes = br#"{"prompt":"hello"}"#.to_vec();
        let response_bytes = br#"{"response":"world"}"#.to_vec();
        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![
                InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&prompt_bytes),
                },
                InlineArtefact {
                    name: "response.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&response_bytes),
                },
            ],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_response: CreateBundleResponse = serde_json::from_slice(&create_body).unwrap();

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/bundles/{}", create_response.bundle_id))
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: ProofBundle = serde_json::from_slice(&get_body).unwrap();

        let package_bytes = build_package_bytes(
            &bundle,
            &[
                ("prompt.json", &prompt_bytes),
                ("response.json", &response_bytes),
            ],
            false,
        );
        let verify_payload = VerifyRequest::Package(Box::new(PackageVerifyRequest {
            bundle_pkg_base64: Base64::encode_string(&package_bytes),
            public_key_pem,
        }));

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
            .unwrap();
        let verify_res = app.clone().oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let verify_body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&verify_body).unwrap();
        assert!(verify_response.valid);
        assert_eq!(verify_response.artefacts_verified, 2);
    }

    #[tokio::test]
    async fn verify_package_manifest_mismatch_returns_invalid() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let prompt_bytes = br#"{"prompt":"hello"}"#.to_vec();
        let response_bytes = br#"{"response":"world"}"#.to_vec();
        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![
                InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&prompt_bytes),
                },
                InlineArtefact {
                    name: "response.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(&response_bytes),
                },
            ],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let create_body = axum::body::to_bytes(create_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_response: CreateBundleResponse = serde_json::from_slice(&create_body).unwrap();

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/bundles/{}", create_response.bundle_id))
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: ProofBundle = serde_json::from_slice(&get_body).unwrap();

        let package_bytes = build_package_bytes(
            &bundle,
            &[
                ("prompt.json", &prompt_bytes),
                ("response.json", &response_bytes),
            ],
            true,
        );
        let verify_payload = VerifyRequest::Package(Box::new(PackageVerifyRequest {
            bundle_pkg_base64: Base64::encode_string(&package_bytes),
            public_key_pem,
        }));

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
            .unwrap();
        let verify_res = app.clone().oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let verify_body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&verify_body).unwrap();
        assert!(!verify_response.valid);
        assert!(verify_response.message.contains("manifest mismatch"));
    }

    #[tokio::test]
    async fn create_bundle_rejects_oversized_artefact() {
        let state_limit = 32;
        let state = test_state(state_limit).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let oversized = vec![b'a'; state_limit + 1];

        let payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![InlineArtefact {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                data_base64: Base64::encode_string(&oversized),
            }],
        };

        let request = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_bundle_rejects_duplicate_artefact_names() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![
                InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                },
                InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"duplicate"}"#),
                },
            ],
        };

        let request = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_missing_artefact_returns_not_found() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/bundles/PLMISSING/artefacts/prompt.json")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_bundles_filters_by_role_and_item_type() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![InlineArtefact {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
            }],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);

        let query_req = Request::builder()
            .method("GET")
            .uri("/v1/bundles?role=provider&type=llm_interaction&page=1&limit=10")
            .body(Body::empty())
            .unwrap();
        let query_res = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(query_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: ListBundlesResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.page, 1);
        assert_eq!(response.limit, 10);
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].actor_role, "provider");
        assert!(response.items[0].expires_at.is_some());
        assert!(!response.items[0].has_legal_hold);
        assert_eq!(response.items[0].assurance_level, "signed");
    }

    #[tokio::test]
    async fn list_bundles_filters_by_assurance_flags() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"assurance"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();
        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let query_req = Request::builder()
            .method("GET")
            .uri("/v1/bundles?has_timestamp=true&has_receipt=true&assurance_level=transparency_anchored")
            .body(Body::empty())
            .unwrap();
        let query_res = app.oneshot(query_req).await.unwrap();
        assert_eq!(query_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(query_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: ListBundlesResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].bundle_id, created.bundle_id);
        assert!(response.items[0].has_timestamp);
        assert!(response.items[0].has_receipt);
        assert_eq!(response.items[0].assurance_level, "transparency_anchored");
    }

    #[tokio::test]
    async fn list_systems_rolls_up_bundle_and_assurance_counts() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let first = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-a").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"system-a-1"}"#),
                }],
            },
        )
        .await;
        let second = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::LiteracyAttestation(
                        proof_layer_core::schema::LiteracyAttestationEvidence {
                            attested_role: "support_agent".to_string(),
                            status: "completed".to_string(),
                            training_ref: Some("course://ai-literacy/v1".to_string()),
                            attestation_commitment: None,
                            completion_date: None,
                            training_provider: None,
                            certificate_digest: None,
                            metadata: serde_json::json!({"source": "lms"}),
                        },
                    )],
                    Some("ai_literacy"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"system-a-2"}"#),
                }],
            },
        )
        .await;
        let _third = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-b",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-b").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"system-b"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &first.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();
        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/bundles/{}", second.bundle_id))
            .body(Body::empty())
            .unwrap();
        let delete_res = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(delete_res.status(), StatusCode::OK);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/systems")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let systems: ListSystemsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(systems.items.len(), 2);
        let system_a = systems
            .items
            .iter()
            .find(|entry| entry.system_id == "system-a")
            .unwrap();
        assert_eq!(system_a.bundle_count, 2);
        assert_eq!(system_a.active_bundle_count, 1);
        assert_eq!(system_a.deleted_bundle_count, 1);
        assert_eq!(system_a.timestamped_bundle_count, 1);
        assert_eq!(system_a.receipt_bundle_count, 1);
        assert!(system_a.latest_bundle_at.is_some());
    }

    #[tokio::test]
    async fn get_system_summary_reports_role_item_and_retention_breakdowns() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let provider_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-summary",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-summary").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"provider"}"#),
                }],
            },
        )
        .await;
        let _integrator_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-summary",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::LiteracyAttestation(
                        proof_layer_core::schema::LiteracyAttestationEvidence {
                            attested_role: "reviewer".to_string(),
                            status: "approved".to_string(),
                            training_ref: Some("training://eu-ai-act-basics".to_string()),
                            attestation_commitment: None,
                            completion_date: None,
                            training_provider: None,
                            certificate_digest: None,
                            metadata: serde_json::json!({"source": "training"}),
                        },
                    )],
                    Some("ai_literacy"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"integrator"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &provider_bundle.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();
        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let request = Request::builder()
            .method("GET")
            .uri("/v1/systems/system-summary/summary")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let summary: SystemSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(summary.system_id, "system-summary");
        assert_eq!(summary.bundle_count, 2);
        assert_eq!(summary.active_bundle_count, 2);
        assert_eq!(summary.deleted_bundle_count, 0);
        assert_eq!(summary.timestamped_bundle_count, 1);
        assert_eq!(summary.receipt_bundle_count, 1);
        assert!(
            summary
                .actor_roles
                .iter()
                .any(|entry| entry.value == "provider" && entry.count == 1)
        );
        assert!(
            summary
                .actor_roles
                .iter()
                .any(|entry| entry.value == "integrator" && entry.count == 1)
        );
        assert!(
            summary
                .evidence_types
                .iter()
                .any(|entry| entry.value == "llm_interaction" && entry.count == 1)
        );
        assert!(
            summary
                .evidence_types
                .iter()
                .any(|entry| entry.value == "literacy_attestation" && entry.count == 1)
        );
        assert!(
            summary
                .retention_classes
                .iter()
                .any(|entry| entry.value == "runtime_logs" && entry.count == 1)
        );
        assert!(
            summary
                .retention_classes
                .iter()
                .any(|entry| entry.value == "ai_literacy" && entry.count == 1)
        );
        assert!(
            summary
                .assurance_levels
                .iter()
                .any(|entry| entry.value == "transparency_anchored" && entry.count == 1)
        );
        assert!(
            summary
                .assurance_levels
                .iter()
                .any(|entry| entry.value == "signed" && entry.count == 1)
        );
        assert!(
            summary
                .model_ids
                .iter()
                .any(|entry| entry.value == "anthropic:claude-sonnet-4-6")
        );
    }

    #[tokio::test]
    async fn retention_status_reports_seeded_policy_counts() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![InlineArtefact {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
            }],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);

        let status_req = Request::builder()
            .method("GET")
            .uri("/v1/retention/status")
            .body(Body::empty())
            .unwrap();
        let status_res = app.oneshot(status_req).await.unwrap();
        assert_eq!(status_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(status_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: RetentionStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            response.grace_period_days,
            DEFAULT_RETENTION_GRACE_PERIOD_DAYS
        );
        let unspecified = response
            .policies
            .iter()
            .find(|policy| policy.retention_class == "unspecified")
            .unwrap();
        assert_eq!(unspecified.active_bundles, 1);
        assert_eq!(unspecified.held_bundles, 0);
        assert_eq!(unspecified.hard_delete_ready_bundles, 0);
        assert!(unspecified.next_expiry.is_some());

        let gpai = response
            .policies
            .iter()
            .find(|policy| policy.retention_class == "gpai_documentation")
            .unwrap();
        assert_eq!(gpai.expiry_mode, RetentionExpiryMode::UntilWithdrawn);
        assert_eq!(gpai.active_bundles, 0);
        assert!(gpai.next_expiry.is_none());
    }

    #[tokio::test]
    async fn gpai_documentation_bundles_do_not_get_expiry_dates() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-gpai-retention",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::ModelEvaluation(
                        proof_layer_core::schema::ModelEvaluationEvidence {
                            evaluation_id: "eval-gpai-retention".to_string(),
                            benchmark: "mmlu-pro".to_string(),
                            status: "completed".to_string(),
                            summary: Some("retention semantics test".to_string()),
                            report_commitment: Some(
                                "sha256:abababababababababababababababababababababababababababababababab"
                                    .to_string(),
                            ),
                            metrics_summary: Vec::new(),
                            group_performance: Vec::new(),
                            evaluation_methodology: None,
                            metadata: serde_json::json!({"suite": "gpai-retention"}),
                        },
                    )],
                    Some("gpai_documentation"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "model_evaluation.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"evaluation_id":"eval-1"}"#),
                }],
            },
        )
        .await;

        let expires_at: Option<String> =
            sqlx::query_scalar("SELECT expires_at FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(expires_at, None);
    }

    #[tokio::test]
    async fn retention_scan_soft_deletes_expired_bundles() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let create_payload = CreateBundleRequest {
            capture: SealableCaptureInput::Legacy(sample_capture()),
            artefacts: vec![InlineArtefact {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
            }],
        };

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&create_payload).unwrap()))
            .unwrap();
        let create_res = app.clone().oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);

        sqlx::query("UPDATE bundles SET expires_at = ?")
            .bind("2020-01-01T00:00:00+00:00")
            .execute(&db)
            .await
            .unwrap();

        let scan_req = Request::builder()
            .method("POST")
            .uri("/v1/retention/scan")
            .body(Body::empty())
            .unwrap();
        let scan_res = app.clone().oneshot(scan_req).await.unwrap();
        assert_eq!(scan_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scan_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: RetentionScanResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.soft_deleted, 1);
        assert_eq!(response.hard_deleted, 0);
        assert_eq!(response.held_skipped, 0);

        let list_req = Request::builder()
            .method("GET")
            .uri("/v1/bundles")
            .body(Body::empty())
            .unwrap();
        let list_res = app.oneshot(list_req).await.unwrap();
        assert_eq!(list_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(list_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: ListBundlesResponse = serde_json::from_slice(&body).unwrap();
        assert!(response.items.is_empty());
    }

    #[tokio::test]
    async fn legal_hold_blocks_manual_and_scan_deletion_until_released() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-hold",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-hold").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"held"}"#),
                }],
            },
        )
        .await;

        let hold_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/bundles/{}/legal-hold", created.bundle_id))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&LegalHoldRequest {
                    reason: "regulatory inquiry".to_string(),
                    until: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let hold_res = app.clone().oneshot(hold_req).await.unwrap();
        assert_eq!(hold_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(hold_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let hold: LegalHoldResponse = serde_json::from_slice(&body).unwrap();
        assert!(hold.active);
        assert_eq!(hold.reason.as_deref(), Some("regulatory inquiry"));

        sqlx::query("UPDATE bundles SET expires_at = ? WHERE bundle_id = ?")
            .bind("2020-01-01T00:00:00+00:00")
            .bind(&created.bundle_id)
            .execute(&db)
            .await
            .unwrap();

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/bundles/{}", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let delete_res = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(delete_res.status(), StatusCode::CONFLICT);

        let scan_req = Request::builder()
            .method("POST")
            .uri("/v1/retention/scan")
            .body(Body::empty())
            .unwrap();
        let scan_res = app.clone().oneshot(scan_req).await.unwrap();
        assert_eq!(scan_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scan_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: RetentionScanResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.soft_deleted, 0);
        assert_eq!(response.hard_deleted, 0);
        assert_eq!(response.held_skipped, 1);

        let release_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/bundles/{}/legal-hold", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let release_res = app.clone().oneshot(release_req).await.unwrap();
        assert_eq!(release_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(release_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let released: LegalHoldResponse = serde_json::from_slice(&body).unwrap();
        assert!(!released.active);

        let scan_req = Request::builder()
            .method("POST")
            .uri("/v1/retention/scan")
            .body(Body::empty())
            .unwrap();
        let scan_res = app.clone().oneshot(scan_req).await.unwrap();
        assert_eq!(scan_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scan_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: RetentionScanResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.soft_deleted, 1);
        assert_eq!(response.hard_deleted, 0);
    }

    #[tokio::test]
    async fn retention_scan_hard_deletes_soft_deleted_bundles_after_grace_period() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let storage_dir = state.storage_dir.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"cleanup"}"#),
                }],
            },
        )
        .await;

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/bundles/{}", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let delete_res = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(delete_res.status(), StatusCode::OK);

        sqlx::query("UPDATE bundles SET deleted_at = ? WHERE bundle_id = ?")
            .bind("2020-01-01T00:00:00+00:00")
            .bind(&created.bundle_id)
            .execute(&db)
            .await
            .unwrap();

        let artefact_dir = storage_dir.join("artefacts").join(&created.bundle_id);
        assert!(artefact_dir.exists());

        let scan_req = Request::builder()
            .method("POST")
            .uri("/v1/retention/scan")
            .body(Body::empty())
            .unwrap();
        let scan_res = app.clone().oneshot(scan_req).await.unwrap();
        assert_eq!(scan_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(scan_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: RetentionScanResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.soft_deleted, 0);
        assert_eq!(response.hard_deleted, 1);
        assert_eq!(response.held_skipped, 0);

        let remaining: Option<String> =
            sqlx::query_scalar("SELECT bundle_id FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(remaining.is_none());
        assert!(!artefact_dir.exists());
    }

    #[tokio::test]
    async fn audit_trail_lists_and_filters_recorded_actions() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"audit"}"#),
                }],
            },
        )
        .await;

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/bundles/{}", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle: ProofBundle = serde_json::from_slice(&get_body).unwrap();

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Inline(Box::new(InlineVerifyRequest {
                    bundle,
                    artefacts: vec![InlineVerifyArtefact {
                        name: "prompt.json".to_string(),
                        data_base64: Base64::encode_string(br#"{"prompt":"audit"}"#),
                    }],
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.clone().oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);

        let delete_req = Request::builder()
            .method("DELETE")
            .uri(format!("/v1/bundles/{}", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let delete_res = app.clone().oneshot(delete_req).await.unwrap();
        assert_eq!(delete_res.status(), StatusCode::OK);

        let audit_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/audit-trail?bundle_id={}", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let audit_res = app.clone().oneshot(audit_req).await.unwrap();
        assert_eq!(audit_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(audit_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuditTrailResponse = serde_json::from_slice(&body).unwrap();

        assert!(response.items.len() >= 3);
        assert!(
            response
                .items
                .iter()
                .any(|item| item.action == "create_bundle")
        );
        assert!(
            response
                .items
                .iter()
                .any(|item| item.action == "get_bundle")
        );
        assert!(
            response
                .items
                .iter()
                .any(|item| item.action == "delete_bundle")
        );
        assert!(
            response
                .items
                .iter()
                .all(|item| item.bundle_id.as_deref() == Some(created.bundle_id.as_str()))
        );

        let action_req = Request::builder()
            .method("GET")
            .uri("/v1/audit-trail?action=verify_bundle")
            .body(Body::empty())
            .unwrap();
        let action_res = app.oneshot(action_req).await.unwrap();
        assert_eq!(action_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(action_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: AuditTrailResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].action, "verify_bundle");
        assert_eq!(response.items[0].actor.as_deref(), Some(AUDIT_ACTOR_API));
        assert_eq!(
            response.items[0]
                .details
                .get("valid")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn get_config_returns_runtime_retention_and_assurance_views() {
        let state = test_state_with_tenant(DEFAULT_MAX_PAYLOAD_BYTES, "org-demo").await;
        let expected_backup_dir = state.backup_dir.display().to_string();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(config.service.addr, DEFAULT_ADDR);
        assert_eq!(config.service.max_payload_bytes, DEFAULT_MAX_PAYLOAD_BYTES);
        assert!(!config.service.tls_enabled);
        assert!(!config.auth.enabled);
        assert!(config.auth.principal_labels.is_empty());
        assert_eq!(config.tenant.organization_id.as_deref(), Some("org-demo"));
        assert!(config.tenant.enforced);
        assert_eq!(config.signing.key_id, "kid-dev-01");
        assert_eq!(config.signing.algorithm, "ed25519");
        assert!(
            config
                .signing
                .public_key_pem
                .contains("BEGIN PROOF LAYER ED25519 PUBLIC KEY")
        );
        assert!(!config.signing.ephemeral);
        assert_eq!(config.storage.metadata_backend, "sqlite");
        assert_eq!(config.storage.blob_backend, "filesystem");
        assert_eq!(
            config.retention.grace_period_days,
            DEFAULT_RETENTION_GRACE_PERIOD_DAYS
        );
        assert_eq!(
            config.retention.scan_interval_hours,
            DEFAULT_RETENTION_SCAN_INTERVAL_HOURS
        );
        assert!(!config.backup.enabled);
        assert_eq!(config.backup.interval_hours, DEFAULT_BACKUP_INTERVAL_HOURS);
        assert_eq!(
            config.backup.retention_count,
            DEFAULT_BACKUP_RETENTION_COUNT
        );
        assert!(!config.backup.encryption.enabled);
        assert_eq!(config.backup.encryption.algorithm, None);
        assert_eq!(config.backup.encryption.key_id, None);
        assert_eq!(config.backup.directory, expected_backup_dir);
        assert!(
            config
                .retention
                .policies
                .iter()
                .any(|policy| policy.retention_class == "unspecified")
        );
        let gpai = config
            .retention
            .policies
            .iter()
            .find(|policy| policy.retention_class == "gpai_documentation")
            .unwrap();
        assert_eq!(gpai.expiry_mode, RetentionExpiryMode::UntilWithdrawn);
        assert!(!config.timestamp.enabled);
        assert_eq!(config.timestamp.provider, DEFAULT_TIMESTAMP_PROVIDER);
        assert_eq!(config.timestamp.url, DEFAULT_TIMESTAMP_URL);
        assert_eq!(config.timestamp.assurance, None);
        assert!(!config.transparency.enabled);
        assert_eq!(config.transparency.provider, DEFAULT_TRANSPARENCY_PROVIDER);
        assert_eq!(config.transparency.url, None);
        assert_eq!(config.disclosure.policies.len(), 3);
        assert!(
            config
                .disclosure
                .policies
                .iter()
                .any(|policy| policy.name == DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM)
        );
        assert!(config.audit.enabled);
    }

    #[tokio::test]
    async fn apply_runtime_config_to_db_seeds_retention_and_assurance_settings() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let (tsa_certificate, _) = build_test_certificate();
        let runtime_config = VaultRuntimeConfig {
            addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            storage_dir: state.storage_dir.clone(),
            db_path: state.storage_dir.join("metadata.db"),
            backup_dir: state.backup_dir.clone(),
            tls_cert_path: None,
            tls_key_path: None,
            auth_config: None,
            tenant_organization_id: None,
            signing_key_path: None,
            signing_kid: "kid-runtime".to_string(),
            metadata_backend: "sqlite".to_string(),
            blob_backend: "filesystem".to_string(),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            retention_grace_period_days: 45,
            retention_scan_interval_hours: 8,
            backup_interval_hours: 12,
            backup_retention_count: 6,
            backup_encryption: None,
            retention_policies: vec![RetentionPolicyConfig {
                retention_class: "runtime_logs".to_string(),
                expiry_mode: RetentionExpiryMode::FixedDays,
                min_duration_days: 4000,
                max_duration_days: Some(5000),
                legal_basis: "custom_runtime_policy".to_string(),
                active: true,
            }],
            timestamp_config: Some(TimestampConfig {
                enabled: true,
                provider: "rfc3161".to_string(),
                url: "https://tsa.example.test".to_string(),
                assurance: Some("qualified".to_string()),
                trust_anchor_pems: vec![tsa_certificate.encode_pem()],
                crl_pems: vec![test_timestamp_crl_pem()],
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: vec![tsa_certificate.encode_pem()],
                policy_oids: vec!["1.2.3.4".to_string()],
            }),
            transparency_config: Some(TransparencyConfig {
                enabled: true,
                provider: "rekor".to_string(),
                url: Some("https://rekor.example.test".to_string()),
                scitt_format: None,
                log_public_key_pem: None,
            }),
            config_path: Some(state.storage_dir.join("vault.toml")),
        };

        apply_runtime_config_to_db(&state.db, &runtime_config)
            .await
            .unwrap();

        let policies = load_retention_policies(&state.db).await.unwrap();
        let runtime_logs = policies
            .iter()
            .find(|policy| policy.retention_class == "runtime_logs")
            .unwrap();
        assert_eq!(runtime_logs.expiry_mode, RetentionExpiryMode::FixedDays);
        assert_eq!(runtime_logs.min_duration_days, 4000);
        assert_eq!(runtime_logs.max_duration_days, Some(5000));
        assert_eq!(runtime_logs.legal_basis, "custom_runtime_policy");

        let timestamp = load_timestamp_config(&state.db).await.unwrap();
        assert!(timestamp.enabled);
        assert_eq!(timestamp.url, "https://tsa.example.test");

        let transparency = load_transparency_config(&state.db).await.unwrap();
        assert!(transparency.enabled);
        assert_eq!(
            transparency.url.as_deref(),
            Some("https://rekor.example.test")
        );

        let audit_actions: Vec<String> =
            sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id ASC")
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert!(audit_actions.contains(&"startup_config_sync".to_string()));
    }

    #[tokio::test]
    async fn get_config_reports_demo_provider_availability() {
        let state = test_state_with_demo_provider(
            DEFAULT_MAX_PAYLOAD_BYTES,
            DemoProviderName::Openai,
            DemoProviderResponse {
                capture_mode: "live_provider_capture".to_string(),
                provider: "openai".to_string(),
                model: "gpt-5-mini".to_string(),
                output_text: "demo".to_string(),
                usage: DemoTokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                    total_tokens: 15,
                },
                latency_ms: 120,
                provider_request_id: Some("resp_123".to_string()),
                prompt_payload: serde_json::json!({"prompt": "demo"}),
                response_payload: serde_json::json!({"output_text": "demo"}),
                trace_payload: serde_json::json!({"request_id": "req-demo"}),
            },
        )
        .await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        assert!(config.demo.providers.openai.live_enabled);
        assert!(!config.demo.providers.anthropic.live_enabled);
        assert_eq!(config.demo.capture_modes, vec!["synthetic", "live"]);
    }

    #[tokio::test]
    async fn demo_provider_response_synthetic_mode_returns_structured_payload() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/demo/provider-response")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DemoProviderResponseRequest {
                            mode: DemoCaptureMode::Synthetic,
                            provider: DemoProviderName::Openai,
                            model: "gpt-5-mini".to_string(),
                            system_prompt: "Stay concise".to_string(),
                            user_prompt: "Summarize the proof workflow".to_string(),
                            provider_api_key: None,
                            temperature: 0.2,
                            max_tokens: 256,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DemoProviderResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.capture_mode, "synthetic_demo_capture");
        assert_eq!(payload.provider, "openai");
        assert_eq!(payload.model, "gpt-5-mini");
        assert!(payload.output_text.contains("Proof Layer"));
        assert!(payload.usage.total_tokens > 0);
        assert!(payload.prompt_payload.is_object());
        assert!(payload.response_payload.is_object());
        assert!(payload.trace_payload.is_object());
    }

    #[tokio::test]
    async fn demo_provider_response_live_mode_rejects_unavailable_provider() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/demo/provider-response")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DemoProviderResponseRequest {
                            mode: DemoCaptureMode::Live,
                            provider: DemoProviderName::Anthropic,
                            model: "claude-sonnet-4-6".to_string(),
                            system_prompt: "Stay concise".to_string(),
                            user_prompt: "Summarize the proof workflow".to_string(),
                            provider_api_key: None,
                            temperature: 0.2,
                            max_tokens: 256,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            payload["error"]
                .as_str()
                .unwrap()
                .contains("requires either vault configuration or a temporary provider_api_key")
        );
    }

    #[tokio::test]
    async fn demo_provider_response_live_mode_supports_fake_provider_clients() {
        let state = test_state_with_demo_provider(
            DEFAULT_MAX_PAYLOAD_BYTES,
            DemoProviderName::Openai,
            DemoProviderResponse {
                capture_mode: "live_provider_capture".to_string(),
                provider: "openai".to_string(),
                model: "gpt-5.2".to_string(),
                output_text: "Live provider output".to_string(),
                usage: DemoTokenUsage {
                    input_tokens: 23,
                    output_tokens: 44,
                    total_tokens: 67,
                },
                latency_ms: 412,
                provider_request_id: Some("resp_live_01".to_string()),
                prompt_payload: serde_json::json!({"kind": "request"}),
                response_payload: serde_json::json!({"kind": "response"}),
                trace_payload: serde_json::json!({"request_id": "req-live-01"}),
            },
        )
        .await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/demo/provider-response")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DemoProviderResponseRequest {
                            mode: DemoCaptureMode::Live,
                            provider: DemoProviderName::Openai,
                            model: "gpt-5.2".to_string(),
                            system_prompt: "Stay concise".to_string(),
                            user_prompt: "Summarize the proof workflow".to_string(),
                            provider_api_key: None,
                            temperature: 0.2,
                            max_tokens: 256,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: DemoProviderResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.capture_mode, "live_provider_capture");
        assert_eq!(payload.provider_request_id.as_deref(), Some("resp_live_01"));
        assert_eq!(payload.output_text, "Live provider output");
        assert_eq!(payload.usage.total_tokens, 67);
    }

    #[tokio::test]
    async fn demo_provider_response_validates_required_fields() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/demo/provider-response")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "mode": "synthetic",
                            "provider": "openai",
                            "model": "",
                            "system_prompt": "",
                            "user_prompt": "hello",
                            "temperature": 0.2,
                            "max_tokens": 0
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            payload["error"]
                .as_str()
                .unwrap()
                .contains("model must not be empty")
        );
    }

    #[tokio::test]
    async fn timestamp_bundle_endpoint_requires_enabled_timestamp_config() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"timestamp"}"#),
                }],
            },
        )
        .await;

        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/bundles/{}/timestamp", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn verify_timestamp_endpoint_supports_direct_payloads() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(bundle_root, Some("test-tsa"));

        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify/timestamp")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyTimestampRequest::Direct {
                    bundle_root: bundle_root.to_string(),
                    timestamp: token,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verified: VerifyTimestampResponse = serde_json::from_slice(&body).unwrap();
        assert!(verified.valid);
        assert!(verified.message.contains("VALID"));
        assert!(verified.verification.is_some());
    }

    #[tokio::test]
    async fn anchor_bundle_endpoint_requires_enabled_transparency_config() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"anchor"}"#),
                }],
            },
        )
        .await;

        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/bundles/{}/anchor", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn anchor_bundle_endpoint_requires_timestamped_bundle_when_enabled() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        upsert_service_config(
            &db,
            SERVICE_CONFIG_KEY_TRANSPARENCY,
            &TransparencyConfig {
                enabled: true,
                provider: "rekor".to_string(),
                url: Some("https://rekor.example.test".to_string()),
                scitt_format: None,
                log_public_key_pem: None,
            },
        )
        .await
        .unwrap();

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"anchor"}"#),
                }],
            },
        )
        .await;

        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/bundles/{}/anchor", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn anchor_bundle_endpoint_supports_scitt_provider() {
        use std::{net::TcpListener, thread};

        #[derive(Serialize)]
        struct ScittCoseReceiptPayload<'a> {
            entry_id: &'a str,
            service_id: &'a str,
            registered_at: &'a str,
            statement_hash: &'a str,
        }

        #[derive(Serialize)]
        struct ScittCoseReceiptEnvelope<'a> {
            payload: ScittCoseReceiptPayload<'a>,
            signature_der_b64: String,
        }

        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let signing_key = P256SigningKey::random(&mut OsRng);
        let public_key_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let service_id = hex::encode(Sha256::digest(
            signing_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let mut content_length = 0_usize;

            loop {
                let mut line = String::new();
                let bytes_read = reader.read_line(&mut line).unwrap();
                if bytes_read == 0 || line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    content_length = value.trim().parse::<usize>().unwrap();
                }
                request.push_str(&line);
            }

            let mut body = vec![0_u8; content_length];
            reader.read_exact(&mut body).unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(payload["statement_cose_b64"].is_string());
            let statement_hash = payload["statement_hash"].as_str().unwrap();
            let response_payload = {
                let payload = ScittCoseReceiptPayload {
                    entry_id: "entry-scitt-001",
                    service_id: &service_id,
                    registered_at: "2026-03-06T13:15:00Z",
                    statement_hash,
                };
                let mut bytes = Vec::new();
                ciborium::into_writer(&payload, &mut bytes).unwrap();
                bytes
            };
            let signature: Signature = signing_key.sign(&response_payload);
            let mut receipt_cbor = Vec::new();
            ciborium::into_writer(
                &ScittCoseReceiptEnvelope {
                    payload: ScittCoseReceiptPayload {
                        entry_id: "entry-scitt-001",
                        service_id: &service_id,
                        registered_at: "2026-03-06T13:15:00Z",
                        statement_hash,
                    },
                    signature_der_b64: Base64::encode_string(signature.to_der().as_bytes()),
                },
                &mut receipt_cbor,
            )
            .unwrap();
            let response_body = serde_json::json!({
                "entry_id": "entry-scitt-001",
                "service_id": service_id,
                "registered_at": "2026-03-06T13:15:00Z",
                "receipt_cbor_b64": Base64::encode_string(&receipt_cbor),
            })
            .to_string();

            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        });

        upsert_service_config(
            &db,
            SERVICE_CONFIG_KEY_TRANSPARENCY,
            &TransparencyConfig {
                enabled: true,
                provider: "scitt".to_string(),
                url: Some(format!("http://{addr}/entries")),
                scitt_format: None,
                log_public_key_pem: Some(public_key_pem),
            },
        )
        .await
        .unwrap();

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"anchor-scitt"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/bundles/{}/anchor", created.bundle_id))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let anchored: AnchorBundleResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(anchored.kind, SCITT_TRANSPARENCY_KIND);
        assert_eq!(anchored.provider.as_deref(), Some("scitt"));

        server.join().unwrap();
    }

    #[tokio::test]
    async fn apply_timestamp_token_to_bundle_persists_bundle_timestamp() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"timestamp"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        let token = build_test_timestamp_token(&bundle.integrity.bundle_root, Some("test-tsa"));

        let verification = apply_timestamp_token_to_bundle(&mut bundle, token, None).unwrap();
        assert_eq!(verification.provider.as_deref(), Some("test-tsa"));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();

        let stored = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.timestamp.is_some());

        let has_timestamp: bool =
            sqlx::query_scalar("SELECT has_timestamp FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(has_timestamp);
    }

    #[tokio::test]
    async fn apply_receipt_to_bundle_persists_bundle_receipt() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"receipt"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();

        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        let verification = apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        assert_eq!(verification.provider.as_deref(), Some("rekor"));
        assert_eq!(verification.log_index, 0);
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let stored = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.receipt.is_some());

        let has_receipt: bool =
            sqlx::query_scalar("SELECT has_receipt FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(has_receipt);
    }

    #[tokio::test]
    async fn apply_scitt_receipt_to_bundle_persists_bundle_receipt() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"receipt-scitt"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();

        let receipt = build_test_scitt_receipt(&bundle.integrity.bundle_root, Some("scitt"));
        let verification = apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        assert_eq!(verification.kind, SCITT_TRANSPARENCY_KIND);
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let stored = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        assert!(stored.receipt.is_some());
    }

    #[tokio::test]
    async fn verify_receipt_endpoint_supports_bundle_id_lookup() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::Legacy(sample_capture()),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"verify-receipt"}"#),
                }],
            },
        )
        .await;

        let mut bundle = load_active_bundle(&db, &created.bundle_id)
            .await
            .unwrap()
            .unwrap();
        bundle.timestamp = Some(build_test_timestamp_token(
            &bundle.integrity.bundle_root,
            Some("test-tsa"),
        ));
        persist_bundle_timestamp(&db, &bundle).await.unwrap();
        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        apply_receipt_to_bundle(&mut bundle, receipt, None).unwrap();
        persist_bundle_receipt(&db, &bundle).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/verify/receipt")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyReceiptRequest::BundleId {
                    bundle_id: created.bundle_id.clone(),
                    live_check_mode: ReceiptLiveCheckMode::Off,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verified: VerifyReceiptResponse = serde_json::from_slice(&body).unwrap();
        assert!(verified.valid);
        assert!(verified.message.contains("VALID"));
        assert_eq!(
            verified
                .verification
                .as_ref()
                .and_then(|verification| verification.provider.as_deref()),
            Some("rekor")
        );
    }

    #[tokio::test]
    async fn update_retention_config_upserts_policy_and_refreshes_bundle_expiry() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/retention")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&UpdateRetentionConfigRequest {
                    policies: vec![RetentionPolicyConfig {
                        retention_class: "custom_short".to_string(),
                        expiry_mode: RetentionExpiryMode::FixedDays,
                        min_duration_days: 10,
                        max_duration_days: Some(30),
                        legal_basis: "test_policy".to_string(),
                        active: true,
                    }],
                })
                .unwrap(),
            ))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(put_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: UpdateRetentionConfigResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.updated, 1);
        assert!(
            response
                .policies
                .iter()
                .any(|policy| policy.retention_class == "custom_short")
        );

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-config",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-config").items,
                    Some("custom_short"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"config"}"#),
                }],
            },
        )
        .await;

        let before: String =
            sqlx::query_scalar("SELECT expires_at FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/retention")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&UpdateRetentionConfigRequest {
                    policies: vec![RetentionPolicyConfig {
                        retention_class: "custom_short".to_string(),
                        expiry_mode: RetentionExpiryMode::FixedDays,
                        min_duration_days: 20,
                        max_duration_days: Some(40),
                        legal_basis: "test_policy_v2".to_string(),
                        active: true,
                    }],
                })
                .unwrap(),
            ))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);

        let after: String =
            sqlx::query_scalar("SELECT expires_at FROM bundles WHERE bundle_id = ?")
                .bind(&created.bundle_id)
                .fetch_one(&db)
                .await
                .unwrap();

        let before = chrono::DateTime::parse_from_rfc3339(&before).unwrap();
        let after = chrono::DateTime::parse_from_rfc3339(&after).unwrap();
        assert!(after > before);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        let custom = config
            .retention
            .policies
            .iter()
            .find(|policy| policy.retention_class == "custom_short")
            .unwrap();
        assert_eq!(custom.min_duration_days, 20);
        assert_eq!(custom.max_duration_days, Some(40));
        assert_eq!(custom.legal_basis, "test_policy_v2");

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/retention")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&UpdateRetentionConfigRequest {
                    policies: vec![RetentionPolicyConfig {
                        retention_class: "custom_short".to_string(),
                        expiry_mode: RetentionExpiryMode::FixedDays,
                        min_duration_days: 20,
                        max_duration_days: Some(40),
                        legal_basis: "test_policy_v2".to_string(),
                        active: false,
                    }],
                })
                .unwrap(),
            ))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);

        let create_req = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreateBundleRequest {
                    capture: SealableCaptureInput::V10(sample_event_with_profile(
                        "system-config",
                        proof_layer_core::ActorRole::Provider,
                        sample_event_with_system("system-config").items,
                        Some("custom_short"),
                    )),
                    artefacts: vec![InlineArtefact {
                        name: "prompt.json".to_string(),
                        content_type: "application/json".to_string(),
                        data_base64: Base64::encode_string(br#"{"prompt":"inactive"}"#),
                    }],
                })
                .unwrap(),
            ))
            .unwrap();
        let create_res = app.oneshot(create_req).await.unwrap();
        assert_eq!(create_res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_timestamp_config_persists_and_is_returned_from_get_config() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let (tsa_certificate, _) = build_test_certificate();
        let tsa_certificate_pem = tsa_certificate.encode_pem();
        let expected_trust_anchor_pem = tsa_certificate_pem.trim().to_string();

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/timestamp")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TimestampConfig {
                    enabled: true,
                    provider: "RFC3161".to_string(),
                    url: "https://tsa.example.test".to_string(),
                    assurance: Some("Qualified".to_string()),
                    trust_anchor_pems: vec![tsa_certificate_pem],
                    crl_pems: vec![test_timestamp_crl_pem()],
                    ocsp_responder_urls: Vec::new(),
                    qualified_signer_pems: vec![expected_trust_anchor_pem.clone()],
                    policy_oids: vec!["1.2.3.4".to_string()],
                })
                .unwrap(),
            ))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(put_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: TimestampConfig = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            updated,
            TimestampConfig {
                enabled: true,
                provider: DEFAULT_TIMESTAMP_PROVIDER.to_string(),
                url: "https://tsa.example.test".to_string(),
                assurance: Some("qualified".to_string()),
                trust_anchor_pems: vec![expected_trust_anchor_pem],
                crl_pems: vec![test_timestamp_crl_pem().trim().to_string()],
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: vec![tsa_certificate.encode_pem().trim().to_string()],
                policy_oids: vec!["1.2.3.4".to_string()],
            }
        );

        let get_req = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(config.timestamp, updated);

        let audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("get_config")
        .fetch_one(&db)
        .await
        .unwrap();
        let audit: serde_json::Value = serde_json::from_str(&audit_details).unwrap();
        assert_eq!(
            audit
                .get("timestamp_provider")
                .and_then(serde_json::Value::as_str),
            Some(DEFAULT_TIMESTAMP_PROVIDER)
        );

        let update_audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("update_timestamp_config")
        .fetch_one(&db)
        .await
        .unwrap();
        let update_audit: serde_json::Value = serde_json::from_str(&update_audit_details).unwrap();
        assert_eq!(
            update_audit
                .get("enabled")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            update_audit
                .get("assurance")
                .and_then(serde_json::Value::as_str),
            Some("qualified")
        );
        assert_eq!(
            update_audit
                .get("policy_oid_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[tokio::test]
    async fn update_timestamp_config_rejects_qualified_without_trust_material() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/timestamp")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TimestampConfig {
                    enabled: true,
                    provider: "rfc3161".to_string(),
                    url: "https://tsa.example.test".to_string(),
                    assurance: Some("qualified".to_string()),
                    trust_anchor_pems: Vec::new(),
                    crl_pems: Vec::new(),
                    ocsp_responder_urls: Vec::new(),
                    qualified_signer_pems: Vec::new(),
                    policy_oids: Vec::new(),
                })
                .unwrap(),
            ))
            .unwrap();

        let put_res = app.oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(put_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            error
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap()
                .contains(
                    "qualified timestamp assurance requires at least one expected policy OID"
                )
        );
    }

    #[tokio::test]
    async fn update_transparency_config_persists_and_validates_provider_shape() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let bad_put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/transparency")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TransparencyConfig {
                    enabled: true,
                    provider: "none".to_string(),
                    url: None,
                    scitt_format: None,
                    log_public_key_pem: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let bad_put_res = app.clone().oneshot(bad_put_req).await.unwrap();
        assert_eq!(bad_put_res.status(), StatusCode::BAD_REQUEST);

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/transparency")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TransparencyConfig {
                    enabled: true,
                    provider: "Rekor".to_string(),
                    url: Some("https://rekor.example.test".to_string()),
                    scitt_format: None,
                    log_public_key_pem: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(put_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: TransparencyConfig = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            updated,
            TransparencyConfig {
                enabled: true,
                provider: "rekor".to_string(),
                url: Some("https://rekor.example.test".to_string()),
                scitt_format: None,
                log_public_key_pem: None,
            }
        );

        let get_req = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(config.transparency, updated);

        let update_audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("update_transparency_config")
        .fetch_one(&db)
        .await
        .unwrap();
        let update_audit: serde_json::Value = serde_json::from_str(&update_audit_details).unwrap();
        assert_eq!(
            update_audit
                .get("provider")
                .and_then(serde_json::Value::as_str),
            Some("rekor")
        );
    }

    #[tokio::test]
    async fn update_disclosure_config_persists_and_is_returned_from_get_config() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request_config = DisclosureConfig {
            policies: vec![
                DisclosurePolicyConfig {
                    name: "regulator_minimum".to_string(),
                    allowed_item_types: Vec::new(),
                    excluded_item_types: vec!["tool_call".to_string()],
                    allowed_obligation_refs: Vec::new(),
                    excluded_obligation_refs: Vec::new(),
                    include_artefact_metadata: false,
                    include_artefact_bytes: false,
                    artefact_names: Vec::new(),
                    redacted_fields_by_item_type: BTreeMap::new(),
                },
                DisclosurePolicyConfig {
                    name: "annex_iv_redacted".to_string(),
                    allowed_item_types: vec![
                        "technical_doc".to_string(),
                        "risk_assessment".to_string(),
                    ],
                    excluded_item_types: Vec::new(),
                    allowed_obligation_refs: vec!["art11_annex_iv".to_string()],
                    excluded_obligation_refs: Vec::new(),
                    include_artefact_metadata: true,
                    include_artefact_bytes: true,
                    artefact_names: vec!["doc.json".to_string()],
                    redacted_fields_by_item_type: BTreeMap::from([(
                        "risk_assessment".to_string(),
                        vec!["metadata".to_string()],
                    )]),
                },
            ],
        };

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/disclosure")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request_config).unwrap()))
            .unwrap();
        let put_res = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(put_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: DisclosureConfig = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated, request_config);

        let get_req = Request::builder()
            .method("GET")
            .uri("/v1/config")
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let config: VaultConfigResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(config.disclosure, updated);

        let update_audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("update_disclosure_config")
        .fetch_one(&db)
        .await
        .unwrap();
        let update_audit: serde_json::Value = serde_json::from_str(&update_audit_details).unwrap();
        assert_eq!(
            update_audit
                .get("policy_count")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
    }

    #[tokio::test]
    async fn list_disclosure_templates_returns_catalog_and_audits() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request = Request::builder()
            .method("GET")
            .uri("/v1/disclosure/templates")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let catalog: DisclosureTemplateCatalogResponse = serde_json::from_slice(&body).unwrap();

        assert!(
            catalog
                .templates
                .iter()
                .any(|template| template.profile == DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM)
        );
        assert!(
            catalog
                .redaction_groups
                .iter()
                .any(|group| group.name == "commitments")
        );

        let audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("list_disclosure_templates")
        .fetch_one(&db)
        .await
        .unwrap();
        let audit: serde_json::Value = serde_json::from_str(&audit_details).unwrap();
        assert_eq!(
            audit
                .get("template_count")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[tokio::test]
    async fn render_disclosure_template_supports_groups_and_explicit_redactions() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/disclosure/templates/render")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&DisclosureTemplateRenderRequest {
                    profile: DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW.to_string(),
                    name: Some("privacy_review_custom".to_string()),
                    redaction_groups: vec!["metadata".to_string()],
                    redacted_fields_by_item_type: BTreeMap::from([(
                        "risk_assessment".to_string(),
                        vec!["/metadata/internal_notes".to_string()],
                    )]),
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rendered: DisclosureTemplateResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(rendered.profile, DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW);
        assert_eq!(rendered.policy.name, "privacy_review_custom");
        assert!(
            rendered
                .policy
                .redacted_fields_by_item_type
                .get("risk_assessment")
                .unwrap()
                .contains(&"/metadata/internal_notes".to_string())
        );
        assert!(
            rendered
                .default_redaction_groups
                .contains(&"operational_metrics".to_string())
        );

        let audit_details: String = sqlx::query_scalar(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1",
        )
        .bind("render_disclosure_template")
        .fetch_one(&db)
        .await
        .unwrap();
        let audit: serde_json::Value = serde_json::from_str(&audit_details).unwrap();
        assert_eq!(
            audit.get("profile").and_then(serde_json::Value::as_str),
            Some(DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW)
        );
    }

    #[tokio::test]
    async fn preview_disclosure_supports_inline_policy_and_pack_type_filters() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-preview",
                    proof_layer_core::ActorRole::Provider,
                    vec![
                        EvidenceItem::TechnicalDoc(
                            proof_layer_core::schema::TechnicalDocEvidence {
                                document_ref: "annex-iv/system-card".to_string(),
                                section: Some("safety_controls".to_string()),
                                commitment: Some(
                                    "sha256:abababababababababababababababababababababababababababababababab"
                                        .to_string(),
                                ),
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
                        ),
                        EvidenceItem::RiskAssessment(
                            proof_layer_core::schema::RiskAssessmentEvidence {
                                risk_id: "risk-42".to_string(),
                                severity: "high".to_string(),
                                status: "open".to_string(),
                                summary: Some("preview policy".to_string()),
                                risk_description: None,
                                likelihood: None,
                                affected_groups: Vec::new(),
                                mitigation_measures: Vec::new(),
                                residual_risk_level: None,
                                risk_owner: None,
                                vulnerable_groups_considered: None,
                                test_results_summary: None,
                                metadata: serde_json::json!({"source":"preview"}),
                            },
                        ),
                    ],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "doc.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"doc":"preview"}"#),
                }],
            },
        )
        .await;

        let preview_req = Request::builder()
            .method("POST")
            .uri("/v1/disclosure/preview")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&DisclosurePreviewRequest {
                    bundle_id: created.bundle_id.clone(),
                    pack_type: Some("annex_iv".to_string()),
                    disclosure_policy: None,
                    policy: Some(DisclosurePolicyConfig {
                        name: "risk_only".to_string(),
                        allowed_item_types: Vec::new(),
                        excluded_item_types: Vec::new(),
                        allowed_obligation_refs: vec!["art9".to_string()],
                        excluded_obligation_refs: Vec::new(),
                        include_artefact_metadata: false,
                        include_artefact_bytes: false,
                        artefact_names: Vec::new(),
                        redacted_fields_by_item_type: BTreeMap::from([(
                            "risk_assessment".to_string(),
                            vec!["/metadata/source".to_string()],
                        )]),
                    }),
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let preview_res = app.clone().oneshot(preview_req).await.unwrap();
        assert_eq!(preview_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(preview_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let preview: DisclosurePreviewResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(preview.bundle_id, created.bundle_id);
        assert_eq!(preview.policy_name, "risk_only");
        assert_eq!(preview.pack_type.as_deref(), Some("annex_iv"));
        assert_eq!(preview.candidate_item_indices, vec![0, 1]);
        assert_eq!(preview.disclosed_item_indices, vec![1]);
        assert_eq!(preview.disclosed_item_types, vec!["risk_assessment"]);
        assert_eq!(preview.disclosed_item_obligation_refs, vec!["art9"]);
        assert_eq!(
            preview.disclosed_item_field_redactions,
            BTreeMap::from([(1usize, vec!["/metadata/source".to_string()])])
        );
        assert!(preview.disclosed_artefact_indices.is_empty());
        assert!(!preview.disclosed_artefact_bytes_included);
    }

    #[tokio::test]
    async fn preview_disclosure_supports_inline_template_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let created = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-preview-template",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-preview-template").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"template"}"#),
                }],
            },
        )
        .await;

        let preview_req = Request::builder()
            .method("POST")
            .uri("/v1/disclosure/preview")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&DisclosurePreviewRequest {
                    bundle_id: created.bundle_id.clone(),
                    pack_type: Some("runtime_logs".to_string()),
                    disclosure_policy: None,
                    policy: None,
                    disclosure_template: Some(DisclosureTemplateRenderRequest {
                        profile: DEFAULT_DISCLOSURE_POLICY_RUNTIME_MINIMUM.to_string(),
                        name: Some("runtime_minimum_template".to_string()),
                        redaction_groups: vec!["metadata".to_string()],
                        redacted_fields_by_item_type: BTreeMap::new(),
                    }),
                })
                .unwrap(),
            ))
            .unwrap();
        let preview_res = app.clone().oneshot(preview_req).await.unwrap();
        assert_eq!(preview_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(preview_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let preview: DisclosurePreviewResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(preview.policy_name, "runtime_minimum_template");
        assert_eq!(preview.disclosed_item_types, vec!["llm_interaction"]);
        assert_eq!(
            preview.disclosed_item_field_redactions,
            BTreeMap::from([(
                0usize,
                vec![
                    "input_commitment".to_string(),
                    "output_commitment".to_string(),
                    "trace_commitment".to_string(),
                    "/parameters".to_string(),
                    "/trace_semconv_version".to_string(),
                ]
            )])
        );
    }

    #[tokio::test]
    async fn create_pack_with_privacy_review_template_skips_missing_optional_redactions() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let llm_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-privacy-pack",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-privacy-pack").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"privacy"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-privacy-pack".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: None,
                    disclosure_template: Some(DisclosureTemplateRenderRequest {
                        profile: DEFAULT_DISCLOSURE_POLICY_PRIVACY_REVIEW.to_string(),
                        name: Some("privacy_review_pack".to_string()),
                        redaction_groups: Vec::new(),
                        redacted_fields_by_item_type: BTreeMap::new(),
                    }),
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_ids, vec![llm_bundle.bundle_id.clone()]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        let selectors = manifest.bundles[0]
            .disclosed_item_field_redactions
            .get(&0usize)
            .cloned()
            .unwrap_or_default();
        assert!(!selectors.contains(&"retrieval_commitment".to_string()));
        assert!(!selectors.contains(&"tool_outputs_commitment".to_string()));
        assert!(!selectors.contains(&"/token_usage".to_string()));
        assert!(selectors.contains(&"input_commitment".to_string()));
        assert!(selectors.contains(&"output_commitment".to_string()));

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                    bundle_pkg_base64: archive.files[0].data_base64.clone(),
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.valid);
    }

    #[tokio::test]
    async fn create_pack_applies_runtime_log_curation_and_exports_verifiable_bundle_packages() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let llm_items = sample_event_with_system("system-a").items;
        let llm_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Provider,
                    llm_items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::TechnicalDoc(
                        proof_layer_core::schema::TechnicalDocEvidence {
                            document_ref: "doc-1".to_string(),
                            section: Some("accuracy".to_string()),
                            commitment: Some(
                                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                    .to_string(),
                            ),
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
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "doc.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"doc":"annex iv"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Deployer,
                    vec![EvidenceItem::RiskAssessment(
                        proof_layer_core::schema::RiskAssessmentEvidence {
                            risk_id: "risk-1".to_string(),
                            severity: "high".to_string(),
                            status: "open".to_string(),
                            summary: Some("runtime incident".to_string()),
                            risk_description: None,
                            likelihood: None,
                            affected_groups: Vec::new(),
                            mitigation_measures: Vec::new(),
                            residual_risk_level: None,
                            risk_owner: None,
                            vulnerable_groups_considered: None,
                            test_results_summary: None,
                            metadata: serde_json::json!({"source":"monitoring"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "risk.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"risk":"open"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-b",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-b").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"other-system"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-a".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.pack_type, "runtime_logs");
        assert_eq!(pack.bundle_format, PACK_BUNDLE_FORMAT_FULL);
        assert_eq!(pack.bundle_count, 1);
        assert_eq!(pack.bundle_ids.len(), 1);

        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let get_res = app.clone().oneshot(get_req).await.unwrap();
        assert_eq!(get_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let fetched_pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched_pack.bundle_ids, pack.bundle_ids);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(manifest.bundle_ids, pack.bundle_ids);
        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.curation_profile, PACK_CURATION_PROFILE);
        assert_eq!(manifest.bundle_format, PACK_BUNDLE_FORMAT_FULL);
        assert_eq!(manifest.bundles[0].system_id.as_deref(), Some("system-a"));
        assert_eq!(manifest.bundles[0].bundle_format, PACK_BUNDLE_FORMAT_FULL);
        let expected_package_name = format!("bundles/{}.pkg", pack.bundle_ids[0]);
        assert_eq!(
            manifest.bundles[0].package_name.as_deref(),
            Some(expected_package_name.as_str())
        );
        assert_eq!(manifest.bundles[0].item_types, vec!["llm_interaction"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art12_19_26"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"retention_class:runtime_logs".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:llm_interaction".to_string())
        );

        let obligation_ref: Option<String> = sqlx::query_scalar(
            "SELECT obligation_ref
             FROM evidence_items
             WHERE bundle_id = ?
             ORDER BY item_index
             LIMIT 1",
        )
        .bind(&llm_bundle.bundle_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(obligation_ref.as_deref(), Some("art12_19_26"));

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);
        assert_eq!(archive.format, PACK_EXPORT_FORMAT);
        assert_eq!(archive.manifest.bundle_ids, pack.bundle_ids);
        assert_eq!(archive.files.len(), 1);
        assert_eq!(
            archive.files[0].name,
            format!("bundles/{}.pkg", pack.bundle_ids[0])
        );

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                    bundle_pkg_base64: archive.files[0].data_base64.clone(),
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.valid);
        assert_eq!(verify_response.artefacts_verified, 1);
    }

    #[tokio::test]
    async fn create_pack_supports_disclosure_bundle_format_and_exports_verifiable_redacted_packages()
     {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let llm_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-a",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-a").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-a".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_ids, vec![llm_bundle.bundle_id.clone()]);
        assert_eq!(pack.bundle_format, PACK_BUNDLE_FORMAT_DISCLOSURE);
        assert_eq!(
            pack.disclosure_policy.as_deref(),
            Some(DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(manifest.bundle_format, PACK_BUNDLE_FORMAT_DISCLOSURE);
        assert_eq!(
            manifest.disclosure_policy.as_deref(),
            Some(DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM)
        );
        assert_eq!(manifest.bundles.len(), 1);
        let expected_package_name = format!("bundles/{}.disclosure.pkg", llm_bundle.bundle_id);
        assert_eq!(
            manifest.bundles[0].package_name.as_deref(),
            Some(expected_package_name.as_str())
        );
        assert_eq!(
            manifest.bundles[0].bundle_format,
            PACK_BUNDLE_FORMAT_DISCLOSURE
        );
        assert_eq!(manifest.bundles[0].disclosed_item_indices, vec![0]);
        assert_eq!(
            manifest.bundles[0].disclosed_item_types,
            vec!["llm_interaction"]
        );

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);
        assert_eq!(archive.format, PACK_EXPORT_FORMAT);
        assert_eq!(
            archive.manifest.bundle_format,
            PACK_BUNDLE_FORMAT_DISCLOSURE
        );
        assert_eq!(archive.files.len(), 1);
        assert_eq!(
            archive.files[0].name,
            format!("bundles/{}.disclosure.pkg", llm_bundle.bundle_id)
        );

        let disclosure_package =
            Base64::decode_vec(&archive.files[0].data_base64).expect("base64 disclosure package");
        let decoded =
            read_package_from_bytes(&disclosure_package, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
        assert_eq!(decoded.format, DISCLOSURE_PACKAGE_FORMAT);
        let redacted = parse_redacted_bundle_file(&decoded.files).unwrap();
        assert_eq!(redacted.bundle_id, llm_bundle.bundle_id);
        assert_eq!(redacted.disclosed_items.len(), 1);
        assert!(redacted.disclosed_artefacts.is_empty());

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                    bundle_pkg_base64: archive.files[0].data_base64.clone(),
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.valid);
        assert_eq!(verify_response.artefacts_verified, 0);
    }

    #[tokio::test]
    async fn create_pack_applies_named_disclosure_policy_with_artefact_metadata_only_by_default() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let technical_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-docs",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::TechnicalDoc(
                        proof_layer_core::schema::TechnicalDocEvidence {
                            document_ref: "annex-iv/system-card".to_string(),
                            section: Some("safety_controls".to_string()),
                            commitment: Some(
                                "sha256:abababababababababababababababababababababababababababababababab"
                                    .to_string(),
                            ),
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
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![
                    InlineArtefact {
                        name: "doc.json".to_string(),
                        content_type: "application/json".to_string(),
                        data_base64: Base64::encode_string(br#"{"doc":"system-card"}"#),
                    },
                    InlineArtefact {
                        name: "diagram.txt".to_string(),
                        content_type: "text/plain".to_string(),
                        data_base64: Base64::encode_string(b"annex-iv-diagram"),
                    },
                ],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-docs".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: Some(
                        DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED.to_string(),
                    ),
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            pack.disclosure_policy.as_deref(),
            Some(DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            manifest.disclosure_policy.as_deref(),
            Some(DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED)
        );
        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(
            manifest.bundles[0].disclosed_artefact_names,
            vec!["doc.json".to_string(), "diagram.txt".to_string()]
        );
        assert!(!manifest.bundles[0].disclosed_artefact_bytes_included);

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);
        let disclosure_package =
            Base64::decode_vec(&archive.files[0].data_base64).expect("base64 disclosure package");
        let decoded =
            read_package_from_bytes(&disclosure_package, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
        let redacted = parse_redacted_bundle_file(&decoded.files).unwrap();
        assert_eq!(redacted.bundle_id, technical_bundle.bundle_id);
        assert_eq!(redacted.disclosed_items.len(), 1);
        assert_eq!(redacted.disclosed_artefacts.len(), 2);
        assert_eq!(redacted.disclosed_artefacts[0].meta.name, "doc.json");
        assert_eq!(redacted.disclosed_artefacts[1].meta.name, "diagram.txt");
        assert!(!decoded.files.contains_key("artefacts/doc.json"));
        assert!(!decoded.files.contains_key("artefacts/diagram.txt"));

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                    bundle_pkg_base64: archive.files[0].data_base64.clone(),
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.valid);
        assert_eq!(verify_response.artefacts_verified, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_bundle_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_annex_iv_scenario(&app).await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: Some(scenario.technical_doc.bundle_id.clone()),
                    pack_id: None,
                    bundle: None,
                    profile: CompletenessProfile::AnnexIvGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::AnnexIvGovernanceV1);
        assert_eq!(report.bundle_id, scenario.technical_doc.bundle_id);
        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report.fail_count > 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_annex_iv_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::AnnexIvGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::AnnexIvGovernanceV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_gpai_provider_bundle_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_gpai_provider_scenario(&app).await;

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: Some(scenario.compute_metrics.bundle_id.clone()),
                    pack_id: None,
                    bundle: None,
                    profile: CompletenessProfile::GpaiProviderV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::GpaiProviderV1);
        assert_eq!(report.bundle_id, scenario.compute_metrics.bundle_id);
        assert_eq!(report.status, CompletenessStatus::Fail);
        assert!(report.fail_count > 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_gpai_provider_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_gpai_provider_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::GpaiProviderV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::GpaiProviderV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_post_market_monitoring_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_post_market_monitoring_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::PostMarketMonitoringV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::PostMarketMonitoringV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 6);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_provider_governance_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_provider_governance_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::ProviderGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::ProviderGovernanceV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 8);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_conformity_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_conformity_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::ConformityV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::ConformityV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 3);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_incident_response_inline_bundle_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_incident_response_bundle();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: None,
                    bundle: Some(bundle),
                    profile: CompletenessProfile::IncidentResponseV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::IncidentResponseV1);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 10);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_rejects_invalid_selection_combinations() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let bundle = fixture_annex_iv_bundle();

        for payload in [
            EvaluateCompletenessRequest {
                bundle_id: None,
                pack_id: None,
                bundle: None,
                profile: CompletenessProfile::AnnexIvGovernanceV1,
            },
            EvaluateCompletenessRequest {
                bundle_id: Some("bundle-123".to_string()),
                pack_id: None,
                bundle: Some(bundle.clone()),
                profile: CompletenessProfile::AnnexIvGovernanceV1,
            },
            EvaluateCompletenessRequest {
                bundle_id: Some("bundle-123".to_string()),
                pack_id: Some("pack-123".to_string()),
                bundle: None,
                profile: CompletenessProfile::AnnexIvGovernanceV1,
            },
            EvaluateCompletenessRequest {
                bundle_id: None,
                pack_id: Some("pack-123".to_string()),
                bundle: Some(bundle.clone()),
                profile: CompletenessProfile::AnnexIvGovernanceV1,
            },
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/v1/completeness/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                error["error"],
                "provide exactly one of bundle_id, bundle, or pack_id"
            );
        }
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_gpai_provider_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("foundation-model-alpha".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::GpaiProviderV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::GpaiProviderV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 6);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_annex_iv_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::AnnexIvGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::AnnexIvGovernanceV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 8);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_post_market_monitoring_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_post_market_monitoring_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "post_market_monitoring".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("claims-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::PostMarketMonitoringV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::PostMarketMonitoringV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 6);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_incident_response_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_incident_response_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "incident_response".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("benefits-review".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::IncidentResponseV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::IncidentResponseV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 10);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_provider_governance_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_provider_governance_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "provider_governance".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::ProviderGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::ProviderGovernanceV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 8);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_supports_conformity_pack_id_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_conformity_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "conformity".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-conformity".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id.clone()),
                    bundle: None,
                    profile: CompletenessProfile::ConformityV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: proof_layer_core::CompletenessReport = serde_json::from_slice(&body).unwrap();

        assert_eq!(report.profile, CompletenessProfile::ConformityV1);
        assert_eq!(report.bundle_id, pack.pack_id);
        assert_eq!(report.status, CompletenessStatus::Pass);
        assert_eq!(report.pass_count, 3);
        assert_eq!(report.warn_count, 0);
        assert_eq!(report.fail_count, 0);
    }

    #[tokio::test]
    async fn evaluate_completeness_api_rejects_pack_profile_mismatch() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_gpai_provider_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("foundation-model-alpha".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id),
                    bundle: None,
                    profile: CompletenessProfile::AnnexIvGovernanceV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["error"],
            "requested profile does not match pack completeness profile"
        );
    }

    #[tokio::test]
    async fn evaluate_completeness_api_rejects_pack_without_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id),
                    bundle: None,
                    profile: CompletenessProfile::GpaiProviderV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["error"],
            "pack does not have pack-scoped completeness"
        );
    }

    #[tokio::test]
    async fn evaluate_completeness_api_rejects_missing_pack_completeness_report() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_gpai_provider_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("foundation-model-alpha".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        sqlx::query("UPDATE packs SET pack_completeness_report_json = NULL WHERE pack_id = ?")
            .bind(&pack.pack_id)
            .execute(&db)
            .await
            .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/v1/completeness/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EvaluateCompletenessRequest {
                    bundle_id: None,
                    pack_id: Some(pack.pack_id),
                    bundle: None,
                    profile: CompletenessProfile::GpaiProviderV1,
                })
                .unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            error["error"],
            "pack-scoped completeness report unavailable for this pack; recreate the pack"
        );
    }

    #[tokio::test]
    async fn annex_iv_pack_curates_expected_governance_bundle_set() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::AnnexIvGovernanceV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::AnnexIvGovernanceV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(8));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));

        let expected_bundle_ids = BTreeSet::from([
            scenario.technical_doc.bundle_id.clone(),
            scenario.risk_assessment.bundle_id.clone(),
            scenario.data_governance.bundle_id.clone(),
            scenario.instructions_for_use.bundle_id.clone(),
            scenario.human_oversight.bundle_id.clone(),
            scenario.qms_record.bundle_id.clone(),
            scenario.standards_alignment.bundle_id.clone(),
            scenario.post_market_monitoring.bundle_id.clone(),
        ]);
        let actual_bundle_ids = pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>();

        assert_eq!(actual_bundle_ids, expected_bundle_ids);
        assert!(!pack.bundle_ids.contains(&scenario.runtime_logs.bundle_id));
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_risk.bundle_id)
        );
    }

    #[tokio::test]
    async fn create_pack_can_target_explicit_bundle_ids_without_sweeping_same_system_history() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_annex_iv_scenario(&app).await;
        let extra_same_system_bundle = create_annex_iv_governance_bundle(
            &app,
            EvidenceItem::RiskAssessment(proof_layer_core::schema::RiskAssessmentEvidence {
                risk_id: "risk-historical".to_string(),
                severity: "medium".to_string(),
                status: "open".to_string(),
                summary: Some(
                    "Older same-system risk bundle that should stay out of this export".to_string(),
                ),
                risk_description: None,
                likelihood: None,
                affected_groups: Vec::new(),
                mitigation_measures: Vec::new(),
                residual_risk_level: None,
                risk_owner: None,
                vulnerable_groups_considered: None,
                test_results_summary: None,
                metadata: serde_json::json!({
                    "source": "historical-run",
                }),
            }),
            "risk_mgmt",
            "req-historical-risk",
            "historical-risk.json",
            br#"{"risk":"historical"}"#,
        )
        .await;
        let selected_bundle_ids = vec![
            scenario.technical_doc.bundle_id.clone(),
            scenario.risk_assessment.bundle_id.clone(),
            scenario.data_governance.bundle_id.clone(),
            scenario.instructions_for_use.bundle_id.clone(),
            scenario.human_oversight.bundle_id.clone(),
            scenario.qms_record.bundle_id.clone(),
            scenario.standards_alignment.bundle_id.clone(),
            scenario.post_market_monitoring.bundle_id.clone(),
        ];

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: selected_bundle_ids.clone(),
                    system_id: None,
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            selected_bundle_ids.into_iter().collect::<BTreeSet<_>>()
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&extra_same_system_bundle.bundle_id)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
    }

    #[tokio::test]
    async fn annex_iv_pack_manifest_records_expected_match_metadata() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::AnnexIvGovernanceV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(8));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::AnnexIvGovernanceV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(8));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));

        let technical_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == scenario.technical_doc.bundle_id)
            .unwrap();
        assert_eq!(technical_entry.actor_role, "provider");
        assert_eq!(
            technical_entry.system_id.as_deref(),
            Some("hiring-assistant")
        );
        assert_eq!(technical_entry.item_types, vec!["technical_doc"]);
        assert_eq!(technical_entry.obligation_refs, vec!["art11_annex_iv"]);
        assert!(
            technical_entry
                .matched_rules
                .contains(&"pack_type:annex_iv".to_string())
        );
        assert!(
            technical_entry
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            technical_entry
                .matched_rules
                .contains(&"item_type:technical_doc".to_string())
        );
        assert!(
            technical_entry
                .matched_rules
                .contains(&"obligation_ref:art11_annex_iv".to_string())
        );
        assert_eq!(
            technical_entry.completeness_status,
            Some(CompletenessStatus::Fail)
        );

        let expected_refs = BTreeMap::from([
            (
                scenario.risk_assessment.bundle_id.clone(),
                "art9".to_string(),
            ),
            (
                scenario.data_governance.bundle_id.clone(),
                "art10".to_string(),
            ),
            (
                scenario.instructions_for_use.bundle_id.clone(),
                "art13".to_string(),
            ),
            (
                scenario.human_oversight.bundle_id.clone(),
                "art14".to_string(),
            ),
            (scenario.qms_record.bundle_id.clone(), "art17".to_string()),
            (
                scenario.standards_alignment.bundle_id.clone(),
                "art40_43".to_string(),
            ),
            (
                scenario.post_market_monitoring.bundle_id.clone(),
                "art72".to_string(),
            ),
        ]);

        for entry in &manifest.bundles {
            assert_eq!(entry.actor_role, "provider");
            assert_eq!(entry.system_id.as_deref(), Some("hiring-assistant"));
            assert_eq!(entry.completeness_status, Some(CompletenessStatus::Fail));
            if let Some(expected_ref) = expected_refs.get(&entry.bundle_id) {
                assert_eq!(entry.obligation_refs, vec![expected_ref.clone()]);
                assert!(
                    entry
                        .matched_rules
                        .contains(&format!("obligation_ref:{expected_ref}"))
                );
            }
        }
    }

    #[tokio::test]
    async fn annex_iv_disclosure_pack_verifies_and_preserves_redactions() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: Some(
                        DEFAULT_DISCLOSURE_POLICY_ANNEX_IV_REDACTED.to_string(),
                    ),
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_ids.len(), 8);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        let risk_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == scenario.risk_assessment.bundle_id)
            .unwrap();
        assert_eq!(
            risk_entry.disclosed_item_field_redactions,
            BTreeMap::from([(0usize, vec!["/metadata".to_string()])])
        );

        let data_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == scenario.data_governance.bundle_id)
            .unwrap();
        assert_eq!(
            data_entry.disclosed_item_field_redactions,
            BTreeMap::from([(
                0usize,
                vec![
                    "/metadata".to_string(),
                    "/personal_data_categories".to_string(),
                    "/safeguards".to_string(),
                ],
            )])
        );

        let ifu_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == scenario.instructions_for_use.bundle_id)
            .unwrap();
        assert_eq!(
            ifu_entry.disclosed_item_field_redactions,
            BTreeMap::from([(0usize, vec!["/metadata".to_string()])])
        );

        for entry in &manifest.bundles {
            assert!(!entry.disclosed_artefact_bytes_included);
        }

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);
        assert_eq!(archive.files.len(), 8);

        let mut seen_bundle_ids = BTreeSet::new();
        for packaged in &archive.files {
            let verify_req = Request::builder()
                .method("POST")
                .uri("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                        bundle_pkg_base64: packaged.data_base64.clone(),
                        public_key_pem: public_key_pem.clone(),
                    })))
                    .unwrap(),
                ))
                .unwrap();
            let verify_res = app.clone().oneshot(verify_req).await.unwrap();
            assert_eq!(verify_res.status(), StatusCode::OK);
            let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
                .await
                .unwrap();
            let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
            assert!(verify_response.valid);
            assert_eq!(verify_response.artefacts_verified, 0);

            let disclosure_package = Base64::decode_vec(&packaged.data_base64).unwrap();
            let decoded =
                read_package_from_bytes(&disclosure_package, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
            let redacted = parse_redacted_bundle_file(&decoded.files).unwrap();
            seen_bundle_ids.insert(redacted.bundle_id.clone());
            assert!(
                !decoded
                    .files
                    .keys()
                    .any(|name| name.starts_with("artefacts/"))
            );

            if redacted.bundle_id == scenario.risk_assessment.bundle_id {
                assert_eq!(
                    redacted.disclosed_items[0]
                        .field_redacted_item
                        .as_ref()
                        .unwrap()
                        .redacted_paths,
                    vec!["/metadata/internal_notes".to_string()]
                );
            }
            if redacted.bundle_id == scenario.data_governance.bundle_id {
                assert_eq!(
                    redacted.disclosed_items[0]
                        .field_redacted_item
                        .as_ref()
                        .unwrap()
                        .redacted_paths,
                    vec![
                        "/metadata/owner".to_string(),
                        "/personal_data_categories/0".to_string(),
                        "/personal_data_categories/1".to_string(),
                        "/safeguards/0".to_string(),
                        "/safeguards/1".to_string(),
                    ]
                );
            }
            if redacted.bundle_id == scenario.instructions_for_use.bundle_id {
                assert_eq!(
                    redacted.disclosed_items[0]
                        .field_redacted_item
                        .as_ref()
                        .unwrap()
                        .redacted_paths,
                    vec!["/metadata/distribution".to_string()]
                );
            }
        }

        assert_eq!(
            seen_bundle_ids,
            pack.bundle_ids.into_iter().collect::<BTreeSet<_>>()
        );
    }

    #[tokio::test]
    async fn annex_iv_disclosure_pack_uses_full_bundle_inputs_for_pack_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::AnnexIvGovernanceV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(8));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
    }

    #[tokio::test]
    async fn annex_iv_pack_order_is_stable() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        create_annex_iv_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_iv".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        let ordered_item_types = manifest
            .bundles
            .iter()
            .map(|entry| entry.item_types[0].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ordered_item_types,
            vec![
                "technical_doc".to_string(),
                "risk_assessment".to_string(),
                "data_governance".to_string(),
                "instructions_for_use".to_string(),
                "human_oversight".to_string(),
                "qms_record".to_string(),
                "standards_alignment".to_string(),
                "post_market_monitoring".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn create_pack_supports_inline_disclosure_template_requests() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let llm_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-template-pack",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-template-pack").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-template-pack".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: None,
                    disclosure_template: Some(DisclosureTemplateRenderRequest {
                        profile: DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM.to_string(),
                        name: Some("regulator_template_pack".to_string()),
                        redaction_groups: Vec::new(),
                        redacted_fields_by_item_type: BTreeMap::new(),
                    }),
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_ids, vec![llm_bundle.bundle_id.clone()]);
        assert_eq!(
            pack.disclosure_policy.as_deref(),
            Some("regulator_template_pack")
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            manifest.disclosure_policy.as_deref(),
            Some("regulator_template_pack")
        );
        assert!(
            manifest.bundles[0]
                .disclosed_item_field_redactions
                .is_empty()
        );
    }

    #[tokio::test]
    async fn create_pack_applies_named_disclosure_policy_with_field_redactions() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let public_key_pem = encode_public_key_pem(&state.signing_key.verifying_key());
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let update_config = DisclosureConfig {
            policies: vec![
                DisclosurePolicyConfig {
                    name: "runtime_minimum".to_string(),
                    allowed_item_types: vec!["llm_interaction".to_string()],
                    excluded_item_types: Vec::new(),
                    allowed_obligation_refs: Vec::new(),
                    excluded_obligation_refs: Vec::new(),
                    include_artefact_metadata: false,
                    include_artefact_bytes: false,
                    artefact_names: Vec::new(),
                    redacted_fields_by_item_type: BTreeMap::from([(
                        "llm_interaction".to_string(),
                        vec!["output_commitment".to_string()],
                    )]),
                },
                DisclosurePolicyConfig {
                    name: DEFAULT_DISCLOSURE_POLICY_REGULATOR_MINIMUM.to_string(),
                    allowed_item_types: Vec::new(),
                    excluded_item_types: Vec::new(),
                    allowed_obligation_refs: Vec::new(),
                    excluded_obligation_refs: Vec::new(),
                    include_artefact_metadata: false,
                    include_artefact_bytes: false,
                    artefact_names: Vec::new(),
                    redacted_fields_by_item_type: BTreeMap::new(),
                },
            ],
        };
        let update_req = Request::builder()
            .method("PUT")
            .uri("/v1/config/disclosure")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&update_config).unwrap()))
            .unwrap();
        let update_res = app.clone().oneshot(update_req).await.unwrap();
        assert_eq!(update_res.status(), StatusCode::OK);

        let llm_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-redacted",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-redacted").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "runtime_logs".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-redacted".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: Some("runtime_minimum".to_string()),
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_ids, vec![llm_bundle.bundle_id.clone()]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            manifest.bundles[0].disclosed_item_field_redactions,
            BTreeMap::from([(0usize, vec!["output_commitment".to_string()])])
        );

        let export_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/export", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let export_res = app.clone().oneshot(export_req).await.unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let export_bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let archive = decode_pack_archive(&export_bytes);
        let disclosure_package =
            Base64::decode_vec(&archive.files[0].data_base64).expect("base64 disclosure package");
        let decoded =
            read_package_from_bytes(&disclosure_package, DEFAULT_MAX_PAYLOAD_BYTES).unwrap();
        let redacted = parse_redacted_bundle_file(&decoded.files).unwrap();
        assert!(redacted.disclosed_items[0].item.is_none());
        assert_eq!(
            redacted.disclosed_items[0]
                .field_redacted_item
                .as_ref()
                .unwrap()
                .redacted_paths,
            vec!["/output_commitment".to_string()]
        );

        let verify_req = Request::builder()
            .method("POST")
            .uri("/v1/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&VerifyRequest::Package(Box::new(PackageVerifyRequest {
                    bundle_pkg_base64: archive.files[0].data_base64.clone(),
                    public_key_pem,
                })))
                .unwrap(),
            ))
            .unwrap();
        let verify_res = app.oneshot(verify_req).await.unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(verify_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_response: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(verify_response.valid);
    }

    #[tokio::test]
    async fn incident_response_pack_curates_incident_reports_and_indexes_obligation_ref() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let db = state.db.clone();
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let incident_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-incident",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::IncidentReport(
                        proof_layer_core::schema::IncidentReportEvidence {
                            incident_id: "inc-42".to_string(),
                            severity: "serious".to_string(),
                            status: "open".to_string(),
                            occurred_at: Some("2026-03-06T10:15:00Z".to_string()),
                            summary: Some("unsafe medical guidance surfaced in production".to_string()),
                            report_commitment: Some(
                                "sha256:abababababababababababababababababababababababababababababababab"
                                    .to_string(),
                            ),
                            detection_method: None,
                            root_cause_summary: None,
                            corrective_action_ref: None,
                            authority_notification_required: None,
                            authority_notification_status: None,
                            metadata: serde_json::json!({"reported_by": "runtime-monitor"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "incident.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(
                        br#"{"incident_id":"inc-42","summary":"unsafe medical guidance surfaced in production"}"#,
                    ),
                }],
            },
        )
        .await;

        let corrective_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-incident",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::CorrectiveAction(
                        proof_layer_core::schema::CorrectiveActionEvidence {
                            action_id: "ca-42".to_string(),
                            status: "in_progress".to_string(),
                            summary: Some("block unsafe prompt template and notify operators".to_string()),
                            due_at: Some("2026-03-08T12:00:00Z".to_string()),
                            record_commitment: Some(
                                "sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"owner": "safety-ops"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "corrective-action.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(
                        br#"{"action_id":"ca-42","status":"in_progress"}"#,
                    ),
                }],
            },
        )
        .await;

        let authority_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-incident",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::AuthorityNotification(
                        proof_layer_core::schema::AuthorityNotificationEvidence {
                            notification_id: "notif-42".to_string(),
                            authority: "eu_ai_office".to_string(),
                            status: "drafted".to_string(),
                            incident_id: Some("inc-42".to_string()),
                            due_at: Some("2026-03-08T12:00:00Z".to_string()),
                            report_commitment: Some(
                                "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"channel": "portal"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "authority-notification.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(
                        br#"{"notification_id":"notif-42","authority":"eu_ai_office"}"#,
                    ),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "incident_response".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-incident".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(pack.bundle_count, 3);
        assert!(pack.bundle_ids.contains(&incident_bundle.bundle_id));
        assert!(pack.bundle_ids.contains(&corrective_bundle.bundle_id));
        assert!(pack.bundle_ids.contains(&authority_bundle.bundle_id));

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.clone().oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 3);
        let incident_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == incident_bundle.bundle_id)
            .unwrap();
        let corrective_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == corrective_bundle.bundle_id)
            .unwrap();
        let authority_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == authority_bundle.bundle_id)
            .unwrap();
        assert_eq!(incident_entry.item_types, vec!["incident_report"]);
        assert_eq!(incident_entry.obligation_refs, vec!["art55_73"]);
        assert!(
            incident_entry
                .matched_rules
                .contains(&"item_type:incident_report".to_string())
        );
        assert!(
            incident_entry
                .matched_rules
                .contains(&"obligation_ref:art55_73".to_string())
        );
        assert_eq!(corrective_entry.item_types, vec!["corrective_action"]);
        assert_eq!(corrective_entry.obligation_refs, vec!["art20_73"]);
        assert!(
            corrective_entry
                .matched_rules
                .contains(&"item_type:corrective_action".to_string())
        );
        assert!(
            corrective_entry
                .matched_rules
                .contains(&"obligation_ref:art20_73".to_string())
        );
        assert_eq!(authority_entry.item_types, vec!["authority_notification"]);
        assert_eq!(authority_entry.obligation_refs, vec!["art73_notification"]);
        assert!(
            authority_entry
                .matched_rules
                .contains(&"item_type:authority_notification".to_string())
        );
        assert!(
            authority_entry
                .matched_rules
                .contains(&"obligation_ref:art73_notification".to_string())
        );

        let obligation_ref: Option<String> = sqlx::query_scalar(
            "SELECT obligation_ref
             FROM evidence_items
             WHERE bundle_id = ?
             ORDER BY item_index
             LIMIT 1",
        )
        .bind(&incident_bundle.bundle_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(obligation_ref.as_deref(), Some("art55_73"));

        let corrective_obligation_ref: Option<String> = sqlx::query_scalar(
            "SELECT obligation_ref
             FROM evidence_items
             WHERE bundle_id = ?
             ORDER BY item_index
             LIMIT 1",
        )
        .bind(&corrective_bundle.bundle_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(corrective_obligation_ref.as_deref(), Some("art20_73"));

        let authority_obligation_ref: Option<String> = sqlx::query_scalar(
            "SELECT obligation_ref
             FROM evidence_items
             WHERE bundle_id = ?
             ORDER BY item_index
             LIMIT 1",
        )
        .bind(&authority_bundle.bundle_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            authority_obligation_ref.as_deref(),
            Some("art73_notification")
        );
    }

    #[tokio::test]
    async fn post_market_monitoring_pack_curates_runtime_monitoring_and_reporting_evidence() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let runtime_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-monitoring",
                    proof_layer_core::ActorRole::Provider,
                    sample_event_with_system("system-monitoring").items,
                    Some("runtime_logs"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "prompt.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"prompt":"hello"}"#),
                }],
            },
        )
        .await;

        let monitoring_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-monitoring",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::PostMarketMonitoring(
                        proof_layer_core::schema::PostMarketMonitoringEvidence {
                            plan_id: "pmm-42".to_string(),
                            status: "active".to_string(),
                            summary: Some("weekly drift review with escalation thresholds".to_string()),
                            report_commitment: Some(
                                "sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"owner": "safety-ops"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "post-market-monitoring.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"plan_id":"pmm-42"}"#),
                }],
            },
        )
        .await;

        let authority_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-monitoring",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::AuthoritySubmission(
                        proof_layer_core::schema::AuthoritySubmissionEvidence {
                            submission_id: "sub-42".to_string(),
                            authority: "eu_ai_office".to_string(),
                            status: "submitted".to_string(),
                            channel: Some("portal".to_string()),
                            submitted_at: Some("2026-03-08T09:30:00Z".to_string()),
                            document_commitment: Some(
                                "sha256:f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"case": "inc-42"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "authority-submission.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"submission_id":"sub-42"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-other",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::PostMarketMonitoring(
                        proof_layer_core::schema::PostMarketMonitoringEvidence {
                            plan_id: "pmm-99".to_string(),
                            status: "active".to_string(),
                            summary: Some("unrelated system monitoring".to_string()),
                            report_commitment: Some(
                                "sha256:0101010101010101010101010101010101010101010101010101010101010101"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"owner": "other-team"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "other-monitoring.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"plan_id":"pmm-99"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "post_market_monitoring".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-monitoring".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 3);
        assert!(pack.bundle_ids.contains(&runtime_bundle.bundle_id));
        assert!(pack.bundle_ids.contains(&monitoring_bundle.bundle_id));
        assert!(pack.bundle_ids.contains(&authority_bundle.bundle_id));

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 3);
        let runtime_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == runtime_bundle.bundle_id)
            .unwrap();
        let monitoring_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == monitoring_bundle.bundle_id)
            .unwrap();
        let authority_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == authority_bundle.bundle_id)
            .unwrap();

        assert_eq!(runtime_entry.item_types, vec!["llm_interaction"]);
        assert_eq!(runtime_entry.obligation_refs, vec!["art12_19_26"]);
        assert!(
            runtime_entry
                .matched_rules
                .contains(&"retention_class:runtime_logs".to_string())
        );
        assert!(
            runtime_entry
                .matched_rules
                .contains(&"obligation_ref:art12_19_26".to_string())
        );

        assert_eq!(monitoring_entry.item_types, vec!["post_market_monitoring"]);
        assert_eq!(monitoring_entry.obligation_refs, vec!["art72"]);
        assert!(
            monitoring_entry
                .matched_rules
                .contains(&"item_type:post_market_monitoring".to_string())
        );
        assert!(
            monitoring_entry
                .matched_rules
                .contains(&"obligation_ref:art72".to_string())
        );

        assert_eq!(authority_entry.item_types, vec!["authority_submission"]);
        assert_eq!(authority_entry.obligation_refs, vec!["art73_submission"]);
        assert!(
            authority_entry
                .matched_rules
                .contains(&"item_type:authority_submission".to_string())
        );
        assert!(
            authority_entry
                .matched_rules
                .contains(&"obligation_ref:art73_submission".to_string())
        );
    }

    #[tokio::test]
    async fn annex_xi_pack_requires_provider_role_and_preserves_match_metadata() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let provider_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-z",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::TrainingProvenance(
                        proof_layer_core::schema::TrainingProvenanceEvidence {
                            dataset_ref: "dataset://foundation/pretrain-v3".to_string(),
                            stage: "pretraining".to_string(),
                            lineage_ref: Some("lineage://snapshot/provider".to_string()),
                            record_commitment: Some(
                                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                                    .to_string(),
                            ),
                            compute_metrics_ref: None,
                            training_dataset_summary: None,
                            consortium_context: None,
                            metadata: serde_json::json!({"source": "registry"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "provider-training-provenance.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"dataset":"provider"}"#),
                }],
            },
        )
        .await;

        let provider_copyright_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-z",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::CopyrightPolicy(
                        proof_layer_core::schema::CopyrightPolicyEvidence {
                            policy_ref: "copyright://policy/v1".to_string(),
                            status: "published".to_string(),
                            jurisdiction: Some("eu".to_string()),
                            commitment: Some(
                                "sha256:cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca"
                                    .to_string(),
                            ),
                            metadata: serde_json::json!({"scope": "training data intake"}),
                        },
                    )],
                    Some("gpai_documentation"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "provider-copyright-policy.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"policy":"provider"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-z",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::TrainingProvenance(
                        proof_layer_core::schema::TrainingProvenanceEvidence {
                            dataset_ref: "dataset://foundation/pretrain-v3".to_string(),
                            stage: "fine_tuning".to_string(),
                            lineage_ref: Some("lineage://snapshot/integrator".to_string()),
                            record_commitment: Some(
                                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                                    .to_string(),
                            ),
                            compute_metrics_ref: None,
                            training_dataset_summary: None,
                            consortium_context: None,
                            metadata: serde_json::json!({"source": "integrator-registry"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "integrator-training-provenance.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"dataset":"integrator"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-z".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 2);
        assert_eq!(
            pack.bundle_ids,
            vec![
                provider_bundle.bundle_id.clone(),
                provider_copyright_bundle.bundle_id.clone()
            ]
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 2);
        let training_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == provider_bundle.bundle_id)
            .unwrap();
        let copyright_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == provider_copyright_bundle.bundle_id)
            .unwrap();
        assert_eq!(training_entry.actor_role, "provider");
        assert_eq!(training_entry.item_types, vec!["training_provenance"]);
        assert_eq!(training_entry.obligation_refs, vec!["art53_annex_xi"]);
        assert!(
            training_entry
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            training_entry
                .matched_rules
                .contains(&"item_type:training_provenance".to_string())
        );
        assert!(
            training_entry
                .matched_rules
                .contains(&"obligation_ref:art53_annex_xi".to_string())
        );
        assert_eq!(copyright_entry.actor_role, "provider");
        assert_eq!(copyright_entry.item_types, vec!["copyright_policy"]);
        assert_eq!(copyright_entry.obligation_refs, vec!["art53_copyright"]);
        assert!(
            copyright_entry
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            copyright_entry
                .matched_rules
                .contains(&"item_type:copyright_policy".to_string())
        );
        assert!(
            copyright_entry
                .matched_rules
                .contains(&"obligation_ref:art53_copyright".to_string())
        );
    }

    #[tokio::test]
    async fn annex_xi_pack_attaches_gpai_provider_completeness_profile_and_excludes_other_systems()
    {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_gpai_provider_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("foundation-model-alpha".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::GpaiProviderV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::GpaiProviderV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(6));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(pack.bundle_count, 6);
        assert_eq!(
            pack.bundle_ids,
            vec![
                scenario.technical_doc.bundle_id.clone(),
                scenario.model_evaluation.bundle_id.clone(),
                scenario.training_provenance.bundle_id.clone(),
                scenario.compute_metrics.bundle_id.clone(),
                scenario.copyright_policy.bundle_id.clone(),
                scenario.training_summary.bundle_id.clone(),
            ]
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_bundle.bundle_id)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::GpaiProviderV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(6));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::GpaiProviderV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(6));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 6);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );

        let compute_entry = manifest
            .bundles
            .iter()
            .find(|entry| entry.bundle_id == scenario.compute_metrics.bundle_id)
            .unwrap();
        assert_eq!(compute_entry.item_types, vec!["compute_metrics"]);
        assert_eq!(
            compute_entry.obligation_refs,
            vec!["art51_compute_threshold"]
        );
        assert!(
            compute_entry
                .matched_rules
                .contains(&"pack_type:annex_xi".to_string())
        );
        assert!(
            compute_entry
                .matched_rules
                .contains(&"item_type:compute_metrics".to_string())
        );
        assert!(
            compute_entry
                .matched_rules
                .contains(&"obligation_ref:art51_compute_threshold".to_string())
        );
    }

    #[tokio::test]
    async fn annex_xi_disclosure_pack_uses_full_bundle_inputs_for_pack_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let _scenario = create_gpai_provider_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "annex_xi".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("foundation-model-alpha".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_DISCLOSURE.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::GpaiProviderV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(6));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
    }

    #[tokio::test]
    async fn fundamental_rights_pack_reports_bundle_and_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_fundamental_rights_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "fundamental_rights".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("benefits-review".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::FundamentalRightsV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::FundamentalRightsV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(2));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                scenario.assessment.bundle_id.clone(),
                scenario.human_oversight.bundle_id.clone(),
            ])
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::FundamentalRightsV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(2));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::FundamentalRightsV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(2));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 2);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );
    }

    #[tokio::test]
    async fn post_market_monitoring_pack_reports_bundle_and_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_post_market_monitoring_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "post_market_monitoring".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("claims-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::PostMarketMonitoringV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::PostMarketMonitoringV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(6));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                scenario.monitoring.bundle_id.clone(),
                scenario.incident_report.bundle_id.clone(),
                scenario.corrective_action.bundle_id.clone(),
                scenario.authority_notification.bundle_id.clone(),
                scenario.authority_submission.bundle_id.clone(),
                scenario.reporting_deadline.bundle_id.clone(),
                scenario.regulator_correspondence.bundle_id.clone(),
            ])
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_bundle.bundle_id)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::PostMarketMonitoringV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(7));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::PostMarketMonitoringV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(6));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 7);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );
    }

    #[tokio::test]
    async fn incident_response_pack_reports_bundle_and_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_incident_response_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "incident_response".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("benefits-review".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::IncidentResponseV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::IncidentResponseV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(10));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                scenario.technical_doc.bundle_id.clone(),
                scenario.risk_assessment.bundle_id.clone(),
                scenario.human_oversight.bundle_id.clone(),
                scenario.policy_decision.bundle_id.clone(),
                scenario.incident_report.bundle_id.clone(),
                scenario.corrective_action.bundle_id.clone(),
                scenario.authority_notification.bundle_id.clone(),
                scenario.authority_submission.bundle_id.clone(),
                scenario.reporting_deadline.bundle_id.clone(),
                scenario.regulator_correspondence.bundle_id.clone(),
            ])
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_bundle.bundle_id)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::IncidentResponseV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(10));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::IncidentResponseV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(10));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 10);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );
    }

    #[tokio::test]
    async fn provider_governance_pack_reports_bundle_and_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_provider_governance_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "provider_governance".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("hiring-assistant".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::ProviderGovernanceV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::ProviderGovernanceV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(8));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                scenario.technical_doc.bundle_id.clone(),
                scenario.risk_assessment.bundle_id.clone(),
                scenario.data_governance.bundle_id.clone(),
                scenario.instructions_for_use.bundle_id.clone(),
                scenario.qms_record.bundle_id.clone(),
                scenario.standards_alignment.bundle_id.clone(),
                scenario.post_market_monitoring.bundle_id.clone(),
                scenario.corrective_action.bundle_id.clone(),
            ])
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_risk.bundle_id)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::ProviderGovernanceV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(8));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::ProviderGovernanceV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(8));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 8);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );
    }

    #[tokio::test]
    async fn conformity_pack_reports_bundle_and_pack_scoped_completeness() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);
        let scenario = create_conformity_scenario(&app).await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "conformity".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-conformity".to_string()),
                    from: None,
                    to: None,
                    bundle_format: PACK_BUNDLE_FORMAT_FULL.to_string(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            pack.completeness_profile,
            Some(CompletenessProfile::ConformityV1)
        );
        assert_eq!(pack.completeness_status, Some(CompletenessStatus::Fail));
        assert_eq!(
            pack.pack_completeness_profile,
            Some(CompletenessProfile::ConformityV1)
        );
        assert_eq!(
            pack.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(pack.pack_completeness_pass_count, Some(3));
        assert_eq!(pack.pack_completeness_warn_count, Some(0));
        assert_eq!(pack.pack_completeness_fail_count, Some(0));
        assert_eq!(
            pack.bundle_ids.iter().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                scenario.conformity_assessment.bundle_id.clone(),
                scenario.declaration.bundle_id.clone(),
                scenario.registration.bundle_id.clone(),
            ])
        );
        assert!(
            !pack
                .bundle_ids
                .contains(&scenario.other_system_bundle.bundle_id)
        );

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            manifest.completeness_profile,
            Some(CompletenessProfile::ConformityV1)
        );
        assert_eq!(manifest.completeness_pass_count, Some(0));
        assert_eq!(manifest.completeness_warn_count, Some(0));
        assert_eq!(manifest.completeness_fail_count, Some(3));
        assert_eq!(
            manifest.pack_completeness_profile,
            Some(CompletenessProfile::ConformityV1)
        );
        assert_eq!(
            manifest.pack_completeness_status,
            Some(CompletenessStatus::Pass)
        );
        assert_eq!(manifest.pack_completeness_pass_count, Some(3));
        assert_eq!(manifest.pack_completeness_warn_count, Some(0));
        assert_eq!(manifest.pack_completeness_fail_count, Some(0));
        assert_eq!(manifest.bundles.len(), 3);
        assert!(
            manifest
                .bundles
                .iter()
                .all(|entry| entry.completeness_status == Some(CompletenessStatus::Fail))
        );
    }

    #[tokio::test]
    async fn provider_governance_pack_curates_qms_records_for_provider_role() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let provider_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-governance",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::QmsRecord(
                        proof_layer_core::schema::QmsRecordEvidence {
                            record_id: "qms-77".to_string(),
                            process: "release-approval".to_string(),
                            status: "approved".to_string(),
                            record_commitment: Some(
                                "sha256:dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada"
                                    .to_string(),
                            ),
                            policy_name: None,
                            revision: None,
                            effective_date: None,
                            expiry_date: None,
                            scope: None,
                            approval_commitment: None,
                            audit_results_summary: None,
                            continuous_improvement_actions: Vec::new(),
                            metadata: serde_json::json!({"owner": "quality"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "provider-qms-record.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"record":"provider"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-governance",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::QmsRecord(
                        proof_layer_core::schema::QmsRecordEvidence {
                            record_id: "qms-88".to_string(),
                            process: "release-approval".to_string(),
                            status: "approved".to_string(),
                            record_commitment: Some(
                                "sha256:edededededededededededededededededededededededededededededededed"
                                    .to_string(),
                            ),
                            policy_name: None,
                            revision: None,
                            effective_date: None,
                            expiry_date: None,
                            scope: None,
                            approval_commitment: None,
                            audit_results_summary: None,
                            continuous_improvement_actions: Vec::new(),
                            metadata: serde_json::json!({"owner": "partner-quality"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "integrator-qms-record.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"record":"integrator"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "provider_governance".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-governance".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 1);
        assert_eq!(pack.bundle_ids, vec![provider_bundle.bundle_id.clone()]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.bundles[0].actor_role, "provider");
        assert_eq!(manifest.bundles[0].item_types, vec!["qms_record"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art17"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"pack_type:provider_governance".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:qms_record".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art17".to_string())
        );
    }

    #[tokio::test]
    async fn fundamental_rights_pack_requires_deployer_role_and_fria_flag() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let mut deployer_fria_event = sample_event_with_profile(
            "system-fria",
            proof_layer_core::ActorRole::Deployer,
            vec![EvidenceItem::FundamentalRightsAssessment(
                proof_layer_core::schema::FundamentalRightsAssessmentEvidence {
                    assessment_id: "fria-77".to_string(),
                    status: "completed".to_string(),
                    scope: Some("public-sector benefit eligibility".to_string()),
                    report_commitment: Some(
                        "sha256:ababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcd"
                            .to_string(),
                    ),
                    legal_basis: None,
                    affected_rights: Vec::new(),
                    stakeholder_consultation_summary: None,
                    mitigation_plan_summary: None,
                    assessor: None,
                    metadata: serde_json::json!({"owner": "rights-review"}),
                },
            )],
            Some("technical_doc"),
        );
        deployer_fria_event.compliance_profile = Some(proof_layer_core::ComplianceProfile {
            intended_use: Some("Benefit eligibility screening".to_string()),
            risk_tier: Some("high_risk".to_string()),
            fria_required: Some(true),
            deployment_context: Some("public_sector".to_string()),
            ..proof_layer_core::ComplianceProfile::default()
        });

        let included_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(deployer_fria_event),
                artefacts: vec![InlineArtefact {
                    name: "fria-report.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"assessment":"included"}"#),
                }],
            },
        )
        .await;

        let mut deployer_non_fria_event = sample_event_with_profile(
            "system-fria",
            proof_layer_core::ActorRole::Deployer,
            vec![EvidenceItem::FundamentalRightsAssessment(
                proof_layer_core::schema::FundamentalRightsAssessmentEvidence {
                    assessment_id: "fria-88".to_string(),
                    status: "completed".to_string(),
                    scope: Some("employment support".to_string()),
                    report_commitment: Some(
                        "sha256:bcbcdcdcbcbcdcdcbcbcdcdcbcbcdcdcbcbcdcdcbcbcdcdcbcbcdcdcbcbcdcdc"
                            .to_string(),
                    ),
                    legal_basis: None,
                    affected_rights: Vec::new(),
                    stakeholder_consultation_summary: None,
                    mitigation_plan_summary: None,
                    assessor: None,
                    metadata: serde_json::json!({"owner": "rights-review"}),
                },
            )],
            Some("technical_doc"),
        );
        deployer_non_fria_event.compliance_profile = Some(proof_layer_core::ComplianceProfile {
            fria_required: Some(false),
            ..proof_layer_core::ComplianceProfile::default()
        });

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(deployer_non_fria_event),
                artefacts: vec![InlineArtefact {
                    name: "fria-report-excluded.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"assessment":"excluded"}"#),
                }],
            },
        )
        .await;

        let mut provider_fria_event = sample_event_with_profile(
            "system-fria",
            proof_layer_core::ActorRole::Provider,
            vec![EvidenceItem::FundamentalRightsAssessment(
                proof_layer_core::schema::FundamentalRightsAssessmentEvidence {
                    assessment_id: "fria-99".to_string(),
                    status: "completed".to_string(),
                    scope: Some("provider review".to_string()),
                    report_commitment: Some(
                        "sha256:cdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdababcdcdabab"
                            .to_string(),
                    ),
                    legal_basis: None,
                    affected_rights: Vec::new(),
                    stakeholder_consultation_summary: None,
                    mitigation_plan_summary: None,
                    assessor: None,
                    metadata: serde_json::json!({"owner": "provider-review"}),
                },
            )],
            Some("technical_doc"),
        );
        provider_fria_event.compliance_profile = Some(proof_layer_core::ComplianceProfile {
            fria_required: Some(true),
            ..proof_layer_core::ComplianceProfile::default()
        });

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(provider_fria_event),
                artefacts: vec![InlineArtefact {
                    name: "provider-fria-report.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"assessment":"provider"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "fundamental_rights".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-fria".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 1);
        assert_eq!(pack.bundle_ids, vec![included_bundle.bundle_id.clone()]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.bundles[0].actor_role, "deployer");
        assert_eq!(
            manifest.bundles[0].item_types,
            vec!["fundamental_rights_assessment"]
        );
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art27"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"pack_type:fundamental_rights".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"actor_role:deployer".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"compliance_profile.fria_required:true".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art27".to_string())
        );
    }

    #[tokio::test]
    async fn systemic_risk_pack_curates_adversarial_tests_for_provider_role() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let provider_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-risk",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::AdversarialTest(
                        proof_layer_core::schema::AdversarialTestEvidence {
                            test_id: "adv-77".to_string(),
                            focus: "prompt-injection".to_string(),
                            status: "open".to_string(),
                            finding_severity: Some("high".to_string()),
                            report_commitment: Some(
                                "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                                    .to_string(),
                            ),
                            threat_model: None,
                            test_methodology: None,
                            attack_classes: Vec::new(),
                            affected_components: Vec::new(),
                            metadata: serde_json::json!({"suite": "red-team"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "provider-adversarial-test.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"test":"provider"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-risk",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::AdversarialTest(
                        proof_layer_core::schema::AdversarialTestEvidence {
                            test_id: "adv-88".to_string(),
                            focus: "data-exfiltration".to_string(),
                            status: "open".to_string(),
                            finding_severity: Some("medium".to_string()),
                            report_commitment: Some(
                                "sha256:dededededededededededededededededededededededededededededededede"
                                    .to_string(),
                            ),
                            threat_model: None,
                            test_methodology: None,
                            attack_classes: Vec::new(),
                            affected_components: Vec::new(),
                            metadata: serde_json::json!({"suite": "partner-red-team"}),
                        },
                    )],
                    Some("risk_mgmt"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "integrator-adversarial-test.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"test":"integrator"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "systemic_risk".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-risk".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 1);
        assert_eq!(pack.bundle_ids, vec![provider_bundle.bundle_id]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.bundles[0].actor_role, "provider");
        assert_eq!(manifest.bundles[0].item_types, vec!["adversarial_test"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art55"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:adversarial_test".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art55".to_string())
        );
    }

    #[tokio::test]
    async fn conformity_pack_curates_provider_declarations() {
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
        let app = build_router(state, DEFAULT_MAX_PAYLOAD_BYTES);

        let provider_bundle = create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-conformity",
                    proof_layer_core::ActorRole::Provider,
                    vec![EvidenceItem::Declaration(
                        proof_layer_core::schema::DeclarationEvidence {
                            declaration_id: "decl-77".to_string(),
                            jurisdiction: "eu".to_string(),
                            status: "issued".to_string(),
                            document_commitment: Some(
                                "sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
                                    .to_string(),
                            ),
                            signatory: None,
                            document_version: None,
                            metadata: serde_json::json!({"annex": "v"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "provider-declaration.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"declaration":"provider"}"#),
                }],
            },
        )
        .await;

        create_bundle_response(
            &app,
            &CreateBundleRequest {
                capture: SealableCaptureInput::V10(sample_event_with_profile(
                    "system-conformity",
                    proof_layer_core::ActorRole::Integrator,
                    vec![EvidenceItem::Declaration(
                        proof_layer_core::schema::DeclarationEvidence {
                            declaration_id: "decl-78".to_string(),
                            jurisdiction: "eu".to_string(),
                            status: "issued".to_string(),
                            document_commitment: Some(
                                "sha256:f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"
                                    .to_string(),
                            ),
                            signatory: None,
                            document_version: None,
                            metadata: serde_json::json!({"annex": "v"}),
                        },
                    )],
                    Some("technical_doc"),
                )),
                artefacts: vec![InlineArtefact {
                    name: "integrator-declaration.json".to_string(),
                    content_type: "application/json".to_string(),
                    data_base64: Base64::encode_string(br#"{"declaration":"integrator"}"#),
                }],
            },
        )
        .await;

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "conformity".to_string(),
                    bundle_ids: Vec::new(),
                    system_id: Some("system-conformity".to_string()),
                    from: None,
                    to: None,
                    bundle_format: default_pack_bundle_format(),
                    disclosure_policy: None,
                    disclosure_template: None,
                })
                .unwrap(),
            ))
            .unwrap();
        let pack_res = app.clone().oneshot(pack_req).await.unwrap();
        assert_eq!(pack_res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(pack_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let pack: PackSummaryResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(pack.bundle_count, 1);
        assert_eq!(pack.bundle_ids, vec![provider_bundle.bundle_id]);

        let manifest_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/packs/{}/manifest", pack.pack_id))
            .body(Body::empty())
            .unwrap();
        let manifest_res = app.oneshot(manifest_req).await.unwrap();
        assert_eq!(manifest_res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(manifest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let manifest: PackManifest = serde_json::from_slice(&body).unwrap();

        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.bundles[0].actor_role, "provider");
        assert_eq!(manifest.bundles[0].item_types, vec!["declaration"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art47_annex_v"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:declaration".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art47_annex_v".to_string())
        );
    }
}
