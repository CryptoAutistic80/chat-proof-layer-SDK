use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use base64ct::{Base64, Encoding};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ArtefactInput, BuildBundleError, CaptureEvent, CaptureInput, EvidenceItem, ProofBundle,
    ReceiptVerification, RekorTransparencyProvider, Rfc3161HttpTimestampProvider,
    ScittTransparencyProvider, TimestampAssuranceProfile, TimestampToken, TimestampTrustPolicy,
    TimestampVerification, TransparencyReceipt, TransparencyTrustPolicy,
    anchor_bundle as anchor_bundle_receipt, build_bundle, canonicalize_value,
    decode_private_key_pem, decode_public_key_pem, sha256_prefixed, timestamp_digest,
    validate_bundle_integrity_fields, validate_timestamp_trust_policy,
    validate_transparency_trust_policy, verify_receipt, verify_receipt_with_policy,
    verify_timestamp, verify_timestamp_with_policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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
    time::Duration,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use ulid::Ulid;

const DEFAULT_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_RETENTION_GRACE_PERIOD_DAYS: i64 = 30;
const DEFAULT_RETENTION_SCAN_INTERVAL_HOURS: i64 = 24;
const DEFAULT_CONFIG_PATH: &str = "./vault.toml";
const PACKAGE_FORMAT: &str = "pl-bundle-pkg-v1";
const PACK_EXPORT_FORMAT: &str = "pl-evidence-pack-v1";
const PACK_EXPORT_FILE_NAME: &str = "evidence_pack.pkg";
const PACK_CURATION_PROFILE: &str = "pack-rules-v1";
const AUDIT_ACTOR_API: &str = "api";
const AUDIT_ACTOR_SYSTEM: &str = "system";
const SERVICE_CONFIG_KEY_TIMESTAMP: &str = "timestamp";
const SERVICE_CONFIG_KEY_TRANSPARENCY: &str = "transparency";
const DEFAULT_TIMESTAMP_PROVIDER: &str = "rfc3161";
const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";
const DEFAULT_TRANSPARENCY_PROVIDER: &str = "none";

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    addr: String,
    storage_dir: PathBuf,
    signing_key: Arc<SigningKey>,
    signing_kid: String,
    metadata_backend: String,
    blob_backend: String,
    max_payload_bytes: usize,
    retention_grace_period_days: i64,
    retention_scan_interval_hours: i64,
}

#[derive(Debug, Clone)]
struct VaultRuntimeConfig {
    addr: SocketAddr,
    storage_dir: PathBuf,
    db_path: PathBuf,
    signing_key_path: Option<PathBuf>,
    signing_kid: String,
    metadata_backend: String,
    blob_backend: String,
    max_payload_bytes: usize,
    retention_grace_period_days: i64,
    retention_scan_interval_hours: i64,
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
    signing: VaultSigningFileConfig,
    #[serde(default)]
    storage: VaultStorageFileConfig,
    #[serde(default)]
    timestamp: Option<VaultTimestampFileConfig>,
    #[serde(default)]
    transparency: Option<VaultTransparencyFileConfig>,
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
    log_public_key_pem: Option<String>,
    log_public_key_path: Option<String>,
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
    },
    Direct {
        bundle_root: String,
        receipt: TransparencyReceipt,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyTimestampResponse {
    valid: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<TimestampVerification>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifyReceiptResponse {
    valid: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<ReceiptVerification>,
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
    timestamp: TimestampConfig,
    transparency: TransparencyConfig,
    audit: AuditConfigView,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultServiceConfigView {
    addr: String,
    max_payload_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultSigningConfigView {
    key_id: String,
    algorithm: String,
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
    log_public_key_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditConfigView {
    enabled: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    obligation_refs: Vec<String>,
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
}

struct CuratedPackBundle {
    row: PackSourceBundleRow,
    bundle: ProofBundle,
    item_types: Vec<String>,
    obligation_refs: Vec<String>,
    matched_rules: Vec<String>,
}

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

    let db = open_sqlite_pool(&runtime_config.db_path).await?;
    initialize_sqlite_schema(&db).await?;
    seed_default_retention_policies(&db).await?;
    apply_runtime_config_to_db(&db, &runtime_config).await?;
    backfill_bundle_expiries(&db).await?;
    backfill_item_obligation_refs(&db).await?;

    let signing_key = load_signing_key(runtime_config.signing_key_path.as_deref())?;

    let state = AppState {
        db,
        addr: addr.to_string(),
        storage_dir,
        signing_key: Arc::new(signing_key),
        signing_kid: runtime_config.signing_kid.clone(),
        metadata_backend: runtime_config.metadata_backend.clone(),
        blob_backend: runtime_config.blob_backend.clone(),
        max_payload_bytes: runtime_config.max_payload_bytes,
        retention_grace_period_days: runtime_config.retention_grace_period_days,
        retention_scan_interval_hours: runtime_config.retention_scan_interval_hours,
    };

    maybe_spawn_retention_scan_task(state.clone());
    let app = build_router(state, runtime_config.max_payload_bytes);

    info!(
        "proof-service listening on {addr} using config source {}",
        runtime_config
            .config_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "env/defaults".to_string())
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState, max_payload_bytes: usize) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
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
        .route("/v1/systems", get(list_systems))
        .route("/v1/systems/{system_id}/summary", get(get_system_summary))
        .route("/v1/packs", post(create_pack))
        .route("/v1/packs/{pack_id}", get(get_pack))
        .route("/v1/packs/{pack_id}/manifest", get(get_pack_manifest))
        .route("/v1/packs/{pack_id}/export", get(get_pack_export))
        .route("/v1/retention/status", get(retention_status))
        .route("/v1/retention/scan", post(retention_scan))
        .route("/v1/verify", post(verify_bundle))
        .route("/v1/verify/timestamp", post(verify_timestamp_token))
        .route("/v1/verify/receipt", post(verify_transparency_receipt))
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

    let retention_policies = file_config
        .retention
        .policies
        .into_iter()
        .map(|policy| {
            validate_retention_policy_config(&policy)?;
            Ok(policy)
        })
        .collect::<Result<Vec<_>>>()?;

    let timestamp_config = resolve_timestamp_file_config(config_base_dir, file_config.timestamp)?;
    let transparency_config =
        resolve_transparency_file_config(config_base_dir, file_config.transparency)?;

    Ok(VaultRuntimeConfig {
        addr,
        storage_dir,
        db_path,
        signing_key_path,
        signing_kid,
        metadata_backend,
        blob_backend,
        max_payload_bytes,
        retention_grace_period_days,
        retention_scan_interval_hours,
        retention_policies,
        timestamp_config,
        transparency_config,
        config_path: config_path.map(FsPath::to_path_buf),
    })
}

fn validate_file_config_capabilities(file_config: &VaultFileConfig) -> Result<()> {
    if file_config.server.tls_cert.is_some() || file_config.server.tls_key.is_some() {
        bail!("server.tls_cert/server.tls_key are not implemented yet");
    }

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

async fn create_bundle(
    State(state): State<AppState>,
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

    let bundle_id = generate_bundle_id();
    let bundle = match request.capture {
        SealableCaptureInput::V10(capture) => build_bundle(
            capture,
            &artefacts,
            &state.signing_key,
            &state.signing_kid,
            &bundle_id,
            Utc::now(),
        ),
        SealableCaptureInput::Legacy(capture) => build_bundle(
            capture,
            &artefacts,
            &state.signing_key,
            &state.signing_kid,
            &bundle_id,
            Utc::now(),
        ),
    }
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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

async fn retention_status(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
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
        Some(AUDIT_ACTOR_API),
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

async fn list_systems(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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

async fn get_config(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let response = build_vault_config_response(&state)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "get_config",
        Some(AUDIT_ACTOR_API),
        None,
        None,
        serde_json::json!({
            "retention_policy_count": response.retention.policies.len(),
            "grace_period_days": response.retention.grace_period_days,
            "scan_interval_hours": response.retention.scan_interval_hours,
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
        Some(AUDIT_ACTOR_API),
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
    Json(request): Json<TimestampConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let config = validate_timestamp_config(request).map_err(ApiError::bad_request_anyhow)?;
    upsert_service_config(&state.db, SERVICE_CONFIG_KEY_TIMESTAMP, &config)
        .await
        .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "update_timestamp_config",
        Some(AUDIT_ACTOR_API),
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
    Json(request): Json<TransparencyConfig>,
) -> Result<impl IntoResponse, ApiError> {
    let config = validate_transparency_config(request).map_err(ApiError::bad_request_anyhow)?;
    upsert_service_config(&state.db, SERVICE_CONFIG_KEY_TRANSPARENCY, &config)
        .await
        .map_err(ApiError::internal_anyhow)?;

    append_audit_log(
        &state.db,
        "update_transparency_config",
        Some(AUDIT_ACTOR_API),
        None,
        None,
        serde_json::json!({
            "enabled": config.enabled,
            "provider": &config.provider,
            "url": &config.url,
            "has_log_public_key": config.log_public_key_pem.is_some(),
        }),
    )
    .await
    .map_err(ApiError::internal_anyhow)?;

    Ok((StatusCode::OK, Json(config)))
}

async fn delete_bundle(
    State(state): State<AppState>,
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
            let bundle_for_submission = bundle.clone();
            tokio::task::spawn_blocking(move || {
                let provider = ScittTransparencyProvider::with_label(url, provider_label);
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
    Json(request): Json<CreatePackRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let request = normalize_create_pack_request(request).map_err(ApiError::bad_request_anyhow)?;
    let profile = pack_profile(&request.pack_type).map_err(ApiError::bad_request_anyhow)?;
    let rows = query_pack_source_bundles(&state.db, &request)
        .await
        .map_err(ApiError::internal_anyhow)?;
    let curated_rows = curate_pack_bundles(&profile, rows).map_err(ApiError::internal_anyhow)?;

    if curated_rows.is_empty() {
        return Err(ApiError::bad_request(
            "pack query matched no bundles after curation rules",
        ));
    }

    let pack_id = generate_bundle_id();
    let created_at = Utc::now().to_rfc3339();
    let mut bundle_ids = Vec::with_capacity(curated_rows.len());
    let mut bundle_entries = Vec::with_capacity(curated_rows.len());
    let mut files = Vec::with_capacity(curated_rows.len());

    for curated in curated_rows {
        let artefacts = load_pack_artefacts(&state.db, &curated.bundle.bundle_id)
            .await
            .map_err(ApiError::internal_anyhow)?;
        let package_bytes = build_bundle_package_bytes(
            &curated.bundle,
            curated.row.bundle_json.as_bytes(),
            &artefacts,
        )
        .map_err(ApiError::internal_anyhow)?;

        bundle_ids.push(curated.row.bundle_id.clone());
        bundle_entries.push(PackBundleEntry {
            bundle_id: curated.row.bundle_id.clone(),
            created_at: curated.row.created_at,
            actor_role: curated.row.actor_role,
            system_id: curated.row.system_id,
            model_id: curated.row.model_id,
            retention_class: curated.row.retention_class,
            item_types: curated.item_types,
            obligation_refs: curated.obligation_refs,
            matched_rules: curated.matched_rules,
        });
        files.push(PackagedFile {
            name: format!("bundles/{}.pkg", curated.row.bundle_id),
            data_base64: Base64::encode_string(&package_bytes),
        });
    }

    let manifest = PackManifest {
        pack_id: pack_id.clone(),
        pack_type: request.pack_type.clone(),
        curation_profile: PACK_CURATION_PROFILE.to_string(),
        generated_at: created_at.clone(),
        system_id: request.system_id.clone(),
        from: request.from.clone(),
        to: request.to.clone(),
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
    persist_pack_metadata(&state.db, &manifest, &export_path)
        .await
        .map_err(ApiError::internal_anyhow)?;
    append_audit_log(
        &state.db,
        "create_pack",
        Some(AUDIT_ACTOR_API),
        None,
        Some(&pack_id),
        serde_json::json!({
            "pack_type": manifest.pack_type.clone(),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Some(AUDIT_ACTOR_API),
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
        Ok(verification) => VerifyTimestampResponse {
            valid: true,
            message: format!(
                "VALID: RFC 3161 token {} at {}",
                if verification.trusted {
                    "trusted"
                } else {
                    "verified"
                },
                verification.generated_at
            ),
            verification: Some(verification),
        },
        Err(err) => VerifyTimestampResponse {
            valid: false,
            message: format!("INVALID: {err}"),
            verification: None,
        },
    };
    append_audit_log(
        &state.db,
        "verify_timestamp",
        Some(AUDIT_ACTOR_API),
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
    Json(request): Json<VerifyReceiptRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (bundle_id, bundle_root, receipt) = resolve_receipt_verification_target(&state.db, request)
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
        Some(policy) => verify_receipt_with_policy(&receipt, &bundle_root, policy),
        None => verify_receipt(&receipt, &bundle_root),
    } {
        Ok(verification) => VerifyReceiptResponse {
            valid: true,
            message: format!(
                "VALID: transparency receipt {} at {}",
                if verification.trusted {
                    "trusted"
                } else {
                    "verified"
                },
                verification.integrated_time
            ),
            verification: Some(verification),
        },
        Err(err) => VerifyReceiptResponse {
            valid: false,
            message: format!("INVALID: {err}"),
            verification: None,
        },
    };
    append_audit_log(
        &state.db,
        "verify_receipt",
        Some(AUDIT_ACTOR_API),
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

    let files = read_bundle_package_from_bytes(&package_bytes, max_payload_bytes)
        .map_err(ApiError::bad_request_anyhow)?;
    let bundle = parse_bundle_file(&files).map_err(ApiError::bad_request_anyhow)?;
    validate_bundle_integrity_fields(&bundle).map_err(ApiError::bad_request_anyhow)?;
    let verifying_key = decode_public_key_pem(&request.public_key_pem)
        .map_err(|err| ApiError::bad_request(format!("invalid public key: {err}")))?;

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

    let manifest_ok = verify_manifest(&files).map_err(ApiError::bad_request_anyhow)?;
    let artefacts = extract_artefacts(&files).map_err(ApiError::bad_request_anyhow)?;
    let core_outcome = bundle.verify_with_artefacts(&artefacts, &verifying_key);

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
) -> Result<(Option<String>, String, TransparencyReceipt)> {
    match request {
        VerifyReceiptRequest::BundleId { bundle_id } => {
            let bundle = load_active_bundle(db, &bundle_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("bundle not found"))?;
            let receipt = bundle
                .receipt
                .ok_or_else(|| anyhow::anyhow!("bundle has no transparency receipt"))?;
            Ok((Some(bundle_id), bundle.integrity.bundle_root, receipt))
        }
        VerifyReceiptRequest::Direct {
            bundle_root,
            receipt,
        } => Ok((None, bundle_root, receipt)),
    }
}

fn read_bundle_package_from_bytes(
    package_bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<BTreeMap<String, Vec<u8>>> {
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
    if package.format != PACKAGE_FORMAT {
        bail!("unsupported package format {}", package.format);
    }

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
    Ok(files)
}

fn parse_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<ProofBundle> {
    let bundle_json = files
        .get("proof_bundle.json")
        .ok_or_else(|| anyhow::anyhow!("package missing proof_bundle.json"))?;
    let bundle: ProofBundle =
        serde_json::from_slice(bundle_json).context("failed to parse proof_bundle.json")?;
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
    request.system_id = normalize_optional_nonempty("system_id", request.system_id)?;
    request.from = normalize_optional_rfc3339("from", request.from)?;
    request.to = normalize_optional_rfc3339("to", request.to)?;

    if let (Some(from), Some(to)) = (request.from.as_deref(), request.to.as_deref()) {
        let from = chrono::DateTime::parse_from_rfc3339(from)
            .with_context(|| format!("from must be RFC3339, got {from}"))?;
        let to = chrono::DateTime::parse_from_rfc3339(to)
            .with_context(|| format!("to must be RFC3339, got {to}"))?;
        if from > to {
            bail!("from must be <= to");
        }
    }

    Ok(request)
}

fn normalize_pack_type(raw: &str) -> Result<String> {
    let normalized = raw.trim().replace('-', "_");
    if normalized.is_empty() {
        bail!("pack_type must not be empty");
    }

    match normalized.as_str() {
        "annex_iv" | "annex_xi" | "annex_xii" | "runtime_logs" | "risk_mgmt" | "ai_literacy"
        | "systemic_risk" | "incident_response" | "conformity" => Ok(normalized),
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
        bundle_count: manifest.bundle_ids.len(),
        bundle_ids: manifest.bundle_ids.clone(),
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
                "human_oversight",
            ],
            retention_classes: &["technical_doc", "risk_mgmt"],
            obligation_refs: &["art11_annex_iv", "art9", "art10", "art14"],
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
            ],
            retention_classes: &["technical_doc", "risk_mgmt", "gpai_documentation"],
            obligation_refs: &["art11_annex_iv", "art9", "art12_19_26", "art53_annex_xi"],
        }),
        "annex_xii" => Ok(PackProfile {
            pack_type: "annex_xii",
            allowed_roles: &["provider", "integrator"],
            item_types: &[
                "llm_interaction",
                "human_oversight",
                "policy_decision",
                "technical_doc",
            ],
            retention_classes: &["technical_doc"],
            obligation_refs: &["art11_annex_iv", "art14"],
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
        }),
        "risk_mgmt" => Ok(PackProfile {
            pack_type: "risk_mgmt",
            allowed_roles: &[],
            item_types: &["risk_assessment", "policy_decision", "human_oversight"],
            retention_classes: &["risk_mgmt"],
            obligation_refs: &["art9"],
        }),
        "ai_literacy" => Ok(PackProfile {
            pack_type: "ai_literacy",
            allowed_roles: &[],
            item_types: &["literacy_attestation"],
            retention_classes: &["ai_literacy"],
            obligation_refs: &["art4"],
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
            ],
            retention_classes: &["risk_mgmt", "technical_doc", "gpai_documentation"],
            obligation_refs: &[
                "art9",
                "art11_annex_iv",
                "art53_annex_xi",
                "art55",
                "art55_73",
            ],
        }),
        "incident_response" => Ok(PackProfile {
            pack_type: "incident_response",
            allowed_roles: &[],
            item_types: &[
                "incident_report",
                "risk_assessment",
                "human_oversight",
                "policy_decision",
                "technical_doc",
            ],
            retention_classes: &["risk_mgmt", "technical_doc"],
            obligation_refs: &["art9", "art11_annex_iv", "art14", "art55_73"],
        }),
        "conformity" => Ok(PackProfile {
            pack_type: "conformity",
            allowed_roles: &["provider"],
            item_types: &["conformity_assessment", "declaration", "registration"],
            retention_classes: &["technical_doc"],
            obligation_refs: &["art43_annex_vi_vii", "art47_annex_v", "art49_71"],
        }),
        _ => bail!("unsupported pack_type {pack_type}"),
    }
}

fn curate_pack_bundles(
    profile: &PackProfile,
    rows: Vec<PackSourceBundleRow>,
) -> Result<Vec<CuratedPackBundle>> {
    let mut curated = Vec::new();

    for row in rows {
        let bundle: ProofBundle =
            serde_json::from_str(&row.bundle_json).context("failed to parse stored bundle JSON")?;
        let item_types = bundle_item_types(&bundle);
        let obligation_refs = bundle_obligation_refs(&bundle);
        let bundle_role = actor_role_name(&bundle);

        if !profile.allowed_roles.is_empty() && !profile.allowed_roles.contains(&bundle_role) {
            continue;
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

        if matched_item_types.is_empty() && matched_obligation_refs.is_empty() && !matched_retention
        {
            continue;
        }

        let mut matched_rules = Vec::new();
        matched_rules.push(format!("pack_type:{}", profile.pack_type));
        if !profile.allowed_roles.is_empty() {
            matched_rules.push(format!("actor_role:{bundle_role}"));
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

        curated.push(CuratedPackBundle {
            row,
            bundle,
            item_types,
            obligation_refs,
            matched_rules,
        });
    }

    Ok(curated)
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

    builder
        .build_query_as::<PackSourceBundleRow>()
        .fetch_all(db)
        .await
        .context("failed to fetch bundles for pack assembly")
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

fn evidence_item_obligation_ref(bundle: &ProofBundle, item: &EvidenceItem) -> Option<&'static str> {
    match item {
        EvidenceItem::TechnicalDoc(_) => Some("art11_annex_iv"),
        EvidenceItem::RiskAssessment(_) => Some("art9"),
        EvidenceItem::DataGovernance(_) => Some("art10"),
        EvidenceItem::HumanOversight(_) => Some("art14"),
        EvidenceItem::ModelEvaluation(_) => Some("art53_annex_xi"),
        EvidenceItem::AdversarialTest(_) => Some("art55"),
        EvidenceItem::TrainingProvenance(_) => Some("art53_annex_xi"),
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
            manifest_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            manifest_json
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
        },
        signing: VaultSigningConfigView {
            key_id: state.signing_kid.clone(),
            algorithm: "ed25519".to_string(),
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
        timestamp: load_timestamp_config(&state.db).await?,
        transparency: load_transparency_config(&state.db).await?,
        audit: AuditConfigView { enabled: true },
    })
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
    config.log_public_key_pem = normalize_optional_string(config.log_public_key_pem);

    match config.provider.as_str() {
        "none" => {
            if config.enabled {
                bail!("transparency provider none cannot be enabled");
            }
            if config.url.is_some() {
                bail!("transparency url must be omitted when provider is none");
            }
            if config.log_public_key_pem.is_some() {
                bail!("transparency log public key must be omitted when provider is none");
            }
        }
        "rekor" | "scitt" => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("transparency url is required when provider is configured")
            })?;
            validate_http_url(url, "transparency url")?;
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
        log_public_key_pem: None,
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

fn load_signing_key(signing_key_path: Option<&FsPath>) -> Result<SigningKey> {
    if let Some(path) = signing_key_path {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read signing key {}", path.display()))?;
        let key = decode_private_key_pem(&contents)
            .with_context(|| format!("failed to parse private key at {}", path.display()))?;
        return Ok(key);
    }

    warn!("no signing key configured, generating ephemeral signing key");
    let secret = rand::random::<[u8; 32]>();
    Ok(SigningKey::from_bytes(&secret))
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
        EvidenceItem::ModelEvaluation(_) => "model_evaluation",
        EvidenceItem::AdversarialTest(_) => "adversarial_test",
        EvidenceItem::TrainingProvenance(_) => "training_provenance",
        EvidenceItem::ConformityAssessment(_) => "conformity_assessment",
        EvidenceItem::Declaration(_) => "declaration",
        EvidenceItem::Registration(_) => "registration",
        EvidenceItem::LiteracyAttestation(_) => "literacy_attestation",
        EvidenceItem::IncidentReport(_) => "incident_report",
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
        TransparencyReceipt, encode_public_key_pem, sha256_prefixed,
    };
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, BufReader, Read, Write};
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

    async fn test_state(max_payload_bytes: usize) -> AppState {
        let storage_dir = std::env::temp_dir().join(format!(
            "proof-service-test-storage-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let db_path = storage_dir.join("metadata.db");
        let db = open_sqlite_pool(&db_path).await.unwrap();
        initialize_sqlite_schema(&db).await.unwrap();
        seed_default_retention_policies(&db).await.unwrap();
        backfill_bundle_expiries(&db).await.unwrap();
        backfill_item_obligation_refs(&db).await.unwrap();
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        AppState {
            db,
            addr: DEFAULT_ADDR.to_string(),
            storage_dir,
            signing_key: Arc::new(signing_key),
            signing_kid: "kid-dev-01".to_string(),
            metadata_backend: "sqlite".to_string(),
            blob_backend: "filesystem".to_string(),
            max_payload_bytes,
            retention_grace_period_days: DEFAULT_RETENTION_GRACE_PERIOD_DAYS,
            retention_scan_interval_hours: DEFAULT_RETENTION_SCAN_INTERVAL_HOURS,
        }
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

    async fn create_bundle_response(
        app: &Router,
        payload: &CreateBundleRequest,
    ) -> CreateBundleResponse {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/bundles")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap();
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
        let (tsa_certificate, _) = build_test_certificate();
        let file_config = VaultFileConfig {
            server: VaultServerFileConfig {
                addr: Some("127.0.0.1:8181".to_string()),
                max_payload_bytes: Some(2048),
                tls_cert: None,
                tls_key: None,
            },
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
                log_public_key_pem: None,
                log_public_key_path: None,
            }),
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
        ]);

        let runtime =
            build_vault_runtime_config(file_config, Some(config_path.as_path()), &env_vars)
                .unwrap();

        assert_eq!(runtime.addr, SocketAddr::from(([0, 0, 0, 0], 9090)));
        assert_eq!(runtime.max_payload_bytes, 2048);
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
        assert_eq!(runtime.retention_grace_period_days, 21);
        assert_eq!(runtime.retention_scan_interval_hours, 6);
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
        let state = test_state(DEFAULT_MAX_PAYLOAD_BYTES).await;
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
        assert_eq!(config.signing.key_id, "kid-dev-01");
        assert_eq!(config.signing.algorithm, "ed25519");
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
            signing_key_path: None,
            signing_kid: "kid-runtime".to_string(),
            metadata_backend: "sqlite".to_string(),
            blob_backend: "filesystem".to_string(),
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            retention_grace_period_days: 45,
            retention_scan_interval_hours: 8,
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
            let statement_hash = payload["statement_hash"].as_str().unwrap();
            let response_payload = canonicalize_value(&serde_json::json!({
                "entryId": "entry-scitt-001",
                "registeredAt": "2026-03-06T13:15:00Z",
                "serviceId": service_id,
                "statementHash": statement_hash,
            }))
            .unwrap();
            let signature: Signature = signing_key.sign(&response_payload);
            let response_body = serde_json::json!({
                "entry_id": "entry-scitt-001",
                "service_id": service_id,
                "registered_at": "2026-03-06T13:15:00Z",
                "receipt_b64": Base64::encode_string(signature.to_der().as_bytes()),
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
                    system_id: Some("system-a".to_string()),
                    from: None,
                    to: None,
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
        assert_eq!(manifest.bundles[0].system_id.as_deref(), Some("system-a"));
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

        let pack_req = Request::builder()
            .method("POST")
            .uri("/v1/packs")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&CreatePackRequest {
                    pack_type: "incident_response".to_string(),
                    system_id: Some("system-incident".to_string()),
                    from: None,
                    to: None,
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
        assert_eq!(pack.bundle_ids, vec![incident_bundle.bundle_id.clone()]);

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

        assert_eq!(manifest.bundles.len(), 1);
        assert_eq!(manifest.bundles[0].item_types, vec!["incident_report"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art55_73"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:incident_report".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art55_73".to_string())
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
                    system_id: Some("system-z".to_string()),
                    from: None,
                    to: None,
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
        assert_eq!(manifest.bundles[0].item_types, vec!["training_provenance"]);
        assert_eq!(manifest.bundles[0].obligation_refs, vec!["art53_annex_xi"]);
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"actor_role:provider".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"item_type:training_provenance".to_string())
        );
        assert!(
            manifest.bundles[0]
                .matched_rules
                .contains(&"obligation_ref:art53_annex_xi".to_string())
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
                    system_id: Some("system-risk".to_string()),
                    from: None,
                    to: None,
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
                    system_id: Some("system-conformity".to_string()),
                    from: None,
                    to: None,
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
