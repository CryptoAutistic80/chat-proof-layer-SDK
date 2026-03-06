use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use base64ct::{Base64, Encoding};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use flate2::read::GzDecoder;
use proof_layer_core::{
    ArtefactInput, BuildBundleError, CaptureEvent, CaptureInput, EvidenceItem, ProofBundle,
    build_bundle, canonicalize_value, decode_private_key_pem, decode_public_key_pem,
    sha256_prefixed, validate_bundle_integrity_fields,
};
use serde::{Deserialize, Serialize};
use sqlx::{
    FromRow, QueryBuilder, Row, Sqlite, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs::{self, File},
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    path::{Component, Path as FsPath, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};
use ulid::Ulid;

const DEFAULT_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;
const PACKAGE_FORMAT: &str = "pl-bundle-pkg-v1";

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    storage_dir: PathBuf,
    signing_key: Arc<SigningKey>,
    signing_kid: String,
    max_payload_bytes: usize,
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

#[derive(Debug, Deserialize)]
struct BundleQuery {
    system_id: Option<String>,
    role: Option<String>,
    #[serde(rename = "type")]
    item_type: Option<String>,
    from: Option<String>,
    to: Option<String>,
    page: Option<u32>,
    limit: Option<u32>,
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
    has_timestamp: bool,
    has_receipt: bool,
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

    let addr: SocketAddr = env::var("PROOF_SERVICE_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_string())
        .parse()
        .context("failed to parse PROOF_SERVICE_ADDR")?;

    let storage_dir = PathBuf::from(
        env::var("PROOF_SERVICE_STORAGE_DIR").unwrap_or_else(|_| "./storage".to_string()),
    );
    fs::create_dir_all(&storage_dir)
        .with_context(|| format!("failed to create storage dir {}", storage_dir.display()))?;

    let db_path = env::var("PROOF_SERVICE_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| storage_dir.join("metadata.db"));
    let db = open_sqlite_pool(&db_path).await?;
    initialize_sqlite_schema(&db).await?;

    let signing_key = load_signing_key()?;
    let signing_kid = env::var("PROOF_SIGNING_KEY_ID").unwrap_or_else(|_| "kid-dev-01".to_string());
    let max_payload_bytes = env::var("PROOF_SERVICE_MAX_PAYLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES);

    let state = AppState {
        db,
        storage_dir,
        signing_key: Arc::new(signing_key),
        signing_kid,
        max_payload_bytes,
    };

    let app = build_router(state, max_payload_bytes);

    info!("proof-service listening on {addr}");
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
        .route("/v1/bundles/{bundle_id}", get(get_bundle))
        .route(
            "/v1/bundles/{bundle_id}/artefacts/{name}",
            get(get_artefact),
        )
        .route("/v1/verify", post(verify_bundle))
        .layer(cors)
        .layer(DefaultBodyLimit::max(max_payload_bytes))
        .with_state(state)
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

    persist_artefacts(&state.storage_dir, &bundle_id, &artefacts)
        .map_err(ApiError::internal_anyhow)?;
    persist_bundle_metadata(&state.db, &state.storage_dir, &bundle)
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
            b.has_timestamp, \
            b.has_receipt \
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

    Ok((
        StatusCode::OK,
        Json(ListBundlesResponse { page, limit, items }),
    ))
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

    Ok((StatusCode::OK, Json(response)))
}

fn verify_inline_request(
    request: InlineVerifyRequest,
    max_payload_bytes: usize,
) -> Result<VerifyResponse, ApiError> {
    validate_bundle_integrity_fields(&request.bundle)
        .map_err(ApiError::bad_request_anyhow)?;

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
    validate_bundle_integrity_fields(&bundle)
        .map_err(ApiError::bad_request_anyhow)?;
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

fn load_signing_key() -> Result<SigningKey> {
    if let Ok(path) = env::var("PROOF_SIGNING_KEY_PATH") {
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read PROOF_SIGNING_KEY_PATH {}", path))?;
        let key = decode_private_key_pem(&contents)
            .with_context(|| format!("failed to parse private key at {}", path))?;
        return Ok(key);
    }

    warn!("PROOF_SIGNING_KEY_PATH not set, generating ephemeral signing key");
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
            deleted_at,
            bundle_json,
            canonical_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
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
    .bind(&bundle_json)
    .bind(canonical_bytes)
    .execute(&mut *tx)
    .await
    .context("failed to insert bundle row")?;

    for (index, item) in bundle.items.iter().enumerate() {
        let item_value = serde_json::to_value(item)?;
        let item_commitment = sha256_prefixed(&canonicalize_value(&item_value)?);
        let metadata_json = serde_json::to_string(&item_value)?;

        sqlx::query(
            "INSERT INTO evidence_items (
                bundle_id,
                item_index,
                item_type,
                obligation_ref,
                item_commitment,
                metadata_json
            ) VALUES (?, ?, ?, NULL, ?, ?)",
        )
        .bind(&bundle.bundle_id)
        .bind(index as i64)
        .bind(evidence_item_type(item))
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
    }
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
            deleted_at TEXT,
            bundle_json TEXT NOT NULL,
            canonical_bytes BLOB NOT NULL
        )",
        "CREATE INDEX IF NOT EXISTS idx_bundles_system ON bundles(system_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_role ON bundles(actor_role, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_request ON bundles(request_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_bundles_app ON bundles(app_id, created_at)",
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
        "CREATE TABLE IF NOT EXISTS artefacts (
            bundle_id TEXT NOT NULL REFERENCES bundles(bundle_id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            digest TEXT NOT NULL,
            size INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            PRIMARY KEY (bundle_id, name)
        )",
    ];

    for statement in statements {
        sqlx::query(statement)
            .execute(db)
            .await
            .with_context(|| format!("failed to execute sqlite schema statement: {statement}"))?;
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
    use flate2::{Compression, write::GzEncoder};
    use proof_layer_core::{encode_public_key_pem, sha256_prefixed};
    use std::io::Write;
    use tower::ServiceExt;

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

    async fn test_state(max_payload_bytes: usize) -> AppState {
        let storage_dir = std::env::temp_dir().join(format!(
            "proof-service-test-storage-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&storage_dir).unwrap();
        let db_path = storage_dir.join("metadata.db");
        let db = open_sqlite_pool(&db_path).await.unwrap();
        initialize_sqlite_schema(&db).await.unwrap();
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        AppState {
            db,
            storage_dir,
            signing_key: Arc::new(signing_key),
            signing_kid: "kid-dev-01".to_string(),
            max_payload_bytes,
        }
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
    }
}
