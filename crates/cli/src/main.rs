use anyhow::{Context, Result, anyhow, bail};
use base64ct::Encoding;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ArtefactInput, CaptureEvent, CaptureInput, EvidenceItem, ProofBundle,
    Rfc3161HttpTimestampProvider, TimestampProvider, build_bundle, build_inclusion_proof,
    capture_input_v01_to_event, decode_private_key_pem, decode_public_key_pem,
    encode_private_key_pem, encode_public_key_pem, sha256_prefixed, timestamp_digest,
    validate_bundle_integrity_fields, verify_timestamp,
};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use tracing::info;
use ulid::Ulid;

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
    Create {
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
    },
    /// Verify a proof bundle package offline.
    Verify {
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
    },
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

#[derive(Debug, Serialize)]
struct VerifyReport {
    canonicalization_ok: bool,
    artefact_integrity_ok: bool,
    signature_ok: bool,
    manifest_ok: bool,
    message: String,
    artefacts_verified: usize,
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
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OptionalCheckState {
    Skipped,
    Missing,
    Unsupported,
    Invalid,
    Valid,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct OptionalCheckReport {
    state: OptionalCheckState,
    message: String,
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
}

#[derive(Debug, Deserialize)]
struct PackSummaryResponse {
    pack_id: String,
    pack_type: String,
    created_at: String,
    system_id: Option<String>,
    from: Option<String>,
    to: Option<String>,
    bundle_count: usize,
    bundle_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
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
        Commands::Create {
            input,
            artefact,
            key,
            out,
            bundle_id,
            created_at,
            signing_kid,
            evidence_type,
            retention_class,
            system_id,
            timestamp_url,
        } => cmd_create(CreateCommandInput {
            input_path: &input,
            artefacts: &artefact,
            key_path: &key,
            out_path: &out,
            bundle_id: bundle_id.as_deref(),
            created_at: created_at.as_deref(),
            signing_kid: &signing_kid,
            overrides: &CreateOverrides {
                evidence_type,
                retention_class,
                system_id,
            },
            timestamp_url: timestamp_url.as_deref(),
        }),
        Commands::Verify {
            input,
            key,
            format,
            check_timestamp,
            check_receipt,
        } => cmd_verify(&input, &key, format, check_timestamp, check_receipt),
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
        } => cmd_pack(
            pack_type,
            &vault_url,
            &out,
            system_id.as_deref(),
            from.as_deref(),
            to.as_deref(),
        ),
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
        let verification = attach_timestamp_to_bundle(&mut bundle, &provider)?;
        info!(
            "timestamp provider={} generated_at={}",
            verification.provider.as_deref().unwrap_or("rfc3161"),
            verification.generated_at
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

fn cmd_verify(
    input_path: &Path,
    key_path: &Path,
    format: OutputFormat,
    check_timestamp: bool,
    check_receipt: bool,
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
    validate_bundle_integrity_fields(&bundle)?;

    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let verifying_key = decode_public_key_pem(&key_pem)
        .with_context(|| format!("failed to parse public key {}", key_path.display()))?;

    let recomputed_canonical = bundle.canonical_header_bytes()?;
    let canonical_file = files
        .get("proof_bundle.canonical.json")
        .ok_or_else(|| anyhow!("package missing proof_bundle.canonical.json"))?;
    let canonicalization_ok = &recomputed_canonical == canonical_file;

    let signature_file = files
        .get("proof_bundle.sig")
        .ok_or_else(|| anyhow!("package missing proof_bundle.sig"))?;
    let signature_ok = signature_file == bundle.integrity.signature.value.as_bytes();

    let manifest_ok = verify_manifest(&files)?;

    let artefacts = extract_artefacts(&files)?;
    let verification = bundle.verify_with_artefacts(&artefacts, &verifying_key);
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

    let timestamp = evaluate_timestamp_check(&bundle, check_timestamp);
    if check_timestamp && timestamp.state != OptionalCheckState::Valid {
        failures.push(timestamp.message.clone());
    }

    let receipt = evaluate_optional_check(
        "transparency receipt",
        "transparency receipt verification",
        bundle.receipt.is_some(),
        check_receipt,
    );
    if check_receipt && receipt.state != OptionalCheckState::Valid {
        failures.push(receipt.message.clone());
    }

    let message = if failures.is_empty() {
        "VALID".to_string()
    } else {
        format!("INVALID: {}", failures.join("; "))
    };

    let report = VerifyReport {
        canonicalization_ok,
        artefact_integrity_ok,
        signature_ok: signature_ok && artefact_integrity_ok,
        manifest_ok,
        message,
        artefacts_verified,
        timestamp,
        receipt,
    };

    match format {
        OutputFormat::Human => print_human_verify_report(&report),
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    if report.canonicalization_ok
        && report.artefact_integrity_ok
        && report.signature_ok
        && report.manifest_ok
        && (!check_timestamp || report.timestamp.state == OptionalCheckState::Valid)
        && (!check_receipt || report.receipt.state == OptionalCheckState::Valid)
    {
        Ok(())
    } else {
        bail!("verification failed")
    }
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

fn cmd_pack(
    pack_type: PackTypeArg,
    vault_url: &str,
    out_path: &Path,
    system_id: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()> {
    let request = CreatePackRequest {
        pack_type: pack_type.as_api_value().to_string(),
        system_id: normalize_optional_cli_text("system_id", system_id)?,
        from: normalize_optional_cli_datetime("from", from)?,
        to: normalize_optional_cli_datetime("to", to)?,
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

    let client = Client::builder()
        .build()
        .context("failed to build HTTP client")?;
    let create_url = join_vault_url(vault_url, "/v1/packs");
    let create_response = client
        .post(&create_url)
        .json(&request)
        .send()
        .with_context(|| format!("failed to call {create_url}"))?;
    let create_response = ensure_success(create_response, "pack create")?;
    let pack: PackSummaryResponse = create_response
        .json()
        .context("failed to decode pack create response")?;

    let export_url = join_vault_url(vault_url, &format!("/v1/packs/{}/export", pack.pack_id));
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

    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    fs::write(out_path, &export_bytes)
        .with_context(|| format!("failed to write {}", out_path.display()))?;

    info!("wrote {}", out_path.display());
    info!("pack_id={}", pack.pack_id);
    info!("pack_type={}", pack.pack_type);
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
    let mut digests = Vec::with_capacity(1 + bundle.artefacts.len());
    digests.push(bundle.integrity.header_digest.clone());
    digests.extend(
        bundle
            .artefacts
            .iter()
            .map(|artefact| artefact.digest.clone()),
    );

    let mut leaves = Vec::with_capacity(digests.len());
    for (index, digest) in digests.iter().enumerate() {
        let proof = build_inclusion_proof(&digests, index)?;
        let label = if index == 0 {
            "header_digest".to_string()
        } else {
            format!("artefact:{}", bundle.artefacts[index - 1].name)
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
    }
}

fn abbreviate_digest(value: &str) -> String {
    if value.len() <= 22 {
        return value.to_string();
    }
    format!("{}...{}", &value[..15], &value[value.len() - 6..])
}

fn evaluate_optional_check(
    label: &str,
    mechanism: &str,
    present: bool,
    requested: bool,
) -> OptionalCheckReport {
    if !requested {
        return OptionalCheckReport {
            state: OptionalCheckState::Skipped,
            message: if present {
                format!("{label} present but not checked")
            } else {
                format!("{label} not present (optional)")
            },
        };
    }

    if !present {
        return OptionalCheckReport {
            state: OptionalCheckState::Missing,
            message: format!("{label} check requested but bundle has no {label}"),
        };
    }

    OptionalCheckReport {
        state: OptionalCheckState::Unsupported,
        message: format!("{label} present but {mechanism} is not implemented yet"),
    }
}

fn evaluate_timestamp_check(bundle: &ProofBundle, requested: bool) -> OptionalCheckReport {
    if !requested {
        return OptionalCheckReport {
            state: OptionalCheckState::Skipped,
            message: if bundle.timestamp.is_some() {
                "timestamp present but not checked".to_string()
            } else {
                "timestamp not present (optional)".to_string()
            },
        };
    }

    let Some(timestamp) = bundle.timestamp.as_ref() else {
        return OptionalCheckReport {
            state: OptionalCheckState::Missing,
            message: "timestamp check requested but bundle has no timestamp".to_string(),
        };
    };

    match verify_timestamp(timestamp, &bundle.integrity.bundle_root) {
        Ok(verification) => OptionalCheckReport {
            state: OptionalCheckState::Valid,
            message: format!(
                "RFC 3161 token valid at {} ({} signer{})",
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

fn attach_timestamp_to_bundle(
    bundle: &mut ProofBundle,
    provider: &dyn TimestampProvider,
) -> Result<proof_layer_core::TimestampVerification> {
    if bundle.timestamp.is_some() {
        bail!("bundle already contains a timestamp token");
    }

    let token = timestamp_digest(&bundle.integrity.bundle_root, provider)
        .context("failed to request timestamp token")?;
    let verification = verify_timestamp(&token, &bundle.integrity.bundle_root)
        .context("failed to verify returned timestamp token")?;
    bundle.timestamp = Some(token);

    Ok(verification)
}

fn write_bundle_package(out_path: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let parent = out_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;

    let package = BundlePackage {
        format: "pl-bundle-pkg-v1".to_string(),
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

fn read_bundle_package(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
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

    if package.format != "pl-bundle-pkg-v1" {
        bail!("unsupported package format {}", package.format);
    }

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

    Ok(files)
}

fn parse_bundle_file(files: &BTreeMap<String, Vec<u8>>) -> Result<ProofBundle> {
    let bundle_json = files
        .get("proof_bundle.json")
        .ok_or_else(|| anyhow!("package missing proof_bundle.json"))?;
    let bundle: ProofBundle =
        serde_json::from_slice(bundle_json).context("failed to parse proof_bundle.json")?;
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
    println!();
    println!("Verification result: {}", report.message);
}

fn optional_check_marker(state: &OptionalCheckState) -> &'static str {
    match state {
        OptionalCheckState::Valid => "✓",
        OptionalCheckState::Skipped => "–",
        OptionalCheckState::Missing
        | OptionalCheckState::Unsupported
        | OptionalCheckState::Invalid => "✗",
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
        RFC3161_TIMESTAMP_KIND, Subject, TimestampError, TimestampToken,
    };
    use serde_json::json;
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

    fn build_test_timestamp_token(digest: &str, provider: Option<&str>) -> TimestampToken {
        let signed_data_der = build_test_signed_data_der(digest);
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: base64ct::Base64::encode_string(&signed_data_der),
        }
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
    fn join_vault_url_strips_trailing_slash() {
        let joined = join_vault_url("http://127.0.0.1:8080/", "/v1/packs");
        assert_eq!(joined, "http://127.0.0.1:8080/v1/packs");
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
        assert_eq!(view.leaves.len(), 1 + bundle.artefacts.len());
    }

    #[test]
    fn optional_check_reports_missing_invalid_and_unsupported_states() {
        let missing = evaluate_timestamp_check(&sample_bundle(), true);
        assert_eq!(missing.state, OptionalCheckState::Missing);

        let mut bundle = sample_bundle();
        bundle.timestamp = Some(build_test_timestamp_token(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some("test-tsa"),
        ));
        let invalid = evaluate_timestamp_check(&bundle, true);
        assert_eq!(invalid.state, OptionalCheckState::Invalid);

        let unsupported =
            evaluate_optional_check("transparency receipt", "receipt verification", true, true);
        assert_eq!(unsupported.state, OptionalCheckState::Unsupported);
    }

    #[test]
    fn attach_timestamp_to_bundle_sets_verifiable_token() {
        let mut bundle = sample_bundle();
        let provider = StaticTimestampProvider {
            token: build_test_timestamp_token(&bundle.integrity.bundle_root, Some("test-tsa")),
        };

        let verification = attach_timestamp_to_bundle(&mut bundle, &provider).unwrap();
        assert_eq!(verification.provider.as_deref(), Some("test-tsa"));
        assert!(bundle.timestamp.is_some());

        let timestamp_report = evaluate_timestamp_check(&bundle, true);
        assert_eq!(timestamp_report.state, OptionalCheckState::Valid);
        assert!(timestamp_report.message.contains("RFC 3161 token valid"));
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
