use anyhow::{Context, Result, anyhow, bail};
use base64ct::Encoding;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use proof_layer_core::{
    ArtefactInput, CaptureInput, ProofBundle, build_bundle, decode_private_key_pem,
    decode_public_key_pem, encode_private_key_pem, encode_public_key_pem, sha256_prefixed,
    validate_bundle_integrity_fields,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use tracing::info;

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
    },
    /// Verify a proof bundle package offline.
    Verify {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "human")]
        format: OutputFormat,
    },
    /// Print key fields from a proof bundle package.
    Inspect {
        #[arg(long = "in")]
        input: PathBuf,
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
        } => cmd_create(
            &input,
            &artefact,
            &key,
            &out,
            bundle_id.as_deref(),
            created_at.as_deref(),
            &signing_kid,
        ),
        Commands::Verify { input, key, format } => cmd_verify(&input, &key, format),
        Commands::Inspect { input, format } => cmd_inspect(&input, format),
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

fn cmd_create(
    input_path: &Path,
    artefacts: &[ArtefactArg],
    key_path: &Path,
    out_path: &Path,
    bundle_id: Option<&str>,
    created_at: Option<&str>,
    signing_kid: &str,
) -> Result<()> {
    if artefacts.is_empty() {
        bail!("at least one --artefact name=path value is required");
    }
    if signing_kid.trim().is_empty() {
        bail!("signing kid must not be empty");
    }

    let max_payload_bytes = max_payload_bytes()?;
    let capture_json =
        fs::read(input_path).with_context(|| format!("failed to read {}", input_path.display()))?;
    if capture_json.len() > max_payload_bytes {
        bail!(
            "capture input {} bytes exceeds max {} bytes",
            capture_json.len(),
            max_payload_bytes
        );
    }
    let capture: CaptureInput = serde_json::from_slice(&capture_json)
        .with_context(|| format!("failed to parse capture JSON from {}", input_path.display()))?;

    let signing_key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let signing_key = decode_private_key_pem(&signing_key_pem)
        .with_context(|| format!("failed to parse signing key {}", key_path.display()))?;

    let mut artefact_inputs = Vec::with_capacity(artefacts.len());
    let mut artefact_files = BTreeMap::new();
    for artefact in artefacts {
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

    let bundle_id = match bundle_id {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                bail!("bundle_id must not be empty");
            }
            trimmed.to_string()
        }
        None => generate_bundle_id(),
    };
    let created_at = parse_created_at(created_at)?;
    let bundle = build_bundle(
        capture,
        &artefact_inputs,
        &signing_key,
        signing_kid,
        &bundle_id,
        created_at,
    )?;

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

    write_bundle_package(out_path, &package_files)?;
    info!("created {}", out_path.display());
    info!("bundle_id={}", bundle.bundle_id);
    info!("bundle_root={}", bundle.integrity.bundle_root);

    Ok(())
}

fn cmd_verify(input_path: &Path, key_path: &Path, format: OutputFormat) -> Result<()> {
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

    let (artefact_integrity_ok, message, artefacts_verified) = match verification {
        Ok(summary) => (true, "VALID".to_string(), summary.artefact_count),
        Err(err) => (false, format!("INVALID: {err}"), 0),
    };

    let report = VerifyReport {
        canonicalization_ok,
        artefact_integrity_ok,
        signature_ok: signature_ok && artefact_integrity_ok,
        manifest_ok,
        message,
        artefacts_verified,
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
    {
        Ok(())
    } else {
        bail!("verification failed")
    }
}

fn cmd_inspect(input_path: &Path, format: OutputFormat) -> Result<()> {
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

    match format {
        OutputFormat::Human => {
            println!("bundle_id: {}", bundle.bundle_id);
            println!("created_at: {}", bundle.created_at);
            println!("provider: {}", bundle.model.provider);
            println!("model: {}", bundle.model.model);
            println!("artefacts: {}", bundle.artefacts.len());
            println!("bundle_root: {}", bundle.integrity.bundle_root);
            println!("signature.kid: {}", bundle.integrity.signature.kid);
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
    }

    Ok(())
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
    println!("[–] Timestamp — no RFC 3161 token present (optional)");
    println!("[–] Transparency receipt — not present (optional)");
    println!();
    println!("Verification result: {}", report.message);
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
    let millis = Utc::now().timestamp_millis();
    let random = rand::random::<[u8; 8]>();
    format!("PL{:x}{}", millis, hex::encode(random)).to_uppercase()
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
    use flate2::{Compression, write::GzEncoder};
    use std::time::{SystemTime, UNIX_EPOCH};

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
