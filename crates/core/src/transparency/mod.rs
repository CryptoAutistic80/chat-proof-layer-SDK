use crate::{
    schema::{ProofBundle, TimestampToken, TransparencyReceipt},
    timestamp::{RFC3161_TIMESTAMP_KIND, TimestampError, verify_timestamp},
};
use base64ct::{Base64, Encoding};
use chrono::{TimeZone, Utc};
use reqwest::{StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const REKOR_TRANSPARENCY_KIND: &str = "rekor";
pub const REKOR_RFC3161_ENTRY_KIND: &str = "rfc3161";
pub const REKOR_RFC3161_API_VERSION: &str = "0.0.1";
pub const SIGSTORE_REKOR_URL: &str = "https://rekor.sigstore.dev";

pub trait TransparencyProvider {
    fn submit(&self, entry: &TransparencyEntry) -> Result<TransparencyReceipt, TransparencyError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparencyEntry {
    pub bundle_root: String,
    pub timestamp: TimestampToken,
}

impl TransparencyEntry {
    pub fn from_bundle(bundle: &ProofBundle) -> Result<Self, TransparencyError> {
        let timestamp = bundle
            .timestamp
            .clone()
            .ok_or(TransparencyError::MissingTimestamp)?;
        Ok(Self {
            bundle_root: bundle.integrity.bundle_root.clone(),
            timestamp,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RekorTransparencyProvider {
    url: String,
    provider_label: Option<String>,
    client: Client,
}

impl RekorTransparencyProvider {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_label(url, REKOR_TRANSPARENCY_KIND)
    }

    pub fn with_label(url: impl Into<String>, provider_label: impl Into<String>) -> Self {
        let provider_label = provider_label.into();
        Self {
            url: normalize_url(url.into()),
            provider_label: if provider_label.trim().is_empty() {
                None
            } else {
                Some(provider_label)
            },
            client: Client::new(),
        }
    }

    pub fn sigstore() -> Self {
        Self::with_label(SIGSTORE_REKOR_URL, REKOR_TRANSPARENCY_KIND)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn create_entry_url(&self) -> String {
        format!("{}/api/v1/log/entries", self.url)
    }

    fn retrieve_entry_url(&self) -> String {
        format!("{}/api/v1/log/entries/retrieve", self.url)
    }

    fn submit_proposed_entry(
        &self,
        proposed_entry: &RekorRfc3161ProposedEntry,
    ) -> Result<Value, TransparencyError> {
        let response = self
            .client
            .post(self.create_entry_url())
            .json(proposed_entry)
            .send()
            .map_err(TransparencyError::Transport)?;

        match response.status() {
            StatusCode::CREATED | StatusCode::OK => parse_json_response(response),
            StatusCode::CONFLICT => self.retrieve_existing_entry(proposed_entry),
            status => Err(TransparencyError::HttpStatus {
                status: status.as_u16(),
                body: parse_error_body(response),
            }),
        }
    }

    fn retrieve_existing_entry(
        &self,
        proposed_entry: &RekorRfc3161ProposedEntry,
    ) -> Result<Value, TransparencyError> {
        let response = self
            .client
            .post(self.retrieve_entry_url())
            .json(&json!({
                "entries": [proposed_entry],
            }))
            .send()
            .map_err(TransparencyError::Transport)?;

        if !response.status().is_success() {
            return Err(TransparencyError::HttpStatus {
                status: response.status().as_u16(),
                body: parse_error_body(response),
            });
        }

        let mut entries = response
            .json::<Vec<Value>>()
            .map_err(TransparencyError::Transport)?;
        entries
            .drain(..)
            .next()
            .ok_or(TransparencyError::DuplicateEntryNotFound)
    }
}

impl TransparencyProvider for RekorTransparencyProvider {
    fn submit(&self, entry: &TransparencyEntry) -> Result<TransparencyReceipt, TransparencyError> {
        let proposed_entry = RekorRfc3161ProposedEntry {
            kind: REKOR_RFC3161_ENTRY_KIND.to_string(),
            api_version: REKOR_RFC3161_API_VERSION.to_string(),
            spec: RekorRfc3161Spec {
                tsr: RekorRfc3161Tsr {
                    content: entry.timestamp.token_base64.clone(),
                },
            },
        };
        let log_entry = self.submit_proposed_entry(&proposed_entry)?;
        let entry_uuid = extract_single_entry_uuid(&log_entry)?;
        let receipt = TransparencyReceipt {
            kind: REKOR_TRANSPARENCY_KIND.to_string(),
            provider: self.provider_label.clone(),
            body: json!({
                "log_url": self.url,
                "entry_uuid": entry_uuid,
                "log_entry": log_entry,
            }),
        };
        verify_receipt(&receipt, &entry.bundle_root)?;
        Ok(receipt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptVerification {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub log_url: String,
    pub entry_uuid: String,
    pub leaf_hash: String,
    pub log_id: String,
    pub log_index: u64,
    pub integrated_time: String,
    pub tree_size: u64,
    pub root_hash: String,
    pub inclusion_proof_hashes: usize,
    pub inclusion_proof_verified: bool,
    pub signed_entry_timestamp_present: bool,
    pub timestamp_generated_at: String,
}

#[derive(Debug, Error)]
pub enum TransparencyError {
    #[error("bundle already has a transparency receipt")]
    ExistingReceipt,
    #[error("bundle must be timestamped before transparency anchoring")]
    MissingTimestamp,
    #[error("transparency receipt kind must be {REKOR_TRANSPARENCY_KIND}, got {0}")]
    UnsupportedReceiptKind(String),
    #[error("transparency provider request failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("transparency provider returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("duplicate transparency entry lookup returned no entries")]
    DuplicateEntryNotFound,
    #[error("transparency receipt body is invalid: {0}")]
    InvalidBody(String),
    #[error("transparency receipt log URL must start with http:// or https://")]
    InvalidLogUrl,
    #[error("transparency receipt entry UUID is invalid: {0}")]
    InvalidEntryUuid(String),
    #[error("transparency receipt log ID is invalid: {0}")]
    InvalidLogId(String),
    #[error("transparency receipt missing verification block")]
    MissingVerification,
    #[error("transparency receipt missing inclusion proof")]
    MissingInclusionProof,
    #[error("transparency receipt missing signed entry timestamp")]
    MissingSignedEntryTimestamp,
    #[error("transparency receipt body encoding is invalid: {0}")]
    InvalidEntryEncoding(String),
    #[error(
        "transparency receipt inclusion proof tree_size {tree_size} is invalid for log_index {log_index}"
    )]
    InvalidTreeSize { log_index: u64, tree_size: u64 },
    #[error("transparency receipt inclusion proof hash is invalid: {0}")]
    InvalidProofHash(String),
    #[error("transparency receipt inclusion proof root hash is invalid: {0}")]
    InvalidRootHash(String),
    #[error("transparency receipt leaf hash did not match entry UUID")]
    LeafHashMismatch { expected: String, actual: String },
    #[error(
        "transparency receipt inclusion proof length {actual} did not match expected {expected}"
    )]
    InvalidProofLength { expected: usize, actual: usize },
    #[error("transparency receipt inclusion proof root mismatch")]
    InclusionProofRootMismatch { expected: String, actual: String },
    #[error("transparency receipt embeds unsupported Rekor entry kind: {0}")]
    UnsupportedEntryKind(String),
    #[error("transparency receipt embeds unsupported Rekor API version: {0}")]
    UnsupportedApiVersion(String),
    #[error("transparency receipt integrated_time is invalid: {0}")]
    InvalidIntegratedTime(i64),
    #[error("embedded RFC 3161 timestamp verification failed: {0}")]
    Timestamp(#[from] TimestampError),
}

pub fn anchor_bundle(
    bundle: &ProofBundle,
    provider: &dyn TransparencyProvider,
) -> Result<TransparencyReceipt, TransparencyError> {
    if bundle.receipt.is_some() {
        return Err(TransparencyError::ExistingReceipt);
    }

    let entry = TransparencyEntry::from_bundle(bundle)?;
    let receipt = provider.submit(&entry)?;
    verify_receipt(&receipt, &bundle.integrity.bundle_root)?;
    Ok(receipt)
}

pub fn verify_receipt(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
) -> Result<ReceiptVerification, TransparencyError> {
    if receipt.kind != REKOR_TRANSPARENCY_KIND {
        return Err(TransparencyError::UnsupportedReceiptKind(
            receipt.kind.clone(),
        ));
    }

    let body: RekorStoredReceiptBody = serde_json::from_value(receipt.body.clone())
        .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
    validate_http_url(&body.log_url)?;
    if !is_valid_hex_identifier(&body.entry_uuid) {
        return Err(TransparencyError::InvalidEntryUuid(body.entry_uuid));
    }

    let mut entries: BTreeMap<String, RekorLogEntry> = serde_json::from_value(body.log_entry)
        .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
    let Some((entry_uuid, entry)) = entries.pop_first() else {
        return Err(TransparencyError::InvalidBody(
            "log_entry must contain exactly one Rekor entry".to_string(),
        ));
    };
    if !entries.is_empty() {
        return Err(TransparencyError::InvalidBody(
            "log_entry must contain exactly one Rekor entry".to_string(),
        ));
    }
    if entry_uuid != body.entry_uuid {
        return Err(TransparencyError::InvalidBody(format!(
            "entry_uuid {} did not match log_entry key {}",
            body.entry_uuid, entry_uuid
        )));
    }
    if !is_valid_log_id(&entry.log_id) {
        return Err(TransparencyError::InvalidLogId(entry.log_id));
    }

    let verification = entry
        .verification
        .ok_or(TransparencyError::MissingVerification)?;
    let inclusion_proof = verification
        .inclusion_proof
        .ok_or(TransparencyError::MissingInclusionProof)?;
    let signed_entry_timestamp = verification
        .signed_entry_timestamp
        .ok_or(TransparencyError::MissingSignedEntryTimestamp)?;
    if inclusion_proof.log_index != entry.log_index {
        return Err(TransparencyError::InvalidBody(format!(
            "inclusion proof log_index {} did not match entry log_index {}",
            inclusion_proof.log_index, entry.log_index
        )));
    }

    if entry.log_index >= inclusion_proof.tree_size {
        return Err(TransparencyError::InvalidTreeSize {
            log_index: entry.log_index,
            tree_size: inclusion_proof.tree_size,
        });
    }

    let (body_bytes, proposed_entry) = decode_rekor_proposed_entry(entry.body)?;
    let leaf_hash_bytes = hash_rekor_leaf(&body_bytes);
    let leaf_hash = hex::encode(&leaf_hash_bytes);
    if leaf_hash != entry_uuid {
        return Err(TransparencyError::LeafHashMismatch {
            expected: entry_uuid.clone(),
            actual: leaf_hash,
        });
    }
    let root_hash = verify_rekor_inclusion_proof(
        entry.log_index,
        inclusion_proof.tree_size,
        &leaf_hash_bytes,
        &inclusion_proof,
    )?;

    if proposed_entry.kind != REKOR_RFC3161_ENTRY_KIND {
        return Err(TransparencyError::UnsupportedEntryKind(proposed_entry.kind));
    }
    if proposed_entry.api_version != REKOR_RFC3161_API_VERSION {
        return Err(TransparencyError::UnsupportedApiVersion(
            proposed_entry.api_version,
        ));
    }

    let embedded_token = TimestampToken {
        kind: RFC3161_TIMESTAMP_KIND.to_string(),
        provider: receipt.provider.clone(),
        token_base64: proposed_entry.spec.tsr.content,
    };
    let timestamp = verify_timestamp(&embedded_token, bundle_root)?;
    let integrated_time = Utc
        .timestamp_opt(entry.integrated_time, 0)
        .single()
        .ok_or(TransparencyError::InvalidIntegratedTime(
            entry.integrated_time,
        ))?
        .to_rfc3339();

    Ok(ReceiptVerification {
        kind: receipt.kind.clone(),
        provider: receipt.provider.clone(),
        log_url: body.log_url,
        entry_uuid,
        leaf_hash: hex::encode(leaf_hash_bytes),
        log_id: entry.log_id,
        log_index: entry.log_index,
        integrated_time,
        tree_size: inclusion_proof.tree_size,
        root_hash,
        inclusion_proof_hashes: inclusion_proof.hashes.len(),
        inclusion_proof_verified: true,
        signed_entry_timestamp_present: !signed_entry_timestamp.is_empty(),
        timestamp_generated_at: timestamp.generated_at,
    })
}

fn normalize_url(url: String) -> String {
    url.trim_end_matches('/').to_string()
}

fn validate_http_url(url: &str) -> Result<(), TransparencyError> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err(TransparencyError::InvalidLogUrl)
    }
}

fn is_valid_hex_identifier(value: &str) -> bool {
    (value.len() == 64 || value.len() == 80) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_valid_log_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn extract_single_entry_uuid(log_entry: &Value) -> Result<String, TransparencyError> {
    let object = log_entry.as_object().ok_or_else(|| {
        TransparencyError::InvalidBody("log entry response must be a JSON object".to_string())
    })?;
    if object.len() != 1 {
        return Err(TransparencyError::InvalidBody(
            "log entry response must contain exactly one Rekor entry".to_string(),
        ));
    }
    let entry_uuid = object.keys().next().cloned().ok_or_else(|| {
        TransparencyError::InvalidBody("log entry response was empty".to_string())
    })?;
    if !is_valid_hex_identifier(&entry_uuid) {
        return Err(TransparencyError::InvalidEntryUuid(entry_uuid));
    }
    Ok(entry_uuid)
}

fn parse_json_response(response: reqwest::blocking::Response) -> Result<Value, TransparencyError> {
    response
        .json::<Value>()
        .map_err(TransparencyError::Transport)
}

fn parse_error_body(response: reqwest::blocking::Response) -> String {
    response
        .text()
        .unwrap_or_else(|_| "unable to read response body".to_string())
}

fn decode_rekor_proposed_entry(
    body: Value,
) -> Result<(Vec<u8>, RekorRfc3161ProposedEntry), TransparencyError> {
    let bytes = match body {
        Value::String(encoded) => Base64::decode_vec(&encoded)
            .map_err(|err| TransparencyError::InvalidEntryEncoding(err.to_string()))?,
        Value::Object(_) => serde_json::to_vec(&body)
            .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?,
        other => {
            return Err(TransparencyError::InvalidBody(format!(
                "unsupported Rekor body type {}",
                other
            )));
        }
    };

    let entry = serde_json::from_slice(&bytes)
        .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
    Ok((bytes, entry))
}

fn hash_rekor_leaf(body: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(body);
    hasher.finalize().to_vec()
}

fn hash_rekor_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

fn verify_rekor_inclusion_proof(
    log_index: u64,
    tree_size: u64,
    leaf_hash: &[u8],
    proof: &RekorInclusionProof,
) -> Result<String, TransparencyError> {
    let expected_root = hex::decode(&proof.root_hash)
        .map_err(|err| TransparencyError::InvalidRootHash(err.to_string()))?;
    let proof_hashes = proof
        .hashes
        .iter()
        .map(|hash| {
            hex::decode(hash).map_err(|err| TransparencyError::InvalidProofHash(err.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (inner, border) = decompose_inclusion_proof(log_index, tree_size);
    let expected_len = inner + border;
    if proof_hashes.len() != expected_len {
        return Err(TransparencyError::InvalidProofLength {
            expected: expected_len,
            actual: proof_hashes.len(),
        });
    }

    let mut current = leaf_hash.to_vec();
    for (level, sibling) in proof_hashes.iter().take(inner).enumerate() {
        current = if ((log_index >> level) & 1) == 0 {
            hash_rekor_children(&current, sibling)
        } else {
            hash_rekor_children(sibling, &current)
        };
    }
    for sibling in proof_hashes.iter().skip(inner) {
        current = hash_rekor_children(sibling, &current);
    }

    if current != expected_root {
        return Err(TransparencyError::InclusionProofRootMismatch {
            expected: hex::encode(expected_root),
            actual: hex::encode(current),
        });
    }

    Ok(hex::encode(current))
}

fn decompose_inclusion_proof(index: u64, size: u64) -> (usize, usize) {
    let inner = inner_proof_size(index, size);
    let border = (index >> inner).count_ones() as usize;
    (inner, border)
}

fn inner_proof_size(index: u64, size: u64) -> usize {
    let diff = index ^ (size - 1);
    if diff == 0 {
        0
    } else {
        u64::BITS as usize - diff.leading_zeros() as usize
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorStoredReceiptBody {
    log_url: String,
    entry_uuid: String,
    log_entry: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorRfc3161ProposedEntry {
    kind: String,
    #[serde(rename = "apiVersion")]
    api_version: String,
    spec: RekorRfc3161Spec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorRfc3161Spec {
    tsr: RekorRfc3161Tsr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorRfc3161Tsr {
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorLogEntry {
    body: Value,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logID")]
    log_id: String,
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<RekorEntryVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorEntryVerification {
    #[serde(
        rename = "inclusionProof",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    inclusion_proof: Option<RekorInclusionProof>,
    #[serde(
        rename = "signedEntryTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorInclusionProof {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::{Integer, Mode, OctetString, Oid, encode::Values};
    use cryptographic_message_syntax::{
        Bytes, SignedDataBuilder, SignerBuilder,
        asn1::rfc3161::{MessageImprint, TstInfo},
    };
    use x509_certificate::{
        CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, X509CertificateBuilder,
    };

    struct StaticTransparencyProvider {
        receipt: TransparencyReceipt,
    }

    impl TransparencyProvider for StaticTransparencyProvider {
        fn submit(
            &self,
            _entry: &TransparencyEntry,
        ) -> Result<TransparencyReceipt, TransparencyError> {
            Ok(self.receipt.clone())
        }
    }

    #[test]
    fn verify_receipt_accepts_valid_rekor_rfc3161_entry() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let receipt = build_test_rekor_receipt(bundle_root, Some("rekor"));

        let verification = verify_receipt(&receipt, bundle_root).unwrap();
        assert_eq!(verification.kind, REKOR_TRANSPARENCY_KIND);
        assert_eq!(verification.provider.as_deref(), Some("rekor"));
        assert_eq!(verification.log_url, SIGSTORE_REKOR_URL);
        assert_eq!(verification.log_index, 0);
        assert_eq!(verification.tree_size, 1);
        assert_eq!(verification.inclusion_proof_hashes, 0);
        assert!(verification.inclusion_proof_verified);
        assert!(verification.signed_entry_timestamp_present);
        assert!(
            verification
                .integrated_time
                .starts_with("2026-03-06T13:00:00")
        );
        assert!(
            verification
                .timestamp_generated_at
                .starts_with("2026-03-06T12:00:00")
        );
        assert_eq!(verification.entry_uuid, verification.leaf_hash);
        assert_eq!(verification.root_hash, verification.leaf_hash);
    }

    #[test]
    fn verify_receipt_rejects_bundle_root_mismatch() {
        let receipt = build_test_rekor_receipt(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("rekor"),
        );

        let err = verify_receipt(
            &receipt,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();
        assert!(matches!(err, TransparencyError::Timestamp(_)));
    }

    #[test]
    fn verify_receipt_rejects_tampered_inclusion_proof() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut receipt = build_test_rekor_receipt(bundle_root, Some("rekor"));
        let entry_uuid = receipt.body["entry_uuid"].as_str().unwrap().to_string();
        receipt.body["log_entry"][&entry_uuid]["verification"]["inclusionProof"]["rootHash"] =
            Value::String(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
            );

        let err = verify_receipt(&receipt, bundle_root).unwrap_err();
        assert!(matches!(
            err,
            TransparencyError::InclusionProofRootMismatch { .. }
        ));
    }

    #[test]
    fn anchor_bundle_uses_provider_trait() {
        let bundle = build_test_bundle();
        let receipt = build_test_rekor_receipt(&bundle.integrity.bundle_root, Some("rekor"));
        let provider = StaticTransparencyProvider {
            receipt: receipt.clone(),
        };

        let actual = anchor_bundle(&bundle, &provider).unwrap();
        assert_eq!(actual, receipt);
    }

    #[test]
    fn rekor_provider_submits_rfc3161_payload() {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            thread,
        };

        let token = build_test_timestamp_token(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("test-tsa"),
        );
        let expected_token_base64 = token.token_base64.clone();
        let (_, receipt_json) = build_test_rekor_log_entry_response(&token.token_base64);
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
            request.push_str(std::str::from_utf8(&body).unwrap());
            assert!(request.starts_with("POST /api/v1/log/entries HTTP/1.1"));
            assert!(request.contains("\"kind\":\"rfc3161\""));
            assert!(request.contains("\"apiVersion\":\"0.0.1\""));
            assert!(request.contains(&expected_token_base64));

            let body = receipt_json.to_string();
            write!(
                stream,
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let provider = RekorTransparencyProvider::new(format!("http://{}", addr));
        let entry = TransparencyEntry {
            bundle_root: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            timestamp: token,
        };

        let receipt = provider.submit(&entry).unwrap();
        assert_eq!(receipt.kind, REKOR_TRANSPARENCY_KIND);
        assert_eq!(receipt.provider.as_deref(), Some(REKOR_TRANSPARENCY_KIND));
        server.join().unwrap();
    }

    fn build_test_bundle() -> ProofBundle {
        ProofBundle {
            bundle_version: "1.0".to_string(),
            bundle_id: "01JNFVDSM64DJN8SNMZP63YQC8".to_string(),
            created_at: "2026-03-06T12:30:00+00:00".to_string(),
            actor: crate::schema::Actor {
                issuer: "proof-layer-test".to_string(),
                app_id: "demo".to_string(),
                env: "test".to_string(),
                organization_id: None,
                role: crate::schema::ActorRole::Provider,
                signing_key_id: "kid-dev-01".to_string(),
            },
            subject: crate::schema::Subject::default(),
            context: crate::schema::EvidenceContext::default(),
            items: Vec::new(),
            artefacts: Vec::new(),
            policy: crate::schema::Policy::default(),
            integrity: crate::schema::Integrity {
                header_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                bundle_root:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                signature: crate::schema::SignatureInfo {
                    kid: "kid-dev-01".to_string(),
                    value: "signature".to_string(),
                    ..crate::schema::SignatureInfo::default()
                },
                ..crate::schema::Integrity::default()
            },
            timestamp: Some(build_test_timestamp_token(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Some("test-tsa"),
            )),
            receipt: None,
        }
    }

    fn build_test_rekor_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let (entry_uuid, log_entry) = build_test_rekor_log_entry_response(&token.token_base64);
        TransparencyReceipt {
            kind: REKOR_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: json!({
                "log_url": SIGSTORE_REKOR_URL,
                "entry_uuid": entry_uuid,
                "log_entry": log_entry,
            }),
        }
    }

    fn build_test_rekor_log_entry_response(token_base64: &str) -> (String, Value) {
        let body_bytes = serde_json::to_vec(&json!({
            "kind": REKOR_RFC3161_ENTRY_KIND,
            "apiVersion": REKOR_RFC3161_API_VERSION,
            "spec": {
                "tsr": {
                    "content": token_base64,
                }
            }
        }))
        .unwrap();
        let leaf_hash = hex::encode(hash_rekor_leaf(&body_bytes));
        let mut log_entry = serde_json::Map::new();
        log_entry.insert(
            leaf_hash.clone(),
            json!({
                "body": Base64::encode_string(&body_bytes),
                "integratedTime": 1772802000_i64,
                "logID": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "logIndex": 0,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 0,
                        "treeSize": 1,
                        "rootHash": leaf_hash,
                        "hashes": []
                    },
                    "signedEntryTimestamp": Base64::encode_string(b"rekor-set")
                }
            }),
        );

        (leaf_hash, Value::Object(log_entry))
    }

    fn build_test_timestamp_token(digest: &str, provider: Option<&str>) -> TimestampToken {
        let signed_data_der = build_test_signed_data_der(digest);
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: Base64::encode_string(&signed_data_der),
        }
    }

    fn build_test_signed_data_der(digest: &str) -> Vec<u8> {
        let (certificate, signing_key) = build_test_certificate();
        let tst_info_der = build_test_tst_info_der(digest);

        SignedDataBuilder::default()
            .content_inline(tst_info_der)
            .content_type(Oid(Bytes::copy_from_slice(
                cryptographic_message_syntax::asn1::rfc3161::OID_CONTENT_TYPE_TST_INFO.as_ref(),
            )))
            .certificate(certificate.clone())
            .signer(SignerBuilder::new(&signing_key, certificate))
            .build_der()
            .unwrap()
    }

    fn build_test_tst_info_der(digest: &str) -> Vec<u8> {
        let mut imprint_hasher = x509_certificate::DigestAlgorithm::Sha256.digester();
        imprint_hasher.update(digest.as_bytes());
        let imprint = imprint_hasher.finish();

        let tst_info = TstInfo {
            version: Integer::from(1),
            policy: Oid(Bytes::copy_from_slice(&[42, 3, 4])),
            message_imprint: MessageImprint {
                hash_algorithm: x509_certificate::DigestAlgorithm::Sha256.into(),
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
}
