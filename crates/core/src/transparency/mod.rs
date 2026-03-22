use crate::{
    assurance::{CheckState, ReceiptLiveCheckMode, ReceiptLiveVerification},
    canon::canonicalize_value,
    schema::{ProofBundle, TimestampToken, TransparencyReceipt},
    timestamp::{
        RFC3161_TIMESTAMP_KIND, TimestampError, TimestampTrustPolicy, verify_timestamp,
        verify_timestamp_with_policy,
    },
};
use base64ct::{Base64, Encoding};
use ciborium::{from_reader as cbor_from_reader, into_writer as cbor_into_writer};
use chrono::{TimeZone, Utc};
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use reqwest::{StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sigstore_merkle::proof::verify_consistency_proof;
use sigstore_types::Sha256Hash;
use std::{
    collections::BTreeMap,
    io::Cursor,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;

pub const REKOR_TRANSPARENCY_KIND: &str = "rekor";
pub const SCITT_TRANSPARENCY_KIND: &str = "scitt";
pub const REKOR_RFC3161_ENTRY_KIND: &str = "rfc3161";
pub const REKOR_RFC3161_API_VERSION: &str = "0.0.1";
pub const SIGSTORE_REKOR_URL: &str = "https://rekor.sigstore.dev";
pub const SCITT_STATEMENT_PROFILE: &str = "application/vnd.proof-layer.scitt-statement.v1+json";
pub const SCITT_BODY_FORMAT_LEGACY_JSON: &str = "proof-layer-json-v1";
pub const SCITT_BODY_FORMAT_COSE_CCF: &str = "ietf-scitt-cose-ccf-v1";
const REKOR_CONNECT_TIMEOUT_SECONDS: u64 = 3;
const REKOR_TOTAL_TIMEOUT_SECONDS: u64 = 10;

pub trait TransparencyProvider {
    fn submit(&self, entry: &TransparencyEntry) -> Result<TransparencyReceipt, TransparencyError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyTrustPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_public_key_pem: Option<String>,
    #[serde(default)]
    pub timestamp: TimestampTrustPolicy,
}

impl TransparencyTrustPolicy {
    pub fn is_empty(&self) -> bool {
        self.log_public_key_pem
            .as_deref()
            .is_none_or(|pem| pem.trim().is_empty())
            && self.timestamp.is_empty()
    }
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

#[derive(Debug, Clone)]
pub struct ScittTransparencyProvider {
    url: String,
    provider_label: Option<String>,
    client: Client,
    format: ScittFormat,
    statement_signer: Arc<Ed25519SigningKey>,
    statement_signing_kid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScittFormat {
    LegacyJson,
    #[default]
    CoseCcf,
}

#[derive(Debug, Clone)]
pub struct ScittStatementSigner {
    pub signing_key: Arc<Ed25519SigningKey>,
    pub key_id: String,
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

impl ScittTransparencyProvider {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_label(url, SCITT_TRANSPARENCY_KIND)
    }

    pub fn with_label(url: impl Into<String>, provider_label: impl Into<String>) -> Self {
        Self::with_format_and_signer(
            url,
            provider_label,
            ScittFormat::CoseCcf,
            None,
        )
    }

    pub fn with_format(
        url: impl Into<String>,
        provider_label: impl Into<String>,
        format: ScittFormat,
    ) -> Self {
        Self::with_format_and_signer(url, provider_label, format, None)
    }

    pub fn with_statement_signer(
        url: impl Into<String>,
        provider_label: impl Into<String>,
        format: ScittFormat,
        signer: ScittStatementSigner,
    ) -> Self {
        Self::with_format_and_signer(url, provider_label, format, Some(signer))
    }

    fn with_format_and_signer(
        url: impl Into<String>,
        provider_label: impl Into<String>,
        format: ScittFormat,
        signer: Option<ScittStatementSigner>,
    ) -> Self {
        let provider_label = provider_label.into();
        let default_key = Arc::new(Ed25519SigningKey::from_bytes(&rand::random::<[u8; 32]>()));
        let signer = signer.unwrap_or(ScittStatementSigner {
            signing_key: default_key,
            key_id: "scitt-statement-signer".to_string(),
        });
        Self {
            url: normalize_url(url.into()),
            provider_label: if provider_label.trim().is_empty() {
                None
            } else {
                Some(provider_label)
            },
            client: Client::new(),
            format,
            statement_signer: signer.signing_key,
            statement_signing_kid: signer.key_id,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn format(&self) -> ScittFormat {
        self.format
    }

    fn submit_statement(
        &self,
        request: &ScittSubmissionRequest,
    ) -> Result<ScittSubmissionResponse, TransparencyError> {
        let response = self
            .client
            .post(&self.url)
            .json(request)
            .send()
            .map_err(TransparencyError::Transport)?;

        if !response.status().is_success() {
            return Err(TransparencyError::HttpStatus {
                status: response.status().as_u16(),
                body: parse_error_body(response),
            });
        }

        response
            .json::<ScittSubmissionResponse>()
            .map_err(TransparencyError::Transport)
    }

    fn build_statement_bytes(
        &self,
        entry: &TransparencyEntry,
    ) -> Result<Vec<u8>, TransparencyError> {
        match self.format {
            ScittFormat::LegacyJson => {
                let statement = ScittLegacyStatement {
                    profile: SCITT_STATEMENT_PROFILE.to_string(),
                    bundle_root: entry.bundle_root.clone(),
                    timestamp: entry.timestamp.clone(),
                };
                let statement_value = serde_json::to_value(&statement)
                    .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
                canonicalize_value(&statement_value)
                    .map_err(|err| TransparencyError::InvalidBody(err.to_string()))
            }
            ScittFormat::CoseCcf => {
                let payload = ScittCoseStatementPayload {
                    profile: SCITT_STATEMENT_PROFILE.to_string(),
                    bundle_root: entry.bundle_root.clone(),
                    timestamp: entry.timestamp.clone(),
                };
                let payload_bytes = cbor_to_vec(&payload)?;
                let protected = HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .key_id(self.statement_signing_kid.as_bytes().to_vec())
                    .build();
                let sign1 = CoseSign1Builder::new()
                    .protected(protected)
                    .payload(payload_bytes)
                    .create_signature(b"", |data| {
                        self.statement_signer.sign(data).to_bytes().to_vec()
                    })
                    .build();
                sign1
                    .to_vec()
                    .map_err(|err| TransparencyError::InvalidBody(err.to_string()))
            }
        }
    }
}

impl ScittFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyJson => SCITT_BODY_FORMAT_LEGACY_JSON,
            Self::CoseCcf => SCITT_BODY_FORMAT_COSE_CCF,
        }
    }
}

impl TransparencyProvider for ScittTransparencyProvider {
    fn submit(&self, entry: &TransparencyEntry) -> Result<TransparencyReceipt, TransparencyError> {
        let statement_bytes = self.build_statement_bytes(entry)?;
        let statement_hash = crate::hash::sha256_prefixed(&statement_bytes);
        let response = self.submit_statement(&ScittSubmissionRequest {
            scitt_format: Some(self.format.as_str().to_string()),
            statement_b64: matches!(self.format, ScittFormat::LegacyJson)
                .then(|| Base64::encode_string(&statement_bytes)),
            statement_cose_b64: matches!(self.format, ScittFormat::CoseCcf)
                .then(|| Base64::encode_string(&statement_bytes)),
            statement_hash: statement_hash.clone(),
        })?;

        let receipt = match self.format {
            ScittFormat::LegacyJson => TransparencyReceipt {
                kind: SCITT_TRANSPARENCY_KIND.to_string(),
                provider: self.provider_label.clone(),
                body: json!({
                    "body_format": SCITT_BODY_FORMAT_LEGACY_JSON,
                    "service_url": self.url,
                    "entry_id": response.entry_id,
                    "service_id": response.service_id,
                    "registered_at": response.registered_at,
                    "statement_b64": Base64::encode_string(&statement_bytes),
                    "statement_hash": statement_hash,
                    "receipt_b64": response.receipt_b64.ok_or_else(|| {
                        TransparencyError::InvalidBody(
                            "SCITT response missing receipt_b64".to_string(),
                        )
                    })?,
                }),
            },
            ScittFormat::CoseCcf => TransparencyReceipt {
                kind: SCITT_TRANSPARENCY_KIND.to_string(),
                provider: self.provider_label.clone(),
                body: json!({
                    "body_format": SCITT_BODY_FORMAT_COSE_CCF,
                    "service_url": self.url,
                    "entry_id": response.entry_id,
                    "service_id": response.service_id,
                    "registered_at": response.registered_at,
                    "statement_hash": statement_hash,
                    "statement_cose_b64": Base64::encode_string(&statement_bytes),
                    "receipt_cbor_b64": response.receipt_cbor_b64.ok_or_else(|| {
                        TransparencyError::InvalidBody(
                            "SCITT response missing receipt_cbor_b64".to_string(),
                        )
                    })?,
                }),
            },
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
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed_entry_timestamp_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_id_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub trusted: bool,
    pub timestamp_generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_verification: Option<ReceiptLiveVerification>,
}

#[derive(Debug, Error)]
pub enum TransparencyError {
    #[error("bundle already has a transparency receipt")]
    ExistingReceipt,
    #[error("bundle must be timestamped before transparency anchoring")]
    MissingTimestamp,
    #[error(
        "transparency receipt kind must be {REKOR_TRANSPARENCY_KIND} or {SCITT_TRANSPARENCY_KIND}, got {0}"
    )]
    UnsupportedReceiptKind(String),
    #[error("transparency provider request failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("transparency provider returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("duplicate transparency entry lookup returned no entries")]
    DuplicateEntryNotFound,
    #[error("transparency receipt body is invalid: {0}")]
    InvalidBody(String),
    #[error("transparency receipt URL must start with http:// or https://")]
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
    #[error("transparency trust policy requires a PEM transparency public key")]
    MissingLogPublicKey,
    #[error("transparency public key is invalid: {0}")]
    InvalidLogPublicKey(String),
    #[error("transparency receipt signed entry timestamp base64 is invalid: {0}")]
    InvalidSignedEntryTimestamp(String),
    #[error("transparency receipt service/log ID did not match trusted public key")]
    TransparencyKeyIdMismatch { expected: String, actual: String },
    #[error("transparency receipt signed entry timestamp verification failed")]
    SignedEntryTimestampVerification,
    #[error("transparency receipt signed entry timestamp canonicalization failed: {0}")]
    SignedEntryTimestampCanonicalization(String),
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
    #[error("transparency receipt registered_at is invalid: {0}")]
    InvalidRegisteredAt(String),
    #[error("transparency receipt service entry ID must not be empty")]
    MissingEntryId,
    #[error("transparency receipt statement is missing")]
    MissingStatement,
    #[error("transparency receipt statement base64 is invalid: {0}")]
    InvalidStatementEncoding(String),
    #[error("transparency receipt statement hash is invalid: {0}")]
    InvalidStatementHash(String),
    #[error("transparency receipt service ID is invalid: {0}")]
    InvalidServiceId(String),
    #[error("transparency receipt statement profile is unsupported: {0}")]
    UnsupportedScittStatementProfile(String),
    #[error("transparency receipt service signature is missing")]
    MissingReceiptSignature,
    #[error("transparency receipt service signature base64 is invalid: {0}")]
    InvalidReceiptSignature(String),
    #[error("transparency receipt service signature verification failed")]
    ReceiptSignatureVerification,
    #[error("live receipt verification is only supported for {kind} receipts")]
    LiveCheckUnsupported { kind: String },
    #[error("live receipt verification request to {url} failed: {message}")]
    LiveCheckTransport { url: String, message: String },
    #[error("live receipt verification request to {url} returned HTTP {status}")]
    LiveCheckHttpStatus { url: String, status: u16 },
    #[error("live receipt verification response was invalid: {message}")]
    LiveCheckResponse { message: String },
    #[error("live receipt verification could not prove tree consistency")]
    LiveConsistencyProofMismatch,
    #[error("live receipt entry did not match the stored entry: {message}")]
    LiveEntryMismatch { message: String },
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
    verify_receipt_internal(receipt, bundle_root, None)
}

pub fn verify_receipt_with_policy(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    policy: &TransparencyTrustPolicy,
) -> Result<ReceiptVerification, TransparencyError> {
    verify_receipt_internal(receipt, bundle_root, Some(policy))
}

pub fn verify_receipt_with_live_check(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    mode: ReceiptLiveCheckMode,
) -> Result<ReceiptVerification, TransparencyError> {
    let verification = verify_receipt(receipt, bundle_root)?;
    attach_live_receipt_verification(receipt, verification, mode)
}

pub fn verify_receipt_with_policy_and_live_check(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    policy: &TransparencyTrustPolicy,
    mode: ReceiptLiveCheckMode,
) -> Result<ReceiptVerification, TransparencyError> {
    let verification = verify_receipt_with_policy(receipt, bundle_root, policy)?;
    attach_live_receipt_verification(receipt, verification, mode)
}

pub fn validate_transparency_trust_policy(
    policy: &TransparencyTrustPolicy,
) -> Result<(), TransparencyError> {
    if policy.is_empty() {
        return Ok(());
    }

    if policy
        .log_public_key_pem
        .as_deref()
        .is_some_and(|pem| !pem.trim().is_empty())
    {
        load_log_public_key(policy)?;
    }
    if !policy.timestamp.is_empty() {
        crate::timestamp::validate_timestamp_trust_policy(&policy.timestamp)
            .map_err(TransparencyError::Timestamp)?;
    }
    Ok(())
}

fn verify_receipt_internal(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    policy: Option<&TransparencyTrustPolicy>,
) -> Result<ReceiptVerification, TransparencyError> {
    match receipt.kind.as_str() {
        REKOR_TRANSPARENCY_KIND => verify_rekor_receipt(receipt, bundle_root, policy),
        SCITT_TRANSPARENCY_KIND => verify_scitt_receipt(receipt, bundle_root, policy),
        _ => Err(TransparencyError::UnsupportedReceiptKind(
            receipt.kind.clone(),
        )),
    }
}

fn attach_live_receipt_verification(
    receipt: &TransparencyReceipt,
    mut verification: ReceiptVerification,
    mode: ReceiptLiveCheckMode,
) -> Result<ReceiptVerification, TransparencyError> {
    if mode == ReceiptLiveCheckMode::Off {
        return Ok(verification);
    }

    match receipt.kind.as_str() {
        REKOR_TRANSPARENCY_KIND => match verify_rekor_receipt_live(receipt, &verification, mode) {
            Ok(live) => {
                verification.live_verification = Some(live);
                Ok(verification)
            }
            Err(error) if mode == ReceiptLiveCheckMode::BestEffort => {
                verification.live_verification = Some(ReceiptLiveVerification {
                    mode,
                    state: CheckState::Warn,
                    checked_at: Utc::now().to_rfc3339(),
                    summary: error.to_string(),
                    current_tree_size: None,
                    current_root_hash: None,
                    entry_retrieved: None,
                    consistency_verified: None,
                });
                Ok(verification)
            }
            Err(error) => Err(error),
        },
        kind => {
            if mode == ReceiptLiveCheckMode::BestEffort {
                verification.live_verification = Some(ReceiptLiveVerification {
                    mode,
                    state: CheckState::Warn,
                    checked_at: Utc::now().to_rfc3339(),
                    summary: format!(
                        "Live receipt verification is not available for {kind} receipts."
                    ),
                    current_tree_size: None,
                    current_root_hash: None,
                    entry_retrieved: None,
                    consistency_verified: None,
                });
                Ok(verification)
            } else {
                Err(TransparencyError::LiveCheckUnsupported {
                    kind: kind.to_string(),
                })
            }
        }
    }
}

fn verify_rekor_receipt(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    policy: Option<&TransparencyTrustPolicy>,
) -> Result<ReceiptVerification, TransparencyError> {
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
        .as_ref()
        .ok_or(TransparencyError::MissingVerification)?;
    let inclusion_proof = verification
        .inclusion_proof
        .as_ref()
        .ok_or(TransparencyError::MissingInclusionProof)?;
    let signed_entry_timestamp = verification
        .signed_entry_timestamp
        .as_deref()
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

    let (body_bytes, proposed_entry) = decode_rekor_proposed_entry(entry.body.clone())?;
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
        inclusion_proof,
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
    let timestamp = if let Some(policy) = policy.filter(|policy| !policy.timestamp.is_empty()) {
        verify_timestamp_with_policy(&embedded_token, bundle_root, &policy.timestamp)?
    } else {
        verify_timestamp(&embedded_token, bundle_root)?
    };
    let integrated_time = Utc
        .timestamp_opt(entry.integrated_time, 0)
        .single()
        .ok_or(TransparencyError::InvalidIntegratedTime(
            entry.integrated_time,
        ))?
        .to_rfc3339();
    let (signed_entry_timestamp_verified, log_id_verified, trusted) =
        if let Some(policy) = policy.filter(|policy| !policy.is_empty()) {
            let (signed_entry_timestamp_verified, log_id_verified, set_trusted) = if policy
                .log_public_key_pem
                .as_deref()
                .is_some_and(|pem| !pem.trim().is_empty())
            {
                verify_rekor_signed_entry_timestamp(&entry, signed_entry_timestamp, policy)?
            } else {
                (false, false, false)
            };
            let timestamp_trusted = match policy.timestamp.assurance_profile {
                Some(_) => timestamp.assurance_profile_verified,
                None if policy.timestamp.is_empty() => true,
                None => timestamp.trusted,
            };
            let trusted = set_trusted && timestamp_trusted;
            (signed_entry_timestamp_verified, log_id_verified, trusted)
        } else {
            (false, false, false)
        };

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
        signed_entry_timestamp_verified,
        log_id_verified,
        trusted,
        timestamp_generated_at: timestamp.generated_at,
        live_verification: None,
    })
}

fn verify_scitt_receipt(
    receipt: &TransparencyReceipt,
    bundle_root: &str,
    policy: Option<&TransparencyTrustPolicy>,
) -> Result<ReceiptVerification, TransparencyError> {
    let body = parse_scitt_stored_receipt_body(receipt.body.clone())?;
    validate_http_url(body.service_url())?;
    if body.entry_id().trim().is_empty() {
        return Err(TransparencyError::MissingEntryId);
    }
    if !is_valid_log_id(body.service_id()) {
        return Err(TransparencyError::InvalidServiceId(
            body.service_id().to_string(),
        ));
    }
    if crate::hash::parse_sha256_prefixed(body.statement_hash()).is_err() {
        return Err(TransparencyError::InvalidStatementHash(
            body.statement_hash().to_string(),
        ));
    }

    let statement_bytes = body.statement_bytes()?;
    let computed_statement_hash = crate::hash::sha256_prefixed(&statement_bytes);
    if computed_statement_hash != body.statement_hash() {
        return Err(TransparencyError::InvalidStatementHash(format!(
            "expected {}, got {}",
            computed_statement_hash,
            body.statement_hash()
        )));
    }

    let statement = parse_scitt_statement(&body, &statement_bytes)?;
    if statement.profile != SCITT_STATEMENT_PROFILE {
        return Err(TransparencyError::UnsupportedScittStatementProfile(
            statement.profile,
        ));
    }
    if statement.bundle_root != bundle_root {
        return Err(TransparencyError::InvalidBody(format!(
            "statement bundle_root {} did not match bundle root {}",
            statement.bundle_root, bundle_root
        )));
    }

    let timestamp = if let Some(policy) = policy.filter(|policy| !policy.timestamp.is_empty()) {
        verify_timestamp_with_policy(&statement.timestamp, bundle_root, &policy.timestamp)?
    } else {
        verify_timestamp(&statement.timestamp, bundle_root)?
    };
    let registered_at = chrono::DateTime::parse_from_rfc3339(body.registered_at())
        .map_err(|_| TransparencyError::InvalidRegisteredAt(body.registered_at().to_string()))?
        .with_timezone(&Utc)
        .to_rfc3339();

    let (signed_entry_timestamp_verified, log_id_verified, trusted) =
        if let Some(policy) = policy.filter(|policy| !policy.is_empty()) {
            let (signature_verified, key_id_verified, receipt_trusted) = if policy
                .log_public_key_pem
                .as_deref()
                .is_some_and(|pem| !pem.trim().is_empty())
            {
                verify_scitt_receipt_signature(&body, policy)?
            } else {
                (false, false, false)
            };
            let timestamp_trusted = match policy.timestamp.assurance_profile {
                Some(_) => timestamp.assurance_profile_verified,
                None if policy.timestamp.is_empty() => true,
                None => timestamp.trusted,
            };
            let trusted = receipt_trusted && timestamp_trusted;
            (signature_verified, key_id_verified, trusted)
        } else {
            (false, false, false)
        };

    Ok(ReceiptVerification {
        kind: receipt.kind.clone(),
        provider: receipt.provider.clone(),
        log_url: body.service_url().to_string(),
        entry_uuid: body.entry_id().to_string(),
        leaf_hash: computed_statement_hash.clone(),
        log_id: body.service_id().to_string(),
        log_index: 0,
        integrated_time: registered_at,
        tree_size: 0,
        root_hash: computed_statement_hash,
        inclusion_proof_hashes: 0,
        inclusion_proof_verified: false,
        signed_entry_timestamp_present: true,
        signed_entry_timestamp_verified,
        log_id_verified,
        trusted,
        timestamp_generated_at: timestamp.generated_at,
        live_verification: None,
    })
}

pub fn verify_rekor_receipt_live(
    receipt: &TransparencyReceipt,
    verification: &ReceiptVerification,
    mode: ReceiptLiveCheckMode,
) -> Result<ReceiptLiveVerification, TransparencyError> {
    if receipt.kind != REKOR_TRANSPARENCY_KIND {
        return Err(TransparencyError::LiveCheckUnsupported {
            kind: receipt.kind.clone(),
        });
    }

    let body: RekorStoredReceiptBody = serde_json::from_value(receipt.body.clone())
        .map_err(|err| TransparencyError::LiveCheckResponse {
            message: err.to_string(),
        })?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(REKOR_CONNECT_TIMEOUT_SECONDS))
        .timeout(Duration::from_secs(REKOR_TOTAL_TIMEOUT_SECONDS))
        .build()
        .map_err(|err| TransparencyError::LiveCheckResponse {
            message: err.to_string(),
        })?;

    let log_info: RekorLogInfoResponse =
        live_get_json(&client, &format!("{}/api/v1/log", body.log_url))?;
    if log_info.tree_size < verification.tree_size {
        return Err(TransparencyError::LiveCheckResponse {
            message: format!(
                "current tree size {} is smaller than stored tree size {}",
                log_info.tree_size, verification.tree_size
            ),
        });
    }

    let stored_root = sha256_hash_from_value(&verification.root_hash)?;
    let current_root = sha256_hash_from_value(&log_info.root_hash)?;
    let consistency_verified = if log_info.tree_size == verification.tree_size {
        if verification.root_hash != log_info.root_hash {
            return Err(TransparencyError::LiveConsistencyProofMismatch);
        }
        true
    } else {
        let proof: RekorConsistencyProofResponse = live_get_json(
            &client,
            &format!(
                "{}/api/v1/log/proof?firstSize={}&lastSize={}&treeID={}",
                body.log_url, verification.tree_size, log_info.tree_size, verification.log_id
            ),
        )?;
        let proof_hashes = proof
            .hashes
            .iter()
            .map(|hash| sha256_hash_from_value(hash))
            .collect::<Result<Vec<_>, _>>()?;
        verify_consistency_proof(
            verification.tree_size,
            log_info.tree_size,
            &proof_hashes,
            &stored_root,
            &current_root,
        )
        .map_err(|_| TransparencyError::LiveConsistencyProofMismatch)?;
        true
    };

    let live_entry: Value = live_get_json(
        &client,
        &format!("{}/api/v1/log/entries/{}", body.log_url, body.entry_uuid),
    )?;
    if live_entry != body.log_entry {
        return Err(TransparencyError::LiveEntryMismatch {
            message: "the live log entry did not match the stored entry".to_string(),
        });
    }

    Ok(ReceiptLiveVerification {
        mode,
        state: CheckState::Pass,
        checked_at: Utc::now().to_rfc3339(),
        summary: if log_info.tree_size == verification.tree_size {
            "Stored proof still matches the current log head.".to_string()
        } else {
            "Stored proof is consistent with the current log head and the live entry still matches."
                .to_string()
        },
        current_tree_size: Some(log_info.tree_size),
        current_root_hash: Some(log_info.root_hash),
        entry_retrieved: Some(true),
        consistency_verified: Some(consistency_verified),
    })
}

fn live_get_json<T: serde::de::DeserializeOwned>(
    client: &Client,
    url: &str,
) -> Result<T, TransparencyError> {
    let response = client
        .get(url)
        .send()
        .map_err(|err| TransparencyError::LiveCheckTransport {
            url: url.to_string(),
            message: err.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(TransparencyError::LiveCheckHttpStatus {
            url: url.to_string(),
            status: response.status().as_u16(),
        });
    }
    response
        .json::<T>()
        .map_err(|err| TransparencyError::LiveCheckResponse {
            message: err.to_string(),
        })
}

fn sha256_hash_from_value(value: &str) -> Result<Sha256Hash, TransparencyError> {
    Sha256Hash::from_hex_or_base64(value).map_err(|err| TransparencyError::LiveCheckResponse {
        message: err.to_string(),
    })
}

fn normalize_url(url: String) -> String {
    url.trim_end_matches('/').to_string()
}

fn load_log_public_key(
    policy: &TransparencyTrustPolicy,
) -> Result<VerifyingKey, TransparencyError> {
    let pem = policy
        .log_public_key_pem
        .as_deref()
        .map(str::trim)
        .filter(|pem| !pem.is_empty())
        .ok_or(TransparencyError::MissingLogPublicKey)?;

    VerifyingKey::from_public_key_pem(pem)
        .map_err(|err| TransparencyError::InvalidLogPublicKey(err.to_string()))
}

fn verify_rekor_signed_entry_timestamp(
    entry: &RekorLogEntry,
    signed_entry_timestamp: &str,
    policy: &TransparencyTrustPolicy,
) -> Result<(bool, bool, bool), TransparencyError> {
    let verifying_key = load_log_public_key(policy)?;
    let expected_log_id = compute_transparency_key_id(&verifying_key)?;
    if entry.log_id != expected_log_id {
        return Err(TransparencyError::TransparencyKeyIdMismatch {
            expected: expected_log_id,
            actual: entry.log_id.clone(),
        });
    }

    let canonical_payload = canonicalize_rekor_set_payload(entry)?;
    let signature_bytes = Base64::decode_vec(signed_entry_timestamp)
        .map_err(|err| TransparencyError::InvalidSignedEntryTimestamp(err.to_string()))?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|err| TransparencyError::InvalidSignedEntryTimestamp(err.to_string()))?;
    verifying_key
        .verify(&canonical_payload, &signature)
        .map_err(|_| TransparencyError::SignedEntryTimestampVerification)?;

    Ok((true, true, true))
}

fn verify_scitt_receipt_signature(
    body: &ScittStoredReceiptBody,
    policy: &TransparencyTrustPolicy,
) -> Result<(bool, bool, bool), TransparencyError> {
    let verifying_key = load_log_public_key(policy)?;
    let expected_service_id = compute_transparency_key_id(&verifying_key)?;
    if body.service_id() != expected_service_id {
        return Err(TransparencyError::TransparencyKeyIdMismatch {
            expected: expected_service_id,
            actual: body.service_id().to_string(),
        });
    }

    let canonical_payload = canonicalize_scitt_receipt_payload(body)?;
    let signature_b64 = match body {
        ScittStoredReceiptBody::Legacy(body) => body.receipt_b64.clone(),
        ScittStoredReceiptBody::Cose(body) => decode_scitt_cose_receipt_envelope(body)?
            .signature_der_b64,
    };
    let signature_bytes = Base64::decode_vec(&signature_b64)
        .map_err(|err| TransparencyError::InvalidReceiptSignature(err.to_string()))?;
    let signature = Signature::from_der(&signature_bytes)
        .map_err(|err| TransparencyError::InvalidReceiptSignature(err.to_string()))?;
    verifying_key
        .verify(&canonical_payload, &signature)
        .map_err(|_| TransparencyError::ReceiptSignatureVerification)?;

    Ok((true, true, true))
}

fn canonicalize_rekor_set_payload(entry: &RekorLogEntry) -> Result<Vec<u8>, TransparencyError> {
    canonicalize_value(&json!({
        "body": entry.body,
        "integratedTime": entry.integrated_time,
        "logID": entry.log_id,
        "logIndex": entry.log_index,
    }))
    .map_err(|err| TransparencyError::SignedEntryTimestampCanonicalization(err.to_string()))
}

fn canonicalize_scitt_receipt_payload(
    body: &ScittStoredReceiptBody,
) -> Result<Vec<u8>, TransparencyError> {
    match body {
        ScittStoredReceiptBody::Legacy(body) => canonicalize_value(&json!({
            "entryId": body.entry_id,
            "registeredAt": body.registered_at,
            "serviceId": body.service_id,
            "statementHash": body.statement_hash,
        }))
        .map_err(|err| TransparencyError::SignedEntryTimestampCanonicalization(err.to_string())),
        ScittStoredReceiptBody::Cose(body) => {
            let envelope = decode_scitt_cose_receipt_envelope(body)?;
            if envelope.payload.entry_id != body.entry_id
                || envelope.payload.service_id != body.service_id
                || envelope.payload.registered_at != body.registered_at
                || envelope.payload.statement_hash != body.statement_hash
            {
                return Err(TransparencyError::InvalidBody(
                    "SCITT receipt payload did not match the stored metadata".to_string(),
                ));
            }
            cbor_to_vec(&envelope.payload)
                .map_err(|err| TransparencyError::SignedEntryTimestampCanonicalization(err.to_string()))
        }
    }
}

impl ScittStoredReceiptBody {
    fn service_url(&self) -> &str {
        match self {
            Self::Legacy(body) => &body.service_url,
            Self::Cose(body) => &body.service_url,
        }
    }

    fn entry_id(&self) -> &str {
        match self {
            Self::Legacy(body) => &body.entry_id,
            Self::Cose(body) => &body.entry_id,
        }
    }

    fn service_id(&self) -> &str {
        match self {
            Self::Legacy(body) => &body.service_id,
            Self::Cose(body) => &body.service_id,
        }
    }

    fn registered_at(&self) -> &str {
        match self {
            Self::Legacy(body) => &body.registered_at,
            Self::Cose(body) => &body.registered_at,
        }
    }

    fn statement_hash(&self) -> &str {
        match self {
            Self::Legacy(body) => &body.statement_hash,
            Self::Cose(body) => &body.statement_hash,
        }
    }

    fn statement_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        match self {
            Self::Legacy(body) => {
                if body.statement_b64.trim().is_empty() {
                    return Err(TransparencyError::MissingStatement);
                }
                Base64::decode_vec(&body.statement_b64)
                    .map_err(|err| TransparencyError::InvalidStatementEncoding(err.to_string()))
            }
            Self::Cose(body) => {
                if body.statement_cose_b64.trim().is_empty() {
                    return Err(TransparencyError::MissingStatement);
                }
                Base64::decode_vec(&body.statement_cose_b64)
                    .map_err(|err| TransparencyError::InvalidStatementEncoding(err.to_string()))
            }
        }
    }
}

fn parse_scitt_stored_receipt_body(body: Value) -> Result<ScittStoredReceiptBody, TransparencyError> {
    let body_format = body
        .get("body_format")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if body.get("statement_cose_b64").is_some() || body.get("receipt_cbor_b64").is_some() {
        let body: ScittCoseStoredReceiptBody = serde_json::from_value(body)
            .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
        if !body.body_format.is_empty() && body.body_format != SCITT_BODY_FORMAT_COSE_CCF {
            return Err(TransparencyError::InvalidBody(format!(
                "unsupported SCITT body format {}",
                body.body_format
            )));
        }
        if body.receipt_cbor_b64.trim().is_empty() {
            return Err(TransparencyError::MissingReceiptSignature);
        }
        Ok(ScittStoredReceiptBody::Cose(body))
    } else if body_format.is_none() || body_format == Some(SCITT_BODY_FORMAT_LEGACY_JSON) {
        let body: ScittLegacyStoredReceiptBody = serde_json::from_value(body)
            .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
        if body.statement_b64.trim().is_empty() {
            return Err(TransparencyError::MissingStatement);
        }
        if body.receipt_b64.trim().is_empty() {
            return Err(TransparencyError::MissingReceiptSignature);
        }
        Ok(ScittStoredReceiptBody::Legacy(body))
    } else {
        Err(TransparencyError::InvalidBody(format!(
            "unsupported SCITT body format {}",
            body_format.unwrap_or_default()
        )))
    }
}

fn parse_scitt_statement(
    body: &ScittStoredReceiptBody,
    statement_bytes: &[u8],
) -> Result<ScittLegacyStatement, TransparencyError> {
    match body {
        ScittStoredReceiptBody::Legacy(_) => serde_json::from_slice(statement_bytes)
            .map_err(|err| TransparencyError::InvalidBody(err.to_string())),
        ScittStoredReceiptBody::Cose(_) => {
            let sign1 = CoseSign1::from_slice(statement_bytes)
                .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
            let payload = sign1.payload.ok_or_else(|| {
                TransparencyError::InvalidBody(
                    "SCITT COSE statement did not contain a payload".to_string(),
                )
            })?;
            let payload: ScittCoseStatementPayload = cbor_from_slice(&payload)
                .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
            Ok(ScittLegacyStatement {
                profile: payload.profile,
                bundle_root: payload.bundle_root,
                timestamp: payload.timestamp,
            })
        }
    }
}

fn decode_scitt_cose_receipt_envelope(
    body: &ScittCoseStoredReceiptBody,
) -> Result<ScittCoseReceiptEnvelope, TransparencyError> {
    let bytes = Base64::decode_vec(&body.receipt_cbor_b64)
        .map_err(|err| TransparencyError::InvalidReceiptSignature(err.to_string()))?;
    cbor_from_slice(&bytes).map_err(|err| TransparencyError::InvalidBody(err.to_string()))
}

fn cbor_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, TransparencyError> {
    let mut bytes = Vec::new();
    cbor_into_writer(value, &mut bytes)
        .map_err(|err| TransparencyError::InvalidBody(err.to_string()))?;
    Ok(bytes)
}

fn cbor_from_slice<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ciborium::de::Error<std::io::Error>> {
    cbor_from_reader(Cursor::new(bytes))
}

fn compute_transparency_key_id(verifying_key: &VerifyingKey) -> Result<String, TransparencyError> {
    let public_key_der = verifying_key
        .to_public_key_der()
        .map_err(|err| TransparencyError::InvalidLogPublicKey(err.to_string()))?;
    Ok(hex::encode(Sha256::digest(public_key_der.as_bytes())))
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

fn is_false(value: &bool) -> bool {
    !*value
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittLegacyStatement {
    profile: String,
    bundle_root: String,
    timestamp: TimestampToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittSubmissionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scitt_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    statement_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    statement_cose_b64: Option<String>,
    statement_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittSubmissionResponse {
    entry_id: String,
    service_id: String,
    registered_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_cbor_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittLegacyStoredReceiptBody {
    service_url: String,
    entry_id: String,
    service_id: String,
    registered_at: String,
    statement_b64: String,
    statement_hash: String,
    receipt_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittCoseStoredReceiptBody {
    body_format: String,
    service_url: String,
    entry_id: String,
    service_id: String,
    registered_at: String,
    statement_hash: String,
    statement_cose_b64: String,
    receipt_cbor_b64: String,
}

#[derive(Debug, Clone)]
enum ScittStoredReceiptBody {
    Legacy(ScittLegacyStoredReceiptBody),
    Cose(ScittCoseStoredReceiptBody),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittCoseStatementPayload {
    profile: String,
    bundle_root: String,
    timestamp: TimestampToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittCoseReceiptPayload {
    entry_id: String,
    service_id: String,
    registered_at: String,
    statement_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScittCoseReceiptEnvelope {
    payload: ScittCoseReceiptPayload,
    signature_der_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorLogInfoResponse {
    #[serde(rename = "treeSize")]
    tree_size: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RekorConsistencyProofResponse {
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(rename = "rootHash", default, skip_serializing_if = "Option::is_none")]
    root_hash: Option<String>,
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
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer},
        elliptic_curve::rand_core::OsRng,
        pkcs8::{EncodePublicKey, LineEnding},
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
        assert!(!verification.signed_entry_timestamp_verified);
        assert!(!verification.trusted);
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
    fn verify_receipt_with_policy_accepts_trusted_log_key() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (receipt, log_public_key_pem) = build_trusted_rekor_receipt(bundle_root, Some("rekor"));
        let policy = TransparencyTrustPolicy {
            log_public_key_pem: Some(log_public_key_pem),
            timestamp: TimestampTrustPolicy::default(),
        };

        let verification = verify_receipt_with_policy(&receipt, bundle_root, &policy).unwrap();
        assert!(verification.signed_entry_timestamp_present);
        assert!(verification.signed_entry_timestamp_verified);
        assert!(verification.log_id_verified);
        assert!(verification.trusted);
    }

    #[test]
    fn verify_receipt_with_policy_rejects_wrong_log_key() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (receipt, _) = build_trusted_rekor_receipt(bundle_root, Some("rekor"));
        let wrong_key = SigningKey::random(&mut OsRng);
        let policy = TransparencyTrustPolicy {
            log_public_key_pem: Some(
                wrong_key
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap(),
            ),
            timestamp: TimestampTrustPolicy::default(),
        };

        let err = verify_receipt_with_policy(&receipt, bundle_root, &policy).unwrap_err();
        assert!(matches!(
            err,
            TransparencyError::TransparencyKeyIdMismatch { .. }
        ));
    }

    #[test]
    fn verify_receipt_with_policy_accepts_standard_timestamp_assurance_profile() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (receipt, log_public_key_pem) = build_trusted_rekor_receipt(bundle_root, Some("rekor"));
        let policy = TransparencyTrustPolicy {
            log_public_key_pem: Some(log_public_key_pem),
            timestamp: TimestampTrustPolicy {
                trust_anchor_pems: Vec::new(),
                crl_pems: Vec::new(),
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: Vec::new(),
                policy_oids: Vec::new(),
                assurance_profile: Some(crate::timestamp::TimestampAssuranceProfile::Standard),
            },
        };

        let verification = verify_receipt_with_policy(&receipt, bundle_root, &policy).unwrap();
        assert!(verification.signed_entry_timestamp_verified);
        assert!(verification.log_id_verified);
        assert!(verification.trusted);
    }

    #[test]
    fn verify_receipt_with_policy_allows_timestamp_profile_without_log_key() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let receipt = build_test_rekor_receipt(bundle_root, Some("rekor"));
        let policy = TransparencyTrustPolicy {
            log_public_key_pem: None,
            timestamp: TimestampTrustPolicy {
                trust_anchor_pems: Vec::new(),
                crl_pems: Vec::new(),
                ocsp_responder_urls: Vec::new(),
                qualified_signer_pems: Vec::new(),
                policy_oids: Vec::new(),
                assurance_profile: Some(crate::timestamp::TimestampAssuranceProfile::Standard),
            },
        };

        let verification = verify_receipt_with_policy(&receipt, bundle_root, &policy).unwrap();
        assert!(!verification.signed_entry_timestamp_verified);
        assert!(!verification.log_id_verified);
        assert!(!verification.trusted);
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
    fn verify_receipt_accepts_valid_scitt_statement() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let receipt = build_test_scitt_receipt(bundle_root, Some("scitt"));

        let verification = verify_receipt(&receipt, bundle_root).unwrap();
        assert_eq!(verification.kind, SCITT_TRANSPARENCY_KIND);
        assert_eq!(verification.provider.as_deref(), Some("scitt"));
        assert_eq!(verification.log_url, "https://scitt.example.test/entries");
        assert_eq!(verification.log_index, 0);
        assert_eq!(verification.tree_size, 0);
        assert!(!verification.inclusion_proof_verified);
        assert!(verification.signed_entry_timestamp_present);
        assert!(!verification.signed_entry_timestamp_verified);
        assert!(!verification.trusted);
        assert!(
            verification
                .integrated_time
                .starts_with("2026-03-06T13:15:00")
        );
        assert_eq!(verification.leaf_hash, verification.root_hash);
    }

    #[test]
    fn verify_receipt_with_policy_accepts_trusted_scitt_key() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (receipt, service_public_key_pem) =
            build_trusted_scitt_receipt(bundle_root, Some("scitt"));
        let policy = TransparencyTrustPolicy {
            log_public_key_pem: Some(service_public_key_pem),
            timestamp: TimestampTrustPolicy::default(),
        };

        let verification = verify_receipt_with_policy(&receipt, bundle_root, &policy).unwrap();
        assert!(verification.signed_entry_timestamp_verified);
        assert!(verification.log_id_verified);
        assert!(verification.trusted);
    }

    #[test]
    fn verify_receipt_rejects_tampered_scitt_statement_hash() {
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut receipt = build_test_scitt_receipt(bundle_root, Some("scitt"));
        receipt.body["statement_hash"] = Value::String(
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        );

        let err = verify_receipt(&receipt, bundle_root).unwrap_err();
        assert!(matches!(err, TransparencyError::InvalidStatementHash(_)));
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

    #[test]
    fn scitt_provider_submits_statement_hash_payload() {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            thread,
        };

        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(bundle_root, Some("test-tsa"));
        let signer = ScittStatementSigner {
            signing_key: Arc::new(Ed25519SigningKey::from_bytes(&[7_u8; 32])),
            key_id: "kid-scitt-test".to_string(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let provider = ScittTransparencyProvider::with_statement_signer(
            format!("http://{addr}/entries"),
            SCITT_TRANSPARENCY_KIND,
            ScittFormat::CoseCcf,
            signer,
        );
        let statement_bytes = provider
            .build_statement_bytes(&TransparencyEntry {
                bundle_root: bundle_root.to_string(),
                timestamp: token.clone(),
            })
            .unwrap();
        let statement_b64 = Base64::encode_string(&statement_bytes);
        let statement_hash = crate::hash::sha256_prefixed(&statement_bytes);
        let (response, _) = build_trusted_scitt_receipt_response(
            &statement_hash,
            "entry-scitt-001",
            "2026-03-06T13:15:00Z",
            ScittFormat::CoseCcf,
        );

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
            assert!(request.starts_with("POST /entries HTTP/1.1"));
            assert!(request.contains(&statement_b64));
            assert!(request.contains(&statement_hash));

            let body = serde_json::to_string(&response).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let entry = TransparencyEntry {
            bundle_root: bundle_root.to_string(),
            timestamp: token,
        };

        let receipt = provider.submit(&entry).unwrap();
        assert_eq!(receipt.kind, SCITT_TRANSPARENCY_KIND);
        assert_eq!(receipt.provider.as_deref(), Some(SCITT_TRANSPARENCY_KIND));
        assert_eq!(
            receipt.body["body_format"].as_str(),
            Some(SCITT_BODY_FORMAT_COSE_CCF)
        );
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
            compliance_profile: None,
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

    fn build_trusted_rekor_receipt(
        bundle_root: &str,
        provider: Option<&str>,
    ) -> (TransparencyReceipt, String) {
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
        let leaf_hash = hex::encode(hash_rekor_leaf(&body_bytes));
        let signing_key = SigningKey::random(&mut OsRng);
        let log_id = compute_transparency_key_id(signing_key.verifying_key()).unwrap();
        let entry = RekorLogEntry {
            body: Value::String(Base64::encode_string(&body_bytes)),
            integrated_time: 1772802000_i64,
            log_id: log_id.clone(),
            log_index: 0,
            verification: None,
        };
        let set_payload = canonicalize_rekor_set_payload(&entry).unwrap();
        let set_signature: Signature = signing_key.sign(&set_payload);
        let mut log_entry = serde_json::Map::new();
        log_entry.insert(
            leaf_hash.clone(),
            json!({
                "body": entry.body,
                "integratedTime": entry.integrated_time,
                "logID": entry.log_id,
                "logIndex": entry.log_index,
                "verification": {
                    "inclusionProof": {
                        "logIndex": 0,
                        "treeSize": 1,
                        "rootHash": leaf_hash.clone(),
                        "hashes": []
                    },
                    "signedEntryTimestamp": Base64::encode_string(
                        set_signature.to_der().as_bytes()
                    )
                }
            }),
        );

        let receipt = TransparencyReceipt {
            kind: REKOR_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: json!({
                "log_url": SIGSTORE_REKOR_URL,
                "entry_uuid": leaf_hash.clone(),
                "log_entry": Value::Object(log_entry),
            }),
        };

        (
            receipt,
            signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
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

    fn build_test_scitt_receipt(bundle_root: &str, provider: Option<&str>) -> TransparencyReceipt {
        let token = build_test_timestamp_token(bundle_root, provider);
        let statement = ScittLegacyStatement {
            profile: SCITT_STATEMENT_PROFILE.to_string(),
            bundle_root: bundle_root.to_string(),
            timestamp: token,
        };
        let statement_bytes =
            canonicalize_value(&serde_json::to_value(&statement).unwrap()).unwrap();
        let statement_hash = crate::hash::sha256_prefixed(&statement_bytes);

        TransparencyReceipt {
            kind: SCITT_TRANSPARENCY_KIND.to_string(),
            provider: provider.map(str::to_string),
            body: json!({
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

    fn build_trusted_scitt_receipt(
        bundle_root: &str,
        provider: Option<&str>,
    ) -> (TransparencyReceipt, String) {
        let token = build_test_timestamp_token(bundle_root, provider);
        let statement = ScittLegacyStatement {
            profile: SCITT_STATEMENT_PROFILE.to_string(),
            bundle_root: bundle_root.to_string(),
            timestamp: token,
        };
        let statement_bytes =
            canonicalize_value(&serde_json::to_value(&statement).unwrap()).unwrap();
        let statement_hash = crate::hash::sha256_prefixed(&statement_bytes);
        let (response, public_key_pem) = build_trusted_scitt_receipt_response(
            &statement_hash,
            "entry-scitt-001",
            "2026-03-06T13:15:00Z",
            ScittFormat::LegacyJson,
        );

        (
            TransparencyReceipt {
                kind: SCITT_TRANSPARENCY_KIND.to_string(),
                provider: provider.map(str::to_string),
                body: json!({
                    "service_url": "https://scitt.example.test/entries",
                    "entry_id": response.entry_id,
                    "service_id": response.service_id,
                    "registered_at": response.registered_at,
                    "statement_b64": Base64::encode_string(&statement_bytes),
                    "statement_hash": statement_hash,
                    "receipt_b64": response.receipt_b64,
                }),
            },
            public_key_pem,
        )
    }

    fn build_trusted_scitt_receipt_response(
        statement_hash: &str,
        entry_id: &str,
        registered_at: &str,
        format: ScittFormat,
    ) -> (ScittSubmissionResponse, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let service_id = compute_transparency_key_id(signing_key.verifying_key()).unwrap();
        let payload = match format {
            ScittFormat::LegacyJson => canonicalize_scitt_receipt_payload(
                &ScittStoredReceiptBody::Legacy(ScittLegacyStoredReceiptBody {
                    service_url: "https://scitt.example.test/entries".to_string(),
                    entry_id: entry_id.to_string(),
                    service_id: service_id.clone(),
                    registered_at: registered_at.to_string(),
                    statement_b64: String::new(),
                    statement_hash: statement_hash.to_string(),
                    receipt_b64: String::new(),
                }),
            )
            .unwrap(),
            ScittFormat::CoseCcf => canonicalize_scitt_receipt_payload(
                &ScittStoredReceiptBody::Cose(ScittCoseStoredReceiptBody {
                    body_format: SCITT_BODY_FORMAT_COSE_CCF.to_string(),
                    service_url: "https://scitt.example.test/entries".to_string(),
                    entry_id: entry_id.to_string(),
                    service_id: service_id.clone(),
                    registered_at: registered_at.to_string(),
                    statement_hash: statement_hash.to_string(),
                    statement_cose_b64: String::new(),
                    receipt_cbor_b64: Base64::encode_string(
                        &cbor_to_vec(&ScittCoseReceiptEnvelope {
                            payload: ScittCoseReceiptPayload {
                                entry_id: entry_id.to_string(),
                                service_id: service_id.clone(),
                                registered_at: registered_at.to_string(),
                                statement_hash: statement_hash.to_string(),
                            },
                            signature_der_b64: String::new(),
                        })
                        .unwrap(),
                    ),
                }),
            )
            .unwrap(),
        };
        let signature: Signature = signing_key.sign(&payload);

        (
            ScittSubmissionResponse {
                entry_id: entry_id.to_string(),
                service_id: service_id.clone(),
                registered_at: registered_at.to_string(),
                receipt_b64: matches!(format, ScittFormat::LegacyJson)
                    .then(|| Base64::encode_string(signature.to_der().as_bytes())),
                receipt_cbor_b64: matches!(format, ScittFormat::CoseCcf).then(|| {
                    Base64::encode_string(
                        &cbor_to_vec(&ScittCoseReceiptEnvelope {
                            payload: ScittCoseReceiptPayload {
                                entry_id: entry_id.to_string(),
                                service_id: service_id.clone(),
                                registered_at: registered_at.to_string(),
                                statement_hash: statement_hash.to_string(),
                            },
                            signature_der_b64: Base64::encode_string(
                                signature.to_der().as_bytes()
                            ),
                        })
                        .unwrap(),
                    )
                }),
            },
            signing_key
                .verifying_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
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
