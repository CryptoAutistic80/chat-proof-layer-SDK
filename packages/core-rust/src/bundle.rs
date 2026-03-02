use crate::{
    canonicalize::{CanonError, canonicalize_value},
    hash::{DigestError, parse_sha256_prefixed, sha256_prefixed},
    merkle::{MerkleError, compute_commitment},
    verify::{VerifyBundleRootError, verify_bundle_root},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Component, Path},
};
use thiserror::Error;

pub const CANONICALIZATION_ALGORITHM: &str = "RFC8785-JCS";
pub const HASH_ALGORITHM: &str = "SHA-256";
pub const BUNDLE_ROOT_ALGORITHM: &str = "pl-merkle-sha256-v1";
pub const SIGNATURE_FORMAT: &str = "JWS";
pub const SIGNATURE_ALGORITHM: &str = "EdDSA";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub issuer: String,
    pub app_id: String,
    pub env: String,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outputs {
    pub assistant_text_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_outputs_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub otel_genai_semconv_version: String,
    pub trace_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub redactions: Vec<String>,
    pub encryption: EncryptionPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPolicy {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtefactMeta {
    pub name: String,
    pub digest: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub format: String,
    pub alg: String,
    pub kid: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub canonicalization: String,
    pub hash: String,
    pub header_digest: String,
    pub bundle_root_algorithm: String,
    pub bundle_root: String,
    pub signature: SignatureInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub messages_commitment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieval_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureInput {
    pub actor: Actor,
    pub subject: Subject,
    pub model: ModelInfo,
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub trace: Trace,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub bundle_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub actor: Actor,
    pub subject: Subject,
    pub model: ModelInfo,
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub trace: Trace,
    pub artefacts: Vec<ArtefactMeta>,
    pub policy: Policy,
    pub integrity: Integrity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
}

impl ProofBundle {
    pub fn canonical_header_projection(&self) -> Value {
        json!({
            "bundle_version": self.bundle_version,
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "actor": self.actor,
            "subject": self.subject,
            "model": self.model,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "trace": self.trace,
            "artefacts": self.artefacts,
            "policy": self.policy,
        })
    }

    pub fn canonical_header_bytes(&self) -> Result<Vec<u8>, CanonError> {
        canonicalize_value(&self.canonical_header_projection())
    }

    pub fn verify_with_artefacts(
        &self,
        artefacts: &BTreeMap<String, Vec<u8>>,
        verifying_key: &VerifyingKey,
    ) -> Result<VerificationSummary, BundleVerificationError> {
        validate_bundle_integrity_fields(self)?;

        let canonical_header = self.canonical_header_bytes()?;
        let computed_header_digest = sha256_prefixed(&canonical_header);
        if computed_header_digest != self.integrity.header_digest {
            return Err(BundleVerificationError::HeaderDigestMismatch {
                expected: self.integrity.header_digest.clone(),
                actual: computed_header_digest,
            });
        }

        for meta in &self.artefacts {
            let bytes = artefacts
                .get(&meta.name)
                .ok_or_else(|| BundleVerificationError::MissingArtefact(meta.name.clone()))?;
            if meta.size != bytes.len() as u64 {
                return Err(BundleVerificationError::ArtefactSizeMismatch {
                    name: meta.name.clone(),
                    expected: meta.size,
                    actual: bytes.len() as u64,
                });
            }
            let digest = sha256_prefixed(bytes);
            if digest != meta.digest {
                return Err(BundleVerificationError::ArtefactDigestMismatch {
                    name: meta.name.clone(),
                    expected: meta.digest.clone(),
                    actual: digest,
                });
            }
        }

        let mut ordered_digests = Vec::with_capacity(1 + self.artefacts.len());
        ordered_digests.push(self.integrity.header_digest.clone());
        ordered_digests.extend(self.artefacts.iter().map(|item| item.digest.clone()));

        let commitment = compute_commitment(&ordered_digests)?;
        if commitment.root != self.integrity.bundle_root {
            return Err(BundleVerificationError::BundleRootMismatch {
                expected: self.integrity.bundle_root.clone(),
                actual: commitment.root,
            });
        }

        verify_bundle_root(
            &self.integrity.signature.value,
            &self.integrity.bundle_root,
            verifying_key,
        )?;

        Ok(VerificationSummary {
            artefact_count: self.artefacts.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerificationSummary {
    pub artefact_count: usize,
}

#[derive(Debug, Error)]
pub enum BundleVerificationError {
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonError),
    #[error("header digest mismatch; expected {expected}, got {actual}")]
    HeaderDigestMismatch { expected: String, actual: String },
    #[error("missing artefact bytes for {0}")]
    MissingArtefact(String),
    #[error("artefact size mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactSizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("artefact digest mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("bundle root mismatch; expected {expected}, got {actual}")]
    BundleRootMismatch { expected: String, actual: String },
    #[error("invalid digest format: {0}")]
    Digest(#[from] DigestError),
    #[error("unsupported canonicalization algorithm: {0}")]
    UnsupportedCanonicalization(String),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(String),
    #[error("unsupported bundle root algorithm: {0}")]
    UnsupportedBundleRootAlgorithm(String),
    #[error("unsupported signature format: {0}")]
    UnsupportedSignatureFormat(String),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("signature kid must not be empty")]
    EmptySignatureKid,
    #[error("signature value must not be empty")]
    EmptySignatureValue,
    #[error("duplicate artefact name found: {0}")]
    DuplicateArtefactName(String),
    #[error("invalid artefact name: {0}")]
    InvalidArtefactName(String),
    #[error("merkle commitment failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("signature verification failed: {0}")]
    Signature(#[from] VerifyBundleRootError),
}

pub fn validate_bundle_integrity_fields(
    bundle: &ProofBundle,
) -> Result<(), BundleVerificationError> {
    if bundle.integrity.canonicalization != CANONICALIZATION_ALGORITHM {
        return Err(BundleVerificationError::UnsupportedCanonicalization(
            bundle.integrity.canonicalization.clone(),
        ));
    }
    if bundle.integrity.hash != HASH_ALGORITHM {
        return Err(BundleVerificationError::UnsupportedHash(
            bundle.integrity.hash.clone(),
        ));
    }
    if bundle.integrity.bundle_root_algorithm != BUNDLE_ROOT_ALGORITHM {
        return Err(BundleVerificationError::UnsupportedBundleRootAlgorithm(
            bundle.integrity.bundle_root_algorithm.clone(),
        ));
    }
    if bundle.integrity.signature.format != SIGNATURE_FORMAT {
        return Err(BundleVerificationError::UnsupportedSignatureFormat(
            bundle.integrity.signature.format.clone(),
        ));
    }
    if bundle.integrity.signature.alg != SIGNATURE_ALGORITHM {
        return Err(BundleVerificationError::UnsupportedSignatureAlgorithm(
            bundle.integrity.signature.alg.clone(),
        ));
    }
    if bundle.integrity.signature.kid.trim().is_empty() {
        return Err(BundleVerificationError::EmptySignatureKid);
    }
    if bundle.integrity.signature.value.trim().is_empty() {
        return Err(BundleVerificationError::EmptySignatureValue);
    }

    parse_sha256_prefixed(&bundle.integrity.header_digest)?;
    parse_sha256_prefixed(&bundle.integrity.bundle_root)?;

    let mut seen_names = HashSet::with_capacity(bundle.artefacts.len());
    for artefact in &bundle.artefacts {
        validate_artefact_name(&artefact.name)?;
        if !seen_names.insert(artefact.name.clone()) {
            return Err(BundleVerificationError::DuplicateArtefactName(
                artefact.name.clone(),
            ));
        }
        parse_sha256_prefixed(&artefact.digest)?;
    }
    Ok(())
}

fn validate_artefact_name(name: &str) -> Result<(), BundleVerificationError> {
    if name.trim().is_empty() {
        return Err(BundleVerificationError::InvalidArtefactName(
            name.to_string(),
        ));
    }

    let path = Path::new(name);
    if path.is_absolute() {
        return Err(BundleVerificationError::InvalidArtefactName(
            name.to_string(),
        ));
    }

    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(BundleVerificationError::InvalidArtefactName(
                name.to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build::{ArtefactInput, build_bundle},
        sign::sign_bundle_root,
    };
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;

    fn sample_capture() -> CaptureInput {
        CaptureInput {
            actor: Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "dev".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
            },
            subject: Subject {
                request_id: "req-123".to_string(),
                thread_id: Some("thr-1".to_string()),
                user_ref: Some("hmac_sha256:abc".to_string()),
            },
            model: ModelInfo {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                parameters: serde_json::json!({"temperature": 0.2}),
            },
            inputs: Inputs {
                messages_commitment:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                retrieval_commitment: None,
            },
            outputs: Outputs {
                assistant_text_commitment:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                tool_outputs_commitment: None,
            },
            trace: Trace {
                otel_genai_semconv_version: "1.0.0".to_string(),
                trace_commitment:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
            },
            policy: Policy {
                redactions: vec![],
                encryption: EncryptionPolicy { enabled: false },
            },
        }
    }

    fn sample_artefacts() -> Vec<ArtefactInput> {
        vec![
            ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"prompt":"hello"}"#.to_vec(),
            },
            ArtefactInput {
                name: "response.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"response":"world"}"#.to_vec(),
            },
        ]
    }

    fn sample_bundle() -> (ProofBundle, SigningKey, BTreeMap<String, Vec<u8>>) {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let artefacts = sample_artefacts();
        let bytes = artefacts
            .iter()
            .map(|a| (a.name.clone(), a.bytes.clone()))
            .collect();
        let bundle = build_bundle(
            sample_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "PLTEST1234567890ABCDEF1234567890",
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
        )
        .expect("bundle build should succeed");
        (bundle, signing_key, bytes)
    }

    #[test]
    fn verify_happy_path_succeeds() {
        let (bundle, signing_key, artefacts) = sample_bundle();
        let verifying_key = signing_key.verifying_key();
        let summary = bundle
            .verify_with_artefacts(&artefacts, &verifying_key)
            .expect("bundle should verify");
        assert_eq!(summary.artefact_count, 2);
    }

    #[test]
    fn verify_fails_on_modified_artefact() {
        let (bundle, signing_key, mut artefacts) = sample_bundle();
        artefacts.insert("response.json".to_string(), b"tampered".to_vec());
        let verifying_key = signing_key.verifying_key();
        let err = bundle
            .verify_with_artefacts(&artefacts, &verifying_key)
            .expect_err("tampered artefact must fail");
        assert!(matches!(
            err,
            BundleVerificationError::ArtefactSizeMismatch { .. }
                | BundleVerificationError::ArtefactDigestMismatch { .. }
        ));
    }

    #[test]
    fn verify_fails_on_modified_header() {
        let (mut bundle, signing_key, artefacts) = sample_bundle();
        bundle.model.model = "different-model".to_string();
        let verifying_key = signing_key.verifying_key();
        let err = bundle
            .verify_with_artefacts(&artefacts, &verifying_key)
            .expect_err("modified header must fail");
        assert!(matches!(
            err,
            BundleVerificationError::HeaderDigestMismatch { .. }
        ));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (bundle, _signing_key, artefacts) = sample_bundle();
        let wrong_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>()).verifying_key();
        let err = bundle
            .verify_with_artefacts(&artefacts, &wrong_key)
            .expect_err("wrong key must fail");
        assert!(matches!(err, BundleVerificationError::Signature(_)));
    }

    #[test]
    fn reject_unknown_integrity_algorithms() {
        let (mut bundle, _signing_key, _artefacts) = sample_bundle();
        bundle.integrity.hash = "SHA-1".to_string();
        let err = validate_bundle_integrity_fields(&bundle).expect_err("unsupported hash");
        assert!(matches!(err, BundleVerificationError::UnsupportedHash(_)));
    }

    #[test]
    fn reject_duplicate_artefact_names() {
        let (mut bundle, signing_key, _artefacts) = sample_bundle();
        bundle.artefacts.push(bundle.artefacts[0].clone());
        bundle.integrity.signature.value = sign_bundle_root(
            &bundle.integrity.bundle_root,
            &signing_key,
            &bundle.integrity.signature.kid,
        )
        .expect("sign");
        let err = validate_bundle_integrity_fields(&bundle).expect_err("duplicate names");
        assert!(matches!(
            err,
            BundleVerificationError::DuplicateArtefactName(_)
        ));
    }
}
