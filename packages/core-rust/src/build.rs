use crate::{
    bundle::{
        ArtefactMeta, BUNDLE_ROOT_ALGORITHM, CANONICALIZATION_ALGORITHM, CaptureInput,
        HASH_ALGORITHM, Integrity, ProofBundle, SIGNATURE_ALGORITHM, SIGNATURE_FORMAT,
        SignatureInfo,
    },
    canonicalize::CanonError,
    hash::sha256_prefixed,
    merkle::{MerkleError, compute_commitment},
    sign::{SignError, sign_bundle_root},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ArtefactInput {
    pub name: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum BuildBundleError {
    #[error("artifact list cannot be empty")]
    EmptyArtefacts,
    #[error("artifact name cannot be empty")]
    EmptyArtefactName,
    #[error("duplicate artifact name found: {0}")]
    DuplicateArtefactName(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonError),
    #[error("merkle commitment failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("signing failed: {0}")]
    Signing(#[from] SignError),
}

pub fn build_bundle(
    capture: CaptureInput,
    artefacts: &[ArtefactInput],
    signing_key: &SigningKey,
    kid: &str,
    bundle_id: &str,
    created_at: DateTime<Utc>,
) -> Result<ProofBundle, BuildBundleError> {
    if artefacts.is_empty() {
        return Err(BuildBundleError::EmptyArtefacts);
    }

    let mut seen_names = HashSet::with_capacity(artefacts.len());
    let mut artefact_meta = Vec::with_capacity(artefacts.len());
    for artefact in artefacts {
        if artefact.name.trim().is_empty() {
            return Err(BuildBundleError::EmptyArtefactName);
        }
        if !seen_names.insert(artefact.name.clone()) {
            return Err(BuildBundleError::DuplicateArtefactName(
                artefact.name.clone(),
            ));
        }

        artefact_meta.push(ArtefactMeta {
            name: artefact.name.clone(),
            digest: sha256_prefixed(&artefact.bytes),
            size: artefact.bytes.len() as u64,
            content_type: artefact.content_type.clone(),
        });
    }

    let mut bundle = ProofBundle {
        bundle_version: "0.1".to_string(),
        bundle_id: bundle_id.to_string(),
        created_at: created_at.to_rfc3339(),
        actor: capture.actor,
        subject: capture.subject,
        model: capture.model,
        inputs: capture.inputs,
        outputs: capture.outputs,
        trace: capture.trace,
        artefacts: artefact_meta,
        policy: capture.policy,
        integrity: Integrity {
            canonicalization: CANONICALIZATION_ALGORITHM.to_string(),
            hash: HASH_ALGORITHM.to_string(),
            header_digest: String::new(),
            bundle_root_algorithm: BUNDLE_ROOT_ALGORITHM.to_string(),
            bundle_root: String::new(),
            signature: SignatureInfo {
                format: SIGNATURE_FORMAT.to_string(),
                alg: SIGNATURE_ALGORITHM.to_string(),
                kid: kid.to_string(),
                value: String::new(),
            },
        },
        timestamp: None,
        receipt: None,
    };

    let canonical_header = bundle.canonical_header_bytes()?;
    let header_digest = sha256_prefixed(&canonical_header);

    let mut ordered_digests = Vec::with_capacity(1 + bundle.artefacts.len());
    ordered_digests.push(header_digest.clone());
    ordered_digests.extend(bundle.artefacts.iter().map(|entry| entry.digest.clone()));

    let commitment = compute_commitment(&ordered_digests)?;
    let signature_value = sign_bundle_root(&commitment.root, signing_key, kid)?;

    bundle.integrity.header_digest = header_digest;
    bundle.integrity.bundle_root = commitment.root;
    bundle.integrity.bundle_root_algorithm = commitment.algorithm;
    bundle.integrity.signature.value = signature_value;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Actor, CaptureInput, EncryptionPolicy, Inputs, ModelInfo, Outputs, Policy, Subject, Trace,
    };
    use chrono::TimeZone;

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

    #[test]
    fn build_bundle_creates_integrity_fields() {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

        let artefacts = vec![ArtefactInput {
            name: "prompt.json".to_string(),
            content_type: "application/json".to_string(),
            bytes: br#"{"hello":"world"}"#.to_vec(),
        }];

        let bundle = build_bundle(
            sample_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
        )
        .expect("bundle build should succeed");

        assert_eq!(bundle.bundle_version, "0.1");
        assert!(bundle.integrity.header_digest.starts_with("sha256:"));
        assert!(bundle.integrity.bundle_root.starts_with("sha256:"));
        assert!(!bundle.integrity.signature.value.is_empty());
    }

    #[test]
    fn duplicate_artefact_names_are_rejected() {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

        let artefacts = vec![
            ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"hello":"world"}"#.to_vec(),
            },
            ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"hello":"again"}"#.to_vec(),
            },
        ];

        let err = build_bundle(
            sample_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
        )
        .expect_err("duplicate names should fail");

        assert!(matches!(err, BuildBundleError::DuplicateArtefactName(_)));
    }

    #[test]
    fn build_bundle_is_deterministic_for_fixed_inputs() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let artefacts = vec![
            ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"hello":"world"}"#.to_vec(),
            },
            ArtefactInput {
                name: "response.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"answer":"42"}"#.to_vec(),
            },
        ];

        let created_at = Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap();
        let bundle_a = build_bundle(
            sample_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "PLFIXEDTESTBUNDLE0000000000000001",
            created_at,
        )
        .expect("bundle build should succeed");
        let bundle_b = build_bundle(
            sample_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "PLFIXEDTESTBUNDLE0000000000000001",
            created_at,
        )
        .expect("bundle build should succeed");

        assert_eq!(
            bundle_a.integrity.header_digest,
            bundle_b.integrity.header_digest
        );
        assert_eq!(
            bundle_a.integrity.bundle_root,
            bundle_b.integrity.bundle_root
        );
        assert_eq!(
            bundle_a.integrity.signature.value,
            bundle_b.integrity.signature.value
        );
    }
}
