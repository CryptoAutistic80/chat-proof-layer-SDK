use crate::{
    hash::sha256_prefixed,
    merkle::{MerkleError, compute_commitment},
    schema::migration::capture_input_v01_to_event,
    schema::{
        ArtefactRef, BUNDLE_ROOT_ALGORITHM, BUNDLE_VERSION, CANONICALIZATION_ALGORITHM,
        CaptureEvent, HASH_ALGORITHM, Integrity, ProofBundle, SIGNATURE_ALGORITHM,
        SIGNATURE_FORMAT, SignatureInfo, v01,
    },
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

#[derive(Debug, Clone)]
pub enum BundleBuildInput {
    V10(CaptureEvent),
    V01(v01::CaptureInput),
}

impl From<CaptureEvent> for BundleBuildInput {
    fn from(value: CaptureEvent) -> Self {
        Self::V10(value)
    }
}

impl From<v01::CaptureInput> for BundleBuildInput {
    fn from(value: v01::CaptureInput) -> Self {
        Self::V01(value)
    }
}

#[derive(Debug, Error)]
pub enum BuildBundleError {
    #[error("artifact list cannot be empty")]
    EmptyArtefacts,
    #[error("artifact name cannot be empty")]
    EmptyArtefactName,
    #[error("duplicate artifact name found: {0}")]
    DuplicateArtefactName(String),
    #[error("bundle_id must not be empty")]
    EmptyBundleId,
    #[error("capture event must contain at least one evidence item")]
    EmptyItems,
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] crate::canon::CanonError),
    #[error("merkle commitment failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("signing failed: {0}")]
    Signing(#[from] SignError),
}

pub fn build_bundle(
    capture: impl Into<BundleBuildInput>,
    artefacts: &[ArtefactInput],
    signing_key: &SigningKey,
    kid: &str,
    bundle_id: &str,
    created_at: DateTime<Utc>,
) -> Result<ProofBundle, BuildBundleError> {
    if artefacts.is_empty() {
        return Err(BuildBundleError::EmptyArtefacts);
    }
    if bundle_id.trim().is_empty() {
        return Err(BuildBundleError::EmptyBundleId);
    }

    let mut event = match capture.into() {
        BundleBuildInput::V10(event) => event,
        BundleBuildInput::V01(legacy) => capture_input_v01_to_event(legacy),
    };
    if event.items.is_empty() {
        return Err(BuildBundleError::EmptyItems);
    }
    event.actor.signing_key_id = kid.to_string();

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

        artefact_meta.push(ArtefactRef {
            name: artefact.name.clone(),
            digest: sha256_prefixed(&artefact.bytes),
            size: artefact.bytes.len() as u64,
            content_type: artefact.content_type.clone(),
        });
    }

    let mut bundle = ProofBundle {
        bundle_version: BUNDLE_VERSION.to_string(),
        bundle_id: bundle_id.to_string(),
        created_at: created_at.to_rfc3339(),
        actor: event.actor,
        subject: event.subject,
        compliance_profile: event.compliance_profile,
        context: event.context,
        items: event.items,
        artefacts: artefact_meta,
        policy: event.policy,
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
    bundle.integrity.header_digest = header_digest.clone();

    let commitment = compute_commitment(&bundle.commitment_digests()?)?;
    let signature_value = sign_bundle_root(&commitment.root, signing_key, kid)?;

    bundle.integrity.bundle_root = commitment.root;
    bundle.integrity.bundle_root_algorithm = BUNDLE_ROOT_ALGORITHM.to_string();
    bundle.integrity.signature.value = signature_value;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bundle::{
            Actor, ActorRole, CaptureEvent, EncryptionPolicy, EvidenceContext, EvidenceItem,
            LlmInteractionEvidence, Policy, Subject,
        },
        bundle::{CaptureInput, Inputs, ModelInfo, Outputs, Trace},
    };
    use chrono::TimeZone;
    use serde_json::json;

    fn sample_legacy_capture() -> CaptureInput {
        CaptureInput {
            actor: crate::schema::v01::Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "dev".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
            },
            subject: crate::schema::v01::Subject {
                request_id: "req-123".to_string(),
                thread_id: Some("thr-1".to_string()),
                user_ref: Some("hmac_sha256:abc".to_string()),
            },
            model: ModelInfo {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                parameters: json!({"temperature": 0.2}),
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
                retention_class: None,
            },
        }
    }

    fn sample_v10_capture() -> CaptureEvent {
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
                system_id: Some("system-1".to_string()),
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
                latency_ms: None,
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
                retention_class: Some("runtime_logs".to_string()),
            },
        }
    }

    #[test]
    fn build_bundle_from_legacy_input_creates_v10_bundle() {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let artefacts = vec![ArtefactInput {
            name: "prompt.json".to_string(),
            content_type: "application/json".to_string(),
            bytes: br#"{"hello":"world"}"#.to_vec(),
        }];

        let bundle = build_bundle(
            sample_legacy_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
        )
        .expect("bundle build should succeed");

        assert_eq!(bundle.bundle_version, BUNDLE_VERSION);
        assert_eq!(bundle.items.len(), 1);
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
            sample_legacy_capture(),
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
            sample_v10_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "PLFIXEDTESTBUNDLE0000000000000001",
            created_at,
        )
        .expect("bundle build should succeed");
        let bundle_b = build_bundle(
            sample_v10_capture(),
            &artefacts,
            &signing_key,
            "kid-dev-01",
            "PLFIXEDTESTBUNDLE0000000000000001",
            created_at,
        )
        .expect("bundle build should succeed");

        assert_eq!(
            bundle_a.canonical_header_bytes().unwrap(),
            bundle_b.canonical_header_bytes().unwrap()
        );
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
