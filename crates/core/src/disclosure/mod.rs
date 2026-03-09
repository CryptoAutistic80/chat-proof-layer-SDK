use crate::{
    canon::{CanonError, canonicalize_value},
    merkle::{InclusionProof, MerkleError, build_inclusion_proof, verify_inclusion_proof},
    schema::{
        Actor, ArtefactRef, BUNDLE_VERSION, EvidenceContext, EvidenceItem, Integrity, Policy,
        ProofBundle, Subject, TimestampToken, TransparencyReceipt, artefact_commitment_digest,
        field_commitment_digest, item_commitment_digest_for_algorithm,
        item_commitment_digest_from_fields, validate_bundle_integrity_fields,
    },
    verify::{VerifyBundleRootError, verify_bundle_root},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldRedactedItem {
    pub item_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revealed_data: BTreeMap<String, Value>,
    pub field_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisclosedItem {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<EvidenceItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_redacted_item: Option<FieldRedactedItem>,
    pub proof: InclusionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisclosedArtefact {
    pub index: usize,
    pub meta: ArtefactRef,
    pub proof: InclusionProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactedBundle {
    pub bundle_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub actor: Actor,
    pub subject: Subject,
    #[serde(default)]
    pub context: EvidenceContext,
    #[serde(default)]
    pub policy: Policy,
    pub integrity: Integrity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<TransparencyReceipt>,
    pub total_items: usize,
    pub total_artefacts: usize,
    pub header_proof: InclusionProof,
    #[serde(default)]
    pub disclosed_items: Vec<DisclosedItem>,
    #[serde(default)]
    pub disclosed_artefacts: Vec<DisclosedArtefact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedVerificationSummary {
    pub disclosed_item_count: usize,
    pub disclosed_artefact_count: usize,
}

#[derive(Debug, Error)]
pub enum DisclosureError {
    #[error(
        "selective disclosure requires bundle root algorithm pl-merkle-sha256-v2 or pl-merkle-sha256-v3"
    )]
    UnsupportedBundleRootAlgorithm,
    #[error("field-level redaction requires bundle root algorithm pl-merkle-sha256-v3")]
    FieldRedactionRequiresV3,
    #[error("redacted bundle version must be {expected}, got {actual}")]
    UnsupportedBundleVersion { expected: String, actual: String },
    #[error("bundle validation failed: {0}")]
    BundleValidation(#[from] crate::schema::BundleValidationError),
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonError),
    #[error("merkle operation failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("signature verification failed: {0}")]
    VerifyBundleRoot(#[from] VerifyBundleRootError),
    #[error("duplicate disclosed item index {0}")]
    DuplicateItemIndex(usize),
    #[error("field redaction was requested for undisclosed item index {0}")]
    FieldRedactionItemNotSelected(usize),
    #[error("duplicate disclosed artefact index {0}")]
    DuplicateArtefactIndex(usize),
    #[error("disclosed item index {index} is out of bounds for {len} items")]
    ItemIndexOutOfBounds { index: usize, len: usize },
    #[error("disclosed artefact index {index} is out of bounds for {len} artefacts")]
    ArtefactIndexOutOfBounds { index: usize, len: usize },
    #[error("header digest mismatch; expected {expected}, got {actual}")]
    HeaderDigestMismatch { expected: String, actual: String },
    #[error("header proof root mismatch")]
    HeaderProofRootMismatch,
    #[error("header proof leaf mismatch")]
    HeaderProofLeafMismatch,
    #[error("header proof index must be 0")]
    HeaderProofIndexMismatch,
    #[error("item digest mismatch at disclosed index {index}; expected {expected}, got {actual}")]
    ItemDigestMismatch {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error("item proof root mismatch at disclosed index {0}")]
    ItemProofRootMismatch(usize),
    #[error("item proof leaf mismatch at disclosed index {0}")]
    ItemProofLeafMismatch(usize),
    #[error(
        "disclosed item at index {index} must include exactly one of item or field_redacted_item"
    )]
    InvalidDisclosedItemPayload { index: usize },
    #[error("item proof leaf index mismatch; expected {expected}, got {actual}")]
    ItemProofIndexMismatch { expected: usize, actual: usize },
    #[error("item field {field} is not present at disclosed index {index}")]
    UnknownItemField { index: usize, field: String },
    #[error(
        "disclosed item field digest mismatch at index {index} for field {field}; expected {expected}, got {actual}"
    )]
    FieldDigestMismatch {
        index: usize,
        field: String,
        expected: String,
        actual: String,
    },
    #[error("field redaction metadata mismatch at disclosed index {0}")]
    FieldRedactionMetadataMismatch(usize),
    #[error(
        "artefact commitment mismatch at disclosed index {index}; expected {expected}, got {actual}"
    )]
    ArtefactDigestMismatch {
        index: usize,
        expected: String,
        actual: String,
    },
    #[error("artefact proof root mismatch at disclosed index {0}")]
    ArtefactProofRootMismatch(usize),
    #[error("artefact proof leaf mismatch at disclosed index {0}")]
    ArtefactProofLeafMismatch(usize),
    #[error("artefact proof leaf index mismatch; expected {expected}, got {actual}")]
    ArtefactProofIndexMismatch { expected: usize, actual: usize },
    #[error("artefact bytes missing for disclosed artefact {0}")]
    MissingArtefactBytes(String),
    #[error("artefact size mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactSizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("artefact content digest mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactContentDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
}

pub fn redact_bundle(
    bundle: &ProofBundle,
    item_indices: &[usize],
    artefact_indices: &[usize],
) -> Result<RedactedBundle, DisclosureError> {
    redact_bundle_with_field_redactions(bundle, item_indices, artefact_indices, &BTreeMap::new())
}

pub fn redact_bundle_with_field_redactions(
    bundle: &ProofBundle,
    item_indices: &[usize],
    artefact_indices: &[usize],
    field_redactions: &BTreeMap<usize, Vec<String>>,
) -> Result<RedactedBundle, DisclosureError> {
    validate_bundle_integrity_fields(bundle)?;
    if !supports_selective_disclosure(&bundle.integrity.bundle_root_algorithm) {
        return Err(DisclosureError::UnsupportedBundleRootAlgorithm);
    }
    if bundle.integrity.bundle_root_algorithm == crate::schema::BUNDLE_ROOT_ALGORITHM_V2
        && !field_redactions.is_empty()
    {
        return Err(DisclosureError::FieldRedactionRequiresV3);
    }

    let digests = bundle.commitment_digests()?;
    let total_items = bundle.items.len();
    let total_artefacts = bundle.artefacts.len();

    let item_indices = normalize_indices(item_indices, total_items, true)?;
    let artefact_indices = normalize_indices(artefact_indices, total_artefacts, false)?;
    for index in field_redactions.keys() {
        if !item_indices.contains(index) {
            return Err(DisclosureError::FieldRedactionItemNotSelected(*index));
        }
    }

    let header_proof = build_inclusion_proof(&digests, 0)?;
    let disclosed_items = item_indices
        .into_iter()
        .map(|index| {
            let proof = build_inclusion_proof(&digests, 1 + index)?;
            let field_redacted_item = if bundle.integrity.bundle_root_algorithm
                == crate::schema::BUNDLE_ROOT_ALGORITHM_V3
            {
                build_field_redacted_item(
                    index,
                    &bundle.items[index],
                    field_redactions
                        .get(&index)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                )?
            } else {
                None
            };
            Ok(DisclosedItem {
                index,
                item: if field_redacted_item.is_some() {
                    None
                } else {
                    Some(bundle.items[index].clone())
                },
                field_redacted_item,
                proof,
            })
        })
        .collect::<Result<Vec<_>, DisclosureError>>()?;
    let disclosed_artefacts = artefact_indices
        .into_iter()
        .map(|index| {
            let proof = build_inclusion_proof(&digests, 1 + total_items + index)?;
            Ok(DisclosedArtefact {
                index,
                meta: bundle.artefacts[index].clone(),
                proof,
            })
        })
        .collect::<Result<Vec<_>, DisclosureError>>()?;

    Ok(RedactedBundle {
        bundle_version: bundle.bundle_version.clone(),
        bundle_id: bundle.bundle_id.clone(),
        created_at: bundle.created_at.clone(),
        actor: bundle.actor.clone(),
        subject: bundle.subject.clone(),
        context: bundle.context.clone(),
        policy: bundle.policy.clone(),
        integrity: bundle.integrity.clone(),
        timestamp: bundle.timestamp.clone(),
        receipt: bundle.receipt.clone(),
        total_items,
        total_artefacts,
        header_proof,
        disclosed_items,
        disclosed_artefacts,
    })
}

pub fn verify_redacted_bundle(
    bundle: &RedactedBundle,
    artefacts: &BTreeMap<String, Vec<u8>>,
    verifying_key: &VerifyingKey,
) -> Result<RedactedVerificationSummary, DisclosureError> {
    if bundle.bundle_version != BUNDLE_VERSION {
        return Err(DisclosureError::UnsupportedBundleVersion {
            expected: BUNDLE_VERSION.to_string(),
            actual: bundle.bundle_version.clone(),
        });
    }
    if !supports_selective_disclosure(&bundle.integrity.bundle_root_algorithm) {
        return Err(DisclosureError::UnsupportedBundleRootAlgorithm);
    }

    let canonical_header = canonicalize_value(&commitment_header_projection(bundle))?;
    let computed_header_digest = crate::hash::sha256_prefixed(&canonical_header);
    if computed_header_digest != bundle.integrity.header_digest {
        return Err(DisclosureError::HeaderDigestMismatch {
            expected: bundle.integrity.header_digest.clone(),
            actual: computed_header_digest,
        });
    }
    if bundle.header_proof.index != 0 {
        return Err(DisclosureError::HeaderProofIndexMismatch);
    }
    if bundle.header_proof.root != bundle.integrity.bundle_root {
        return Err(DisclosureError::HeaderProofRootMismatch);
    }
    if bundle.header_proof.leaf != bundle.integrity.header_digest {
        return Err(DisclosureError::HeaderProofLeafMismatch);
    }
    if !verify_inclusion_proof(&bundle.header_proof)? {
        return Err(DisclosureError::HeaderProofRootMismatch);
    }

    verify_bundle_root(
        &bundle.integrity.signature.value,
        &bundle.integrity.bundle_root,
        verifying_key,
    )?;

    let mut seen_item_indices = BTreeSet::new();
    for disclosed in &bundle.disclosed_items {
        if !seen_item_indices.insert(disclosed.index) {
            return Err(DisclosureError::DuplicateItemIndex(disclosed.index));
        }
        if disclosed.index >= bundle.total_items {
            return Err(DisclosureError::ItemIndexOutOfBounds {
                index: disclosed.index,
                len: bundle.total_items,
            });
        }
        let expected_digest =
            disclosed_item_digest(disclosed, &bundle.integrity.bundle_root_algorithm)?;
        if disclosed.proof.index != 1 + disclosed.index {
            return Err(DisclosureError::ItemProofIndexMismatch {
                expected: 1 + disclosed.index,
                actual: disclosed.proof.index,
            });
        }
        if disclosed.proof.root != bundle.integrity.bundle_root {
            return Err(DisclosureError::ItemProofRootMismatch(disclosed.index));
        }
        if disclosed.proof.leaf != expected_digest {
            return Err(DisclosureError::ItemDigestMismatch {
                index: disclosed.index,
                expected: disclosed.proof.leaf.clone(),
                actual: expected_digest,
            });
        }
        if !verify_inclusion_proof(&disclosed.proof)? {
            return Err(DisclosureError::ItemProofLeafMismatch(disclosed.index));
        }
    }

    let mut seen_artefact_indices = BTreeSet::new();
    for disclosed in &bundle.disclosed_artefacts {
        if !seen_artefact_indices.insert(disclosed.index) {
            return Err(DisclosureError::DuplicateArtefactIndex(disclosed.index));
        }
        if disclosed.index >= bundle.total_artefacts {
            return Err(DisclosureError::ArtefactIndexOutOfBounds {
                index: disclosed.index,
                len: bundle.total_artefacts,
            });
        }
        let expected_leaf = artefact_commitment_digest(&disclosed.meta)?;
        if disclosed.proof.index != 1 + bundle.total_items + disclosed.index {
            return Err(DisclosureError::ArtefactProofIndexMismatch {
                expected: 1 + bundle.total_items + disclosed.index,
                actual: disclosed.proof.index,
            });
        }
        if disclosed.proof.root != bundle.integrity.bundle_root {
            return Err(DisclosureError::ArtefactProofRootMismatch(disclosed.index));
        }
        if disclosed.proof.leaf != expected_leaf {
            return Err(DisclosureError::ArtefactDigestMismatch {
                index: disclosed.index,
                expected: disclosed.proof.leaf.clone(),
                actual: expected_leaf,
            });
        }
        if !verify_inclusion_proof(&disclosed.proof)? {
            return Err(DisclosureError::ArtefactProofLeafMismatch(disclosed.index));
        }
        if let Some(bytes) = artefacts.get(&disclosed.meta.name) {
            if disclosed.meta.size != bytes.len() as u64 {
                return Err(DisclosureError::ArtefactSizeMismatch {
                    name: disclosed.meta.name.clone(),
                    expected: disclosed.meta.size,
                    actual: bytes.len() as u64,
                });
            }
            let digest = crate::hash::sha256_prefixed(bytes);
            if digest != disclosed.meta.digest {
                return Err(DisclosureError::ArtefactContentDigestMismatch {
                    name: disclosed.meta.name.clone(),
                    expected: disclosed.meta.digest.clone(),
                    actual: digest,
                });
            }
        }
    }

    Ok(RedactedVerificationSummary {
        disclosed_item_count: bundle.disclosed_items.len(),
        disclosed_artefact_count: bundle.disclosed_artefacts.len(),
    })
}

fn normalize_indices(
    indices: &[usize],
    len: usize,
    items: bool,
) -> Result<Vec<usize>, DisclosureError> {
    let mut normalized = Vec::with_capacity(indices.len());
    let mut seen = BTreeSet::new();
    for &index in indices {
        if index >= len {
            return Err(if items {
                DisclosureError::ItemIndexOutOfBounds { index, len }
            } else {
                DisclosureError::ArtefactIndexOutOfBounds { index, len }
            });
        }
        if !seen.insert(index) {
            return Err(if items {
                DisclosureError::DuplicateItemIndex(index)
            } else {
                DisclosureError::DuplicateArtefactIndex(index)
            });
        }
        normalized.push(index);
    }
    normalized.sort_unstable();
    Ok(normalized)
}

fn commitment_header_projection(bundle: &RedactedBundle) -> serde_json::Value {
    json!({
        "bundle_version": bundle.bundle_version,
        "bundle_id": bundle.bundle_id,
        "created_at": bundle.created_at,
        "actor": bundle.actor,
        "subject": bundle.subject,
        "context": bundle.context,
        "policy": bundle.policy,
        "item_count": bundle.total_items,
        "artefact_count": bundle.total_artefacts,
    })
}

fn supports_selective_disclosure(algorithm: &str) -> bool {
    algorithm == crate::schema::BUNDLE_ROOT_ALGORITHM_V2
        || algorithm == crate::schema::BUNDLE_ROOT_ALGORITHM_V3
}

fn disclosed_item_digest(
    disclosed: &DisclosedItem,
    algorithm: &str,
) -> Result<String, DisclosureError> {
    match algorithm {
        crate::schema::BUNDLE_ROOT_ALGORITHM_V2 => {
            match (&disclosed.item, &disclosed.field_redacted_item) {
                (Some(item), None) => item_commitment_digest_for_algorithm(item, algorithm)
                    .map_err(DisclosureError::Canonicalization),
                _ => Err(DisclosureError::InvalidDisclosedItemPayload {
                    index: disclosed.index,
                }),
            }
        }
        crate::schema::BUNDLE_ROOT_ALGORITHM_V3 => {
            match (&disclosed.item, &disclosed.field_redacted_item) {
                (Some(item), None) => item_commitment_digest_for_algorithm(item, algorithm)
                    .map_err(DisclosureError::Canonicalization),
                (None, Some(redacted)) => verify_field_redacted_item(disclosed.index, redacted),
                _ => Err(DisclosureError::InvalidDisclosedItemPayload {
                    index: disclosed.index,
                }),
            }
        }
        _ => Err(DisclosureError::UnsupportedBundleRootAlgorithm),
    }
}

fn build_field_redacted_item(
    index: usize,
    item: &EvidenceItem,
    requested_fields: &[String],
) -> Result<Option<FieldRedactedItem>, DisclosureError> {
    if requested_fields.is_empty() {
        return Ok(None);
    }

    let (item_type, data) = item_type_and_data(item)?;
    let requested_fields = requested_fields.iter().cloned().collect::<BTreeSet<_>>();
    for field in &requested_fields {
        if !data.contains_key(field) {
            return Err(DisclosureError::UnknownItemField {
                index,
                field: field.clone(),
            });
        }
    }

    let mut revealed_data = BTreeMap::new();
    let mut field_digests = BTreeMap::new();
    for (field, value) in &data {
        field_digests.insert(
            field.clone(),
            field_commitment_digest(value).map_err(DisclosureError::Canonicalization)?,
        );
        if !requested_fields.contains(field) {
            revealed_data.insert(field.clone(), value.clone());
        }
    }

    Ok(Some(FieldRedactedItem {
        item_type,
        revealed_data,
        field_digests,
        redacted_fields: requested_fields.into_iter().collect(),
    }))
}

fn verify_field_redacted_item(
    index: usize,
    item: &FieldRedactedItem,
) -> Result<String, DisclosureError> {
    let revealed_fields = item.revealed_data.keys().cloned().collect::<BTreeSet<_>>();
    let derived_redacted_fields = item
        .field_digests
        .keys()
        .filter(|field| !revealed_fields.contains(*field))
        .cloned()
        .collect::<Vec<_>>();
    if derived_redacted_fields != item.redacted_fields {
        return Err(DisclosureError::FieldRedactionMetadataMismatch(index));
    }

    for (field, value) in &item.revealed_data {
        let expected_digest = item
            .field_digests
            .get(field)
            .ok_or(DisclosureError::FieldRedactionMetadataMismatch(index))?;
        let actual_digest =
            field_commitment_digest(value).map_err(DisclosureError::Canonicalization)?;
        if &actual_digest != expected_digest {
            return Err(DisclosureError::FieldDigestMismatch {
                index,
                field: field.clone(),
                expected: expected_digest.clone(),
                actual: actual_digest,
            });
        }
    }

    item_commitment_digest_from_fields(&item.item_type, &item.field_digests)
        .map_err(DisclosureError::Canonicalization)
}

fn item_type_and_data(
    item: &EvidenceItem,
) -> Result<(String, BTreeMap<String, Value>), DisclosureError> {
    let value = serde_json::to_value(item)
        .map_err(CanonError::from)
        .map_err(DisclosureError::Canonicalization)?;
    let object = value.as_object().ok_or_else(|| {
        DisclosureError::Canonicalization(CanonError::Canonicalization(
            "evidence item must serialize to an object".to_string(),
        ))
    })?;
    let item_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DisclosureError::Canonicalization(CanonError::Canonicalization(
                "evidence item is missing its type tag".to_string(),
            ))
        })?
        .to_string();
    let data = object
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DisclosureError::Canonicalization(CanonError::Canonicalization(
                "evidence item must serialize object data".to_string(),
            ))
        })?;
    let data = data
        .iter()
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    Ok((item_type, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build::{ArtefactInput, build_bundle},
        schema::{
            Actor, ActorRole, CaptureEvent, EncryptionPolicy, EvidenceContext,
            LlmInteractionEvidence, Policy, Subject, ToolCallEvidence,
        },
    };
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn sample_bundle() -> ProofBundle {
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        build_bundle(
            CaptureEvent {
                actor: Actor {
                    issuer: "proof-layer-local".to_string(),
                    app_id: "demo".to_string(),
                    env: "test".to_string(),
                    signing_key_id: "kid-dev-01".to_string(),
                    role: ActorRole::Provider,
                    organization_id: None,
                },
                subject: Subject {
                    request_id: Some("req-123".to_string()),
                    thread_id: None,
                    user_ref: None,
                    system_id: Some("system-1".to_string()),
                    model_id: Some("anthropic:claude-sonnet-4-6".to_string()),
                    deployment_id: None,
                    version: Some("2026.03".to_string()),
                },
                context: EvidenceContext {
                    provider: Some("anthropic".to_string()),
                    model: Some("claude-sonnet-4-6".to_string()),
                    parameters: json!({"temperature": 0.2}),
                    trace_commitment: None,
                    otel_genai_semconv_version: None,
                },
                items: vec![
                    EvidenceItem::LlmInteraction(LlmInteractionEvidence {
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
                        trace_commitment: None,
                        trace_semconv_version: None,
                    }),
                    EvidenceItem::ToolCall(ToolCallEvidence {
                        tool_name: "search".to_string(),
                        input_commitment: Some(
                            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                .to_string(),
                        ),
                        output_commitment: Some(
                            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                .to_string(),
                        ),
                        metadata: json!({"source":"tool"}),
                    }),
                ],
                policy: Policy {
                    redactions: vec![],
                    encryption: EncryptionPolicy { enabled: false },
                    retention_class: Some("runtime_logs".to_string()),
                },
            },
            &[ArtefactInput {
                name: "prompt.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"prompt":"hello"}"#.to_vec(),
            }],
            &signing_key,
            "kid-dev-01",
            "01JPH3J11VJ5R9MZZZC0DISCLO",
            chrono::Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn redact_bundle_round_trips_selected_item() {
        let bundle = sample_bundle();
        let redacted = redact_bundle(&bundle, &[1], &[]).unwrap();
        let verifying_key = SigningKey::from_bytes(&[9_u8; 32]).verifying_key();
        let summary = verify_redacted_bundle(&redacted, &BTreeMap::new(), &verifying_key).unwrap();
        assert_eq!(summary.disclosed_item_count, 1);
        assert_eq!(summary.disclosed_artefact_count, 0);
        assert_eq!(redacted.total_items, 2);
        assert_eq!(redacted.header_proof.index, 0);
    }

    #[test]
    fn redact_bundle_round_trips_selected_item_with_field_redaction() {
        let bundle = sample_bundle();
        let redacted = redact_bundle_with_field_redactions(
            &bundle,
            &[0],
            &[],
            &BTreeMap::from([(0usize, vec!["output_commitment".to_string()])]),
        )
        .unwrap();
        let verifying_key = SigningKey::from_bytes(&[9_u8; 32]).verifying_key();
        let summary = verify_redacted_bundle(&redacted, &BTreeMap::new(), &verifying_key).unwrap();
        assert_eq!(summary.disclosed_item_count, 1);
        assert!(redacted.disclosed_items[0].item.is_none());
        let field_redacted_item = redacted.disclosed_items[0]
            .field_redacted_item
            .as_ref()
            .unwrap();
        assert_eq!(field_redacted_item.item_type, "llm_interaction");
        assert_eq!(
            field_redacted_item.redacted_fields,
            vec!["output_commitment".to_string()]
        );
        assert!(
            !field_redacted_item
                .revealed_data
                .contains_key("output_commitment")
        );
    }

    #[test]
    fn verify_redacted_bundle_rejects_tampered_revealed_field() {
        let bundle = sample_bundle();
        let mut redacted = redact_bundle_with_field_redactions(
            &bundle,
            &[0],
            &[],
            &BTreeMap::from([(0usize, vec!["output_commitment".to_string()])]),
        )
        .unwrap();
        let field_redacted_item = redacted.disclosed_items[0]
            .field_redacted_item
            .as_mut()
            .unwrap();
        field_redacted_item
            .revealed_data
            .insert("provider".to_string(), json!("tampered"));
        let verifying_key = SigningKey::from_bytes(&[9_u8; 32]).verifying_key();
        let err = verify_redacted_bundle(&redacted, &BTreeMap::new(), &verifying_key).unwrap_err();
        assert!(matches!(err, DisclosureError::FieldDigestMismatch { .. }));
    }

    #[test]
    fn field_redaction_requires_v3_commitment_layout() {
        let mut bundle = sample_bundle();
        bundle.integrity.bundle_root_algorithm =
            crate::schema::BUNDLE_ROOT_ALGORITHM_V2.to_string();
        let err = redact_bundle_with_field_redactions(
            &bundle,
            &[0],
            &[],
            &BTreeMap::from([(0usize, vec!["output_commitment".to_string()])]),
        )
        .unwrap_err();
        assert!(matches!(err, DisclosureError::FieldRedactionRequiresV3));
    }

    #[test]
    fn redact_bundle_rejects_legacy_commitment_layout() {
        let mut bundle = sample_bundle();
        bundle.integrity.bundle_root_algorithm =
            crate::schema::LEGACY_BUNDLE_ROOT_ALGORITHM.to_string();
        let err = redact_bundle(&bundle, &[0], &[]).unwrap_err();
        assert!(matches!(
            err,
            DisclosureError::UnsupportedBundleRootAlgorithm
        ));
    }
}
