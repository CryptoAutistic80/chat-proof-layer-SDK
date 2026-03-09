use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use napi::{Error, Result, bindgen_prelude::Buffer};
use napi_derive::napi;
use proof_layer_core::{
    ArtefactInput, BundleBuildInput, CaptureEvent, LegacyCaptureInput, ProofBundle, RedactedBundle,
    build_bundle, canonicalize_json_strict, compute_commitment, decode_private_key_pem,
    decode_public_key_pem, redact_bundle, redact_bundle_with_field_redactions, sha256_prefixed,
    sign_bundle_root, validate_bundle_integrity_fields, verify_bundle_root, verify_redacted_bundle,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct VerifyArtefact {
    name: String,
    data_base64: String,
}

#[derive(Debug, Deserialize)]
struct BuildArtefact {
    name: String,
    #[serde(default)]
    content_type: Option<String>,
    data_base64: String,
}

fn napi_error(message: impl Into<String>) -> Error {
    Error::from_reason(message.into())
}

#[napi(js_name = "canonicalizeJson")]
pub fn canonicalize_json(input: Buffer) -> Result<Buffer> {
    canonicalize_json_strict(input.as_ref())
        .map(Buffer::from)
        .map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "hashSha256")]
pub fn hash_sha256(data: Buffer) -> String {
    sha256_prefixed(data.as_ref())
}

#[napi(js_name = "computeMerkleRoot")]
pub fn compute_merkle_root(digests: Vec<String>) -> Result<String> {
    compute_commitment(&digests)
        .map(|commitment| commitment.root)
        .map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "signBundleRoot")]
pub fn sign_bundle_root_native(
    bundle_root: String,
    key_pem: String,
    kid: String,
) -> Result<String> {
    let signing_key =
        decode_private_key_pem(&key_pem).map_err(|err| napi_error(err.to_string()))?;
    sign_bundle_root(&bundle_root, &signing_key, &kid).map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "verifyBundleRoot")]
pub fn verify_bundle_root_native(
    jws: String,
    bundle_root: String,
    public_key_pem: String,
) -> Result<bool> {
    let verifying_key =
        decode_public_key_pem(&public_key_pem).map_err(|err| napi_error(err.to_string()))?;
    verify_bundle_root(&jws, &bundle_root, &verifying_key)
        .map(|_| true)
        .map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "verifyBundle")]
pub fn verify_bundle_native(
    bundle_json: String,
    artefacts_json: String,
    public_key_pem: String,
) -> Result<String> {
    let bundle: ProofBundle =
        serde_json::from_str(&bundle_json).map_err(|err| napi_error(err.to_string()))?;
    validate_bundle_integrity_fields(&bundle).map_err(|err| napi_error(err.to_string()))?;

    let artefacts: Vec<VerifyArtefact> =
        serde_json::from_str(&artefacts_json).map_err(|err| napi_error(err.to_string()))?;
    let mut artefact_map = BTreeMap::new();
    for artefact in artefacts {
        let bytes = Base64::decode_vec(&artefact.data_base64)
            .map_err(|err| napi_error(format!("invalid base64 for {}: {err}", artefact.name)))?;
        artefact_map.insert(artefact.name, bytes);
    }

    let verifying_key =
        decode_public_key_pem(&public_key_pem).map_err(|err| napi_error(err.to_string()))?;
    let summary = bundle
        .verify_with_artefacts(&artefact_map, &verifying_key)
        .map_err(|err| napi_error(err.to_string()))?;

    serde_json::to_string(&serde_json::json!({
        "artefact_count": summary.artefact_count,
    }))
    .map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "redactBundle")]
pub fn redact_bundle_native(
    bundle_json: String,
    item_indices_json: String,
    artefact_indices_json: String,
    field_redactions_json: String,
) -> Result<String> {
    let bundle: ProofBundle =
        serde_json::from_str(&bundle_json).map_err(|err| napi_error(err.to_string()))?;
    let item_indices: Vec<usize> =
        serde_json::from_str(&item_indices_json).map_err(|err| napi_error(err.to_string()))?;
    let artefact_indices: Vec<usize> =
        serde_json::from_str(&artefact_indices_json).map_err(|err| napi_error(err.to_string()))?;
    let field_redactions: BTreeMap<usize, Vec<String>> =
        serde_json::from_str(&field_redactions_json).map_err(|err| napi_error(err.to_string()))?;

    let redacted = if field_redactions.is_empty() {
        redact_bundle(&bundle, &item_indices, &artefact_indices)
    } else {
        redact_bundle_with_field_redactions(
            &bundle,
            &item_indices,
            &artefact_indices,
            &field_redactions,
        )
    }
    .map_err(|err| napi_error(err.to_string()))?;
    serde_json::to_string(&redacted).map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "verifyRedactedBundle")]
pub fn verify_redacted_bundle_native(
    bundle_json: String,
    artefacts_json: String,
    public_key_pem: String,
) -> Result<String> {
    let bundle: RedactedBundle =
        serde_json::from_str(&bundle_json).map_err(|err| napi_error(err.to_string()))?;

    let artefacts: Vec<VerifyArtefact> =
        serde_json::from_str(&artefacts_json).map_err(|err| napi_error(err.to_string()))?;
    let mut artefact_map = BTreeMap::new();
    for artefact in artefacts {
        let bytes = Base64::decode_vec(&artefact.data_base64)
            .map_err(|err| napi_error(format!("invalid base64 for {}: {err}", artefact.name)))?;
        artefact_map.insert(artefact.name, bytes);
    }

    let verifying_key =
        decode_public_key_pem(&public_key_pem).map_err(|err| napi_error(err.to_string()))?;
    let summary = verify_redacted_bundle(&bundle, &artefact_map, &verifying_key)
        .map_err(|err| napi_error(err.to_string()))?;

    serde_json::to_string(&serde_json::json!({
        "disclosed_item_count": summary.disclosed_item_count,
        "disclosed_artefact_count": summary.disclosed_artefact_count,
    }))
    .map_err(|err| napi_error(err.to_string()))
}

#[napi(js_name = "buildBundle")]
pub fn build_bundle_native(
    capture_json: String,
    artefacts_json: String,
    key_pem: String,
    kid: String,
    bundle_id: String,
    created_at: String,
) -> Result<String> {
    let capture = serde_json::from_str::<CaptureEvent>(&capture_json)
        .map(BundleBuildInput::from)
        .or_else(|_| {
            serde_json::from_str::<LegacyCaptureInput>(&capture_json).map(BundleBuildInput::from)
        })
        .map_err(|err| napi_error(err.to_string()))?;

    let artefacts: Vec<BuildArtefact> =
        serde_json::from_str(&artefacts_json).map_err(|err| napi_error(err.to_string()))?;
    let artefact_inputs = artefacts
        .into_iter()
        .map(|artefact| {
            let bytes = Base64::decode_vec(&artefact.data_base64).map_err(|err| {
                napi_error(format!("invalid base64 for {}: {err}", artefact.name))
            })?;
            Ok(ArtefactInput {
                name: artefact.name,
                content_type: artefact
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let signing_key =
        decode_private_key_pem(&key_pem).map_err(|err| napi_error(err.to_string()))?;
    let created_at = DateTime::parse_from_rfc3339(&created_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| napi_error(err.to_string()))?;

    let bundle = build_bundle(
        capture,
        &artefact_inputs,
        &signing_key,
        &kid,
        &bundle_id,
        created_at,
    )
    .map_err(|err| napi_error(err.to_string()))?;

    serde_json::to_string(&bundle).map_err(|err| napi_error(err.to_string()))
}
