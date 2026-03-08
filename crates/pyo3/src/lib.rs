use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use proof_layer_core::{
    ArtefactInput, BundleBuildInput, CaptureEvent, LegacyCaptureInput, ProofBundle, RedactedBundle,
    build_bundle, canonicalize_json_strict, compute_commitment, decode_private_key_pem,
    decode_public_key_pem, redact_bundle, sha256_prefixed,
    sign_bundle_root as sign_bundle_root_core, validate_bundle_integrity_fields,
    verify_bundle_root as verify_bundle_root_core, verify_redacted_bundle,
};
use pyo3::{Bound, exceptions::PyValueError, prelude::*, types::PyModule};
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

fn py_value_error(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

#[pyfunction]
fn canonicalize(json_bytes: &[u8]) -> PyResult<Vec<u8>> {
    canonicalize_json_strict(json_bytes).map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn hash_sha256(data: &[u8]) -> String {
    sha256_prefixed(data)
}

#[pyfunction]
fn compute_merkle_root(digests: Vec<String>) -> PyResult<String> {
    compute_commitment(&digests)
        .map(|commitment| commitment.root)
        .map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn sign_bundle_root(root: &str, key_pem: &str, kid: &str) -> PyResult<String> {
    let signing_key =
        decode_private_key_pem(key_pem).map_err(|err| py_value_error(err.to_string()))?;
    sign_bundle_root_core(root, &signing_key, kid).map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn verify_bundle_root(jws: &str, expected_root: &str, pub_key_pem: &str) -> PyResult<bool> {
    let verifying_key =
        decode_public_key_pem(pub_key_pem).map_err(|err| py_value_error(err.to_string()))?;
    verify_bundle_root_core(jws, expected_root, &verifying_key)
        .map(|_| true)
        .map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn verify_bundle(bundle_json: &str, artefacts_json: &str, pub_key_pem: &str) -> PyResult<String> {
    let bundle: ProofBundle =
        serde_json::from_str(bundle_json).map_err(|err| py_value_error(err.to_string()))?;
    validate_bundle_integrity_fields(&bundle).map_err(|err| py_value_error(err.to_string()))?;

    let artefacts: Vec<VerifyArtefact> =
        serde_json::from_str(artefacts_json).map_err(|err| py_value_error(err.to_string()))?;
    let mut artefact_map = BTreeMap::new();
    for artefact in artefacts {
        let bytes = Base64::decode_vec(&artefact.data_base64).map_err(|err| {
            py_value_error(format!("invalid base64 for {}: {err}", artefact.name))
        })?;
        artefact_map.insert(artefact.name, bytes);
    }

    let verifying_key =
        decode_public_key_pem(pub_key_pem).map_err(|err| py_value_error(err.to_string()))?;
    let summary = bundle
        .verify_with_artefacts(&artefact_map, &verifying_key)
        .map_err(|err| py_value_error(err.to_string()))?;

    serde_json::to_string(&serde_json::json!({
        "artefact_count": summary.artefact_count,
    }))
    .map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn redact_bundle_json(
    bundle_json: &str,
    item_indices_json: &str,
    artefact_indices_json: &str,
) -> PyResult<String> {
    let bundle: ProofBundle =
        serde_json::from_str(bundle_json).map_err(|err| py_value_error(err.to_string()))?;
    let item_indices: Vec<usize> =
        serde_json::from_str(item_indices_json).map_err(|err| py_value_error(err.to_string()))?;
    let artefact_indices: Vec<usize> = serde_json::from_str(artefact_indices_json)
        .map_err(|err| py_value_error(err.to_string()))?;

    let redacted = redact_bundle(&bundle, &item_indices, &artefact_indices)
        .map_err(|err| py_value_error(err.to_string()))?;
    serde_json::to_string(&redacted).map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn verify_redacted_bundle_json(
    bundle_json: &str,
    artefacts_json: &str,
    pub_key_pem: &str,
) -> PyResult<String> {
    let bundle: RedactedBundle =
        serde_json::from_str(bundle_json).map_err(|err| py_value_error(err.to_string()))?;

    let artefacts: Vec<VerifyArtefact> =
        serde_json::from_str(artefacts_json).map_err(|err| py_value_error(err.to_string()))?;
    let mut artefact_map = BTreeMap::new();
    for artefact in artefacts {
        let bytes = Base64::decode_vec(&artefact.data_base64).map_err(|err| {
            py_value_error(format!("invalid base64 for {}: {err}", artefact.name))
        })?;
        artefact_map.insert(artefact.name, bytes);
    }

    let verifying_key =
        decode_public_key_pem(pub_key_pem).map_err(|err| py_value_error(err.to_string()))?;
    let summary = verify_redacted_bundle(&bundle, &artefact_map, &verifying_key)
        .map_err(|err| py_value_error(err.to_string()))?;

    serde_json::to_string(&serde_json::json!({
        "disclosed_item_count": summary.disclosed_item_count,
        "disclosed_artefact_count": summary.disclosed_artefact_count,
    }))
    .map_err(|err| py_value_error(err.to_string()))
}

#[pyfunction]
fn build_bundle_json(
    capture_json: &str,
    artefacts_json: &str,
    key_pem: &str,
    kid: &str,
    bundle_id: &str,
    created_at: &str,
) -> PyResult<String> {
    let capture = serde_json::from_str::<CaptureEvent>(capture_json)
        .map(BundleBuildInput::from)
        .or_else(|_| {
            serde_json::from_str::<LegacyCaptureInput>(capture_json).map(BundleBuildInput::from)
        })
        .map_err(|err| py_value_error(err.to_string()))?;

    let artefacts: Vec<BuildArtefact> =
        serde_json::from_str(artefacts_json).map_err(|err| py_value_error(err.to_string()))?;
    let artefact_inputs = artefacts
        .into_iter()
        .map(|artefact| {
            let bytes = Base64::decode_vec(&artefact.data_base64).map_err(|err| {
                py_value_error(format!("invalid base64 for {}: {err}", artefact.name))
            })?;
            Ok(ArtefactInput {
                name: artefact.name,
                content_type: artefact
                    .content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                bytes,
            })
        })
        .collect::<PyResult<Vec<_>>>()?;

    let signing_key =
        decode_private_key_pem(key_pem).map_err(|err| py_value_error(err.to_string()))?;
    let created_at = DateTime::parse_from_rfc3339(created_at)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| py_value_error(err.to_string()))?;

    let bundle = build_bundle(
        capture,
        &artefact_inputs,
        &signing_key,
        kid,
        bundle_id,
        created_at,
    )
    .map_err(|err| py_value_error(err.to_string()))?;

    serde_json::to_string(&bundle).map_err(|err| py_value_error(err.to_string()))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonicalize, m)?)?;
    m.add_function(wrap_pyfunction!(hash_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(compute_merkle_root, m)?)?;
    m.add_function(wrap_pyfunction!(sign_bundle_root, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bundle_root, m)?)?;
    m.add_function(wrap_pyfunction!(build_bundle_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(redact_bundle_json, m)?)?;
    m.add_function(wrap_pyfunction!(verify_redacted_bundle_json, m)?)?;
    Ok(())
}
