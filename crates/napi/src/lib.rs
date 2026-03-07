use base64ct::{Base64, Encoding};
use napi::{Error, Result, bindgen_prelude::Buffer};
use napi_derive::napi;
use proof_layer_core::{
    ProofBundle, canonicalize_json_strict, compute_commitment, decode_private_key_pem,
    decode_public_key_pem, sha256_prefixed, sign_bundle_root, validate_bundle_integrity_fields,
    verify_bundle_root,
};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct VerifyArtefact {
    name: String,
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
