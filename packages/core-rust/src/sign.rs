use crate::hash::{DigestError, parse_sha256_prefixed};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PRIVATE_PEM_BEGIN: &str = "-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----";
const PRIVATE_PEM_END: &str = "-----END PROOF LAYER ED25519 PRIVATE KEY-----";
const PUBLIC_PEM_BEGIN: &str = "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----";
const PUBLIC_PEM_END: &str = "-----END PROOF LAYER ED25519 PUBLIC KEY-----";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: String,
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("bundle_root digest is invalid: {0}")]
    InvalidBundleRoot(#[from] DigestError),
    #[error("kid must not be empty")]
    EmptyKid,
    #[error("failed to serialize JWS header: {0}")]
    HeaderSerialization(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum KeyEncodingError {
    #[error("invalid PEM header/footer")]
    InvalidPem,
    #[error("base64 key decode failed: {0}")]
    Base64(String),
    #[error("private key must be exactly 32 bytes")]
    InvalidPrivateKeyLength,
    #[error("public key must be exactly 32 bytes")]
    InvalidPublicKeyLength,
    #[error("invalid public key bytes: {0}")]
    InvalidPublicKey(String),
}

pub fn sign_bundle_root(
    bundle_root: &str,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<String, SignError> {
    parse_sha256_prefixed(bundle_root)?;
    if kid.trim().is_empty() {
        return Err(SignError::EmptyKid);
    }

    let header = JwsHeader {
        alg: "EdDSA".to_string(),
        kid: kid.to_owned(),
    };

    let header_json = serde_json::to_vec(&header)?;
    let header_b64 = Base64UrlUnpadded::encode_string(&header_json);
    let payload_b64 = Base64UrlUnpadded::encode_string(bundle_root.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());

    Ok(format!("{signing_input}.{signature_b64}"))
}

pub fn encode_private_key_pem(signing_key: &SigningKey) -> String {
    let payload = Base64::encode_string(&signing_key.to_bytes());
    format!("{PRIVATE_PEM_BEGIN}\n{payload}\n{PRIVATE_PEM_END}\n")
}

pub fn encode_public_key_pem(verifying_key: &VerifyingKey) -> String {
    let payload = Base64::encode_string(&verifying_key.to_bytes());
    format!("{PUBLIC_PEM_BEGIN}\n{payload}\n{PUBLIC_PEM_END}\n")
}

pub fn decode_private_key_pem(contents: &str) -> Result<SigningKey, KeyEncodingError> {
    let payload = extract_pem_payload(contents, PRIVATE_PEM_BEGIN, PRIVATE_PEM_END)?;
    let decoded =
        Base64::decode_vec(&payload).map_err(|err| KeyEncodingError::Base64(err.to_string()))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| KeyEncodingError::InvalidPrivateKeyLength)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn decode_public_key_pem(contents: &str) -> Result<VerifyingKey, KeyEncodingError> {
    let payload = extract_pem_payload(contents, PUBLIC_PEM_BEGIN, PUBLIC_PEM_END)?;
    let decoded =
        Base64::decode_vec(&payload).map_err(|err| KeyEncodingError::Base64(err.to_string()))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| KeyEncodingError::InvalidPublicKeyLength)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|err| KeyEncodingError::InvalidPublicKey(err.to_string()))
}

fn extract_pem_payload(contents: &str, begin: &str, end: &str) -> Result<String, KeyEncodingError> {
    let trimmed = contents.trim();
    let begin_pos = trimmed.find(begin).ok_or(KeyEncodingError::InvalidPem)?;
    let end_pos = trimmed.find(end).ok_or(KeyEncodingError::InvalidPem)?;
    if begin_pos != 0 || end_pos <= begin.len() {
        return Err(KeyEncodingError::InvalidPem);
    }

    let body = &trimmed[begin.len()..end_pos];
    let payload: String = body.lines().map(str::trim).collect();
    if payload.is_empty() {
        return Err(KeyEncodingError::InvalidPem);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verify_bundle_root;

    #[test]
    fn sign_and_verify_round_trip() {
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying = signing.verifying_key();

        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let jws = sign_bundle_root(bundle_root, &signing, "kid-1").expect("sign should work");
        verify_bundle_root(&jws, bundle_root, &verifying).expect("verify should pass");
    }

    #[test]
    fn key_pem_round_trip() {
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying = signing.verifying_key();

        let signing_pem = encode_private_key_pem(&signing);
        let verifying_pem = encode_public_key_pem(&verifying);

        let parsed_signing = decode_private_key_pem(&signing_pem).expect("private PEM parse");
        let parsed_verifying = decode_public_key_pem(&verifying_pem).expect("public PEM parse");

        assert_eq!(signing.to_bytes(), parsed_signing.to_bytes());
        assert_eq!(verifying.to_bytes(), parsed_verifying.to_bytes());
    }
}
