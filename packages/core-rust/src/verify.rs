use crate::{
    hash::{DigestError, parse_sha256_prefixed},
    sign::JwsHeader,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyBundleRootError {
    #[error("JWS compact serialization must have exactly 3 segments")]
    InvalidCompact,
    #[error("base64url decode failed for {segment}: {message}")]
    Base64Decode {
        segment: &'static str,
        message: String,
    },
    #[error("JWS header is invalid JSON: {0}")]
    InvalidHeader(#[from] serde_json::Error),
    #[error("unsupported JWS algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("payload does not match expected bundle_root")]
    PayloadMismatch,
    #[error("bundle_root digest is invalid: {0}")]
    InvalidBundleRoot(#[from] DigestError),
    #[error("signature bytes are invalid: {0}")]
    InvalidSignatureBytes(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
}

pub fn verify_bundle_root(
    jws: &str,
    bundle_root: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), VerifyBundleRootError> {
    parse_sha256_prefixed(bundle_root)?;

    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyBundleRootError::InvalidCompact);
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(parts[0]).map_err(|err| {
        VerifyBundleRootError::Base64Decode {
            segment: "header",
            message: err.to_string(),
        }
    })?;
    let payload_bytes = Base64UrlUnpadded::decode_vec(parts[1]).map_err(|err| {
        VerifyBundleRootError::Base64Decode {
            segment: "payload",
            message: err.to_string(),
        }
    })?;
    let signature_bytes = Base64UrlUnpadded::decode_vec(parts[2]).map_err(|err| {
        VerifyBundleRootError::Base64Decode {
            segment: "signature",
            message: err.to_string(),
        }
    })?;

    let header: JwsHeader = serde_json::from_slice(&header_bytes)?;
    if header.alg != "EdDSA" {
        return Err(VerifyBundleRootError::UnsupportedAlgorithm(header.alg));
    }

    if payload_bytes != bundle_root.as_bytes() {
        return Err(VerifyBundleRootError::PayloadMismatch);
    }

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|err| VerifyBundleRootError::InvalidSignatureBytes(err.to_string()))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|err| VerifyBundleRootError::Signature(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::sign_bundle_root;

    fn split_jws(jws: &str) -> (String, String, String) {
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        (
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        )
    }

    #[test]
    fn tampered_header_fails_verification() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let jws = sign_bundle_root(bundle_root, &signing_key, "kid-dev-01").unwrap();
        let (_h, payload, signature) = split_jws(&jws);

        let tampered_header_json = br#"{"alg":"EdDSA","kid":"kid-attacker"}"#;
        let tampered_header = Base64UrlUnpadded::encode_string(tampered_header_json);
        let tampered = format!("{tampered_header}.{payload}.{signature}");

        let err = verify_bundle_root(&tampered, bundle_root, &verifying_key).unwrap_err();
        assert!(matches!(err, VerifyBundleRootError::Signature(_)));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let jws = sign_bundle_root(bundle_root, &signing_key, "kid-dev-01").unwrap();
        let (header, _payload, signature) = split_jws(&jws);

        let tampered_payload = Base64UrlUnpadded::encode_string(
            b"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let tampered = format!("{header}.{tampered_payload}.{signature}");

        let err = verify_bundle_root(&tampered, bundle_root, &verifying_key).unwrap_err();
        assert!(matches!(err, VerifyBundleRootError::PayloadMismatch));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();
        let bundle_root = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let jws = sign_bundle_root(bundle_root, &signing_key, "kid-dev-01").unwrap();
        let (header, payload, mut signature) = split_jws(&jws);
        signature.push('A');
        let tampered = format!("{header}.{payload}.{signature}");

        let err = verify_bundle_root(&tampered, bundle_root, &verifying_key).unwrap_err();
        assert!(matches!(
            err,
            VerifyBundleRootError::Base64Decode { .. }
                | VerifyBundleRootError::InvalidSignatureBytes(_)
                | VerifyBundleRootError::Signature(_)
        ));
    }
}
