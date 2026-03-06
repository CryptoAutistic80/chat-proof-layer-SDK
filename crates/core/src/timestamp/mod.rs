use crate::{
    hash::{DigestError, parse_sha256_prefixed},
    schema::TimestampToken,
};
use base64ct::{Base64, Encoding};
use bcder::{Mode, decode::Constructed};
use chrono::{DateTime, Utc};
use cryptographic_message_syntax::{
    SignedData, TimeStampError as CmsTimeStampError, asn1::rfc3161::TstInfo,
    time_stamp_message_http,
};
use thiserror::Error;
use x509_certificate::DigestAlgorithm;

pub const RFC3161_TIMESTAMP_KIND: &str = "rfc3161";
pub const DIGICERT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";
pub const FREETSA_TIMESTAMP_URL: &str = "https://freetsa.org/tsr";

pub trait TimestampProvider {
    fn timestamp(&self, digest: &str) -> Result<TimestampToken, TimestampError>;
}

#[derive(Debug, Clone)]
pub struct Rfc3161HttpTimestampProvider {
    url: String,
    provider_label: Option<String>,
}

impl Rfc3161HttpTimestampProvider {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_label(url, RFC3161_TIMESTAMP_KIND)
    }

    pub fn with_label(url: impl Into<String>, provider_label: impl Into<String>) -> Self {
        let provider_label = provider_label.into();
        Self {
            url: url.into(),
            provider_label: if provider_label.trim().is_empty() {
                None
            } else {
                Some(provider_label)
            },
        }
    }

    pub fn digicert() -> Self {
        Self::with_label(DIGICERT_TIMESTAMP_URL, "digicert")
    }

    pub fn freetsa() -> Self {
        Self::with_label(FREETSA_TIMESTAMP_URL, "freetsa")
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TimestampProvider for Rfc3161HttpTimestampProvider {
    fn timestamp(&self, digest: &str) -> Result<TimestampToken, TimestampError> {
        parse_sha256_prefixed(digest).map_err(TimestampError::InvalidDigest)?;

        let response =
            time_stamp_message_http(&self.url, digest.as_bytes(), DigestAlgorithm::Sha256)
                .map_err(TimestampError::Transport)?;
        if !response.is_success() {
            return Err(TimestampError::UnsuccessfulResponse);
        }

        let token_der = response
            .time_stamp_token
            .as_ref()
            .map(|token| token.content.clone().into_bytes())
            .ok_or(TimestampError::MissingToken)?
            .to_vec();

        let token = TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: self.provider_label.clone(),
            token_base64: Base64::encode_string(&token_der),
        };

        verify_timestamp(&token, digest)?;

        Ok(token)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimestampVerification {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub generated_at: String,
    pub digest_algorithm: String,
    pub message_imprint: String,
    pub signer_count: usize,
    pub certificate_count: usize,
}

#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("bundle root digest is invalid: {0}")]
    InvalidDigest(#[from] DigestError),
    #[error("timestamp token kind must be {RFC3161_TIMESTAMP_KIND}, got {0}")]
    UnsupportedKind(String),
    #[error("timestamp token base64 is invalid: {0}")]
    InvalidBase64(String),
    #[error("timestamp provider request failed: {0}")]
    Transport(#[source] CmsTimeStampError),
    #[error("timestamp response was not successful")]
    UnsuccessfulResponse,
    #[error("timestamp response did not include a token")]
    MissingToken,
    #[error("timestamp token CMS parse failed: {0}")]
    CmsParse(String),
    #[error("timestamp token TSTInfo parse failed: {0}")]
    TstInfoParse(String),
    #[error("timestamp token has no signers")]
    NoSigners,
    #[error("timestamp token has no encapsulated TSTInfo content")]
    MissingSignedContent,
    #[error("timestamp token signer verification failed: {0}")]
    SignerVerification(String),
    #[error("timestamp token uses unsupported message imprint algorithm: {0}")]
    UnsupportedImprintAlgorithm(String),
    #[error("timestamp token message imprint mismatch")]
    MessageImprintMismatch { expected: String, actual: String },
}

pub fn timestamp_digest(
    digest: &str,
    provider: &dyn TimestampProvider,
) -> Result<TimestampToken, TimestampError> {
    parse_sha256_prefixed(digest).map_err(TimestampError::InvalidDigest)?;
    provider.timestamp(digest)
}

pub fn verify_timestamp(
    token: &TimestampToken,
    digest: &str,
) -> Result<TimestampVerification, TimestampError> {
    parse_sha256_prefixed(digest).map_err(TimestampError::InvalidDigest)?;
    if token.kind != RFC3161_TIMESTAMP_KIND {
        return Err(TimestampError::UnsupportedKind(token.kind.clone()));
    }

    let token_der = Base64::decode_vec(&token.token_base64)
        .map_err(|err| TimestampError::InvalidBase64(err.to_string()))?;
    let signed_data = SignedData::parse_ber(&token_der)
        .map_err(|err| TimestampError::CmsParse(err.to_string()))?;

    let signer_count = signed_data.signers().count();
    if signer_count == 0 {
        return Err(TimestampError::NoSigners);
    }

    for signer in signed_data.signers() {
        signer
            .verify_signature_with_signed_data(&signed_data)
            .map_err(|err| TimestampError::SignerVerification(err.to_string()))?;
        signer
            .verify_message_digest_with_signed_data(&signed_data)
            .map_err(|err| TimestampError::SignerVerification(err.to_string()))?;
    }

    let tst_info_bytes = signed_data
        .signed_content()
        .ok_or(TimestampError::MissingSignedContent)?;
    let tst_info = Constructed::decode(tst_info_bytes, Mode::Der, TstInfo::take_from)
        .map_err(|err| TimestampError::TstInfoParse(err.to_string()))?;

    let digest_algorithm = DigestAlgorithm::try_from(&tst_info.message_imprint.hash_algorithm)
        .map_err(|err| TimestampError::UnsupportedImprintAlgorithm(err.to_string()))?;
    let expected_imprint = compute_message_imprint_hex(digest, digest_algorithm);
    let actual_imprint = format!(
        "{}:{}",
        digest_algorithm_name(digest_algorithm),
        hex::encode(tst_info.message_imprint.hashed_message.to_bytes())
    );
    if expected_imprint != actual_imprint {
        return Err(TimestampError::MessageImprintMismatch {
            expected: expected_imprint,
            actual: actual_imprint,
        });
    }

    let generated_at = DateTime::<Utc>::from(tst_info.gen_time).to_rfc3339();
    let certificate_count = signed_data.certificates().count();

    Ok(TimestampVerification {
        kind: token.kind.clone(),
        provider: token.provider.clone(),
        generated_at,
        digest_algorithm: digest_algorithm_name(digest_algorithm).to_string(),
        message_imprint: actual_imprint,
        signer_count,
        certificate_count,
    })
}

fn compute_message_imprint_hex(digest: &str, algorithm: DigestAlgorithm) -> String {
    let mut hasher = algorithm.digester();
    hasher.update(digest.as_bytes());
    format!(
        "{}:{}",
        digest_algorithm_name(algorithm),
        hex::encode(hasher.finish())
    )
}

fn digest_algorithm_name(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha384 => "sha384",
        DigestAlgorithm::Sha512 => "sha512",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::{Integer, Mode, OctetString, Oid, encode::Values};
    use cryptographic_message_syntax::{
        Bytes, SignedDataBuilder, SignerBuilder,
        asn1::rfc3161::{MessageImprint, OID_CONTENT_TYPE_TST_INFO, TstInfo},
    };
    use x509_certificate::{
        CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, X509CertificateBuilder,
    };

    struct StaticTimestampProvider {
        token: TimestampToken,
    }

    impl TimestampProvider for StaticTimestampProvider {
        fn timestamp(&self, _digest: &str) -> Result<TimestampToken, TimestampError> {
            Ok(self.token.clone())
        }
    }

    #[test]
    fn verify_timestamp_accepts_valid_signed_token() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(digest, Some("test-tsa"));

        let verification = verify_timestamp(&token, digest).unwrap();
        assert_eq!(verification.kind, RFC3161_TIMESTAMP_KIND);
        assert_eq!(verification.provider.as_deref(), Some("test-tsa"));
        assert_eq!(verification.digest_algorithm, "sha256");
        assert_eq!(verification.signer_count, 1);
        assert_eq!(verification.certificate_count, 1);
        assert!(verification.generated_at.starts_with("2026-03-06T12:00:00"));
    }

    #[test]
    fn verify_timestamp_rejects_message_imprint_mismatch() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some("test-tsa"),
        );

        let err = verify_timestamp(&token, digest).unwrap_err();
        assert!(matches!(err, TimestampError::MessageImprintMismatch { .. }));
    }

    #[test]
    fn timestamp_digest_uses_provider_trait() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(digest, Some("test-tsa"));
        let provider = StaticTimestampProvider {
            token: token.clone(),
        };

        let actual = timestamp_digest(digest, &provider).unwrap();
        assert_eq!(actual, token);
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
                OID_CONTENT_TYPE_TST_INFO.as_ref(),
            )))
            .certificate(certificate.clone())
            .signer(SignerBuilder::new(&signing_key, certificate))
            .build_der()
            .unwrap()
    }

    fn build_test_tst_info_der(digest: &str) -> Vec<u8> {
        let mut imprint_hasher = DigestAlgorithm::Sha256.digester();
        imprint_hasher.update(digest.as_bytes());
        let imprint = imprint_hasher.finish();

        let tst_info = TstInfo {
            version: Integer::from(1),
            policy: Oid(Bytes::copy_from_slice(&[42, 3, 4])),
            message_imprint: MessageImprint {
                hash_algorithm: DigestAlgorithm::Sha256.into(),
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
