use crate::{
    hash::{DigestError, parse_sha256_prefixed},
    schema::TimestampToken,
};
use base64ct::{Base64, Encoding};
use bcder::{Mode, Oid, decode::Constructed};
use chrono::{DateTime, Utc};
use cryptographic_message_syntax::{
    SignedData, SignerInfo, TimeStampError as CmsTimeStampError, asn1::rfc3161::TstInfo,
    time_stamp_message_http,
};
use std::str::FromStr;
use thiserror::Error;
use x509_certificate::{CapturedX509Certificate, DigestAlgorithm};

pub const RFC3161_TIMESTAMP_KIND: &str = "rfc3161";
pub const DIGICERT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";
pub const FREETSA_TIMESTAMP_URL: &str = "https://freetsa.org/tsr";

pub trait TimestampProvider {
    fn timestamp(&self, digest: &str) -> Result<TimestampToken, TimestampError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimestampTrustPolicy {
    #[serde(default)]
    pub trust_anchor_pems: Vec<String>,
    #[serde(default)]
    pub policy_oids: Vec<String>,
}

impl TimestampTrustPolicy {
    pub fn is_empty(&self) -> bool {
        self.trust_anchor_pems
            .iter()
            .all(|pem| pem.trim().is_empty())
            && self
                .policy_oids
                .iter()
                .all(|policy_oid| policy_oid.trim().is_empty())
    }
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
    pub policy_oid: String,
    pub signer_count: usize,
    pub certificate_count: usize,
    #[serde(default, skip_serializing_if = "is_false")]
    pub policy_oid_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub trusted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub chain_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revocation_checked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_subject: Option<String>,
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
    #[error("timestamp policy OID is invalid: {0}")]
    InvalidPolicyOid(String),
    #[error("timestamp policy OID {actual} did not match the configured policy set")]
    UnexpectedPolicyOid { actual: String },
    #[error("timestamp trust policy requires at least one PEM trust anchor certificate")]
    MissingTrustAnchors,
    #[error("timestamp trust anchor certificate is invalid: {0}")]
    InvalidTrustAnchor(String),
    #[error("timestamp signer certificate was not found in the CMS certificate set")]
    MissingSignerCertificate,
    #[error("timestamp certificate {subject} was not valid at {generated_at}")]
    CertificateNotValidAtGenerationTime {
        subject: String,
        generated_at: String,
    },
    #[error("timestamp signer certificate {subject} did not chain to a trusted anchor")]
    SignerCertificateNotTrusted { subject: String },
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
    verify_timestamp_internal(token, digest, None)
}

pub fn verify_timestamp_with_policy(
    token: &TimestampToken,
    digest: &str,
    policy: &TimestampTrustPolicy,
) -> Result<TimestampVerification, TimestampError> {
    verify_timestamp_internal(token, digest, Some(policy))
}

pub fn validate_timestamp_trust_policy(
    policy: &TimestampTrustPolicy,
) -> Result<(), TimestampError> {
    if policy.is_empty() {
        return Ok(());
    }
    for policy_oid in &policy.policy_oids {
        parse_expected_policy_oid(policy_oid)?;
    }
    if has_trust_anchors(policy) {
        load_trust_anchors(policy).map(|_| ())?;
    }
    Ok(())
}

fn verify_timestamp_internal(
    token: &TimestampToken,
    digest: &str,
    policy: Option<&TimestampTrustPolicy>,
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
    let policy_oid = parse_policy_oid(&tst_info.policy)?;
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

    let generated_at_time = DateTime::<Utc>::from(tst_info.gen_time.clone());
    let generated_at = generated_at_time.to_rfc3339();
    let certificate_count = signed_data.certificates().count();
    let expected_policy_oids = policy
        .map(|policy| {
            policy
                .policy_oids
                .iter()
                .filter_map(|policy_oid| {
                    let trimmed = policy_oid.trim();
                    (!trimmed.is_empty()).then(|| trimmed.to_string())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let policy_oid_verified = expected_policy_oids.contains(&policy_oid);
    if !expected_policy_oids.is_empty() && !policy_oid_verified {
        return Err(TimestampError::UnexpectedPolicyOid {
            actual: policy_oid.clone(),
        });
    }
    let (trusted, chain_verified, signer_subject, trust_anchor_subject) =
        if let Some(policy) = policy.filter(|policy| has_trust_anchors(policy)) {
            let trust_anchors = load_trust_anchors(policy)?;
            let (signer_subject, trust_anchor_subject) =
                verify_timestamp_trust(&signed_data, generated_at_time, &trust_anchors)?;
            (true, true, Some(signer_subject), Some(trust_anchor_subject))
        } else {
            (false, false, None, None)
        };

    Ok(TimestampVerification {
        kind: token.kind.clone(),
        provider: token.provider.clone(),
        generated_at,
        digest_algorithm: digest_algorithm_name(digest_algorithm).to_string(),
        message_imprint: actual_imprint,
        policy_oid,
        signer_count,
        certificate_count,
        policy_oid_verified,
        trusted,
        chain_verified,
        revocation_checked: false,
        signer_subject,
        trust_anchor_subject,
    })
}

fn load_trust_anchors(
    policy: &TimestampTrustPolicy,
) -> Result<Vec<CapturedX509Certificate>, TimestampError> {
    let mut trust_anchors = Vec::new();

    for pem in &policy.trust_anchor_pems {
        let trimmed = pem.trim();
        if trimmed.is_empty() {
            continue;
        }
        let certificates = CapturedX509Certificate::from_pem_multiple(trimmed.as_bytes())
            .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;
        trust_anchors.extend(certificates);
    }

    if trust_anchors.is_empty() {
        return Err(TimestampError::MissingTrustAnchors);
    }

    Ok(trust_anchors)
}

fn has_trust_anchors(policy: &TimestampTrustPolicy) -> bool {
    policy
        .trust_anchor_pems
        .iter()
        .any(|pem| !pem.trim().is_empty())
}

fn verify_timestamp_trust(
    signed_data: &SignedData,
    generated_at: DateTime<Utc>,
    trust_anchors: &[CapturedX509Certificate],
) -> Result<(String, String), TimestampError> {
    let embedded_certificates = signed_data.certificates().collect::<Vec<_>>();
    let mut signer_subject = None;
    let mut trust_anchor_subject = None;

    for signer in signed_data.signers() {
        let signer_certificate = find_signer_certificate(&embedded_certificates, signer)?;
        let (anchor, chain) = resolve_chain_to_trust_anchor(
            signer_certificate,
            &embedded_certificates,
            trust_anchors,
        )?;
        for certificate in chain {
            ensure_certificate_valid_at(certificate, generated_at)?;
        }

        if signer_subject.is_none() {
            signer_subject = Some(certificate_display_name(signer_certificate));
        }
        if trust_anchor_subject.is_none() {
            trust_anchor_subject = Some(certificate_display_name(anchor));
        }
    }

    Ok((
        signer_subject.unwrap_or_else(|| "unnamed-certificate".to_string()),
        trust_anchor_subject.unwrap_or_else(|| "unnamed-certificate".to_string()),
    ))
}

fn find_signer_certificate<'a>(
    certificates: &[&'a CapturedX509Certificate],
    signer: &SignerInfo,
) -> Result<&'a CapturedX509Certificate, TimestampError> {
    let Some((issuer, serial_number)) = signer.certificate_issuer_and_serial() else {
        return Err(TimestampError::MissingSignerCertificate);
    };

    certificates
        .iter()
        .copied()
        .find(|certificate| {
            certificate.issuer_name() == issuer && certificate.serial_number_asn1() == serial_number
        })
        .ok_or(TimestampError::MissingSignerCertificate)
}

fn resolve_chain_to_trust_anchor<'a>(
    signer_certificate: &'a CapturedX509Certificate,
    embedded_certificates: &[&'a CapturedX509Certificate],
    trust_anchors: &'a [CapturedX509Certificate],
) -> Result<
    (
        &'a CapturedX509Certificate,
        Vec<&'a CapturedX509Certificate>,
    ),
    TimestampError,
> {
    let mut chain = vec![signer_certificate];
    let mut current = signer_certificate;
    let max_depth = embedded_certificates.len() + trust_anchors.len() + 1;

    for _ in 0..max_depth {
        if let Some(anchor) = trust_anchors.iter().find(|anchor| *anchor == current) {
            return Ok((anchor, chain));
        }

        let issuer = embedded_certificates
            .iter()
            .copied()
            .chain(trust_anchors.iter())
            .find(|candidate| {
                *candidate != current && current.verify_signed_by_certificate(candidate).is_ok()
            })
            .ok_or_else(|| TimestampError::SignerCertificateNotTrusted {
                subject: certificate_display_name(signer_certificate),
            })?;

        chain.push(issuer);
        current = issuer;
    }

    Err(TimestampError::SignerCertificateNotTrusted {
        subject: certificate_display_name(signer_certificate),
    })
}

fn ensure_certificate_valid_at(
    certificate: &CapturedX509Certificate,
    generated_at: DateTime<Utc>,
) -> Result<(), TimestampError> {
    if certificate.time_constraints_valid(Some(generated_at)) {
        Ok(())
    } else {
        Err(TimestampError::CertificateNotValidAtGenerationTime {
            subject: certificate_display_name(certificate),
            generated_at: generated_at.to_rfc3339(),
        })
    }
}

fn certificate_display_name(certificate: &CapturedX509Certificate) -> String {
    certificate
        .subject_common_name()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "unnamed-certificate".to_string())
}

fn parse_policy_oid(policy: &Oid) -> Result<String, TimestampError> {
    Ok(policy.to_string())
}

fn parse_expected_policy_oid(policy_oid: &str) -> Result<String, TimestampError> {
    let trimmed = policy_oid.trim();
    Oid::<Vec<u8>>::from_str(trimmed)
        .map_err(|err| TimestampError::InvalidPolicyOid(err.to_string()))?;
    Ok(trimmed.to_string())
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

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use bcder::{Integer, Mode, OctetString, Oid, encode::Values};
    use chrono::Duration;
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
        assert_eq!(verification.policy_oid, "1.2.3.4");
        assert!(!verification.policy_oid_verified);
        assert_eq!(verification.signer_count, 1);
        assert_eq!(verification.certificate_count, 1);
        assert!(!verification.trusted);
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

    #[test]
    fn verify_timestamp_with_policy_accepts_trusted_anchor() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = Utc::now();
        let (token, certificate) = build_timestamp_token_fixture(
            digest,
            Some("test-tsa"),
            generated_at,
            Duration::hours(6),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            policy_oids: Vec::new(),
        };

        let verification = verify_timestamp_with_policy(&token, digest, &policy).unwrap();
        assert!(verification.trusted);
        assert!(verification.chain_verified);
        assert!(!verification.revocation_checked);
        assert_eq!(
            verification.signer_subject.as_deref(),
            Some("proof-layer-test-tsa")
        );
        assert_eq!(
            verification.trust_anchor_subject.as_deref(),
            Some("proof-layer-test-tsa")
        );
    }

    #[test]
    fn verify_timestamp_with_policy_accepts_matching_policy_oid_without_anchors() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(digest, Some("test-tsa"));
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: Vec::new(),
            policy_oids: vec!["1.2.3.4".to_string()],
        };

        let verification = verify_timestamp_with_policy(&token, digest, &policy).unwrap();
        assert_eq!(verification.policy_oid, "1.2.3.4");
        assert!(verification.policy_oid_verified);
        assert!(!verification.trusted);
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_untrusted_anchor() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = Utc::now();
        let (token, _) = build_timestamp_token_fixture(
            digest,
            Some("test-tsa"),
            generated_at,
            Duration::hours(6),
        );
        let (untrusted_anchor, _) = build_test_certificate(Duration::hours(6));
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![untrusted_anchor.encode_pem()],
            policy_oids: Vec::new(),
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::SignerCertificateNotTrusted { .. }
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_certificate_outside_validity_window() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = Utc::now() + Duration::hours(2);
        let (token, certificate) = build_timestamp_token_fixture(
            digest,
            Some("test-tsa"),
            generated_at,
            Duration::hours(1),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            policy_oids: Vec::new(),
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::CertificateNotValidAtGenerationTime { .. }
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_unexpected_policy_oid() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let token = build_test_timestamp_token(digest, Some("test-tsa"));
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: Vec::new(),
            policy_oids: vec!["1.2.3.5".to_string()],
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(err, TimestampError::UnexpectedPolicyOid { .. }));
    }

    fn build_test_timestamp_token(digest: &str, provider: Option<&str>) -> TimestampToken {
        let signed_data_der = build_test_signed_data_der(
            digest,
            chrono::DateTime::parse_from_rfc3339("2026-03-06T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: Base64::encode_string(&signed_data_der),
        }
    }

    fn build_timestamp_token_fixture(
        digest: &str,
        provider: Option<&str>,
        generated_at: DateTime<Utc>,
        validity_duration: Duration,
    ) -> (TimestampToken, CapturedX509Certificate) {
        let (certificate, signing_key) = build_test_certificate(validity_duration);
        let signed_data_der =
            build_test_signed_data_der(digest, generated_at, Some((&certificate, &signing_key)));
        (
            TimestampToken {
                kind: RFC3161_TIMESTAMP_KIND.to_string(),
                provider: provider.map(str::to_string),
                token_base64: Base64::encode_string(&signed_data_der),
            },
            certificate,
        )
    }

    fn build_test_signed_data_der(
        digest: &str,
        generated_at: DateTime<Utc>,
        signing_material: Option<(&CapturedX509Certificate, &InMemorySigningKeyPair)>,
    ) -> Vec<u8> {
        let owned_signing_material = signing_material
            .is_none()
            .then(|| build_test_certificate(Duration::hours(6)));
        let (certificate, signing_key) = match signing_material {
            Some((certificate, signing_key)) => (certificate, signing_key),
            None => {
                let owned = owned_signing_material.as_ref().unwrap();
                (&owned.0, &owned.1)
            }
        };
        let tst_info_der = build_test_tst_info_der(digest, generated_at);

        SignedDataBuilder::default()
            .content_inline(tst_info_der)
            .content_type(Oid(Bytes::copy_from_slice(
                OID_CONTENT_TYPE_TST_INFO.as_ref(),
            )))
            .certificate(certificate.clone())
            .signer(SignerBuilder::new(signing_key, certificate.clone()))
            .build_der()
            .unwrap()
    }

    fn build_test_tst_info_der(digest: &str, generated_at: DateTime<Utc>) -> Vec<u8> {
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
            gen_time: generated_at.into(),
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

    fn build_test_certificate(
        validity_duration: Duration,
    ) -> (CapturedX509Certificate, InMemorySigningKeyPair) {
        let mut builder = X509CertificateBuilder::default();
        builder
            .subject()
            .append_common_name_utf8_string("proof-layer-test-tsa")
            .unwrap();
        builder.subject().append_country_utf8_string("GB").unwrap();
        builder.validity_duration(validity_duration);
        builder
            .create_with_random_keypair(KeyAlgorithm::Ed25519)
            .unwrap()
    }
}
