use crate::{
    hash::{DigestError, parse_sha256_prefixed},
    schema::TimestampToken,
};
use base64ct::{Base64, Encoding};
use bcder::{Mode, Oid, decode::Constructed, encode::Values};
use chrono::{DateTime, Utc};
use cryptographic_message_syntax::{
    SignedData, SignerInfo, TimeStampError as CmsTimeStampError, asn1::rfc3161::TstInfo,
    time_stamp_message_http,
};
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertStatus, OcspFlag, OcspRequest, OcspResponse, OcspResponseStatus},
    stack::Stack,
    x509::{X509, store::X509StoreBuilder, verify::X509VerifyParam},
};
use reqwest::{Url, blocking::Client};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use x509_certificate::{CapturedX509Certificate, DigestAlgorithm};
use x509_parser::{
    certificate::X509Certificate as ParsedX509Certificate, pem::Pem, prelude::FromDer,
    revocation_list::CertificateRevocationList,
};

pub const RFC3161_TIMESTAMP_KIND: &str = "rfc3161";
pub const DIGICERT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";
pub const FREETSA_TIMESTAMP_URL: &str = "https://freetsa.org/tsr";

pub trait TimestampProvider {
    fn timestamp(&self, digest: &str) -> Result<TimestampToken, TimestampError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampAssuranceProfile {
    #[default]
    Standard,
    Qualified,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimestampTrustPolicy {
    #[serde(default)]
    pub trust_anchor_pems: Vec<String>,
    #[serde(default)]
    pub crl_pems: Vec<String>,
    #[serde(default)]
    pub ocsp_responder_urls: Vec<String>,
    #[serde(default)]
    pub qualified_signer_pems: Vec<String>,
    #[serde(default)]
    pub policy_oids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_profile: Option<TimestampAssuranceProfile>,
}

impl TimestampTrustPolicy {
    pub fn is_empty(&self) -> bool {
        self.trust_anchor_pems
            .iter()
            .all(|pem| pem.trim().is_empty())
            && self.crl_pems.iter().all(|pem| pem.trim().is_empty())
            && self
                .ocsp_responder_urls
                .iter()
                .all(|url| url.trim().is_empty())
            && self
                .qualified_signer_pems
                .iter()
                .all(|pem| pem.trim().is_empty())
            && self
                .policy_oids
                .iter()
                .all(|policy_oid| policy_oid.trim().is_empty())
            && self.assurance_profile.is_none()
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

        let signed_data = response
            .signed_data()
            .map_err(|err| TimestampError::CmsParse(err.to_string()))?
            .ok_or(TimestampError::MissingToken)?;
        let mut token_der = Vec::new();
        signed_data
            .encode_ref()
            .write_encoded(Mode::Der, &mut token_der)
            .map_err(|err| TimestampError::CmsParse(err.to_string()))?;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_profile: Option<TimestampAssuranceProfile>,
    pub signer_count: usize,
    pub certificate_count: usize,
    #[serde(default, skip_serializing_if = "is_false")]
    pub assurance_profile_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub policy_oid_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub trusted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub chain_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub certificate_profile_verified: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub revocation_checked: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ocsp_checked: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub qualified_signer_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_anchor_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_responder_url: Option<String>,
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
    #[error("qualified timestamp assurance requires at least one expected policy OID")]
    QualifiedAssuranceRequiresPolicyOids,
    #[error("qualified timestamp assurance requires at least one PEM trust anchor certificate")]
    QualifiedAssuranceRequiresTrustAnchors,
    #[error("qualified timestamp assurance requires at least one PEM X509 CRL")]
    QualifiedAssuranceRequiresCrls,
    #[error("qualified timestamp assurance requires at least one qualified TSA signer certificate")]
    QualifiedAssuranceRequiresQualifiedSigners,
    #[error("timestamp trust policy requires at least one PEM trust anchor certificate")]
    MissingTrustAnchors,
    #[error("timestamp revocation checking requires at least one PEM trust anchor certificate")]
    RevocationRequiresTrustAnchors,
    #[error("timestamp OCSP checking requires at least one PEM trust anchor certificate")]
    OcspRequiresTrustAnchors,
    #[error("timestamp trust anchor certificate is invalid: {0}")]
    InvalidTrustAnchor(String),
    #[error("timestamp CRL is invalid: {0}")]
    InvalidCrl(String),
    #[error("timestamp OCSP responder URL is invalid: {0}")]
    InvalidOcspResponderUrl(String),
    #[error("qualified TSA signer certificate is invalid: {0}")]
    InvalidQualifiedSigner(String),
    #[error("timestamp signer certificate was not found in the CMS certificate set")]
    MissingSignerCertificate,
    #[error("timestamp certificate {subject} was not valid at {generated_at}")]
    CertificateNotValidAtGenerationTime {
        subject: String,
        generated_at: String,
    },
    #[error("timestamp signer certificate {subject} asserted CA=true")]
    SignerCertificateIsCa { subject: String },
    #[error(
        "timestamp signer certificate {subject} must include a critical ExtendedKeyUsage limited to timeStamping"
    )]
    SignerCertificateInvalidExtendedKeyUsage { subject: String },
    #[error("timestamp signer certificate {subject} key usage is not valid for time stamping")]
    SignerCertificateInvalidKeyUsage { subject: String },
    #[error("timestamp CRL issuer certificate was not found for signer certificate {subject}")]
    MissingCrlIssuerCertificate { subject: String },
    #[error("no applicable timestamp CRL was found for signer certificate {subject}")]
    MissingApplicableCrl { subject: String },
    #[error("timestamp CRL for signer certificate {subject} was not valid at {generated_at}")]
    CrlNotValidAtGenerationTime {
        subject: String,
        generated_at: String,
    },
    #[error("timestamp CRL signature verification failed for signer certificate {subject}")]
    CrlSignatureVerification { subject: String },
    #[error("timestamp signer certificate {subject} was revoked at {revoked_at}")]
    SignerCertificateRevoked { subject: String, revoked_at: String },
    #[error("timestamp OCSP request to {url} failed: {message}")]
    OcspTransport { url: String, message: String },
    #[error("timestamp OCSP responder {url} returned HTTP {status}")]
    OcspHttpStatus { url: String, status: u16 },
    #[error("timestamp OCSP response from {url} was invalid: {message}")]
    InvalidOcspResponse { url: String, message: String },
    #[error("timestamp OCSP response from {url} had status {status}")]
    OcspUnsuccessfulResponse { url: String, status: String },
    #[error(
        "timestamp OCSP response from {url} did not include status for signer certificate {subject}"
    )]
    MissingApplicableOcspStatus { url: String, subject: String },
    #[error(
        "timestamp OCSP response from {url} reported unknown status for signer certificate {subject}"
    )]
    SignerCertificateOcspUnknown { url: String, subject: String },
    #[error("timestamp OCSP response from {url} was not current for signer certificate {subject}")]
    OcspResponseNotCurrent { url: String, subject: String },
    #[error(
        "timestamp OCSP response signature verification failed for signer certificate {subject}: {message}"
    )]
    OcspResponseVerification {
        url: String,
        subject: String,
        message: String,
    },
    #[error(
        "timestamp signer certificate {subject} was revoked at {revoked_at} according to OCSP responder {url}"
    )]
    SignerCertificateRevokedByOcsp {
        subject: String,
        revoked_at: String,
        url: String,
    },
    #[error(
        "timestamp signer certificate {subject} did not match the configured qualified TSA signer allowlist"
    )]
    UnexpectedQualifiedSigner { subject: String },
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
    validate_timestamp_trust_policy(policy)?;
    verify_timestamp_internal(token, digest, Some(policy))
}

pub fn validate_timestamp_trust_policy(
    policy: &TimestampTrustPolicy,
) -> Result<(), TimestampError> {
    if policy.is_empty() {
        return Ok(());
    }
    if policy.assurance_profile == Some(TimestampAssuranceProfile::Qualified) {
        if !has_expected_policy_oids(policy) {
            return Err(TimestampError::QualifiedAssuranceRequiresPolicyOids);
        }
        if !has_trust_anchors(policy) {
            return Err(TimestampError::QualifiedAssuranceRequiresTrustAnchors);
        }
        if !has_crls(policy) {
            return Err(TimestampError::QualifiedAssuranceRequiresCrls);
        }
        if !has_qualified_signers(policy) {
            return Err(TimestampError::QualifiedAssuranceRequiresQualifiedSigners);
        }
    }
    if has_crls(policy) && !has_trust_anchors(policy) {
        return Err(TimestampError::RevocationRequiresTrustAnchors);
    }
    if has_ocsp_responders(policy) && !has_trust_anchors(policy) {
        return Err(TimestampError::OcspRequiresTrustAnchors);
    }
    for policy_oid in &policy.policy_oids {
        parse_expected_policy_oid(policy_oid)?;
    }
    if has_trust_anchors(policy) {
        load_trust_anchors(policy).map(|_| ())?;
    }
    if has_crls(policy) {
        load_crls(policy).map(|_| ())?;
    }
    if has_ocsp_responders(policy) {
        load_ocsp_responder_urls(policy).map(|_| ())?;
    }
    if has_qualified_signers(policy) {
        load_qualified_signers(policy).map(|_| ())?;
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
    let assurance_profile = policy.and_then(|policy| policy.assurance_profile);
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
    let (
        trusted,
        chain_verified,
        certificate_profile_verified,
        revocation_checked,
        ocsp_checked,
        qualified_signer_verified,
        signer_subject,
        trust_anchor_subject,
        ocsp_responder_url,
    ) = if let Some(policy) = policy.filter(|policy| has_trust_anchors(policy)) {
        let trust_anchors = load_trust_anchors(policy)?;
        let crls = if has_crls(policy) {
            load_crls(policy)?
        } else {
            Vec::new()
        };
        let ocsp_responder_urls = if has_ocsp_responders(policy) {
            load_ocsp_responder_urls(policy)?
        } else {
            Vec::new()
        };
        let qualified_signers = if has_qualified_signers(policy) {
            load_qualified_signers(policy)?
        } else {
            Vec::new()
        };
        let trust_result = verify_timestamp_trust(
            &signed_data,
            generated_at_time,
            &trust_anchors,
            &crls,
            &ocsp_responder_urls,
            &qualified_signers,
        )?;
        (
            true,
            true,
            trust_result.certificate_profile_verified,
            trust_result.revocation_checked,
            trust_result.ocsp_checked,
            trust_result.qualified_signer_verified,
            Some(trust_result.signer_subject),
            Some(trust_result.trust_anchor_subject),
            trust_result.ocsp_responder_url,
        )
    } else {
        (false, false, false, false, false, false, None, None, None)
    };
    let assurance_profile_verified = match assurance_profile {
        Some(TimestampAssuranceProfile::Standard) => true,
        Some(TimestampAssuranceProfile::Qualified) => {
            policy_oid_verified
                && trusted
                && certificate_profile_verified
                && revocation_checked
                && qualified_signer_verified
        }
        None => false,
    };

    Ok(TimestampVerification {
        kind: token.kind.clone(),
        provider: token.provider.clone(),
        generated_at,
        digest_algorithm: digest_algorithm_name(digest_algorithm).to_string(),
        message_imprint: actual_imprint,
        policy_oid,
        assurance_profile,
        signer_count,
        certificate_count,
        assurance_profile_verified,
        policy_oid_verified,
        trusted,
        chain_verified,
        certificate_profile_verified,
        revocation_checked,
        ocsp_checked,
        qualified_signer_verified,
        signer_subject,
        trust_anchor_subject,
        ocsp_responder_url,
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

fn load_crls(policy: &TimestampTrustPolicy) -> Result<Vec<Vec<u8>>, TimestampError> {
    let mut crls = Vec::new();

    for pem_bundle in &policy.crl_pems {
        let trimmed = pem_bundle.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut found_crl = false;
        for pem in Pem::iter_from_buffer(trimmed.as_bytes()) {
            let pem = pem.map_err(|err| TimestampError::InvalidCrl(err.to_string()))?;
            if !pem.label.contains("CRL") {
                continue;
            }
            CertificateRevocationList::from_der(&pem.contents)
                .map_err(|err| TimestampError::InvalidCrl(err.to_string()))?;
            crls.push(pem.contents);
            found_crl = true;
        }

        if !found_crl {
            return Err(TimestampError::InvalidCrl(
                "expected at least one PEM X509 CRL block".to_string(),
            ));
        }
    }

    if crls.is_empty() {
        return Err(TimestampError::InvalidCrl(
            "expected at least one PEM X509 CRL block".to_string(),
        ));
    }

    Ok(crls)
}

fn load_ocsp_responder_urls(policy: &TimestampTrustPolicy) -> Result<Vec<String>, TimestampError> {
    let mut urls = Vec::new();

    for responder_url in &policy.ocsp_responder_urls {
        let trimmed = responder_url.trim();
        if trimmed.is_empty() {
            continue;
        }
        Url::parse(trimmed)
            .map_err(|err| TimestampError::InvalidOcspResponderUrl(err.to_string()))?;
        urls.push(trimmed.to_string());
    }

    if urls.is_empty() {
        return Err(TimestampError::InvalidOcspResponderUrl(
            "expected at least one responder URL".to_string(),
        ));
    }

    Ok(urls)
}

fn load_qualified_signers(
    policy: &TimestampTrustPolicy,
) -> Result<Vec<CapturedX509Certificate>, TimestampError> {
    let mut signers = Vec::new();

    for pem in &policy.qualified_signer_pems {
        let trimmed = pem.trim();
        if trimmed.is_empty() {
            continue;
        }
        let certificates = CapturedX509Certificate::from_pem_multiple(trimmed.as_bytes())
            .map_err(|err| TimestampError::InvalidQualifiedSigner(err.to_string()))?;
        signers.extend(certificates);
    }

    if signers.is_empty() {
        return Err(TimestampError::InvalidQualifiedSigner(
            "expected at least one PEM certificate".to_string(),
        ));
    }

    Ok(signers)
}

fn has_trust_anchors(policy: &TimestampTrustPolicy) -> bool {
    policy
        .trust_anchor_pems
        .iter()
        .any(|pem| !pem.trim().is_empty())
}

fn has_crls(policy: &TimestampTrustPolicy) -> bool {
    policy.crl_pems.iter().any(|pem| !pem.trim().is_empty())
}

fn has_ocsp_responders(policy: &TimestampTrustPolicy) -> bool {
    policy
        .ocsp_responder_urls
        .iter()
        .any(|url| !url.trim().is_empty())
}

fn has_qualified_signers(policy: &TimestampTrustPolicy) -> bool {
    policy
        .qualified_signer_pems
        .iter()
        .any(|pem| !pem.trim().is_empty())
}

fn has_expected_policy_oids(policy: &TimestampTrustPolicy) -> bool {
    policy
        .policy_oids
        .iter()
        .any(|policy_oid| !policy_oid.trim().is_empty())
}

struct TimestampTrustResult {
    signer_subject: String,
    trust_anchor_subject: String,
    certificate_profile_verified: bool,
    revocation_checked: bool,
    ocsp_checked: bool,
    qualified_signer_verified: bool,
    ocsp_responder_url: Option<String>,
}

fn verify_timestamp_trust(
    signed_data: &SignedData,
    generated_at: DateTime<Utc>,
    trust_anchors: &[CapturedX509Certificate],
    crls: &[Vec<u8>],
    ocsp_responder_urls: &[String],
    qualified_signers: &[CapturedX509Certificate],
) -> Result<TimestampTrustResult, TimestampError> {
    let embedded_certificates = signed_data.certificates().collect::<Vec<_>>();
    let mut signer_subject = None;
    let mut trust_anchor_subject = None;
    let mut ocsp_responder_url = None;
    let mut certificate_profile_verified = false;
    let revocation_required = !crls.is_empty();
    let ocsp_required = !ocsp_responder_urls.is_empty();
    let qualified_signer_required = !qualified_signers.is_empty();

    for signer in signed_data.signers() {
        let signer_certificate = find_signer_certificate(&embedded_certificates, signer)?;
        let (anchor, chain) = resolve_chain_to_trust_anchor(
            signer_certificate,
            &embedded_certificates,
            trust_anchors,
        )?;
        for certificate in &chain {
            ensure_certificate_valid_at(certificate, generated_at)?;
        }
        ensure_timestamp_signer_certificate_profile(signer_certificate)?;

        if revocation_required {
            let issuer_certificate = chain.get(1).copied().unwrap_or(signer_certificate);
            ensure_signer_not_revoked(signer_certificate, issuer_certificate, generated_at, crls)?;
            if ocsp_required {
                let responder_url = ensure_signer_not_revoked_via_ocsp(
                    signer_certificate,
                    issuer_certificate,
                    &embedded_certificates,
                    trust_anchors,
                    generated_at,
                    ocsp_responder_urls,
                )?;
                if ocsp_responder_url.is_none() {
                    ocsp_responder_url = Some(responder_url);
                }
            }
        } else if ocsp_required {
            let issuer_certificate = chain.get(1).copied().unwrap_or(signer_certificate);
            let responder_url = ensure_signer_not_revoked_via_ocsp(
                signer_certificate,
                issuer_certificate,
                &embedded_certificates,
                trust_anchors,
                generated_at,
                ocsp_responder_urls,
            )?;
            if ocsp_responder_url.is_none() {
                ocsp_responder_url = Some(responder_url);
            }
        }
        if qualified_signer_required {
            ensure_qualified_signer_match(signer_certificate, qualified_signers)?;
        }

        if signer_subject.is_none() {
            signer_subject = Some(certificate_display_name(signer_certificate));
        }
        if trust_anchor_subject.is_none() {
            trust_anchor_subject = Some(certificate_display_name(anchor));
        }
        certificate_profile_verified = true;
    }

    Ok(TimestampTrustResult {
        signer_subject: signer_subject.unwrap_or_else(|| "unnamed-certificate".to_string()),
        trust_anchor_subject: trust_anchor_subject
            .unwrap_or_else(|| "unnamed-certificate".to_string()),
        certificate_profile_verified,
        revocation_checked: revocation_required,
        ocsp_checked: ocsp_required,
        qualified_signer_verified: qualified_signer_required,
        ocsp_responder_url,
    })
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
        if let Some(anchor) = trust_anchors
            .iter()
            .find(|anchor| certificates_match(anchor, current))
        {
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

fn certificates_match(left: &CapturedX509Certificate, right: &CapturedX509Certificate) -> bool {
    left == right
        || (left.subject_name() == right.subject_name()
            && left.issuer_name() == right.issuer_name()
            && left.serial_number_asn1() == right.serial_number_asn1()
            && left.public_key_data().as_ref() == right.public_key_data().as_ref())
}

fn ensure_timestamp_signer_certificate_profile(
    certificate: &CapturedX509Certificate,
) -> Result<(), TimestampError> {
    let subject = certificate_display_name(certificate);
    let (_, parsed) = ParsedX509Certificate::from_der(certificate.constructed_data())
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;

    if parsed
        .basic_constraints()
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?
        .is_some_and(|basic| basic.value.ca)
    {
        return Err(TimestampError::SignerCertificateIsCa { subject });
    }

    let eku = parsed
        .extended_key_usage()
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?
        .ok_or_else(
            || TimestampError::SignerCertificateInvalidExtendedKeyUsage {
                subject: subject.clone(),
            },
        )?;
    let eku_value = eku.value;
    if !eku.critical
        || !eku_value.time_stamping
        || eku_value.any
        || eku_value.server_auth
        || eku_value.client_auth
        || eku_value.code_signing
        || eku_value.email_protection
        || eku_value.ocsp_signing
        || !eku_value.other.is_empty()
    {
        return Err(TimestampError::SignerCertificateInvalidExtendedKeyUsage { subject });
    }

    if let Some(key_usage) = parsed
        .key_usage()
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?
    {
        let key_usage = key_usage.value;
        let signing_allowed = key_usage.digital_signature() || key_usage.non_repudiation();
        let disallowed_usage = key_usage.key_encipherment()
            || key_usage.data_encipherment()
            || key_usage.key_agreement()
            || key_usage.key_cert_sign()
            || key_usage.crl_sign()
            || key_usage.encipher_only()
            || key_usage.decipher_only();
        if !signing_allowed || disallowed_usage {
            return Err(TimestampError::SignerCertificateInvalidKeyUsage { subject });
        }
    }

    Ok(())
}

fn ensure_signer_not_revoked(
    signer_certificate: &CapturedX509Certificate,
    issuer_certificate: &CapturedX509Certificate,
    generated_at: DateTime<Utc>,
    crls: &[Vec<u8>],
) -> Result<(), TimestampError> {
    let subject = certificate_display_name(signer_certificate);
    let generated_at_ts = generated_at.timestamp();
    let (_, parsed_signer) = ParsedX509Certificate::from_der(signer_certificate.constructed_data())
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;
    let (_, parsed_issuer) = ParsedX509Certificate::from_der(issuer_certificate.constructed_data())
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;

    for crl_der in crls {
        let (_, crl) = CertificateRevocationList::from_der(crl_der)
            .map_err(|err| TimestampError::InvalidCrl(err.to_string()))?;
        if crl.issuer() != parsed_issuer.subject() {
            continue;
        }

        if crl.last_update().timestamp() > generated_at_ts
            || crl
                .next_update()
                .is_some_and(|next_update| next_update.timestamp() < generated_at_ts)
        {
            return Err(TimestampError::CrlNotValidAtGenerationTime {
                subject: subject.clone(),
                generated_at: generated_at.to_rfc3339(),
            });
        }

        crl.verify_signature(parsed_issuer.public_key())
            .map_err(|_| TimestampError::CrlSignatureVerification {
                subject: subject.clone(),
            })?;

        if let Some(revoked) = crl
            .iter_revoked_certificates()
            .find(|revoked| revoked.raw_serial() == parsed_signer.raw_serial())
        {
            return Err(TimestampError::SignerCertificateRevoked {
                subject,
                revoked_at: revoked.revocation_date.to_datetime().to_string(),
            });
        }

        return Ok(());
    }

    Err(TimestampError::MissingApplicableCrl { subject })
}

fn ensure_signer_not_revoked_via_ocsp(
    signer_certificate: &CapturedX509Certificate,
    issuer_certificate: &CapturedX509Certificate,
    embedded_certificates: &[&CapturedX509Certificate],
    trust_anchors: &[CapturedX509Certificate],
    generated_at: DateTime<Utc>,
    responder_urls: &[String],
) -> Result<String, TimestampError> {
    let subject = certificate_display_name(signer_certificate);
    let signer_x509 = openssl_x509_from_captured(signer_certificate)?;
    let issuer_x509 = openssl_x509_from_captured(issuer_certificate)?;
    let mut request = OcspRequest::new().map_err(|err| TimestampError::InvalidOcspResponse {
        url: "local".to_string(),
        message: err.to_string(),
    })?;
    request
        .add_id(
            openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &signer_x509, &issuer_x509)
                .map_err(|err| TimestampError::InvalidOcspResponse {
                    url: "local".to_string(),
                    message: err.to_string(),
                })?,
        )
        .map_err(|err| TimestampError::InvalidOcspResponse {
            url: "local".to_string(),
            message: err.to_string(),
        })?;
    let request_der = request
        .to_der()
        .map_err(|err| TimestampError::InvalidOcspResponse {
            url: "local".to_string(),
            message: err.to_string(),
        })?;
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| TimestampError::OcspTransport {
            url: "local".to_string(),
            message: err.to_string(),
        })?;
    let cert_stack = build_ocsp_cert_stack(embedded_certificates, trust_anchors)?;
    let trust_store = build_ocsp_trust_store(trust_anchors)?;
    let cert_id =
        openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &signer_x509, &issuer_x509)
            .map_err(|err| TimestampError::InvalidOcspResponse {
                url: "local".to_string(),
                message: err.to_string(),
            })?;
    let context = OcspVerificationContext {
        client: &client,
        cert_id: &cert_id,
        cert_stack: &cert_stack,
        trust_store: &trust_store,
        subject: &subject,
        generated_at,
    };
    let mut last_error = None;

    for responder_url in responder_urls {
        match verify_ocsp_responder(responder_url, &request_der, &context) {
            Ok(()) => return Ok(responder_url.clone()),
            Err(err) => last_error = Some(err),
        }
    }

    Err(
        last_error.unwrap_or(TimestampError::InvalidOcspResponderUrl(
            "expected at least one responder URL".to_string(),
        )),
    )
}

struct OcspVerificationContext<'a> {
    client: &'a Client,
    cert_id: &'a openssl::ocsp::OcspCertIdRef,
    cert_stack: &'a Stack<X509>,
    trust_store: &'a openssl::x509::store::X509Store,
    subject: &'a str,
    generated_at: DateTime<Utc>,
}

fn verify_ocsp_responder(
    responder_url: &str,
    request_der: &[u8],
    context: &OcspVerificationContext<'_>,
) -> Result<(), TimestampError> {
    let response = context
        .client
        .post(responder_url)
        .header("content-type", "application/ocsp-request")
        .header("accept", "application/ocsp-response")
        .body(request_der.to_vec())
        .send()
        .map_err(|err| TimestampError::OcspTransport {
            url: responder_url.to_string(),
            message: err.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(TimestampError::OcspHttpStatus {
            url: responder_url.to_string(),
            status: response.status().as_u16(),
        });
    }
    let response_der = response
        .bytes()
        .map_err(|err| TimestampError::OcspTransport {
            url: responder_url.to_string(),
            message: err.to_string(),
        })?;
    let ocsp_response = OcspResponse::from_der(response_der.as_ref()).map_err(|err| {
        TimestampError::InvalidOcspResponse {
            url: responder_url.to_string(),
            message: err.to_string(),
        }
    })?;
    if ocsp_response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(TimestampError::OcspUnsuccessfulResponse {
            url: responder_url.to_string(),
            status: format!("{:?}", ocsp_response.status()),
        });
    }
    let basic = ocsp_response
        .basic()
        .map_err(|err| TimestampError::InvalidOcspResponse {
            url: responder_url.to_string(),
            message: err.to_string(),
        })?;
    basic
        .verify(context.cert_stack, context.trust_store, OcspFlag::empty())
        .map_err(|err| TimestampError::OcspResponseVerification {
            url: responder_url.to_string(),
            subject: context.subject.to_string(),
            message: err.to_string(),
        })?;
    let status = basic.find_status(context.cert_id).ok_or_else(|| {
        TimestampError::MissingApplicableOcspStatus {
            url: responder_url.to_string(),
            subject: context.subject.to_string(),
        }
    })?;
    status.check_validity(300, Some(86_400)).map_err(|_| {
        TimestampError::OcspResponseNotCurrent {
            url: responder_url.to_string(),
            subject: context.subject.to_string(),
        }
    })?;

    match status.status {
        OcspCertStatus::GOOD => Ok(()),
        OcspCertStatus::REVOKED => {
            let revoked_at = status
                .revocation_time
                .map(display_openssl_generalized_time)
                .unwrap_or_else(|| "unknown".to_string());
            if status
                .revocation_time
                .and_then(parse_openssl_generalized_time)
                .is_some_and(|revocation_time| revocation_time <= context.generated_at)
            {
                Err(TimestampError::SignerCertificateRevokedByOcsp {
                    subject: context.subject.to_string(),
                    revoked_at,
                    url: responder_url.to_string(),
                })
            } else {
                Ok(())
            }
        }
        _ => Err(TimestampError::SignerCertificateOcspUnknown {
            url: responder_url.to_string(),
            subject: context.subject.to_string(),
        }),
    }
}

fn build_ocsp_cert_stack(
    embedded_certificates: &[&CapturedX509Certificate],
    trust_anchors: &[CapturedX509Certificate],
) -> Result<Stack<X509>, TimestampError> {
    let mut certificates = Stack::new().map_err(|err| TimestampError::InvalidOcspResponse {
        url: "local".to_string(),
        message: err.to_string(),
    })?;

    for certificate in embedded_certificates {
        certificates
            .push(openssl_x509_from_captured(certificate)?)
            .map_err(|err| TimestampError::InvalidOcspResponse {
                url: "local".to_string(),
                message: err.to_string(),
            })?;
    }
    for trust_anchor in trust_anchors {
        certificates
            .push(openssl_x509_from_captured(trust_anchor)?)
            .map_err(|err| TimestampError::InvalidOcspResponse {
                url: "local".to_string(),
                message: err.to_string(),
            })?;
    }

    Ok(certificates)
}

fn build_ocsp_trust_store(
    trust_anchors: &[CapturedX509Certificate],
) -> Result<openssl::x509::store::X509Store, TimestampError> {
    let mut builder = X509StoreBuilder::new()
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;
    let mut verify_param = X509VerifyParam::new()
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;
    verify_param.set_time(Utc::now().timestamp());
    builder
        .set_param(&verify_param)
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;

    for trust_anchor in trust_anchors {
        builder
            .add_cert(openssl_x509_from_captured(trust_anchor)?)
            .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))?;
    }

    Ok(builder.build())
}

fn openssl_x509_from_captured(
    certificate: &CapturedX509Certificate,
) -> Result<X509, TimestampError> {
    X509::from_der(certificate.constructed_data())
        .map_err(|err| TimestampError::InvalidTrustAnchor(err.to_string()))
}

fn parse_openssl_generalized_time(
    time: &openssl::asn1::Asn1GeneralizedTimeRef,
) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::parse_from_str(&time.to_string(), "%b %e %H:%M:%S %Y GMT")
        .ok()
        .map(|time| DateTime::<Utc>::from_naive_utc_and_offset(time, Utc))
}

fn display_openssl_generalized_time(time: &openssl::asn1::Asn1GeneralizedTimeRef) -> String {
    time.to_string()
}

fn ensure_qualified_signer_match(
    signer_certificate: &CapturedX509Certificate,
    qualified_signers: &[CapturedX509Certificate],
) -> Result<(), TimestampError> {
    if qualified_signers
        .iter()
        .any(|candidate| certificates_match(candidate, signer_certificate))
    {
        Ok(())
    } else {
        Err(TimestampError::UnexpectedQualifiedSigner {
            subject: certificate_display_name(signer_certificate),
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    use x509_certificate::{
        CapturedX509Certificate, InMemorySigningKeyPair, KeyAlgorithm, X509CertificateBuilder,
        certificate::KeyUsage,
    };

    struct StaticTimestampProvider {
        token: TimestampToken,
    }

    const FIXTURE_ROOT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICBjCCAaygAwIBAgIUU7PBh7taLAmG19BY8phnDDsZVlwwCgYIKoZIzj0EAwIw
LDEdMBsGA1UEAwwUcHJvb2YtbGF5ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCMB4X
DTI2MDMwNzIxNTEyN1oXDTI3MDMwNzIxNTEyN1owLDEdMBsGA1UEAwwUcHJvb2Yt
bGF5ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEwxuCssNgu7tBvShQqgixNy2HxFXvG0Vl7+s543A6KD/bwu4lrBxpWvdl
/jh2PIoqiI6437pzD12QPwl0edB7uKOBqzCBqDAdBgNVHQ4EFgQUpFIKiTRJ7cMF
xu7WWuwKitJqAaMwUQYDVR0jBEowSKEwpC4wLDEdMBsGA1UEAwwUcHJvb2YtbGF5
ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCghRTs8GHu1osCYbX0FjymGcMOxlWXDAM
BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDCDAKBggqhkjOPQQDAgNIADBFAiBM+ejhtT8tdJgaTcIjU6rCIQN6Jj/ilu4W
cZpYdU8oMQIhAIa52nxpcwMRyZIA7YIEGMYZpC8ln3j0B2aegACNVZG9
-----END CERTIFICATE-----
"#;

    const FIXTURE_TSA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICBjCCAaygAwIBAgIUU7PBh7taLAmG19BY8phnDDsZVlwwCgYIKoZIzj0EAwIw
LDEdMBsGA1UEAwwUcHJvb2YtbGF5ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCMB4X
DTI2MDMwNzIxNTEyN1oXDTI3MDMwNzIxNTEyN1owLDEdMBsGA1UEAwwUcHJvb2Yt
bGF5ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEwxuCssNgu7tBvShQqgixNy2HxFXvG0Vl7+s543A6KD/bwu4lrBxpWvdl
/jh2PIoqiI6437pzD12QPwl0edB7uKOBqzCBqDAdBgNVHQ4EFgQUpFIKiTRJ7cMF
xu7WWuwKitJqAaMwUQYDVR0jBEowSKEwpC4wLDEdMBsGA1UEAwwUcHJvb2YtbGF5
ZXItdGVzdC10c2ExCzAJBgNVBAYTAkdCghRTs8GHu1osCYbX0FjymGcMOxlWXDAM
BgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDCDAKBggqhkjOPQQDAgNIADBFAiBM+ejhtT8tdJgaTcIjU6rCIQN6Jj/ilu4W
cZpYdU8oMQIhAIa52nxpcwMRyZIA7YIEGMYZpC8ln3j0B2aegACNVZG9
-----END CERTIFICATE-----
"#;

    const FIXTURE_TSA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+vaAJTU2Ob9P93ed
/t7V2Nqa5+24UlRSlYGjpUh0QvqhRANCAATDG4Kyw2C7u0G9KFCqCLE3LYfEVe8b
RWXv6znjcDooP9vC7iWsHGla92X+OHY8iiqIjrjfunMPXZA/CXR50Hu4
-----END PRIVATE KEY-----
"#;

    const FIXTURE_EMPTY_CRL_PEM: &str = r#"-----BEGIN X509 CRL-----
MIHmMIGNAgEBMAoGCCqGSM49BAMCMCwxHTAbBgNVBAMMFHByb29mLWxheWVyLXRl
c3QtdHNhMQswCQYDVQQGEwJHQhcNMjYwMzA3MjE1MTI3WhcNMjYwNDA2MjE1MTI3
WqAwMC4wHwYDVR0jBBgwFoAUpFIKiTRJ7cMFxu7WWuwKitJqAaMwCwYDVR0UBAQC
AhAAMAoGCCqGSM49BAMCA0gAMEUCIDgOKS2Yghk4zHOJTpUFBiiCjEvlrEwml/S+
lbMJi3Q4AiEA9D8MwQFYMn4s0CXt3fdhssaMf69SlNwNKpMpVVWs54A=
-----END X509 CRL-----
"#;

    const FIXTURE_REVOKED_CRL_PEM: &str = r#"-----BEGIN X509 CRL-----
MIIBDzCBtgIBATAKBggqhkjOPQQDAjAsMR0wGwYDVQQDDBRwcm9vZi1sYXllci10
ZXN0LXRzYTELMAkGA1UEBhMCR0IXDTI2MDMwNzIxNTEyN1oXDTI2MDQwNjIxNTEy
N1owJzAlAhRTs8GHu1osCYbX0FjymGcMOxlWXBcNMjYwMzA3MjE1MTI3WqAwMC4w
HwYDVR0jBBgwFoAUpFIKiTRJ7cMFxu7WWuwKitJqAaMwCwYDVR0UBAQCAhABMAoG
CCqGSM49BAMCA0gAMEUCIQDcS8DN0FLpKwFW61x4dbzL6yaf11ufqc27ob4CaPr0
QAIgPxprcGWSAwfCXug9lIZY8wlqWqLLMKxkWpyq3B/Rp6g=
-----END X509 CRL-----
"#;

    const OCSP_FIXTURE_ROOT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIULhIWLnhQZ2tNQ7+3TIX4HxBKOC4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJdGVzdC1yb290MB4XDTI2MDMwODA4NTMzMFoXDTM2MDMw
NTA4NTMzMFowFDESMBAGA1UEAwwJdGVzdC1yb290MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAiTZxIt17bf5bO9TjzBcv+V9CMy4/Ox2aUdOcWs7CZaO9
8sRsowzj9IBImOhS/PPj1w37bQ6gYrJZ+t1rkekJK6l9bWTf3unUL7nJGwikqbfm
SCMAFhIYEfcd0hQPCqLgjLEtz2gfveHAZhULZojMg8stRwjLvyoPPsD8SQJ4mj+h
w3q2dcuTYq3Fq17uqNzvwMcsATVAexubhd6F7RakQ5ZBpMyViB6Seef/TvvCWNdG
Zt1FJsZl+CBFDTMhely3QjoRONfcUrvrdVf087JQAU9ZJNJuUS9zQE2aLvlvJW93
DbWs1BuVFSTQ8xE6D97CoKBHzFQRJrhNFng62p1DrwIDAQABo2MwYTAdBgNVHQ4E
FgQUxk2kEtaKwHYI15Lug4zSZi67obYwHwYDVR0jBBgwFoAUxk2kEtaKwHYI15Lu
g4zSZi67obYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZI
hvcNAQELBQADggEBAGip4SD0eusiKHVWpAuBOaMUcBHUQkV63f0yiV99afSNbpEz
+RmUJMHiiOIGh1Gvec4bpAysDCFK/jlpxclrpcoERU5gaeNlrTrFbMVs44f3lxR5
Vi+UksFI+Li2uTlo22KCmr4tc4nuhktBvEizG+jphVGMkhg0YnItLNx9RcnUTNyH
3Pao/zhhYe1FSvHAZZ1YrEocIDWe4yB8TejwUg8NLfZ5kq9dgulr96gSUju+7KYw
RProT2urQNtOkDcGrjnVzjrlyghiVTeJrEDPLx2Uz+HLBTi4aPDFAMN+NAbjfpdV
rCVy6eeN5D31jVZXtuGExYaVXOJrhu+MGhuTWNA=
-----END CERTIFICATE-----
"#;

    const OCSP_FIXTURE_TSA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJdGVz
dC1yb290MB4XDTI2MDMwODA4NTMzMVoXDTM2MDMwNTA4NTMzMVowEzERMA8GA1UE
AwwIdGVzdC10c2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuyWyd
VMM3OXatEnC+2Pddd+ovH8+ade3gOWaoW7ADyQUf1+c9nUKoaDL+pPmhON15NPmb
EIfpWzP6FbhDtO8mL/nQ617tVB2CletHb2o43LU8vmmCE/4Tq0tntYoxgHcUmO1f
egwDLgohSbDM2xPtpnti/h2ZL4fMq/X20oItcyr2cM9nWlbl9QY78BZ6IPVRZVco
moWXgzUko1DW8yOZcj7dVr9DiufbsJs5q8jChDthm7q1nmBwNZQsHgU7sXZWe8Cy
bZrn/QIc9sCbPx/gHScKaufDC4/h0CHWAgFtCB0IoX42x0Y6MhgjPHC6KIFf8+f3
tsEZCx5ir4whMHnHAgMBAAGjeDB2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBTCp8lFrqNfeYwa
Sp6Ny+RUqh92yjAfBgNVHSMEGDAWgBTGTaQS1orAdgjXku6DjNJmLruhtjANBgkq
hkiG9w0BAQsFAAOCAQEAUeMWfRu/H6mkU6g+QB/iAqj9q0vhtelQcSqwbNS/nJw4
gFC6pqUT4OWPcHtK+X5U0nYjwJCoP1s2x5zEPS6ix6UGmguBpcx3E6ryXINIf01f
EiY5UCT0T5XO2VD4+Iij61DmaYO02qF0bTWrPkvRSSXWpMgXhZlu/EFSirCRcHL7
0+Jdry5yUT+hmaKSbDIV/O1DC79yNwk6rbksdS9/gUCzqSMCMJVA/3eb4fUYzJXw
Cav/6Hym15B+WhAtMgiXj5sdVvL5uYCytLSyL7nOmkvzftP0pTqCL+MZSiHHtVSC
j8hngQ7mwPUHDF8P33WP782e9Z+UKAiH9LKO1Piu9w==
-----END CERTIFICATE-----
"#;

    const OCSP_FIXTURE_TSA_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCuyWydVMM3OXat
EnC+2Pddd+ovH8+ade3gOWaoW7ADyQUf1+c9nUKoaDL+pPmhON15NPmbEIfpWzP6
FbhDtO8mL/nQ617tVB2CletHb2o43LU8vmmCE/4Tq0tntYoxgHcUmO1fegwDLgoh
SbDM2xPtpnti/h2ZL4fMq/X20oItcyr2cM9nWlbl9QY78BZ6IPVRZVcomoWXgzUk
o1DW8yOZcj7dVr9DiufbsJs5q8jChDthm7q1nmBwNZQsHgU7sXZWe8CybZrn/QIc
9sCbPx/gHScKaufDC4/h0CHWAgFtCB0IoX42x0Y6MhgjPHC6KIFf8+f3tsEZCx5i
r4whMHnHAgMBAAECggEALQnzRoFagmb4yTU4vzzaVQf63OTGEqezwbUY2mYx72/D
tcZlLE/TJuEeztZFCwHDtCFt9kKmuv+I37bsEepUO5NePLMB9YbYydcG1xQDG57n
xrzMJDwxmvDnT9SMRSA0zyZu+EzTPpiE/Lnn6InFU1Y0cjhH+TqxtBBVo6Hv8HTQ
wcUV1HCxumXpDWv23PJ3xs7fJ6J9k6e7D9yJLt4xMIfpAO/pp3wM1IWYP2+gxFbD
UHd8ri0fNqO5e9aAcQvJX+QfzmuNW0IPQ8ksa0yd/8Vi3pNtCWYyreX5/a+5BxrW
098jfESvOQD59R9pmgB8jJ/S4h3QNlfJwEEmFcug7QKBgQDpTBPunwvUGJMlxqbA
aLlrwd1wS8avZLAnUeefQd71imqiw/A5oFLECYnHma1JCKhOjGBZ9ttC7F1imgKH
ydrRCey9epDUiqENULTqFz2nxSIvSX98IeumdHAprUP3ERzOFdJ6vxWWsVFm1CXu
4Svzhj0A7agg4jym+lLUvl17OwKBgQC/y7r/6U7J8VZ0gy/o9h7cbIayfNhduBOB
40NC3ndT0RaErE8Zig9CLv62I9XHRSQMzNJWhoJ0pVMMjRj2N4KcuU9ygiTzb4lK
EBSCTpl7ApNr0AN9zs+NUZ+rdYFHhW87WiJFDCMsuy4oCpnT1FyWJAyaxkkDjLDM
b0TIUdPa5QKBgEbxXIpOkRFBG9X7749JCUGMZWMVl+iUDMEYNgAGzt8J5V1zieRs
LV7xq5Un1TsFR/EC3PXejFRwfgFS5fwW1NSGWRhRYiNPuKPM7AbXZGdVGg0ZI4xC
4F7wv37c8nL6IDFHD4dF/jGh4CgN0S8wB+Z45qoWmu7M/TalnnSVIuYrAoGABJy5
mn3ZzzFmita8yDVi+JoDgzdNXLOYhH8alvkSlYlpqTcbj9mqFEVdCrRB59DZ1RT3
2ezSJkvze1HJT+J12Z77Mh2/FbuQ6Z8JXzjUqAif0u/lpZjblOJpnI3u1fF3g03f
lRl9nw3BRmU63cU1lMa5Jt+t0dAIUGI8nTSai6ECgYACd3gYbMQCIL47M8quLd+h
x+NIK7lM13qnl5eGW2PzFVzymZEJPZHOh2s2s7e3C6esYn07v4aOCnT6qjBty7cQ
Alq6xMOvOD2/oBRcbcmSVBEJYEiuMxovmzHEubjMRjZL0TKd+9gE80q8MBd/E9gQ
ZJEzDECj9/jkH0atk+SIJw==
-----END PRIVATE KEY-----
"#;

    const OCSP_FIXTURE_GOOD_RESPONSE_BASE64: &str = "MIIFDwoBAKCCBQgwggUEBgkrBgEFBQcwAQEEggT1MIIE8TCBtaEWMBQxEjAQBgNVBAMMCXRlc3Qtcm9vdBgPMjAyNjAzMDgwODUzMzFaMGUwYzA7MAkGBSsOAwIaBQAEFMNkgwrCNHgxmKwrtqQEMhxbFMVTBBTGTaQS1orAdgjXku6DjNJmLruhtgICEACAABgPMjAyNjAzMDgwODUzMzFaoBEYDzIwMjYwMzA5MDg1MzMxWqEjMCEwHwYJKwYBBQUHMAECBBIEEJOycmfMiMGk20Ya5r/1EnwwDQYJKoZIhvcNAQELBQADggEBACP5cTF1+Cl8CjiW18gkgQnVTHOdkxEtfMd32ijhkWIFY2YPqLaWTACl6C9via0oHjKbmgCdg8kAOFVQP5XdvfCGWxidPD7wOSLagilo05qI60ova0eazy886u57jCuSBwPnDmXFGUaV8txkQgh5IKlMwUwrIePGIOhieM0RyRvzrnSAlm672uvSGI9DmLeIDBjcIND+yjhiKrPpRtsaKuo7h3x/jmK0cn4ipJcwr7zRGWXVnoGJUpukF+UcokQ52Fc9mMroOiywYtaztK6AQnndAr1fT5I2pHDX+1PYyzPgmTRVlOx1ylEz7gpjNiEDE+e9IJNS2pnDB20CXX7y7iygggMhMIIDHTCCAxkwggIBoAMCAQICFC4SFi54UGdrTUO/t0yF+B8QSjguMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRlc3Qtcm9vdDAeFw0yNjAzMDgwODUzMzBaFw0zNjAzMDUwODUzMzBaMBQxEjAQBgNVBAMMCXRlc3Qtcm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIk2cSLde23+WzvU48wXL/lfQjMuPzsdmlHTnFrOwmWjvfLEbKMM4/SASJjoUvzz49cN+20OoGKyWfrda5HpCSupfW1k397p1C+5yRsIpKm35kgjABYSGBH3HdIUDwqi4IyxLc9oH73hwGYVC2aIzIPLLUcIy78qDz7A/EkCeJo/ocN6tnXLk2Ktxate7qjc78DHLAE1QHsbm4Xehe0WpEOWQaTMlYgeknnn/077wljXRmbdRSbGZfggRQ0zIXpct0I6ETjX3FK763VX9POyUAFPWSTSblEvc0BNmi75byVvdw21rNQblRUk0PMROg/ewqCgR8xUESa4TRZ4OtqdQ68CAwEAAaNjMGEwHQYDVR0OBBYEFMZNpBLWisB2CNeS7oOM0mYuu6G2MB8GA1UdIwQYMBaAFMZNpBLWisB2CNeS7oOM0mYuu6G2MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBoqeEg9HrrIih1VqQLgTmjFHAR1EJFet39MolffWn0jW6RM/kZlCTB4ojiBodRr3nOG6QMrAwhSv45acXJa6XKBEVOYGnjZa06xWzFbOOH95cUeVYvlJLBSPi4trk5aNtigpq+LXOJ7oZLQbxIsxvo6YVRjJIYNGJyLSzcfUXJ1Ezch9z2qP84YWHtRUrxwGWdWKxKHCA1nuMgfE3o8FIPDS32eZKvXYLpa/eoElI7vuymMET66E9rq0DbTpA3Bq451c465coIYlU3iaxAzy8dlM/hywU4uGjwxQDDfjQG436XVawlcunnjeQ99Y1WV7bhhMWGlVzia4bvjBobk1jQ";

    const OCSP_FIXTURE_REVOKED_RESPONSE_BASE64: &str = "MIIFJQoBAKCCBR4wggUaBgkrBgEFBQcwAQEEggULMIIFBzCBy6EWMBQxEjAQBgNVBAMMCXRlc3Qtcm9vdBgPMjAyNjAzMDgwODUzMzFaMHsweTA7MAkGBSsOAwIaBQAEFMNkgwrCNHgxmKwrtqQEMhxbFMVTBBTGTaQS1orAdgjXku6DjNJmLruhtgICEAChFhgPMjAyNjAzMDgwODUzMzFaoAMKAQEYDzIwMjYwMzA4MDg1MzMxWqARGA8yMDI2MDMwOTA4NTMzMVqhIzAhMB8GCSsGAQUFBzABAgQSBBAGQX2yKS/PM7iZEebryIWCMA0GCSqGSIb3DQEBCwUAA4IBAQCAY111bWPPFgfArohwxLZ/LUU+xMySGKkeqrfOUsZhTVJGVAQIGEJjabVEJaq5uotmrA8WE1WLNu3aeUgHfo2S2XyCY5+1dSlOLfYc/jgNGPDed9c8tlCg6VEhjq0fZJdwoimQOkuvdEdSlWGr7V0NZRO7e19WahPisoAuPGBi9cixOS+8U+UqfvevLa8b35Eqxvr7uFBsaBKa4zOyu1nTK5YBcWsweaA1C+CKD07Vxj0HOUfQL4+uUH3h+KMoPK9upGso12TxqPmNgXBNnYWZQIFPHcsVsz/HaPv0lN6RLnIt0s08CqDLFsuAG61qiUYZD3QQx8bmeimKtrP39wGboIIDITCCAx0wggMZMIICAaADAgECAhQuEhYueFBna01Dv7dMhfgfEEo4LjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0ZXN0LXJvb3QwHhcNMjYwMzA4MDg1MzMwWhcNMzYwMzA1MDg1MzMwWjAUMRIwEAYDVQQDDAl0ZXN0LXJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCJNnEi3Xtt/ls71OPMFy/5X0IzLj87HZpR05xazsJlo73yxGyjDOP0gEiY6FL88+PXDfttDqBisln63WuR6QkrqX1tZN/e6dQvuckbCKSpt+ZIIwAWEhgR9x3SFA8KouCMsS3PaB+94cBmFQtmiMyDyy1HCMu/Kg8+wPxJAniaP6HDerZ1y5NircWrXu6o3O/AxywBNUB7G5uF3oXtFqRDlkGkzJWIHpJ55/9O+8JY10Zm3UUmxmX4IEUNMyF6XLdCOhE419xSu+t1V/TzslABT1kk0m5RL3NATZou+W8lb3cNtazUG5UVJNDzEToP3sKgoEfMVBEmuE0WeDranUOvAgMBAAGjYzBhMB0GA1UdDgQWBBTGTaQS1orAdgjXku6DjNJmLruhtjAfBgNVHSMEGDAWgBTGTaQS1orAdgjXku6DjNJmLruhtjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAaKnhIPR66yIodVakC4E5oxRwEdRCRXrd/TKJX31p9I1ukTP5GZQkweKI4gaHUa95zhukDKwMIUr+OWnFyWulygRFTmBp42WtOsVsxWzjh/eXFHlWL5SSwUj4uLa5OWjbYoKavi1zie6GS0G8SLMb6OmFUYySGDRici0s3H1FydRM3Ifc9qj/OGFh7UVK8cBlnVisShwgNZ7jIHxN6PBSDw0t9nmSr12C6Wv3qBJSO77spjBE+uhPa6tA206QNwauOdXOOuXKCGJVN4msQM8vHZTP4csFOLho8MUAw340BuN+l1WsJXLp543kPfWNVle24YTFhpVc4muG74waG5NY0A==";

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
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        let verification = verify_timestamp_with_policy(&token, digest, &policy).unwrap();
        assert_eq!(verification.assurance_profile, None);
        assert!(!verification.assurance_profile_verified);
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
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: None,
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
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
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
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
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
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: vec!["1.2.3.5".to_string()],
            assurance_profile: None,
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(err, TimestampError::UnexpectedPolicyOid { .. }));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_qualified_without_policy_oids() {
        let (_, certificate) = build_timestamp_token_fixture(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("test-tsa"),
            Utc::now(),
            Duration::hours(6),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::QualifiedAssuranceRequiresPolicyOids
        ));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_qualified_without_trust_anchors() {
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: Vec::new(),
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::QualifiedAssuranceRequiresTrustAnchors
        ));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_qualified_without_crls() {
        let (_, certificate) = build_timestamp_token_fixture(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("test-tsa"),
            Utc::now(),
            Duration::hours(6),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::QualifiedAssuranceRequiresCrls
        ));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_crls_without_trust_anchors() {
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: Vec::new(),
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::RevocationRequiresTrustAnchors
        ));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_ocsp_without_trust_anchors() {
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: Vec::new(),
            crl_pems: Vec::new(),
            ocsp_responder_urls: vec!["http://127.0.0.1:9999".to_string()],
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(err, TimestampError::OcspRequiresTrustAnchors));
    }

    #[test]
    fn validate_timestamp_trust_policy_rejects_qualified_without_signer_allowlist() {
        let (_, certificate) = build_timestamp_token_fixture(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("test-tsa"),
            Utc::now(),
            Duration::hours(6),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = validate_timestamp_trust_policy(&policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::QualifiedAssuranceRequiresQualifiedSigners
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_accepts_good_ocsp_response() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-08T08:53:31Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_ocsp_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let responder_url = serve_once_http_response(
            "200 OK",
            "application/ocsp-response",
            Base64::decode_vec(OCSP_FIXTURE_GOOD_RESPONSE_BASE64).unwrap(),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![OCSP_FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: Vec::new(),
            ocsp_responder_urls: vec![responder_url.clone()],
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        match verify_timestamp_with_policy(&token, digest, &policy) {
            Ok(verification) => {
                assert!(verification.trusted);
                assert!(verification.chain_verified);
                assert!(verification.ocsp_checked);
                assert_eq!(
                    verification.ocsp_responder_url.as_deref(),
                    Some(responder_url.as_str())
                );
            }
            Err(TimestampError::OcspResponseNotCurrent { url, subject }) => {
                assert_eq!(url, responder_url);
                assert_eq!(subject, "test-tsa");
                assert_eq!(
                    decode_ocsp_fixture_status(OCSP_FIXTURE_GOOD_RESPONSE_BASE64),
                    OcspCertStatus::GOOD
                );
            }
            Err(err) => panic!("unexpected OCSP verification error: {err}"),
        }
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_revoked_signer_via_ocsp() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-08T08:53:31Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_ocsp_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let responder_url = serve_once_http_response(
            "200 OK",
            "application/ocsp-response",
            Base64::decode_vec(OCSP_FIXTURE_REVOKED_RESPONSE_BASE64).unwrap(),
        );
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![OCSP_FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: Vec::new(),
            ocsp_responder_urls: vec![responder_url.clone()],
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        match verify_timestamp_with_policy(&token, digest, &policy) {
            Err(TimestampError::SignerCertificateRevokedByOcsp { .. }) => {}
            Err(TimestampError::OcspResponseNotCurrent { url, subject }) => {
                assert_eq!(url, responder_url);
                assert_eq!(subject, "test-tsa");
                assert_eq!(
                    decode_ocsp_fixture_status(OCSP_FIXTURE_REVOKED_RESPONSE_BASE64),
                    OcspCertStatus::REVOKED
                );
            }
            Err(err) => panic!("unexpected OCSP verification error: {err}"),
            Ok(_) => panic!("expected revoked OCSP verification to fail"),
        }
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_invalid_tsa_certificate_profile() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = Utc::now();
        let (certificate, signing_key) = build_unprofiled_test_certificate(Duration::hours(6));
        let token = TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: Some("test-tsa".to_string()),
            token_base64: Base64::encode_string(&build_test_signed_data_der(
                digest,
                generated_at,
                Some((&certificate, &signing_key)),
            )),
        };
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![certificate.encode_pem()],
            crl_pems: Vec::new(),
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: Vec::new(),
            policy_oids: Vec::new(),
            assurance_profile: None,
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::SignerCertificateInvalidExtendedKeyUsage { .. }
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_unexpected_qualified_signer() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-07T21:51:27Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_crl_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let (unexpected_signer, _) = build_test_certificate(Duration::hours(6));
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: vec![unexpected_signer.encode_pem()],
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::UnexpectedQualifiedSigner { .. }
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_accepts_non_revoked_crl() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-07T21:51:27Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_crl_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: vec![FIXTURE_TSA_CERT_PEM.to_string()],
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let verification = verify_timestamp_with_policy(&token, digest, &policy).unwrap();
        assert!(verification.trusted);
        assert!(verification.chain_verified);
        assert!(verification.certificate_profile_verified);
        assert!(verification.revocation_checked);
        assert!(verification.assurance_profile_verified);
        assert_eq!(
            verification.trust_anchor_subject.as_deref(),
            Some("proof-layer-test-tsa")
        );
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_revoked_signer_certificate() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-07T21:51:27Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_crl_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: vec![FIXTURE_REVOKED_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: vec![FIXTURE_TSA_CERT_PEM.to_string()],
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(
            err,
            TimestampError::SignerCertificateRevoked { .. }
        ));
    }

    #[test]
    fn verify_timestamp_with_policy_rejects_missing_applicable_crl() {
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
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: vec![certificate.encode_pem()],
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let err = verify_timestamp_with_policy(&token, digest, &policy).unwrap_err();
        assert!(matches!(err, TimestampError::MissingApplicableCrl { .. }));
    }

    #[test]
    fn verify_timestamp_with_policy_accepts_qualified_assurance_profile_with_crl_backed_chain() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-03-07T21:51:27Z")
            .unwrap()
            .with_timezone(&Utc);
        let token = build_crl_backed_timestamp_token(digest, Some("test-tsa"), generated_at);
        let policy = TimestampTrustPolicy {
            trust_anchor_pems: vec![FIXTURE_ROOT_CERT_PEM.to_string()],
            crl_pems: vec![FIXTURE_EMPTY_CRL_PEM.to_string()],
            ocsp_responder_urls: Vec::new(),
            qualified_signer_pems: vec![FIXTURE_TSA_CERT_PEM.to_string()],
            policy_oids: vec!["1.2.3.4".to_string()],
            assurance_profile: Some(TimestampAssuranceProfile::Qualified),
        };

        let verification = verify_timestamp_with_policy(&token, digest, &policy).unwrap();
        assert_eq!(
            verification.assurance_profile,
            Some(TimestampAssuranceProfile::Qualified)
        );
        assert!(verification.assurance_profile_verified);
        assert!(verification.policy_oid_verified);
        assert!(verification.trusted);
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

    fn build_crl_backed_timestamp_token(
        digest: &str,
        provider: Option<&str>,
        generated_at: DateTime<Utc>,
    ) -> TimestampToken {
        let certificate =
            CapturedX509Certificate::from_pem(FIXTURE_TSA_CERT_PEM.as_bytes()).unwrap();
        let signing_key =
            InMemorySigningKeyPair::from_pkcs8_pem(FIXTURE_TSA_KEY_PEM.as_bytes()).unwrap();
        let signed_data_der =
            build_test_signed_data_der(digest, generated_at, Some((&certificate, &signing_key)));
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: Base64::encode_string(&signed_data_der),
        }
    }

    fn build_ocsp_backed_timestamp_token(
        digest: &str,
        provider: Option<&str>,
        generated_at: DateTime<Utc>,
    ) -> TimestampToken {
        let certificate =
            CapturedX509Certificate::from_pem(OCSP_FIXTURE_TSA_CERT_PEM.as_bytes()).unwrap();
        let signing_key =
            InMemorySigningKeyPair::from_pkcs8_pem(OCSP_FIXTURE_TSA_KEY_PEM.as_bytes()).unwrap();
        let signed_data_der =
            build_test_signed_data_der(digest, generated_at, Some((&certificate, &signing_key)));
        TimestampToken {
            kind: RFC3161_TIMESTAMP_KIND.to_string(),
            provider: provider.map(str::to_string),
            token_base64: Base64::encode_string(&signed_data_der),
        }
    }

    fn decode_ocsp_fixture_status(response_base64: &str) -> OcspCertStatus {
        let response_der = Base64::decode_vec(response_base64).unwrap();
        let response = OcspResponse::from_der(&response_der).unwrap();
        let basic = response.basic().unwrap();
        let root = X509::from_pem(OCSP_FIXTURE_ROOT_CERT_PEM.as_bytes()).unwrap();
        let signer = X509::from_pem(OCSP_FIXTURE_TSA_CERT_PEM.as_bytes()).unwrap();
        let cert_id =
            openssl::ocsp::OcspCertId::from_cert(MessageDigest::sha1(), &signer, &root).unwrap();
        basic.find_status(&cert_id).unwrap().status
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
        builder.constraint_not_ca();
        builder.key_usage(KeyUsage::DigitalSignature);
        builder.add_extension_der_data(
            Oid(Bytes::copy_from_slice(&[85, 29, 37])),
            true,
            [
                0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
            ],
        );
        builder
            .create_with_random_keypair(KeyAlgorithm::Ed25519)
            .unwrap()
    }

    fn build_unprofiled_test_certificate(
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

    fn serve_once_http_response(status_line: &str, content_type: &str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let status_line = status_line.to_string();
        let content_type = content_type.to_string();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_buffer = [0u8; 4096];
            let _ = stream.read(&mut request_buffer);
            let response_headers = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response_headers.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });

        format!("http://{addr}")
    }
}
