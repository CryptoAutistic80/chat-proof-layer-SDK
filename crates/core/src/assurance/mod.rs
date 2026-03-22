use crate::{
    timestamp::{
        TimestampAssuranceProfile, TimestampError, TimestampTrustPolicy, TimestampVerification,
    },
    transparency::{
        ReceiptVerification, TransparencyError, TransparencyTrustPolicy, REKOR_TRANSPARENCY_KIND,
        SCITT_TRANSPARENCY_KIND,
    },
};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    #[default]
    Structural,
    Trusted,
    Qualified,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Warn,
    Fail,
    #[default]
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerificationCheck {
    pub id: String,
    pub label: String,
    pub state: CheckState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TimestampAssessment {
    pub level: TrustLevel,
    pub headline: String,
    pub summary: String,
    pub next_step: String,
    pub checks: Vec<VerificationCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptAssessment {
    pub level: TrustLevel,
    pub headline: String,
    pub summary: String,
    pub next_step: String,
    pub checks: Vec<VerificationCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_check: Option<ReceiptLiveVerification>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLiveCheckMode {
    #[default]
    Off,
    BestEffort,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceiptLiveVerification {
    pub mode: ReceiptLiveCheckMode,
    pub state: CheckState,
    pub checked_at: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_retrieved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_verified: Option<bool>,
}

pub fn assess_timestamp_verification(
    verification: &TimestampVerification,
    policy: Option<&TimestampTrustPolicy>,
) -> TimestampAssessment {
    let level = if verification.assurance_profile == Some(TimestampAssuranceProfile::Qualified)
        && verification.assurance_profile_verified
    {
        TrustLevel::Qualified
    } else if verification.trusted {
        TrustLevel::Trusted
    } else {
        TrustLevel::Structural
    };

    let (headline, summary, next_step) = match level {
        TrustLevel::Qualified => (
            "Qualified timestamp trust confirmed".to_string(),
            "The timestamp token matches this proof and passed the stronger trust checks you asked for.".to_string(),
            "Keep the trust files with the proof so another person can repeat the same check."
                .to_string(),
        ),
        TrustLevel::Trusted => (
            "Timestamp trust confirmed".to_string(),
            "The timestamp token matches this proof and chains to a trusted signer.".to_string(),
            "Keep the trust files with the proof so another person can repeat the same check."
                .to_string(),
        ),
        TrustLevel::Structural => (
            "Timestamp token is valid".to_string(),
            "The timestamp token matches this proof, but stronger trust checks were not proven."
                .to_string(),
            "Add trust files if you want to show who signed the timestamp and whether that signer was trusted."
                .to_string(),
        ),
    };

    TimestampAssessment {
        level,
        headline,
        summary,
        next_step,
        checks: vec![
            check(
                "bundle_root_match",
                "Bundle root match",
                CheckState::Pass,
                "The timestamp token matches this proof record.",
            ),
            check(
                "cms_signature",
                "Timestamp signature",
                CheckState::Pass,
                "The timestamp token signature and signed content are intact.",
            ),
            policy_check(
                "policy_oid",
                "Policy ID",
                has_policy_oids(policy),
                CheckState::Pass,
                format!("Matched policy ID {}.", verification.policy_oid),
                "No expected policy ID was configured.",
            ),
            policy_check(
                "trust_anchor",
                "Trusted signer chain",
                has_trust_anchors(policy),
                CheckState::Pass,
                verification
                    .trust_anchor_subject
                    .as_deref()
                    .map(|subject| format!("Chained to trusted certificate {subject}."))
                    .unwrap_or_else(|| {
                        "Chained to a trusted signer certificate.".to_string()
                    }),
                "No trusted signer certificate was configured.",
            ),
            policy_check(
                "certificate_profile",
                "Signer certificate profile",
                has_trust_anchors(policy),
                CheckState::Pass,
                verification
                    .signer_subject
                    .as_deref()
                    .map(|subject| {
                        format!(
                            "Signer certificate {subject} is valid for timestamping."
                        )
                    })
                    .unwrap_or_else(|| {
                        "The signer certificate is valid for timestamping.".to_string()
                    }),
                "Signer certificate profile checks were not requested.",
            ),
            policy_check(
                "crl",
                "Revocation list",
                has_crls(policy),
                CheckState::Pass,
                "The signer was checked against the supplied revocation list.".to_string(),
                "No revocation list was configured.",
            ),
            policy_check(
                "ocsp",
                "Online status check",
                has_ocsp(policy),
                CheckState::Pass,
                verification
                    .ocsp_responder_url
                    .as_deref()
                    .map(|url| format!("Status was checked with {url}."))
                    .unwrap_or_else(|| "Online signer status was checked.".to_string()),
                "No online status responder was configured.",
            ),
            policy_check(
                "qualified_signer",
                "Approved signer",
                has_qualified_signers(policy),
                CheckState::Pass,
                verification
                    .signer_subject
                    .as_deref()
                    .map(|subject| format!("Approved signer matched {subject}."))
                    .unwrap_or_else(|| "Approved signer matched.".to_string()),
                "No approved signer list was configured.",
            ),
            policy_check(
                "qualified_profile",
                "Qualified profile",
                requests_qualified(policy),
                CheckState::Pass,
                "All qualified timestamp checks passed.".to_string(),
                "Qualified timestamp checks were not requested.",
            ),
        ],
    }
}

pub fn assess_timestamp_error(
    error: &TimestampError,
    policy: Option<&TimestampTrustPolicy>,
) -> TimestampAssessment {
    let failed_check_id = timestamp_failed_check_id(error);
    let mut checks = vec![
        check(
            "bundle_root_match",
            "Bundle root match",
            timestamp_bundle_root_state(error),
            bundle_root_error_detail(error).unwrap_or_else(|| {
                "The timestamp token matches this proof record.".to_string()
            }),
        ),
        check(
            "cms_signature",
            "Timestamp signature",
            timestamp_signature_state(error),
            cms_error_detail(error).unwrap_or_else(|| {
                "The timestamp token signature and signed content are intact.".to_string()
            }),
        ),
        policy_check(
            "policy_oid",
            "Policy ID",
            has_policy_oids(policy),
            if failed_check_id == "policy_oid" {
                CheckState::Fail
            } else if timestamp_error_happened_after_policy(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            policy_error_detail(error)
                .unwrap_or_else(|| "The policy ID matched what was expected.".to_string()),
            "No expected policy ID was configured.",
        ),
        policy_check(
            "trust_anchor",
            "Trusted signer chain",
            has_trust_anchors(policy),
            if failed_check_id == "trust_anchor" {
                CheckState::Fail
            } else if timestamp_error_happened_after_trust_anchor(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            trust_anchor_error_detail(error)
                .unwrap_or_else(|| "The token chained to a trusted signer certificate.".to_string()),
            "No trusted signer certificate was configured.",
        ),
        policy_check(
            "certificate_profile",
            "Signer certificate profile",
            has_trust_anchors(policy),
            if failed_check_id == "certificate_profile" {
                CheckState::Fail
            } else if timestamp_error_happened_after_certificate_profile(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            certificate_profile_error_detail(error).unwrap_or_else(|| {
                "The signer certificate profile is suitable for timestamping.".to_string()
            }),
            "Signer certificate profile checks were not requested.",
        ),
        policy_check(
            "crl",
            "Revocation list",
            has_crls(policy),
            if failed_check_id == "crl" {
                CheckState::Fail
            } else if timestamp_error_happened_after_crl(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            crl_error_detail(error).unwrap_or_else(|| {
                "The signer was checked against the supplied revocation list.".to_string()
            }),
            "No revocation list was configured.",
        ),
        policy_check(
            "ocsp",
            "Online status check",
            has_ocsp(policy),
            if failed_check_id == "ocsp" {
                CheckState::Fail
            } else if timestamp_error_happened_after_ocsp(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            ocsp_error_detail(error)
                .unwrap_or_else(|| "Online signer status was checked.".to_string()),
            "No online status responder was configured.",
        ),
        policy_check(
            "qualified_signer",
            "Approved signer",
            has_qualified_signers(policy),
            if failed_check_id == "qualified_signer" {
                CheckState::Fail
            } else if timestamp_error_happened_after_qualified_signer(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            qualified_signer_error_detail(error)
                .unwrap_or_else(|| "Approved signer matched.".to_string()),
            "No approved signer list was configured.",
        ),
        policy_check(
            "qualified_profile",
            "Qualified profile",
            requests_qualified(policy),
            if requests_qualified(policy) && failed_check_id != "cms_signature" {
                CheckState::Warn
            } else {
                CheckState::NotRun
            },
            "The stronger qualified check could not be completed.".to_string(),
            "Qualified timestamp checks were not requested.",
        ),
    ];

    if let Some(check) = checks.iter_mut().find(|check| check.id == failed_check_id) {
        check.detail = Some(timestamp_failure_summary(error));
    }

    TimestampAssessment {
        level: TrustLevel::Structural,
        headline: "Timestamp check failed".to_string(),
        summary: timestamp_failure_summary(error),
        next_step: timestamp_failure_next_step(failed_check_id).to_string(),
        checks,
    }
}

pub fn assess_receipt_verification(
    verification: &ReceiptVerification,
    policy: Option<&TransparencyTrustPolicy>,
) -> ReceiptAssessment {
    let level = if policy
        .and_then(|policy| policy.timestamp.assurance_profile)
        == Some(TimestampAssuranceProfile::Qualified)
        && verification.trusted
    {
        TrustLevel::Qualified
    } else if verification.trusted {
        TrustLevel::Trusted
    } else {
        TrustLevel::Structural
    };

    let live_check = verification.live_verification.clone();
    let live_summary = match live_check.as_ref() {
        Some(live) if live.state == CheckState::Pass => {
            " The log was also checked live.".to_string()
        }
        Some(live) if live.state == CheckState::Warn => {
            " The stored receipt checked out, but a live log check could not be confirmed."
                .to_string()
        }
        Some(live) if live.state == CheckState::Fail => {
            " The stored receipt checked out, but the requested live log check failed."
                .to_string()
        }
        _ => String::new(),
    };

    let (headline, summary, next_step) = match level {
        TrustLevel::Qualified => (
            "Transparency proof confirmed at qualified level".to_string(),
            format!(
                "The receipt matches this proof and the attached timestamp met the stronger qualified check.{}",
                live_summary
            ),
            "Keep the trusted log key and timestamp trust files so another person can repeat the same check."
                .to_string(),
        ),
        TrustLevel::Trusted => (
            "Transparency proof confirmed".to_string(),
            format!(
                "The receipt matches this proof and the log or service key was trusted.{}",
                live_summary
            ),
            "Keep the trusted log key with the proof so another person can repeat the same check."
                .to_string(),
        ),
        TrustLevel::Structural => (
            "Transparency receipt is valid".to_string(),
            format!(
                "The stored receipt matches this proof, but stronger trust checks were not proven.{}",
                live_summary
            ),
            "Add the trusted log key if you want to show who issued the receipt.".to_string(),
        ),
    };

    let live_state = live_check
        .as_ref()
        .map(|live| live.state)
        .unwrap_or(CheckState::NotRun);
    let live_detail = live_check
        .as_ref()
        .map(|live| live.summary.clone())
        .unwrap_or_else(|| "No live log check was requested.".to_string());

    let kind_label = if verification.kind == SCITT_TRANSPARENCY_KIND {
        "service receipt"
    } else {
        "log receipt"
    };

    ReceiptAssessment {
        level,
        headline,
        summary,
        next_step,
        checks: vec![
            check(
                "bundle_root_match",
                "Bundle root match",
                CheckState::Pass,
                format!("The {kind_label} matches this proof record."),
            ),
            check(
                "embedded_timestamp",
                "Embedded timestamp",
                CheckState::Pass,
                "The embedded timestamp token matches this proof record.",
            ),
            check(
                "inclusion_proof",
                "Inclusion proof",
                if verification.kind == REKOR_TRANSPARENCY_KIND {
                    CheckState::Pass
                } else {
                    CheckState::NotRun
                },
                if verification.kind == REKOR_TRANSPARENCY_KIND {
                    "The stored Rekor inclusion proof is valid.".to_string()
                } else {
                    "This SCITT receipt uses a service receipt instead of a Rekor inclusion proof."
                        .to_string()
                },
            ),
            check(
                "signed_entry_timestamp",
                "Receipt signature",
                if verification.signed_entry_timestamp_verified {
                    CheckState::Pass
                } else if verification.signed_entry_timestamp_present {
                    CheckState::NotRun
                } else {
                    CheckState::Fail
                },
                if verification.signed_entry_timestamp_verified {
                    "The receipt signature was verified with the trusted log or service key."
                        .to_string()
                } else if verification.signed_entry_timestamp_present {
                    "A receipt signature is present, but no trusted log or service key was supplied."
                        .to_string()
                } else {
                    "The receipt did not include a signature to check.".to_string()
                },
            ),
            check(
                "trusted_log_key",
                "Trusted log key",
                if verification.log_id_verified {
                    CheckState::Pass
                } else {
                    CheckState::NotRun
                },
                if verification.log_id_verified {
                    "The trusted log or service key matched the receipt.".to_string()
                } else {
                    "No trusted log or service key was supplied.".to_string()
                },
            ),
            check(
                "live_log_confirmation",
                "Live log confirmation",
                live_state,
                live_detail,
            ),
        ],
        live_check,
    }
}

pub fn assess_receipt_error(
    error: &TransparencyError,
    policy: Option<&TransparencyTrustPolicy>,
    live_check: Option<ReceiptLiveVerification>,
) -> ReceiptAssessment {
    let failed_check_id = receipt_failed_check_id(error);
    let live_state = live_check
        .as_ref()
        .map(|live| live.state)
        .unwrap_or(CheckState::NotRun);
    let live_detail = live_check
        .as_ref()
        .map(|live| live.summary.clone())
        .unwrap_or_else(|| "No live log check was requested.".to_string());
    let kind_uses_inclusion = !matches!(error, TransparencyError::UnsupportedReceiptKind(kind) if kind == SCITT_TRANSPARENCY_KIND);

    let checks = vec![
        check(
            "bundle_root_match",
            "Bundle root match",
            if failed_check_id == "bundle_root_match" {
                CheckState::Fail
            } else if receipt_error_happened_after_bundle_root(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            if failed_check_id == "bundle_root_match" {
                receipt_failure_summary(error)
            } else {
                "The receipt matches this proof record.".to_string()
            },
        ),
        check(
            "embedded_timestamp",
            "Embedded timestamp",
            if failed_check_id == "embedded_timestamp" {
                CheckState::Fail
            } else if receipt_error_happened_after_timestamp(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            if failed_check_id == "embedded_timestamp" {
                receipt_failure_summary(error)
            } else {
                "The embedded timestamp token matches this proof record.".to_string()
            },
        ),
        check(
            "inclusion_proof",
            "Inclusion proof",
            if failed_check_id == "inclusion_proof" {
                CheckState::Fail
            } else if kind_uses_inclusion && receipt_error_happened_after_inclusion(error) {
                CheckState::Pass
            } else {
                CheckState::NotRun
            },
            if failed_check_id == "inclusion_proof" {
                receipt_failure_summary(error)
            } else {
                "The stored inclusion proof was valid or was not needed.".to_string()
            },
        ),
        check(
            "signed_entry_timestamp",
            "Receipt signature",
            if failed_check_id == "signed_entry_timestamp" {
                CheckState::Fail
            } else {
                CheckState::NotRun
            },
            if failed_check_id == "signed_entry_timestamp" {
                receipt_failure_summary(error)
            } else {
                "No receipt signature check was completed.".to_string()
            },
        ),
        check(
            "trusted_log_key",
            "Trusted log key",
            if failed_check_id == "trusted_log_key" {
                CheckState::Fail
            } else if has_log_public_key(policy) && receipt_error_happened_after_trusted_key(error) {
                CheckState::Pass
            } else if has_log_public_key(policy) {
                CheckState::Warn
            } else {
                CheckState::NotRun
            },
            if failed_check_id == "trusted_log_key" {
                receipt_failure_summary(error)
            } else if has_log_public_key(policy) {
                "A trusted log or service key was supplied.".to_string()
            } else {
                "No trusted log or service key was supplied.".to_string()
            },
        ),
        check(
            "live_log_confirmation",
            "Live log confirmation",
            if failed_check_id == "live_log_confirmation" {
                CheckState::Fail
            } else {
                live_state
            },
            if failed_check_id == "live_log_confirmation" {
                receipt_failure_summary(error)
            } else {
                live_detail
            },
        ),
    ];

    ReceiptAssessment {
        level: TrustLevel::Structural,
        headline: "Transparency receipt check failed".to_string(),
        summary: receipt_failure_summary(error),
        next_step: receipt_failure_next_step(failed_check_id).to_string(),
        checks,
        live_check,
    }
}

fn check(id: &str, label: &str, state: CheckState, detail: impl Into<String>) -> VerificationCheck {
    VerificationCheck {
        id: id.to_string(),
        label: label.to_string(),
        state,
        detail: Some(detail.into()),
    }
}

fn policy_check(
    id: &str,
    label: &str,
    enabled: bool,
    enabled_state: CheckState,
    enabled_detail: impl Into<String>,
    disabled_detail: impl Into<String>,
) -> VerificationCheck {
    if enabled {
        check(id, label, enabled_state, enabled_detail)
    } else {
        check(id, label, CheckState::NotRun, disabled_detail)
    }
}

fn requests_qualified(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .and_then(|policy| policy.assurance_profile)
        == Some(TimestampAssuranceProfile::Qualified)
}

fn has_policy_oids(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .into_iter()
        .flat_map(|policy| policy.policy_oids.iter())
        .any(|value| !value.trim().is_empty())
}

fn has_trust_anchors(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .into_iter()
        .flat_map(|policy| policy.trust_anchor_pems.iter())
        .any(|value| !value.trim().is_empty())
}

fn has_crls(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .into_iter()
        .flat_map(|policy| policy.crl_pems.iter())
        .any(|value| !value.trim().is_empty())
}

fn has_ocsp(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .into_iter()
        .flat_map(|policy| policy.ocsp_responder_urls.iter())
        .any(|value| !value.trim().is_empty())
}

fn has_qualified_signers(policy: Option<&TimestampTrustPolicy>) -> bool {
    policy
        .into_iter()
        .flat_map(|policy| policy.qualified_signer_pems.iter())
        .any(|value| !value.trim().is_empty())
}

fn has_log_public_key(policy: Option<&TransparencyTrustPolicy>) -> bool {
    policy
        .and_then(|policy| policy.log_public_key_pem.as_deref())
        .is_some_and(|pem| !pem.trim().is_empty())
}

fn timestamp_bundle_root_state(error: &TimestampError) -> CheckState {
    match error {
        TimestampError::MessageImprintMismatch { .. } => CheckState::Fail,
        TimestampError::CmsParse(_)
        | TimestampError::TstInfoParse(_)
        | TimestampError::NoSigners
        | TimestampError::MissingSignedContent
        | TimestampError::SignerVerification(_)
        | TimestampError::UnsupportedKind(_)
        | TimestampError::InvalidBase64(_)
        | TimestampError::UnsupportedImprintAlgorithm(_) => CheckState::NotRun,
        _ => CheckState::Pass,
    }
}

fn timestamp_signature_state(error: &TimestampError) -> CheckState {
    match error {
        TimestampError::CmsParse(_)
        | TimestampError::TstInfoParse(_)
        | TimestampError::NoSigners
        | TimestampError::MissingSignedContent
        | TimestampError::SignerVerification(_)
        | TimestampError::UnsupportedKind(_)
        | TimestampError::InvalidBase64(_)
        | TimestampError::UnsupportedImprintAlgorithm(_) => CheckState::Fail,
        TimestampError::MessageImprintMismatch { .. } => CheckState::Pass,
        _ => CheckState::Pass,
    }
}

fn timestamp_failed_check_id(error: &TimestampError) -> &'static str {
    match error {
        TimestampError::MessageImprintMismatch { .. } => "bundle_root_match",
        TimestampError::CmsParse(_)
        | TimestampError::TstInfoParse(_)
        | TimestampError::NoSigners
        | TimestampError::MissingSignedContent
        | TimestampError::SignerVerification(_)
        | TimestampError::UnsupportedKind(_)
        | TimestampError::InvalidBase64(_)
        | TimestampError::UnsupportedImprintAlgorithm(_) => "cms_signature",
        TimestampError::UnexpectedPolicyOid { .. }
        | TimestampError::InvalidPolicyOid(_)
        | TimestampError::QualifiedAssuranceRequiresPolicyOids => "policy_oid",
        TimestampError::MissingTrustAnchors
        | TimestampError::QualifiedAssuranceRequiresTrustAnchors
        | TimestampError::InvalidTrustAnchor(_)
        | TimestampError::SignerCertificateNotTrusted { .. } => "trust_anchor",
        TimestampError::CertificateNotValidAtGenerationTime { .. }
        | TimestampError::SignerCertificateIsCa { .. }
        | TimestampError::SignerCertificateInvalidExtendedKeyUsage { .. }
        | TimestampError::SignerCertificateInvalidKeyUsage { .. } => "certificate_profile",
        TimestampError::QualifiedAssuranceRequiresCrls
        | TimestampError::RevocationRequiresTrustAnchors
        | TimestampError::InvalidCrl(_)
        | TimestampError::MissingCrlIssuerCertificate { .. }
        | TimestampError::MissingApplicableCrl { .. }
        | TimestampError::CrlNotValidAtGenerationTime { .. }
        | TimestampError::CrlSignatureVerification { .. }
        | TimestampError::SignerCertificateRevoked { .. } => "crl",
        TimestampError::OcspRequiresTrustAnchors
        | TimestampError::InvalidOcspResponderUrl(_)
        | TimestampError::OcspTransport { .. }
        | TimestampError::OcspHttpStatus { .. }
        | TimestampError::InvalidOcspResponse { .. }
        | TimestampError::OcspUnsuccessfulResponse { .. }
        | TimestampError::MissingApplicableOcspStatus { .. }
        | TimestampError::SignerCertificateOcspUnknown { .. }
        | TimestampError::OcspResponseNotCurrent { .. }
        | TimestampError::OcspResponseVerification { .. }
        | TimestampError::SignerCertificateRevokedByOcsp { .. } => "ocsp",
        TimestampError::QualifiedAssuranceRequiresQualifiedSigners
        | TimestampError::InvalidQualifiedSigner(_)
        | TimestampError::UnexpectedQualifiedSigner { .. } => "qualified_signer",
        _ => "cms_signature",
    }
}

fn timestamp_error_happened_after_policy(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::CmsParse(_)
            | TimestampError::TstInfoParse(_)
            | TimestampError::NoSigners
            | TimestampError::MissingSignedContent
            | TimestampError::SignerVerification(_)
            | TimestampError::UnsupportedKind(_)
            | TimestampError::InvalidBase64(_)
            | TimestampError::UnsupportedImprintAlgorithm(_)
            | TimestampError::MessageImprintMismatch { .. }
            | TimestampError::UnexpectedPolicyOid { .. }
            | TimestampError::InvalidPolicyOid(_)
            | TimestampError::QualifiedAssuranceRequiresPolicyOids
    )
}

fn timestamp_error_happened_after_trust_anchor(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::MissingTrustAnchors
            | TimestampError::QualifiedAssuranceRequiresTrustAnchors
            | TimestampError::InvalidTrustAnchor(_)
            | TimestampError::SignerCertificateNotTrusted { .. }
    )
    && timestamp_error_happened_after_policy(error)
}

fn timestamp_error_happened_after_certificate_profile(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::CertificateNotValidAtGenerationTime { .. }
            | TimestampError::SignerCertificateIsCa { .. }
            | TimestampError::SignerCertificateInvalidExtendedKeyUsage { .. }
            | TimestampError::SignerCertificateInvalidKeyUsage { .. }
    )
    && timestamp_error_happened_after_trust_anchor(error)
}

fn timestamp_error_happened_after_crl(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::QualifiedAssuranceRequiresCrls
            | TimestampError::RevocationRequiresTrustAnchors
            | TimestampError::InvalidCrl(_)
            | TimestampError::MissingCrlIssuerCertificate { .. }
            | TimestampError::MissingApplicableCrl { .. }
            | TimestampError::CrlNotValidAtGenerationTime { .. }
            | TimestampError::CrlSignatureVerification { .. }
            | TimestampError::SignerCertificateRevoked { .. }
    )
    && timestamp_error_happened_after_certificate_profile(error)
}

fn timestamp_error_happened_after_ocsp(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::OcspRequiresTrustAnchors
            | TimestampError::InvalidOcspResponderUrl(_)
            | TimestampError::OcspTransport { .. }
            | TimestampError::OcspHttpStatus { .. }
            | TimestampError::InvalidOcspResponse { .. }
            | TimestampError::OcspUnsuccessfulResponse { .. }
            | TimestampError::MissingApplicableOcspStatus { .. }
            | TimestampError::SignerCertificateOcspUnknown { .. }
            | TimestampError::OcspResponseNotCurrent { .. }
            | TimestampError::OcspResponseVerification { .. }
            | TimestampError::SignerCertificateRevokedByOcsp { .. }
    )
    && timestamp_error_happened_after_crl(error)
}

fn timestamp_error_happened_after_qualified_signer(error: &TimestampError) -> bool {
    !matches!(
        error,
        TimestampError::QualifiedAssuranceRequiresQualifiedSigners
            | TimestampError::InvalidQualifiedSigner(_)
            | TimestampError::UnexpectedQualifiedSigner { .. }
    )
    && timestamp_error_happened_after_ocsp(error)
}

fn bundle_root_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::MessageImprintMismatch { expected, actual } => Some(format!(
            "The token was for a different proof record: expected {expected}, got {actual}."
        )),
        _ => None,
    }
}

fn cms_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::CmsParse(message)
        | TimestampError::TstInfoParse(message)
        | TimestampError::SignerVerification(message) => Some(message.clone()),
        TimestampError::NoSigners => Some("The timestamp token did not contain a signer.".to_string()),
        TimestampError::MissingSignedContent => {
            Some("The timestamp token did not contain signed timestamp data.".to_string())
        }
        TimestampError::UnsupportedKind(kind) => {
            Some(format!("Unsupported timestamp token kind {kind}."))
        }
        TimestampError::InvalidBase64(message) => Some(message.clone()),
        TimestampError::UnsupportedImprintAlgorithm(message) => Some(message.clone()),
        _ => None,
    }
}

fn policy_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::UnexpectedPolicyOid { actual } => {
            Some(format!("The token used policy ID {actual}, which was not expected."))
        }
        TimestampError::InvalidPolicyOid(message) => Some(message.clone()),
        TimestampError::QualifiedAssuranceRequiresPolicyOids => Some(
            "The stronger qualified check needs at least one expected policy ID.".to_string(),
        ),
        _ => None,
    }
}

fn trust_anchor_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::MissingTrustAnchors => {
            Some("A trusted signer certificate is required for this check.".to_string())
        }
        TimestampError::QualifiedAssuranceRequiresTrustAnchors => Some(
            "The stronger qualified check needs at least one trusted signer certificate."
                .to_string(),
        ),
        TimestampError::InvalidTrustAnchor(message) => Some(message.clone()),
        TimestampError::SignerCertificateNotTrusted { subject } => {
            Some(format!("Signer certificate {subject} did not chain to a trusted signer."))
        }
        _ => None,
    }
}

fn certificate_profile_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::CertificateNotValidAtGenerationTime {
            subject,
            generated_at,
        } => Some(format!(
            "Signer certificate {subject} was not valid when the timestamp was created at {generated_at}."
        )),
        TimestampError::SignerCertificateIsCa { subject } => Some(format!(
            "Signer certificate {subject} was marked as a certificate authority, which is not valid for timestamp signing."
        )),
        TimestampError::SignerCertificateInvalidExtendedKeyUsage { subject } => Some(format!(
            "Signer certificate {subject} was not limited to timestamp signing."
        )),
        TimestampError::SignerCertificateInvalidKeyUsage { subject } => Some(format!(
            "Signer certificate {subject} did not have the right key-usage settings."
        )),
        _ => None,
    }
}

fn crl_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::QualifiedAssuranceRequiresCrls => Some(
            "The stronger qualified check needs at least one revocation list.".to_string(),
        ),
        TimestampError::RevocationRequiresTrustAnchors => Some(
            "Revocation checking needs a trusted signer certificate too.".to_string(),
        ),
        TimestampError::InvalidCrl(message) => Some(message.clone()),
        TimestampError::MissingCrlIssuerCertificate { subject } => Some(format!(
            "No issuer certificate was found for signer certificate {subject}."
        )),
        TimestampError::MissingApplicableCrl { subject } => Some(format!(
            "No matching revocation list was found for signer certificate {subject}."
        )),
        TimestampError::CrlNotValidAtGenerationTime {
            subject,
            generated_at,
        } => Some(format!(
            "The revocation list for signer certificate {subject} was not current at {generated_at}."
        )),
        TimestampError::CrlSignatureVerification { subject } => Some(format!(
            "The revocation list signature for signer certificate {subject} could not be verified."
        )),
        TimestampError::SignerCertificateRevoked { subject, revoked_at } => Some(format!(
            "Signer certificate {subject} had already been revoked at {revoked_at}."
        )),
        _ => None,
    }
}

fn ocsp_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::OcspRequiresTrustAnchors => Some(
            "Online status checking needs a trusted signer certificate too.".to_string(),
        ),
        TimestampError::InvalidOcspResponderUrl(message) => Some(message.clone()),
        TimestampError::OcspTransport { url, message } => {
            Some(format!("Could not contact the online status service at {url}: {message}."))
        }
        TimestampError::OcspHttpStatus { url, status } => Some(format!(
            "The online status service at {url} returned HTTP {status}."
        )),
        TimestampError::InvalidOcspResponse { url, message } => Some(format!(
            "The online status service at {url} returned an invalid response: {message}."
        )),
        TimestampError::OcspUnsuccessfulResponse { url, status } => Some(format!(
            "The online status service at {url} returned status {status}."
        )),
        TimestampError::MissingApplicableOcspStatus { url, subject } => Some(format!(
            "The online status service at {url} did not include a result for signer certificate {subject}."
        )),
        TimestampError::SignerCertificateOcspUnknown { url, subject } => Some(format!(
            "The online status service at {url} returned an unknown result for signer certificate {subject}."
        )),
        TimestampError::OcspResponseNotCurrent { url, subject } => Some(format!(
            "The online status response at {url} was not current for signer certificate {subject}."
        )),
        TimestampError::OcspResponseVerification {
            url,
            subject,
            message,
        } => Some(format!(
            "The online status response at {url} could not be verified for signer certificate {subject}: {message}."
        )),
        TimestampError::SignerCertificateRevokedByOcsp {
            subject,
            revoked_at,
            url,
        } => Some(format!(
            "The online status service at {url} reported signer certificate {subject} as revoked at {revoked_at}."
        )),
        _ => None,
    }
}

fn qualified_signer_error_detail(error: &TimestampError) -> Option<String> {
    match error {
        TimestampError::QualifiedAssuranceRequiresQualifiedSigners => Some(
            "The stronger qualified check needs at least one approved signer certificate."
                .to_string(),
        ),
        TimestampError::InvalidQualifiedSigner(message) => Some(message.clone()),
        TimestampError::UnexpectedQualifiedSigner { subject } => Some(format!(
            "Signer certificate {subject} did not match the approved signer list."
        )),
        _ => None,
    }
}

fn timestamp_failure_summary(error: &TimestampError) -> String {
    bundle_root_error_detail(error)
        .or_else(|| cms_error_detail(error))
        .or_else(|| policy_error_detail(error))
        .or_else(|| trust_anchor_error_detail(error))
        .or_else(|| certificate_profile_error_detail(error))
        .or_else(|| crl_error_detail(error))
        .or_else(|| ocsp_error_detail(error))
        .or_else(|| qualified_signer_error_detail(error))
        .unwrap_or_else(|| error.to_string())
}

fn timestamp_failure_next_step(check_id: &str) -> &'static str {
    match check_id {
        "bundle_root_match" => "Check that the timestamp belongs to this exact proof record.",
        "cms_signature" => "Use the original timestamp token or request a fresh one.",
        "policy_oid" => "Use the expected policy ID or update the policy list.",
        "trust_anchor" => "Add the right trusted signer certificate for this timestamp.",
        "certificate_profile" => {
            "Use a signer certificate that is meant for timestamp signing."
        }
        "crl" => "Add a current revocation list for the timestamp signer.",
        "ocsp" => "Check the online status settings or try again later.",
        "qualified_signer" => {
            "Add the right approved signer certificate for the stronger check."
        }
        _ => "Check the timestamp files and try again.",
    }
}

fn receipt_failed_check_id(error: &TransparencyError) -> &'static str {
    match error {
        TransparencyError::Timestamp(_) => "embedded_timestamp",
        TransparencyError::LeafHashMismatch { .. }
        | TransparencyError::InvalidBody(_)
        | TransparencyError::MissingStatement
        | TransparencyError::InvalidStatementEncoding(_)
        | TransparencyError::InvalidStatementHash(_)
        | TransparencyError::UnsupportedScittStatementProfile(_)
        | TransparencyError::InvalidEntryUuid(_)
        | TransparencyError::InvalidEntryEncoding(_) => "bundle_root_match",
        TransparencyError::MissingInclusionProof
        | TransparencyError::InvalidTreeSize { .. }
        | TransparencyError::InvalidProofHash(_)
        | TransparencyError::InvalidRootHash(_)
        | TransparencyError::InvalidProofLength { .. }
        | TransparencyError::InclusionProofRootMismatch { .. } => "inclusion_proof",
        TransparencyError::MissingSignedEntryTimestamp
        | TransparencyError::SignedEntryTimestampVerification
        | TransparencyError::InvalidSignedEntryTimestamp(_)
        | TransparencyError::MissingReceiptSignature
        | TransparencyError::InvalidReceiptSignature(_)
        | TransparencyError::ReceiptSignatureVerification => "signed_entry_timestamp",
        TransparencyError::MissingLogPublicKey
        | TransparencyError::InvalidLogPublicKey(_)
        | TransparencyError::TransparencyKeyIdMismatch { .. } => "trusted_log_key",
        TransparencyError::LiveCheckUnsupported { .. }
        | TransparencyError::LiveCheckTransport { .. }
        | TransparencyError::LiveCheckHttpStatus { .. }
        | TransparencyError::LiveCheckResponse { .. }
        | TransparencyError::LiveConsistencyProofMismatch
        | TransparencyError::LiveEntryMismatch { .. } => "live_log_confirmation",
        _ => "bundle_root_match",
    }
}

fn receipt_error_happened_after_bundle_root(error: &TransparencyError) -> bool {
    !matches!(
        error,
        TransparencyError::LeafHashMismatch { .. }
            | TransparencyError::InvalidBody(_)
            | TransparencyError::MissingStatement
            | TransparencyError::InvalidStatementEncoding(_)
            | TransparencyError::InvalidStatementHash(_)
            | TransparencyError::UnsupportedScittStatementProfile(_)
            | TransparencyError::InvalidEntryUuid(_)
            | TransparencyError::InvalidEntryEncoding(_)
    )
}

fn receipt_error_happened_after_timestamp(error: &TransparencyError) -> bool {
    !matches!(error, TransparencyError::Timestamp(_)) && receipt_error_happened_after_bundle_root(error)
}

fn receipt_error_happened_after_inclusion(error: &TransparencyError) -> bool {
    !matches!(
        error,
        TransparencyError::MissingInclusionProof
            | TransparencyError::InvalidTreeSize { .. }
            | TransparencyError::InvalidProofHash(_)
            | TransparencyError::InvalidRootHash(_)
            | TransparencyError::InvalidProofLength { .. }
            | TransparencyError::InclusionProofRootMismatch { .. }
    ) && receipt_error_happened_after_timestamp(error)
}

fn receipt_error_happened_after_trusted_key(error: &TransparencyError) -> bool {
    !matches!(
        error,
        TransparencyError::MissingLogPublicKey
            | TransparencyError::InvalidLogPublicKey(_)
            | TransparencyError::TransparencyKeyIdMismatch { .. }
    ) && receipt_error_happened_after_inclusion(error)
}

fn receipt_failure_summary(error: &TransparencyError) -> String {
    match error {
        TransparencyError::Timestamp(source) => timestamp_failure_summary(source),
        TransparencyError::MissingInclusionProof => {
            "The receipt did not include an inclusion proof.".to_string()
        }
        TransparencyError::InvalidTreeSize {
            log_index,
            tree_size,
        } => format!(
            "The inclusion proof tree size {tree_size} is not valid for log index {log_index}."
        ),
        TransparencyError::InvalidProofHash(message)
        | TransparencyError::InvalidRootHash(message)
        | TransparencyError::InvalidSignedEntryTimestamp(message)
        | TransparencyError::InvalidEntryUuid(message)
        | TransparencyError::InvalidLogId(message)
        | TransparencyError::InvalidEntryEncoding(message)
        | TransparencyError::InvalidStatementEncoding(message)
        | TransparencyError::InvalidStatementHash(message)
        | TransparencyError::InvalidServiceId(message)
        | TransparencyError::InvalidReceiptSignature(message)
        | TransparencyError::InvalidBody(message)
        | TransparencyError::InvalidLogPublicKey(message) => message.clone(),
        TransparencyError::LeafHashMismatch { expected, actual } => format!(
            "The receipt leaf hash did not match: expected {expected}, got {actual}."
        ),
        TransparencyError::InvalidProofLength { expected, actual } => format!(
            "The inclusion proof length was {actual}, but {expected} was expected."
        ),
        TransparencyError::InclusionProofRootMismatch { expected, actual } => format!(
            "The inclusion proof root did not match: expected {expected}, got {actual}."
        ),
        TransparencyError::MissingSignedEntryTimestamp => {
            "The receipt did not include a signature to verify.".to_string()
        }
        TransparencyError::MissingLogPublicKey => {
            "A trusted log or service key is required for this check.".to_string()
        }
        TransparencyError::TransparencyKeyIdMismatch { expected, actual } => format!(
            "The receipt key ID did not match the trusted key: expected {expected}, got {actual}."
        ),
        TransparencyError::SignedEntryTimestampVerification => {
            "The receipt signature could not be verified.".to_string()
        }
        TransparencyError::MissingReceiptSignature => {
            "The SCITT receipt did not include a service signature.".to_string()
        }
        TransparencyError::ReceiptSignatureVerification => {
            "The SCITT service signature could not be verified.".to_string()
        }
        TransparencyError::LiveCheckUnsupported { kind } => format!(
            "Live log confirmation is not supported for {kind} receipts."
        ),
        TransparencyError::LiveCheckTransport { url, message } => format!(
            "Could not reach the live log at {url}: {message}."
        ),
        TransparencyError::LiveCheckHttpStatus { url, status } => {
            format!("The live log at {url} returned HTTP {status}.")
        }
        TransparencyError::LiveCheckResponse { message } => message.clone(),
        TransparencyError::LiveConsistencyProofMismatch => {
            "The live log could not prove that the stored tree is consistent with the current tree."
                .to_string()
        }
        TransparencyError::LiveEntryMismatch { message } => message.clone(),
        _ => error.to_string(),
    }
}

fn receipt_failure_next_step(check_id: &str) -> &'static str {
    match check_id {
        "bundle_root_match" => "Check that the receipt belongs to this exact proof record.",
        "embedded_timestamp" => "Check the embedded timestamp token and try again.",
        "inclusion_proof" => "Use the original receipt or request a fresh one from the log.",
        "signed_entry_timestamp" => "Add the right log or service key and try again.",
        "trusted_log_key" => "Add the right trusted log or service key.",
        "live_log_confirmation" => "Try the live log check again or fall back to the stored proof.",
        _ => "Check the receipt files and try again.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_error_maps_wrong_policy_oid_to_policy_check() {
        let assessment = assess_timestamp_error(
            &TimestampError::UnexpectedPolicyOid {
                actual: "1.2.3.4".to_string(),
            },
            Some(&TimestampTrustPolicy {
                policy_oids: vec!["1.2.3.5".to_string()],
                ..TimestampTrustPolicy::default()
            }),
        );

        assert_eq!(assessment.headline, "Timestamp check failed");
        assert_eq!(
            assessment
                .checks
                .iter()
                .find(|check| check.id == "policy_oid")
                .map(|check| check.state),
            Some(CheckState::Fail)
        );
    }

    #[test]
    fn receipt_assessment_uses_live_check_copy_when_present() {
        let assessment = assess_receipt_verification(
            &ReceiptVerification {
                kind: REKOR_TRANSPARENCY_KIND.to_string(),
                provider: Some("rekor".to_string()),
                log_url: "https://rekor.example.test".to_string(),
                entry_uuid: "entry-1".to_string(),
                leaf_hash: "hash-1".to_string(),
                log_id: "log-1".to_string(),
                log_index: 1,
                integrated_time: "2026-03-01T00:00:00Z".to_string(),
                tree_size: 2,
                root_hash: "root-1".to_string(),
                inclusion_proof_hashes: 1,
                inclusion_proof_verified: true,
                signed_entry_timestamp_present: true,
                signed_entry_timestamp_verified: true,
                log_id_verified: true,
                trusted: true,
                timestamp_generated_at: "2026-03-01T00:00:00Z".to_string(),
                live_verification: Some(ReceiptLiveVerification {
                    mode: ReceiptLiveCheckMode::BestEffort,
                    state: CheckState::Pass,
                    checked_at: "2026-03-01T00:10:00Z".to_string(),
                    summary: "Live log confirmation passed.".to_string(),
                    current_tree_size: Some(4),
                    current_root_hash: Some("root-2".to_string()),
                    entry_retrieved: Some(true),
                    consistency_verified: Some(true),
                }),
            },
            Some(&TransparencyTrustPolicy {
                log_public_key_pem: Some("pem".to_string()),
                timestamp: TimestampTrustPolicy::default(),
            }),
        );

        assert_eq!(assessment.live_check.map(|live| live.state), Some(CheckState::Pass));
    }
}
