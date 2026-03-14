pub mod migration;
pub mod v01;

use crate::{
    canon::{CanonError, canonicalize_value},
    hash::{DigestError, parse_sha256_prefixed, sha256_prefixed},
    merkle::{MerkleError, compute_commitment},
    verify::{VerifyBundleRootError, verify_bundle_root},
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

pub const BUNDLE_VERSION: &str = "1.0";
pub const CANONICALIZATION_ALGORITHM: &str = "RFC8785-JCS";
pub const HASH_ALGORITHM: &str = "SHA-256";
pub const LEGACY_BUNDLE_ROOT_ALGORITHM: &str = "pl-merkle-sha256-v1";
pub const BUNDLE_ROOT_ALGORITHM_V2: &str = "pl-merkle-sha256-v2";
pub const BUNDLE_ROOT_ALGORITHM_V3: &str = "pl-merkle-sha256-v3";
pub const BUNDLE_ROOT_ALGORITHM_V4: &str = "pl-merkle-sha256-v4";
pub const BUNDLE_ROOT_ALGORITHM: &str = BUNDLE_ROOT_ALGORITHM_V4;
pub const SIGNATURE_FORMAT: &str = "JWS";
pub const SIGNATURE_ALGORITHM: &str = "EdDSA";

fn null_json() -> Value {
    Value::Null
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    #[default]
    Provider,
    Deployer,
    Integrator,
    Importer,
    Distributor,
    AuthorizedRepresentative,
    GpaiProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub issuer: String,
    pub app_id: String,
    pub env: String,
    pub signing_key_id: String,
    #[serde(default)]
    pub role: ActorRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Subject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prohibited_practice_screening: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_risk_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpai_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemic_risk: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fria_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_context: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

impl Default for ComplianceProfile {
    fn default() -> Self {
        Self {
            intended_use: None,
            prohibited_practice_screening: None,
            risk_tier: None,
            high_risk_domain: None,
            gpai_status: None,
            systemic_risk: None,
            fria_required: None,
            deployment_context: None,
            metadata: Value::Null,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub parameters: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otel_genai_semconv_version: Option<String>,
}

impl Default for EvidenceContext {
    fn default() -> Self {
        Self {
            provider: None,
            model: None,
            parameters: Value::Null,
            trace_commitment: None,
            otel_genai_semconv_version: None,
        }
    }
}

impl EvidenceContext {
    pub fn from_v01_capture(model: &v01::ModelInfo, trace: &v01::Trace) -> Self {
        Self {
            provider: Some(model.provider.clone()),
            model: Some(model.model.clone()),
            parameters: model.parameters.clone(),
            trace_commitment: Some(trace.trace_commitment.clone()),
            otel_genai_semconv_version: Some(trace.otel_genai_semconv_version.clone()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmInteractionEvidence {
    pub provider: String,
    pub model: String,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub parameters: Value,
    pub input_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_commitment: Option<String>,
    pub output_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_outputs_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<TokenUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_semconv_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCallEvidence {
    pub tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetrievalEvidence {
    pub corpus: String,
    pub result_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HumanOversightEvidence {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecisionEvidence {
    pub policy_name: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskAssessmentEvidence {
    pub risk_id: String,
    pub severity: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataGovernanceEvidence {
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_ref: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TechnicalDocEvidence {
    pub document_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelEvaluationEvidence {
    pub evaluation_id: String,
    pub benchmark: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdversarialTestEvidence {
    pub test_id: String,
    pub focus: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrainingProvenanceEvidence {
    pub dataset_ref: String,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConformityAssessmentEvidence {
    pub assessment_id: String,
    pub procedure: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeclarationEvidence {
    pub declaration_id: String,
    pub jurisdiction: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationEvidence {
    pub registration_id: String,
    pub authority: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LiteracyAttestationEvidence {
    pub attested_role: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstructionsForUseEvidence {
    pub document_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QmsRecordEvidence {
    pub record_id: String,
    pub process: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FundamentalRightsAssessmentEvidence {
    pub assessment_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardsAlignmentEvidence {
    pub standard_ref: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostMarketMonitoringEvidence {
    pub plan_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrectiveActionEvidence {
    pub action_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityNotificationEvidence {
    pub notification_id: String,
    pub authority: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthoritySubmissionEvidence {
    pub submission_id: String,
    pub authority: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportingDeadlineEvidence {
    pub deadline_id: String,
    pub authority: String,
    pub obligation_ref: String,
    pub due_at: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegulatorCorrespondenceEvidence {
    pub correspondence_id: String,
    pub authority: String,
    pub direction: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DownstreamDocumentationEvidence {
    pub document_ref: String,
    pub audience: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CopyrightPolicyEvidence {
    pub policy_ref: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrainingSummaryEvidence {
    pub summary_ref: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentReportEvidence {
    pub incident_id: String,
    pub severity: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_commitment: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EvidenceItem {
    LlmInteraction(LlmInteractionEvidence),
    ToolCall(ToolCallEvidence),
    Retrieval(RetrievalEvidence),
    HumanOversight(HumanOversightEvidence),
    PolicyDecision(PolicyDecisionEvidence),
    RiskAssessment(RiskAssessmentEvidence),
    DataGovernance(DataGovernanceEvidence),
    TechnicalDoc(TechnicalDocEvidence),
    ModelEvaluation(ModelEvaluationEvidence),
    AdversarialTest(AdversarialTestEvidence),
    TrainingProvenance(TrainingProvenanceEvidence),
    ConformityAssessment(ConformityAssessmentEvidence),
    Declaration(DeclarationEvidence),
    Registration(RegistrationEvidence),
    LiteracyAttestation(LiteracyAttestationEvidence),
    InstructionsForUse(InstructionsForUseEvidence),
    QmsRecord(QmsRecordEvidence),
    FundamentalRightsAssessment(FundamentalRightsAssessmentEvidence),
    StandardsAlignment(StandardsAlignmentEvidence),
    PostMarketMonitoring(PostMarketMonitoringEvidence),
    CorrectiveAction(CorrectiveActionEvidence),
    AuthorityNotification(AuthorityNotificationEvidence),
    AuthoritySubmission(AuthoritySubmissionEvidence),
    ReportingDeadline(ReportingDeadlineEvidence),
    RegulatorCorrespondence(RegulatorCorrespondenceEvidence),
    DownstreamDocumentation(DownstreamDocumentationEvidence),
    CopyrightPolicy(CopyrightPolicyEvidence),
    TrainingSummary(TrainingSummaryEvidence),
    IncidentReport(IncidentReportEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtefactRef {
    pub name: String,
    pub digest: String,
    pub size: u64,
    pub content_type: String,
}

pub type ArtefactMeta = ArtefactRef;
pub type ItemPathCommitmentParts = (String, BTreeMap<String, String>, BTreeMap<String, String>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EncryptionPolicy {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Policy {
    #[serde(default)]
    pub redactions: Vec<String>,
    #[serde(default)]
    pub encryption: EncryptionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureInfo {
    pub format: String,
    pub alg: String,
    pub kid: String,
    pub value: String,
}

impl Default for SignatureInfo {
    fn default() -> Self {
        Self {
            format: SIGNATURE_FORMAT.to_string(),
            alg: SIGNATURE_ALGORITHM.to_string(),
            kid: String::new(),
            value: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Integrity {
    pub canonicalization: String,
    pub hash: String,
    pub header_digest: String,
    pub bundle_root_algorithm: String,
    pub bundle_root: String,
    pub signature: SignatureInfo,
}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            canonicalization: CANONICALIZATION_ALGORITHM.to_string(),
            hash: HASH_ALGORITHM.to_string(),
            header_digest: String::new(),
            bundle_root_algorithm: BUNDLE_ROOT_ALGORITHM.to_string(),
            bundle_root: String::new(),
            signature: SignatureInfo::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimestampToken {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub token_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransparencyReceipt {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default = "null_json", skip_serializing_if = "Value::is_null")]
    pub body: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureEvent {
    pub actor: Actor,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_profile: Option<ComplianceProfile>,
    #[serde(default)]
    pub context: EvidenceContext,
    pub items: Vec<EvidenceItem>,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceBundle {
    pub bundle_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub actor: Actor,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_profile: Option<ComplianceProfile>,
    #[serde(default)]
    pub context: EvidenceContext,
    pub items: Vec<EvidenceItem>,
    pub artefacts: Vec<ArtefactRef>,
    #[serde(default)]
    pub policy: Policy,
    pub integrity: Integrity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<TransparencyReceipt>,
}

pub type ProofBundle = EvidenceBundle;

impl EvidenceBundle {
    pub fn legacy_canonical_header_projection(&self) -> Value {
        let mut header = serde_json::Map::new();
        header.insert("bundle_version".to_string(), json!(self.bundle_version));
        header.insert("bundle_id".to_string(), json!(self.bundle_id));
        header.insert("created_at".to_string(), json!(self.created_at));
        header.insert("actor".to_string(), json!(self.actor));
        header.insert("subject".to_string(), json!(self.subject));
        if let Some(profile) = &self.compliance_profile {
            header.insert("compliance_profile".to_string(), json!(profile));
        }
        header.insert("context".to_string(), json!(self.context));
        header.insert("items".to_string(), json!(self.items));
        header.insert("artefacts".to_string(), json!(self.artefacts));
        header.insert("policy".to_string(), json!(self.policy));
        Value::Object(header)
    }

    pub fn canonical_header_projection(&self) -> Value {
        let mut header = serde_json::Map::new();
        header.insert("bundle_version".to_string(), json!(self.bundle_version));
        header.insert("bundle_id".to_string(), json!(self.bundle_id));
        header.insert("created_at".to_string(), json!(self.created_at));
        header.insert("actor".to_string(), json!(self.actor));
        header.insert("subject".to_string(), json!(self.subject));
        if let Some(profile) = &self.compliance_profile {
            header.insert("compliance_profile".to_string(), json!(profile));
        }
        header.insert("context".to_string(), json!(self.context));
        header.insert("policy".to_string(), json!(self.policy));
        header.insert("item_count".to_string(), json!(self.items.len()));
        header.insert("artefact_count".to_string(), json!(self.artefacts.len()));
        Value::Object(header)
    }

    pub fn legacy_canonical_header_bytes(&self) -> Result<Vec<u8>, CanonError> {
        canonicalize_value(&self.legacy_canonical_header_projection())
    }

    pub fn canonical_header_bytes(&self) -> Result<Vec<u8>, CanonError> {
        canonicalize_value(&self.canonical_header_projection())
    }

    pub fn item_commitment_digests(&self) -> Result<Vec<String>, CanonError> {
        self.items
            .iter()
            .map(|item| {
                item_commitment_digest_for_algorithm(item, &self.integrity.bundle_root_algorithm)
            })
            .collect()
    }

    pub fn artefact_commitment_digests(&self) -> Result<Vec<String>, CanonError> {
        self.artefacts
            .iter()
            .map(artefact_commitment_digest)
            .collect()
    }

    pub fn commitment_digests(&self) -> Result<Vec<String>, CanonError> {
        match self.integrity.bundle_root_algorithm.as_str() {
            LEGACY_BUNDLE_ROOT_ALGORITHM => {
                let mut ordered_digests = Vec::with_capacity(1 + self.artefacts.len());
                ordered_digests.push(self.integrity.header_digest.clone());
                ordered_digests.extend(self.artefacts.iter().map(|item| item.digest.clone()));
                Ok(ordered_digests)
            }
            BUNDLE_ROOT_ALGORITHM_V2 => {
                let item_digests = self.item_commitment_digests()?;
                let artefact_digests = self.artefact_commitment_digests()?;
                let mut ordered_digests =
                    Vec::with_capacity(1 + item_digests.len() + artefact_digests.len());
                ordered_digests.push(self.integrity.header_digest.clone());
                ordered_digests.extend(item_digests);
                ordered_digests.extend(artefact_digests);
                Ok(ordered_digests)
            }
            BUNDLE_ROOT_ALGORITHM_V3 | BUNDLE_ROOT_ALGORITHM_V4 => {
                let item_digests = self.item_commitment_digests()?;
                let artefact_digests = self.artefact_commitment_digests()?;
                let mut ordered_digests =
                    Vec::with_capacity(1 + item_digests.len() + artefact_digests.len());
                ordered_digests.push(self.integrity.header_digest.clone());
                ordered_digests.extend(item_digests);
                ordered_digests.extend(artefact_digests);
                Ok(ordered_digests)
            }
            other => Err(CanonError::Canonicalization(format!(
                "unsupported bundle root algorithm {other}"
            ))),
        }
    }

    pub fn primary_llm_interaction(&self) -> Option<&LlmInteractionEvidence> {
        self.items.iter().find_map(|item| match item {
            EvidenceItem::LlmInteraction(evidence) => Some(evidence),
            _ => None,
        })
    }

    pub fn verify_with_artefacts(
        &self,
        artefacts: &BTreeMap<String, Vec<u8>>,
        verifying_key: &VerifyingKey,
    ) -> Result<VerificationSummary, BundleVerificationError> {
        validate_bundle_integrity_fields(self)?;

        let canonical_header = match self.integrity.bundle_root_algorithm.as_str() {
            LEGACY_BUNDLE_ROOT_ALGORITHM => self.legacy_canonical_header_bytes()?,
            BUNDLE_ROOT_ALGORITHM_V2 | BUNDLE_ROOT_ALGORITHM_V3 | BUNDLE_ROOT_ALGORITHM_V4 => {
                self.canonical_header_bytes()?
            }
            other => {
                return Err(BundleVerificationError::Canonicalization(
                    CanonError::Canonicalization(format!(
                        "unsupported bundle root algorithm {other}"
                    )),
                ));
            }
        };
        let computed_header_digest = sha256_prefixed(&canonical_header);
        if computed_header_digest != self.integrity.header_digest {
            return Err(BundleVerificationError::HeaderDigestMismatch {
                expected: self.integrity.header_digest.clone(),
                actual: computed_header_digest,
            });
        }

        for meta in &self.artefacts {
            let bytes = artefacts
                .get(&meta.name)
                .ok_or_else(|| BundleVerificationError::MissingArtefact(meta.name.clone()))?;
            if meta.size != bytes.len() as u64 {
                return Err(BundleVerificationError::ArtefactSizeMismatch {
                    name: meta.name.clone(),
                    expected: meta.size,
                    actual: bytes.len() as u64,
                });
            }
            let digest = sha256_prefixed(bytes);
            if digest != meta.digest {
                return Err(BundleVerificationError::ArtefactDigestMismatch {
                    name: meta.name.clone(),
                    expected: meta.digest.clone(),
                    actual: digest,
                });
            }
        }

        let commitment = compute_commitment(&self.commitment_digests()?)?;
        if commitment.root != self.integrity.bundle_root {
            return Err(BundleVerificationError::BundleRootMismatch {
                expected: self.integrity.bundle_root.clone(),
                actual: commitment.root,
            });
        }

        verify_bundle_root(
            &self.integrity.signature.value,
            &self.integrity.bundle_root,
            verifying_key,
        )?;

        Ok(VerificationSummary {
            artefact_count: self.artefacts.len(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSummary {
    pub artefact_count: usize,
}

#[derive(Debug, Error)]
pub enum BundleValidationError {
    #[error("bundle_version must be {expected}, got {actual}")]
    UnsupportedBundleVersion { expected: String, actual: String },
    #[error("bundle_id must not be empty")]
    EmptyBundleId,
    #[error("actor.signing_key_id must not be empty")]
    EmptySigningKeyId,
    #[error("bundle must contain at least one evidence item")]
    EmptyItems,
    #[error("duplicate artefact name found: {0}")]
    DuplicateArtefactName(String),
    #[error("invalid digest in {field}: {source}")]
    InvalidDigest { field: String, source: DigestError },
    #[error("unsupported canonicalization algorithm: {0}")]
    UnsupportedCanonicalization(String),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(String),
    #[error("unsupported bundle root algorithm: {0}")]
    UnsupportedBundleRootAlgorithm(String),
    #[error("unsupported signature format: {0}")]
    UnsupportedSignatureFormat(String),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("signature kid must not be empty")]
    EmptySignatureKid,
    #[error("signature value must not be empty")]
    EmptySignatureValue,
}

#[derive(Debug, Error)]
pub enum BundleVerificationError {
    #[error("bundle validation failed: {0}")]
    Validation(#[from] BundleValidationError),
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonError),
    #[error("header digest mismatch; expected {expected}, got {actual}")]
    HeaderDigestMismatch { expected: String, actual: String },
    #[error("missing artefact bytes for {0}")]
    MissingArtefact(String),
    #[error("artefact size mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactSizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("artefact digest mismatch for {name}; expected {expected}, got {actual}")]
    ArtefactDigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("bundle root mismatch; expected {expected}, got {actual}")]
    BundleRootMismatch { expected: String, actual: String },
    #[error("merkle commitment failed: {0}")]
    Merkle(#[from] MerkleError),
    #[error("signature verification failed: {0}")]
    VerifyBundleRoot(#[from] VerifyBundleRootError),
}

pub fn validate_bundle_integrity_fields(
    bundle: &EvidenceBundle,
) -> Result<(), BundleValidationError> {
    if bundle.bundle_version != BUNDLE_VERSION {
        return Err(BundleValidationError::UnsupportedBundleVersion {
            expected: BUNDLE_VERSION.to_string(),
            actual: bundle.bundle_version.clone(),
        });
    }
    if bundle.bundle_id.trim().is_empty() {
        return Err(BundleValidationError::EmptyBundleId);
    }
    if bundle.actor.signing_key_id.trim().is_empty() {
        return Err(BundleValidationError::EmptySigningKeyId);
    }
    if bundle.items.is_empty() {
        return Err(BundleValidationError::EmptyItems);
    }
    if bundle.integrity.canonicalization != CANONICALIZATION_ALGORITHM {
        return Err(BundleValidationError::UnsupportedCanonicalization(
            bundle.integrity.canonicalization.clone(),
        ));
    }
    if bundle.integrity.hash != HASH_ALGORITHM {
        return Err(BundleValidationError::UnsupportedHash(
            bundle.integrity.hash.clone(),
        ));
    }
    if bundle.integrity.bundle_root_algorithm != LEGACY_BUNDLE_ROOT_ALGORITHM
        && bundle.integrity.bundle_root_algorithm != BUNDLE_ROOT_ALGORITHM_V2
        && bundle.integrity.bundle_root_algorithm != BUNDLE_ROOT_ALGORITHM_V3
        && bundle.integrity.bundle_root_algorithm != BUNDLE_ROOT_ALGORITHM_V4
    {
        return Err(BundleValidationError::UnsupportedBundleRootAlgorithm(
            bundle.integrity.bundle_root_algorithm.clone(),
        ));
    }
    if bundle.integrity.signature.format != SIGNATURE_FORMAT {
        return Err(BundleValidationError::UnsupportedSignatureFormat(
            bundle.integrity.signature.format.clone(),
        ));
    }
    if bundle.integrity.signature.alg != SIGNATURE_ALGORITHM {
        return Err(BundleValidationError::UnsupportedSignatureAlgorithm(
            bundle.integrity.signature.alg.clone(),
        ));
    }
    if bundle.integrity.signature.kid.trim().is_empty() {
        return Err(BundleValidationError::EmptySignatureKid);
    }
    if bundle.integrity.signature.value.trim().is_empty() {
        return Err(BundleValidationError::EmptySignatureValue);
    }

    parse_sha256_prefixed(&bundle.integrity.header_digest).map_err(|source| {
        BundleValidationError::InvalidDigest {
            field: "integrity.header_digest".to_string(),
            source,
        }
    })?;
    parse_sha256_prefixed(&bundle.integrity.bundle_root).map_err(|source| {
        BundleValidationError::InvalidDigest {
            field: "integrity.bundle_root".to_string(),
            source,
        }
    })?;

    let mut seen = HashSet::new();
    for meta in &bundle.artefacts {
        if !seen.insert(meta.name.clone()) {
            return Err(BundleValidationError::DuplicateArtefactName(
                meta.name.clone(),
            ));
        }
        parse_sha256_prefixed(&meta.digest).map_err(|source| {
            BundleValidationError::InvalidDigest {
                field: format!("artefacts[{}].digest", meta.name),
                source,
            }
        })?;
    }

    for (index, item) in bundle.items.iter().enumerate() {
        validate_item_digests(index, item)?;
    }

    if let Some(trace_commitment) = &bundle.context.trace_commitment {
        parse_sha256_prefixed(trace_commitment).map_err(|source| {
            BundleValidationError::InvalidDigest {
                field: "context.trace_commitment".to_string(),
                source,
            }
        })?;
    }

    Ok(())
}

fn validate_item_digests(index: usize, item: &EvidenceItem) -> Result<(), BundleValidationError> {
    match item {
        EvidenceItem::LlmInteraction(evidence) => {
            validate_named_digest(index, "input_commitment", &evidence.input_commitment)?;
            validate_named_digest(index, "output_commitment", &evidence.output_commitment)?;
            if let Some(value) = &evidence.retrieval_commitment {
                validate_named_digest(index, "retrieval_commitment", value)?;
            }
            if let Some(value) = &evidence.tool_outputs_commitment {
                validate_named_digest(index, "tool_outputs_commitment", value)?;
            }
            if let Some(value) = &evidence.trace_commitment {
                validate_named_digest(index, "trace_commitment", value)?;
            }
        }
        EvidenceItem::ToolCall(evidence) => {
            if let Some(value) = &evidence.input_commitment {
                validate_named_digest(index, "input_commitment", value)?;
            }
            if let Some(value) = &evidence.output_commitment {
                validate_named_digest(index, "output_commitment", value)?;
            }
        }
        EvidenceItem::Retrieval(evidence) => {
            validate_named_digest(index, "result_commitment", &evidence.result_commitment)?;
            if let Some(value) = &evidence.query_commitment {
                validate_named_digest(index, "query_commitment", value)?;
            }
        }
        EvidenceItem::HumanOversight(evidence) => {
            if let Some(value) = &evidence.notes_commitment {
                validate_named_digest(index, "notes_commitment", value)?;
            }
        }
        EvidenceItem::PolicyDecision(evidence) => {
            if let Some(value) = &evidence.rationale_commitment {
                validate_named_digest(index, "rationale_commitment", value)?;
            }
        }
        EvidenceItem::InstructionsForUse(evidence) => {
            if let Some(value) = &evidence.commitment {
                validate_named_digest(index, "commitment", value)?;
            }
        }
        EvidenceItem::TechnicalDoc(evidence) => {
            if let Some(value) = &evidence.commitment {
                validate_named_digest(index, "commitment", value)?;
            }
        }
        EvidenceItem::QmsRecord(evidence) => {
            if let Some(value) = &evidence.record_commitment {
                validate_named_digest(index, "record_commitment", value)?;
            }
        }
        EvidenceItem::FundamentalRightsAssessment(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::StandardsAlignment(evidence) => {
            if let Some(value) = &evidence.mapping_commitment {
                validate_named_digest(index, "mapping_commitment", value)?;
            }
        }
        EvidenceItem::PostMarketMonitoring(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::CorrectiveAction(evidence) => {
            if let Some(value) = &evidence.record_commitment {
                validate_named_digest(index, "record_commitment", value)?;
            }
        }
        EvidenceItem::AuthorityNotification(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::AuthoritySubmission(evidence) => {
            if let Some(value) = &evidence.document_commitment {
                validate_named_digest(index, "document_commitment", value)?;
            }
        }
        EvidenceItem::ReportingDeadline(_) => {}
        EvidenceItem::RegulatorCorrespondence(evidence) => {
            if let Some(value) = &evidence.message_commitment {
                validate_named_digest(index, "message_commitment", value)?;
            }
        }
        EvidenceItem::ModelEvaluation(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::AdversarialTest(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::TrainingProvenance(evidence) => {
            if let Some(value) = &evidence.record_commitment {
                validate_named_digest(index, "record_commitment", value)?;
            }
        }
        EvidenceItem::ConformityAssessment(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::Declaration(evidence) => {
            if let Some(value) = &evidence.document_commitment {
                validate_named_digest(index, "document_commitment", value)?;
            }
        }
        EvidenceItem::Registration(evidence) => {
            if let Some(value) = &evidence.receipt_commitment {
                validate_named_digest(index, "receipt_commitment", value)?;
            }
        }
        EvidenceItem::DownstreamDocumentation(evidence) => {
            if let Some(value) = &evidence.commitment {
                validate_named_digest(index, "commitment", value)?;
            }
        }
        EvidenceItem::CopyrightPolicy(evidence) => {
            if let Some(value) = &evidence.commitment {
                validate_named_digest(index, "commitment", value)?;
            }
        }
        EvidenceItem::TrainingSummary(evidence) => {
            if let Some(value) = &evidence.commitment {
                validate_named_digest(index, "commitment", value)?;
            }
        }
        EvidenceItem::LiteracyAttestation(evidence) => {
            if let Some(value) = &evidence.attestation_commitment {
                validate_named_digest(index, "attestation_commitment", value)?;
            }
        }
        EvidenceItem::IncidentReport(evidence) => {
            if let Some(value) = &evidence.report_commitment {
                validate_named_digest(index, "report_commitment", value)?;
            }
        }
        EvidenceItem::RiskAssessment(_) | EvidenceItem::DataGovernance(_) => {}
    }

    Ok(())
}

pub fn item_commitment_digest(item: &EvidenceItem) -> Result<String, CanonError> {
    item_commitment_digest_for_algorithm(item, BUNDLE_ROOT_ALGORITHM)
}

pub fn item_commitment_digest_for_algorithm(
    item: &EvidenceItem,
    algorithm: &str,
) -> Result<String, CanonError> {
    match algorithm {
        LEGACY_BUNDLE_ROOT_ALGORITHM | BUNDLE_ROOT_ALGORITHM_V2 => {
            let canonical = canonicalize_value(&serde_json::to_value(item)?)?;
            Ok(sha256_prefixed(&canonical))
        }
        BUNDLE_ROOT_ALGORITHM_V3 => {
            let (item_type, field_digests) = item_field_commitment_digests(item)?;
            item_commitment_digest_from_fields(&item_type, &field_digests)
        }
        BUNDLE_ROOT_ALGORITHM_V4 => {
            let (item_type, container_kinds, path_digests) = item_path_commitment_digests(item)?;
            item_commitment_digest_from_paths(&item_type, &container_kinds, &path_digests)
        }
        other => Err(CanonError::Canonicalization(format!(
            "unsupported bundle root algorithm {other}"
        ))),
    }
}

pub fn item_field_commitment_digests(
    item: &EvidenceItem,
) -> Result<(String, BTreeMap<String, String>), CanonError> {
    let value = serde_json::to_value(item)?;
    let object = value.as_object().ok_or_else(|| {
        CanonError::Canonicalization("evidence item must serialize to an object".to_string())
    })?;
    let item_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonError::Canonicalization("evidence item is missing its type tag".to_string())
        })?
        .to_string();
    let data = object
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CanonError::Canonicalization("evidence item must serialize object data".to_string())
        })?;

    let mut field_digests = BTreeMap::new();
    for (field, value) in data {
        field_digests.insert(field.clone(), field_commitment_digest(value)?);
    }

    Ok((item_type, field_digests))
}

pub fn item_path_commitment_digests(
    item: &EvidenceItem,
) -> Result<ItemPathCommitmentParts, CanonError> {
    let value = serde_json::to_value(item)?;
    let object = value.as_object().ok_or_else(|| {
        CanonError::Canonicalization("evidence item must serialize to an object".to_string())
    })?;
    let item_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonError::Canonicalization("evidence item is missing its type tag".to_string())
        })?
        .to_string();
    let data = object
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CanonError::Canonicalization("evidence item must serialize object data".to_string())
        })?;

    let mut container_kinds = BTreeMap::new();
    let mut path_digests = BTreeMap::new();
    container_kinds.insert(String::new(), "object".to_string());
    for (field, value) in data {
        collect_path_commitment_digests(
            &format!("/{}", escape_json_pointer_segment(field)),
            value,
            &mut container_kinds,
            &mut path_digests,
        )?;
    }

    Ok((item_type, container_kinds, path_digests))
}

pub fn item_commitment_digest_from_fields(
    item_type: &str,
    field_digests: &BTreeMap<String, String>,
) -> Result<String, CanonError> {
    let canonical = canonicalize_value(&json!({
        "field_digests": field_digests,
        "item_type": item_type,
    }))?;
    Ok(sha256_prefixed(&canonical))
}

pub fn item_commitment_digest_from_paths(
    item_type: &str,
    container_kinds: &BTreeMap<String, String>,
    path_digests: &BTreeMap<String, String>,
) -> Result<String, CanonError> {
    let canonical = canonicalize_value(&json!({
        "container_kinds": container_kinds,
        "item_type": item_type,
        "path_digests": path_digests,
    }))?;
    Ok(sha256_prefixed(&canonical))
}

pub fn field_commitment_digest(value: &Value) -> Result<String, CanonError> {
    let canonical = canonicalize_value(value)?;
    Ok(sha256_prefixed(&canonical))
}

pub fn artefact_commitment_digest(meta: &ArtefactRef) -> Result<String, CanonError> {
    let canonical = canonicalize_value(&serde_json::to_value(meta)?)?;
    Ok(sha256_prefixed(&canonical))
}

fn validate_named_digest(
    index: usize,
    field: &str,
    value: &str,
) -> Result<(), BundleValidationError> {
    parse_sha256_prefixed(value).map_err(|source| BundleValidationError::InvalidDigest {
        field: format!("items[{index}].{field}"),
        source,
    })?;
    Ok(())
}

fn collect_path_commitment_digests(
    path: &str,
    value: &Value,
    container_kinds: &mut BTreeMap<String, String>,
    path_digests: &mut BTreeMap<String, String>,
) -> Result<(), CanonError> {
    match value {
        Value::Object(object) => {
            container_kinds.insert(path.to_string(), "object".to_string());
            for (key, value) in object {
                collect_path_commitment_digests(
                    &format!("{path}/{}", escape_json_pointer_segment(key)),
                    value,
                    container_kinds,
                    path_digests,
                )?;
            }
        }
        Value::Array(array) => {
            container_kinds.insert(path.to_string(), "array".to_string());
            for (index, value) in array.iter().enumerate() {
                collect_path_commitment_digests(
                    &format!("{path}/{index}"),
                    value,
                    container_kinds,
                    path_digests,
                )?;
            }
        }
        _ => {
            path_digests.insert(path.to_string(), field_commitment_digest(value)?);
        }
    }
    Ok(())
}

fn escape_json_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build::{ArtefactInput, build_bundle},
        sign::decode_public_key_pem,
    };
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;

    fn sample_event() -> CaptureEvent {
        CaptureEvent {
            actor: Actor {
                issuer: "proof-layer-local".to_string(),
                app_id: "demo".to_string(),
                env: "dev".to_string(),
                signing_key_id: "kid-dev-01".to_string(),
                role: ActorRole::Provider,
                organization_id: Some("org-demo".to_string()),
            },
            subject: Subject {
                request_id: Some("req-123".to_string()),
                thread_id: Some("thr-1".to_string()),
                user_ref: Some("hmac_sha256:abc".to_string()),
                system_id: Some("system-1".to_string()),
                model_id: Some("anthropic:claude-sonnet-4-6".to_string()),
                deployment_id: Some("deploy-1".to_string()),
                version: Some("2026.03".to_string()),
            },
            compliance_profile: Some(ComplianceProfile {
                intended_use: Some("Internal reviewer assistance".to_string()),
                prohibited_practice_screening: Some("screened_not_prohibited".to_string()),
                risk_tier: Some("high_risk_candidate".to_string()),
                high_risk_domain: Some("annex_iii_employment".to_string()),
                gpai_status: Some("downstream_integrator".to_string()),
                systemic_risk: Some(false),
                fria_required: Some(false),
                deployment_context: Some("private_sector_internal".to_string()),
                metadata: json!({"owner": "compliance"}),
            }),
            context: EvidenceContext {
                provider: Some("anthropic".to_string()),
                model: Some("claude-sonnet-4-6".to_string()),
                parameters: json!({"temperature": 0.2}),
                trace_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                otel_genai_semconv_version: Some("1.0.0".to_string()),
            },
            items: vec![EvidenceItem::LlmInteraction(LlmInteractionEvidence {
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
                latency_ms: Some(1234),
                trace_commitment: Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                ),
                trace_semconv_version: Some("1.0.0".to_string()),
            })],
            policy: Policy {
                redactions: vec![],
                encryption: EncryptionPolicy { enabled: false },
                retention_class: Some("runtime_logs".to_string()),
            },
        }
    }

    #[test]
    fn v10_bundle_is_built_and_verifiable() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let bundle = build_bundle(
            sample_event(),
            &[ArtefactInput {
                name: "response.json".to_string(),
                content_type: "application/json".to_string(),
                bytes: br#"{"answer":"42"}"#.to_vec(),
            }],
            &signing_key,
            "kid-dev-01",
            "01JNFVDSM64DJN8SNMZP63YQC8",
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).unwrap(),
        )
        .expect("bundle build should succeed");

        assert_eq!(bundle.bundle_version, BUNDLE_VERSION);
        assert_eq!(bundle.items.len(), 1);
        assert!(bundle.integrity.bundle_root.starts_with("sha256:"));

        let verifying_pem = crate::sign::encode_public_key_pem(&signing_key.verifying_key());
        let verifying_key = decode_public_key_pem(&verifying_pem).unwrap();
        let mut artefacts = BTreeMap::new();
        artefacts.insert("response.json".to_string(), br#"{"answer":"42"}"#.to_vec());

        bundle
            .verify_with_artefacts(&artefacts, &verifying_key)
            .expect("bundle should verify");
    }

    #[test]
    fn duplicate_artefact_names_are_rejected() {
        let mut bundle = EvidenceBundle {
            bundle_version: BUNDLE_VERSION.to_string(),
            bundle_id: "01JNFVDSM64DJN8SNMZP63YQC8".to_string(),
            created_at: "2026-03-02T00:00:00+00:00".to_string(),
            actor: sample_event().actor,
            subject: sample_event().subject,
            compliance_profile: sample_event().compliance_profile,
            context: sample_event().context,
            items: sample_event().items,
            artefacts: vec![
                ArtefactRef {
                    name: "prompt.json".to_string(),
                    digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    size: 1,
                    content_type: "application/json".to_string(),
                },
                ArtefactRef {
                    name: "prompt.json".to_string(),
                    digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    size: 1,
                    content_type: "application/json".to_string(),
                },
            ],
            policy: sample_event().policy,
            integrity: Integrity {
                header_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                bundle_root:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                signature: SignatureInfo {
                    kid: "kid-dev-01".to_string(),
                    value: "signature".to_string(),
                    ..SignatureInfo::default()
                },
                ..Integrity::default()
            },
            timestamp: None,
            receipt: None,
        };

        let err = validate_bundle_integrity_fields(&bundle).unwrap_err();
        assert!(matches!(
            err,
            BundleValidationError::DuplicateArtefactName(_)
        ));

        bundle.artefacts.pop();
        assert!(validate_bundle_integrity_fields(&bundle).is_ok());
    }

    #[test]
    fn incident_report_invalid_digest_is_rejected() {
        let mut event = sample_event();
        event.items = vec![EvidenceItem::IncidentReport(IncidentReportEvidence {
            incident_id: "inc-001".to_string(),
            severity: "serious".to_string(),
            status: "open".to_string(),
            occurred_at: Some("2026-03-05T12:30:00Z".to_string()),
            summary: Some("model produced unsafe escalation advice".to_string()),
            report_commitment: Some("sha256:not-a-digest".to_string()),
            metadata: json!({"source": "runtime_monitor"}),
        })];

        let bundle = EvidenceBundle {
            bundle_version: BUNDLE_VERSION.to_string(),
            bundle_id: "01JNFVDSM64DJN8SNMZP63YQC8".to_string(),
            created_at: "2026-03-02T00:00:00+00:00".to_string(),
            actor: event.actor,
            subject: event.subject,
            compliance_profile: event.compliance_profile,
            context: event.context,
            items: event.items,
            artefacts: vec![ArtefactRef {
                name: "incident.json".to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size: 1,
                content_type: "application/json".to_string(),
            }],
            policy: event.policy,
            integrity: Integrity {
                header_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                bundle_root:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                signature: SignatureInfo {
                    kid: "kid-dev-01".to_string(),
                    value: "signature".to_string(),
                    ..SignatureInfo::default()
                },
                ..Integrity::default()
            },
            timestamp: None,
            receipt: None,
        };

        let err = validate_bundle_integrity_fields(&bundle).unwrap_err();
        assert!(matches!(
            err,
            BundleValidationError::InvalidDigest { field, .. }
            if field == "items[0].report_commitment"
        ));
    }

    #[test]
    fn training_provenance_invalid_digest_is_rejected() {
        let mut event = sample_event();
        event.items = vec![EvidenceItem::TrainingProvenance(
            TrainingProvenanceEvidence {
                dataset_ref: "dataset://foundation/pretrain-v3".to_string(),
                stage: "pretraining".to_string(),
                lineage_ref: Some("lineage://snapshot/2026-03-01".to_string()),
                record_commitment: Some("sha256:not-a-digest".to_string()),
                metadata: json!({"provider": "internal-data-registry"}),
            },
        )];

        let bundle = EvidenceBundle {
            bundle_version: BUNDLE_VERSION.to_string(),
            bundle_id: "01JNFVDSM64DJN8SNMZP63YQC8".to_string(),
            created_at: "2026-03-02T00:00:00+00:00".to_string(),
            actor: event.actor,
            subject: event.subject,
            compliance_profile: event.compliance_profile,
            context: event.context,
            items: event.items,
            artefacts: vec![ArtefactRef {
                name: "training_provenance.json".to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size: 1,
                content_type: "application/json".to_string(),
            }],
            policy: event.policy,
            integrity: Integrity {
                header_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                bundle_root:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                signature: SignatureInfo {
                    kid: "kid-dev-01".to_string(),
                    value: "signature".to_string(),
                    ..SignatureInfo::default()
                },
                ..Integrity::default()
            },
            timestamp: None,
            receipt: None,
        };

        let err = validate_bundle_integrity_fields(&bundle).unwrap_err();
        assert!(matches!(
            err,
            BundleValidationError::InvalidDigest { field, .. }
            if field == "items[0].record_commitment"
        ));
    }

    #[test]
    fn declaration_invalid_digest_is_rejected() {
        let mut event = sample_event();
        event.items = vec![EvidenceItem::Declaration(DeclarationEvidence {
            declaration_id: "decl-001".to_string(),
            jurisdiction: "eu".to_string(),
            status: "issued".to_string(),
            document_commitment: Some("sha256:not-a-digest".to_string()),
            metadata: json!({"annex": "v"}),
        })];

        let bundle = EvidenceBundle {
            bundle_version: BUNDLE_VERSION.to_string(),
            bundle_id: "01JNFVDSM64DJN8SNMZP63YQC8".to_string(),
            created_at: "2026-03-02T00:00:00+00:00".to_string(),
            actor: event.actor,
            subject: event.subject,
            compliance_profile: event.compliance_profile,
            context: event.context,
            items: event.items,
            artefacts: vec![ArtefactRef {
                name: "declaration.json".to_string(),
                digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                size: 1,
                content_type: "application/json".to_string(),
            }],
            policy: event.policy,
            integrity: Integrity {
                header_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
                bundle_root:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                signature: SignatureInfo {
                    kid: "kid-dev-01".to_string(),
                    value: "signature".to_string(),
                    ..SignatureInfo::default()
                },
                ..Integrity::default()
            },
            timestamp: None,
            receipt: None,
        };

        let err = validate_bundle_integrity_fields(&bundle).unwrap_err();
        assert!(matches!(
            err,
            BundleValidationError::InvalidDigest { field, .. }
            if field == "items[0].document_commitment"
        ));
    }
}
