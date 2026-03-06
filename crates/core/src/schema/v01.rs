use super::{ArtefactRef, EncryptionPolicy, Integrity, Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Actor {
    pub issuer: String,
    pub app_id: String,
    pub env: String,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelInfo {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inputs {
    pub messages_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outputs {
    pub assistant_text_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_outputs_commitment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Trace {
    pub otel_genai_semconv_version: String,
    pub trace_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureInput {
    pub actor: Actor,
    pub subject: Subject,
    pub model: ModelInfo,
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub trace: Trace,
    pub policy: Policy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofBundle {
    pub bundle_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub actor: Actor,
    pub subject: Subject,
    pub model: ModelInfo,
    pub inputs: Inputs,
    pub outputs: Outputs,
    pub trace: Trace,
    pub artefacts: Vec<ArtefactRef>,
    pub policy: Policy,
    pub integrity: Integrity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
}

impl ProofBundle {
    pub fn default_policy() -> Policy {
        Policy {
            redactions: Vec::new(),
            encryption: EncryptionPolicy { enabled: false },
            retention_class: None,
        }
    }
}
