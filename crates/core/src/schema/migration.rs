use super::{
    Actor, ActorRole, CaptureEvent, EvidenceBundle, EvidenceContext, EvidenceItem, Integrity,
    LlmInteractionEvidence, Subject, v01,
};

pub fn capture_input_v01_to_event(old: v01::CaptureInput) -> CaptureEvent {
    CaptureEvent {
        actor: Actor {
            issuer: old.actor.issuer,
            app_id: old.actor.app_id,
            env: old.actor.env,
            signing_key_id: old.actor.signing_key_id,
            role: ActorRole::Provider,
            organization_id: None,
        },
        subject: Subject {
            request_id: Some(old.subject.request_id),
            thread_id: old.subject.thread_id,
            user_ref: old.subject.user_ref,
            system_id: None,
            model_id: Some(format!("{}:{}", old.model.provider, old.model.model)),
            deployment_id: None,
            version: None,
        },
        context: EvidenceContext::from_v01_capture(&old.model, &old.trace),
        items: vec![EvidenceItem::LlmInteraction(LlmInteractionEvidence {
            provider: old.model.provider,
            model: old.model.model,
            parameters: old.model.parameters,
            input_commitment: old.inputs.messages_commitment,
            retrieval_commitment: old.inputs.retrieval_commitment,
            output_commitment: old.outputs.assistant_text_commitment,
            tool_outputs_commitment: old.outputs.tool_outputs_commitment,
            token_usage: None,
            latency_ms: None,
            trace_commitment: Some(old.trace.trace_commitment),
            trace_semconv_version: Some(old.trace.otel_genai_semconv_version),
        })],
        policy: old.policy,
    }
}

pub fn migrate_v01_to_v10(old: v01::ProofBundle) -> EvidenceBundle {
    let event = capture_input_v01_to_event(v01::CaptureInput {
        actor: old.actor,
        subject: old.subject,
        model: old.model,
        inputs: old.inputs,
        outputs: old.outputs,
        trace: old.trace,
        policy: old.policy.clone(),
    });

    EvidenceBundle {
        bundle_version: super::BUNDLE_VERSION.to_string(),
        bundle_id: old.bundle_id,
        created_at: old.created_at,
        actor: event.actor,
        subject: event.subject,
        context: event.context,
        items: event.items,
        artefacts: old.artefacts,
        policy: old.policy,
        integrity: Integrity::default(),
        timestamp: None,
        receipt: None,
    }
}
