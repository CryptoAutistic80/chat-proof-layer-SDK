from __future__ import annotations

import warnings

__all__ = [
    "LocalChatProofSession",
    "ProofLayer",
    "proved_completion",
    "proved_message",
    "verify_local_chat_bundle",
    "with_anthropic_proof_layer",
    "with_proof_layer",
]

_CHAT_EXPORTS = {
    "LocalChatProofSession": ("proofsdk.chat_proof", "LocalChatProofSession"),
    "verify_local_chat_bundle": ("proofsdk.chat_proof", "verify_local_chat_bundle"),
    "ProofLayer": ("proofsdk.proof_layer", "ProofLayer"),
    "with_proof_layer": ("proofsdk.providers.openai", "with_proof_layer"),
    "with_anthropic_proof_layer": ("proofsdk.providers.anthropic", "with_proof_layer"),
    "proved_completion": ("proofsdk.providers.openai_like", "proved_completion"),
    "proved_message": ("proofsdk.providers.anthropic_like", "proved_message"),
}

_DEPRECATED_DEFAULT_EXPORTS = {
    "ProofLayerClient": ("proofsdk.client", "ProofLayerClient"),
    "LocalProofLayerClient": ("proofsdk.local_client", "LocalProofLayerClient"),
    "build_bundle": ("proofsdk.native", "build_bundle"),
    "canonicalize_json": ("proofsdk.native", "canonicalize_json"),
    "compute_merkle_root": ("proofsdk.native", "compute_merkle_root"),
    "evaluate_completeness": ("proofsdk.native", "evaluate_completeness"),
    "hash_sha256": ("proofsdk.native", "hash_sha256"),
    "redact_bundle": ("proofsdk.native", "redact_bundle"),
    "sign_bundle_root": ("proofsdk.native", "sign_bundle_root"),
    "verify_bundle": ("proofsdk.native", "verify_bundle"),
    "verify_redacted_bundle": ("proofsdk.native", "verify_redacted_bundle"),
    "verify_bundle_root": ("proofsdk.native", "verify_bundle_root"),
    "select_pack_readiness": ("proofsdk.pack_readiness", "select_pack_readiness"),
    "create_disclosure_policy": ("proofsdk.disclosure_policy", "create_disclosure_policy"),
    "create_disclosure_policy_template": ("proofsdk.disclosure_policy", "create_disclosure_policy_template"),
    "DISCLOSURE_POLICY_TEMPLATE_NAMES": ("proofsdk.disclosure_policy", "DISCLOSURE_POLICY_TEMPLATE_NAMES"),
    "DISCLOSURE_REDACTION_GROUPS": ("proofsdk.disclosure_policy", "DISCLOSURE_REDACTION_GROUPS"),
    "prove_llm_call": ("proofsdk.decorators", "prove_llm_call"),
}

for _name in (
    "create_adversarial_test_request",
    "create_authority_notification_request",
    "create_authority_submission_request",
    "create_compute_metrics_request",
    "create_conformity_assessment_request",
    "create_copyright_policy_request",
    "create_corrective_action_request",
    "create_data_governance_request",
    "create_declaration_request",
    "create_downstream_documentation_request",
    "create_fundamental_rights_assessment_request",
    "create_human_oversight_request",
    "create_incident_report_request",
    "create_instructions_for_use_request",
    "create_literacy_attestation_request",
    "create_llm_interaction_request",
    "create_model_evaluation_request",
    "create_policy_decision_request",
    "create_post_market_monitoring_request",
    "create_qms_record_request",
    "create_registration_request",
    "create_regulator_correspondence_request",
    "create_reporting_deadline_request",
    "create_retrieval_request",
    "create_risk_assessment_request",
    "create_standards_alignment_request",
    "create_technical_doc_request",
    "create_tool_call_request",
    "create_training_provenance_request",
    "create_training_summary_request",
):
    _DEPRECATED_DEFAULT_EXPORTS[_name] = ("proofsdk.evidence", _name)


def __getattr__(name: str):
    if name in _CHAT_EXPORTS:
        module_name, attr_name = _CHAT_EXPORTS[name]
        module = __import__(module_name, fromlist=[attr_name])
        value = getattr(module, attr_name)
        globals()[name] = value
        return value

    if name in _DEPRECATED_DEFAULT_EXPORTS:
        module_name, attr_name = _DEPRECATED_DEFAULT_EXPORTS[name]
        warnings.warn(
            f"proofsdk.{name} is deprecated on the default import path. "
            "Import advanced helpers from proofsdk.advanced instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        module = __import__(module_name, fromlist=[attr_name])
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    raise AttributeError(name)
