from __future__ import annotations

from typing import Any

DISCLOSURE_POLICY_TEMPLATE_NAMES = [
    "regulator_minimum",
    "annex_iv_redacted",
    "incident_summary",
    "runtime_minimum",
    "privacy_review",
]

DISCLOSURE_REDACTION_GROUPS = [
    "commitments",
    "metadata",
    "parameters",
    "operational_metrics",
]

_ALL_ITEM_TYPES = [
    "llm_interaction",
    "tool_call",
    "retrieval",
    "human_oversight",
    "policy_decision",
    "risk_assessment",
    "data_governance",
    "technical_doc",
    "instructions_for_use",
    "qms_record",
    "fundamental_rights_assessment",
    "standards_alignment",
    "post_market_monitoring",
    "corrective_action",
    "authority_notification",
    "authority_submission",
    "reporting_deadline",
    "regulator_correspondence",
    "model_evaluation",
    "adversarial_test",
    "training_provenance",
    "downstream_documentation",
    "copyright_policy",
    "training_summary",
    "conformity_assessment",
    "declaration",
    "registration",
    "literacy_attestation",
    "incident_report",
    "compute_metrics",
]

_ANNEX_IV_DEFAULT_REDACTIONS = {
    "risk_assessment": ["/metadata"],
    "data_governance": ["/metadata", "/personal_data_categories", "/safeguards"],
    "instructions_for_use": ["/metadata"],
    "qms_record": ["/metadata"],
    "standards_alignment": ["/metadata"],
    "post_market_monitoring": ["/metadata"],
}

_INCIDENT_SUMMARY_DEFAULT_REDACTIONS = {
    "incident_report": ["/root_cause_summary"],
    "adversarial_test": ["/threat_model", "/affected_components"],
}

_GROUP_SELECTORS: dict[str, dict[str, list[str]]] = {
    "commitments": {
        "llm_interaction": [
            "input_commitment",
            "retrieval_commitment",
            "output_commitment",
            "tool_outputs_commitment",
            "trace_commitment",
        ],
        "tool_call": ["input_commitment", "output_commitment"],
        "retrieval": ["result_commitment", "query_commitment"],
        "human_oversight": ["notes_commitment"],
        "policy_decision": ["rationale_commitment"],
        "technical_doc": ["commitment"],
        "instructions_for_use": ["commitment"],
        "qms_record": ["record_commitment"],
        "fundamental_rights_assessment": ["report_commitment"],
        "standards_alignment": ["mapping_commitment"],
        "post_market_monitoring": ["report_commitment"],
        "corrective_action": ["record_commitment"],
        "authority_notification": ["report_commitment"],
        "authority_submission": ["document_commitment"],
        "reporting_deadline": [],
        "regulator_correspondence": ["message_commitment"],
        "model_evaluation": ["report_commitment"],
        "adversarial_test": ["report_commitment"],
        "training_provenance": ["record_commitment"],
        "downstream_documentation": ["commitment"],
        "copyright_policy": ["commitment"],
        "training_summary": ["commitment"],
        "conformity_assessment": ["report_commitment"],
        "declaration": ["document_commitment"],
        "registration": ["receipt_commitment"],
        "literacy_attestation": ["attestation_commitment"],
        "incident_report": ["report_commitment"],
        "compute_metrics": [],
    },
    "metadata": {
        "tool_call": ["/metadata"],
        "retrieval": ["/metadata"],
        "policy_decision": ["/metadata"],
        "risk_assessment": ["/metadata"],
        "data_governance": ["/metadata"],
        "instructions_for_use": ["/metadata"],
        "qms_record": ["/metadata"],
        "fundamental_rights_assessment": ["/metadata"],
        "standards_alignment": ["/metadata"],
        "post_market_monitoring": ["/metadata"],
        "corrective_action": ["/metadata"],
        "authority_notification": ["/metadata"],
        "authority_submission": ["/metadata"],
        "reporting_deadline": ["/metadata"],
        "regulator_correspondence": ["/metadata"],
        "model_evaluation": ["/metadata"],
        "adversarial_test": ["/metadata"],
        "training_provenance": ["/metadata"],
        "downstream_documentation": ["/metadata"],
        "copyright_policy": ["/metadata"],
        "training_summary": ["/metadata"],
        "conformity_assessment": ["/metadata"],
        "declaration": ["/metadata"],
        "literacy_attestation": ["/metadata"],
        "incident_report": ["/metadata"],
        "compute_metrics": ["/metadata"],
    },
    "parameters": {
        "llm_interaction": ["/parameters"],
    },
    "operational_metrics": {
        "llm_interaction": ["/token_usage", "/latency_ms", "/trace_semconv_version"],
    },
}

_TEMPLATE_BASES: dict[str, dict[str, Any]] = {
    "regulator_minimum": {
        "policy": {
            "allowed_item_types": [],
            "excluded_item_types": [],
            "allowed_obligation_refs": [],
            "excluded_obligation_refs": [],
            "include_artefact_metadata": False,
            "include_artefact_bytes": False,
            "artefact_names": [],
        },
        "default_groups": [],
    },
    "annex_iv_redacted": {
        "policy": {
            "allowed_item_types": [
                "technical_doc",
                "risk_assessment",
                "data_governance",
                "instructions_for_use",
                "human_oversight",
                "qms_record",
                "standards_alignment",
                "post_market_monitoring",
                "corrective_action",
            ],
            "excluded_item_types": [],
            "allowed_obligation_refs": [],
            "excluded_obligation_refs": [],
            "include_artefact_metadata": True,
            "include_artefact_bytes": False,
            "artefact_names": [],
            "redacted_fields_by_item_type": _ANNEX_IV_DEFAULT_REDACTIONS,
        },
        "default_groups": [],
    },
    "incident_summary": {
        "policy": {
            "allowed_item_types": [
                "incident_report",
                "authority_notification",
                "authority_submission",
                "reporting_deadline",
                "regulator_correspondence",
                "risk_assessment",
                "policy_decision",
                "human_oversight",
                "adversarial_test",
            ],
            "excluded_item_types": ["llm_interaction", "retrieval", "tool_call"],
            "allowed_obligation_refs": [],
            "excluded_obligation_refs": [],
            "include_artefact_metadata": False,
            "include_artefact_bytes": False,
            "artefact_names": [],
            "redacted_fields_by_item_type": _INCIDENT_SUMMARY_DEFAULT_REDACTIONS,
        },
        "default_groups": [],
    },
    "runtime_minimum": {
        "policy": {
            "allowed_item_types": [
                "llm_interaction",
                "tool_call",
                "retrieval",
                "policy_decision",
                "human_oversight",
            ],
            "excluded_item_types": [],
            "allowed_obligation_refs": [],
            "excluded_obligation_refs": [],
            "include_artefact_metadata": False,
            "include_artefact_bytes": False,
            "artefact_names": [],
        },
        "default_groups": ["commitments", "parameters", "operational_metrics"],
    },
    "privacy_review": {
        "policy": {
            "allowed_item_types": [
                "llm_interaction",
                "risk_assessment",
                "incident_report",
                "policy_decision",
                "human_oversight",
            ],
            "excluded_item_types": [],
            "allowed_obligation_refs": [],
            "excluded_obligation_refs": [],
            "include_artefact_metadata": False,
            "include_artefact_bytes": False,
            "artefact_names": [],
        },
        "default_groups": ["commitments", "metadata", "parameters", "operational_metrics"],
    },
}


def _unique_strings(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        trimmed = value.strip()
        if trimmed and trimmed not in seen:
            seen.add(trimmed)
            normalized.append(trimmed)
    return normalized


def _selected_item_types(policy: dict[str, Any]) -> list[str]:
    allowed = policy.get("allowed_item_types") or []
    return list(allowed) if allowed else list(_ALL_ITEM_TYPES)


def _merge_redacted_selectors(
    base: dict[str, list[str]] | None,
    extra: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for mapping in (base or {}, extra or {}):
        for item_type, selectors in mapping.items():
            bucket = merged.setdefault(item_type, [])
            for selector in selectors:
                trimmed = selector.strip()
                if trimmed and trimmed not in bucket:
                    bucket.append(trimmed)
    return merged


def _selectors_for_groups(item_types: list[str], groups: list[str]) -> dict[str, list[str]]:
    by_item_type: dict[str, list[str]] = {}
    for item_type in item_types:
        for group in groups:
            for selector in _GROUP_SELECTORS.get(group, {}).get(item_type, []):
                bucket = by_item_type.setdefault(item_type, [])
                if selector not in bucket:
                    bucket.append(selector)
    return by_item_type


def create_disclosure_policy(
    *,
    name: str,
    allowed_item_types: list[str] | None = None,
    excluded_item_types: list[str] | None = None,
    allowed_obligation_refs: list[str] | None = None,
    excluded_obligation_refs: list[str] | None = None,
    include_artefact_metadata: bool = False,
    include_artefact_bytes: bool = False,
    artefact_names: list[str] | None = None,
    redaction_groups: list[str] | None = None,
    redacted_fields_by_item_type: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    policy = {
        "name": name,
        "allowed_item_types": _unique_strings(allowed_item_types),
        "excluded_item_types": _unique_strings(excluded_item_types),
        "allowed_obligation_refs": _unique_strings(allowed_obligation_refs),
        "excluded_obligation_refs": _unique_strings(excluded_obligation_refs),
        "include_artefact_metadata": include_artefact_metadata,
        "include_artefact_bytes": include_artefact_bytes,
        "artefact_names": _unique_strings(artefact_names),
    }
    group_selectors = _selectors_for_groups(_selected_item_types(policy), redaction_groups or [])
    policy["redacted_fields_by_item_type"] = _merge_redacted_selectors(
        group_selectors,
        redacted_fields_by_item_type,
    )
    return policy


def create_disclosure_policy_template(
    template: str,
    *,
    name: str | None = None,
    redaction_groups: list[str] | None = None,
    redacted_fields_by_item_type: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    if template not in _TEMPLATE_BASES:
        raise ValueError(f"unknown disclosure policy template {template}")
    base = _TEMPLATE_BASES[template]
    policy = base["policy"]
    return create_disclosure_policy(
        name=name or template,
        allowed_item_types=policy["allowed_item_types"],
        excluded_item_types=policy["excluded_item_types"],
        allowed_obligation_refs=policy["allowed_obligation_refs"],
        excluded_obligation_refs=policy["excluded_obligation_refs"],
        include_artefact_metadata=policy["include_artefact_metadata"],
        include_artefact_bytes=policy["include_artefact_bytes"],
        artefact_names=policy["artefact_names"],
        redaction_groups=[*base["default_groups"], *(redaction_groups or [])],
        redacted_fields_by_item_type=_merge_redacted_selectors(
            policy.get("redacted_fields_by_item_type"),
            redacted_fields_by_item_type,
        ),
    )
