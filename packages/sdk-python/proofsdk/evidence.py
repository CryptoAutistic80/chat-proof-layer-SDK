from __future__ import annotations

import json
from typing import Any

from proofsdk.native import hash_sha256


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, default=str).encode("utf-8")


def _json_artefact(name: str, value: Any) -> dict[str, Any]:
    return {
        "name": name,
        "content_type": "application/json",
        "data": json.dumps(value, default=str).encode("utf-8"),
    }


def _inline_artefact(name: str, data: Any, content_type: str | None = None) -> dict[str, Any]:
    if content_type is None:
        if isinstance(data, (bytes, bytearray, memoryview)):
            content_type = "application/octet-stream"
        elif isinstance(data, str):
            content_type = "text/plain; charset=utf-8"
        else:
            content_type = "application/json"
    return {"name": name, "content_type": content_type, "data": data}


def _named_data_artefact(base_name: str, data: Any) -> dict[str, Any]:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return _inline_artefact(f"{base_name}.bin", bytes(data), "application/octet-stream")
    if isinstance(data, str):
        return _inline_artefact(f"{base_name}.txt", data, "text/plain; charset=utf-8")
    return _inline_artefact(f"{base_name}.json", data, "application/json")


def _create_capture_request(
    *,
    key_id: str,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    model_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    context: dict[str, Any] | None = None,
    compliance_profile: dict[str, Any] | None = None,
    items: list[dict[str, Any]],
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = artefacts or [_json_artefact("evidence.json", {"items": items})]
    capture: dict[str, Any] = {
        "actor": {
            "issuer": issuer,
            "app_id": app_id,
            "env": env,
            "signing_key_id": key_id,
            "role": role,
        },
        "subject": {
            "request_id": request_id,
            "thread_id": thread_id,
            "user_ref": user_ref,
            "system_id": system_id,
            "model_id": model_id,
            "deployment_id": deployment_id,
            "version": version,
        },
        "items": items,
        "policy": {
            "redactions": redactions or [],
            "encryption": {"enabled": bool(encryption_enabled)},
            "retention_class": retention_class,
        },
    }
    if context is not None:
        capture["context"] = context
    if compliance_profile is not None:
        capture["compliance_profile"] = compliance_profile
    return {"capture": capture, "artefacts": artefacts}


def default_llm_interaction_artefacts(input: Any, output: Any) -> list[dict[str, Any]]:
    return [
        _json_artefact("prompt.json", input),
        _json_artefact("response.json", output),
    ]


def create_llm_interaction_request(
    *,
    key_id: str,
    provider: str,
    model: str,
    input: Any,
    output: Any,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    system_id: str | None = None,
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    model_parameters: Any = None,
    retrieval_commitment: str | None = None,
    tool_outputs_commitment: str | None = None,
    trace: Any = None,
    trace_commitment: str | None = None,
    otel_semconv_version: str | None = None,
    compliance_profile: dict[str, Any] | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    prompt_bytes = _to_bytes(input)
    response_bytes = _to_bytes(output)
    trace_bytes = None if trace is None else _to_bytes(trace)
    computed_trace_commitment = trace_commitment or (
        hash_sha256(trace_bytes) if trace_bytes is not None else None
    )
    trace_semconv_version = otel_semconv_version or (
        "1.0.0" if computed_trace_commitment else None
    )

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        model_id=f"{provider}:{model}",
        compliance_profile=compliance_profile,
        context={
            "provider": provider,
            "model": model,
            "parameters": model_parameters or {},
            "trace_commitment": computed_trace_commitment,
            "otel_genai_semconv_version": trace_semconv_version,
        },
        items=[
            {
                "type": "llm_interaction",
                "data": {
                    "provider": provider,
                    "model": model,
                    "parameters": model_parameters or {},
                    "input_commitment": hash_sha256(prompt_bytes),
                    "retrieval_commitment": retrieval_commitment,
                    "output_commitment": hash_sha256(response_bytes),
                    "tool_outputs_commitment": tool_outputs_commitment,
                    "trace_commitment": computed_trace_commitment,
                    "trace_semconv_version": trace_semconv_version,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts or default_llm_interaction_artefacts(input, output),
    )


def create_tool_call_request(
    *,
    key_id: str,
    tool_name: str,
    input: Any = None,
    output: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(_json_artefact("tool_call.json", {"tool_name": tool_name, "metadata": metadata}))
        if input is not None:
            artefacts.append(_named_data_artefact("tool_input", input))
        if output is not None:
            artefacts.append(_named_data_artefact("tool_output", output))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "tool_call",
                "data": {
                    "tool_name": tool_name,
                    "input_commitment": hash_sha256(input) if input is not None else None,
                    "output_commitment": hash_sha256(output) if output is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_retrieval_request(
    *,
    key_id: str,
    corpus: str,
    result: Any,
    query: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.extend(
            [
                _json_artefact("retrieval.json", {"corpus": corpus, "metadata": metadata}),
                _named_data_artefact("retrieval_result", result),
            ]
        )
        if query is not None:
            artefacts.append(_named_data_artefact("retrieval_query", query))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "retrieval",
                "data": {
                    "corpus": corpus,
                    "result_commitment": hash_sha256(result),
                    "query_commitment": hash_sha256(query) if query is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_human_oversight_request(
    *,
    key_id: str,
    action: str,
    reviewer: str | None = None,
    notes: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(_json_artefact("human_oversight.json", {"action": action, "reviewer": reviewer}))
        if notes is not None:
            artefacts.append(_named_data_artefact("oversight_notes", notes))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "human_oversight",
                "data": {
                    "action": action,
                    "reviewer": reviewer,
                    "notes_commitment": hash_sha256(notes) if notes is not None else None,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_policy_decision_request(
    *,
    key_id: str,
    policy_name: str,
    decision: str,
    rationale: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "policy_decision.json",
                {"policy_name": policy_name, "decision": decision, "metadata": metadata},
            )
        )
        if rationale is not None:
            artefacts.append(_named_data_artefact("policy_rationale", rationale))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "policy_decision",
                "data": {
                    "policy_name": policy_name,
                    "decision": decision,
                    "rationale_commitment": hash_sha256(rationale) if rationale is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_risk_assessment_request(
    *,
    key_id: str,
    risk_id: str,
    severity: str,
    status: str,
    summary: str | None = None,
    metadata: Any = None,
    record: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "risk_assessment",
                "data": {
                    "risk_id": risk_id,
                    "severity": severity,
                    "status": status,
                    "summary": summary,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts
        or [
            _json_artefact(
                "risk_assessment.json",
                {
                    "risk_id": risk_id,
                    "severity": severity,
                    "status": status,
                    "summary": summary,
                    "metadata": metadata,
                    "record": record,
                },
            )
        ],
    )


def create_data_governance_request(
    *,
    key_id: str,
    decision: str,
    dataset_ref: str | None = None,
    metadata: Any = None,
    record: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "data_governance",
                "data": {
                    "decision": decision,
                    "dataset_ref": dataset_ref,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts
        or [
            _json_artefact(
                "data_governance.json",
                {
                    "decision": decision,
                    "dataset_ref": dataset_ref,
                    "metadata": metadata,
                    "record": record,
                },
            )
        ],
    )


def create_technical_doc_request(
    *,
    key_id: str,
    document_ref: str,
    section: str | None = None,
    commitment: str | None = None,
    document: Any = None,
    document_name: str | None = None,
    document_content_type: str | None = None,
    descriptor: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        if document is not None:
            artefacts.append(
                _inline_artefact(
                    document_name or "technical_doc.bin",
                    document,
                    document_content_type,
                )
            )
        if descriptor is not None or document is None:
            artefacts.append(
                _json_artefact(
                    "technical_doc.json",
                    {
                        "document_ref": document_ref,
                        "section": section,
                        "descriptor": descriptor,
                    },
                )
            )

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "technical_doc",
                "data": {
                    "document_ref": document_ref,
                    "section": section,
                    "commitment": commitment or (hash_sha256(document) if document is not None else None),
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_literacy_attestation_request(
    *,
    key_id: str,
    attested_role: str,
    status: str,
    training_ref: str | None = None,
    attestation: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "literacy_attestation.json",
                {
                    "attested_role": attested_role,
                    "status": status,
                    "training_ref": training_ref,
                    "metadata": metadata,
                },
            )
        )
        if attestation is not None:
            artefacts.append(_named_data_artefact("literacy_attestation_record", attestation))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "literacy_attestation",
                "data": {
                    "attested_role": attested_role,
                    "status": status,
                    "training_ref": training_ref,
                    "attestation_commitment": (
                        hash_sha256(attestation) if attestation is not None else None
                    ),
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_incident_report_request(
    *,
    key_id: str,
    incident_id: str,
    severity: str,
    status: str,
    occurred_at: str | None = None,
    summary: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "incident_report.json",
                {
                    "incident_id": incident_id,
                    "severity": severity,
                    "status": status,
                    "occurred_at": occurred_at,
                    "summary": summary,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("incident_report_record", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "incident_report",
                "data": {
                    "incident_id": incident_id,
                    "severity": severity,
                    "status": status,
                    "occurred_at": occurred_at,
                    "summary": summary,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_model_evaluation_request(
    *,
    key_id: str,
    evaluation_id: str,
    benchmark: str,
    status: str,
    summary: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "model_evaluation.json",
                {
                    "evaluation_id": evaluation_id,
                    "benchmark": benchmark,
                    "status": status,
                    "summary": summary,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("model_evaluation_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "model_evaluation",
                "data": {
                    "evaluation_id": evaluation_id,
                    "benchmark": benchmark,
                    "status": status,
                    "summary": summary,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )


def create_adversarial_test_request(
    *,
    key_id: str,
    test_id: str,
    focus: str,
    status: str,
    finding_severity: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "adversarial_test.json",
                {
                    "test_id": test_id,
                    "focus": focus,
                    "status": status,
                    "finding_severity": finding_severity,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("adversarial_test_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "adversarial_test",
                "data": {
                    "test_id": test_id,
                    "focus": focus,
                    "status": status,
                    "finding_severity": finding_severity,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )


def create_training_provenance_request(
    *,
    key_id: str,
    dataset_ref: str,
    stage: str,
    lineage_ref: str | None = None,
    record: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "training_provenance.json",
                {
                    "dataset_ref": dataset_ref,
                    "stage": stage,
                    "lineage_ref": lineage_ref,
                    "metadata": metadata,
                },
            )
        )
        if record is not None:
            artefacts.append(_named_data_artefact("training_provenance_record", record))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "training_provenance",
                "data": {
                    "dataset_ref": dataset_ref,
                    "stage": stage,
                    "lineage_ref": lineage_ref,
                    "record_commitment": hash_sha256(record) if record is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )


def create_conformity_assessment_request(
    *,
    key_id: str,
    assessment_id: str,
    procedure: str,
    status: str,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "conformity_assessment.json",
                {
                    "assessment_id": assessment_id,
                    "procedure": procedure,
                    "status": status,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("conformity_assessment_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "conformity_assessment",
                "data": {
                    "assessment_id": assessment_id,
                    "procedure": procedure,
                    "status": status,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_declaration_request(
    *,
    key_id: str,
    declaration_id: str,
    jurisdiction: str,
    status: str,
    document: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "declaration.json",
                {
                    "declaration_id": declaration_id,
                    "jurisdiction": jurisdiction,
                    "status": status,
                    "metadata": metadata,
                },
            )
        )
        if document is not None:
            artefacts.append(_named_data_artefact("declaration_document", document))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "declaration",
                "data": {
                    "declaration_id": declaration_id,
                    "jurisdiction": jurisdiction,
                    "status": status,
                    "document_commitment": hash_sha256(document) if document is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_registration_request(
    *,
    key_id: str,
    registration_id: str,
    authority: str,
    status: str,
    receipt: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "registration.json",
                {
                    "registration_id": registration_id,
                    "authority": authority,
                    "status": status,
                    "metadata": metadata,
                },
            )
        )
        if receipt is not None:
            artefacts.append(_named_data_artefact("registration_receipt", receipt))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "registration",
                "data": {
                    "registration_id": registration_id,
                    "authority": authority,
                    "status": status,
                    "receipt_commitment": hash_sha256(receipt) if receipt is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_instructions_for_use_request(
    *,
    key_id: str,
    document_ref: str,
    version_tag: str | None = None,
    section: str | None = None,
    document: Any = None,
    document_name: str | None = None,
    document_content_type: str | None = None,
    commitment: str | None = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        if document is not None:
            artefacts.append(
                _inline_artefact(
                    document_name or "instructions_for_use.bin",
                    document,
                    document_content_type,
                )
            )
        artefacts.append(
            _json_artefact(
                "instructions_for_use.json",
                {
                    "document_ref": document_ref,
                    "version": version_tag,
                    "section": section,
                    "metadata": metadata,
                },
            )
        )

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "instructions_for_use",
                "data": {
                    "document_ref": document_ref,
                    "version": version_tag,
                    "section": section,
                    "commitment": commitment
                    or (hash_sha256(document) if document is not None else None),
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_qms_record_request(
    *,
    key_id: str,
    record_id: str,
    process: str,
    status: str,
    record: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "qms_record.json",
                {
                    "record_id": record_id,
                    "process": process,
                    "status": status,
                    "metadata": metadata,
                },
            )
        )
        if record is not None:
            artefacts.append(_named_data_artefact("qms_record_record", record))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "qms_record",
                "data": {
                    "record_id": record_id,
                    "process": process,
                    "status": status,
                    "record_commitment": hash_sha256(record) if record is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_fundamental_rights_assessment_request(
    *,
    key_id: str,
    assessment_id: str,
    status: str,
    scope: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "fundamental_rights_assessment.json",
                {
                    "assessment_id": assessment_id,
                    "status": status,
                    "scope": scope,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("fundamental_rights_assessment_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "fundamental_rights_assessment",
                "data": {
                    "assessment_id": assessment_id,
                    "status": status,
                    "scope": scope,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_standards_alignment_request(
    *,
    key_id: str,
    standard_ref: str,
    status: str,
    scope: str | None = None,
    mapping: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "standards_alignment.json",
                {
                    "standard_ref": standard_ref,
                    "status": status,
                    "scope": scope,
                    "metadata": metadata,
                },
            )
        )
        if mapping is not None:
            artefacts.append(_named_data_artefact("standards_alignment_mapping", mapping))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "standards_alignment",
                "data": {
                    "standard_ref": standard_ref,
                    "status": status,
                    "scope": scope,
                    "mapping_commitment": hash_sha256(mapping) if mapping is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_post_market_monitoring_request(
    *,
    key_id: str,
    plan_id: str,
    status: str,
    summary: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "post_market_monitoring.json",
                {
                    "plan_id": plan_id,
                    "status": status,
                    "summary": summary,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("post_market_monitoring_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "post_market_monitoring",
                "data": {
                    "plan_id": plan_id,
                    "status": status,
                    "summary": summary,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_corrective_action_request(
    *,
    key_id: str,
    action_id: str,
    status: str,
    summary: str | None = None,
    due_at: str | None = None,
    record: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "corrective_action.json",
                {
                    "action_id": action_id,
                    "status": status,
                    "summary": summary,
                    "due_at": due_at,
                    "metadata": metadata,
                },
            )
        )
        if record is not None:
            artefacts.append(_named_data_artefact("corrective_action_record", record))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "corrective_action",
                "data": {
                    "action_id": action_id,
                    "status": status,
                    "summary": summary,
                    "due_at": due_at,
                    "record_commitment": hash_sha256(record) if record is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_authority_notification_request(
    *,
    key_id: str,
    notification_id: str,
    authority: str,
    status: str,
    incident_id: str | None = None,
    due_at: str | None = None,
    report: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "authority_notification.json",
                {
                    "notification_id": notification_id,
                    "authority": authority,
                    "status": status,
                    "incident_id": incident_id,
                    "due_at": due_at,
                    "metadata": metadata,
                },
            )
        )
        if report is not None:
            artefacts.append(_named_data_artefact("authority_notification_report", report))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "authority_notification",
                "data": {
                    "notification_id": notification_id,
                    "authority": authority,
                    "status": status,
                    "incident_id": incident_id,
                    "due_at": due_at,
                    "report_commitment": hash_sha256(report) if report is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_authority_submission_request(
    *,
    key_id: str,
    submission_id: str,
    authority: str,
    status: str,
    channel: str | None = None,
    submitted_at: str | None = None,
    document: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "authority_submission.json",
                {
                    "submission_id": submission_id,
                    "authority": authority,
                    "status": status,
                    "channel": channel,
                    "submitted_at": submitted_at,
                    "metadata": metadata,
                },
            )
        )
        if document is not None:
            artefacts.append(_named_data_artefact("authority_submission_document", document))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "authority_submission",
                "data": {
                    "submission_id": submission_id,
                    "authority": authority,
                    "status": status,
                    "channel": channel,
                    "submitted_at": submitted_at,
                    "document_commitment": hash_sha256(document) if document is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_reporting_deadline_request(
    *,
    key_id: str,
    deadline_id: str,
    authority: str,
    obligation_ref: str,
    due_at: str,
    status: str,
    incident_id: str | None = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "reporting_deadline.json",
                {
                    "deadline_id": deadline_id,
                    "authority": authority,
                    "obligation_ref": obligation_ref,
                    "due_at": due_at,
                    "status": status,
                    "incident_id": incident_id,
                    "metadata": metadata,
                },
            )
        )

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "reporting_deadline",
                "data": {
                    "deadline_id": deadline_id,
                    "authority": authority,
                    "obligation_ref": obligation_ref,
                    "due_at": due_at,
                    "status": status,
                    "incident_id": incident_id,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_regulator_correspondence_request(
    *,
    key_id: str,
    correspondence_id: str,
    authority: str,
    direction: str,
    status: str,
    occurred_at: str | None = None,
    message: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "regulator_correspondence.json",
                {
                    "correspondence_id": correspondence_id,
                    "authority": authority,
                    "direction": direction,
                    "status": status,
                    "occurred_at": occurred_at,
                    "metadata": metadata,
                },
            )
        )
        if message is not None:
            artefacts.append(_named_data_artefact("regulator_correspondence_message", message))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "regulator_correspondence",
                "data": {
                    "correspondence_id": correspondence_id,
                    "authority": authority,
                    "direction": direction,
                    "status": status,
                    "occurred_at": occurred_at,
                    "message_commitment": hash_sha256(message) if message is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class,
        artefacts=artefacts,
    )


def create_downstream_documentation_request(
    *,
    key_id: str,
    document_ref: str,
    audience: str,
    status: str,
    document: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "downstream_documentation.json",
                {
                    "document_ref": document_ref,
                    "audience": audience,
                    "status": status,
                    "metadata": metadata,
                },
            )
        )
        if document is not None:
            artefacts.append(_named_data_artefact("downstream_documentation_document", document))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "downstream_documentation",
                "data": {
                    "document_ref": document_ref,
                    "audience": audience,
                    "status": status,
                    "commitment": hash_sha256(document) if document is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )


def create_copyright_policy_request(
    *,
    key_id: str,
    policy_ref: str,
    status: str,
    jurisdiction: str | None = None,
    document: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "copyright_policy.json",
                {
                    "policy_ref": policy_ref,
                    "status": status,
                    "jurisdiction": jurisdiction,
                    "metadata": metadata,
                },
            )
        )
        if document is not None:
            artefacts.append(_named_data_artefact("copyright_policy_document", document))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "copyright_policy",
                "data": {
                    "policy_ref": policy_ref,
                    "status": status,
                    "jurisdiction": jurisdiction,
                    "commitment": hash_sha256(document) if document is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )


def create_training_summary_request(
    *,
    key_id: str,
    summary_ref: str,
    status: str,
    audience: str | None = None,
    document: Any = None,
    metadata: Any = None,
    compliance_profile: dict[str, Any] | None = None,
    role: str = "provider",
    issuer: str = "proof-layer-python",
    app_id: str = "python-sdk",
    env: str = "dev",
    request_id: str | None = None,
    thread_id: str | None = None,
    user_ref: str | None = None,
    system_id: str | None = None,
    deployment_id: str | None = None,
    version: str | None = None,
    redactions: list[str] | None = None,
    encryption_enabled: bool = False,
    retention_class: str | None = None,
    artefacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artefacts = list(artefacts or [])
    if not artefacts:
        artefacts.append(
            _json_artefact(
                "training_summary.json",
                {
                    "summary_ref": summary_ref,
                    "status": status,
                    "audience": audience,
                    "metadata": metadata,
                },
            )
        )
        if document is not None:
            artefacts.append(_named_data_artefact("training_summary_document", document))

    return _create_capture_request(
        key_id=key_id,
        role=role,
        issuer=issuer,
        app_id=app_id,
        env=env,
        request_id=request_id,
        thread_id=thread_id,
        user_ref=user_ref,
        system_id=system_id,
        deployment_id=deployment_id,
        version=version,
        compliance_profile=compliance_profile,
        items=[
            {
                "type": "training_summary",
                "data": {
                    "summary_ref": summary_ref,
                    "status": status,
                    "audience": audience,
                    "commitment": hash_sha256(document) if document is not None else None,
                    "metadata": metadata,
                },
            }
        ],
        redactions=redactions,
        encryption_enabled=encryption_enabled,
        retention_class=retention_class or "gpai_documentation",
        artefacts=artefacts,
    )
