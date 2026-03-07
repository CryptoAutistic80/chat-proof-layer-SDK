from __future__ import annotations
import uuid
from typing import Any, Callable

from proofsdk.evidence import create_llm_interaction_request


def _submit_bundle(proof_client, request: dict[str, Any], capture_options: dict[str, Any]) -> dict[str, Any]:
    bundle_id = capture_options.get("bundle_id")
    created_at = capture_options.get("created_at")
    if bundle_id is not None or created_at is not None:
        try:
            return proof_client.create_bundle(
                request["capture"],
                request["artefacts"],
                bundle_id=bundle_id,
                created_at=created_at,
            )
        except TypeError:
            pass
    return proof_client.create_bundle(request["capture"], request["artefacts"])


def proved_completion(
    call: Callable[[dict[str, Any]], dict[str, Any]],
    params: dict[str, Any],
    proof_client,
    capture_options: dict[str, Any] | None = None,
):
    capture_options = capture_options or {}
    completion = call(params)
    request = create_llm_interaction_request(
        key_id=capture_options.get("signing_key_id", "kid-dev-01"),
        role=capture_options.get("role", "provider"),
        issuer=capture_options.get("issuer", "proof-layer-python"),
        app_id=capture_options.get("app_id", "python-sdk"),
        env=capture_options.get("env", "dev"),
        system_id=capture_options.get("system_id"),
        provider="openai",
        model=completion.get("model") or params.get("model") or "unknown",
        input=params,
        output=completion,
        request_id=capture_options.get("request_id", str(uuid.uuid4())),
        thread_id=capture_options.get("thread_id"),
        user_ref=capture_options.get("user_ref"),
        model_parameters=capture_options.get(
            "model_parameters",
            {"temperature": params.get("temperature"), "max_tokens": params.get("max_tokens")},
        ),
        retrieval_commitment=capture_options.get("retrieval_commitment"),
        tool_outputs_commitment=capture_options.get("tool_outputs_commitment"),
        trace=capture_options.get(
            "trace",
            {
                "usage": completion.get("usage"),
                "system_fingerprint": completion.get("system_fingerprint"),
                "provider": "openai",
            },
        ),
        otel_semconv_version=capture_options.get("otel_semconv_version"),
        redactions=capture_options.get("redactions"),
        encryption_enabled=bool(capture_options.get("encryption_enabled", False)),
        retention_class=capture_options.get("retention_class"),
        artefacts=capture_options.get("artefacts"),
    )
    proof = _submit_bundle(proof_client, request, capture_options)
    return completion, proof
