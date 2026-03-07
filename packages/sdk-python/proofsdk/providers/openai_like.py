from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from proofsdk.native import hash_sha256


def proved_completion(
    call: Callable[[dict[str, Any]], dict[str, Any]],
    params: dict[str, Any],
    proof_client,
    capture_options: dict[str, Any] | None = None,
):
    capture_options = capture_options or {}
    completion = call(params)

    prompt_bytes = json.dumps(params).encode("utf-8")
    response_bytes = json.dumps(completion).encode("utf-8")
    trace_bytes = json.dumps(
        {
            "usage": completion.get("usage"),
            "system_fingerprint": completion.get("system_fingerprint"),
            "provider": "openai",
        }
    ).encode("utf-8")

    capture = {
        "actor": {
            "issuer": capture_options.get("issuer", "proof-layer-python"),
            "app_id": capture_options.get("app_id", "python-demo"),
            "env": capture_options.get("env", "dev"),
            "signing_key_id": capture_options.get("signing_key_id", "kid-dev-01"),
        },
        "subject": {
            "request_id": capture_options.get("request_id", str(uuid.uuid4())),
            "thread_id": capture_options.get("thread_id"),
            "user_ref": capture_options.get("user_ref"),
        },
        "model": {
            "provider": "openai",
            "model": completion.get("model") or params.get("model") or "unknown",
            "parameters": capture_options.get(
                "model_parameters",
                {"temperature": params.get("temperature"), "max_tokens": params.get("max_tokens")},
            ),
        },
        "inputs": {
            "messages_commitment": hash_sha256(prompt_bytes),
            "retrieval_commitment": capture_options.get("retrieval_commitment"),
        },
        "outputs": {
            "assistant_text_commitment": hash_sha256(response_bytes),
            "tool_outputs_commitment": capture_options.get("tool_outputs_commitment"),
        },
        "trace": {
            "otel_genai_semconv_version": capture_options.get("otel_semconv_version", "1.0.0"),
            "trace_commitment": hash_sha256(trace_bytes),
        },
        "policy": {
            "redactions": capture_options.get("redactions", []),
            "encryption": {"enabled": bool(capture_options.get("encryption_enabled", False))},
        },
    }

    proof = proof_client.create_bundle(
        capture,
        [
            {"name": "prompt.json", "content_type": "application/json", "data": prompt_bytes},
            {"name": "response.json", "content_type": "application/json", "data": response_bytes},
        ],
    )
    return completion, proof
