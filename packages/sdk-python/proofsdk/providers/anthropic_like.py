from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Callable


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def proved_message(
    call: Callable[[dict[str, Any]], dict[str, Any]],
    params: dict[str, Any],
    proof_client,
    capture_options: dict[str, Any] | None = None,
):
    capture_options = capture_options or {}
    message = call(params)

    prompt_bytes = json.dumps(params).encode("utf-8")
    response_bytes = json.dumps(message).encode("utf-8")
    trace_bytes = json.dumps(
        {
            "usage": message.get("usage"),
            "stop_reason": message.get("stop_reason"),
            "provider": "anthropic",
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
            "provider": "anthropic",
            "model": message.get("model") or params.get("model") or "unknown",
            "parameters": capture_options.get(
                "model_parameters",
                {"temperature": params.get("temperature"), "max_tokens": params.get("max_tokens")},
            ),
        },
        "inputs": {
            "messages_commitment": _sha256_prefixed(prompt_bytes),
            "retrieval_commitment": capture_options.get("retrieval_commitment"),
        },
        "outputs": {
            "assistant_text_commitment": _sha256_prefixed(response_bytes),
            "tool_outputs_commitment": capture_options.get("tool_outputs_commitment"),
        },
        "trace": {
            "otel_genai_semconv_version": capture_options.get("otel_semconv_version", "1.0.0"),
            "trace_commitment": _sha256_prefixed(trace_bytes),
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
    return message, proof
