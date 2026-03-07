from __future__ import annotations

import functools
import json
import uuid
from typing import Any, Callable

from proofsdk.native import hash_sha256


def prove_llm_call(proof_client, provider: str, capture_options: dict[str, Any] | None = None):
    capture_options = capture_options or {}

    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            prompt_payload = {"args": args, "kwargs": kwargs}
            prompt_bytes = json.dumps(prompt_payload, default=str).encode("utf-8")
            response_bytes = json.dumps(result, default=str).encode("utf-8")

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
                    "provider": provider,
                    "model": capture_options.get("model", "decorated-call"),
                    "parameters": capture_options.get("model_parameters", {}),
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
                    "trace_commitment": hash_sha256(response_bytes),
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
            return {"result": result, "proof": proof}

        return wrapper

    return decorator
