from __future__ import annotations

import functools
import uuid
from typing import Any, Callable

from proofsdk.evidence import create_llm_interaction_request
from proofsdk.providers.openai_like import _submit_bundle


def prove_llm_call(proof_client, provider: str, capture_options: dict[str, Any] | None = None):
    capture_options = capture_options or {}

    def decorator(func: Callable[..., Any]):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            prompt_payload = {"args": args, "kwargs": kwargs}
            request = create_llm_interaction_request(
                key_id=capture_options.get("signing_key_id", "kid-dev-01"),
                role=capture_options.get("role", "provider"),
                issuer=capture_options.get("issuer", "proof-layer-python"),
                app_id=capture_options.get("app_id", "python-sdk"),
                env=capture_options.get("env", "dev"),
                system_id=capture_options.get("system_id"),
                provider=provider,
                model=capture_options.get("model", "decorated-call"),
                input=prompt_payload,
                output=result,
                request_id=capture_options.get("request_id", str(uuid.uuid4())),
                thread_id=capture_options.get("thread_id"),
                user_ref=capture_options.get("user_ref"),
                model_parameters=capture_options.get("model_parameters", {}),
                retrieval_commitment=capture_options.get("retrieval_commitment"),
                tool_outputs_commitment=capture_options.get("tool_outputs_commitment"),
                trace=capture_options.get(
                    "trace",
                    {"provider": provider, "decorated": True},
                ),
                otel_semconv_version=capture_options.get("otel_semconv_version"),
                redactions=capture_options.get("redactions"),
                encryption_enabled=bool(capture_options.get("encryption_enabled", False)),
                retention_class=capture_options.get("retention_class"),
                artefacts=capture_options.get("artefacts"),
            )
            proof = _submit_bundle(proof_client, request, capture_options)
            return {"result": result, "proof": proof}

        return wrapper

    return decorator
