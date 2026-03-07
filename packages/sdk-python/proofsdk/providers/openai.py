from __future__ import annotations

from typing import Any

from proofsdk.providers.openai_like import proved_completion


def with_proof_layer(client, proof_layer, capture_options: dict[str, Any] | None = None):
    capture_options = capture_options or {}

    class _WrappedCompletions:
        def create(self, params: dict[str, Any]) -> dict[str, Any]:
            completion, proof = proved_completion(
                client.chat.completions.create,
                params,
                proof_layer,
                capture_options=capture_options,
            )
            return {
                **completion,
                "proof_layer": {
                    "bundle_id": proof["bundle_id"],
                    "bundle_root": proof["bundle_root"],
                    "signature": proof["signature"],
                    "created_at": proof.get("created_at"),
                    "bundle": proof.get("bundle"),
                },
            }

    class _WrappedChat:
        completions = _WrappedCompletions()

    class _WrappedClient:
        chat = _WrappedChat()

    return _WrappedClient()
