from __future__ import annotations

from typing import Any

from proofsdk.providers.anthropic_like import proved_message


def with_proof_layer(client, proof_layer, capture_options: dict[str, Any] | None = None):
    capture_options = capture_options or {}

    class _WrappedMessages:
        def create(self, params: dict[str, Any]) -> dict[str, Any]:
            message, proof = proved_message(
                client.messages.create,
                params,
                proof_layer,
                capture_options=capture_options,
            )
            return {
                **message,
                "proof_layer": {
                    "bundle_id": proof["bundle_id"],
                    "bundle_root": proof["bundle_root"],
                    "signature": proof["signature"],
                    "created_at": proof.get("created_at"),
                    "bundle": proof.get("bundle"),
                },
            }

    class _WrappedClient:
        messages = _WrappedMessages()

    return _WrappedClient()
