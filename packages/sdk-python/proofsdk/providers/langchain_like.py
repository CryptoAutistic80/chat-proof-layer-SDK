from __future__ import annotations

from typing import Any

from proofsdk.tooling.tool_capture import capture_tool_call


class ProofLayerCallbackHandler:
    """PoC LangChain-like callback capture handler.

    This class intentionally avoids hard dependency on langchain packages.
    """

    def __init__(self, proof_client, provider: str = "langchain", capture_options: dict[str, Any] | None = None):
        self.proof_client = proof_client
        self.provider = provider
        self.capture_options = capture_options or {}
        self.events: list[dict[str, Any]] = []

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs):
        self.events.append(
            {
                "type": "llm_start",
                "serialized": serialized,
                "prompts": prompts,
                "kwargs": kwargs,
            }
        )

    def on_llm_end(self, response: dict[str, Any], **kwargs):
        self.events.append({"type": "llm_end", "response": response, "kwargs": kwargs})

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs):
        self.events.append(
            {
                "type": "tool_start",
                "serialized": serialized,
                "input": input_str,
                "kwargs": kwargs,
            }
        )

    def on_tool_end(self, output: str, **kwargs):
        self.events.append(capture_tool_call("tool", {"input": "unknown"}, {"output": output}))

    def flush_bundle(self, capture: dict[str, Any], artefacts: list[dict[str, Any]]):
        return self.proof_client.create_bundle(capture, artefacts)
