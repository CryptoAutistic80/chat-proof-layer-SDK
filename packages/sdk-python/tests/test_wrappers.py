import unittest

from proofsdk.decorators import prove_llm_call
from proofsdk.providers.openai_like import proved_completion


class FakeProofClient:
    def __init__(self):
        self.calls = []

    def create_bundle(self, capture, artefacts):
        self.calls.append((capture, artefacts))
        return {"bundle_id": "B-123", "bundle_root": "sha256:abc", "signature": "sig"}


class TestWrappers(unittest.TestCase):
    def test_proved_completion(self):
        proof_client = FakeProofClient()

        completion, proof = proved_completion(
            lambda params: {
                "id": "cmpl-1",
                "model": params["model"],
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
            {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            proof_client,
        )

        self.assertEqual(completion["id"], "cmpl-1")
        self.assertEqual(proof["bundle_id"], "B-123")
        self.assertEqual(len(proof_client.calls), 1)

    def test_decorator(self):
        proof_client = FakeProofClient()

        @prove_llm_call(proof_client=proof_client, provider="anthropic")
        def my_step(messages):
            return "ok"

        out = my_step([{"role": "user", "content": "hello"}])
        self.assertEqual(out["result"], "ok")
        self.assertEqual(out["proof"]["bundle_id"], "B-123")


if __name__ == "__main__":
    unittest.main()
