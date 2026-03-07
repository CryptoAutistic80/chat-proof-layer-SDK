import unittest
from pathlib import Path

from proofsdk.decorators import prove_llm_call
from proofsdk.local_client import LocalProofLayerClient
from proofsdk.proof_layer import ProofLayer
from proofsdk.providers.openai import with_proof_layer
from proofsdk.providers.openai_like import proved_completion

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"


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
        capture, _artefacts = proof_client.calls[0]
        self.assertEqual(capture["context"]["provider"], "openai")
        self.assertEqual(capture["items"][0]["type"], "llm_interaction")

    def test_decorator(self):
        proof_client = FakeProofClient()

        @prove_llm_call(proof_client=proof_client, provider="anthropic")
        def my_step(messages):
            return "ok"

        out = my_step([{"role": "user", "content": "hello"}])
        self.assertEqual(out["result"], "ok")
        self.assertEqual(out["proof"]["bundle_id"], "B-123")

    def test_proved_completion_with_local_client(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_client = LocalProofLayerClient(signing_key_pem=signing_key_pem, signing_key_id="kid-dev-01")

        completion, proof = proved_completion(
            lambda params: {
                "id": "cmpl-local-1",
                "model": params["model"],
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            },
            {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
            proof_client,
            capture_options={"request_id": "req-local-1"},
        )

        self.assertEqual(completion["id"], "cmpl-local-1")
        self.assertIn("bundle", proof)
        self.assertEqual(proof["bundle"]["bundle_version"], "1.0")
        self.assertEqual(proof["bundle"]["integrity"]["signature"]["kid"], "kid-dev-01")

    def test_with_proof_layer_attaches_proof_metadata(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(signing_key_pem=signing_key_pem, key_id="kid-dev-01")

        wrapped = with_proof_layer(
            type(
                "Client",
                (),
                {
                    "chat": type(
                        "Chat",
                        (),
                        {
                            "completions": type(
                                "Completions",
                                (),
                                {
                                    "create": staticmethod(
                                        lambda params: {
                                            "id": "cmpl-typed-1",
                                            "model": params["model"],
                                            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                                        }
                                    )
                                },
                            )()
                        },
                    )()
                },
            )(),
            proof_layer,
            {"request_id": "req-proof-layer-wrapper"},
        )

        completion = wrapped.chat.completions.create(
            {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]}
        )

        self.assertEqual(completion["id"], "cmpl-typed-1")
        self.assertEqual(completion["proof_layer"]["bundle"]["bundle_version"], "1.0")
        self.assertTrue(len(completion["proof_layer"]["signature"]) > 10)


if __name__ == "__main__":
    unittest.main()
