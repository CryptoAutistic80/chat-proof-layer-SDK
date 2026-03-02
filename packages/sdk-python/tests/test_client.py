import json
import unittest

from proofsdk.client import ProofLayerClient


class TestProofLayerClient(unittest.TestCase):
    def test_create_bundle_serializes_payload(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {"bundle_id": "B1"}

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.create_bundle(
            {"capture": True},
            [{"name": "prompt.json", "content_type": "application/json", "data": "{}"}],
        )

        self.assertEqual(out["bundle_id"], "B1")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/bundles")
        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(payload["artefacts"][0]["name"], "prompt.json")
        self.assertIn("data_base64", payload["artefacts"][0])


if __name__ == "__main__":
    unittest.main()
