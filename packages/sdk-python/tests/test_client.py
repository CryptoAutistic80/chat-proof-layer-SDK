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

    def test_create_pack_serializes_bundle_format(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {"pack_id": "P1", "bundle_format": "disclosure"}

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.create_pack(
            pack_type="annex_iv",
            system_id="system-123",
            from_date="2026-03-01",
            to_date="2026-03-08",
            bundle_format="disclosure",
        )

        self.assertEqual(out["pack_id"], "P1")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/packs")
        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(
            payload,
            {
                "pack_type": "annex_iv",
                "system_id": "system-123",
                "from": "2026-03-01",
                "to": "2026-03-08",
                "bundle_format": "disclosure",
            },
        )


if __name__ == "__main__":
    unittest.main()
