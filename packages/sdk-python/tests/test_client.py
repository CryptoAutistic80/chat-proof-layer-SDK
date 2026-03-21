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
            return {
                "pack_id": "P1",
                "bundle_format": "disclosure",
                "disclosure_policy": "annex_iv_redacted",
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.create_pack(
            pack_type="annex_iv",
            system_id="system-123",
            from_date="2026-03-01",
            to_date="2026-03-08",
            bundle_format="disclosure",
            disclosure_policy="annex_iv_redacted",
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
                "disclosure_policy": "annex_iv_redacted",
            },
        )

    def test_evaluate_completeness_posts_bundle_id_or_bundle(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "profile": "gpai_provider_v1",
                "status": "pass",
                "bundle_id": "B1",
                "system_id": "foundation-model-alpha",
                "pass_count": 6,
                "warn_count": 0,
                "fail_count": 0,
                "rules": [],
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.evaluate_completeness(
            bundle_id="B1",
            profile="gpai_provider_v1",
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/completeness/evaluate")
        self.assertEqual(
            json.loads(captured["body"].decode("utf-8")),
            {
                "bundle_id": "B1",
                "profile": "gpai_provider_v1",
            },
        )
        self.assertEqual(out["status"], "pass")

    def test_create_pack_serializes_inline_disclosure_template(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "pack_id": "P2",
                "bundle_format": "disclosure",
                "disclosure_policy": "runtime_template_pack",
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.create_pack(
            pack_type="runtime_logs",
            system_id="system-456",
            bundle_format="disclosure",
            disclosure_template={
                "profile": "runtime_minimum",
                "name": "runtime_template_pack",
                "redaction_groups": ["metadata"],
            },
        )

        self.assertEqual(out["disclosure_policy"], "runtime_template_pack")
        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(
            payload,
            {
                "pack_type": "runtime_logs",
                "system_id": "system-456",
                "from": None,
                "to": None,
                "bundle_format": "disclosure",
                "disclosure_template": {
                    "profile": "runtime_minimum",
                    "name": "runtime_template_pack",
                    "redaction_groups": ["metadata"],
                },
            },
        )

    def test_get_disclosure_config_reads_nested_vault_config(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            return {
                "service": {"addr": "127.0.0.1:8080", "max_payload_bytes": 10485760},
                "signing": {"key_id": "kid-dev-01", "algorithm": "ed25519-jws"},
                "storage": {"metadata_backend": "sqlite", "blob_backend": "fs"},
                "retention": {"grace_period_days": 30, "scan_interval_hours": 24, "policies": []},
                "timestamp": {"enabled": False, "provider": "rfc3161", "url": "https://tsa.example.test"},
                "transparency": {"enabled": False, "provider": "rekor"},
                "disclosure": {
                    "policies": [
                        {
                            "name": "annex_iv_redacted",
                            "include_artefact_metadata": True,
                            "include_artefact_bytes": True,
                            "artefact_names": ["doc.json"],
                        }
                    ]
                },
                "audit": {"enabled": True},
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        disclosure = client.get_disclosure_config()

        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["path"], "/v1/config")
        self.assertEqual(disclosure["policies"][0]["name"], "annex_iv_redacted")
        self.assertTrue(disclosure["policies"][0]["include_artefact_bytes"])

    def test_get_disclosure_templates_reads_catalog(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            return {
                "templates": [
                    {
                        "profile": "runtime_minimum",
                        "description": "Runtime disclosure template",
                        "default_redaction_groups": ["commitments"],
                        "policy": {"name": "runtime_minimum"},
                    }
                ],
                "redaction_groups": [
                    {
                        "name": "commitments",
                        "description": "Hide digest fields.",
                    }
                ],
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        catalog = client.get_disclosure_templates()

        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["path"], "/v1/disclosure/templates")
        self.assertEqual(catalog["templates"][0]["profile"], "runtime_minimum")

    def test_render_disclosure_template_posts_template_options(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "profile": "privacy_review",
                "description": "Privacy review disclosure",
                "default_redaction_groups": ["metadata"],
                "policy": {
                    "name": "privacy_review_custom",
                    "redacted_fields_by_item_type": {
                        "risk_assessment": ["/metadata/internal_notes"]
                    },
                },
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        rendered = client.render_disclosure_template(
            profile="privacy_review",
            name="privacy_review_custom",
            redaction_groups=["metadata"],
            redacted_fields_by_item_type={"risk_assessment": ["/metadata/internal_notes"]},
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/disclosure/templates/render")
        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(
            payload,
            {
                "profile": "privacy_review",
                "name": "privacy_review_custom",
                "redaction_groups": ["metadata"],
                "redacted_fields_by_item_type": {
                    "risk_assessment": ["/metadata/internal_notes"]
                },
            },
        )
        self.assertEqual(rendered["policy"]["name"], "privacy_review_custom")

    def test_update_disclosure_config_uses_put(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return json.loads(body.decode("utf-8"))

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.update_disclosure_config(
            {
                "policies": [
                    {
                        "name": "incident_summary",
                        "allowed_item_types": ["incident_report"],
                        "include_artefact_metadata": True,
                        "include_artefact_bytes": False,
                        "artefact_names": ["incident.json"],
                    }
                ]
            }
        )

        self.assertEqual(captured["method"], "PUT")
        self.assertEqual(captured["path"], "/v1/config/disclosure")
        self.assertEqual(out["policies"][0]["name"], "incident_summary")
        self.assertTrue(out["policies"][0]["include_artefact_metadata"])

    def test_preview_disclosure_posts_inline_policy(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "bundle_id": "B1",
                "policy_name": "risk_only",
                "disclosed_item_indices": [1],
                "disclosed_item_types": ["risk_assessment"],
                "disclosed_item_obligation_refs": ["art9"],
                "disclosed_artefact_indices": [],
                "disclosed_artefact_names": [],
                "disclosed_artefact_bytes_included": False,
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.preview_disclosure(
            bundle_id="B1",
            pack_type="annex_iv",
            policy={
                "name": "risk_only",
                "allowed_obligation_refs": ["art9"],
                "include_artefact_metadata": False,
                "include_artefact_bytes": False,
            },
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/disclosure/preview")
        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(payload["bundle_id"], "B1")
        self.assertEqual(payload["pack_type"], "annex_iv")
        self.assertEqual(payload["policy"]["allowed_obligation_refs"], ["art9"])
        self.assertEqual(out["disclosed_item_types"], ["risk_assessment"])

    def test_preview_disclosure_posts_inline_template(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "bundle_id": "B2",
                "policy_name": "privacy_review_internal",
                "disclosed_item_indices": [0],
                "disclosed_item_types": ["llm_interaction"],
                "disclosed_item_field_redactions": {"0": ["/parameters"]},
                "disclosed_item_obligation_refs": ["art12_19_26"],
                "disclosed_artefact_indices": [],
                "disclosed_artefact_names": [],
                "disclosed_artefact_bytes_included": False,
            }

        client = ProofLayerClient(base_url="http://127.0.0.1:8080", request_fn=request_fn)
        out = client.preview_disclosure(
            bundle_id="B2",
            pack_type="runtime_logs",
            disclosure_template={
                "profile": "privacy_review",
                "name": "privacy_review_internal",
                "redaction_groups": ["metadata"],
            },
        )

        payload = json.loads(captured["body"].decode("utf-8"))
        self.assertEqual(
            payload,
            {
                "bundle_id": "B2",
                "pack_type": "runtime_logs",
                "disclosure_template": {
                    "profile": "privacy_review",
                    "name": "privacy_review_internal",
                    "redaction_groups": ["metadata"],
                },
            },
        )
        self.assertEqual(out["policy_name"], "privacy_review_internal")


if __name__ == "__main__":
    unittest.main()
