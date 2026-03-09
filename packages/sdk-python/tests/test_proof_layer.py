import json
import unittest
from pathlib import Path

from proofsdk import ProofLayer

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"


class TestProofLayer(unittest.TestCase):
    def test_capture_seals_local_llm_interaction_bundle(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-123",
            issuer="proof-layer-python",
            app_id="python-sdk",
            env="test",
        )

        result = proof_layer.capture(
            provider="openai",
            model="gpt-4o-mini",
            input=[{"role": "user", "content": "hello"}],
            output={"role": "assistant", "content": "hi"},
            request_id="req-proof-layer-1",
        )

        self.assertEqual(result["bundle"]["bundle_version"], "1.0")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-123")
        self.assertEqual(result["bundle"]["integrity"]["signature"]["kid"], "kid-dev-01")

    def test_disclose_returns_a_locally_verifiable_redacted_bundle(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        redacted = proof_layer.disclose(bundle=bundle, item_indices=[0])
        summary = proof_layer.verify_redacted_bundle(redacted, [], public_key_pem)

        self.assertEqual(len(redacted["disclosed_items"]), 1)
        self.assertEqual(
            summary,
            {
                "disclosed_item_count": 1,
                "disclosed_artefact_count": 0,
            },
        )

    def test_disclose_forwards_field_level_redaction_options(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        redacted = proof_layer.disclose(
            bundle=bundle,
            item_indices=[0],
            field_redactions={0: ["output_commitment"]},
        )

        self.assertIsNone(redacted["disclosed_items"][0].get("item"))
        self.assertEqual(
            redacted["disclosed_items"][0]["field_redacted_item"]["redacted_paths"],
            ["/output_commitment"],
        )

    def test_vault_mode_can_update_disclosure_config(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return json.loads(body.decode("utf-8"))

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.update_disclosure_config(
            {
                "policies": [
                    {
                        "name": "regulator_minimum",
                        "excluded_item_types": ["tool_call"],
                        "include_artefact_metadata": False,
                        "include_artefact_bytes": False,
                        "artefact_names": [],
                    }
                ]
            }
        )

        self.assertEqual(captured["method"], "PUT")
        self.assertEqual(captured["path"], "/v1/config/disclosure")
        self.assertEqual(result["policies"][0]["name"], "regulator_minimum")

    def test_vault_mode_can_list_disclosure_templates(self):
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

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.get_disclosure_templates()

        self.assertEqual(captured["method"], "GET")
        self.assertEqual(captured["path"], "/v1/disclosure/templates")
        self.assertEqual(result["templates"][0]["profile"], "runtime_minimum")

    def test_vault_mode_can_render_disclosure_template(self):
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

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.render_disclosure_template(
            profile="privacy_review",
            name="privacy_review_custom",
            redaction_groups=["metadata"],
            redacted_fields_by_item_type={"risk_assessment": ["/metadata/internal_notes"]},
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/disclosure/templates/render")
        self.assertEqual(result["policy"]["name"], "privacy_review_custom")

    def test_vault_mode_can_preview_disclosure(self):
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

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.preview_disclosure(
            bundle_id="B1",
            policy={"name": "risk_only", "allowed_obligation_refs": ["art9"]},
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/disclosure/preview")
        self.assertEqual(result["disclosed_item_types"], ["risk_assessment"])

    def test_capture_risk_assessment_seals_lifecycle_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-risk-42",
        )

        result = proof_layer.capture_risk_assessment(
            risk_id="risk-42",
            severity="medium",
            status="mitigated",
            summary="manual review added",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "risk_assessment")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-risk-42")

    def test_capture_retrieval_seals_retrieval_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-rag-42",
        )

        result = proof_layer.capture_retrieval(
            corpus="policy-kb",
            query="refund policy",
            result={"docs": [{"id": "doc-1", "score": 0.99}]},
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "retrieval")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-rag-42")
        self.assertTrue(result["bundle"]["items"][0]["data"]["result_commitment"].startswith("sha256:"))

    def test_capture_literacy_attestation_seals_literacy_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-literacy-42",
        )

        result = proof_layer.capture_literacy_attestation(
            attested_role="reviewer",
            status="completed",
            training_ref="course://ai-literacy/v1",
            attestation={"completion_id": "att-42"},
            retention_class="ai_literacy",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "literacy_attestation")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-literacy-42")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["attestation_commitment"].startswith("sha256:")
        )

    def test_capture_incident_report_seals_incident_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-incident-42",
        )

        result = proof_layer.capture_incident_report(
            incident_id="inc-42",
            severity="serious",
            status="open",
            occurred_at="2026-03-06T10:15:00Z",
            summary="unsafe medical guidance surfaced",
            report="timeline and corrective actions",
            retention_class="risk_mgmt",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "incident_report")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-incident-42")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )

    def test_capture_model_evaluation_seals_evaluation_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-gpai-42",
        )

        result = proof_layer.capture_model_evaluation(
            evaluation_id="eval-42",
            benchmark="mmlu-pro",
            status="completed",
            summary="baseline complete",
            report={"score": "0.84"},
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "model_evaluation")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-gpai-42")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )

    def test_capture_adversarial_test_seals_systemic_risk_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-gpai-43",
        )

        result = proof_layer.capture_adversarial_test(
            test_id="adv-42",
            focus="prompt-injection",
            status="open",
            finding_severity="high",
            report="exploit transcript",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "adversarial_test")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-gpai-43")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )

    def test_capture_training_provenance_seals_provenance_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-gpai-44",
        )

        result = proof_layer.capture_training_provenance(
            dataset_ref="dataset://foundation/pretrain-v3",
            stage="pretraining",
            lineage_ref="lineage://snapshot/2026-03-01",
            record={"manifests": 12},
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "training_provenance")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-gpai-44")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["record_commitment"].startswith("sha256:")
        )

    def test_capture_conformity_assessment_seals_conformity_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-conf-42",
        )

        result = proof_layer.capture_conformity_assessment(
            assessment_id="ca-42",
            procedure="annex_vii",
            status="completed",
            report={"outcome": "pass"},
            retention_class="technical_doc",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "conformity_assessment")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-conf-42")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )

    def test_capture_declaration_seals_declaration_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-conf-43",
        )

        result = proof_layer.capture_declaration(
            declaration_id="decl-42",
            jurisdiction="eu",
            status="issued",
            document="eu declaration body",
            retention_class="technical_doc",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "declaration")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-conf-43")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["document_commitment"].startswith("sha256:")
        )

    def test_capture_registration_seals_registration_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-conf-44",
        )

        result = proof_layer.capture_registration(
            registration_id="reg-42",
            authority="eu_database",
            status="accepted",
            receipt={"receipt_id": "rcpt-42"},
            retention_class="technical_doc",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "registration")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-conf-44")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["receipt_commitment"].startswith("sha256:")
        )


if __name__ == "__main__":
    unittest.main()
