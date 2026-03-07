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
