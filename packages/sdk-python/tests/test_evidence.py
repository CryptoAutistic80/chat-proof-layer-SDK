import unittest

from proofsdk import (
    create_adversarial_test_request,
    create_data_governance_request,
    create_human_oversight_request,
    create_incident_report_request,
    create_literacy_attestation_request,
    create_llm_interaction_request,
    create_model_evaluation_request,
    create_policy_decision_request,
    create_retrieval_request,
    create_risk_assessment_request,
    create_technical_doc_request,
    create_training_provenance_request,
    create_tool_call_request,
)


class TestEvidenceBuilders(unittest.TestCase):
    def test_llm_interaction_request_uses_v1_shape(self):
        request = create_llm_interaction_request(
            key_id="kid-dev-01",
            role="deployer",
            system_id="system-123",
            provider="openai",
            model="gpt-4o-mini",
            input=[{"role": "user", "content": "hello"}],
            output={"role": "assistant", "content": "hi"},
            request_id="req-1",
            model_parameters={"temperature": 0.2},
            trace={"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}},
        )

        self.assertEqual(request["capture"]["actor"]["role"], "deployer")
        self.assertEqual(request["capture"]["subject"]["system_id"], "system-123")
        self.assertEqual(request["capture"]["context"]["provider"], "openai")
        self.assertEqual(request["capture"]["items"][0]["type"], "llm_interaction")
        self.assertTrue(request["capture"]["items"][0]["data"]["input_commitment"].startswith("sha256:"))
        self.assertEqual(request["artefacts"][0]["name"], "prompt.json")
        self.assertEqual(request["artefacts"][1]["name"], "response.json")

    def test_risk_assessment_request_emits_default_artefact(self):
        request = create_risk_assessment_request(
            key_id="kid-dev-01",
            system_id="system-risk-1",
            risk_id="risk-123",
            severity="high",
            status="open",
            summary="hallucination path under review",
            metadata={"owner": "risk-team"},
            record={"controls": ["approval", "monitoring"]},
            retention_class="provider_documentation_days",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "risk_assessment")
        self.assertEqual(request["capture"]["policy"]["retention_class"], "provider_documentation_days")
        self.assertEqual(request["artefacts"][0]["name"], "risk_assessment.json")

    def test_data_governance_request_emits_dataset_ref(self):
        request = create_data_governance_request(
            key_id="kid-dev-01",
            system_id="system-data-1",
            decision="approved_with_restrictions",
            dataset_ref="dataset://curated/training-v2",
            metadata={"reviewer": "privacy"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "data_governance")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["dataset_ref"],
            "dataset://curated/training-v2",
        )

    def test_technical_doc_request_hashes_inline_document(self):
        request = create_technical_doc_request(
            key_id="kid-dev-01",
            system_id="system-doc-1",
            document_ref="annex-iv/system-card",
            section="risk_controls",
            document=b"system-card-v1",
            document_name="system-card.txt",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "technical_doc")
        self.assertTrue(request["capture"]["items"][0]["data"]["commitment"].startswith("sha256:"))
        self.assertEqual(request["artefacts"][0]["name"], "system-card.txt")

    def test_tool_call_request_hashes_input_output(self):
        request = create_tool_call_request(
            key_id="kid-dev-01",
            system_id="system-tool-1",
            tool_name="search_database",
            input={"query": "hello"},
            output={"hits": 3},
            metadata={"latency_ms": 18},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "tool_call")
        self.assertTrue(request["capture"]["items"][0]["data"]["input_commitment"].startswith("sha256:"))
        self.assertTrue(request["capture"]["items"][0]["data"]["output_commitment"].startswith("sha256:"))
        self.assertEqual(request["artefacts"][1]["name"], "tool_input.json")
        self.assertEqual(request["artefacts"][2]["name"], "tool_output.json")

    def test_retrieval_request_hashes_result_query(self):
        request = create_retrieval_request(
            key_id="kid-dev-01",
            system_id="system-rag-1",
            corpus="knowledge-base",
            query="refund policy",
            result={"docs": [{"id": "doc-1"}]},
            metadata={"top_k": 3},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "retrieval")
        self.assertTrue(request["capture"]["items"][0]["data"]["result_commitment"].startswith("sha256:"))
        self.assertTrue(request["capture"]["items"][0]["data"]["query_commitment"].startswith("sha256:"))

    def test_human_oversight_request_hashes_notes(self):
        request = create_human_oversight_request(
            key_id="kid-dev-01",
            system_id="system-oversight-1",
            action="approved_after_review",
            reviewer="ops-lead",
            notes="Reviewed against internal policy",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "human_oversight")
        self.assertTrue(request["capture"]["items"][0]["data"]["notes_commitment"].startswith("sha256:"))

    def test_policy_decision_request_hashes_rationale(self):
        request = create_policy_decision_request(
            key_id="kid-dev-01",
            system_id="system-policy-1",
            policy_name="harm-filter",
            decision="blocked",
            rationale={"score": 0.98},
            metadata={"rule": "violence"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "policy_decision")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["rationale_commitment"].startswith("sha256:")
        )

    def test_literacy_attestation_request_emits_art4_evidence(self):
        request = create_literacy_attestation_request(
            key_id="kid-dev-01",
            system_id="system-literacy-1",
            attested_role="reviewer",
            status="completed",
            training_ref="course://ai-literacy/v1",
            attestation={"completion_id": "att-1"},
            metadata={"source": "lms"},
            retention_class="ai_literacy",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "literacy_attestation")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["training_ref"],
            "course://ai-literacy/v1",
        )
        self.assertTrue(
            request["capture"]["items"][0]["data"]["attestation_commitment"].startswith(
                "sha256:"
            )
        )
        self.assertEqual(request["artefacts"][0]["name"], "literacy_attestation.json")
        self.assertEqual(request["artefacts"][1]["name"], "literacy_attestation_record.json")

    def test_incident_report_request_hashes_report(self):
        request = create_incident_report_request(
            key_id="kid-dev-01",
            system_id="system-incident-1",
            incident_id="inc-1",
            severity="serious",
            status="open",
            occurred_at="2026-03-06T10:15:00Z",
            summary="unsafe escalation path",
            report="timeline and corrective actions",
            metadata={"source": "runtime-monitor"},
            retention_class="risk_mgmt",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "incident_report")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["occurred_at"],
            "2026-03-06T10:15:00Z",
        )
        self.assertTrue(
            request["capture"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "incident_report.json")
        self.assertEqual(request["artefacts"][1]["name"], "incident_report_record.txt")

    def test_model_evaluation_request_emits_gpai_evidence(self):
        request = create_model_evaluation_request(
            key_id="kid-dev-01",
            system_id="system-gpai-1",
            evaluation_id="eval-1",
            benchmark="mmlu-pro",
            status="completed",
            summary="baseline complete",
            report={"score": "0.84"},
            metadata={"suite": "foundation-evals"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "model_evaluation")
        self.assertEqual(request["capture"]["items"][0]["data"]["benchmark"], "mmlu-pro")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "model_evaluation.json")
        self.assertEqual(request["artefacts"][1]["name"], "model_evaluation_report.json")

    def test_adversarial_test_request_emits_systemic_risk_evidence(self):
        request = create_adversarial_test_request(
            key_id="kid-dev-01",
            system_id="system-gpai-2",
            test_id="adv-1",
            focus="prompt-injection",
            status="open",
            finding_severity="high",
            report="exploit transcript",
            metadata={"suite": "red-team"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "adversarial_test")
        self.assertEqual(request["capture"]["items"][0]["data"]["focus"], "prompt-injection")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "adversarial_test.json")
        self.assertEqual(request["artefacts"][1]["name"], "adversarial_test_report.txt")

    def test_training_provenance_request_emits_provenance_evidence(self):
        request = create_training_provenance_request(
            key_id="kid-dev-01",
            system_id="system-gpai-3",
            dataset_ref="dataset://foundation/pretrain-v3",
            stage="pretraining",
            lineage_ref="lineage://snapshot/2026-03-01",
            record={"manifests": 12},
            metadata={"source": "registry"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "training_provenance")
        self.assertEqual(request["capture"]["items"][0]["data"]["stage"], "pretraining")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["record_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "training_provenance.json")
        self.assertEqual(request["artefacts"][1]["name"], "training_provenance_record.json")


if __name__ == "__main__":
    unittest.main()
