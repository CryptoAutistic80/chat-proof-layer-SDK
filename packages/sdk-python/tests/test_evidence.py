import json
import unittest

from proofsdk import (
    create_adversarial_test_request,
    create_authority_submission_request,
    create_conformity_assessment_request,
    create_compute_metrics_request,
    create_instructions_for_use_request,
    create_data_governance_request,
    create_declaration_request,
    create_human_oversight_request,
    create_incident_report_request,
    create_literacy_attestation_request,
    create_llm_interaction_request,
    create_model_evaluation_request,
    create_policy_decision_request,
    create_registration_request,
    create_retrieval_request,
    create_risk_assessment_request,
    create_technical_doc_request,
    create_training_provenance_request,
    create_tool_call_request,
)


class TestEvidenceBuilders(unittest.TestCase):
    def decode_json_artefact(self, artefact):
        return json.loads(bytes(artefact["data"]).decode("utf-8"))

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
            execution_start="2026-03-10T09:00:00Z",
            execution_end="2026-03-10T09:00:01Z",
        )

        self.assertEqual(request["capture"]["actor"]["role"], "deployer")
        self.assertEqual(request["capture"]["subject"]["system_id"], "system-123")
        self.assertEqual(request["capture"]["context"]["provider"], "openai")
        self.assertEqual(request["capture"]["items"][0]["type"], "llm_interaction")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["execution_start"],
            "2026-03-10T09:00:00Z",
        )
        self.assertEqual(
            request["capture"]["items"][0]["data"]["execution_end"],
            "2026-03-10T09:00:01Z",
        )
        self.assertTrue(request["capture"]["items"][0]["data"]["input_commitment"].startswith("sha256:"))
        self.assertEqual(request["artefacts"][0]["name"], "prompt.json")
        self.assertEqual(request["artefacts"][1]["name"], "response.json")

    def test_instructions_for_use_request_emits_governance_evidence(self):
        request = create_instructions_for_use_request(
            key_id="kid-dev-01",
            system_id="system-governance-1",
            document_ref="docs://ifu/v1",
            version_tag="1.0.0",
            section="limitations",
            document=b"read this first",
            compliance_profile={
                "intended_use": "Customer support triage",
                "risk_tier": "high_risk",
            },
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "instructions_for_use")
        self.assertEqual(
            request["capture"]["compliance_profile"]["intended_use"],
            "Customer support triage",
        )
        self.assertTrue(request["capture"]["items"][0]["data"]["commitment"].startswith("sha256:"))
        self.assertEqual(request["artefacts"][0]["name"], "instructions_for_use.bin")

    def test_instructions_for_use_request_emits_full_default_governance_artefact(self):
        request = create_instructions_for_use_request(
            key_id="kid-dev-01",
            system_id="system-governance-2",
            document_ref="docs://ifu/hiring-assistant",
            version_tag="2026.03",
            provider_identity="Proof Layer Hiring Systems Ltd.",
            intended_purpose="Recruiter support for first-pass candidate review",
            system_capabilities=["candidate_summary", "borderline_case_flagging"],
            accuracy_metrics=[{"name": "review_precision", "value": "0.91", "unit": "ratio"}],
            foreseeable_risks=["automation bias"],
            human_oversight_guidance=["Review all adverse outputs before decisions."],
            log_management_guidance=["Retain logs for post-market monitoring."],
            metadata={"owner": "product-compliance"},
        )

        self.assertEqual(request["artefacts"][0]["name"], "instructions_for_use.json")
        self.assertEqual(
            self.decode_json_artefact(request["artefacts"][0]),
            {
                "document_ref": "docs://ifu/hiring-assistant",
                "version": "2026.03",
                "section": None,
                "provider_identity": "Proof Layer Hiring Systems Ltd.",
                "intended_purpose": "Recruiter support for first-pass candidate review",
                "system_capabilities": ["candidate_summary", "borderline_case_flagging"],
                "accuracy_metrics": [
                    {"name": "review_precision", "value": "0.91", "unit": "ratio"}
                ],
                "foreseeable_risks": ["automation bias"],
                "explainability_capabilities": [],
                "human_oversight_guidance": ["Review all adverse outputs before decisions."],
                "compute_requirements": [],
                "service_lifetime": None,
                "log_management_guidance": ["Retain logs for post-market monitoring."],
                "metadata": {"owner": "product-compliance"},
            },
        )

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
            likelihood="medium",
            residual_risk_level="low",
            vulnerable_groups_considered=True,
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "risk_assessment")
        self.assertEqual(request["capture"]["items"][0]["data"]["likelihood"], "medium")
        self.assertEqual(request["capture"]["items"][0]["data"]["residual_risk_level"], "low")
        self.assertTrue(request["capture"]["items"][0]["data"]["vulnerable_groups_considered"])
        self.assertEqual(request["capture"]["policy"]["retention_class"], "provider_documentation_days")
        self.assertEqual(request["artefacts"][0]["name"], "risk_assessment.json")
        self.assertEqual(
            self.decode_json_artefact(request["artefacts"][0]),
            {
                "risk_id": "risk-123",
                "severity": "high",
                "status": "open",
                "summary": "hallucination path under review",
                "risk_description": None,
                "likelihood": "medium",
                "affected_groups": [],
                "mitigation_measures": [],
                "residual_risk_level": "low",
                "risk_owner": None,
                "vulnerable_groups_considered": True,
                "test_results_summary": None,
                "metadata": {"owner": "risk-team"},
                "record": {"controls": ["approval", "monitoring"]},
            },
        )

    def test_data_governance_request_emits_dataset_ref(self):
        request = create_data_governance_request(
            key_id="kid-dev-01",
            system_id="system-data-1",
            decision="approved_with_restrictions",
            dataset_ref="dataset://curated/training-v2",
            metadata={"reviewer": "privacy"},
            dataset_name="curated-training",
            personal_data_categories=["support_tickets"],
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "data_governance")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["dataset_ref"],
            "dataset://curated/training-v2",
        )
        self.assertEqual(request["capture"]["items"][0]["data"]["dataset_name"], "curated-training")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["personal_data_categories"],
            ["support_tickets"],
        )
        self.assertEqual(
            self.decode_json_artefact(request["artefacts"][0]),
            {
                "decision": "approved_with_restrictions",
                "dataset_ref": "dataset://curated/training-v2",
                "dataset_name": "curated-training",
                "dataset_version": None,
                "source_description": None,
                "collection_period": None,
                "geographical_scope": [],
                "preprocessing_operations": [],
                "bias_detection_methodology": None,
                "bias_metrics": [],
                "mitigation_actions": [],
                "data_gaps": [],
                "personal_data_categories": ["support_tickets"],
                "safeguards": [],
                "metadata": {"reviewer": "privacy"},
                "record": None,
            },
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

    def test_technical_doc_request_emits_descriptive_default_governance_artefact(self):
        request = create_technical_doc_request(
            key_id="kid-dev-01",
            system_id="system-doc-2",
            document_ref="annex-iv/system-card",
            annex_iv_sections=["section_2", "section_3"],
            system_description_summary="Ranks candidates for recruiter review.",
            model_description_summary="Fine-tuned ranking model.",
            capabilities_and_limitations="Advisory only for first-pass screening.",
            design_choices_summary="Human review is required before employment decisions.",
            evaluation_metrics_summary="Precision and subgroup parity are reviewed monthly.",
            human_oversight_design_summary="Recruiters must review every adverse or borderline case.",
            post_market_monitoring_plan_ref="pmm://hiring-assistant/2026.03",
        )

        self.assertEqual(request["artefacts"][0]["name"], "technical_doc.json")
        self.assertEqual(
            self.decode_json_artefact(request["artefacts"][0]),
            {
                "document_ref": "annex-iv/system-card",
                "section": None,
                "descriptor": None,
                "annex_iv_sections": ["section_2", "section_3"],
                "system_description_summary": "Ranks candidates for recruiter review.",
                "model_description_summary": "Fine-tuned ranking model.",
                "capabilities_and_limitations": "Advisory only for first-pass screening.",
                "design_choices_summary": "Human review is required before employment decisions.",
                "evaluation_metrics_summary": "Precision and subgroup parity are reviewed monthly.",
                "human_oversight_design_summary": (
                    "Recruiters must review every adverse or borderline case."
                ),
                "post_market_monitoring_plan_ref": "pmm://hiring-assistant/2026.03",
                "simplified_tech_doc": None,
            },
        )

    def test_tool_call_request_hashes_input_output(self):
        request = create_tool_call_request(
            key_id="kid-dev-01",
            system_id="system-tool-1",
            tool_name="search_database",
            input={"query": "hello"},
            output={"hits": 3},
            metadata={"latency_ms": 18},
            execution_start="2026-03-10T10:00:00Z",
            execution_end="2026-03-10T10:00:02Z",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "tool_call")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["execution_start"],
            "2026-03-10T10:00:00Z",
        )
        self.assertEqual(
            request["capture"]["items"][0]["data"]["execution_end"],
            "2026-03-10T10:00:02Z",
        )
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
            database_reference="pg://rag/chunk_store",
            execution_start="2026-03-10T11:00:00Z",
            execution_end="2026-03-10T11:00:01Z",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "retrieval")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["database_reference"],
            "pg://rag/chunk_store",
        )
        self.assertTrue(request["capture"]["items"][0]["data"]["result_commitment"].startswith("sha256:"))
        self.assertTrue(request["capture"]["items"][0]["data"]["query_commitment"].startswith("sha256:"))

    def test_human_oversight_request_hashes_notes(self):
        request = create_human_oversight_request(
            key_id="kid-dev-01",
            system_id="system-oversight-1",
            action="approved_after_review",
            reviewer="ops-lead",
            notes="Reviewed against internal policy",
            actor_role="human_reviewer",
            stop_triggered=True,
            stop_reason="manual kill switch",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "human_oversight")
        self.assertEqual(request["capture"]["items"][0]["data"]["actor_role"], "human_reviewer")
        self.assertTrue(request["capture"]["items"][0]["data"]["stop_triggered"])
        self.assertTrue(request["capture"]["items"][0]["data"]["notes_commitment"].startswith("sha256:"))
        self.assertEqual(
            self.decode_json_artefact(request["artefacts"][0]),
            {
                "action": "approved_after_review",
                "reviewer": "ops-lead",
                "actor_role": "human_reviewer",
                "anomaly_detected": None,
                "override_action": None,
                "interpretation_guidance_followed": None,
                "automation_bias_detected": None,
                "two_person_verification": None,
                "stop_triggered": True,
                "stop_reason": "manual kill switch",
            },
        )
        self.assertEqual(request["artefacts"][1]["name"], "oversight_notes.txt")

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
            detection_method="post_market_monitoring",
            root_cause_summary="policy threshold misconfiguration",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "incident_report")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["occurred_at"],
            "2026-03-06T10:15:00Z",
        )
        self.assertEqual(
            request["capture"]["items"][0]["data"]["detection_method"],
            "post_market_monitoring",
        )
        self.assertTrue(
            request["capture"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "incident_report.json")
        self.assertEqual(request["artefacts"][1]["name"], "incident_report_record.txt")

    def test_authority_submission_request_emits_reporting_evidence(self):
        request = create_authority_submission_request(
            key_id="kid-dev-01",
            system_id="system-incident-2",
            submission_id="sub-1",
            authority="eu_ai_office",
            status="submitted",
            channel="portal",
            submitted_at="2026-03-07T09:30:00Z",
            document={"case_id": "inc-1", "article": "73"},
            metadata={"owner": "legal-ops"},
            retention_class="risk_mgmt",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "authority_submission")
        self.assertEqual(request["capture"]["items"][0]["data"]["authority"], "eu_ai_office")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["document_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "authority_submission.json")
        self.assertEqual(request["artefacts"][1]["name"], "authority_submission_document.json")

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
            evaluation_methodology="held-out benchmark suite",
            metrics_summary=[{"name": "accuracy", "value": "0.84", "unit": "ratio"}],
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "model_evaluation")
        self.assertEqual(request["capture"]["items"][0]["data"]["benchmark"], "mmlu-pro")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["evaluation_methodology"],
            "held-out benchmark suite",
        )
        self.assertEqual(request["capture"]["policy"]["retention_class"], "gpai_documentation")
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
            threat_model="external red-team operator",
            affected_components=["prompt-router"],
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "adversarial_test")
        self.assertEqual(request["capture"]["items"][0]["data"]["focus"], "prompt-injection")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["threat_model"],
            "external red-team operator",
        )
        self.assertEqual(request["capture"]["policy"]["retention_class"], "gpai_documentation")
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
            compute_metrics_ref="compute-2026-q1",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "training_provenance")
        self.assertEqual(request["capture"]["items"][0]["data"]["stage"], "pretraining")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["compute_metrics_ref"],
            "compute-2026-q1",
        )
        self.assertEqual(request["capture"]["policy"]["retention_class"], "gpai_documentation")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["record_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "training_provenance.json")
        self.assertEqual(request["artefacts"][1]["name"], "training_provenance_record.json")

    def test_conformity_assessment_request_emits_conformity_evidence(self):
        request = create_conformity_assessment_request(
            key_id="kid-dev-01",
            system_id="system-conf-1",
            assessment_id="ca-1",
            procedure="annex_vii",
            status="completed",
            report={"outcome": "pass"},
            metadata={"notified_body": "nb-1234"},
            assessment_body="NB-1234",
            retention_class="technical_doc",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "conformity_assessment")
        self.assertEqual(request["capture"]["items"][0]["data"]["procedure"], "annex_vii")
        self.assertEqual(request["capture"]["items"][0]["data"]["assessment_body"], "NB-1234")
        self.assertTrue(
            request["capture"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "conformity_assessment.json")
        self.assertEqual(request["artefacts"][1]["name"], "conformity_assessment_report.json")

    def test_declaration_request_emits_declaration_evidence(self):
        request = create_declaration_request(
            key_id="kid-dev-01",
            system_id="system-conf-2",
            declaration_id="decl-1",
            jurisdiction="eu",
            status="issued",
            document="eu declaration body",
            metadata={"annex": "v"},
            signatory="Chief Compliance Officer",
            retention_class="technical_doc",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "declaration")
        self.assertEqual(request["capture"]["items"][0]["data"]["jurisdiction"], "eu")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["signatory"],
            "Chief Compliance Officer",
        )
        self.assertTrue(
            request["capture"]["items"][0]["data"]["document_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "declaration.json")
        self.assertEqual(request["artefacts"][1]["name"], "declaration_document.txt")

    def test_registration_request_emits_registration_evidence(self):
        request = create_registration_request(
            key_id="kid-dev-01",
            system_id="system-conf-3",
            registration_id="reg-1",
            authority="eu_database",
            status="accepted",
            receipt={"receipt_id": "rcpt-1"},
            metadata={"article": "49"},
            registration_number="EU-REG-49-1",
            retention_class="technical_doc",
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "registration")
        self.assertEqual(request["capture"]["items"][0]["data"]["authority"], "eu_database")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["registration_number"],
            "EU-REG-49-1",
        )
        self.assertTrue(
            request["capture"]["items"][0]["data"]["receipt_commitment"].startswith("sha256:")
        )
        self.assertEqual(request["artefacts"][0]["name"], "registration.json")
        self.assertEqual(request["artefacts"][1]["name"], "registration_receipt.json")

    def test_compute_metrics_request_emits_gpai_threshold_evidence(self):
        request = create_compute_metrics_request(
            key_id="kid-dev-01",
            system_id="system-gpai-4",
            compute_id="compute-2026-q1",
            training_flops_estimate="1.2e25",
            threshold_basis_ref="art51",
            threshold_value="1e25",
            threshold_status="above_threshold",
            measured_at="2026-03-10T12:00:00Z",
            compute_resources_summary=[{"name": "gpu_hours", "value": "42000", "unit": "hours"}],
            metadata={"owner": "foundation-team"},
        )

        self.assertEqual(request["capture"]["items"][0]["type"], "compute_metrics")
        self.assertEqual(
            request["capture"]["items"][0]["data"]["training_flops_estimate"],
            "1.2e25",
        )
        self.assertEqual(
            request["capture"]["items"][0]["data"]["threshold_status"],
            "above_threshold",
        )
        self.assertEqual(request["capture"]["policy"]["retention_class"], "gpai_documentation")
        self.assertEqual(request["artefacts"][0]["name"], "compute_metrics.json")


if __name__ == "__main__":
    unittest.main()
