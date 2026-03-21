import unittest

from proofsdk import (
    DISCLOSURE_POLICY_TEMPLATE_NAMES,
    DISCLOSURE_REDACTION_GROUPS,
    create_disclosure_policy,
    create_disclosure_policy_template,
)


class TestDisclosurePolicyBuilders(unittest.TestCase):
    def test_template_and_group_exports_remain_stable(self):
        self.assertEqual(
            DISCLOSURE_POLICY_TEMPLATE_NAMES,
            [
                "regulator_minimum",
                "annex_iv_redacted",
                "incident_summary",
                "runtime_minimum",
                "privacy_review",
            ],
        )
        self.assertEqual(
            DISCLOSURE_REDACTION_GROUPS,
            ["commitments", "metadata", "parameters", "operational_metrics"],
        )

    def test_runtime_minimum_template_includes_default_redaction_groups(self):
        policy = create_disclosure_policy_template("runtime_minimum")

        self.assertEqual(
            policy["allowed_item_types"],
            [
                "llm_interaction",
                "tool_call",
                "retrieval",
                "policy_decision",
                "human_oversight",
            ],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["llm_interaction"],
            [
                "input_commitment",
                "retrieval_commitment",
                "output_commitment",
                "tool_outputs_commitment",
                "trace_commitment",
                "/parameters",
                "/token_usage",
                "/latency_ms",
                "/trace_semconv_version",
            ],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["tool_call"],
            ["input_commitment", "output_commitment"],
        )

    def test_create_disclosure_policy_merges_groups_with_explicit_selectors(self):
        policy = create_disclosure_policy(
            name="custom_incident",
            allowed_item_types=["authority_submission"],
            redaction_groups=["commitments", "metadata"],
            redacted_fields_by_item_type={
                "authority_submission": ["/metadata/submission_case_id"]
            },
        )

        self.assertEqual(
            policy["redacted_fields_by_item_type"],
            {
                "authority_submission": [
                    "document_commitment",
                    "/metadata",
                    "/metadata/submission_case_id",
                ],
            },
        )

    def test_incident_summary_template_includes_authority_reporting_types(self):
        policy = create_disclosure_policy_template("incident_summary")

        self.assertEqual(
            policy["allowed_item_types"],
            [
                "incident_report",
                "authority_notification",
                "authority_submission",
                "reporting_deadline",
                "regulator_correspondence",
                "risk_assessment",
                "policy_decision",
                "human_oversight",
                "adversarial_test",
            ],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["incident_report"],
            ["/root_cause_summary"],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["adversarial_test"],
            ["/threat_model", "/affected_components"],
        )

    def test_annex_iv_template_includes_structured_governance_redactions(self):
        policy = create_disclosure_policy_template("annex_iv_redacted")

        self.assertEqual(
            policy["allowed_item_types"],
            [
                "technical_doc",
                "risk_assessment",
                "data_governance",
                "instructions_for_use",
                "human_oversight",
            ],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["data_governance"],
            ["/bias_metrics", "/personal_data_categories", "/safeguards"],
        )
        self.assertEqual(
            policy["redacted_fields_by_item_type"]["instructions_for_use"],
            ["/accuracy_metrics", "/compute_requirements", "/log_management_guidance"],
        )


if __name__ == "__main__":
    unittest.main()
