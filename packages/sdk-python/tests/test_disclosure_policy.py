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
            allowed_item_types=["incident_report"],
            redaction_groups=["commitments", "metadata"],
            redacted_fields_by_item_type={"incident_report": ["/summary"]},
        )

        self.assertEqual(
            policy["redacted_fields_by_item_type"],
            {
                "incident_report": ["report_commitment", "/metadata", "/summary"],
            },
        )


if __name__ == "__main__":
    unittest.main()
