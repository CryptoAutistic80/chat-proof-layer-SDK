import unittest

from proofsdk import select_pack_readiness


class TestPackReadiness(unittest.TestCase):
    def test_select_pack_readiness_prefers_pack_scoped_fields(self):
        readiness = select_pack_readiness(
            {
                "pack_id": "P1",
                "pack_type": "annex_iv",
                "completeness_profile": "annex_iv_governance_v1",
                "completeness_status": "fail",
                "pack_completeness_profile": "annex_iv_governance_v1",
                "pack_completeness_status": "pass",
                "pack_completeness_pass_count": 5,
                "pack_completeness_warn_count": 0,
                "pack_completeness_fail_count": 0,
            }
        )

        self.assertEqual(
            readiness,
            {
                "source": "pack_scoped",
                "profile": "annex_iv_governance_v1",
                "status": "pass",
                "pass_count": 5,
                "warn_count": 0,
                "fail_count": 0,
            },
        )

    def test_select_pack_readiness_falls_back_to_legacy_fields(self):
        readiness = select_pack_readiness(
            {
                "pack_id": "P2",
                "pack_type": "runtime_logs",
                "completeness_profile": "gpai_provider_v1",
                "completeness_status": "warn",
                "completeness_pass_count": 1,
                "completeness_warn_count": 1,
                "completeness_fail_count": 0,
            }
        )

        self.assertEqual(
            readiness,
            {
                "source": "bundle_aggregate",
                "profile": "gpai_provider_v1",
                "status": "warn",
                "pass_count": 1,
                "warn_count": 1,
                "fail_count": 0,
            },
        )

    def test_select_pack_readiness_returns_none_when_unavailable(self):
        self.assertIsNone(
            select_pack_readiness(
                {
                    "pack_id": "P3",
                    "pack_type": "runtime_logs",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
