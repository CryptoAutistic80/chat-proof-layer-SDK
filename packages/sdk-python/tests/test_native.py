import json
import unittest
from pathlib import Path

from proofsdk.native import (
    build_bundle,
    evaluate_completeness,
    hash_sha256,
    redact_bundle,
    sign_bundle_root,
    verify_bundle,
    verify_bundle_root,
    verify_redacted_bundle,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"
ANNEX_IV_DIR = GOLDEN_DIR / "annex_iv_governance"
FUNDAMENTAL_RIGHTS_DIR = GOLDEN_DIR / "fundamental_rights"
GPAI_DIR = GOLDEN_DIR / "gpai_provider"
POST_MARKET_MONITORING_DIR = GOLDEN_DIR / "post_market_monitoring"


class TestNativeBindings(unittest.TestCase):
    def test_native_sign_and_verify_round_trip(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")
        bundle_root = hash_sha256("python-native-roundtrip")
        jws = sign_bundle_root(bundle_root, signing_key_pem, "kid-dev-01")

        self.assertIsInstance(jws, str)
        self.assertTrue(verify_bundle_root(jws, bundle_root, public_key_pem))

    def test_native_verify_bundle_uses_rust_core(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")
        artefacts = [
            {
                "name": artefact["name"],
                "data": (GOLDEN_DIR / "fixed_bundle" / "artefacts" / artefact["name"]).read_bytes(),
            }
            for artefact in bundle["artefacts"]
        ]

        summary = verify_bundle(bundle=bundle, artefacts=artefacts, public_key_pem=public_key_pem)
        self.assertEqual(summary, {"artefact_count": len(artefacts)})

    def test_native_build_bundle_reproduces_the_deterministic_golden_bundle(self):
        capture = json.loads((GOLDEN_DIR / "capture.json").read_text(encoding="utf-8"))
        expected_bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        artefacts = [
            {
                "name": "prompt.json",
                "content_type": "application/json",
                "data": (GOLDEN_DIR / "prompt.json").read_bytes(),
            },
            {
                "name": "response.json",
                "content_type": "application/json",
                "data": (GOLDEN_DIR / "response.json").read_bytes(),
            },
        ]

        bundle = build_bundle(
            capture=capture,
            artefacts=artefacts,
            key_pem=signing_key_pem,
            kid="kid-dev-01",
            bundle_id=expected_bundle["bundle_id"],
            created_at=expected_bundle["created_at"],
        )

        self.assertEqual(bundle, expected_bundle)

    def test_native_redact_bundle_and_verify_redacted_bundle_round_trip(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")

        redacted = redact_bundle(bundle=bundle, item_indices=[0])
        summary = verify_redacted_bundle(bundle=redacted, artefacts=[], public_key_pem=public_key_pem)

        self.assertEqual(len(redacted["disclosed_items"]), 1)
        self.assertEqual(len(redacted["disclosed_artefacts"]), 0)
        self.assertEqual(
            summary,
            {
                "disclosed_item_count": 1,
                "disclosed_artefact_count": 0,
            },
        )

    def test_native_redact_bundle_supports_field_level_redaction(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))

        redacted = redact_bundle(
            bundle=bundle,
            item_indices=[0],
            field_redactions={0: ["output_commitment"]},
        )

        self.assertIsNone(redacted["disclosed_items"][0].get("item"))
        self.assertEqual(
            redacted["disclosed_items"][0]["field_redacted_item"]["redacted_paths"],
            ["/output_commitment"],
        )

    def test_native_evaluate_completeness_uses_rust_core(self):
        bundle = {
            "bundle_version": "1.0",
            "bundle_id": "B-annex-iv",
            "created_at": "2026-03-21T00:00:00Z",
            "actor": {
                "issuer": "proof-layer-test",
                "app_id": "python-sdk",
                "env": "test",
                "signing_key_id": "kid-dev-01",
                "role": "provider",
            },
            "subject": {"system_id": "hiring-assistant"},
            "context": {},
            "items": [
                {
                    "type": "technical_doc",
                    "data": json.loads((ANNEX_IV_DIR / "technical_doc.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "risk_assessment",
                    "data": json.loads((ANNEX_IV_DIR / "risk_assessment.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "data_governance",
                    "data": json.loads((ANNEX_IV_DIR / "data_governance.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "instructions_for_use",
                    "data": json.loads((ANNEX_IV_DIR / "instructions_for_use.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "human_oversight",
                    "data": json.loads((ANNEX_IV_DIR / "human_oversight.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "qms_record",
                    "data": json.loads((ANNEX_IV_DIR / "qms_record.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "standards_alignment",
                    "data": json.loads(
                        (ANNEX_IV_DIR / "standards_alignment.json").read_text(encoding="utf-8")
                    ),
                },
                {
                    "type": "post_market_monitoring",
                    "data": json.loads(
                        (ANNEX_IV_DIR / "post_market_monitoring.json").read_text(encoding="utf-8")
                    ),
                },
            ],
            "artefacts": [],
            "policy": {"redactions": [], "encryption": {"enabled": False}},
            "integrity": {
                "canonicalization": "RFC8785-JCS",
                "hash": "SHA-256",
                "header_digest": "sha256:" + "a" * 64,
                "bundle_root_algorithm": "pl-merkle-sha256-v4",
                "bundle_root": "sha256:" + "b" * 64,
                "signature": {
                    "format": "JWS",
                    "alg": "EdDSA",
                    "kid": "kid-dev-01",
                    "value": "sig",
                },
            },
        }

        report = evaluate_completeness(bundle=bundle, profile="annex_iv_governance_v1")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 8)

    def test_native_evaluate_completeness_supports_gpai_provider_profile(self):
        bundle = {
            "bundle_version": "1.0",
            "bundle_id": "B-gpai-provider",
            "created_at": "2026-03-21T00:00:00Z",
            "actor": {
                "issuer": "proof-layer-test",
                "app_id": "python-sdk",
                "env": "test",
                "signing_key_id": "kid-dev-01",
                "role": "provider",
            },
            "subject": {"system_id": "foundation-model-alpha"},
            "context": {},
            "items": [
                {
                    "type": "technical_doc",
                    "data": json.loads((GPAI_DIR / "technical_doc.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "model_evaluation",
                    "data": json.loads((GPAI_DIR / "model_evaluation.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "training_provenance",
                    "data": json.loads((GPAI_DIR / "training_provenance.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "compute_metrics",
                    "data": json.loads((GPAI_DIR / "compute_metrics.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "copyright_policy",
                    "data": json.loads((GPAI_DIR / "copyright_policy.json").read_text(encoding="utf-8")),
                },
                {
                    "type": "training_summary",
                    "data": json.loads((GPAI_DIR / "training_summary.json").read_text(encoding="utf-8")),
                },
            ],
            "artefacts": [],
            "policy": {"redactions": [], "encryption": {"enabled": False}},
            "integrity": {
                "canonicalization": "RFC8785-JCS",
                "hash": "SHA-256",
                "header_digest": "sha256:" + "a" * 64,
                "bundle_root_algorithm": "pl-merkle-sha256-v4",
                "bundle_root": "sha256:" + "b" * 64,
                "signature": {
                    "format": "JWS",
                    "alg": "EdDSA",
                    "kid": "kid-dev-01",
                    "value": "sig",
                },
            },
        }

        report = evaluate_completeness(bundle=bundle, profile="gpai_provider_v1")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 6)

    def test_native_evaluate_completeness_supports_fundamental_rights_profile(self):
        bundle = {
            "bundle_version": "1.0",
            "bundle_id": "B-fundamental-rights",
            "created_at": "2026-03-22T00:00:00Z",
            "actor": {
                "issuer": "proof-layer-test",
                "app_id": "python-sdk",
                "env": "test",
                "signing_key_id": "kid-dev-01",
                "role": "deployer",
            },
            "subject": {"system_id": "benefits-review"},
            "context": {},
            "items": [
                {
                    "type": "fundamental_rights_assessment",
                    "data": json.loads(
                        (FUNDAMENTAL_RIGHTS_DIR / "fundamental_rights_assessment.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "human_oversight",
                    "data": json.loads(
                        (FUNDAMENTAL_RIGHTS_DIR / "human_oversight.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
            ],
            "artefacts": [],
            "policy": {"redactions": [], "encryption": {"enabled": False}},
            "integrity": {
                "canonicalization": "RFC8785-JCS",
                "hash": "SHA-256",
                "header_digest": "sha256:" + "a" * 64,
                "bundle_root_algorithm": "pl-merkle-sha256-v4",
                "bundle_root": "sha256:" + "b" * 64,
                "signature": {
                    "format": "JWS",
                    "alg": "EdDSA",
                    "kid": "kid-dev-01",
                    "value": "sig",
                },
            },
        }

        report = evaluate_completeness(bundle=bundle, profile="fundamental_rights_v1")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 2)

    def test_native_evaluate_completeness_supports_post_market_monitoring_profile(self):
        bundle = {
            "bundle_version": "1.0",
            "bundle_id": "B-post-market-monitoring",
            "created_at": "2026-03-22T00:00:00Z",
            "actor": {
                "issuer": "proof-layer-test",
                "app_id": "python-sdk",
                "env": "test",
                "signing_key_id": "kid-dev-01",
                "role": "provider",
            },
            "subject": {"system_id": "claims-assistant"},
            "context": {},
            "items": [
                {
                    "type": "post_market_monitoring",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "post_market_monitoring.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "incident_report",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "incident_report.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "corrective_action",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "corrective_action.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "authority_notification",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "authority_notification.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "authority_submission",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "authority_submission.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
                {
                    "type": "reporting_deadline",
                    "data": json.loads(
                        (POST_MARKET_MONITORING_DIR / "reporting_deadline.json").read_text(
                            encoding="utf-8"
                        )
                    ),
                },
            ],
            "artefacts": [],
            "policy": {"redactions": [], "encryption": {"enabled": False}},
            "integrity": {
                "canonicalization": "RFC8785-JCS",
                "hash": "SHA-256",
                "header_digest": "sha256:" + "a" * 64,
                "bundle_root_algorithm": "pl-merkle-sha256-v4",
                "bundle_root": "sha256:" + "b" * 64,
                "signature": {
                    "format": "JWS",
                    "alg": "EdDSA",
                    "kid": "kid-dev-01",
                    "value": "sig",
                },
            },
        }

        report = evaluate_completeness(bundle=bundle, profile="post_market_monitoring_v1")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 6)


if __name__ == "__main__":
    unittest.main()
