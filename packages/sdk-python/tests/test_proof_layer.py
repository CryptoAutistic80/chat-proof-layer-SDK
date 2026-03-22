import json
import unittest
from pathlib import Path

from proofsdk import ProofLayer

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"
ANNEX_IV_DIR = GOLDEN_DIR / "annex_iv_governance"
GPAI_DIR = GOLDEN_DIR / "gpai_provider"
POST_MARKET_MONITORING_DIR = GOLDEN_DIR / "post_market_monitoring"


def annex_iv_bundle() -> dict[str, object]:
    return {
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


def gpai_provider_bundle() -> dict[str, object]:
    return {
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


def post_market_monitoring_bundle() -> dict[str, object]:
    return {
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


class TestProofLayer(unittest.TestCase):
    def test_capture_seals_local_llm_interaction_bundle(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-123",
            compliance_profile={
                "intended_use": "Internal reviewer assistance",
                "risk_tier": "limited_risk",
                "gpai_status": "downstream_integrator",
            },
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
        self.assertEqual(
            result["bundle"]["compliance_profile"]["intended_use"],
            "Internal reviewer assistance",
        )
        self.assertEqual(result["bundle"]["integrity"]["signature"]["kid"], "kid-dev-01")

    def test_capture_compute_metrics_seals_local_gpai_threshold_bundle(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-gpai-threshold",
        )

        result = proof_layer.capture_compute_metrics(
            compute_id="compute-2026-q1",
            training_flops_estimate="1.2e25",
            threshold_basis_ref="art51",
            threshold_value="1e25",
            threshold_status="above_threshold",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "compute_metrics")
        self.assertEqual(
            result["bundle"]["items"][0]["data"]["threshold_status"],
            "above_threshold",
        )
        self.assertEqual(result["bundle"]["policy"]["retention_class"], "gpai_documentation")

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

    def test_local_mode_can_evaluate_completeness(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        report = proof_layer.evaluate_completeness(
            bundle=annex_iv_bundle(),
            profile="annex_iv_governance_v1",
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 8)

    def test_local_mode_can_evaluate_gpai_provider_completeness(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        report = proof_layer.evaluate_completeness(
            bundle=gpai_provider_bundle(),
            profile="gpai_provider_v1",
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 6)

    def test_local_mode_can_evaluate_post_market_monitoring_completeness(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        report = proof_layer.evaluate_completeness(
            bundle=post_market_monitoring_bundle(),
            profile="post_market_monitoring_v1",
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["pass_count"], 6)

    def test_local_mode_rejects_pack_completeness_evaluation(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
        )

        with self.assertRaisesRegex(
            ValueError,
            "pack_id is not supported for local completeness evaluation",
        ):
            proof_layer.evaluate_completeness(
                pack_id="P1",
                profile="gpai_provider_v1",
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

    def test_vault_mode_can_verify_timestamp(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "valid": True,
                "message": "VALID: Timestamp trust confirmed",
                "verification": {
                    "kind": "rfc3161",
                    "provider": "test-tsa",
                    "generated_at": "2026-03-22T12:00:00Z",
                    "digest_algorithm": "sha256",
                    "message_imprint": "sha256:" + "a" * 64,
                    "policy_oid": "1.2.3.4",
                    "trusted": True,
                    "chain_verified": True,
                    "signer_count": 1,
                    "certificate_count": 2,
                },
                "assessment": {
                    "level": "trusted",
                    "headline": "Timestamp trust confirmed",
                    "summary": "The timestamp token matches this proof and chains to a trusted signer.",
                    "next_step": "Keep the trust files with the proof so another person can repeat the same check.",
                    "checks": [],
                },
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.verify_timestamp(bundle_id="B1")

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/verify/timestamp")
        self.assertEqual(
            json.loads(captured["body"].decode("utf-8")),
            {"bundle_id": "B1"},
        )
        self.assertEqual(result["assessment"]["headline"], "Timestamp trust confirmed")

    def test_vault_mode_can_verify_receipt(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "valid": True,
                "message": "VALID: Transparency proof confirmed",
                "verification": {
                    "kind": "rekor_rfc3161",
                    "provider": "rekor",
                    "log_url": "https://rekor.example.test",
                    "entry_uuid": "a" * 64,
                    "leaf_hash": "a" * 64,
                    "log_id": "log-1",
                    "log_index": 9,
                    "integrated_time": "2026-03-22T12:00:00Z",
                    "tree_size": 10,
                    "root_hash": "b" * 64,
                    "inclusion_proof_hashes": 2,
                    "inclusion_proof_verified": True,
                    "signed_entry_timestamp_present": True,
                    "signed_entry_timestamp_verified": True,
                    "log_id_verified": True,
                    "trusted": True,
                    "timestamp_generated_at": "2026-03-22T11:59:00Z",
                    "live_verification": {
                        "mode": "best_effort",
                        "state": "pass",
                        "checked_at": "2026-03-22T12:01:00Z",
                        "summary": "The live log still includes this entry.",
                    },
                },
                "assessment": {
                    "level": "trusted",
                    "headline": "Transparency proof confirmed",
                    "summary": "The receipt matches this proof and the log or service key was trusted. The log was also checked live.",
                    "next_step": "Keep the trusted log key with the proof so another person can repeat the same check.",
                    "checks": [],
                    "live_check": {
                        "mode": "best_effort",
                        "state": "pass",
                        "checked_at": "2026-03-22T12:01:00Z",
                        "summary": "The live log still includes this entry.",
                    },
                },
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.verify_receipt(
            bundle_id="B1",
            live_check_mode="best_effort",
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/verify/receipt")
        self.assertEqual(
            json.loads(captured["body"].decode("utf-8")),
            {
                "bundle_id": "B1",
                "live_check_mode": "best_effort",
            },
        )
        self.assertEqual(result["assessment"]["live_check"]["state"], "pass")

    def test_vault_mode_can_evaluate_completeness(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "profile": "gpai_provider_v1",
                "status": "warn",
                "bundle_id": "B1",
                "system_id": "foundation-model-alpha",
                "pass_count": 5,
                "warn_count": 1,
                "fail_count": 0,
                "rules": [],
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.evaluate_completeness(
            bundle_id="B1",
            profile="gpai_provider_v1",
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/completeness/evaluate")
        self.assertEqual(result["status"], "warn")

    def test_vault_mode_can_evaluate_pack_completeness(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "profile": "gpai_provider_v1",
                "status": "pass",
                "bundle_id": "P1",
                "system_id": "foundation-model-alpha",
                "pass_count": 6,
                "warn_count": 0,
                "fail_count": 0,
                "rules": [],
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.evaluate_completeness(
            pack_id="P1",
            profile="gpai_provider_v1",
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/completeness/evaluate")
        self.assertEqual(
            json.loads(captured["body"].decode("utf-8")),
            {
                "pack_id": "P1",
                "profile": "gpai_provider_v1",
            },
        )
        self.assertEqual(result["status"], "pass")

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

    def test_vault_mode_can_create_pack_with_disclosure_template(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "pack_id": "P-inline",
                "bundle_format": "disclosure",
                "disclosure_policy": "runtime_template_pack",
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.create_pack(
            pack_type="runtime_logs",
            bundle_format="disclosure",
            disclosure_template={
                "profile": "runtime_minimum",
                "name": "runtime_template_pack",
                "redaction_groups": ["metadata"],
            },
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/packs")
        self.assertEqual(result["disclosure_policy"], "runtime_template_pack")

    def test_vault_mode_can_create_pack_with_bundle_ids(self):
        captured = {}

        def request_fn(method, path, headers, body):
            captured["method"] = method
            captured["path"] = path
            captured["headers"] = headers
            captured["body"] = body
            return {
                "pack_id": "P-bundles",
                "bundle_ids": ["B1", "B2"],
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.create_pack(
            pack_type="annex_iv",
            bundle_ids=["B1", "B2"],
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/packs")
        self.assertEqual(result["pack_id"], "P-bundles")
        self.assertEqual(
            json.loads(captured["body"].decode("utf-8")),
            {
                "pack_type": "annex_iv",
                "bundle_ids": ["B1", "B2"],
            },
        )

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

    def test_vault_mode_can_preview_disclosure_from_template(self):
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
                "disclosed_item_obligation_refs": ["art12_19_26"],
                "disclosed_item_field_redactions": {"0": ["/parameters"]},
                "disclosed_artefact_indices": [],
                "disclosed_artefact_names": [],
                "disclosed_artefact_bytes_included": False,
            }

        proof_layer = ProofLayer(
            vault_url="http://127.0.0.1:8080",
            request_fn=request_fn,
        )

        result = proof_layer.preview_disclosure(
            bundle_id="B2",
            pack_type="runtime_logs",
            disclosure_template={
                "profile": "privacy_review",
                "name": "privacy_review_internal",
                "redaction_groups": ["metadata"],
            },
        )

        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["path"], "/v1/disclosure/preview")
        self.assertEqual(result["policy_name"], "privacy_review_internal")

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

    def test_capture_instructions_for_use_seals_governance_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-governance-42",
        )

        result = proof_layer.capture_instructions_for_use(
            document_ref="docs://ifu/v1",
            version_tag="1.0.0",
            section="limitations",
            document=b"read this first",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "instructions_for_use")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-governance-42")
        self.assertTrue(result["bundle"]["items"][0]["data"]["commitment"].startswith("sha256:"))

    def test_proof_layer_reuses_shared_compliance_profile_for_annex_iv_governance(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="hiring-assistant",
            role="provider",
            compliance_profile={
                "intended_use": "Recruiter support for first-pass candidate review",
                "prohibited_practice_screening": "screened_no_prohibited_use",
                "risk_tier": "high_risk",
                "high_risk_domain": "employment",
                "deployment_context": "eu_market_placement",
            },
        )

        risk = proof_layer.capture_risk_assessment(
            risk_id="risk-42",
            severity="high",
            status="mitigated",
            risk_description="Potential unfair ranking of borderline candidates.",
        )
        data_governance = proof_layer.capture_data_governance(
            decision="approved_with_restrictions",
            dataset_ref="dataset://hiring-assistant/training-v3",
            dataset_name="hiring-assistant-training",
        )

        self.assertEqual(risk["bundle"]["compliance_profile"]["high_risk_domain"], "employment")
        self.assertEqual(
            data_governance["bundle"]["compliance_profile"]["prohibited_practice_screening"],
            "screened_no_prohibited_use",
        )
        self.assertEqual(risk["bundle"]["subject"]["system_id"], "hiring-assistant")
        self.assertEqual(data_governance["bundle"]["subject"]["system_id"], "hiring-assistant")

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

    def test_capture_post_market_monitoring_seals_monitoring_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-monitoring-42",
        )

        result = proof_layer.capture_post_market_monitoring(
            plan_id="pmm-42",
            status="active",
            summary="weekly drift review with escalation thresholds",
            report={"owner": "safety-ops", "cadence": "weekly"},
            retention_class="risk_mgmt",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "post_market_monitoring")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-monitoring-42")
        self.assertTrue(
            result["bundle"]["items"][0]["data"]["report_commitment"].startswith("sha256:")
        )

    def test_capture_authority_notification_seals_reporting_evidence(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        proof_layer = ProofLayer(
            signing_key_pem=signing_key_pem,
            key_id="kid-dev-01",
            system_id="system-incident-43",
        )

        result = proof_layer.capture_authority_notification(
            notification_id="notif-42",
            authority="eu_ai_office",
            status="drafted",
            incident_id="inc-42",
            due_at="2026-03-08T12:00:00Z",
            report={"incident": "inc-42", "severity": "serious"},
            retention_class="risk_mgmt",
        )

        self.assertEqual(result["bundle"]["items"][0]["type"], "authority_notification")
        self.assertEqual(result["bundle"]["subject"]["system_id"], "system-incident-43")
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
