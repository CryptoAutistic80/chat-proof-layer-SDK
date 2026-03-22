import os
import sys
from pathlib import Path

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "packages", "sdk-python")
    ),
)

from proofsdk.proof_layer import ProofLayer


def main() -> None:
    vault_url = os.environ.get("PROOF_SERVICE_URL", "http://127.0.0.1:8080")
    output_dir = Path(__file__).resolve().parent / "artifacts"
    output_path = output_dir / "incident-response.pkg"

    proof_layer = ProofLayer(
        vault_url=vault_url,
        app_id="python-incident-response-example",
        env="dev",
        system_id="benefits-review",
        role="deployer",
        compliance_profile={
            "intended_use": "Public-sector benefit eligibility review",
            "risk_tier": "high_risk",
            "fria_required": True,
            "deployment_context": "public_sector",
            "metadata": {
                "owner": "incident-ops",
                "market": "eu",
            },
        },
    )

    technical_doc = proof_layer.capture_technical_doc(
        document_ref="docs://benefits-review/incident-response-context",
        section="incident_context",
        descriptor={
            "owner": "incident-ops",
            "document_class": "incident_response_context",
            "system_id": "benefits-review",
            "authority": "eu_ai_office",
        },
        system_description_summary=(
            "Public-sector benefit eligibility workflow with incident triage and regulator-facing escalation controls."
        ),
        model_description_summary=(
            "Advisory eligibility review assistant that prepares summaries for human case officers."
        ),
        capabilities_and_limitations=(
            "Flags incomplete or high-risk cases, but it does not finalize benefit determinations."
        ),
        design_choices_summary=(
            "Incident-response records capture triage, notification, corrective action, and regulator follow-up in one reviewable file."
        ),
        evaluation_metrics_summary=(
            "Appeal-rate, false-negative, and escalation-timeliness checks are reviewed after reportable incidents."
        ),
        human_oversight_design_summary=(
            "Human case officers review adverse or borderline recommendations before any public-service outcome is finalized."
        ),
        post_market_monitoring_plan_ref="incident://benefits-review/triage-playbook-2026-03",
        simplified_tech_doc=True,
        retention_class="technical_doc",
    )

    risk = proof_layer.capture_risk_assessment(
        risk_id="risk-benefits-incident-001",
        severity="high",
        status="mitigated",
        summary="Incident-response risk for adverse public-service recommendations is tracked in the response file.",
        risk_description=(
            "A borderline threshold could over-rely on incomplete evidence and surface adverse recommendations without sufficient escalation."
        ),
        likelihood="medium",
        affected_groups=["benefit_applicants", "case_officers"],
        mitigation_measures=[
            "Mandatory manual review for borderline or adverse recommendations.",
            "Escalation to incident operations when an affected person could receive an adverse outcome.",
            "Authority-notification and corrective-action workflow when serious incidents are suspected.",
        ],
        residual_risk_level="medium",
        risk_owner="incident-ops",
        vulnerable_groups_considered=True,
        test_results_summary=(
            "Replay and reviewer-agreement checks are acceptable only when the escalation workflow remains active."
        ),
        record={
            "review_cycle": "quarterly",
            "reviewer": "rights-review-team",
        },
        retention_class="risk_mgmt",
    )

    oversight = proof_layer.capture_human_oversight(
        action="manual_case_review_required",
        reviewer="rights-panel",
        notes={
            "incident_summary": "Potentially adverse recommendation surfaced in a public-service case.",
            "root_cause_summary": "A borderline-case threshold was too permissive for a narrow benefits cohort.",
            "override_action": "route_to_manual_review",
        },
        actor_role="case_reviewer",
        anomaly_detected=True,
        override_action="route_to_manual_review",
        interpretation_guidance_followed=True,
        automation_bias_detected=False,
        two_person_verification=False,
        stop_triggered=False,
        stop_reason="Human escalation handled the affected public-service case without a global stop.",
        retention_class="risk_mgmt",
    )

    triage_decision = proof_layer.capture_policy_decision(
        policy_name="incident_reportability_triage",
        decision="notify_and_continue_manual_review",
        rationale={
            "authority": "eu_ai_office",
            "notification_summary": "Initial authority notification for a potentially adverse recommendation incident.",
            "owner": "incident-ops",
        },
        metadata={
            "article": "73",
            "owner": "incident-ops",
        },
        retention_class="risk_mgmt",
    )

    incident = proof_layer.capture_incident_report(
        incident_id="inc-benefits-42",
        severity="serious",
        status="open",
        occurred_at="2026-03-07T18:30:00Z",
        summary="Potentially adverse recommendation surfaced in a public-service case.",
        detection_method="human_review_escalation",
        root_cause_summary="A borderline-case threshold was too permissive for a narrow benefits cohort.",
        corrective_action_ref="ca-benefits-42",
        authority_notification_required=True,
        authority_notification_status="drafted",
        report={
            "owner": "incident-ops",
            "summary": "Escalated after human reviewer flagged a borderline denial.",
        },
        retention_class="risk_mgmt",
    )

    corrective_action = proof_layer.capture_corrective_action(
        action_id="ca-benefits-42",
        status="in_progress",
        summary="Tighten the borderline threshold and route similar cases to manual review.",
        due_at="2026-03-09T18:00:00Z",
        record={
            "incident_id": "inc-benefits-42",
            "owner": "safety-ops",
            "change": "threshold_tightened",
        },
        retention_class="risk_mgmt",
    )

    notification = proof_layer.capture_authority_notification(
        notification_id="notif-benefits-42",
        authority="eu_ai_office",
        status="drafted",
        incident_id="inc-benefits-42",
        due_at="2026-03-09T12:00:00Z",
        report={
            "article": "73",
            "summary": "Initial authority notification draft",
        },
        retention_class="risk_mgmt",
    )

    submission = proof_layer.capture_authority_submission(
        submission_id="sub-benefits-42",
        authority="eu_ai_office",
        status="submitted",
        channel="portal",
        submitted_at="2026-03-08T09:45:00Z",
        document={
            "incident_id": "inc-benefits-42",
            "article": "73",
            "summary": "Initial notification package for public-service incident follow-up.",
        },
        retention_class="risk_mgmt",
    )

    deadline = proof_layer.capture_reporting_deadline(
        deadline_id="deadline-benefits-42",
        authority="eu_ai_office",
        obligation_ref="art73_notification",
        due_at="2026-03-09T12:00:00Z",
        status="open",
        incident_id="inc-benefits-42",
        retention_class="risk_mgmt",
    )

    correspondence = proof_layer.capture_regulator_correspondence(
        correspondence_id="corr-benefits-42",
        authority="eu_ai_office",
        direction="outbound",
        status="sent",
        occurred_at="2026-03-08T10:00:00Z",
        message={
            "subject": "Initial authority follow-up",
            "reference": "inc-benefits-42",
        },
        retention_class="risk_mgmt",
    )

    pack = proof_layer.create_pack(
        pack_type="incident_response",
        system_id="benefits-review",
        bundle_format="full",
    )
    manifest = proof_layer.get_pack_manifest(pack["pack_id"])
    readiness = proof_layer.evaluate_completeness(
        pack_id=pack["pack_id"],
        profile="incident_response_v1",
    )
    export_bytes = proof_layer.download_pack_export(pack["pack_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(export_bytes)

    print("vault_url:", vault_url)
    print(
        "captured_bundle_ids:",
        ", ".join(
            [
                technical_doc["bundle_id"],
                risk["bundle_id"],
                oversight["bundle_id"],
                triage_decision["bundle_id"],
                incident["bundle_id"],
                corrective_action["bundle_id"],
                notification["bundle_id"],
                submission["bundle_id"],
                deadline["bundle_id"],
                correspondence["bundle_id"],
            ]
        ),
    )
    print("pack_id:", pack["pack_id"])
    print("pack_type:", manifest["pack_type"])
    print("manifest_bundle_count:", len(manifest["bundles"]))
    print("pack_readiness_profile:", readiness["profile"])
    print("pack_readiness_status:", readiness["status"])
    print("pack_readiness_pass_count:", readiness["pass_count"])
    print(
        "manifest_items:",
        ", ".join(
            f'{entry["bundle_id"]}:{"+".join(entry["item_types"])}'
            for entry in manifest["bundles"]
        ),
    )
    print("export_path:", output_path)


if __name__ == "__main__":
    main()
