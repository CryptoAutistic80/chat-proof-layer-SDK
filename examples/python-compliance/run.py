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
    output_path = output_dir / "fundamental-rights.pkg"

    proof_layer = ProofLayer(
        vault_url=vault_url,
        app_id="python-fundamental-rights-example",
        env="dev",
        system_id="benefits-review",
        role="deployer",
        compliance_profile={
            "intended_use": "Public-sector benefit eligibility review",
            "risk_tier": "high_risk",
            "fria_required": True,
            "deployment_context": "public_sector",
            "metadata": {
                "owner": "rights-review-team",
                "market": "eu",
            },
        },
    )

    interaction = proof_layer.capture(
        provider="internal-review-queue",
        model="eligibility-ranker-v2",
        request_id="req-benefits-001",
        input={
            "case_id": "case-42",
            "prompt": "Summarize the eligibility factors for human review.",
        },
        output={
            "summary": "Manual review required because the applicant falls near a decision threshold."
        },
        retention_class="runtime_logs",
    )

    fria = proof_layer.capture_fundamental_rights_assessment(
        assessment_id="fria-2026-03",
        status="completed",
        scope="public-sector benefit eligibility review",
        report={
            "owner": "rights-review-team",
            "finding": "Human escalation required for borderline cases.",
        },
        legal_basis="GDPR Art. 22 and public-service review safeguards",
        affected_rights=[
            "equal treatment",
            "access to public services",
            "explanation",
        ],
        stakeholder_consultation_summary=(
            "Legal, service-operations, and rights-review stakeholders approved the workflow."
        ),
        mitigation_plan_summary=(
            "Borderline cases require human review and documented justification before any outcome is finalized."
        ),
        assessor="rights-review-team",
        retention_class="technical_doc",
    )

    oversight = proof_layer.capture_human_oversight(
        action="manual_case_review_required",
        reviewer="rights-panel",
        notes={
            "reason": "Borderline case with public-service impact.",
            "sla_hours": 24,
        },
        override_action="route_to_manual_review",
        retention_class="risk_mgmt",
    )

    pack = proof_layer.create_pack(
        pack_type="fundamental_rights",
        system_id="benefits-review",
        bundle_format="full",
    )
    pack_readiness = proof_layer.evaluate_completeness(
        pack_id=pack["pack_id"],
        profile="fundamental_rights_v1",
    )
    manifest = proof_layer.get_pack_manifest(pack["pack_id"])
    export_bytes = proof_layer.download_pack_export(pack["pack_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(export_bytes)

    print("vault_url:", vault_url)
    print(
        "captured_bundle_ids:",
        ", ".join(
            [
                interaction["bundle_id"],
                fria["bundle_id"],
                oversight["bundle_id"],
            ]
        ),
    )
    print("pack_id:", pack["pack_id"])
    print("pack_type:", manifest["pack_type"])
    print("pack_readiness:", pack_readiness["status"], pack_readiness["pass_count"])
    print("manifest_bundle_count:", len(manifest["bundles"]))
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
