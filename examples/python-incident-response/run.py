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

    incident = proof_layer.capture_incident_report(
        incident_id="inc-benefits-42",
        severity="serious",
        status="open",
        occurred_at="2026-03-07T18:30:00Z",
        summary="Potentially adverse recommendation surfaced in a public-service case.",
        report={
            "owner": "incident-ops",
            "summary": "Escalated after human reviewer flagged a borderline denial.",
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
    export_bytes = proof_layer.download_pack_export(pack["pack_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(export_bytes)

    print("vault_url:", vault_url)
    print(
        "captured_bundle_ids:",
        ", ".join(
            [
                incident["bundle_id"],
                notification["bundle_id"],
                deadline["bundle_id"],
                correspondence["bundle_id"],
            ]
        ),
    )
    print("pack_id:", pack["pack_id"])
    print("pack_type:", manifest["pack_type"])
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
