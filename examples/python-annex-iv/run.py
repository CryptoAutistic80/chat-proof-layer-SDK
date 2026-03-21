import json
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


def load_fixture(fixture_dir: Path, name: str) -> dict:
    return json.loads((fixture_dir / name).read_text(encoding="utf-8"))


def main() -> None:
    vault_url = os.environ.get("PROOF_SERVICE_URL", "http://127.0.0.1:8080")
    fixture_dir = (
        Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "annex_iv_governance"
    )
    output_dir = Path(__file__).resolve().parent / "artifacts"
    full_output_path = output_dir / "annex-iv-full.pack"
    disclosure_output_path = output_dir / "annex-iv-disclosure.pack"

    proof_layer = ProofLayer(
        vault_url=vault_url,
        app_id="python-annex-iv-example",
        env="dev",
        system_id="hiring-assistant",
        role="provider",
        compliance_profile={
            "intended_use": "Recruiter support for first-pass candidate review",
            "prohibited_practice_screening": "screened_no_prohibited_use",
            "risk_tier": "high_risk",
            "high_risk_domain": "employment",
            "deployment_context": "eu_market_placement",
            "metadata": {
                "owner": "quality-team",
                "market": "eu",
            },
        },
    )

    technical_doc_fixture = load_fixture(fixture_dir, "technical_doc.json")
    risk_fixture = load_fixture(fixture_dir, "risk_assessment.json")
    data_fixture = load_fixture(fixture_dir, "data_governance.json")
    instructions_fixture = load_fixture(fixture_dir, "instructions_for_use.json")
    oversight_fixture = load_fixture(fixture_dir, "human_oversight.json")
    qms_fixture = load_fixture(fixture_dir, "qms_record.json")
    standards_fixture = load_fixture(fixture_dir, "standards_alignment.json")
    monitoring_fixture = load_fixture(fixture_dir, "post_market_monitoring.json")

    technical_doc = proof_layer.capture_technical_doc(
        **technical_doc_fixture,
        version="2026.03",
        retention_class="technical_doc",
        descriptor={
            "owner": "quality-team",
            "document_class": "annex_iv_system_card",
        },
    )
    risk_assessment = proof_layer.capture_risk_assessment(
        **risk_fixture,
        version="2026.03",
        retention_class="risk_mgmt",
    )
    data_governance = proof_layer.capture_data_governance(
        **data_fixture,
        version="2026.03",
        retention_class="technical_doc",
    )
    instructions_for_use = proof_layer.capture_instructions_for_use(
        document_ref=instructions_fixture["document_ref"],
        version_tag=instructions_fixture["version"],
        section=instructions_fixture["section"],
        provider_identity=instructions_fixture["provider_identity"],
        intended_purpose=instructions_fixture["intended_purpose"],
        system_capabilities=instructions_fixture["system_capabilities"],
        accuracy_metrics=instructions_fixture["accuracy_metrics"],
        foreseeable_risks=instructions_fixture["foreseeable_risks"],
        explainability_capabilities=instructions_fixture["explainability_capabilities"],
        human_oversight_guidance=instructions_fixture["human_oversight_guidance"],
        compute_requirements=instructions_fixture["compute_requirements"],
        service_lifetime=instructions_fixture["service_lifetime"],
        log_management_guidance=instructions_fixture["log_management_guidance"],
        metadata=instructions_fixture["metadata"],
        version="2026.03",
        retention_class="technical_doc",
    )
    human_oversight = proof_layer.capture_human_oversight(
        **oversight_fixture,
        version="2026.03",
        retention_class="risk_mgmt",
        notes={
            "escalation_path": "quality-panel",
            "sla_hours": 24,
        },
    )
    qms_record = proof_layer.capture_qms_record(
        **qms_fixture,
        version="2026.03",
        retention_class="technical_doc",
    )
    standards_alignment = proof_layer.capture_standards_alignment(
        **standards_fixture,
        version="2026.03",
        retention_class="technical_doc",
    )
    post_market_monitoring = proof_layer.capture_post_market_monitoring(
        **monitoring_fixture,
        version="2026.03",
        retention_class="risk_mgmt",
    )

    preview = proof_layer.preview_disclosure(
        bundle_id=data_governance["bundle_id"],
        pack_type="annex_iv",
        disclosure_policy="annex_iv_redacted",
    )

    full_pack = proof_layer.create_pack(
        pack_type="annex_iv",
        system_id="hiring-assistant",
        bundle_format="full",
    )
    disclosure_pack = proof_layer.create_pack(
        pack_type="annex_iv",
        system_id="hiring-assistant",
        bundle_format="disclosure",
        disclosure_policy="annex_iv_redacted",
    )

    full_manifest = proof_layer.get_pack_manifest(full_pack["pack_id"])
    disclosure_manifest = proof_layer.get_pack_manifest(disclosure_pack["pack_id"])
    full_export_bytes = proof_layer.download_pack_export(full_pack["pack_id"])
    disclosure_export_bytes = proof_layer.download_pack_export(disclosure_pack["pack_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    full_output_path.write_bytes(full_export_bytes)
    disclosure_output_path.write_bytes(disclosure_export_bytes)

    print("vault_url:", vault_url)
    print(
        "captured_bundle_ids:",
        ", ".join(
            [
                technical_doc["bundle_id"],
                risk_assessment["bundle_id"],
                data_governance["bundle_id"],
                instructions_for_use["bundle_id"],
                human_oversight["bundle_id"],
                qms_record["bundle_id"],
                standards_alignment["bundle_id"],
                post_market_monitoring["bundle_id"],
            ]
        ),
    )
    print("preview_policy:", preview["policy_name"])
    print("preview_item_types:", ", ".join(preview["disclosed_item_types"]))
    print(
        "preview_field_redactions:",
        json.dumps(preview.get("disclosed_item_field_redactions", {}), sort_keys=True),
    )
    print("full_pack_id:", full_pack["pack_id"])
    print(
        "full_manifest_items:",
        ", ".join(entry["item_types"][0] for entry in full_manifest["bundles"]),
    )
    print("full_export_path:", full_output_path)
    print("disclosure_pack_id:", disclosure_pack["pack_id"])
    print(
        "disclosure_manifest_items:",
        ", ".join(entry["item_types"][0] for entry in disclosure_manifest["bundles"]),
    )
    print("disclosure_export_path:", disclosure_output_path)


if __name__ == "__main__":
    main()
