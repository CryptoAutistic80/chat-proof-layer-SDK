# proof-layer-sdk-python

Python SDK for creating Proof Layer evidence bundles around model calls and lifecycle events.
Integrity-sensitive helpers are backed by the local Rust PyO3 module in `crates/pyo3`.
The shared builder/facade surface now covers all evidence item types currently implemented in Rust core, including `llm_interaction`, `tool_call`, `retrieval`, `human_oversight`, `policy_decision`, `risk_assessment`, `data_governance`, `technical_doc`, `instructions_for_use`, `qms_record`, `fundamental_rights_assessment`, `standards_alignment`, `post_market_monitoring`, `corrective_action`, `authority_notification`, `authority_submission`, `reporting_deadline`, `regulator_correspondence`, `model_evaluation`, `adversarial_test`, `training_provenance`, `compute_metrics`, `downstream_documentation`, `copyright_policy`, `training_summary`, `literacy_attestation`, `incident_report`, `conformity_assessment`, `declaration`, and `registration`.
The GPAI helpers default `model_evaluation`, `adversarial_test`, `training_provenance`, and `compute_metrics` captures to the vault's `gpai_documentation` retention class.

## Install

Use one of these paths:

- local repo build: `python3 ./scripts/build_native.py`
- checked release wheel: install the matching `.whl` asset attached to a `sdk-v*` GitHub release

When `PYPI_API_TOKEN` is configured in GitHub Actions, the release workflow can also publish those wheels to PyPI.

## Build Native Bindings

```bash
python3 ./scripts/build_native.py
```

## Build A Checked Wheel Artifact

```bash
python3 ./scripts/build_dist.py
```

This builds a platform-tagged wheel under `dist/`, runs the native build during wheel creation, and verifies that the wheel contains `proofsdk/_native*` plus the typed package markers. The packaging path defaults to `PROOF_SDK_NATIVE_PROFILE=release`.

The repo’s `.github/workflows/sdk-artifacts.yml` workflow runs the same checked wheel build on Linux, macOS, and Windows, and `.github/workflows/sdk-release.yml` attaches those wheels to GitHub releases for `sdk-v*` tags.

## Chat Session Vertical Slice (Local)

Use `LocalChatProofSession` for deterministic transcript hashing, session-level signatures, and local tamper verification. A runnable end-to-end sample is available at `examples/python-chat-proof/run.py`, which writes `examples/bundles/chat-session.bundle.json`.

```python
from proofsdk import LocalChatProofSession, verify_local_chat_bundle

session = LocalChatProofSession(signing_key_pem=PRIVATE_KEY_PEM, provider="openai", model="gpt-4.1-mini")
session.log_turn(role="user", content="hello")
session.log_turn(role="assistant", content="hi")
sealed = session.finalize_bundle()
check = verify_local_chat_bundle(sealed["bundle"], sealed["transcript"], PUBLIC_KEY_PEM)
print(check["verified"])
```

## Quick Usage

```python
from proofsdk import (
    LocalProofLayerClient,
    ProofLayer,
    build_bundle,
    create_disclosure_policy_template,
    hash_sha256,
    select_pack_readiness,
    verify_bundle,
)
from proofsdk.client import ProofLayerClient
from proofsdk.providers.openai import with_proof_layer

proof_client = ProofLayerClient(base_url="http://127.0.0.1:8080")
local_client = LocalProofLayerClient(
    signing_key_pem="-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
    signing_key_id="kid-dev-01",
)
proof_layer = ProofLayer(
    signing_key_pem="-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
    key_id="kid-dev-01",
    system_id="system-123",
)

wrapped = with_proof_layer(
    type(
        "Client",
        (),
        {
            "chat": type(
                "Chat",
                (),
                {
                    "completions": type(
                        "Completions",
                        (),
                        {
                            "create": staticmethod(
                                lambda params: {
                                    "id": "cmpl-1",
                                    "model": params["model"],
                                    "choices": [{"message": {"role": "assistant", "content": "hello"}}],
                                }
                            )
                        },
                    )()
                },
            )()
        },
    )(),
    proof_layer,
)
completion = wrapped.chat.completions.create(
    {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]}
)

print(completion["id"], completion["proof_layer"]["bundle_id"])
print(hash_sha256(b'{"hello":"world"}'))

local_bundle = build_bundle(
    capture=full_capture_dict,
    artefacts=[{"name": "prompt.json", "content_type": "application/json", "data": b"{}"}],
    key_pem="-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
    kid="kid-dev-01",
    bundle_id="PLFIXEDGOLDEN000000000000000001",
    created_at="2026-03-02T00:00:00+00:00",
)

locally_sealed = local_client.create_bundle(
    full_capture_dict,
    [{"name": "prompt.json", "content_type": "application/json", "data": b"{}"}],
)

readiness = proof_layer.evaluate_completeness(
    bundle=locally_sealed["bundle"],
    profile="annex_iv_governance_v1",
)

provider_governance_readiness = proof_layer.evaluate_completeness(
    # full_provider_governance_bundle should contain the provider-side governance evidence set.
    bundle=full_provider_governance_bundle,
    profile="provider_governance_v1",
)

conformity_readiness = proof_layer.evaluate_completeness(
    # full_conformity_bundle should contain the conformity assessment, declaration, and registration evidence set.
    bundle=full_conformity_bundle,
    profile="conformity_v1",
)

gpai_readiness = proof_layer.evaluate_completeness(
    # full_gpai_provider_bundle should contain the full structured GPAI provider evidence set.
    bundle=full_gpai_provider_bundle,
    profile="gpai_provider_v1",
)

fria_readiness = proof_layer.evaluate_completeness(
    # full_fundamental_rights_bundle should contain the deployer-side FRIA assessment + oversight evidence set.
    bundle=full_fundamental_rights_bundle,
    profile="fundamental_rights_v1",
)
incident_response_readiness = proof_layer.evaluate_completeness(
    # full_incident_response_bundle should contain the incident context, triage, oversight, incident, and authority-reporting evidence set.
    bundle=full_incident_response_bundle,
    profile="incident_response_v1",
)
monitoring_readiness = proof_layer.evaluate_completeness(
    # full_post_market_monitoring_bundle should contain the monitoring, incident, corrective-action, and authority-reporting evidence set.
    bundle=full_post_market_monitoring_bundle,
    profile="post_market_monitoring_v1",
)

timestamp_check = proof_client.verify_timestamp(bundle_id="BUNDLE_ID")
receipt_check = proof_client.verify_receipt(
    bundle_id="BUNDLE_ID",
    live_check_mode="best_effort",
)

summary = verify_bundle(
    bundle=locally_sealed["bundle"],
    artefacts=[{"name": "prompt.json", "data": b"{}"}],
    public_key_pem="-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n",
)

print(summary["artefact_count"])
print(readiness["status"])
print(gpai_readiness["status"])
print(timestamp_check["assessment"]["headline"], timestamp_check["assessment"]["level"])
print(
    receipt_check["assessment"]["summary"],
    receipt_check["assessment"].get("live_check", {}).get("state"),
)

redacted = proof_layer.disclose(
    bundle=locally_sealed["bundle"],
    item_indices=[0],
    field_redactions={0: ["output_commitment"]},
)
redacted_summary = proof_layer.verify_redacted_bundle(
    redacted,
    [],
    "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n",
)

pack = proof_client.create_pack(
    pack_type="annex_iv",
    system_id="system-123",
    bundle_format="disclosure",
    disclosure_policy="annex_iv_redacted",
)
template_pack = proof_client.create_pack(
    pack_type="runtime_logs",
    system_id="system-123",
    bundle_format="disclosure",
    disclosure_template={
        "profile": "runtime_minimum",
        "name": "runtime_minimum_export",
        "redaction_groups": ["metadata"],
    },
)
template_catalog = proof_client.get_disclosure_templates()
rendered_template = proof_client.render_disclosure_template(
    profile="privacy_review",
    name="privacy_review_internal",
    redaction_groups=["metadata"],
    redacted_fields_by_item_type={"risk_assessment": ["/metadata/internal_notes"]},
)
proof_client.update_disclosure_config(
    {
        "policies": [
            create_disclosure_policy_template(
                "runtime_minimum",
                name="runtime_minimum_internal",
                redaction_groups=["metadata"],
            )
        ]
    }
)
preview = proof_client.preview_disclosure(
    bundle_id="BUNDLE_ID",
    pack_type="annex_iv",
    policy={
        "name": "risk_only",
        "allowed_obligation_refs": ["art9"],
    },
)
template_preview = proof_client.preview_disclosure(
    bundle_id="BUNDLE_ID",
    pack_type="runtime_logs",
    disclosure_template={
        "profile": "privacy_review",
        "name": "privacy_review_internal",
        "redaction_groups": ["metadata"],
    },
)
archive = proof_client.download_pack_export(pack["pack_id"])
vault_readiness = proof_client.evaluate_completeness(
    bundle_id="BUNDLE_ID",
    profile="annex_iv_governance_v1",
)
annex_xi_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="gpai_provider_v1",
)
provider_governance_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="provider_governance_v1",
)
conformity_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="conformity_v1",
)
fundamental_rights_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="fundamental_rights_v1",
)
incident_response_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="incident_response_v1",
)
monitoring_pack_readiness = proof_client.evaluate_completeness(
    pack_id="PACK_ID",
    profile="post_market_monitoring_v1",
)
pack_readiness = select_pack_readiness(pack)

risk_bundle = proof_layer.capture_risk_assessment(
    risk_id="risk-42",
    severity="medium",
    status="mitigated",
    summary="manual review added",
)

print(risk_bundle["bundle"]["items"][0]["type"])
print(redacted_summary["disclosed_item_count"], len(archive))
print(preview["disclosed_item_types"])
print(template_pack["pack_id"], template_preview["disclosed_item_types"])
print(template_catalog["templates"][0]["profile"], rendered_template["policy"]["name"])
print(
    annex_xi_pack_readiness["status"],
    provider_governance_pack_readiness["status"],
    conformity_pack_readiness["status"],
)
print(
    incident_response_readiness["status"],
    incident_response_pack_readiness["status"],
    monitoring_readiness["status"],
    monitoring_pack_readiness["status"],
)
print(pack_readiness["source"], pack_readiness["status"])
print(vault_readiness["status"])
```

Vault pack responses preserve the legacy per-bundle `completeness_*` fields and add `pack_completeness_*` when a pack has synthesized pack-level readiness support.
Use `select_pack_readiness(pack_summary_or_manifest)` when you want one helper that prefers the true pack-scoped signal (`source == "pack_scoped"`) and falls back to the legacy bundle aggregate signal (`source == "bundle_aggregate"`).

Vault verification responses now also include a plain-English `assessment` block.
Use `verify_timestamp(...)` and `verify_receipt(...)` when you want both the low-level crypto result and a short human-readable trust summary.
For receipts, `live_check_mode="best_effort"` adds an opt-in live Rekor freshness check without turning temporary network problems into a hard failure.

For `annex_iv`, the pack-scoped pass count is currently `8` because `annex_iv_governance_v1` now evaluates the full governance set curated by the pack.
For `conformity`, the pack-scoped pass count is currently `3` because `conformity_v1` evaluates the conformity assessment, declaration, and registration artefacts curated by that pack.
For `provider_governance`, the pack-scoped pass count is currently `8` because `provider_governance_v1` evaluates the provider-side governance set curated by that pack, including corrective action follow-up.
For `incident_response`, the pack-scoped pass count is currently `10` because `incident_response_v1` evaluates the incident context, triage, oversight, corrective-action, authority-reporting, and correspondence families curated by that pack.
For `post_market_monitoring`, the pack-scoped pass count is currently `6` because `post_market_monitoring_v1` evaluates the required monitoring and authority-reporting rule families.

For the full provider-side Annex IV governance walkthrough, build the native module and run:

```bash
python3 packages/sdk-python/scripts/build_native.py
python3 examples/python-annex-iv/run.py
```

That example captures the checked governance set, previews `annex_iv_redacted`, and exports both full and disclosure-format `annex_iv` packs.
