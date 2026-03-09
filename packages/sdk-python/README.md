# proof-layer-sdk-python

Python SDK for creating Proof Layer evidence bundles around model calls and lifecycle events.
Integrity-sensitive helpers are backed by the local Rust PyO3 module in `crates/pyo3`.
The shared builder/facade surface now covers all evidence item types currently implemented in Rust core, including `model_evaluation`, `adversarial_test`, `training_provenance`, `literacy_attestation`, `incident_report`, `conformity_assessment`, `declaration`, and `registration`.
The GPAI helpers default `model_evaluation`, `adversarial_test`, and `training_provenance` captures to the vault's `gpai_documentation` retention class.

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

## Quick Usage

```python
from proofsdk import (
    LocalProofLayerClient,
    ProofLayer,
    build_bundle,
    create_disclosure_policy_template,
    hash_sha256,
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

summary = verify_bundle(
    bundle=locally_sealed["bundle"],
    artefacts=[{"name": "prompt.json", "data": b"{}"}],
    public_key_pem="-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n",
)

print(summary["artefact_count"])

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
```
