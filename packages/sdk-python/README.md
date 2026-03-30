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

## Quick Start (Chat Session)

```python
from proofsdk import ProofLayer, with_proof_layer

proof_layer = ProofLayer.load(
    signing_key_pem="-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
    key_id="kid-dev-01",
)

wrapped = with_proof_layer(openai_client, proof_layer)
completion = wrapped.chat.completions.create(
    {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]}
)

print(completion["proof_layer"]["bundle_id"])
```

For lifecycle/compliance captures (risk, QMS, declarations, packs, etc.), use imports from `proofsdk.advanced`.

## Advanced Usage

Use `proofsdk.advanced.*` modules for lifecycle/compliance capture builders and utilities.
