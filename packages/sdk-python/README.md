# proof-layer-sdk-python (PoC)

Python wrappers for creating proof bundles around LLM requests and tool calls.
Integrity-sensitive helpers are now backed by the local Rust PyO3 module in `crates/pyo3`.

## Build Native Bindings

```bash
python3 ./scripts/build_native.py
```

## Quick Usage

```python
from proofsdk import build_bundle, hash_sha256, verify_bundle
from proofsdk.client import ProofLayerClient
from proofsdk.providers.openai_like import proved_completion

proof_client = ProofLayerClient(base_url="http://127.0.0.1:8080")

completion, proof = proved_completion(
    lambda params: {
        "id": "cmpl-1",
        "model": params["model"],
        "choices": [{"message": {"role": "assistant", "content": "hello"}}]
    },
    {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hi"}]},
    proof_client,
)

print(completion["id"], proof["bundle_id"])
print(hash_sha256(b'{"hello":"world"}'))

local_bundle = build_bundle(
    capture=full_capture_dict,
    artefacts=[{"name": "prompt.json", "content_type": "application/json", "data": b"{}"}],
    key_pem="-----BEGIN PROOF LAYER ED25519 PRIVATE KEY-----\n...\n-----END PROOF LAYER ED25519 PRIVATE KEY-----\n",
    kid="kid-dev-01",
    bundle_id="PLFIXEDGOLDEN000000000000000001",
    created_at="2026-03-02T00:00:00+00:00",
)

summary = verify_bundle(
    bundle=local_bundle,
    artefacts=[{"name": "prompt.json", "data": b"{}"}],
    public_key_pem="-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----\n...\n-----END PROOF LAYER ED25519 PUBLIC KEY-----\n",
)

print(summary["artefact_count"])
```
