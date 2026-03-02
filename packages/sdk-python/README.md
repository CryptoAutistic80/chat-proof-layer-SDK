# proof-layer-sdk-python (PoC)

Python wrappers for creating proof bundles around LLM requests and tool calls.

## Quick Usage

```python
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
```
