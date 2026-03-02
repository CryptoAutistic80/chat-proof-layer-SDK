import os
import sys

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "packages", "sdk-python")
    ),
)

from proofsdk.client import ProofLayerClient
from proofsdk.providers.openai_like import proved_completion


def main() -> None:
    proof_client = ProofLayerClient(base_url="http://127.0.0.1:8080")

    def fake_openai_call(params):
        return {
            "id": "cmpl-demo-1",
            "model": params["model"],
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"Echo: {params['messages'][-1]['content']}",
                    }
                }
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 7, "total_tokens": 15},
            "system_fingerprint": "demo-fingerprint",
        }

    completion, proof = proved_completion(
        fake_openai_call,
        {
            "model": "gpt-4o-mini",
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": "You are concise."},
                {"role": "user", "content": "Summarize proof layers in one sentence."},
            ],
        },
        proof_client,
        {"app_id": "python-basic-example", "env": "dev"},
    )

    print("completion:", completion["choices"][0]["message"]["content"])
    print("bundle_id:", proof["bundle_id"])
    print("bundle_root:", proof["bundle_root"])


if __name__ == "__main__":
    main()
