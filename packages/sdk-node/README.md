# @proof-layer/sdk-node (PoC)

Node SDK wrappers for creating Proof Layer bundles around model calls.

## Quick Usage

```js
import { ProofLayerClient, provedCompletion } from "./src/index.js";

const proofClient = new ProofLayerClient({ baseUrl: "http://127.0.0.1:8080" });
const openaiClient = {
  chat: {
    completions: {
      create: async (params) => ({
        id: "cmpl-demo",
        model: params.model,
        choices: [{ message: { role: "assistant", content: "Hello" } }],
        usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 }
      })
    }
  }
};

const { completion, bundleId } = await provedCompletion(
  openaiClient,
  { model: "gpt-4o-mini", messages: [{ role: "user", content: "Say hello" }] },
  proofClient
);

console.log(bundleId, completion.id);
```
