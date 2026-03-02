import { ProofLayerClient, provedCompletion } from "../../packages/sdk-node/src/index.js";

async function main() {
  const proofClient = new ProofLayerClient({
    baseUrl: process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080"
  });

  const openaiLikeClient = {
    chat: {
      completions: {
        create: async (params) => ({
          id: "cmpl-demo-1",
          model: params.model,
          choices: [
            {
              message: {
                role: "assistant",
                content: `Echo: ${params.messages?.[params.messages.length - 1]?.content ?? ""}`
              }
            }
          ],
          usage: { prompt_tokens: 8, completion_tokens: 7, total_tokens: 15 },
          system_fingerprint: "demo-fingerprint"
        })
      }
    }
  };

  const { completion, bundleId, bundleRoot } = await provedCompletion(
    openaiLikeClient,
    {
      model: "gpt-4o-mini",
      temperature: 0.2,
      messages: [
        { role: "system", content: "You are concise." },
        { role: "user", content: "Summarize proof layers in one sentence." }
      ]
    },
    proofClient,
    { appId: "node-basic-example", env: "dev" }
  );

  console.log("completion:", completion.choices[0].message.content);
  console.log("bundle_id:", bundleId);
  console.log("bundle_root:", bundleRoot);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
