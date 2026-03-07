import { ProofLayer } from "../../sdks/typescript/dist/index.js";
import { withProofLayer } from "../../sdks/typescript/dist/providers/openai.js";

async function main() {
  const proofLayer = new ProofLayer({
    vaultUrl: process.env.PROOF_SERVICE_URL ?? "http://127.0.0.1:8080",
    appId: "typescript-basic-example",
    env: "dev"
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

  const openai = withProofLayer(openaiLikeClient, proofLayer);
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    temperature: 0.2,
    messages: [
      { role: "system", content: "You are concise." },
      { role: "user", content: "Summarize proof layers in one sentence." }
    ]
  });

  console.log("completion:", completion.choices[0].message.content);
  console.log("bundle_id:", completion.proofLayer.bundleId);
  console.log("bundle_root:", completion.proofLayer.bundleRoot);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
