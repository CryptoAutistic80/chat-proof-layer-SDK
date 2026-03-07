import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LocalProofLayerClient, provedCompletion } from "../dist/index.js";
import { withProofLayer as withGenericProofLayer } from "../dist/providers/generic.js";
import { ProofLayer } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");

test("provedCompletion wraps provider call and creates bundle", async () => {
  const fakeClient = {
    chat: {
      completions: {
        create: async (params) => ({
          id: "cmpl-1",
          model: params.model,
          choices: [{ message: { role: "assistant", content: "ok" } }],
          usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 }
        })
      }
    }
  };

  let captured;
  const proofClient = {
    createBundle: async (payload) => {
      captured = payload;
      return {
        bundle_id: "B-123",
        bundle_root: "sha256:abc",
        signature: "sig",
        created_at: "2026-03-02T00:00:00Z"
      };
    }
  };

  const out = await provedCompletion(
    fakeClient,
    { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
    proofClient
  );

  assert.equal(out.bundleId, "B-123");
  assert.equal(out.completion.id, "cmpl-1");
  assert.equal(captured.artefacts.length, 2);
  assert.equal(captured.capture.context.provider, "openai");
  assert.equal(captured.capture.items[0].type, "llm_interaction");
  assert.ok(captured.capture.items[0].data.input_commitment.startsWith("sha256:"));
  assert.ok(captured.capture.items[0].data.output_commitment.startsWith("sha256:"));
});

test("provedCompletion works with LocalProofLayerClient", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofClient = new LocalProofLayerClient({
    signingKeyPem,
    signingKeyId: "kid-dev-01",
    bundleIdFactory: () => "pl-local-provider-test",
    createdAtFactory: () => "2026-03-02T00:00:00+00:00"
  });

  const out = await provedCompletion(
    (params) => ({
      id: "cmpl-local-1",
      model: params.model,
      choices: [{ message: { role: "assistant", content: "ok" } }],
      usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 }
    }),
    { model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] },
    proofClient,
    { requestId: "req-local-1" }
  );

  assert.equal(out.bundleId, "pl-local-provider-test");
  assert.equal(out.bundle?.bundle_version, "1.0");
  assert.equal(out.bundle?.integrity.signature.kid, "kid-dev-01");
});

test("generic provider wrapper attaches proof metadata", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-generic-1"
  });

  const wrapped = withGenericProofLayer(
    async (params) => ({
      id: "generic-1",
      model: params.model,
      output_text: "ok",
      usage: { input_tokens: 2, output_tokens: 1 }
    }),
    proofLayer,
    {
      provider: "custom-provider",
      buildTrace: (_params, result) => ({ usage: result.usage, provider: "custom-provider" })
    }
  );

  const result = await wrapped({
    model: "custom-model-1",
    messages: [{ role: "user", content: "hello" }]
  });

  assert.equal(result.id, "generic-1");
  assert.equal(result.proofLayer.bundle?.subject.system_id, "system-generic-1");
  assert.equal(result.proofLayer.bundle?.context.provider, "custom-provider");
});
