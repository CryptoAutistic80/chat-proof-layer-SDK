import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ProofLayer, ProofLayerExporter, captureToolCall } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");

test("ProofLayerExporter captures tool events through ProofLayer", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-otel-1"
  });
  const exporter = new ProofLayerExporter(proofLayer);

  const result = await exporter.captureToolEvents(
    [captureToolCall("lookup", { query: "hello" }, { answer: "world" })],
    {
      provider: "openai",
      model: "gpt-4o-mini",
      input: [{ role: "user", content: "hello" }],
      output: { role: "assistant", content: "world" }
    }
  );

  assert.equal(result.bundle?.bundle_version, "1.0");
  assert.equal(result.bundle?.subject.system_id, "system-otel-1");
  assert.equal(result.bundle?.context.otel_genai_semconv_version, "1.0.0");
});
