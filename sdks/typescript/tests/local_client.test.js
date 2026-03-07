import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LocalProofLayerClient } from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");

test("LocalProofLayerClient builds the deterministic golden bundle", async () => {
  const capture = JSON.parse(await readFile(path.join(goldenDir, "capture.json"), "utf8"));
  const expectedBundle = JSON.parse(
    await readFile(path.join(goldenDir, "fixed_bundle", "proof_bundle.json"), "utf8")
  );
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const client = new LocalProofLayerClient({ signingKeyPem, signingKeyId: "kid-dev-01" });
  const artefacts = [
    {
      name: "prompt.json",
      contentType: "application/json",
      data: await readFile(path.join(goldenDir, "prompt.json"))
    },
    {
      name: "response.json",
      contentType: "application/json",
      data: await readFile(path.join(goldenDir, "response.json"))
    }
  ];

  const out = await client.createBundle({
    capture,
    artefacts,
    bundleId: expectedBundle.bundle_id,
    createdAt: expectedBundle.created_at
  });

  assert.equal(out.bundle_id, expectedBundle.bundle_id);
  assert.equal(out.bundle_root, expectedBundle.integrity.bundle_root);
  assert.equal(out.signature, expectedBundle.integrity.signature.value);
  assert.deepEqual(out.bundle, expectedBundle);
});
