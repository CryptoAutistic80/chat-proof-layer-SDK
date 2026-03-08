import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildBundle,
  hashSha256,
  redactBundle,
  signBundleRoot,
  verifyBundle,
  verifyRedactedBundle,
  verifyBundleRoot
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");

test("native sign and verify round-trip uses Rust core logic", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const publicKeyPem = await readFile(path.join(goldenDir, "verify_key.txt"), "utf8");
  const bundleRoot = hashSha256("native-node-roundtrip");
  const jws = signBundleRoot(bundleRoot, signingKeyPem, "kid-dev-01");

  assert.equal(typeof jws, "string");
  assert.equal(verifyBundleRoot(jws, bundleRoot, publicKeyPem), true);
});

test("native verifyBundle performs offline verification against the golden fixture", async () => {
  const bundle = JSON.parse(await readFile(path.join(goldenDir, "fixed_bundle", "proof_bundle.json"), "utf8"));
  const publicKeyPem = await readFile(path.join(goldenDir, "verify_key.txt"), "utf8");
  const artefacts = await Promise.all(
    bundle.artefacts.map(async (artefact) => ({
      name: artefact.name,
      data: await readFile(path.join(goldenDir, "fixed_bundle", "artefacts", artefact.name))
    }))
  );

  const summary = verifyBundle({ bundle, artefacts, publicKeyPem });
  assert.deepEqual(summary, { artefact_count: artefacts.length });
});

test("native buildBundle reproduces the deterministic golden bundle", async () => {
  const capture = JSON.parse(await readFile(path.join(goldenDir, "capture.json"), "utf8"));
  const expectedBundle = JSON.parse(
    await readFile(path.join(goldenDir, "fixed_bundle", "proof_bundle.json"), "utf8")
  );
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
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

  const bundle = buildBundle({
    capture,
    artefacts,
    keyPem: signingKeyPem,
    kid: "kid-dev-01",
    bundleId: expectedBundle.bundle_id,
    createdAt: expectedBundle.created_at
  });

  assert.deepEqual(bundle, expectedBundle);
});

test("native redactBundle and verifyRedactedBundle round-trip a disclosed item", async () => {
  const bundle = JSON.parse(await readFile(path.join(goldenDir, "fixed_bundle", "proof_bundle.json"), "utf8"));
  const publicKeyPem = await readFile(path.join(goldenDir, "verify_key.txt"), "utf8");

  const redacted = redactBundle({
    bundle,
    itemIndices: [0]
  });
  const summary = verifyRedactedBundle({
    bundle: redacted,
    artefacts: [],
    publicKeyPem
  });

  assert.equal(redacted.disclosed_items.length, 1);
  assert.equal(redacted.disclosed_artefacts.length, 0);
  assert.deepEqual(summary, {
    disclosed_item_count: 1,
    disclosed_artefact_count: 0
  });
});
