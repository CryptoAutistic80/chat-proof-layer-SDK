import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  hashSha256,
  signBundleRoot,
  verifyBundle,
  verifyBundleRoot
} from "../src/native.js";

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
