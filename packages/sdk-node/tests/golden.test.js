import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { canonicalize } from "json-canonicalize";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");
const fixedBundleDir = path.join(goldenDir, "fixed_bundle");
const rfcVectorPath = path.join(goldenDir, "rfc8785_vectors.json");

function sha256Prefixed(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function parseDigestBytes(digest) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
    throw new Error(`invalid digest format: ${digest}`);
  }
  return Buffer.from(digest.slice("sha256:".length), "hex");
}

function computeBundleRoot(digests) {
  let level = digests.map((digest) => {
    const leafInput = Buffer.concat([Buffer.from([0x00]), parseDigestBytes(digest)]);
    return createHash("sha256").update(leafInput).digest();
  });

  while (level.length > 1) {
    if (level.length % 2 === 1) {
      level.push(level[level.length - 1]);
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const parentInput = Buffer.concat([Buffer.from([0x01]), level[i], level[i + 1]]);
      next.push(createHash("sha256").update(parentInput).digest());
    }
    level = next;
  }

  return `sha256:${createHash("sha256").update(level[0]).digest("hex")}`;
}

function decodeBase64Url(segment) {
  const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padLength), "base64");
}

function extractProofLayerPublicKeyRaw(pem) {
  const lines = pem
    .trim()
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  assert.equal(lines[0], "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----");
  assert.equal(lines[lines.length - 1], "-----END PROOF LAYER ED25519 PUBLIC KEY-----");
  return Buffer.from(lines.slice(1, -1).join(""), "base64");
}

function ed25519SpkiFromRaw(rawKey) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  if (rawKey.length !== 32) {
    throw new Error(`public key must be 32 bytes, got ${rawKey.length}`);
  }
  return Buffer.concat([prefix, rawKey]);
}

test("golden fixture digest and signature assertions are deterministic", async () => {
  const expected = JSON.parse(
    await readFile(path.join(goldenDir, "expected_bundle_values.json"), "utf8")
  );
  const bundle = JSON.parse(await readFile(path.join(fixedBundleDir, "proof_bundle.json"), "utf8"));
  const canonicalFixture = await readFile(path.join(fixedBundleDir, "proof_bundle.canonical.json"));
  const signatureFixture = (await readFile(path.join(fixedBundleDir, "proof_bundle.sig"), "utf8")).trim();
  const verifyPem = await readFile(path.join(goldenDir, "verify_key.txt"), "utf8");

  assert.equal(bundle.bundle_id, expected.bundle_id);
  assert.equal(bundle.created_at, expected.created_at);
  assert.equal(bundle.integrity.header_digest, expected.header_digest);
  assert.equal(bundle.integrity.bundle_root, expected.bundle_root);
  assert.equal(bundle.integrity.signature.kid, expected.signing_kid);
  assert.equal(bundle.integrity.signature.value, expected.signature_jws);
  assert.equal(signatureFixture, expected.signature_jws);

  const projection = {
    bundle_version: bundle.bundle_version,
    bundle_id: bundle.bundle_id,
    created_at: bundle.created_at,
    actor: bundle.actor,
    subject: bundle.subject,
    model: bundle.model,
    inputs: bundle.inputs,
    outputs: bundle.outputs,
    trace: bundle.trace,
    artefacts: bundle.artefacts,
    policy: bundle.policy
  };
  const canonical = Buffer.from(canonicalize(projection), "utf8");
  assert.deepEqual(canonical, canonicalFixture);
  assert.equal(sha256Prefixed(canonical), expected.header_digest);

  for (const artefact of bundle.artefacts) {
    const bytes = await readFile(path.join(fixedBundleDir, "artefacts", artefact.name));
    assert.equal(sha256Prefixed(bytes), artefact.digest);
    assert.equal(sha256Prefixed(bytes), expected.artefact_digests[artefact.name]);
    assert.equal(bytes.length, artefact.size);
  }

  for (const [name, entry] of Object.entries(expected.manifest_entries)) {
    const bytes = await readFile(path.join(fixedBundleDir, name));
    assert.equal(sha256Prefixed(bytes), entry.digest);
    assert.equal(bytes.length, entry.size);
  }

  const orderedDigests = [expected.header_digest, ...bundle.artefacts.map((artefact) => artefact.digest)];
  const rootOne = computeBundleRoot(orderedDigests);
  const rootTwo = computeBundleRoot(orderedDigests);
  assert.equal(rootOne, rootTwo);
  assert.equal(rootOne, expected.bundle_root);

  const parts = expected.signature_jws.split(".");
  assert.equal(parts.length, 3);
  const header = JSON.parse(decodeBase64Url(parts[0]).toString("utf8"));
  assert.equal(header.alg, "EdDSA");
  assert.equal(header.kid, expected.signing_kid);
  const payload = decodeBase64Url(parts[1]).toString("utf8");
  assert.equal(payload, expected.bundle_root);

  const signatureBytes = decodeBase64Url(parts[2]);
  const rawPublic = extractProofLayerPublicKeyRaw(verifyPem);
  const publicKey = createPublicKey({
    key: ed25519SpkiFromRaw(rawPublic),
    format: "der",
    type: "spki"
  });
  const verified = verifySignature(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"),
    publicKey,
    signatureBytes
  );
  assert.equal(verified, true);
});

test("RFC 8785 vectors canonicalize as expected", async () => {
  const fixture = JSON.parse(await readFile(rfcVectorPath, "utf8"));
  for (const vector of fixture.vectors) {
    const parsed = JSON.parse(vector.raw_json);
    const canonical = canonicalize(parsed);
    assert.equal(canonical, vector.canonical_json, vector.name);
  }
});
