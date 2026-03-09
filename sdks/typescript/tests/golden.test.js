import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalizeJson,
  computeMerkleRoot,
  hashSha256,
  verifyBundleRoot
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");
const fixedBundleDir = path.join(goldenDir, "fixed_bundle");
const rfcVectorPath = path.join(goldenDir, "rfc8785_vectors.json");

function escapeJsonPointerSegment(segment) {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

function collectPathCommitments(pathValue, value, containerKinds, pathDigests) {
  if (Array.isArray(value)) {
    containerKinds[pathValue] = "array";
    value.forEach((entry, index) => {
      collectPathCommitments(`${pathValue}/${index}`, entry, containerKinds, pathDigests);
    });
    return;
  }

  if (value && typeof value === "object") {
    containerKinds[pathValue] = "object";
    for (const [key, entry] of Object.entries(value)) {
      collectPathCommitments(
        `${pathValue}/${escapeJsonPointerSegment(key)}`,
        entry,
        containerKinds,
        pathDigests
      );
    }
    return;
  }

  pathDigests[pathValue] = hashSha256(canonicalizeJson(JSON.stringify(value)));
}

function itemCommitmentDigest(item, algorithm) {
  if (algorithm === "pl-merkle-sha256-v4") {
    const containerKinds = { "": "object" };
    const pathDigests = {};
    for (const [field, value] of Object.entries(item.data)) {
      collectPathCommitments(`/${escapeJsonPointerSegment(field)}`, value, containerKinds, pathDigests);
    }
    return hashSha256(
      canonicalizeJson({
        item_type: item.type,
        container_kinds: containerKinds,
        path_digests: pathDigests
      })
    );
  }

  if (algorithm === "pl-merkle-sha256-v3") {
    const fieldDigests = Object.fromEntries(
      Object.entries(item.data).map(([field, value]) => [
        field,
        hashSha256(canonicalizeJson(JSON.stringify(value)))
      ])
    );
    return hashSha256(
      canonicalizeJson({
        item_type: item.type,
        field_digests: fieldDigests
      })
    );
  }

  return hashSha256(canonicalizeJson(item));
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
  assert.equal(bundle.integrity.bundle_root_algorithm, expected.bundle_root_algorithm);
  assert.equal(bundle.integrity.signature.kid, expected.signing_kid);
  assert.equal(bundle.integrity.signature.value, expected.signature_jws);
  assert.equal(signatureFixture, expected.signature_jws);

  const projection = {
    bundle_version: bundle.bundle_version,
    bundle_id: bundle.bundle_id,
    created_at: bundle.created_at,
    actor: bundle.actor,
    subject: bundle.subject,
    context: bundle.context,
    policy: bundle.policy,
    item_count: bundle.items.length,
    artefact_count: bundle.artefacts.length
  };
  const canonical = canonicalizeJson(projection);
  assert.deepEqual(canonical, canonicalFixture);
  assert.equal(hashSha256(canonical), expected.header_digest);

  for (const artefact of bundle.artefacts) {
    const bytes = await readFile(path.join(fixedBundleDir, "artefacts", artefact.name));
    assert.equal(hashSha256(bytes), artefact.digest);
    assert.equal(hashSha256(bytes), expected.artefact_digests[artefact.name]);
    assert.equal(bytes.length, artefact.size);
  }

  for (const [name, entry] of Object.entries(expected.manifest_entries)) {
    const bytes = await readFile(path.join(fixedBundleDir, name));
    assert.equal(hashSha256(bytes), entry.digest);
    assert.equal(bytes.length, entry.size);
  }

  const orderedDigests = [
    expected.header_digest,
    ...bundle.items.map((item) => itemCommitmentDigest(item, bundle.integrity.bundle_root_algorithm)),
    ...bundle.artefacts.map((artefact) => hashSha256(canonicalizeJson(artefact)))
  ];
  const rootOne = computeMerkleRoot(orderedDigests);
  const rootTwo = computeMerkleRoot(orderedDigests);
  assert.equal(rootOne, rootTwo);
  assert.equal(rootOne, expected.bundle_root);

  assert.equal(verifyBundleRoot(expected.signature_jws, expected.bundle_root, verifyPem), true);
});

test("RFC 8785 vectors canonicalize as expected", async () => {
  const fixture = JSON.parse(await readFile(rfcVectorPath, "utf8"));
  for (const vector of fixture.vectors) {
    const canonical = canonicalizeJson(vector.raw_json).toString("utf8");
    assert.equal(canonical, vector.canonical_json, vector.name);
  }
});
