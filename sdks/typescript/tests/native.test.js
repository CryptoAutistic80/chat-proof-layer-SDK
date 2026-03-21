import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildBundle,
  evaluateCompleteness,
  hashSha256,
  redactBundle,
  signBundleRoot,
  verifyBundle,
  verifyRedactedBundle,
  verifyBundleRoot,
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");
const annexIvDir = path.join(goldenDir, "annex_iv_governance");
const gpaiDir = path.join(goldenDir, "gpai_provider");

test("native sign and verify round-trip uses Rust core logic", async () => {
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const publicKeyPem = await readFile(
    path.join(goldenDir, "verify_key.txt"),
    "utf8",
  );
  const bundleRoot = hashSha256("native-node-roundtrip");
  const jws = signBundleRoot(bundleRoot, signingKeyPem, "kid-dev-01");

  assert.equal(typeof jws, "string");
  assert.equal(verifyBundleRoot(jws, bundleRoot, publicKeyPem), true);
});

test("native verifyBundle performs offline verification against the golden fixture", async () => {
  const bundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );
  const publicKeyPem = await readFile(
    path.join(goldenDir, "verify_key.txt"),
    "utf8",
  );
  const artefacts = await Promise.all(
    bundle.artefacts.map(async (artefact) => ({
      name: artefact.name,
      data: await readFile(
        path.join(goldenDir, "fixed_bundle", "artefacts", artefact.name),
      ),
    })),
  );

  const summary = verifyBundle({ bundle, artefacts, publicKeyPem });
  assert.deepEqual(summary, { artefact_count: artefacts.length });
});

test("native buildBundle reproduces the deterministic golden bundle", async () => {
  const capture = JSON.parse(
    await readFile(path.join(goldenDir, "capture.json"), "utf8"),
  );
  const expectedBundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );
  const signingKeyPem = await readFile(
    path.join(goldenDir, "signing_key.txt"),
    "utf8",
  );
  const artefacts = [
    {
      name: "prompt.json",
      contentType: "application/json",
      data: await readFile(path.join(goldenDir, "prompt.json")),
    },
    {
      name: "response.json",
      contentType: "application/json",
      data: await readFile(path.join(goldenDir, "response.json")),
    },
  ];

  const bundle = buildBundle({
    capture,
    artefacts,
    keyPem: signingKeyPem,
    kid: "kid-dev-01",
    bundleId: expectedBundle.bundle_id,
    createdAt: expectedBundle.created_at,
  });

  assert.deepEqual(bundle, expectedBundle);
});

test("native redactBundle and verifyRedactedBundle round-trip a disclosed item", async () => {
  const bundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );
  const publicKeyPem = await readFile(
    path.join(goldenDir, "verify_key.txt"),
    "utf8",
  );

  const redacted = redactBundle({
    bundle,
    itemIndices: [0],
  });
  const summary = verifyRedactedBundle({
    bundle: redacted,
    artefacts: [],
    publicKeyPem,
  });

  assert.equal(redacted.disclosed_items.length, 1);
  assert.equal(redacted.disclosed_artefacts.length, 0);
  assert.deepEqual(summary, {
    disclosed_item_count: 1,
    disclosed_artefact_count: 0,
  });
});

test("native redactBundle supports field-level redaction for v3 bundles", async () => {
  const bundle = JSON.parse(
    await readFile(
      path.join(goldenDir, "fixed_bundle", "proof_bundle.json"),
      "utf8",
    ),
  );

  const redacted = redactBundle({
    bundle,
    itemIndices: [0],
    fieldRedactions: { 0: ["output_commitment"] },
  });

  assert.equal(redacted.disclosed_items[0].item, undefined);
  assert.deepEqual(
    redacted.disclosed_items[0].field_redacted_item?.redacted_paths,
    ["/output_commitment"],
  );
});

test("native evaluateCompleteness uses Rust core logic", async () => {
  const [
    riskAssessment,
    dataGovernance,
    technicalDoc,
    instructionsForUse,
    humanOversight,
  ] = await Promise.all([
    readFile(path.join(annexIvDir, "risk_assessment.json"), "utf8"),
    readFile(path.join(annexIvDir, "data_governance.json"), "utf8"),
    readFile(path.join(annexIvDir, "technical_doc.json"), "utf8"),
    readFile(path.join(annexIvDir, "instructions_for_use.json"), "utf8"),
    readFile(path.join(annexIvDir, "human_oversight.json"), "utf8"),
  ]);

  const report = evaluateCompleteness({
    profile: "annex_iv_governance_v1",
    bundle: {
      bundle_version: "1.0",
      bundle_id: "B-annex-iv",
      created_at: "2026-03-21T00:00:00Z",
      actor: {
        issuer: "proof-layer-test",
        app_id: "native-tests",
        env: "test",
        signing_key_id: "kid-dev-01",
        role: "provider",
      },
      subject: { system_id: "hiring-assistant" },
      context: {},
      items: [
        { type: "technical_doc", data: JSON.parse(technicalDoc) },
        { type: "risk_assessment", data: JSON.parse(riskAssessment) },
        { type: "data_governance", data: JSON.parse(dataGovernance) },
        { type: "instructions_for_use", data: JSON.parse(instructionsForUse) },
        { type: "human_oversight", data: JSON.parse(humanOversight) },
      ],
      artefacts: [],
      policy: { redactions: [], encryption: { enabled: false } },
      integrity: {
        canonicalization: "RFC8785-JCS",
        hash: "SHA-256",
        header_digest:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        bundle_root_algorithm: "pl-merkle-sha256-v4",
        bundle_root:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        signature: {
          format: "JWS",
          alg: "EdDSA",
          kid: "kid-dev-01",
          value: "sig",
        },
      },
    },
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 5);
});

test("native evaluateCompleteness supports gpai_provider_v1", async () => {
  const [
    technicalDoc,
    modelEvaluation,
    trainingProvenance,
    computeMetrics,
    copyrightPolicy,
    trainingSummary,
  ] = await Promise.all([
    readFile(path.join(gpaiDir, "technical_doc.json"), "utf8"),
    readFile(path.join(gpaiDir, "model_evaluation.json"), "utf8"),
    readFile(path.join(gpaiDir, "training_provenance.json"), "utf8"),
    readFile(path.join(gpaiDir, "compute_metrics.json"), "utf8"),
    readFile(path.join(gpaiDir, "copyright_policy.json"), "utf8"),
    readFile(path.join(gpaiDir, "training_summary.json"), "utf8"),
  ]);

  const report = evaluateCompleteness({
    profile: "gpai_provider_v1",
    bundle: {
      bundle_version: "1.0",
      bundle_id: "B-gpai-provider",
      created_at: "2026-03-21T00:00:00Z",
      actor: {
        issuer: "proof-layer-test",
        app_id: "native-tests",
        env: "test",
        signing_key_id: "kid-dev-01",
        role: "provider",
      },
      subject: { system_id: "foundation-model-alpha" },
      context: {},
      items: [
        { type: "technical_doc", data: JSON.parse(technicalDoc) },
        { type: "model_evaluation", data: JSON.parse(modelEvaluation) },
        { type: "training_provenance", data: JSON.parse(trainingProvenance) },
        { type: "compute_metrics", data: JSON.parse(computeMetrics) },
        { type: "copyright_policy", data: JSON.parse(copyrightPolicy) },
        { type: "training_summary", data: JSON.parse(trainingSummary) },
      ],
      artefacts: [],
      policy: { redactions: [], encryption: { enabled: false } },
      integrity: {
        canonicalization: "RFC8785-JCS",
        hash: "SHA-256",
        header_digest:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        bundle_root_algorithm: "pl-merkle-sha256-v4",
        bundle_root:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        signature: {
          format: "JWS",
          alg: "EdDSA",
          kid: "kid-dev-01",
          value: "sig",
        },
      },
    },
  });

  assert.equal(report.status, "pass");
  assert.equal(report.pass_count, 6);
});
