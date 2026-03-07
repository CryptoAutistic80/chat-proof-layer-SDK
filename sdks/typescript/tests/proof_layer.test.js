import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ProofLayer } from "../dist/index.js";
import { withProofLayer } from "../dist/providers/openai.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../../..");
const goldenDir = path.join(repoRoot, "fixtures", "golden");

test("ProofLayer.capture seals a local llm_interaction bundle", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-123",
    issuer: "proof-layer-ts",
    appId: "typescript-sdk",
    env: "test"
  });

  const result = await proofLayer.capture({
    provider: "openai",
    model: "gpt-4o-mini",
    input: [{ role: "user", content: "hello" }],
    output: { role: "assistant", content: "hi" },
    requestId: "req-proof-layer-1"
  });

  assert.equal(result.bundle?.bundle_version, "1.0");
  assert.equal(result.bundle?.subject?.system_id, "system-123");
  assert.equal(result.bundle?.integrity.signature.kid, "kid-dev-01");
  assert.equal(typeof result.bundleRoot, "string");
});

test("withProofLayer attaches proof metadata to OpenAI-like responses", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01"
  });

  const wrapped = withProofLayer(
    {
      chat: {
        completions: {
          create: async (params) => ({
            id: "cmpl-typed-1",
            model: params.model,
            choices: [{ message: { role: "assistant", content: "ok" } }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }
          })
        }
      }
    },
    proofLayer,
    { requestId: "req-proof-layer-wrapper" }
  );

  const completion = await wrapped.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "hello" }]
  });

  assert.equal(completion.id, "cmpl-typed-1");
  assert.equal(completion.proofLayer.bundle?.bundle_version, "1.0");
  assert.equal(completion.proofLayer.signature.length > 10, true);
});

test("ProofLayer.captureRiskAssessment seals lifecycle evidence locally", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-risk-42"
  });

  const result = await proofLayer.captureRiskAssessment({
    riskId: "risk-42",
    severity: "medium",
    status: "mitigated",
    summary: "manual review added"
  });

  assert.equal(result.bundle?.items[0].type, "risk_assessment");
  assert.equal(result.bundle?.subject.system_id, "system-risk-42");
});

test("ProofLayer.captureTechnicalDoc seals inline document evidence locally", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-doc-42"
  });

  const result = await proofLayer.captureTechnicalDoc({
    documentRef: "annex-iv/system-card",
    section: "safety_controls",
    document: Buffer.from("annex-iv-body", "utf8"),
    documentName: "system-card.txt"
  });

  assert.equal(result.bundle?.items[0].type, "technical_doc");
  assert.equal(result.bundle?.subject.system_id, "system-doc-42");
  assert.ok(result.bundle?.items[0].data.commitment.startsWith("sha256:"));
});

test("ProofLayer.captureRetrieval seals retrieval evidence locally", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-rag-42"
  });

  const result = await proofLayer.captureRetrieval({
    corpus: "policy-kb",
    query: "refund policy",
    result: { docs: [{ id: "doc-1", score: 0.99 }] }
  });

  assert.equal(result.bundle?.items[0].type, "retrieval");
  assert.equal(result.bundle?.subject.system_id, "system-rag-42");
  assert.ok(result.bundle?.items[0].data.result_commitment.startsWith("sha256:"));
});

test("ProofLayer.capturePolicyDecision seals policy decision evidence locally", async () => {
  const signingKeyPem = await readFile(path.join(goldenDir, "signing_key.txt"), "utf8");
  const proofLayer = new ProofLayer({
    signingKeyPem,
    keyId: "kid-dev-01",
    systemId: "system-policy-42"
  });

  const result = await proofLayer.capturePolicyDecision({
    policyName: "harm-filter",
    decision: "blocked",
    rationale: { classifier_score: 0.98 }
  });

  assert.equal(result.bundle?.items[0].type, "policy_decision");
  assert.equal(result.bundle?.subject.system_id, "system-policy-42");
  assert.ok(result.bundle?.items[0].data.rationale_commitment.startsWith("sha256:"));
});
