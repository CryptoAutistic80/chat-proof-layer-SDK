import test from "node:test";
import assert from "node:assert/strict";
import {
  createDataGovernanceRequest,
  createLlmInteractionRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest
} from "../dist/index.js";

test("createLlmInteractionRequest emits v1 llm_interaction capture shape", () => {
  const request = createLlmInteractionRequest({
    keyId: "kid-dev-01",
    role: "deployer",
    systemId: "system-123",
    provider: "openai",
    model: "gpt-4o-mini",
    input: [{ role: "user", content: "hello" }],
    output: { role: "assistant", content: "hi" },
    requestId: "req-1",
    modelParameters: { temperature: 0.2 },
    trace: { usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }
  });

  assert.equal(request.capture.actor.role, "deployer");
  assert.equal(request.capture.subject.system_id, "system-123");
  assert.equal(request.capture.context.provider, "openai");
  assert.equal(request.capture.items[0].type, "llm_interaction");
  assert.ok(request.capture.items[0].data.input_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "prompt.json");
  assert.equal(request.artefacts[1].name, "response.json");
});

test("createRiskAssessmentRequest emits lifecycle evidence with default artefact", () => {
  const request = createRiskAssessmentRequest({
    keyId: "kid-dev-01",
    systemId: "system-risk-1",
    riskId: "risk-123",
    severity: "high",
    status: "open",
    summary: "hallucination path under review",
    metadata: { owner: "risk-team" },
    record: { controls: ["approval", "monitoring"] },
    retentionClass: "provider_documentation_days"
  });

  assert.equal(request.capture.subject.system_id, "system-risk-1");
  assert.equal(request.capture.items[0].type, "risk_assessment");
  assert.equal(request.capture.policy.retention_class, "provider_documentation_days");
  assert.equal(request.artefacts[0].name, "risk_assessment.json");
});

test("createDataGovernanceRequest emits governance evidence with dataset ref", () => {
  const request = createDataGovernanceRequest({
    keyId: "kid-dev-01",
    systemId: "system-data-1",
    decision: "approved_with_restrictions",
    datasetRef: "dataset://curated/training-v2",
    metadata: { reviewer: "privacy" }
  });

  assert.equal(request.capture.items[0].type, "data_governance");
  assert.equal(request.capture.items[0].data.dataset_ref, "dataset://curated/training-v2");
  assert.equal(request.artefacts[0].name, "data_governance.json");
});

test("createTechnicalDocRequest hashes inline documents when commitment is omitted", () => {
  const request = createTechnicalDocRequest({
    keyId: "kid-dev-01",
    systemId: "system-doc-1",
    documentRef: "annex-iv/system-card",
    section: "risk_controls",
    document: Buffer.from("system-card-v1", "utf8"),
    documentName: "system-card.txt"
  });

  assert.equal(request.capture.items[0].type, "technical_doc");
  assert.ok(request.capture.items[0].data.commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "system-card.txt");
});
