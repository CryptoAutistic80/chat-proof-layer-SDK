import test from "node:test";
import assert from "node:assert/strict";
import {
  createAdversarialTestRequest,
  createDataGovernanceRequest,
  createHumanOversightRequest,
  createIncidentReportRequest,
  createLiteracyAttestationRequest,
  createLlmInteractionRequest,
  createModelEvaluationRequest,
  createPolicyDecisionRequest,
  createRetrievalRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest,
  createTrainingProvenanceRequest,
  createToolCallRequest
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

test("createToolCallRequest hashes input/output and emits default artefacts", () => {
  const request = createToolCallRequest({
    keyId: "kid-dev-01",
    systemId: "system-tool-1",
    toolName: "search_database",
    input: { query: "hello" },
    output: { hits: 3 },
    metadata: { latency_ms: 18 }
  });

  assert.equal(request.capture.items[0].type, "tool_call");
  assert.ok(request.capture.items[0].data.input_commitment.startsWith("sha256:"));
  assert.ok(request.capture.items[0].data.output_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "tool_call.json");
  assert.equal(request.artefacts[1].name, "tool_input.json");
  assert.equal(request.artefacts[2].name, "tool_output.json");
});

test("createRetrievalRequest hashes result/query and emits retrieval artefacts", () => {
  const request = createRetrievalRequest({
    keyId: "kid-dev-01",
    systemId: "system-rag-1",
    corpus: "knowledge-base",
    query: "refund policy",
    result: { docs: [{ id: "doc-1" }] },
    metadata: { top_k: 3 }
  });

  assert.equal(request.capture.items[0].type, "retrieval");
  assert.ok(request.capture.items[0].data.result_commitment.startsWith("sha256:"));
  assert.ok(request.capture.items[0].data.query_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[1].name, "retrieval_result.json");
});

test("createHumanOversightRequest hashes notes when provided", () => {
  const request = createHumanOversightRequest({
    keyId: "kid-dev-01",
    systemId: "system-oversight-1",
    action: "approved_after_review",
    reviewer: "ops-lead",
    notes: "Reviewed against internal policy"
  });

  assert.equal(request.capture.items[0].type, "human_oversight");
  assert.ok(request.capture.items[0].data.notes_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[1].name, "oversight_notes.txt");
});

test("createPolicyDecisionRequest hashes rationale when provided", () => {
  const request = createPolicyDecisionRequest({
    keyId: "kid-dev-01",
    systemId: "system-policy-1",
    policyName: "harm-filter",
    decision: "blocked",
    rationale: { score: 0.98 },
    metadata: { rule: "violence" }
  });

  assert.equal(request.capture.items[0].type, "policy_decision");
  assert.ok(request.capture.items[0].data.rationale_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[1].name, "policy_rationale.json");
});

test("createLiteracyAttestationRequest emits art4 evidence with optional commitment", () => {
  const request = createLiteracyAttestationRequest({
    keyId: "kid-dev-01",
    systemId: "system-literacy-1",
    attestedRole: "reviewer",
    status: "completed",
    trainingRef: "course://ai-literacy/v1",
    attestation: { completion_id: "att-1" },
    metadata: { source: "lms" },
    retentionClass: "ai_literacy"
  });

  assert.equal(request.capture.items[0].type, "literacy_attestation");
  assert.equal(request.capture.items[0].data.training_ref, "course://ai-literacy/v1");
  assert.ok(request.capture.items[0].data.attestation_commitment.startsWith("sha256:"));
  assert.equal(request.capture.policy.retention_class, "ai_literacy");
  assert.equal(request.artefacts[0].name, "literacy_attestation.json");
  assert.equal(request.artefacts[1].name, "literacy_attestation_record.json");
});

test("createIncidentReportRequest emits incident evidence with report commitment", () => {
  const request = createIncidentReportRequest({
    keyId: "kid-dev-01",
    systemId: "system-incident-1",
    incidentId: "inc-1",
    severity: "serious",
    status: "open",
    occurredAt: "2026-03-06T10:15:00Z",
    summary: "unsafe escalation path",
    report: "timeline and corrective actions",
    metadata: { source: "runtime-monitor" },
    retentionClass: "risk_mgmt"
  });

  assert.equal(request.capture.items[0].type, "incident_report");
  assert.equal(request.capture.items[0].data.occurred_at, "2026-03-06T10:15:00Z");
  assert.ok(request.capture.items[0].data.report_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "incident_report.json");
  assert.equal(request.artefacts[1].name, "incident_report_record.txt");
});

test("createModelEvaluationRequest emits GPAI evaluation evidence", () => {
  const request = createModelEvaluationRequest({
    keyId: "kid-dev-01",
    systemId: "system-gpai-1",
    evaluationId: "eval-1",
    benchmark: "mmlu-pro",
    status: "completed",
    summary: "baseline complete",
    report: { score: "0.84" },
    metadata: { suite: "foundation-evals" }
  });

  assert.equal(request.capture.items[0].type, "model_evaluation");
  assert.equal(request.capture.items[0].data.benchmark, "mmlu-pro");
  assert.ok(request.capture.items[0].data.report_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "model_evaluation.json");
  assert.equal(request.artefacts[1].name, "model_evaluation_report.json");
});

test("createAdversarialTestRequest emits systemic-risk evidence", () => {
  const request = createAdversarialTestRequest({
    keyId: "kid-dev-01",
    systemId: "system-gpai-2",
    testId: "adv-1",
    focus: "prompt-injection",
    status: "open",
    findingSeverity: "high",
    report: "exploit transcript",
    metadata: { suite: "red-team" }
  });

  assert.equal(request.capture.items[0].type, "adversarial_test");
  assert.equal(request.capture.items[0].data.focus, "prompt-injection");
  assert.ok(request.capture.items[0].data.report_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "adversarial_test.json");
  assert.equal(request.artefacts[1].name, "adversarial_test_report.txt");
});

test("createTrainingProvenanceRequest emits provenance evidence", () => {
  const request = createTrainingProvenanceRequest({
    keyId: "kid-dev-01",
    systemId: "system-gpai-3",
    datasetRef: "dataset://foundation/pretrain-v3",
    stage: "pretraining",
    lineageRef: "lineage://snapshot/2026-03-01",
    record: { manifests: 12 },
    metadata: { source: "registry" }
  });

  assert.equal(request.capture.items[0].type, "training_provenance");
  assert.equal(request.capture.items[0].data.stage, "pretraining");
  assert.ok(request.capture.items[0].data.record_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "training_provenance.json");
  assert.equal(request.artefacts[1].name, "training_provenance_record.json");
});
