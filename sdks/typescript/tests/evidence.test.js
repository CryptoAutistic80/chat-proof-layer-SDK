import test from "node:test";
import assert from "node:assert/strict";
import {
  createAdversarialTestRequest,
  createAuthoritySubmissionRequest,
  createConformityAssessmentRequest,
  createComputeMetricsRequest,
  createDataGovernanceRequest,
  createDeclarationRequest,
  createHumanOversightRequest,
  createIncidentReportRequest,
  createInstructionsForUseRequest,
  createLiteracyAttestationRequest,
  createLlmInteractionRequest,
  createModelEvaluationRequest,
  createPolicyDecisionRequest,
  createRegistrationRequest,
  createRetrievalRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest,
  createTrainingProvenanceRequest,
  createToolCallRequest
} from "../dist/index.js";

function decodeJsonArtefact(artefact) {
  return JSON.parse(Buffer.from(artefact.data).toString("utf8"));
}

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
    trace: { usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } },
    executionStart: "2026-03-10T09:00:00Z",
    executionEnd: "2026-03-10T09:00:01Z"
  });

  assert.equal(request.capture.actor.role, "deployer");
  assert.equal(request.capture.subject.system_id, "system-123");
  assert.equal(request.capture.context.provider, "openai");
  assert.equal(request.capture.items[0].type, "llm_interaction");
  assert.equal(request.capture.items[0].data.execution_start, "2026-03-10T09:00:00Z");
  assert.equal(request.capture.items[0].data.execution_end, "2026-03-10T09:00:01Z");
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
    retentionClass: "provider_documentation_days",
    likelihood: "medium",
    residualRiskLevel: "low",
    vulnerableGroupsConsidered: true
  });

  assert.equal(request.capture.subject.system_id, "system-risk-1");
  assert.equal(request.capture.items[0].type, "risk_assessment");
  assert.equal(request.capture.items[0].data.likelihood, "medium");
  assert.equal(request.capture.items[0].data.residual_risk_level, "low");
  assert.equal(request.capture.items[0].data.vulnerable_groups_considered, true);
  assert.equal(request.capture.policy.retention_class, "provider_documentation_days");
  assert.equal(request.artefacts[0].name, "risk_assessment.json");
  assert.deepEqual(decodeJsonArtefact(request.artefacts[0]), {
    risk_id: "risk-123",
    severity: "high",
    status: "open",
    summary: "hallucination path under review",
    risk_description: null,
    likelihood: "medium",
    affected_groups: [],
    mitigation_measures: [],
    residual_risk_level: "low",
    risk_owner: null,
    vulnerable_groups_considered: true,
    test_results_summary: null,
    metadata: { owner: "risk-team" },
    record: { controls: ["approval", "monitoring"] }
  });
});

test("createDataGovernanceRequest emits governance evidence with dataset ref", () => {
  const request = createDataGovernanceRequest({
    keyId: "kid-dev-01",
    systemId: "system-data-1",
    decision: "approved_with_restrictions",
    datasetRef: "dataset://curated/training-v2",
    metadata: { reviewer: "privacy" },
    datasetName: "curated-training",
    personalDataCategories: ["support_tickets"]
  });

  assert.equal(request.capture.items[0].type, "data_governance");
  assert.equal(request.capture.items[0].data.dataset_ref, "dataset://curated/training-v2");
  assert.equal(request.capture.items[0].data.dataset_name, "curated-training");
  assert.deepEqual(request.capture.items[0].data.personal_data_categories, ["support_tickets"]);
  assert.equal(request.artefacts[0].name, "data_governance.json");
  assert.deepEqual(decodeJsonArtefact(request.artefacts[0]), {
    decision: "approved_with_restrictions",
    dataset_ref: "dataset://curated/training-v2",
    dataset_name: "curated-training",
    dataset_version: null,
    source_description: null,
    collection_period: null,
    geographical_scope: [],
    preprocessing_operations: [],
    bias_detection_methodology: null,
    bias_metrics: [],
    mitigation_actions: [],
    data_gaps: [],
    personal_data_categories: ["support_tickets"],
    safeguards: [],
    metadata: { reviewer: "privacy" },
    record: null
  });
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

test("createTechnicalDocRequest emits descriptive JSON artefact when no binary document is supplied", () => {
  const request = createTechnicalDocRequest({
    keyId: "kid-dev-01",
    systemId: "system-doc-2",
    documentRef: "annex-iv/system-card",
    annexIvSections: ["section_2", "section_3"],
    systemDescriptionSummary: "Ranks candidates for recruiter review.",
    modelDescriptionSummary: "Fine-tuned ranking model.",
    capabilitiesAndLimitations: "Advisory only for first-pass screening.",
    designChoicesSummary: "Human review is required before employment decisions.",
    evaluationMetricsSummary: "Precision and subgroup parity are reviewed monthly.",
    humanOversightDesignSummary: "Recruiters must review every adverse or borderline case.",
    postMarketMonitoringPlanRef: "pmm://hiring-assistant/2026.03"
  });

  assert.equal(request.artefacts[0].name, "technical_doc.json");
  assert.deepEqual(decodeJsonArtefact(request.artefacts[0]), {
    document_ref: "annex-iv/system-card",
    section: null,
    descriptor: null,
    annex_iv_sections: ["section_2", "section_3"],
    system_description_summary: "Ranks candidates for recruiter review.",
    model_description_summary: "Fine-tuned ranking model.",
    capabilities_and_limitations: "Advisory only for first-pass screening.",
    design_choices_summary: "Human review is required before employment decisions.",
    evaluation_metrics_summary: "Precision and subgroup parity are reviewed monthly.",
    human_oversight_design_summary:
      "Recruiters must review every adverse or borderline case.",
    post_market_monitoring_plan_ref: "pmm://hiring-assistant/2026.03",
    simplified_tech_doc: null
  });
});

test("createInstructionsForUseRequest emits the recommended governance artefact shape", () => {
  const request = createInstructionsForUseRequest({
    keyId: "kid-dev-01",
    systemId: "system-ifu-1",
    documentRef: "docs://ifu/hiring-assistant",
    versionTag: "2026.03",
    providerIdentity: "Proof Layer Hiring Systems Ltd.",
    intendedPurpose: "Recruiter support for first-pass candidate review",
    systemCapabilities: ["candidate_summary", "borderline_case_flagging"],
    accuracyMetrics: [{ name: "review_precision", value: "0.91", unit: "ratio" }],
    foreseeableRisks: ["automation bias"],
    humanOversightGuidance: ["Review all adverse outputs before decisions."],
    logManagementGuidance: ["Retain logs for post-market monitoring."],
    metadata: { owner: "product-compliance" }
  });

  assert.equal(request.capture.items[0].type, "instructions_for_use");
  assert.equal(request.artefacts[0].name, "instructions_for_use.json");
  assert.deepEqual(decodeJsonArtefact(request.artefacts[0]), {
    document_ref: "docs://ifu/hiring-assistant",
    version: "2026.03",
    section: null,
    provider_identity: "Proof Layer Hiring Systems Ltd.",
    intended_purpose: "Recruiter support for first-pass candidate review",
    system_capabilities: ["candidate_summary", "borderline_case_flagging"],
    accuracy_metrics: [{ name: "review_precision", value: "0.91", unit: "ratio" }],
    foreseeable_risks: ["automation bias"],
    explainability_capabilities: [],
    human_oversight_guidance: ["Review all adverse outputs before decisions."],
    compute_requirements: [],
    service_lifetime: null,
    log_management_guidance: ["Retain logs for post-market monitoring."],
    metadata: { owner: "product-compliance" }
  });
});

test("createToolCallRequest hashes input/output and emits default artefacts", () => {
  const request = createToolCallRequest({
    keyId: "kid-dev-01",
    systemId: "system-tool-1",
    toolName: "search_database",
    input: { query: "hello" },
    output: { hits: 3 },
    metadata: { latency_ms: 18 },
    executionStart: "2026-03-10T10:00:00Z",
    executionEnd: "2026-03-10T10:00:02Z"
  });

  assert.equal(request.capture.items[0].type, "tool_call");
  assert.ok(request.capture.items[0].data.input_commitment.startsWith("sha256:"));
  assert.ok(request.capture.items[0].data.output_commitment.startsWith("sha256:"));
  assert.equal(request.capture.items[0].data.execution_start, "2026-03-10T10:00:00Z");
  assert.equal(request.capture.items[0].data.execution_end, "2026-03-10T10:00:02Z");
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
    metadata: { top_k: 3 },
    databaseReference: "pg://rag/chunk_store",
    executionStart: "2026-03-10T11:00:00Z",
    executionEnd: "2026-03-10T11:00:01Z"
  });

  assert.equal(request.capture.items[0].type, "retrieval");
  assert.equal(request.capture.items[0].data.database_reference, "pg://rag/chunk_store");
  assert.equal(request.capture.items[0].data.execution_start, "2026-03-10T11:00:00Z");
  assert.equal(request.capture.items[0].data.execution_end, "2026-03-10T11:00:01Z");
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
    notes: "Reviewed against internal policy",
    actorRole: "human_reviewer",
    stopTriggered: true,
    stopReason: "manual kill switch"
  });

  assert.equal(request.capture.items[0].type, "human_oversight");
  assert.equal(request.capture.items[0].data.actor_role, "human_reviewer");
  assert.equal(request.capture.items[0].data.stop_triggered, true);
  assert.equal(request.capture.items[0].data.stop_reason, "manual kill switch");
  assert.ok(request.capture.items[0].data.notes_commitment.startsWith("sha256:"));
  assert.deepEqual(decodeJsonArtefact(request.artefacts[0]), {
    action: "approved_after_review",
    reviewer: "ops-lead",
    actor_role: "human_reviewer",
    anomaly_detected: null,
    override_action: null,
    interpretation_guidance_followed: null,
    automation_bias_detected: null,
    two_person_verification: null,
    stop_triggered: true,
    stop_reason: "manual kill switch"
  });
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
    retentionClass: "risk_mgmt",
    detectionMethod: "post_market_monitoring",
    rootCauseSummary: "policy threshold misconfiguration"
  });

  assert.equal(request.capture.items[0].type, "incident_report");
  assert.equal(request.capture.items[0].data.occurred_at, "2026-03-06T10:15:00Z");
  assert.equal(request.capture.items[0].data.detection_method, "post_market_monitoring");
  assert.equal(
    request.capture.items[0].data.root_cause_summary,
    "policy threshold misconfiguration"
  );
  assert.ok(request.capture.items[0].data.report_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "incident_report.json");
  assert.equal(request.artefacts[1].name, "incident_report_record.txt");
});

test("createAuthoritySubmissionRequest emits authority-reporting evidence", () => {
  const request = createAuthoritySubmissionRequest({
    keyId: "kid-dev-01",
    systemId: "system-incident-2",
    submissionId: "sub-1",
    authority: "eu_ai_office",
    status: "submitted",
    channel: "portal",
    submittedAt: "2026-03-07T09:30:00Z",
    document: { case_id: "inc-1", article: "73" },
    metadata: { owner: "legal-ops" },
    retentionClass: "risk_mgmt"
  });

  assert.equal(request.capture.items[0].type, "authority_submission");
  assert.equal(request.capture.items[0].data.authority, "eu_ai_office");
  assert.ok(request.capture.items[0].data.document_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "authority_submission.json");
  assert.equal(request.artefacts[1].name, "authority_submission_document.json");
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
    metadata: { suite: "foundation-evals" },
    evaluationMethodology: "held-out benchmark suite",
    metricsSummary: [{ name: "accuracy", value: "0.84", unit: "ratio" }]
  });

  assert.equal(request.capture.items[0].type, "model_evaluation");
  assert.equal(request.capture.items[0].data.benchmark, "mmlu-pro");
  assert.equal(
    request.capture.items[0].data.evaluation_methodology,
    "held-out benchmark suite"
  );
  assert.deepEqual(request.capture.items[0].data.metrics_summary, [
    { name: "accuracy", value: "0.84", unit: "ratio" }
  ]);
  assert.equal(request.capture.policy.retention_class, "gpai_documentation");
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
    metadata: { suite: "red-team" },
    threatModel: "external red-team operator",
    affectedComponents: ["prompt-router"]
  });

  assert.equal(request.capture.items[0].type, "adversarial_test");
  assert.equal(request.capture.items[0].data.focus, "prompt-injection");
  assert.equal(request.capture.items[0].data.threat_model, "external red-team operator");
  assert.deepEqual(request.capture.items[0].data.affected_components, ["prompt-router"]);
  assert.equal(request.capture.policy.retention_class, "gpai_documentation");
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
    metadata: { source: "registry" },
    computeMetricsRef: "compute-2026-q1"
  });

  assert.equal(request.capture.items[0].type, "training_provenance");
  assert.equal(request.capture.items[0].data.stage, "pretraining");
  assert.equal(request.capture.items[0].data.compute_metrics_ref, "compute-2026-q1");
  assert.equal(request.capture.policy.retention_class, "gpai_documentation");
  assert.ok(request.capture.items[0].data.record_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "training_provenance.json");
  assert.equal(request.artefacts[1].name, "training_provenance_record.json");
});

test("createConformityAssessmentRequest emits conformity evidence", () => {
  const request = createConformityAssessmentRequest({
    keyId: "kid-dev-01",
    systemId: "system-conf-1",
    assessmentId: "ca-1",
    procedure: "annex_vii",
    status: "completed",
    report: { outcome: "pass" },
    metadata: { notified_body: "nb-1234" },
    assessmentBody: "NB-1234",
    retentionClass: "technical_doc"
  });

  assert.equal(request.capture.items[0].type, "conformity_assessment");
  assert.equal(request.capture.items[0].data.procedure, "annex_vii");
  assert.equal(request.capture.items[0].data.assessment_body, "NB-1234");
  assert.ok(request.capture.items[0].data.report_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "conformity_assessment.json");
  assert.equal(request.artefacts[1].name, "conformity_assessment_report.json");
});

test("createDeclarationRequest emits declaration evidence", () => {
  const request = createDeclarationRequest({
    keyId: "kid-dev-01",
    systemId: "system-conf-2",
    declarationId: "decl-1",
    jurisdiction: "eu",
    status: "issued",
    document: "eu declaration body",
    metadata: { annex: "v" },
    signatory: "Chief Compliance Officer",
    retentionClass: "technical_doc"
  });

  assert.equal(request.capture.items[0].type, "declaration");
  assert.equal(request.capture.items[0].data.jurisdiction, "eu");
  assert.equal(request.capture.items[0].data.signatory, "Chief Compliance Officer");
  assert.ok(request.capture.items[0].data.document_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "declaration.json");
  assert.equal(request.artefacts[1].name, "declaration_document.txt");
});

test("createRegistrationRequest emits registration evidence", () => {
  const request = createRegistrationRequest({
    keyId: "kid-dev-01",
    systemId: "system-conf-3",
    registrationId: "reg-1",
    authority: "eu_database",
    status: "accepted",
    receipt: { receipt_id: "rcpt-1" },
    metadata: { article: "49" },
    registrationNumber: "EU-REG-49-1",
    retentionClass: "technical_doc"
  });

  assert.equal(request.capture.items[0].type, "registration");
  assert.equal(request.capture.items[0].data.authority, "eu_database");
  assert.equal(request.capture.items[0].data.registration_number, "EU-REG-49-1");
  assert.ok(request.capture.items[0].data.receipt_commitment.startsWith("sha256:"));
  assert.equal(request.artefacts[0].name, "registration.json");
  assert.equal(request.artefacts[1].name, "registration_receipt.json");
});

test("createComputeMetricsRequest emits GPAI threshold evidence", () => {
  const request = createComputeMetricsRequest({
    keyId: "kid-dev-01",
    systemId: "system-gpai-4",
    computeId: "compute-2026-q1",
    trainingFlopsEstimate: "1.2e25",
    thresholdBasisRef: "art51",
    thresholdValue: "1e25",
    thresholdStatus: "above_threshold",
    measuredAt: "2026-03-10T12:00:00Z",
    computeResourcesSummary: [{ name: "gpu_hours", value: "42000", unit: "hours" }],
    metadata: { owner: "foundation-team" }
  });

  assert.equal(request.capture.items[0].type, "compute_metrics");
  assert.equal(request.capture.items[0].data.training_flops_estimate, "1.2e25");
  assert.equal(request.capture.items[0].data.threshold_status, "above_threshold");
  assert.deepEqual(request.capture.items[0].data.compute_resources_summary, [
    { name: "gpu_hours", value: "42000", unit: "hours" }
  ]);
  assert.equal(request.capture.policy.retention_class, "gpai_documentation");
  assert.equal(request.artefacts[0].name, "compute_metrics.json");
});
