import { describe, expect, test } from "vitest";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";
import { buildScenarioWorkflow } from "./sdkWorkflowBuilders";

const baseDraft = {
  serviceUrl: "http://127.0.0.1:8080",
  provider: "openai",
  model: "gpt-5-mini",
  temperature: "0.2",
  maxTokens: "256",
  systemId: "benefits-review",
  intendedUse: "Public-sector benefit eligibility review",
  prohibitedPracticeScreening: "screened_no_prohibited_use",
  riskTier: "high_risk",
  highRiskDomain: "employment",
  gpaiStatus: "provider",
  systemicRisk: true,
  deploymentContext: "public_sector",
  owner: "rights-review-team",
  market: "eu",
  datasetName: "support-assistant-ops-corpus",
  datasetVersion: "2026.03",
  sourceDescription: "Curated support tickets and QA-reviewed agent notes.",
  biasMethodology: "Monthly parity review.",
  safeguards: "pseudonymization, role-based access",
  qmsStatus: "approved",
  qmsApprover: "quality-lead",
  instructionsSummary: "Review all borderline cases.",
  instructionsSection: "human-review-required",
  humanOversightGuidance: "Escalate sensitive cases for human review.",
  datasetRef: "dataset://foundation-model-alpha/pretrain-v5",
  trainingDatasetSummary: "Multilingual curated web, code, and licensed reference corpora.",
  consortiumContext: "Single-provider training program",
  trainingFlopsEstimate: "1.2e25",
  thresholdStatus: "above_threshold",
  thresholdValue: "1e25",
  gpuHours: "42000",
  acceleratorCount: "2048",
  monitoringSummary: "Weekly review.",
  authority: "eu_ai_office",
  submissionSummary: "Initial submission.",
  friaRequired: true,
  friaSummary: "Human escalation required.",
  affectedRights: "equal treatment, explanation",
  assessor: "fundamental-rights-lead",
  reviewer: "rights-panel",
  overrideAction: "Candidate routed to manual review queue.",
  incidentSummary: "Potentially adverse recommendation surfaced.",
  rootCauseSummary: "Threshold too permissive for a narrow case segment.",
  correctiveActionRef: "ca-benefits-42",
  correctiveActionSummary: "Tighten the threshold and route similar cases to manual review.",
  notificationSummary: "Initial authority notification.",
  dueAt: "2026-03-09T12:00:00Z",
  correspondenceSubject: "Initial authority follow-up"
};

describe("buildScenarioWorkflow", () => {
  test("builds a multi-step TypeScript annex iv workflow", async () => {
    const scenario = getPlaygroundScenario("ts_support_rules");
    const providerResult = {
      capture_mode: "synthetic_demo_capture",
      provider: "openai",
      model: "gpt-5-mini",
      output_text: "Synthetic response",
      usage: { input_tokens: 12, output_tokens: 18, total_tokens: 30 },
      latency_ms: 120,
      prompt_payload: { prompt: "Summarize the case." },
      response_payload: { output_text: "Synthetic response" },
      trace_payload: { request_id: "req-test" }
    };

    const steps = await buildScenarioWorkflow(scenario, baseDraft, providerResult);

    expect(steps.map((step) => step.itemTypes[0])).toEqual([
      "technical_doc",
      "risk_assessment",
      "data_governance",
      "instructions_for_use",
      "human_oversight",
      "qms_record",
      "standards_alignment",
      "post_market_monitoring"
    ]);
    expect(steps[0].createPayload.capture.compliance_profile.risk_tier).toBe("high_risk");
    expect(steps[0].createPayload.capture.items[0].data.document_ref).toBe(
      "docs://benefits-review/annex-iv-system-card"
    );
    expect(steps[2].createPayload.capture.items[0].data.dataset_name).toBe(
      "support-assistant-ops-corpus"
    );
    expect(steps[6].createPayload.capture.items[0].data.standard_ref).toBe(
      "EN ISO/IEC 42001:2023"
    );
  });

  test("builds a governance-only incident-escalation workflow", async () => {
    const scenario = getPlaygroundScenario("py_incident_escalation");
    const steps = await buildScenarioWorkflow(scenario, baseDraft, null);

    expect(steps.map((step) => step.itemTypes[0])).toEqual([
      "technical_doc",
      "risk_assessment",
      "human_oversight",
      "policy_decision",
      "incident_report",
      "corrective_action",
      "authority_notification",
      "authority_submission",
      "reporting_deadline",
      "regulator_correspondence"
    ]);
    expect(steps[0].createPayload.capture.items[0].data.document_ref).toBe(
      "docs://benefits-review/incident-response-context"
    );
    expect(steps[3].createPayload.capture.items[0].data.policy_name).toBe(
      "incident_reportability_triage"
    );
    expect(steps[4].createPayload.capture.items[0].data.summary).toContain("Potentially adverse");
  });

  test("builds a GPAI threshold workflow with linked provenance and compute evidence", async () => {
    const scenario = getPlaygroundScenario("ts_gpai_thresholds");
    const steps = await buildScenarioWorkflow(scenario, baseDraft, null);

    expect(steps.map((step) => step.itemTypes[0])).toEqual([
      "training_provenance",
      "compute_metrics"
    ]);
    expect(steps[0].createPayload.capture.items[0].data.compute_metrics_ref).toBe(
      "compute-benefits-review-v1"
    );
    expect(steps[1].createPayload.capture.items[0].data.threshold_status).toBe("above_threshold");
  });
});
