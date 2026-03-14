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
  deploymentContext: "public_sector",
  owner: "rights-review-team",
  market: "eu",
  qmsStatus: "approved",
  qmsApprover: "quality-lead",
  instructionsSummary: "Review all borderline cases.",
  instructionsSection: "human-review-required",
  monitoringSummary: "Weekly review.",
  authority: "eu_ai_office",
  submissionSummary: "Initial submission.",
  friaRequired: true,
  friaSummary: "Human escalation required.",
  reviewer: "rights-panel",
  incidentSummary: "Potentially adverse recommendation surfaced.",
  dueAt: "2026-03-09T12:00:00Z",
  correspondenceSubject: "Initial authority follow-up"
};

describe("buildScenarioWorkflow", () => {
  test("builds a multi-step TypeScript support workflow", async () => {
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
      "llm_interaction",
      "instructions_for_use",
      "qms_record"
    ]);
    expect(steps[0].createPayload.capture.compliance_profile.risk_tier).toBe("high_risk");
  });

  test("builds a governance-only incident-escalation workflow", async () => {
    const scenario = getPlaygroundScenario("py_incident_escalation");
    const steps = await buildScenarioWorkflow(scenario, baseDraft, null);

    expect(steps.map((step) => step.itemTypes[0])).toEqual([
      "incident_report",
      "authority_notification",
      "reporting_deadline",
      "regulator_correspondence"
    ]);
    expect(steps[0].createPayload.capture.items[0].data.summary).toContain("Potentially adverse");
  });
});
