import { describe, expect, test } from "vitest";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";
import { renderScenarioScript } from "./sdkScriptTemplates";

const draft = {
  serviceUrl: "http://127.0.0.1:8080",
  provider: "openai",
  model: "gpt-5-mini",
  systemId: "benefits-review",
  intendedUse: "Public-sector benefit eligibility review",
  prohibitedPracticeScreening: "screened_no_prohibited_use",
  riskTier: "high_risk",
  highRiskDomain: "employment",
  gpaiStatus: "provider",
  systemicRisk: true,
  deploymentContext: "public_sector",
  friaRequired: true,
  owner: "rights-review-team",
  market: "eu",
  userPrompt: "Summarize the case for a human reviewer.",
  datasetName: "support-assistant-ops-corpus",
  datasetVersion: "2026.03",
  sourceDescription: "Curated support tickets and QA-reviewed agent notes.",
  biasMethodology: "Monthly parity review.",
  safeguards: "pseudonymization, role-based access",
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
  qmsStatus: "approved",
  qmsApprover: "quality-lead",
  monitoringSummary: "Weekly review.",
  authority: "eu_ai_office",
  submissionSummary: "Initial submission.",
  friaSummary: "Human escalation required.",
  affectedRights: "equal treatment, explanation",
  assessor: "fundamental-rights-lead",
  reviewer: "rights-panel",
  overrideAction: "Candidate routed to manual review queue.",
  incidentSummary: "Potentially adverse recommendation surfaced.",
  rootCauseSummary: "Threshold too permissive for a narrow case segment.",
  correctiveActionRef: "ca-benefits-42",
  notificationSummary: "Initial authority notification.",
  dueAt: "2026-03-09T12:00:00Z",
  correspondenceSubject: "Initial authority follow-up"
};

describe("renderScenarioScript", () => {
  test("renders a TypeScript annex iv workflow script with draft values", () => {
    const script = renderScenarioScript(getPlaygroundScenario("ts_support_rules"), draft);
    expect(script).toContain('new ProofLayer');
    expect(script).toContain('"benefits-review"');
    expect(script).toContain('captureTechnicalDoc');
    expect(script).toContain('captureRiskAssessment');
    expect(script).toContain('captureDataGovernance');
    expect(script).toContain('captureInstructionsForUse');
    expect(script).toContain('captureHumanOversight');
    expect(script).toContain('captureQmsRecord');
    expect(script).toContain('captureStandardsAlignment');
    expect(script).toContain('capturePostMarketMonitoring');
    expect(script).toContain('packType: "annex_iv"');
  });

  test("renders a GPAI provider script with the full Annex XI evidence set", () => {
    const script = renderScenarioScript(getPlaygroundScenario("ts_gpai_thresholds"), draft);
    expect(script).toContain('captureTechnicalDoc');
    expect(script).toContain('captureModelEvaluation');
    expect(script).toContain('captureTrainingProvenance');
    expect(script).toContain('captureComputeMetrics');
    expect(script).toContain('captureCopyrightPolicy');
    expect(script).toContain('captureTrainingSummary');
    expect(script).toContain('packType: "annex_xi"');
  });

  test("renders a CLI script with proofctl commands", () => {
    const script = renderScenarioScript(getPlaygroundScenario("cli_chatbot_support"), draft);
    expect(script).toContain("cargo run -p proofctl -- create");
    expect(script).toContain("cargo run -p proofctl -- verify");
    expect(script).toContain('"system_id": "benefits-review"');
  });
});
