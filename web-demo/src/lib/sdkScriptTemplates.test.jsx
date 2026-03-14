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
  deploymentContext: "public_sector",
  friaRequired: true,
  owner: "rights-review-team",
  market: "eu",
  userPrompt: "Summarize the case for a human reviewer.",
  instructionsSummary: "Review all borderline cases.",
  instructionsSection: "human-review-required",
  qmsStatus: "approved",
  qmsApprover: "quality-lead",
  monitoringSummary: "Weekly review.",
  authority: "eu_ai_office",
  submissionSummary: "Initial submission.",
  friaSummary: "Human escalation required.",
  reviewer: "rights-panel",
  incidentSummary: "Potentially adverse recommendation surfaced.",
  dueAt: "2026-03-09T12:00:00Z",
  correspondenceSubject: "Initial authority follow-up"
};

describe("renderScenarioScript", () => {
  test("renders a TypeScript provider-governance script with draft values", () => {
    const script = renderScenarioScript(getPlaygroundScenario("ts_provider_governance"), draft);
    expect(script).toContain('new ProofLayer');
    expect(script).toContain('"benefits-review"');
    expect(script).toContain('captureInstructionsForUse');
    expect(script).toContain('captureQmsRecord');
  });

  test("renders a CLI script with proofctl commands", () => {
    const script = renderScenarioScript(getPlaygroundScenario("cli_provider_governance"), draft);
    expect(script).toContain("cargo run -p proofctl -- create");
    expect(script).toContain("--type provider-governance");
    expect(script).toContain('"system_id": "benefits-review"');
  });
});
