import { describe, expect, test } from "vitest";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";
import { renderScenarioScript } from "./sdkScriptTemplates";

const draft = {
  serviceUrl: "http://127.0.0.1:8080",
  systemId: "chat-review",
  provider: "openai",
  model: "gpt-5-mini",
  userPrompt: "Summarize the case for a human reviewer.",
  intendedUse: "Chat review",
  prohibitedPracticeScreening: "screened_no_prohibited_use",
  riskTier: "limited_risk",
  highRiskDomain: "",
  gpaiStatus: "",
  systemicRisk: false,
  deploymentContext: "eu_use",
  friaRequired: false,
  owner: "ops",
  market: "eu"
};

describe("renderScenarioScript", () => {
  test("renders baseline chat-session-first TypeScript snippet", () => {
    const script = renderScenarioScript(getPlaygroundScenario("chat_baseline_completion"), draft);
    expect(script).toContain('const session = await proofLayer.capture');
    expect(script).toContain('transcript_hash');
    expect(script).toContain('session_signature');
  });

  test("renders tool-assisted TypeScript snippet", () => {
    const script = renderScenarioScript(getPlaygroundScenario("chat_tool_assisted_answer"), draft);
    expect(script).toContain('tool_name');
    expect(script).toContain('tool_result_ref');
  });

  test("renders Python snippet for retrieval and redacted sharing scenarios", () => {
    const ragScript = renderScenarioScript(getPlaygroundScenario("chat_retrieval_augmented_answer"), draft);
    const shareScript = renderScenarioScript(getPlaygroundScenario("chat_redacted_sharing"), draft);
    expect(ragScript).toContain("from proof_layer import ProofLayer");
    expect(ragScript).toContain('retrieval_index');
    expect(shareScript).toContain('redaction_profile');
  });
});
