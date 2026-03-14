import { describe, expect, test } from "vitest";
import {
  applyScenarioToDraft,
  firstScenarioForLane,
  getPlaygroundScenario
} from "./sdkPlaygroundScenarios";

describe("sdkPlaygroundScenarios", () => {
  test("returns the first scenario for each lane", () => {
    expect(firstScenarioForLane("typescript").id).toBe("ts_chatbot_support");
    expect(firstScenarioForLane("python").id).toBe("py_hiring_review");
    expect(firstScenarioForLane("cli").id).toBe("cli_chatbot_support");
  });

  test("applies scenario defaults without losing connection settings", () => {
    const draft = {
      serviceUrl: "http://vault.example.test",
      apiKey: "secret",
      providerApiKey: "provider-secret",
      attachTimestamp: true,
      attachTransparency: false,
      temperature: "0.4",
      maxTokens: "512"
    };
    const scenario = getPlaygroundScenario("ts_support_rules");
    const nextDraft = applyScenarioToDraft(draft, scenario);

    expect(nextDraft.serviceUrl).toBe("http://vault.example.test");
    expect(nextDraft.apiKey).toBe("secret");
    expect(nextDraft.providerApiKey).toBe("provider-secret");
    expect(nextDraft.systemId).toBe("support-assistant");
    expect(nextDraft.templateProfile).toBe("annex_iv_redacted");
    expect(nextDraft.playgroundHydrated).toBe(true);
  });
});
