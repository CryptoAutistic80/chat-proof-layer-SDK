import { describe, expect, test } from "vitest";
import {
  applyScenarioToDraft,
  firstScenarioForLane,
  getPlaygroundScenario
} from "./sdkPlaygroundScenarios";

describe("sdkPlaygroundScenarios", () => {
  test("returns the first scenario for each lane", () => {
    expect(firstScenarioForLane("typescript").id).toBe("ts_provider_governance");
    expect(firstScenarioForLane("python").id).toBe("py_fundamental_rights");
    expect(firstScenarioForLane("cli").id).toBe("cli_provider_governance");
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
    const scenario = getPlaygroundScenario("ts_provider_governance");
    const nextDraft = applyScenarioToDraft(draft, scenario);

    expect(nextDraft.serviceUrl).toBe("http://vault.example.test");
    expect(nextDraft.apiKey).toBe("secret");
    expect(nextDraft.providerApiKey).toBe("provider-secret");
    expect(nextDraft.systemId).toBe("hiring-assistant");
    expect(nextDraft.templateProfile).toBe("annex_iv_redacted");
    expect(nextDraft.playgroundHydrated).toBe(true);
  });
});
