import { describe, expect, test } from "vitest";
import {
  applyScenarioToDraft,
  firstScenarioForLane,
  getPlaygroundScenario,
  inferPackTypeFromItems,
  listScenariosForLane
} from "./sdkPlaygroundScenarios";

describe("sdkPlaygroundScenarios", () => {
  test("returns the baseline chatbot scenario first", () => {
    expect(firstScenarioForLane().id).toBe("chat_baseline_completion");
    expect(listScenariosForLane()).toHaveLength(4);
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
    const scenario = getPlaygroundScenario("chat_redacted_sharing");
    const nextDraft = applyScenarioToDraft(draft, scenario);

    expect(nextDraft.serviceUrl).toBe("http://vault.example.test");
    expect(nextDraft.apiKey).toBe("secret");
    expect(nextDraft.providerApiKey).toBe("provider-secret");
    expect(nextDraft.systemId).toBe("chat-assistant-share");
    expect(nextDraft.templateProfile).toBe("runtime_minimum");
    expect(nextDraft.playgroundHydrated).toBe(true);
  });

  test("infers chat interaction runs as no export pack", () => {
    const packType = inferPackTypeFromItems([{ type: "llm_interaction" }]);
    expect(packType).toBe(null);
  });
});
