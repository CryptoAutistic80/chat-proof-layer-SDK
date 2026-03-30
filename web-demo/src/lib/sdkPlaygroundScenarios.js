import { DEFAULT_SERVICE_URL, defaultModelFor } from "./presets";

export const PLAYGROUND_LANES = [
  {
    id: "chatbot",
    label: "Chat sessions",
    eyebrow: "Scenario set",
    description: "Capture and share verifiable chatbot conversations."
  }
];

const COMMON_CONNECTION_FIELDS = [
  { key: "serviceUrl", label: "Vault URL", type: "text", placeholder: DEFAULT_SERVICE_URL },
  { key: "apiKey", label: "Vault API key", type: "password", placeholder: "Optional bearer token" }
];

const CHAT_FIELDS = [
  {
    key: "provider",
    label: "Provider",
    type: "select",
    options: [
      { label: "OpenAI", value: "openai" },
      { label: "Anthropic", value: "anthropic" }
    ]
  },
  { key: "model", label: "Model", type: "text" },
  {
    key: "mode",
    label: "Capture mode",
    type: "select",
    options: [
      { label: "Synthetic sample", value: "synthetic" },
      { label: "Live provider", value: "live" }
    ]
  },
  {
    key: "providerApiKey",
    label: "Temporary provider API key",
    type: "password",
    visibleWhen: (draft) => draft.mode === "live",
    placeholder: "Only needed when live access is not already configured"
  },
  { key: "userPrompt", label: "User message", type: "textarea", rows: 5 },
  { key: "intendedUse", label: "Intended use", type: "textarea", rows: 3 },
  { key: "owner", label: "Owner", type: "text" }
];

function explainer(expectation, record, outsideTool) {
  return { expectation, record, outsideTool };
}

export const PLAYGROUND_SCENARIOS = [
  {
    id: "chat_baseline_completion",
    lane: "chatbot",
    label: "Baseline chat completion",
    category: "Chat session",
    description: "Capture one conversational turn and seal the resulting conversation proof.",
    audienceSummary: "A standard chatbot turn with no tools or retrieval context.",
    lawExplainer: explainer(
      "Teams should retain evidence that explains what happened in a meaningful AI conversation.",
      "This scenario records the user message, model response, model metadata, and proof metadata in one conversation proof.",
      "You still need production notices, policy controls, and escalation processes around your assistant."
    ),
    sourceRef: "playground/chat-baseline.ts",
    codeLanguage: "typescript",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "runtime_minimum",
    templateId: "chat_baseline_completion",
    primaryStepId: "interaction",
    recordExplorerIntro: "This conversation proof shows a baseline chatbot exchange and its transcript hash.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "chat-assistant",
      intendedUse: "General support chatbot",
      owner: "assistant-platform",
      userPrompt: "Help me reset my account password safely."
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...CHAT_FIELDS],
    steps: [{ id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }],
    missingEvidence: []
  },
  {
    id: "chat_tool_assisted_answer",
    lane: "chatbot",
    label: "Tool-assisted answer",
    category: "Chat session",
    description: "Capture a conversation where the assistant references a tool output.",
    audienceSummary: "A chatbot that combines model output with tool-backed reasoning.",
    lawExplainer: explainer(
      "When tools influence output, teams should preserve how the final answer was produced.",
      "This scenario stores a conversation proof that links the answer to a tool-assisted exchange.",
      "You still need tool governance, access control, and data-quality controls outside this demo."
    ),
    sourceRef: "playground/chat-tool-assisted.ts",
    codeLanguage: "typescript",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "runtime_minimum",
    templateId: "chat_tool_assisted_answer",
    primaryStepId: "interaction",
    recordExplorerIntro: "This conversation proof highlights a tool-assisted transcript and resulting session signature.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "chat-assistant-tools",
      intendedUse: "Chatbot with internal tool calls",
      owner: "assistant-platform",
      userPrompt: "What is the shipping status for order #10482?"
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...CHAT_FIELDS],
    steps: [{ id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }],
    missingEvidence: []
  },
  {
    id: "chat_retrieval_augmented_answer",
    lane: "chatbot",
    label: "Retrieval-augmented answer",
    category: "Chat session",
    description: "Capture a conversation grounded in retrieved context before response generation.",
    audienceSummary: "A RAG chatbot that cites policy or knowledge snippets during chat.",
    lawExplainer: explainer(
      "Grounded answers are easier to review when transcript and retrieval context stay linked.",
      "This scenario records a retrieval-augmented chat turn as a verifiable conversation proof.",
      "You still need source quality checks and retrieval index governance in production."
    ),
    sourceRef: "playground/chat-rag.py",
    codeLanguage: "python",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "runtime_minimum",
    templateId: "chat_retrieval_augmented_answer",
    primaryStepId: "interaction",
    recordExplorerIntro: "This conversation proof keeps the retrieval-grounded transcript hash available for review.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "anthropic",
      model: defaultModelFor("anthropic"),
      mode: "synthetic",
      systemId: "chat-assistant-rag",
      intendedUse: "Knowledge-grounded support chatbot",
      owner: "assistant-platform",
      userPrompt: "Summarize our refund policy for annual plans."
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...CHAT_FIELDS],
    steps: [{ id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }],
    missingEvidence: []
  },
  {
    id: "chat_redacted_sharing",
    lane: "chatbot",
    label: "Redacted sharing scenario",
    category: "Chat sharing",
    description: "Capture a chat session and prepare it with a redacted sharing profile.",
    audienceSummary: "Teams sharing chatbot evidence externally with minimized disclosure.",
    lawExplainer: explainer(
      "Sharing conversation evidence often requires data minimization and role-based disclosure.",
      "This scenario captures a conversation proof and applies a redacted sharing profile.",
      "You still need legal review and audience-specific sharing policies for real deployments."
    ),
    sourceRef: "playground/chat-redacted-share.py",
    codeLanguage: "python",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "disclosure",
    disclosureProfile: "runtime_minimum",
    templateId: "chat_redacted_sharing",
    primaryStepId: "interaction",
    recordExplorerIntro: "This conversation proof is prepared for redacted sharing with transcript hash and session signature checks.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "chat-assistant-share",
      intendedUse: "Externally shared chatbot conversation evidence",
      owner: "assistant-governance",
      userPrompt: "Draft a concise incident update for a customer."
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...CHAT_FIELDS],
    steps: [{ id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }],
    missingEvidence: []
  }
];

export function getPlaygroundScenario(id) {
  return PLAYGROUND_SCENARIOS.find((scenario) => scenario.id === id) ?? PLAYGROUND_SCENARIOS[0];
}

export function listScenariosForLane() {
  return PLAYGROUND_SCENARIOS;
}

export function firstScenarioForLane() {
  return PLAYGROUND_SCENARIOS[0];
}

export function initialPlaygroundScenario() {
  return PLAYGROUND_SCENARIOS[0];
}

export function applyScenarioToDraft(currentDraft, scenario) {
  return {
    ...currentDraft,
    lane: "chatbot",
    scenarioId: scenario.id,
    actorRole: scenario.actorRole,
    bundleFormat: scenario.bundleFormat,
    templateProfile: scenario.disclosureProfile,
    templateName: `${scenario.disclosureProfile}_web_demo`,
    selectedGroups: [],
    ...scenario.defaults,
    serviceUrl: currentDraft.serviceUrl,
    apiKey: currentDraft.apiKey,
    providerApiKey: currentDraft.providerApiKey,
    attachTimestamp: currentDraft.attachTimestamp,
    attachTransparency: currentDraft.attachTransparency,
    temperature: currentDraft.temperature,
    maxTokens: currentDraft.maxTokens,
    playgroundHydrated: true
  };
}

export function inferPackTypeFromItems(items = []) {
  const types = items.map((item) => item.type);
  if (types.includes("llm_interaction")) {
    return null;
  }
  return null;
}

export function findScenarioByPackType(_packType, items = []) {
  if (items.some((item) => item.type === "llm_interaction")) {
    return PLAYGROUND_SCENARIOS[0];
  }
  return PLAYGROUND_SCENARIOS[0];
}
