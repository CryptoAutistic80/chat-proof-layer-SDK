export const DEFAULT_SERVICE_URL = "http://127.0.0.1:8080";
export const DEFAULT_SYSTEM_ID = "investor-demo-system";

export const PROVIDER_MODELS = {
  anthropic: ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"],
  openai: ["gpt-5.2", "gpt-5-mini", "gpt-5-nano"]
};

export const PRESETS = [
  {
    key: "investor_summary",
    label: "Investor summary",
    description: "Show one sealed AI interaction, plain-English integrity checks, and a minimal disclosure export.",
    actorRole: "provider",
    packType: "runtime_logs",
    disclosureProfile: "regulator_minimum",
    bundleFormat: "disclosure",
    retentionClass: "runtime_logs",
    defaultMode: "synthetic",
    evidenceShape: ["llm_interaction"],
    systemPrompt: "You are a risk-aware operations copilot. Answer precisely, avoid hype, and stay within governance language suitable for investor diligence.",
    userPrompt: "Draft a short summary of what this proof vault can demonstrate to an investor."
  },
  {
    key: "deployer_runtime_log",
    label: "Deployer runtime log",
    description: "Capture one operational interaction and export a runtime-focused disclosure pack.",
    actorRole: "deployer",
    packType: "runtime_logs",
    disclosureProfile: "runtime_minimum",
    bundleFormat: "disclosure",
    retentionClass: "runtime_logs",
    defaultMode: "live_if_available",
    evidenceShape: ["llm_interaction"],
    systemPrompt: "You are an operations copilot reporting runtime state for a production AI service. Stay concrete and include metrics or anomalies where relevant.",
    userPrompt: "What is the current runtime status of this AI system? Report token usage, latency, and any operational anomalies from the latest run."
  },
  {
    key: "incident_review",
    label: "Incident review",
    description: "Capture an interaction, derive an incident wrapper, and preview an incident-focused disclosure policy.",
    actorRole: "integrator",
    packType: "incident_response",
    disclosureProfile: "incident_summary",
    bundleFormat: "disclosure",
    retentionClass: "risk_mgmt",
    defaultMode: "live_if_available",
    evidenceShape: ["llm_interaction", "incident_report"],
    systemPrompt: "You are a post-incident review assistant. Summarize anomalies, operational failures, and policy concerns without speculation.",
    userPrompt: "Summarise any anomalies or unexpected behaviours observed in the last AI interaction and flag any policy violations."
  },
  {
    key: "annex_iv_filing",
    label: "Annex IV filing",
    description: "Capture a technical summary and wrap it in documentation-oriented artefacts for Annex IV style review.",
    actorRole: "provider",
    packType: "annex_iv",
    disclosureProfile: "annex_iv_redacted",
    bundleFormat: "full",
    retentionClass: "technical_doc",
    defaultMode: "live_if_available",
    evidenceShape: ["llm_interaction", "technical_doc"],
    systemPrompt: "You are a technical documentation assistant preparing material for EU AI Act Annex IV style review. Stay precise, factual, and implementation-oriented.",
    userPrompt: "Provide a technical summary of this AI system's capabilities, intended purpose, and any known limitations for an EU AI Act Annex IV compliance filing."
  }
];

export function getPreset(presetKey) {
  return PRESETS.find((preset) => preset.key === presetKey) ?? PRESETS[0];
}

export function modelOptionsFor(provider) {
  return PROVIDER_MODELS[provider] ?? PROVIDER_MODELS.openai;
}

export function defaultModelFor(provider) {
  return modelOptionsFor(provider)[0];
}

export function defaultTemplateName(profile) {
  return `${profile}_web_demo`;
}

export function isProviderLiveEnabled(vaultConfig, provider) {
  return Boolean(vaultConfig?.demo?.providers?.[provider]?.live_enabled);
}

function hasTemporaryProviderKey(providerApiKey) {
  return Boolean(providerApiKey && providerApiKey.trim());
}

export function resolvePresetMode(preset, provider, vaultConfig, providerApiKey = "") {
  if (preset.defaultMode === "synthetic") {
    return "synthetic";
  }
  return isProviderLiveEnabled(vaultConfig, provider) || hasTemporaryProviderKey(providerApiKey)
    ? "live"
    : "synthetic";
}

export function applyPresetToDraft(currentDraft, preset, vaultConfig) {
  const nextMode = resolvePresetMode(
    preset,
    currentDraft.provider,
    vaultConfig,
    currentDraft.providerApiKey
  );
  return {
    ...currentDraft,
    presetKey: preset.key,
    actorRole: preset.actorRole,
    bundleFormat: preset.bundleFormat,
    templateProfile: preset.disclosureProfile,
    templateName: defaultTemplateName(preset.disclosureProfile),
    mode: nextMode,
    systemPrompt: preset.systemPrompt,
    userPrompt: preset.userPrompt
  };
}

export function listPresetOptions() {
  return PRESETS.map((preset) => ({
    key: preset.key,
    label: preset.label,
    description: preset.description
  }));
}
