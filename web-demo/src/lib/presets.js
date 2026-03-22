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
    businessReason: "Show an investor exactly what an AI system did and what evidence can be shared later without exposing everything.",
    audience: "business",
    outcomeLabel: "One AI proof record plus a minimal share package for diligence conversations.",
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
    businessReason: "Show what operational evidence exists for a production-style run and what a deployment team could later prove.",
    audience: "operator",
    outcomeLabel: "One operational proof record focused on runtime evidence and export readiness.",
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
    businessReason: "Show how an AI issue can be captured, reviewed, and turned into a controlled disclosure package for incident handling.",
    audience: "operator",
    outcomeLabel: "One proof-backed incident review with a derived incident wrapper and selective sharing preview.",
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
    label: "Annex IV governance pack",
    description:
      "Capture one interaction and derive the governance evidence needed for an Annex IV style provider pack preview.",
    businessReason:
      "Show how a high-risk provider workflow can turn one governed scenario into technical, risk, oversight, QMS, and monitoring evidence for regulator or conformity review.",
    audience: "compliance",
    outcomeLabel:
      "One governance-oriented proof record with derived Annex IV evidence suitable for provider-side review.",
    actorRole: "provider",
    packType: "annex_iv",
    disclosureProfile: "annex_iv_redacted",
    bundleFormat: "full",
    retentionClass: "technical_doc",
    defaultMode: "live_if_available",
    evidenceShape: [
      "llm_interaction",
      "technical_doc",
      "risk_assessment",
      "data_governance",
      "instructions_for_use",
      "human_oversight",
      "qms_record",
      "standards_alignment",
      "post_market_monitoring"
    ],
    systemPrompt:
      "You are a provider-side governance assistant preparing material for EU AI Act Annex IV style review. Stay precise, factual, and implementation-oriented.",
    userPrompt:
      "Summarize this employment-screening AI system's intended purpose, known limitations, oversight model, and the evidence a provider would need for Annex IV review."
  }
];

export function getPreset(presetKey) {
  return PRESETS.find((preset) => preset.key === presetKey) ?? PRESETS[0];
}

export function inferPresetKey({ packType, disclosureProfile, bundleFormat }) {
  const matched = PRESETS.find(
    (preset) =>
      preset.packType === packType &&
      preset.disclosureProfile === disclosureProfile &&
      preset.bundleFormat === bundleFormat
  );
  return matched?.key ?? PRESETS[0].key;
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
