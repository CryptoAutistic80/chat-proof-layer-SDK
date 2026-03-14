import { DEFAULT_SERVICE_URL, defaultModelFor } from "./presets";

export const PLAYGROUND_LANES = [
  {
    id: "typescript",
    label: "TypeScript",
    eyebrow: "SDK lane",
    description: "Show the JavaScript and TypeScript facade with reusable compliance context."
  },
  {
    id: "python",
    label: "Python",
    eyebrow: "SDK lane",
    description: "Show Python capture flows for deployer-side governance and incident response."
  },
  {
    id: "cli",
    label: "CLI",
    eyebrow: "Rust-native lane",
    description: "Show the `proofctl` path without pretending there is a separate published Rust SDK."
  }
];

const COMMON_CONNECTION_FIELDS = [
  {
    key: "serviceUrl",
    label: "Vault URL",
    type: "text",
    placeholder: DEFAULT_SERVICE_URL
  },
  {
    key: "apiKey",
    label: "Vault API key",
    type: "password",
    placeholder: "Optional bearer token"
  }
];

const INTERACTION_FIELDS = [
  {
    key: "provider",
    label: "Provider",
    type: "select",
    options: [
      { label: "OpenAI", value: "openai" },
      { label: "Anthropic", value: "anthropic" }
    ]
  },
  {
    key: "model",
    label: "Model",
    type: "text"
  },
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
  {
    key: "userPrompt",
    label: "Primary prompt",
    type: "textarea",
    rows: 5
  }
];

const COMMON_PROFILE_FIELDS = [
  {
    key: "systemId",
    label: "System ID",
    type: "text"
  },
  {
    key: "intendedUse",
    label: "Intended use",
    type: "textarea",
    rows: 3
  },
  {
    key: "owner",
    label: "Owner",
    type: "text"
  }
];

export const PLAYGROUND_SCENARIOS = [
  {
    id: "ts_provider_governance",
    lane: "typescript",
    label: "Provider governance",
    description:
      "Capture one interaction plus operator instructions and QMS evidence, then export a provider governance pack.",
    sourceRef: "examples/typescript-compliance/run.mjs",
    codeLanguage: "javascript",
    packType: "provider_governance",
    reviewKind: "provider_governance",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "annex_iv_redacted",
    templateId: "ts_provider_governance",
    primaryStepId: "interaction",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "hiring-assistant",
      systemPrompt:
        "You are a recruiter support assistant. Stay concrete, highlight review steps, and avoid autonomous decisions.",
      intendedUse: "Recruiter support for first-pass candidate review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_market_placement",
      owner: "quality-team",
      market: "eu",
      userPrompt: "Summarize the candidate profile for a human recruiter.",
      instructionsSummary:
        "Operators must review all negative or borderline candidate recommendations.",
      instructionsSection: "human-review-required",
      qmsStatus: "approved",
      qmsApprover: "quality-lead"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "instructionsSummary",
        label: "Instructions note",
        type: "textarea",
        rows: 3
      },
      {
        key: "qmsApprover",
        label: "QMS approver",
        type: "text"
      }
    ],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" },
      {
        id: "instructions_for_use",
        kind: "evidence",
        itemType: "instructions_for_use",
        bundleRole: "support"
      },
      { id: "qms_record", kind: "evidence", itemType: "qms_record", bundleRole: "support" }
    ],
    reviewGaps: [
      "Add standards alignment evidence to show which harmonized standards or internal controls back the release.",
      "Add post-market monitoring records once the system is in production.",
      "Add conformity or declaration material if this example needs to represent a fuller provider file."
    ]
  },
  {
    id: "ts_post_market_monitoring",
    lane: "typescript",
    label: "Post-market monitoring",
    description:
      "Capture one operational interaction, a monitoring plan, and an authority submission for follow-up export.",
    sourceRef: "examples/typescript-monitoring/run.mjs",
    codeLanguage: "javascript",
    packType: "post_market_monitoring",
    reviewKind: "post_market_monitoring",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "incident_summary",
    templateId: "ts_post_market_monitoring",
    primaryStepId: "interaction",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "claims-assistant",
      systemPrompt:
        "You are a claims triage assistant. Summarize the case for a human reviewer and flag missing evidence without making a final decision.",
      intendedUse: "Claims triage support with human review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      deploymentContext: "eu_market_placement",
      owner: "safety-ops",
      market: "eu",
      userPrompt: "Summarize the claim for a human reviewer and flag missing documents.",
      monitoringSummary:
        "Weekly drift review with incident escalation thresholds for adverse outcomes.",
      authority: "eu_ai_office",
      submissionSummary: "Initial notification package for monitoring follow-up."
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "monitoringSummary",
        label: "Monitoring summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "authority",
        label: "Authority",
        type: "text"
      }
    ],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" },
      {
        id: "post_market_monitoring",
        kind: "evidence",
        itemType: "post_market_monitoring",
        bundleRole: "support"
      },
      {
        id: "authority_submission",
        kind: "evidence",
        itemType: "authority_submission",
        bundleRole: "support"
      }
    ],
    reviewGaps: [
      "Add incident reports and corrective actions when monitoring turns up adverse outcomes.",
      "Add retained runtime slices if the reviewer needs evidence from a specific production window.",
      "Add downstream instructions or notices if this monitoring flow needs to show operator communication."
    ]
  },
  {
    id: "py_fundamental_rights",
    lane: "python",
    label: "Fundamental rights",
    description:
      "Capture one deployer-side interaction, a FRIA record, and a human oversight action for a deployer review pack.",
    sourceRef: "examples/python-compliance/run.py",
    codeLanguage: "python",
    packType: "fundamental_rights",
    reviewKind: "fundamental_rights",
    actorRole: "deployer",
    bundleFormat: "full",
    disclosureProfile: "regulator_minimum",
    templateId: "py_fundamental_rights",
    primaryStepId: "interaction",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "benefits-review",
      systemPrompt:
        "You are a public-sector review assistant. Summarize the case for human review and emphasize borderline factors.",
      intendedUse: "Public-sector benefit eligibility review",
      riskTier: "high_risk",
      deploymentContext: "public_sector",
      friaRequired: true,
      owner: "rights-review-team",
      market: "eu",
      userPrompt: "Summarize the eligibility factors for human review.",
      friaSummary: "Human escalation required for borderline cases.",
      reviewer: "rights-panel"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "friaSummary",
        label: "FRIA finding",
        type: "textarea",
        rows: 3
      },
      {
        key: "reviewer",
        label: "Oversight reviewer",
        type: "text"
      }
    ],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" },
      {
        id: "fundamental_rights_assessment",
        kind: "evidence",
        itemType: "fundamental_rights_assessment",
        bundleRole: "support"
      },
      {
        id: "human_oversight",
        kind: "evidence",
        itemType: "human_oversight",
        bundleRole: "support"
      }
    ],
    reviewGaps: [
      "Add consultation records or stakeholder input if the deployer needs to show how affected groups were considered.",
      "Add post-deployment monitoring evidence if the review needs to show how the deployer watches for rights impact after launch.",
      "Add any notices or escalation procedures that explain how human review reaches affected decisions."
    ]
  },
  {
    id: "py_incident_response",
    lane: "python",
    label: "Incident response",
    description:
      "Capture an incident, an authority notification, a reporting deadline, and correspondence in one deployer-side response flow.",
    sourceRef: "examples/python-incident-response/run.py",
    codeLanguage: "python",
    packType: "incident_response",
    reviewKind: "incident_response",
    actorRole: "deployer",
    bundleFormat: "full",
    disclosureProfile: "incident_summary",
    templateId: "py_incident_response",
    primaryStepId: "incident_report",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      systemId: "benefits-review",
      intendedUse: "Public-sector benefit eligibility review",
      riskTier: "high_risk",
      deploymentContext: "public_sector",
      friaRequired: true,
      owner: "incident-ops",
      market: "eu",
      authority: "eu_ai_office",
      incidentSummary: "Potentially adverse recommendation surfaced in a public-service case.",
      dueAt: "2026-03-09T12:00:00Z",
      correspondenceSubject: "Initial authority follow-up"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "authority",
        label: "Authority",
        type: "text"
      },
      {
        key: "incidentSummary",
        label: "Incident summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "dueAt",
        label: "Reporting deadline",
        type: "text"
      }
    ],
    steps: [
      { id: "incident_report", kind: "evidence", itemType: "incident_report", bundleRole: "primary" },
      {
        id: "authority_notification",
        kind: "evidence",
        itemType: "authority_notification",
        bundleRole: "support"
      },
      {
        id: "reporting_deadline",
        kind: "evidence",
        itemType: "reporting_deadline",
        bundleRole: "support"
      },
      {
        id: "regulator_correspondence",
        kind: "evidence",
        itemType: "regulator_correspondence",
        bundleRole: "support"
      }
    ],
    reviewGaps: [
      "Add the final authority submission receipt if the reviewer needs to prove the notification left draft state.",
      "Add corrective action and closure records once the incident response moves beyond initial reporting.",
      "Add any runtime or model-evaluation evidence that explains what caused the incident in operational terms."
    ]
  },
  {
    id: "cli_provider_governance",
    lane: "cli",
    label: "Provider governance via CLI",
    description:
      "Show the Rust-native `proofctl` create and pack flow for the same provider-governance outcome.",
    sourceRef: "README.md#getting-started",
    codeLanguage: "bash",
    packType: "provider_governance",
    reviewKind: "provider_governance",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "annex_iv_redacted",
    templateId: "cli_provider_governance",
    primaryStepId: "interaction",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "cli-hiring-assistant",
      systemPrompt:
        "You are a recruiter support assistant. Stay concrete, highlight review steps, and avoid autonomous decisions.",
      intendedUse: "Recruiter support for first-pass candidate review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_market_placement",
      owner: "quality-team",
      market: "eu",
      userPrompt: "Summarize the candidate profile for a human recruiter.",
      instructionsSummary:
        "Operators must review all negative or borderline candidate recommendations.",
      qmsApprover: "quality-lead"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "instructionsSummary",
        label: "Instructions note",
        type: "textarea",
        rows: 3
      },
      {
        key: "qmsApprover",
        label: "QMS approver",
        type: "text"
      }
    ],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" },
      {
        id: "instructions_for_use",
        kind: "evidence",
        itemType: "instructions_for_use",
        bundleRole: "support"
      },
      { id: "qms_record", kind: "evidence", itemType: "qms_record", bundleRole: "support" }
    ],
    reviewGaps: [
      "Add standards alignment evidence to show which controls back the release.",
      "Add monitoring and corrective-action evidence when the example needs to move beyond pre-release governance.",
      "Add any conformity or declaration artefacts required for a fuller provider evidence file."
    ]
  }
];

export function getPlaygroundScenario(id) {
  return PLAYGROUND_SCENARIOS.find((scenario) => scenario.id === id) ?? PLAYGROUND_SCENARIOS[0];
}

export function listScenariosForLane(lane) {
  return PLAYGROUND_SCENARIOS.filter((scenario) => scenario.lane === lane);
}

export function firstScenarioForLane(lane) {
  return listScenariosForLane(lane)[0] ?? PLAYGROUND_SCENARIOS[0];
}

export function initialPlaygroundScenario() {
  return PLAYGROUND_SCENARIOS[0];
}

export function applyScenarioToDraft(currentDraft, scenario) {
  return {
    ...currentDraft,
    lane: scenario.lane,
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
  if (types.includes("incident_report") || types.includes("authority_notification")) {
    return "incident_response";
  }
  if (types.includes("fundamental_rights_assessment") || types.includes("human_oversight")) {
    return "fundamental_rights";
  }
  if (types.includes("post_market_monitoring") || types.includes("authority_submission")) {
    return "post_market_monitoring";
  }
  if (types.includes("instructions_for_use") || types.includes("qms_record")) {
    return "provider_governance";
  }
  return "runtime_logs";
}

export function findScenarioByPackType(packType) {
  return PLAYGROUND_SCENARIOS.find((scenario) => scenario.packType === packType) ?? null;
}
