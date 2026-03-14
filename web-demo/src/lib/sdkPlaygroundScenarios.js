import { DEFAULT_SERVICE_URL, defaultModelFor } from "./presets";

export const PLAYGROUND_LANES = [
  {
    id: "typescript",
    label: "TypeScript",
    eyebrow: "Language lane",
    description: "Use the JavaScript and TypeScript SDK for app-side AI capture."
  },
  {
    id: "python",
    label: "Python",
    eyebrow: "Language lane",
    description: "Use the Python SDK for reviewed workflows and incident handling."
  },
  {
    id: "cli",
    label: "CLI",
    eyebrow: "Language lane",
    description: "Use the Rust-native proofctl CLI when you want a scriptable terminal path."
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
    label: "Prompt",
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

function explainer(expectation, record, outsideTool) {
  return { expectation, record, outsideTool };
}

export const PLAYGROUND_SCENARIOS = [
  {
    id: "ts_chatbot_support",
    lane: "typescript",
    label: "Customer support chatbot",
    category: "Chatbot",
    description:
      "The simplest example: capture one support-style conversation and inspect the sealed record later.",
    audienceSummary: "A support chatbot or general assistant embedded in an application.",
    lawExplainer: explainer(
      "The law usually expects teams to understand what their AI system did and to keep evidence that can later explain a meaningful run.",
      "This example records the prompt, output, model details, and system context for one chatbot interaction.",
      "Your team still needs to decide whether this workflow triggers transparency or higher-risk duties and what notices or controls belong around it."
    ),
    sourceRef: "playground/typescript-chatbot.ts",
    codeLanguage: "javascript",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "runtime_minimum",
    templateId: "ts_chatbot_support",
    primaryStepId: "interaction",
    recordExplorerIntro:
      "This record shows a single chatbot run: what the user asked, what the model returned, and which system context applied.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "support-chatbot",
      systemPrompt:
        "You are a helpful support assistant. Answer clearly, stay within policy, and ask for a human handoff when needed.",
      intendedUse: "Customer support chatbot for routine account and product questions",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "limited_risk",
      highRiskDomain: "",
      deploymentContext: "eu_use",
      owner: "support-platform-team",
      market: "eu",
      userPrompt: "A customer says they cannot access their account. Draft a helpful reply."
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...INTERACTION_FIELDS, ...COMMON_PROFILE_FIELDS],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }
    ],
    missingEvidence: [
      "Add policy or transparency notices if users need to be clearly told they are interacting with AI.",
      "Add human handoff or escalation records if reviewers need to see how difficult cases leave the chatbot path.",
      "Add operating rules or monitoring records if this moves from a simple demo into a governed production workflow."
    ]
  },
  {
    id: "ts_support_rules",
    lane: "typescript",
    label: "Support assistant with operating rules",
    category: "Support workflow",
    description:
      "Capture the AI run plus the instructions and sign-off around it, then export a provider governance pack.",
    audienceSummary: "A support or triage assistant that must operate under clear human rules.",
    lawExplainer: explainer(
      "The law usually expects more than a raw model output when a workflow needs operating controls and internal review evidence.",
      "This example records the model run plus instructions for operators and a quality-management sign-off record.",
      "Your team still needs to maintain the real operating process, decide which standards apply, and add monitoring once the workflow is live."
    ),
    sourceRef: "examples/typescript-compliance/run.mjs",
    codeLanguage: "javascript",
    packType: "provider_governance",
    reviewKind: "provider_governance",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "annex_iv_redacted",
    templateId: "ts_support_rules",
    primaryStepId: "interaction",
    recordExplorerIntro:
      "This record set shows the model run plus the operating material around it, so a reviewer sees both behavior and controls.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "support-assistant",
      systemPrompt:
        "You are a support operations assistant. Summarize the issue, stay factual, and escalate edge cases for human review.",
      intendedUse: "Support-assistant workflow with human review for sensitive or unusual cases",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "limited_risk",
      highRiskDomain: "",
      deploymentContext: "eu_market_placement",
      owner: "quality-team",
      market: "eu",
      userPrompt: "Summarize a customer complaint and suggest the next safe support step.",
      instructionsSummary:
        "Agents must review high-risk refund, safety, and account-lock decisions before anything is sent.",
      instructionsSection: "agent-review-required",
      qmsStatus: "approved",
      qmsApprover: "quality-lead"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "instructionsSummary",
        label: "Operating rules summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "qmsApprover",
        label: "Quality approver",
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
    missingEvidence: [
      "Add monitoring records once the workflow is live and you need to show how it is watched over time.",
      "Add standards-alignment or release records if this needs to represent a fuller provider file.",
      "Add incident or corrective-action records when the workflow has real operational issues to review."
    ]
  },
  {
    id: "py_hiring_review",
    lane: "python",
    label: "Hiring review assistant",
    category: "Hiring workflow",
    description:
      "Show how a human-reviewed hiring or review workflow can capture the model output, assessment record, and oversight action together.",
    audienceSummary: "A higher-impact review workflow where people remain in the loop.",
    lawExplainer: explainer(
      "For higher-impact workflows, teams usually need to show not only the AI output but also how human review and impact assessment were handled.",
      "This example records the model interaction, a fundamental-rights assessment, and a human-oversight action.",
      "Your team still needs the real assessment process, deployment decision, and any operational safeguards or notices that sit outside the capture tool."
    ),
    sourceRef: "examples/python-compliance/run.py",
    codeLanguage: "python",
    packType: "fundamental_rights",
    reviewKind: "fundamental_rights",
    actorRole: "deployer",
    bundleFormat: "full",
    disclosureProfile: "regulator_minimum",
    templateId: "py_hiring_review",
    primaryStepId: "interaction",
    recordExplorerIntro:
      "This record set shows a reviewed hiring-style workflow where the AI output is only one part of the evidence story.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "hiring-review",
      systemPrompt:
        "You are a hiring review assistant. Summarize candidate information for a human reviewer and avoid final decisions.",
      intendedUse: "Candidate review support with mandatory human oversight",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_use",
      friaRequired: true,
      owner: "people-ops-review-team",
      market: "eu",
      userPrompt: "Summarize the candidate profile for a hiring manager and flag open questions.",
      friaSummary: "Borderline or negative recommendations require manual review and documented justification.",
      reviewer: "hiring-panel"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...INTERACTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "friaSummary",
        label: "Assessment finding",
        type: "textarea",
        rows: 3
      },
      {
        key: "reviewer",
        label: "Human reviewer",
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
    missingEvidence: [
      "Add stakeholder consultation or deployment approval records if the review needs to show how the workflow was accepted for use.",
      "Add post-deployment monitoring if reviewers need to see how the process is watched after launch.",
      "Add notices, escalation steps, or appeal procedures if affected people need to be part of the record."
    ]
  },
  {
    id: "py_incident_escalation",
    lane: "python",
    label: "Incident escalation",
    category: "Incident workflow",
    description:
      "Capture an incident, the draft authority notification, the reporting deadline, and regulator correspondence in one workflow.",
    audienceSummary: "An operational incident path where teams need a reviewable escalation trail.",
    lawExplainer: explainer(
      "When something goes wrong, teams usually need a clear incident trail that shows what happened, who was notified, and what follow-up is due.",
      "This example records the incident itself plus authority and deadline material needed for follow-up.",
      "Your team still needs to decide whether the event is reportable, complete the real submission process, and carry out corrective action outside the tool."
    ),
    sourceRef: "examples/python-incident-response/run.py",
    codeLanguage: "python",
    packType: "incident_response",
    reviewKind: "incident_response",
    actorRole: "deployer",
    bundleFormat: "full",
    disclosureProfile: "incident_summary",
    templateId: "py_incident_escalation",
    primaryStepId: "incident_report",
    recordExplorerIntro:
      "This record set shows how an incident trail can be built from the first report through regulator-facing follow-up.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      systemId: "benefits-review",
      intendedUse: "Public-facing eligibility review with incident escalation",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "",
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
      },
      {
        key: "correspondenceSubject",
        label: "Correspondence subject",
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
    missingEvidence: [
      "Add the final submission receipt if the review needs proof that a regulator actually received the filing.",
      "Add corrective-action and closure records once the incident moves beyond initial escalation.",
      "Add the operational evidence that explains what caused the incident if the reviewer needs deeper root-cause material."
    ]
  },
  {
    id: "cli_chatbot_support",
    lane: "cli",
    label: "Customer support chatbot via CLI",
    category: "CLI workflow",
    description:
      "Show the same single-run chatbot capture path through proofctl commands instead of an SDK facade.",
    audienceSummary: "A scriptable terminal path for teams who want to automate capture from the CLI.",
    lawExplainer: explainer(
      "The same basic expectation applies in a CLI workflow: keep enough evidence to explain a meaningful AI run later.",
      "This example records one chatbot interaction and the key system context around it.",
      "Your team still needs to decide which controls, notices, and sharing rules should sit around the workflow in production."
    ),
    sourceRef: "playground/proofctl-chatbot.sh",
    codeLanguage: "bash",
    packType: null,
    reviewKind: "chatbot_support",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "runtime_minimum",
    templateId: "cli_chatbot_support",
    primaryStepId: "interaction",
    recordExplorerIntro:
      "This record shows the terminal-first version of the same chatbot evidence flow.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "cli-support-chatbot",
      systemPrompt:
        "You are a support assistant. Stay clear, accurate, and escalate account-sensitive issues.",
      intendedUse: "Customer support chatbot captured through proofctl",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "limited_risk",
      highRiskDomain: "",
      deploymentContext: "eu_use",
      owner: "platform-engineering",
      market: "eu",
      userPrompt: "Draft a helpful account access reply for a customer."
    },
    fields: [...COMMON_CONNECTION_FIELDS, ...INTERACTION_FIELDS, ...COMMON_PROFILE_FIELDS],
    steps: [
      { id: "interaction", kind: "interaction", itemType: "llm_interaction", bundleRole: "primary" }
    ],
    missingEvidence: [
      "Add operating rules if the CLI path is being used for a governed production workflow rather than a simple capture example.",
      "Add disclosure and export policy decisions if this record needs to be shared outside the engineering team.",
      "Add monitoring and incident material if the workflow moves into higher-impact operational use."
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
  return null;
}

export function findScenarioByPackType(packType, items = []) {
  if (packType === null) {
    return PLAYGROUND_SCENARIOS.find((scenario) => scenario.id === "ts_chatbot_support") ?? null;
  }
  const scenario = PLAYGROUND_SCENARIOS.find((entry) => entry.packType === packType);
  if (scenario) {
    return scenario;
  }
  if (items.some((item) => item.type === "llm_interaction")) {
    return PLAYGROUND_SCENARIOS.find((entry) => entry.id === "ts_chatbot_support") ?? null;
  }
  return null;
}
