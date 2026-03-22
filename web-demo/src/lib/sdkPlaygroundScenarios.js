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
    label: "Annex IV governance pack",
    category: "High-risk governance",
    description:
      "Capture a provider-side high-risk governance record and export full plus redacted Annex IV packs.",
    audienceSummary:
      "A provider preparing a regulator-facing or conformity-review package for a high-risk employment system.",
    lawExplainer: explainer(
      "Annex IV style readiness needs more than one technical note. Reviewers usually expect technical documentation, risk controls, data governance, oversight, quality management, standards mapping, and monitoring evidence to line up around the same system.",
      "This example records the core governance bundle set for a provider-side high-risk employment workflow and then exports the same inclusion set as both full and redacted Annex IV packs.",
      "Your team still needs the real legal assessment, conformity process, and production operating procedures outside the demo."
    ),
    sourceRef: "examples/typescript-compliance/run.mjs",
    codeLanguage: "javascript",
    packType: "annex_iv",
    reviewKind: "annex_iv",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "annex_iv_redacted",
    templateId: "ts_support_rules",
    primaryStepId: "technical_doc",
    recordExplorerIntro:
      "This record set shows the provider-side governance file around a high-risk employment system, rather than just one model interaction.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      provider: "openai",
      model: defaultModelFor("openai"),
      mode: "synthetic",
      systemId: "hiring-assistant",
      systemPrompt:
        "You are a provider governance assistant preparing Annex IV-ready employment-system records. Stay precise, factual, and implementation-oriented.",
      intendedUse: "Recruiter support for first-pass candidate review",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "high_risk",
      highRiskDomain: "employment",
      deploymentContext: "eu_market_placement",
      owner: "quality-team",
      market: "eu",
      userPrompt:
        "Summarize this employment-screening AI system's intended purpose, known limitations, oversight model, and the evidence a provider would need for Annex IV review.",
      datasetName: "hiring-assistant-training-v3",
      datasetVersion: "2026.03",
      sourceDescription:
        "Curated recruiting assessments, interviewer notes, and QA-reviewed candidate summaries for EU employment workflows.",
      biasMethodology:
        "Quarterly parity review across gender, age-proxy, disability-accommodation, and language cohorts.",
      safeguards: "pseudonymization, role-based access, retention minimization",
      instructionsSummary:
        "Recruiters must review all borderline or adverse recommendations before anything leaves the workflow.",
      instructionsSection: "employment_review_controls",
      humanOversightGuidance:
        "Escalate adverse or borderline recommendations to a human reviewer before any employment decision.",
      qmsStatus: "approved",
      qmsApprover: "quality-lead",
      monitoringSummary:
        "Weekly review of override rates, appeal signals, and fairness sampling for the employment workflow.",
      reviewer: "quality-panel"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "datasetName",
        label: "Dataset name",
        type: "text"
      },
      {
        key: "sourceDescription",
        label: "Dataset source summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "biasMethodology",
        label: "Bias review method",
        type: "textarea",
        rows: 3
      },
      {
        key: "instructionsSummary",
        label: "Operating rules summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "humanOversightGuidance",
        label: "Human oversight guidance",
        type: "textarea",
        rows: 3
      },
      {
        key: "qmsApprover",
        label: "Quality approver",
        type: "text"
      },
      {
        key: "reviewer",
        label: "Human reviewer",
        type: "text"
      },
      {
        key: "monitoringSummary",
        label: "Monitoring summary",
        type: "textarea",
        rows: 3
      }
    ],
    steps: [
      { id: "technical_doc", kind: "evidence", itemType: "technical_doc", bundleRole: "primary" },
      { id: "risk_assessment", kind: "evidence", itemType: "risk_assessment", bundleRole: "support" },
      { id: "data_governance", kind: "evidence", itemType: "data_governance", bundleRole: "support" },
      {
        id: "instructions_for_use",
        kind: "evidence",
        itemType: "instructions_for_use",
        bundleRole: "support"
      },
      { id: "human_oversight", kind: "evidence", itemType: "human_oversight", bundleRole: "support" },
      { id: "qms_record", kind: "evidence", itemType: "qms_record", bundleRole: "support" },
      {
        id: "standards_alignment",
        kind: "evidence",
        itemType: "standards_alignment",
        bundleRole: "support"
      },
      {
        id: "post_market_monitoring",
        kind: "evidence",
        itemType: "post_market_monitoring",
        bundleRole: "support"
      }
    ],
    missingEvidence: [
      "Add conformity-assessment outputs and notified-body material if the reviewer needs the full market-placement file.",
      "Add corrective-action or incident records when the workflow has real operational issues to investigate.",
      "Add the legal sign-off and deployment approval process that sits outside the capture tool."
    ]
  },
  {
    id: "ts_gpai_thresholds",
    lane: "typescript",
    label: "Foundation model threshold tracking",
    category: "GPAI workflow",
    description:
      "Capture training provenance plus compute-threshold evidence for a GPAI provider workflow and export an Annex XI pack.",
    audienceSummary:
      "A GPAI or foundation-model provider that needs to track provenance and systemic-risk compute thresholds.",
    lawExplainer: explainer(
      "For GPAI workflows, teams may need to show how training provenance and compute-threshold evidence line up with provider obligations.",
      "This example records training provenance plus first-class compute metrics so a reviewer can trace dataset lineage and threshold status together.",
      "Your team still needs the broader GPAI file such as downstream documentation, copyright policy, and evaluation evidence."
    ),
    sourceRef: "examples/typescript-gpai/run.mjs",
    codeLanguage: "javascript",
    packType: "annex_xi",
    reviewKind: "annex_xi",
    actorRole: "provider",
    bundleFormat: "full",
    disclosureProfile: "annex_iv_redacted",
    templateId: "ts_gpai_thresholds",
    primaryStepId: "training_provenance",
    recordExplorerIntro:
      "This record set shows a GPAI provider workflow where provenance and compute-threshold evidence are captured as separate but linked records.",
    defaults: {
      serviceUrl: DEFAULT_SERVICE_URL,
      systemId: "foundation-model-alpha",
      intendedUse: "General-purpose text and workflow assistance",
      prohibitedPracticeScreening: "screened_no_prohibited_use",
      riskTier: "",
      highRiskDomain: "",
      gpaiStatus: "provider",
      systemicRisk: true,
      deploymentContext: "eu_market_placement",
      owner: "foundation-ops",
      market: "eu",
      datasetRef: "dataset://foundation-model-alpha/pretrain-v5",
      trainingDatasetSummary: "Multilingual curated web, code, and licensed reference corpora.",
      consortiumContext: "Single-provider training program",
      trainingFlopsEstimate: "1.2e25",
      thresholdStatus: "above_threshold",
      thresholdValue: "1e25",
      gpuHours: "42000",
      acceleratorCount: "2048"
    },
    fields: [
      ...COMMON_CONNECTION_FIELDS,
      ...COMMON_PROFILE_FIELDS,
      {
        key: "datasetRef",
        label: "Dataset reference",
        type: "text"
      },
      {
        key: "trainingDatasetSummary",
        label: "Training dataset summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "consortiumContext",
        label: "Consortium context",
        type: "text"
      },
      {
        key: "trainingFlopsEstimate",
        label: "Training FLOPs estimate",
        type: "text"
      },
      {
        key: "thresholdStatus",
        label: "Threshold status",
        type: "select",
        options: [
          { label: "Above threshold", value: "above_threshold" },
          { label: "Below threshold", value: "below_threshold" }
        ]
      },
      {
        key: "thresholdValue",
        label: "Threshold value",
        type: "text"
      },
      {
        key: "gpuHours",
        label: "GPU hours",
        type: "text"
      },
      {
        key: "acceleratorCount",
        label: "Accelerator count",
        type: "text"
      }
    ],
    steps: [
      {
        id: "training_provenance",
        kind: "evidence",
        itemType: "training_provenance",
        bundleRole: "primary"
      },
      {
        id: "compute_metrics",
        kind: "evidence",
        itemType: "compute_metrics",
        bundleRole: "support"
      }
    ],
    missingEvidence: [
      "Add downstream documentation and copyright-policy records when this needs to represent a fuller GPAI provider file.",
      "Add evaluation or adversarial-testing evidence when reviewers need performance and robustness material with the provenance trail.",
      "Add obligation-filtered export rules if you need to share only a narrow systemic-risk subset."
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
      affectedRights: "equal treatment, access to employment, explanation",
      assessor: "fundamental-rights-lead",
      reviewer: "hiring-panel",
      overrideAction: "Candidate routed to manual review queue before any hiring decision."
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
        key: "affectedRights",
        label: "Affected rights",
        type: "textarea",
        rows: 3
      },
      {
        key: "assessor",
        label: "FRIA assessor",
        type: "text"
      },
      {
        key: "reviewer",
        label: "Human reviewer",
        type: "text"
      },
      {
        key: "overrideAction",
        label: "Oversight outcome",
        type: "textarea",
        rows: 3
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
      "Capture the incident context, triage decision, corrective action, authority reporting, and correspondence in one workflow.",
    audienceSummary:
      "An incident-response path where teams need a reviewable escalation and reporting trail.",
    lawExplainer: explainer(
      "When something goes wrong, teams usually need a clear incident trail that shows what happened, who was notified, and what follow-up is due.",
      "This example records the incident context, triage decision, human-oversight evidence, incident, corrective-action, authority, deadline, and correspondence material needed for follow-up.",
      "Your team still needs to decide whether the event is reportable, complete the real submission process, and carry out closure work outside the tool."
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
      "This record set shows how an incident-response file can be built from the first triage decision through regulator-facing follow-up.",
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
      rootCauseSummary:
        "Missing-document threshold was too permissive for a narrow public-service case segment.",
      correctiveActionRef: "ca-benefits-42",
      correctiveActionSummary:
        "Tighten the borderline threshold and route similar cases to manual review.",
      notificationSummary:
        "Initial authority notification for a potentially adverse recommendation incident.",
      submissionSummary:
        "Initial notification package for public-service incident follow-up.",
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
        key: "rootCauseSummary",
        label: "Root cause summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "correctiveActionRef",
        label: "Corrective action ref",
        type: "text"
      },
      {
        key: "correctiveActionSummary",
        label: "Corrective action summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "dueAt",
        label: "Reporting deadline",
        type: "text"
      },
      {
        key: "notificationSummary",
        label: "Notification summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "submissionSummary",
        label: "Submission summary",
        type: "textarea",
        rows: 3
      },
      {
        key: "correspondenceSubject",
        label: "Correspondence subject",
        type: "text"
      }
    ],
    steps: [
      {
        id: "technical_doc",
        kind: "evidence",
        itemType: "technical_doc",
        bundleRole: "support"
      },
      {
        id: "risk_assessment",
        kind: "evidence",
        itemType: "risk_assessment",
        bundleRole: "support"
      },
      {
        id: "human_oversight",
        kind: "evidence",
        itemType: "human_oversight",
        bundleRole: "support"
      },
      {
        id: "policy_decision",
        kind: "evidence",
        itemType: "policy_decision",
        bundleRole: "primary"
      },
      { id: "incident_report", kind: "evidence", itemType: "incident_report", bundleRole: "primary" },
      {
        id: "corrective_action",
        kind: "evidence",
        itemType: "corrective_action",
        bundleRole: "support"
      },
      {
        id: "authority_notification",
        kind: "evidence",
        itemType: "authority_notification",
        bundleRole: "support"
      },
      {
        id: "authority_submission",
        kind: "evidence",
        itemType: "authority_submission",
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
      "Add closure evidence once the incident moves beyond corrective action and the workflow is fully stabilized.",
      "Add underlying runtime or model-evaluation evidence if the reviewer needs deeper technical root-cause material."
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
  if (types.includes("training_provenance") || types.includes("compute_metrics")) {
    return "annex_xi";
  }
  if (
    types.includes("conformity_assessment") ||
    types.includes("declaration") ||
    types.includes("registration")
  ) {
    return "conformity";
  }
  if (types.includes("post_market_monitoring")) {
    return "post_market_monitoring";
  }
  if (
    types.includes("incident_report") ||
    types.includes("authority_notification") ||
    types.includes("regulator_correspondence") ||
    types.includes("policy_decision")
  ) {
    return "incident_response";
  }
  if (
    types.includes("technical_doc") ||
    types.includes("risk_assessment") ||
    types.includes("standards_alignment")
  ) {
    return "annex_iv";
  }
  if (types.includes("fundamental_rights_assessment") || types.includes("human_oversight")) {
    return "fundamental_rights";
  }
  if (
    types.includes("data_governance") ||
    types.includes("instructions_for_use") ||
    types.includes("qms_record")
  ) {
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
  if (packType === "conformity" || packType === "provider_governance") {
    return PLAYGROUND_SCENARIOS.find((entry) => entry.id === "ts_support_rules") ?? null;
  }
  if (packType === "post_market_monitoring") {
    return PLAYGROUND_SCENARIOS.find((entry) => entry.id === "py_incident_escalation") ?? null;
  }
  if (items.some((item) => item.type === "llm_interaction")) {
    return PLAYGROUND_SCENARIOS.find((entry) => entry.id === "ts_chatbot_support") ?? null;
  }
  return null;
}
