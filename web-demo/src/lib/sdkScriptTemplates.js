import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

function q(value) {
  return JSON.stringify(value ?? "");
}

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function indent(value, spaces = 2) {
  const prefix = " ".repeat(spaces);
  return String(value)
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function renderTsComplianceProfile(draft) {
  return `{
  intendedUse: ${q(draft.intendedUse)},
  prohibitedPracticeScreening: ${q(draft.prohibitedPracticeScreening)},
  riskTier: ${q(draft.riskTier)},
  highRiskDomain: ${q(draft.highRiskDomain)},
  deploymentContext: ${q(draft.deploymentContext)},
  friaRequired: ${draft.friaRequired ? "true" : "false"},
  metadata: {
    owner: ${q(draft.owner)},
    market: ${q(draft.market)}
  }
}`;
}

function renderPyComplianceProfile(draft) {
  return `{
    "intended_use": ${q(draft.intendedUse)},
    "risk_tier": ${q(draft.riskTier)},
    "high_risk_domain": ${q(draft.highRiskDomain)},
    "fria_required": ${draft.friaRequired ? "True" : "False"},
    "deployment_context": ${q(draft.deploymentContext)},
    "metadata": {
        "owner": ${q(draft.owner)},
        "market": ${q(draft.market)},
    },
}`;
}

function renderTsChatbotSupport(draft) {
  return `import { ProofLayer } from "@proof-layer/sdk";

const proofLayer = new ProofLayer({
  vaultUrl: ${q(draft.serviceUrl)},
  appId: "typescript-chatbot-example",
  env: "dev",
  systemId: ${q(draft.systemId)},
  role: "provider",
  complianceProfile: ${indent(renderTsComplianceProfile(draft), 2).trimStart()}
});

const interaction = await proofLayer.capture({
  provider: ${q(draft.provider)},
  model: ${q(draft.model)},
  requestId: "req-support-001",
  input: {
    prompt: ${q(draft.userPrompt)}
  },
  output: {
    summary: "Captured support reply ready for later review."
  },
  retentionClass: "runtime_logs"
});

await interaction.verify();`;
}

function renderTsSupportRules(draft) {
  return `import { ProofLayer } from "@proof-layer/sdk";

const proofLayer = new ProofLayer({
  vaultUrl: ${q(draft.serviceUrl)},
  appId: "typescript-support-rules-example",
  env: "dev",
  systemId: ${q(draft.systemId)},
  role: "provider",
  complianceProfile: ${indent(renderTsComplianceProfile(draft), 2).trimStart()}
});

const interaction = await proofLayer.capture({
  provider: ${q(draft.provider)},
  model: ${q(draft.model)},
  requestId: "req-support-002",
  input: {
    prompt: ${q(draft.userPrompt)}
  },
  output: {
    summary: "Support reply captured for review."
  },
  retentionClass: "runtime_logs"
});

const instructions = await proofLayer.captureInstructionsForUse({
  documentRef: "docs://support-assistant/operating-rules",
  versionTag: "2026.03",
  section: ${q(draft.instructionsSection)},
  document: {
    summary: ${q(draft.instructionsSummary)},
    owner: ${q(draft.owner)}
  },
  retentionClass: "technical_doc"
});

const qmsRecord = await proofLayer.captureQmsRecord({
  recordId: "qms-release-approval-42",
  process: "release_approval",
  status: "approved",
  record: {
    approver: ${q(draft.qmsApprover)},
    release: "2026.03"
  },
  retentionClass: "technical_doc"
});

const pack = await proofLayer.createPack({
  packType: "provider_governance",
  systemId: ${q(draft.systemId)},
  bundleFormat: "full"
});`;
}

function renderPyHiringReview(draft) {
  return `from proofsdk.proof_layer import ProofLayer

proof_layer = ProofLayer(
    vault_url=${q(draft.serviceUrl)},
    app_id="python-hiring-review-example",
    env="dev",
    system_id=${q(draft.systemId)},
    role="deployer",
    compliance_profile=${indent(renderPyComplianceProfile(draft), 4).trimStart()},
)

interaction = proof_layer.capture(
    provider=${q(draft.provider)},
    model=${q(draft.model)},
    request_id="req-hiring-001",
    input={"prompt": ${q(draft.userPrompt)}},
    output={"summary": "Hiring review support captured for later inspection."},
    retention_class="runtime_logs",
)

fria = proof_layer.capture_fundamental_rights_assessment(
    assessment_id="fria-2026-03",
    status="completed",
    scope=${q(draft.intendedUse)},
    report={
        "owner": ${q(draft.owner)},
        "finding": ${q(draft.friaSummary)},
    },
    retention_class="technical_doc",
)

oversight = proof_layer.capture_human_oversight(
    action="manual_case_review_required",
    reviewer=${q(draft.reviewer)},
    notes={"reason": ${q(draft.friaSummary)}},
    retention_class="risk_mgmt",
)

pack = proof_layer.create_pack(
    pack_type="fundamental_rights",
    system_id=${q(draft.systemId)},
    bundle_format="full",
)`;
}

function renderPyIncidentEscalation(draft) {
  return `from proofsdk.proof_layer import ProofLayer

proof_layer = ProofLayer(
    vault_url=${q(draft.serviceUrl)},
    app_id="python-incident-escalation-example",
    env="dev",
    system_id=${q(draft.systemId)},
    role="deployer",
    compliance_profile=${indent(renderPyComplianceProfile(draft), 4).trimStart()},
)

incident = proof_layer.capture_incident_report(
    incident_id="inc-benefits-42",
    severity="serious",
    status="open",
    occurred_at="2026-03-07T18:30:00Z",
    summary=${q(draft.incidentSummary)},
    report={"owner": ${q(draft.owner)}},
    retention_class="risk_mgmt",
)

notification = proof_layer.capture_authority_notification(
    notification_id="notif-benefits-42",
    authority=${q(draft.authority)},
    status="drafted",
    incident_id="inc-benefits-42",
    due_at=${q(draft.dueAt)},
    report={"article": "73"},
    retention_class="risk_mgmt",
)

deadline = proof_layer.capture_reporting_deadline(
    deadline_id="deadline-benefits-42",
    authority=${q(draft.authority)},
    obligation_ref="art73_notification",
    due_at=${q(draft.dueAt)},
    status="open",
    incident_id="inc-benefits-42",
    retention_class="risk_mgmt",
)

correspondence = proof_layer.capture_regulator_correspondence(
    correspondence_id="corr-benefits-42",
    authority=${q(draft.authority)},
    direction="outbound",
    status="sent",
    occurred_at="2026-03-08T10:00:00Z",
    message={"subject": ${q(draft.correspondenceSubject)}},
    retention_class="risk_mgmt",
)

pack = proof_layer.create_pack(
    pack_type="incident_response",
    system_id=${q(draft.systemId)},
    bundle_format="full",
)`;
}

function renderCliChatbotSupport(draft) {
  const captureJson = pretty({
    actor: {
      issuer: "proofctl",
      app_id: "proofctl",
      env: "dev",
      signing_key_id: "cli-signing-key",
      role: "provider"
    },
    subject: {
      request_id: "req-support-001",
      system_id: draft.systemId,
      model_id: `${draft.provider}:${draft.model}`,
      deployment_id: `${draft.systemId}-cli`,
      version: "2026.03"
    },
    compliance_profile: {
      intended_use: draft.intendedUse,
      prohibited_practice_screening: draft.prohibitedPracticeScreening,
      risk_tier: draft.riskTier,
      high_risk_domain: draft.highRiskDomain,
      deployment_context: draft.deploymentContext,
      metadata: {
        owner: draft.owner,
        market: draft.market
      }
    },
    context: {
      provider: draft.provider,
      model: draft.model,
      parameters: {
        capture_mode: draft.mode
      }
    },
    items: [
      {
        type: "llm_interaction",
        data: {
          provider: draft.provider,
          model: draft.model
        }
      }
    ],
    policy: {
      redactions: [],
      encryption: { enabled: false },
      retention_class: "runtime_logs"
    }
  });

  return `cat > ./capture.json <<'JSON'
${captureJson}
JSON

cargo run -p proofctl -- create \\
  --input ./capture.json \\
  --key ./keys/signing.pem \\
  --out ./chatbot-record.pkg \\
  --role provider \\
  --system-id ${draft.systemId} \\
  --intended-use ${q(draft.intendedUse)} \\
  --prohibited-practice-screening ${draft.prohibitedPracticeScreening} \\
  --risk-tier ${q(draft.riskTier)} \\
  --deployment-context ${q(draft.deploymentContext)}

cargo run -p proofctl -- verify \\
  --bundle ./chatbot-record.pkg \\
  --public-key ./keys/verify.pub`;
}

export function renderScenarioScript(scenarioInput, draft) {
  const scenario =
    typeof scenarioInput === "string"
      ? getPlaygroundScenario(scenarioInput)
      : scenarioInput;
  switch (scenario.templateId) {
    case "ts_chatbot_support":
      return renderTsChatbotSupport(draft);
    case "ts_support_rules":
      return renderTsSupportRules(draft);
    case "py_hiring_review":
      return renderPyHiringReview(draft);
    case "py_incident_escalation":
      return renderPyIncidentEscalation(draft);
    case "cli_chatbot_support":
      return renderCliChatbotSupport(draft);
    default:
      return "// Scenario template unavailable";
  }
}
