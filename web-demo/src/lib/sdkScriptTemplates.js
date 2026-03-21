import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

function q(value) {
  return JSON.stringify(value ?? "");
}

function splitList(value) {
  return String(value ?? "")
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
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
  gpaiStatus: ${q(draft.gpaiStatus)},
  systemicRisk: ${draft.systemicRisk ? "true" : "false"},
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
    "prohibited_practice_screening": ${q(draft.prohibitedPracticeScreening)},
    "risk_tier": ${q(draft.riskTier)},
    "high_risk_domain": ${q(draft.highRiskDomain)},
    "gpai_status": ${q(draft.gpaiStatus)},
    "systemic_risk": ${draft.systemicRisk ? "True" : "False"},
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

const dataGovernance = await proofLayer.captureDataGovernance({
  decision: "approved_with_restrictions",
  datasetRef: "dataset://${draft.systemId}/training",
  datasetName: ${q(draft.datasetName)},
  datasetVersion: ${q(draft.datasetVersion ?? "2026.03")},
  sourceDescription: ${q(draft.sourceDescription)},
  collectionPeriod: {
    start: "2024-01-01",
    end: "2025-12-31"
  },
  geographicalScope: ["EU"],
  preprocessingOperations: ["deduplication", "pii_minimization", "label_review"],
  biasDetectionMethodology: ${q(draft.biasMethodology)},
  biasMetrics: [
    {
      name: "selection_rate_gap",
      value: "0.04",
      unit: "ratio",
      methodology: ${q(draft.biasMethodology)}
    }
  ],
  mitigationActions: [
    "Escalate sensitive support actions to human review.",
    "Sample multilingual support outputs for quality assurance."
  ],
  dataGaps: ["Limited historic examples for rare safety escalations."],
  personalDataCategories: ["customer_messages", "account_status"],
  safeguards: ${pretty(splitList(draft.safeguards))},
  retentionClass: "technical_doc"
});

const instructions = await proofLayer.captureInstructionsForUse({
  documentRef: "docs://${draft.systemId}/operator-handbook",
  versionTag: "2026.03",
  section: ${q(draft.instructionsSection)},
  providerIdentity: ${q(`${draft.owner} provider team`)},
  intendedPurpose: ${q(draft.intendedUse)},
  systemCapabilities: ["issue_summary", "safe_response_drafting", "escalation_flagging"],
  accuracyMetrics: [{ name: "review_precision", value: "0.91", unit: "ratio" }],
  foreseeableRisks: ["overconfident refund guidance", "missed escalation on account-access edge cases"],
  explainabilityCapabilities: ["reason_summary", "policy-grounded escalation note"],
  humanOversightGuidance: ${pretty(splitList(draft.humanOversightGuidance))},
  computeRequirements: ["4 vCPU", "8GB RAM"],
  serviceLifetime: "Review quarterly or whenever operator rules change.",
  logManagementGuidance: [
    "Retain runtime logs for post-market monitoring reviews.",
    "Escalate incident-linked logs to safety operations."
  ],
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
  policyName: "Support Assistant Release Governance",
  revision: "3.1",
  effectiveDate: "2026-03-01",
  scope: "EU provider release control",
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

function renderTsGpaiThresholds(draft) {
  return `import { ProofLayer } from "@proof-layer/sdk";

const proofLayer = new ProofLayer({
  vaultUrl: ${q(draft.serviceUrl)},
  appId: "typescript-gpai-example",
  env: "dev",
  systemId: ${q(draft.systemId)},
  role: "provider",
  complianceProfile: ${indent(renderTsComplianceProfile(draft), 2).trimStart()}
});

const training = await proofLayer.captureTrainingProvenance({
  datasetRef: ${q(draft.datasetRef)},
  stage: "pretraining",
  lineageRef: "lineage://${draft.systemId}/2026-03-10",
  computeMetricsRef: "compute-${draft.systemId}-v1",
  trainingDatasetSummary: ${q(draft.trainingDatasetSummary)},
  consortiumContext: ${q(draft.consortiumContext)},
  record: {
    manifests: 28,
    review_owner: ${q(draft.owner)}
  }
});

const compute = await proofLayer.captureComputeMetrics({
  computeId: "compute-${draft.systemId}-v1",
  trainingFlopsEstimate: ${q(draft.trainingFlopsEstimate)},
  thresholdBasisRef: "art51_systemic_risk_threshold",
  thresholdValue: ${q(draft.thresholdValue)},
  thresholdStatus: ${q(draft.thresholdStatus)},
  estimationMethodology: "Cluster scheduler logs and accelerator utilization rollup.",
  measuredAt: "2026-03-10T12:00:00Z",
  computeResourcesSummary: [
    { name: "gpu_hours", value: ${q(draft.gpuHours)}, unit: "hours" },
    { name: "accelerator_count", value: ${q(draft.acceleratorCount)}, unit: "gpus" }
  ],
  consortiumContext: ${q(draft.consortiumContext)},
  metadata: {
    owner: ${q(draft.owner)},
    market: ${q(draft.market)}
  }
});

const pack = await proofLayer.createPack({
  packType: "annex_xi",
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
    legal_basis="GDPR Art. 22 and EU employment-law review safeguards",
    affected_rights=${pretty(splitList(draft.affectedRights))},
    stakeholder_consultation_summary="People operations, legal, and worker-representation stakeholders reviewed the workflow.",
    mitigation_plan_summary="Borderline or negative recommendations require human review and documented justification.",
    assessor=${q(draft.assessor)},
    report={
        "owner": ${q(draft.owner)},
        "finding": ${q(draft.friaSummary)},
    },
    retention_class="technical_doc",
)

oversight = proof_layer.capture_human_oversight(
    action="manual_case_review_required",
    reviewer=${q(draft.reviewer)},
    actor_role="human_reviewer",
    anomaly_detected=False,
    override_action=${q(draft.overrideAction)},
    interpretation_guidance_followed=True,
    automation_bias_detected=False,
    two_person_verification=True,
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
    detection_method="post_market_monitoring",
    root_cause_summary=${q(draft.rootCauseSummary)},
    corrective_action_ref=${q(draft.correctiveActionRef)},
    authority_notification_required=True,
    authority_notification_status="drafted",
    report={
        "owner": ${q(draft.owner)},
        "corrective_action_ref": ${q(draft.correctiveActionRef)},
    },
    retention_class="risk_mgmt",
)

notification = proof_layer.capture_authority_notification(
    notification_id="notif-benefits-42",
    authority=${q(draft.authority)},
    status="drafted",
    incident_id="inc-benefits-42",
    due_at=${q(draft.dueAt)},
    report={"article": "73", "summary": ${q(draft.notificationSummary)}},
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
    case "ts_gpai_thresholds":
      return renderTsGpaiThresholds(draft);
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
