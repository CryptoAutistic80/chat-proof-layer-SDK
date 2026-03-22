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
  appId: "typescript-annex-iv-example",
  env: "dev",
  systemId: ${q(draft.systemId)},
  role: "provider",
  complianceProfile: ${indent(renderTsComplianceProfile(draft), 2).trimStart()}
});

const technicalDoc = await proofLayer.captureTechnicalDoc({
  documentRef: "docs://${draft.systemId}/annex-iv-system-card",
  section: "system_description",
  annexIvSections: ["section_2", "section_3", "section_5", "section_7"],
  systemDescriptionSummary:
    "Provider-operated employment-screening assistant for first-pass candidate review in the EU market.",
  modelDescriptionSummary:
    "Structured reviewer support workflow with mandatory human oversight before any adverse decision.",
  capabilitiesAndLimitations:
    "Summarizes candidate materials and highlights gaps, but does not make autonomous employment decisions.",
  designChoicesSummary:
    "The workflow prioritizes explanation, escalation, and review traceability over full automation.",
  evaluationMetricsSummary:
    "Quarterly fairness, reviewer-agreement, and false-negative checks are tracked in the provider file.",
  humanOversightDesignSummary:
    "Borderline or adverse recommendations route to a human reviewer with documented override controls.",
  postMarketMonitoringPlanRef: "pmm-${draft.systemId}-2026-03",
  descriptor: {
    owner: ${q(draft.owner)},
    document_class: "annex_iv_system_card"
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "technical_doc"
});

const riskAssessment = await proofLayer.captureRiskAssessment({
  riskId: "risk-${draft.systemId}-001",
  severity: "high",
  status: "mitigated",
  summary: "High-risk employment workflow risk tracked for Annex IV readiness.",
  riskDescription:
    "Candidate summaries could over-weight incomplete or proxy-sensitive profile signals without explicit human review.",
  likelihood: "medium",
  affectedGroups: ["job_candidates", "recruiters"],
  mitigationMeasures: [
    "Mandatory human review before shortlist or rejection actions.",
    "Escalation for low-confidence or incomplete-profile cases.",
    "Quarterly fairness and reviewer-agreement sampling."
  ],
  residualRiskLevel: "medium",
  riskOwner: ${q(draft.owner)},
  vulnerableGroupsConsidered: true,
  testResultsSummary:
    "Offline validation and reviewer-agreement checks show acceptable performance only when human oversight remains enabled.",
  metadata: {
    owner: ${q(draft.owner)},
    review_board: ${q(draft.reviewer)}
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "risk_mgmt"
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
  preprocessingOperations: ["deduplication", "pseudonymization", "label_review"],
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
    "Escalate sensitive employment actions to human review.",
    "Sample multilingual candidate summaries for quality assurance."
  ],
  dataGaps: ["Limited historic examples for non-linear career paths."],
  personalDataCategories: ["cv_data", "employment_history"],
  safeguards: ${pretty(splitList(draft.safeguards))},
  metadata: {
    owner: ${q(draft.owner)},
    market: ${q(draft.market)}
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "technical_doc"
});

const instructions = await proofLayer.captureInstructionsForUse({
  documentRef: "docs://${draft.systemId}/operator-handbook",
  versionTag: "2026.03",
  section: ${q(draft.instructionsSection)},
  providerIdentity: ${q(`${draft.owner} provider team`)},
  intendedPurpose: ${q(draft.intendedUse)},
  systemCapabilities: [
    "candidate_summary",
    "qualification_gap_flagging",
    "follow_up_question_suggestions"
  ],
  accuracyMetrics: [{ name: "review_precision", value: "0.91", unit: "ratio" }],
  foreseeableRisks: [
    "overconfident qualification summaries",
    "missed context for non-linear career paths"
  ],
  explainabilityCapabilities: ["reason_summary", "criteria_trace"],
  humanOversightGuidance: ${pretty(splitList(draft.humanOversightGuidance))},
  computeRequirements: ["4 vCPU", "8GB RAM"],
  serviceLifetime: "Review quarterly or whenever operator rules change.",
  logManagementGuidance: [
    "Retain runtime logs for post-market monitoring reviews.",
    "Escalate incident-linked logs to safety operations."
  ],
  metadata: {
    distribution: "internal_reviewer_only"
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "technical_doc"
});

const humanOversight = await proofLayer.captureHumanOversight({
  action: "manual_case_review_required",
  reviewer: ${q(draft.reviewer)},
  actorRole: "human_reviewer",
  anomalyDetected: false,
  overrideAction: "Route borderline cases to manual review queue.",
  interpretationGuidanceFollowed: true,
  automationBiasDetected: false,
  twoPersonVerification: true,
  stopTriggered: false,
  stopReason: null,
  notes: {
    escalation_path: "quality-panel",
    sla_hours: 24
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "risk_mgmt"
});

const qmsRecord = await proofLayer.captureQmsRecord({
  recordId: "qms-${draft.systemId}-release-42",
  process: "release_approval",
  status: "approved",
  policyName: "Hiring Assistant Release Governance",
  revision: "3.1",
  effectiveDate: "2026-03-01",
  scope: "EU provider release control",
  auditResultsSummary:
    "No blocking findings. Quarterly oversight-quality review requested before broader rollout.",
  continuousImprovementActions: [
    "Extend fairness review coverage for non-linear career histories.",
    "Refresh recruiter guidance before the next release."
  ],
  metadata: {
    owner: ${q(draft.owner)}
  },
  record: {
    approver: ${q(draft.qmsApprover)},
    release: "2026.03"
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "technical_doc"
});

const standardsAlignment = await proofLayer.captureStandardsAlignment({
  standardRef: "EN ISO/IEC 42001:2023",
  status: "aligned_with_internal_controls",
  scope: "Provider governance process for ${draft.systemId}",
  metadata: {
    owner: ${q(draft.owner)}
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "technical_doc"
});

const postMarketMonitoring = await proofLayer.capturePostMarketMonitoring({
  planId: "pmm-${draft.systemId}-2026-03",
  status: "active",
  summary: ${q(draft.monitoringSummary)},
  metadata: {
    owner: ${q(draft.owner)}
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "risk_mgmt"
});

const preview = await proofLayer.previewDisclosure({
  bundleId: dataGovernance.bundleId,
  packType: "annex_iv",
  disclosurePolicy: "annex_iv_redacted"
});

const fullPack = await proofLayer.createPack({
  packType: "annex_iv",
  systemId: ${q(draft.systemId)},
  bundleFormat: "full"
});

const disclosurePack = await proofLayer.createPack({
  packType: "annex_iv",
  systemId: ${q(draft.systemId)},
  bundleFormat: "disclosure",
  disclosurePolicy: "annex_iv_redacted"
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

const technicalDoc = await proofLayer.captureTechnicalDoc({
  documentRef: "docs://${draft.systemId}/gpai-provider-overview",
  section: "provider_overview",
  annexIvSections: ["annex_xi_section_1", "annex_xi_section_2"],
  systemDescriptionSummary:
    "General-purpose text and workflow assistance model offered by the provider for EU market placement and downstream integration.",
  modelDescriptionSummary:
    "Foundation-model provider workflow for multilingual text generation and downstream enterprise assistance use cases.",
  capabilitiesAndLimitations:
    "Supports broad text and workflow tasks, but threshold tracking, evaluation coverage, and downstream documentation still govern safe release and use.",
  designChoicesSummary:
    "The provider file emphasizes lineage traceability, compute-threshold tracking, model evaluation, and publishable transparency outputs.",
  evaluationMetricsSummary:
    "Capability, multilingual quality, and policy-adherence metrics are reviewed before release and whenever material training updates occur.",
  humanOversightDesignSummary:
    "Provider release review gates publish model updates only after documented evaluation, threshold, and policy checks are complete.",
  postMarketMonitoringPlanRef: "gpai://${draft.systemId}/provider-monitoring-2026-03",
  descriptor: {
    owner: ${q(draft.owner)},
    document_class: "gpai_provider_system_card"
  },
  modelId: "${draft.systemId}-model-v3",
  version: "2026.03",
  retentionClass: "gpai_documentation"
});

const evaluation = await proofLayer.captureModelEvaluation({
  evaluationId: "eval-${draft.systemId}-provider-2026-03",
  benchmark: "gpai_provider_release_suite",
  status: "passed_with_follow_up",
  summary:
    "Pre-release GPAI provider evaluation covered multilingual capability, policy adherence, and threshold-sensitive release checks.",
  metricsSummary: [
    { name: "instruction_following", value: "0.91", unit: "score" },
    { name: "policy_adherence", value: "0.97", unit: "score" },
    { name: "multilingual_quality", value: "0.88", unit: "score" }
  ],
  groupPerformance: [
    { group: "en", summary: "Stable quality across enterprise help-desk and drafting tasks." },
    { group: "fr_de_es", summary: "Slightly lower quality, but within release threshold." }
  ],
  evaluationMethodology:
    "Combination of scripted benchmark runs, reviewer spot checks, and release-gate policy tests.",
  report: {
    owner: ${q(draft.owner)},
    benchmark_suite: "gpai-provider-eval-2026-03",
    release: "2026.03"
  },
  metadata: {
    owner: ${q(draft.owner)},
    market: ${q(draft.market)}
  }
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

const copyrightPolicy = await proofLayer.captureCopyrightPolicy({
  policyRef: "policy://${draft.systemId}/copyright-compliance",
  status: "approved",
  jurisdiction: "EU",
  document: {
    owner: ${q(draft.owner)},
    policy_version: "2026.03",
    review_cycle: "quarterly"
  },
  metadata: {
    owner: ${q(draft.owner)},
    market: ${q(draft.market)}
  }
});

const trainingSummary = await proofLayer.captureTrainingSummary({
  summaryRef: "summary://${draft.systemId}/training-2026-03",
  status: "published",
  audience: "public",
  document: {
    owner: ${q(draft.owner)},
    publication_status: "ready_for_release",
    dataset_summary: ${q(draft.trainingDatasetSummary)}
  },
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

technical_doc = proof_layer.capture_technical_doc(
    document_ref=${q(`docs://${draft.systemId}/incident-response-context`)},
    section="incident_context",
    descriptor={
        "owner": ${q(draft.owner)},
        "document_class": "incident_response_context",
        "system_id": ${q(draft.systemId)},
        "authority": ${q(draft.authority)},
    },
    system_description_summary="Public-sector benefit eligibility workflow with incident triage and regulator-facing escalation controls.",
    model_description_summary=${q(`Advisory eligibility review workflow using ${draft.provider}:${draft.model} for case summaries and escalation prompts.`)},
    capabilities_and_limitations="Flags incomplete or high-risk cases, but does not finalize benefit determinations.",
    design_choices_summary="Incident-response records capture triage, notification, corrective action, and regulator follow-up in one reviewable file.",
    evaluation_metrics_summary="Appeal-rate, false-negative, and escalation-timeliness checks are reviewed after reportable incidents.",
    human_oversight_design_summary="Human case officers review adverse or borderline recommendations before any public-service outcome is finalized.",
    post_market_monitoring_plan_ref=${q(`incident://${draft.systemId}/triage-playbook-2026-03`)},
    simplified_tech_doc=True,
    retention_class="technical_doc",
)

risk = proof_layer.capture_risk_assessment(
    risk_id=${q(`risk-${draft.systemId}-001`)},
    severity="high",
    status="mitigated",
    summary="Incident-response risk for adverse public-service recommendations is tracked in the response file.",
    risk_description="A borderline threshold could over-rely on incomplete evidence and surface adverse recommendations without sufficient escalation.",
    likelihood="medium",
    affected_groups=["benefit_applicants", "case_officers"],
    mitigation_measures=[
        "Mandatory manual review for borderline or adverse recommendations.",
        "Escalation to incident operations when an affected person could receive an adverse outcome.",
        "Authority-notification and corrective-action workflow when serious incidents are suspected.",
    ],
    residual_risk_level="medium",
    risk_owner=${q(draft.owner)},
    vulnerable_groups_considered=True,
    test_results_summary="Replay and reviewer-agreement checks are acceptable only when the escalation workflow remains active.",
    record={"review_cycle": "quarterly", "reviewer": "rights-review-team"},
    retention_class="risk_mgmt",
)

oversight = proof_layer.capture_human_oversight(
    action="manual_case_review_required",
    reviewer="rights-panel",
    notes={
        "incident_summary": ${q(draft.incidentSummary)},
        "root_cause_summary": ${q(draft.rootCauseSummary)},
        "override_action": "route_to_manual_review",
    },
    actor_role="case_reviewer",
    anomaly_detected=True,
    override_action="route_to_manual_review",
    interpretation_guidance_followed=True,
    automation_bias_detected=False,
    two_person_verification=False,
    stop_triggered=False,
    stop_reason="Human escalation handled the affected public-service case without a global stop.",
    retention_class="risk_mgmt",
)

triage_decision = proof_layer.capture_policy_decision(
    policy_name="incident_reportability_triage",
    decision="notify_and_continue_manual_review",
    rationale={
        "authority": ${q(draft.authority)},
        "notification_summary": ${q(draft.notificationSummary)},
        "owner": ${q(draft.owner)},
    },
    metadata={"article": "73", "owner": ${q(draft.owner)}},
    retention_class="risk_mgmt",
)

incident = proof_layer.capture_incident_report(
    incident_id="inc-benefits-42",
    severity="serious",
    status="open",
    occurred_at="2026-03-07T18:30:00Z",
    summary=${q(draft.incidentSummary)},
    detection_method="human_review_escalation",
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
)

readiness = proof_layer.evaluate_completeness(
    pack_id=pack["pack_id"],
    profile="incident_response_v1",
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
