import {
  buildActor,
  buildDocumentArtefact,
  buildLlmInteractionCapture,
  buildSimpleEvidenceCapture,
  buildSubject,
  jsonArtefact,
  serializeComplianceProfile
} from "./captureBuilders";
import { getPlaygroundScenario } from "./sdkPlaygroundScenarios";

function appIdForLane(lane) {
  if (lane === "typescript") {
    return "web-demo-typescript-playground";
  }
  if (lane === "python") {
    return "web-demo-python-playground";
  }
  return "web-demo-proofctl-playground";
}

function baseActor(scenario) {
  return buildActor({
    role: scenario.actorRole,
    appId: appIdForLane(scenario.lane)
  });
}

function baseSubject(draft, suffix, extra = {}) {
  return buildSubject({
    requestId: `req-${draft.systemId}-${suffix}`,
    threadId: `thread-${draft.systemId}-${suffix}`,
    systemId: draft.systemId,
    deploymentId: `${draft.systemId}-demo`,
    ...extra
  });
}

function splitList(value) {
  return String(value ?? "")
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function optionalText(value) {
  const text = String(value ?? "").trim();
  return text || null;
}

function buildMetricSummary(name, value, unit, methodology = null) {
  const normalizedValue = optionalText(value);
  if (!normalizedValue) {
    return null;
  }
  return {
    name,
    value: normalizedValue,
    ...(unit ? { unit } : {}),
    ...(methodology ? { methodology } : {})
  };
}

function compactList(values) {
  return values.filter(Boolean);
}

export function buildPlaygroundComplianceProfile(draft) {
  return {
    intendedUse: draft.intendedUse,
    prohibitedPracticeScreening: draft.prohibitedPracticeScreening,
    riskTier: draft.riskTier,
    highRiskDomain: draft.highRiskDomain,
    gpaiStatus: draft.gpaiStatus,
    systemicRisk: draft.systemicRisk,
    friaRequired: draft.friaRequired,
    deploymentContext: draft.deploymentContext,
    metadata: {
      owner: draft.owner,
      market: draft.market
    }
  };
}

async function buildInteractionStep(scenario, draft, providerResult) {
  return buildLlmInteractionCapture({
    actorRole: scenario.actorRole,
    systemId: draft.systemId,
    providerResult,
    temperature: Number.parseFloat(draft.temperature) || 0.2,
    maxTokens: Number.parseInt(draft.maxTokens, 10) || 256,
    packType: scenario.packType,
    bundleFormat: scenario.bundleFormat,
    disclosureProfile: scenario.disclosureProfile,
    complianceProfile: buildPlaygroundComplianceProfile(draft),
    appId: appIdForLane(scenario.lane)
  });
}

function governedModelId(draft) {
  return `${draft.systemId}-model-v3`;
}

function governedVersion() {
  return "2026.03";
}

async function buildTechnicalDocStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "technical-doc", {
    modelId: governedModelId(draft),
    version: governedVersion()
  });
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const isIncidentResponse = scenario.id === "py_incident_escalation";
  const descriptor = isIncidentResponse
    ? {
        owner: draft.owner,
        document_class: "incident_response_context",
        system_id: draft.systemId,
        release: governedVersion(),
        authority: draft.authority
      }
    : {
        owner: draft.owner,
        document_class: "annex_iv_system_card",
        system_id: draft.systemId,
        release: governedVersion()
      };
  const descriptorArtefact = await buildDocumentArtefact(
    "technical_doc_descriptor.json",
    descriptor,
    "application/json"
  );
  const documentRef = isIncidentResponse
    ? `docs://${draft.systemId}/incident-response-context`
    : `docs://${draft.systemId}/annex-iv-system-card`;
  const section = isIncidentResponse ? "incident_context" : "system_description";
  const annexIvSections = isIncidentResponse
    ? []
    : ["section_2", "section_3", "section_5", "section_7"];
  const systemDescriptionSummary = isIncidentResponse
    ? "Public-sector benefit eligibility workflow with incident triage and regulator-facing escalation controls."
    : "Provider-operated employment-screening assistant for first-pass candidate review in the EU market.";
  const modelDescriptionSummary = isIncidentResponse
    ? `Advisory eligibility review workflow using ${governedModelId(draft)} for case summaries and escalation prompts.`
    : `Structured reviewer support workflow using ${governedModelId(draft)} for candidate summaries and escalation prompts.`;
  const capabilitiesAndLimitations = isIncidentResponse
    ? "Flags incomplete or high-risk cases, but does not finalize benefit determinations."
    : "Summarizes candidate materials and highlights gaps, but does not make autonomous employment decisions.";
  const designChoicesSummary = isIncidentResponse
    ? "Incident-response records capture triage, notification, corrective action, and regulator follow-up in one reviewable file."
    : "The workflow prioritizes explanation, escalation, and review traceability over full automation.";
  const evaluationMetricsSummary = isIncidentResponse
    ? "Appeal-rate, false-negative, and escalation-timeliness checks are reviewed after reportable incidents."
    : "Quarterly fairness, reviewer-agreement, and false-negative checks are tracked in the provider file.";
  const humanOversightDesignSummary = isIncidentResponse
    ? "Human case officers review adverse or borderline recommendations before any public-service outcome is finalized."
    : "Borderline or adverse recommendations route to a human reviewer with documented override controls.";
  const monitoringPlanRef = isIncidentResponse
    ? `incident://${draft.systemId}/triage-playbook-2026-03`
    : `pmm-${draft.systemId}-2026-03`;
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "technical_doc",
      data: {
        document_ref: documentRef,
        section,
        commitment: descriptorArtefact.commitment,
        annex_iv_sections: annexIvSections,
        system_description_summary: systemDescriptionSummary,
        model_description_summary: modelDescriptionSummary,
        capabilities_and_limitations: capabilitiesAndLimitations,
        design_choices_summary: designChoicesSummary,
        evaluation_metrics_summary: evaluationMetricsSummary,
        human_oversight_design_summary: humanOversightDesignSummary,
        post_market_monitoring_plan_ref: monitoringPlanRef
      }
    },
    artefacts: [
      jsonArtefact("technical_doc.json", {
        document_ref: documentRef,
        section,
        annex_iv_sections: annexIvSections,
        system_description_summary: systemDescriptionSummary,
        model_description_summary: modelDescriptionSummary,
        capabilities_and_limitations: capabilitiesAndLimitations,
        design_choices_summary: designChoicesSummary,
        evaluation_metrics_summary: evaluationMetricsSummary,
        human_oversight_design_summary: humanOversightDesignSummary,
        post_market_monitoring_plan_ref: monitoringPlanRef
      }),
      descriptorArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: isIncidentResponse ? "Incident context" : "Technical documentation",
    summary: isIncidentResponse
      ? "Technical context evidence added to the incident-response file."
      : "Annex IV technical documentation evidence captured for the provider file.",
    localPayloads: { descriptor }
  });
}

async function buildRiskAssessmentStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "risk-assessment", {
    modelId: governedModelId(draft),
    version: governedVersion()
  });
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const isIncidentResponse = scenario.id === "py_incident_escalation";
  const record = {
    risk_owner: draft.owner,
    review_cycle: "quarterly",
    reviewer: draft.reviewer
  };
  const summary = isIncidentResponse
    ? "Incident-response risk for adverse public-service recommendations is tracked in the response file."
    : "High-risk employment workflow risk tracked for Annex IV readiness.";
  const riskDescription = isIncidentResponse
    ? "A borderline threshold could over-rely on incomplete evidence and surface adverse recommendations without sufficient escalation."
    : "Candidate summaries could over-weight incomplete or proxy-sensitive profile signals without explicit human review.";
  const affectedGroups = isIncidentResponse
    ? ["benefit_applicants", "case_officers"]
    : ["job_candidates", "recruiters"];
  const mitigationMeasures = isIncidentResponse
    ? [
        "Mandatory manual review for borderline or adverse recommendations.",
        "Escalation to incident operations when an affected person could receive an adverse outcome.",
        "Authority-notification and corrective-action workflow when serious incidents are suspected."
      ]
    : [
        "Mandatory human review before shortlist or rejection actions.",
        "Escalation for low-confidence or incomplete-profile cases.",
        "Quarterly fairness and reviewer-agreement sampling."
      ];
  const testResultsSummary = isIncidentResponse
    ? "Replay and reviewer-agreement checks are acceptable only when the escalation workflow remains active."
    : "Offline validation and reviewer-agreement checks show acceptable performance only when human oversight remains enabled.";
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "risk_assessment",
      data: {
        risk_id: `risk-${draft.systemId}-001`,
        severity: "high",
        status: "mitigated",
        summary,
        risk_description: riskDescription,
        likelihood: "medium",
        affected_groups: affectedGroups,
        mitigation_measures: mitigationMeasures,
        residual_risk_level: "medium",
        risk_owner: draft.owner,
        vulnerable_groups_considered: true,
        test_results_summary: testResultsSummary,
        metadata: {
          owner: draft.owner,
          review_board: draft.reviewer
        }
      }
    },
    artefacts: [
      jsonArtefact("risk_assessment.json", {
        risk_id: `risk-${draft.systemId}-001`,
        severity: "high",
        status: "mitigated",
        summary,
        risk_description: riskDescription,
        likelihood: "medium",
        affected_groups: affectedGroups,
        mitigation_measures: mitigationMeasures,
        residual_risk_level: "medium",
        risk_owner: draft.owner,
        vulnerable_groups_considered: true,
        test_results_summary: testResultsSummary,
        metadata: {
          owner: draft.owner,
          review_board: draft.reviewer
        },
        record
      })
    ],
    retentionClass: "risk_mgmt",
    label: "Risk assessment",
    summary: isIncidentResponse
      ? "Structured risk evidence added to the incident-response file."
      : "Structured risk evidence added to the Annex IV governance set.",
    localPayloads: { record }
  });
}

async function buildInstructionsStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "instructions");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const humanOversightGuidance = splitList(draft.humanOversightGuidance);
  const accuracyMetrics = compactList([
    buildMetricSummary(
      "review_precision",
      "0.91",
      "ratio",
      "Quarterly reviewer agreement sample."
    )
  ]);
  const systemCapabilities = [
    "candidate_summary",
    "qualification_gap_flagging",
    "follow_up_question_suggestions"
  ];
  const foreseeableRisks = [
    "overconfident qualification summaries",
    "missed context for non-linear career paths"
  ];
  const explainabilityCapabilities = [
    "reason_summary",
    "criteria_trace"
  ];
  const computeRequirements = ["4 vCPU", "8GB RAM"];
  const logManagementGuidance = [
    "Retain runtime logs for post-market monitoring reviews.",
    "Escalate incident-linked logs to safety operations."
  ];
  const document = {
    summary: draft.instructionsSummary,
    owner: draft.owner,
    human_oversight_guidance: humanOversightGuidance
  };
  const documentArtefact = await buildDocumentArtefact(
    "instructions_for_use_document.json",
    document,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "instructions_for_use",
      data: {
        document_ref: `docs://${draft.systemId}/operator-handbook`,
        version: "2026.03",
        section: draft.instructionsSection ?? null,
        commitment: documentArtefact.commitment,
        provider_identity: `${draft.owner} provider team`,
        intended_purpose: draft.intendedUse,
        system_capabilities: systemCapabilities,
        accuracy_metrics: accuracyMetrics,
        foreseeable_risks: foreseeableRisks,
        explainability_capabilities: explainabilityCapabilities,
        human_oversight_guidance: humanOversightGuidance,
        compute_requirements: computeRequirements,
        service_lifetime: "Review quarterly or whenever operator rules change.",
        log_management_guidance: logManagementGuidance,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }
    },
    artefacts: [
      documentArtefact.artefact,
      jsonArtefact("instructions_for_use.json", {
        document_ref: `docs://${draft.systemId}/operator-handbook`,
        version: "2026.03",
        section: draft.instructionsSection ?? null,
        provider_identity: `${draft.owner} provider team`,
        intended_purpose: draft.intendedUse,
        system_capabilities: systemCapabilities,
        accuracy_metrics: accuracyMetrics,
        foreseeable_risks: foreseeableRisks,
        explainability_capabilities: explainabilityCapabilities,
        human_oversight_guidance: humanOversightGuidance,
        compute_requirements: computeRequirements,
        service_lifetime: "Review quarterly or whenever operator rules change.",
        log_management_guidance: logManagementGuidance,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      })
    ],
    retentionClass: "technical_doc",
    label: "Instructions for use",
    summary: "Operating-rules evidence captured for this workflow.",
    localPayloads: { document }
  });
}

async function buildDataGovernanceStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "data-governance");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const safeguards = splitList(draft.safeguards);
  const biasMetrics = compactList([
    buildMetricSummary(
      "selection_rate_gap",
      "0.04",
      "ratio",
      optionalText(draft.biasMethodology)
    )
  ]);
  const record = {
    review_owner: draft.owner,
    safeguards,
    source_description: draft.sourceDescription
  };
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "data_governance",
      data: {
        decision: "approved_with_restrictions",
        dataset_ref: `dataset://${draft.systemId}/training`,
        dataset_name: draft.datasetName ?? null,
        dataset_version: draft.datasetVersion ?? "2026.03",
        source_description: draft.sourceDescription ?? null,
        collection_period: {
          start: "2024-01-01",
          end: "2025-12-31"
        },
        geographical_scope: ["EU"],
        preprocessing_operations: ["deduplication", "pseudonymization", "label_review"],
        bias_detection_methodology: draft.biasMethodology ?? null,
        bias_metrics: biasMetrics,
        mitigation_actions: [
          "Escalate sensitive employment actions to human review.",
          "Sample multilingual candidate summaries for quality assurance."
        ],
        data_gaps: ["Limited historic examples for non-linear career paths."],
        personal_data_categories: ["cv_data", "employment_history"],
        safeguards,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }
    },
    artefacts: [
      jsonArtefact("data_governance.json", {
        decision: "approved_with_restrictions",
        dataset_ref: `dataset://${draft.systemId}/training`,
        dataset_name: draft.datasetName ?? null,
        dataset_version: draft.datasetVersion ?? "2026.03",
        source_description: draft.sourceDescription ?? null,
        collection_period: {
          start: "2024-01-01",
          end: "2025-12-31"
        },
        geographical_scope: ["EU"],
        preprocessing_operations: ["deduplication", "pseudonymization", "label_review"],
        bias_detection_methodology: draft.biasMethodology ?? null,
        bias_metrics: biasMetrics,
        mitigation_actions: [
          "Escalate sensitive employment actions to human review.",
          "Sample multilingual candidate summaries for quality assurance."
        ],
        data_gaps: ["Limited historic examples for non-linear career paths."],
        personal_data_categories: ["cv_data", "employment_history"],
        safeguards,
        metadata: {
          owner: draft.owner,
          market: draft.market
        },
        record
      })
    ],
    retentionClass: "technical_doc",
    label: "Data governance",
    summary: "Structured dataset and bias-governance evidence added to the provider file.",
    localPayloads: { record }
  });
}

async function buildQmsRecordStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "qms");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const record = {
    approver: draft.qmsApprover,
    gate: "release",
    release: "2026.03"
  };
  const approval = {
    approver: draft.qmsApprover,
    approved_at: "2026-03-01T09:00:00Z",
    release: "2026.03"
  };
  const recordArtefact = await buildDocumentArtefact(
    "qms_record_record.json",
    record,
    "application/json"
  );
  const approvalArtefact = await buildDocumentArtefact(
    "qms_record_approval.json",
    approval,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "qms_record",
      data: {
        record_id: `qms-${draft.systemId}-release-42`,
        process: "release_approval",
        status: draft.qmsStatus ?? "approved",
        record_commitment: recordArtefact.commitment,
        policy_name: "Hiring Assistant Release Governance",
        revision: "3.1",
        effective_date: "2026-03-01",
        scope: "EU provider release control",
        approval_commitment: approvalArtefact.commitment,
        audit_results_summary:
          "No blocking findings. Quarterly oversight-quality review requested before broader rollout.",
        continuous_improvement_actions: [
          "Extend fairness review coverage for non-linear career histories.",
          "Refresh recruiter guidance before the next release."
        ],
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("qms_record.json", {
        record_id: `qms-${draft.systemId}-release-42`,
        process: "release_approval",
        status: draft.qmsStatus ?? "approved",
        policy_name: "Hiring Assistant Release Governance",
        revision: "3.1",
        effective_date: "2026-03-01",
        scope: "EU provider release control",
        approval_commitment: approvalArtefact.commitment,
        audit_results_summary:
          "No blocking findings. Quarterly oversight-quality review requested before broader rollout.",
        continuous_improvement_actions: [
          "Extend fairness review coverage for non-linear career histories.",
          "Refresh recruiter guidance before the next release."
        ],
        metadata: {
          owner: draft.owner
        }
      }),
      recordArtefact.artefact,
      approvalArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: "QMS record",
    summary: "Quality sign-off evidence added to the workflow.",
    localPayloads: { record, approval }
  });
}

async function buildStandardsAlignmentStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "standards-alignment", {
    modelId: governedModelId(draft),
    version: governedVersion()
  });
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const mapping = {
    owner: draft.owner,
    mappings: [
      { clause: "governance", evidence: "qms_record" },
      { clause: "risk_management", evidence: "risk_assessment" },
      { clause: "monitoring", evidence: "post_market_monitoring" }
    ]
  };
  const mappingArtefact = await buildDocumentArtefact(
    "standards_alignment_mapping.json",
    mapping,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "standards_alignment",
      data: {
        standard_ref: "EN ISO/IEC 42001:2023",
        status: "aligned_with_internal_controls",
        scope: `Provider governance process for ${draft.systemId}`,
        mapping_commitment: mappingArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("standards_alignment.json", {
        standard_ref: "EN ISO/IEC 42001:2023",
        status: "aligned_with_internal_controls",
        scope: `Provider governance process for ${draft.systemId}`,
        metadata: {
          owner: draft.owner
        }
      }),
      mappingArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: "Standards alignment",
    summary: "Standards-mapping evidence added to the governance pack.",
    localPayloads: { mapping }
  });
}

async function buildPostMarketMonitoringStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "monitoring");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const report = {
    cadence: "weekly",
    owner: draft.owner,
    metrics: ["false_negative_rate", "appeal_rate"]
  };
  const reportArtefact = await buildDocumentArtefact(
    "post_market_monitoring_report.json",
    report,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "post_market_monitoring",
      data: {
        plan_id: `pmm-${draft.systemId}-2026-03`,
        status: "active",
        summary: draft.monitoringSummary,
        report_commitment: reportArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("post_market_monitoring.json", {
        plan_id: `pmm-${draft.systemId}-2026-03`,
        status: "active",
        summary: draft.monitoringSummary,
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Post-market monitoring",
    summary: "Monitoring plan evidence added to the pack.",
    localPayloads: { report }
  });
}

async function buildAuthoritySubmissionStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "authority-submission");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const isIncidentResponse = scenario.id === "py_incident_escalation";
  const document = {
    article: "73",
    summary: draft.submissionSummary
  };
  const documentArtefact = await buildDocumentArtefact(
    "authority_submission_document.json",
    document,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "authority_submission",
      data: {
        submission_id: isIncidentResponse ? "sub-benefits-42" : "sub-claims-42",
        authority: draft.authority,
        status: "submitted",
        channel: "portal",
        submitted_at: isIncidentResponse ? "2026-03-08T09:45:00Z" : "2026-03-08T09:30:00Z",
        document_commitment: documentArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("authority_submission.json", {
        submission_id: isIncidentResponse ? "sub-benefits-42" : "sub-claims-42",
        authority: draft.authority,
        status: "submitted",
        channel: "portal",
        submitted_at: isIncidentResponse ? "2026-03-08T09:45:00Z" : "2026-03-08T09:30:00Z",
        metadata: {
          owner: draft.owner
        }
      }),
      documentArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Authority submission",
    summary: isIncidentResponse
      ? "Regulator submission evidence added to the incident-response file."
      : "Regulator submission evidence added to the monitoring pack.",
    localPayloads: { document }
  });
}

async function buildCorrectiveActionStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "corrective-action");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const isIncidentResponse = scenario.id === "py_incident_escalation";
  const record = {
    incident_id: "inc-benefits-42",
    owner: draft.owner,
    change: draft.correctiveActionSummary
  };
  const recordArtefact = await buildDocumentArtefact(
    "corrective_action_record.json",
    record,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "corrective_action",
      data: {
        action_id: draft.correctiveActionRef ?? "ca-benefits-42",
        status: "in_progress",
        summary: draft.correctiveActionSummary,
        due_at: draft.dueAt,
        record_commitment: recordArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("corrective_action.json", {
        action_id: draft.correctiveActionRef ?? "ca-benefits-42",
        status: "in_progress",
        summary: draft.correctiveActionSummary,
        due_at: draft.dueAt,
        metadata: {
          owner: draft.owner
        }
      }),
      recordArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Corrective action",
    summary: isIncidentResponse
      ? "Corrective action evidence added to the incident-response file."
      : "Corrective action evidence added to the monitoring pack.",
    localPayloads: { record }
  });
}

async function buildFriaStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "fria");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const affectedRights = splitList(draft.affectedRights);
  const report = {
    owner: draft.owner,
    finding: draft.friaSummary,
    assessor: draft.assessor,
    affected_rights: affectedRights
  };
  const reportArtefact = await buildDocumentArtefact(
    "fundamental_rights_assessment_report.json",
    report,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "fundamental_rights_assessment",
      data: {
        assessment_id: "fria-2026-03",
        status: "completed",
        scope: draft.intendedUse,
        report_commitment: reportArtefact.commitment,
        legal_basis: "GDPR Art. 22 and EU employment-law review safeguards",
        affected_rights: affectedRights,
        stakeholder_consultation_summary:
          "People operations, legal, and worker-representation stakeholders reviewed the workflow.",
        mitigation_plan_summary:
          "Borderline or negative recommendations require human review and documented justification.",
        assessor: draft.assessor ?? null,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("fundamental_rights_assessment.json", {
        assessment_id: "fria-2026-03",
        status: "completed",
        scope: draft.intendedUse,
        legal_basis: "GDPR Art. 22 and EU employment-law review safeguards",
        affected_rights: affectedRights,
        stakeholder_consultation_summary:
          "People operations, legal, and worker-representation stakeholders reviewed the workflow.",
        mitigation_plan_summary:
          "Borderline or negative recommendations require human review and documented justification.",
        assessor: draft.assessor ?? null,
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: "Fundamental rights assessment",
    summary: "Fundamental-rights assessment evidence added to the hiring review workflow.",
    localPayloads: { report }
  });
}

async function buildHumanOversightStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "human-oversight");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const isIncidentResponse = scenario.id === "py_incident_escalation";
  const notes = isIncidentResponse
    ? {
        incident_summary: draft.incidentSummary,
        root_cause_summary: draft.rootCauseSummary,
        reviewer: draft.reviewer,
        override_action: "route_to_manual_review",
        sla_hours: 24
      }
    : {
        reason: draft.friaSummary,
        reviewer: draft.reviewer,
        override_action: draft.overrideAction,
        sla_hours: 24
      };
  const notesArtefact = await buildDocumentArtefact(
    "human_oversight_notes.json",
    notes,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "human_oversight",
      data: {
        action: "manual_case_review_required",
        reviewer: draft.reviewer,
        notes_commitment: notesArtefact.commitment,
        actor_role: isIncidentResponse ? "case_reviewer" : "human_reviewer",
        anomaly_detected: isIncidentResponse,
        override_action: isIncidentResponse
          ? "route_to_manual_review"
          : draft.overrideAction ?? null,
        interpretation_guidance_followed: true,
        automation_bias_detected: false,
        two_person_verification: !isIncidentResponse,
        stop_triggered: false,
        stop_reason: isIncidentResponse
          ? "Human escalation handled the affected public-service case without a global stop."
          : null
      }
    },
    artefacts: [
      jsonArtefact("human_oversight.json", {
        action: "manual_case_review_required",
        reviewer: draft.reviewer,
        actor_role: isIncidentResponse ? "case_reviewer" : "human_reviewer",
        anomaly_detected: isIncidentResponse,
        override_action: isIncidentResponse
          ? "route_to_manual_review"
          : draft.overrideAction ?? null,
        interpretation_guidance_followed: true,
        automation_bias_detected: false,
        two_person_verification: !isIncidentResponse,
        stop_triggered: false,
        stop_reason: isIncidentResponse
          ? "Human escalation handled the affected public-service case without a global stop."
          : null
      }),
      notesArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Human oversight",
    summary: isIncidentResponse
      ? "Human-oversight evidence added to the incident-response file."
      : "Human review evidence added to the hiring review workflow.",
    localPayloads: { notes }
  });
}

async function buildPolicyDecisionStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "policy-decision");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const rationale = {
    incident_summary: draft.incidentSummary,
    notification_summary: draft.notificationSummary,
    authority: draft.authority,
    owner: draft.owner
  };
  const rationaleArtefact = await buildDocumentArtefact(
    "policy_decision_rationale.json",
    rationale,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "policy_decision",
      data: {
        policy_name: "incident_reportability_triage",
        decision: "notify_and_continue_manual_review",
        rationale_commitment: rationaleArtefact.commitment,
        metadata: {
          article: "73",
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("policy_decision.json", {
        policy_name: "incident_reportability_triage",
        decision: "notify_and_continue_manual_review",
        metadata: {
          article: "73",
          owner: draft.owner
        }
      }),
      rationaleArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Triage decision",
    summary: "Reportability and escalation decision evidence added to the incident-response file.",
    localPayloads: { rationale }
  });
}

async function buildIncidentReportStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "incident");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const detectionMethod =
    scenario.id === "py_incident_escalation"
      ? "human_review_escalation"
      : "post_market_monitoring";
  const report = {
    owner: draft.owner,
    summary: draft.incidentSummary,
    root_cause_summary: draft.rootCauseSummary,
    corrective_action_ref: draft.correctiveActionRef
  };
  const reportArtefact = await buildDocumentArtefact(
    "incident_report_record.json",
    report,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "incident_report",
      data: {
        incident_id: "inc-benefits-42",
        severity: "serious",
        status: "open",
        occurred_at: "2026-03-07T18:30:00Z",
        summary: draft.incidentSummary,
        report_commitment: reportArtefact.commitment,
        detection_method: detectionMethod,
        root_cause_summary: draft.rootCauseSummary ?? null,
        corrective_action_ref: draft.correctiveActionRef ?? null,
        authority_notification_required: true,
        authority_notification_status: "drafted",
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("incident_report.json", {
        incident_id: "inc-benefits-42",
        severity: "serious",
        status: "open",
        occurred_at: "2026-03-07T18:30:00Z",
        summary: draft.incidentSummary,
        detection_method: detectionMethod,
        root_cause_summary: draft.rootCauseSummary ?? null,
        corrective_action_ref: draft.correctiveActionRef ?? null,
        authority_notification_required: true,
        authority_notification_status: "drafted",
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Incident report",
    summary:
      scenario.id === "py_incident_escalation"
        ? "Initial serious-incident evidence captured for the incident-response file."
        : "Initial serious-incident evidence captured for follow-up.",
    localPayloads: { report }
  });
}

async function buildAuthorityNotificationStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "authority-notification");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const report = {
    article: "73",
    summary: draft.notificationSummary ?? "Initial authority notification draft"
  };
  const reportArtefact = await buildDocumentArtefact(
    "authority_notification_report.json",
    report,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "authority_notification",
      data: {
        notification_id: "notif-benefits-42",
        authority: draft.authority,
        status: "drafted",
        incident_id: "inc-benefits-42",
        due_at: draft.dueAt,
        report_commitment: reportArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("authority_notification.json", {
        notification_id: "notif-benefits-42",
        authority: draft.authority,
        status: "drafted",
        incident_id: "inc-benefits-42",
        due_at: draft.dueAt,
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Authority notification",
    summary: "Notification draft captured for the incident response pack.",
    localPayloads: { report }
  });
}

async function buildTrainingProvenanceStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "training-provenance");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const record = {
    manifests: 28,
    review_owner: draft.owner
  };
  const recordArtefact = await buildDocumentArtefact(
    "training_provenance_record.json",
    record,
    "application/json"
  );
  const computeId = `compute-${draft.systemId}-v1`;
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "training_provenance",
      data: {
        dataset_ref: draft.datasetRef,
        stage: "pretraining",
        lineage_ref: `lineage://${draft.systemId}/2026-03-10`,
        record_commitment: recordArtefact.commitment,
        compute_metrics_ref: computeId,
        training_dataset_summary: draft.trainingDatasetSummary ?? null,
        consortium_context: draft.consortiumContext ?? null,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }
    },
    artefacts: [
      jsonArtefact("training_provenance.json", {
        dataset_ref: draft.datasetRef,
        stage: "pretraining",
        lineage_ref: `lineage://${draft.systemId}/2026-03-10`,
        compute_metrics_ref: computeId,
        training_dataset_summary: draft.trainingDatasetSummary ?? null,
        consortium_context: draft.consortiumContext ?? null,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }),
      recordArtefact.artefact
    ],
    retentionClass: "gpai_documentation",
    label: "Training provenance",
    summary: "Training-lineage evidence added to the GPAI provider workflow.",
    localPayloads: { record }
  });
}

async function buildComputeMetricsStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "compute-metrics");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const computeId = `compute-${draft.systemId}-v1`;
  const computeResourcesSummary = compactList([
    buildMetricSummary("gpu_hours", draft.gpuHours, "hours"),
    buildMetricSummary("accelerator_count", draft.acceleratorCount, "gpus")
  ]);
  const record = {
    source: "web-demo-sample",
    rollup_owner: draft.owner
  };
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "compute_metrics",
      data: {
        compute_id: computeId,
        training_flops_estimate: draft.trainingFlopsEstimate,
        threshold_basis_ref: "art51_systemic_risk_threshold",
        threshold_value: draft.thresholdValue,
        threshold_status: draft.thresholdStatus,
        estimation_methodology: "Cluster scheduler logs and accelerator utilization rollup.",
        measured_at: "2026-03-10T12:00:00Z",
        compute_resources_summary: computeResourcesSummary,
        consortium_context: draft.consortiumContext ?? null,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }
    },
    artefacts: [
      jsonArtefact("compute_metrics.json", {
        compute_id: computeId,
        training_flops_estimate: draft.trainingFlopsEstimate,
        threshold_basis_ref: "art51_systemic_risk_threshold",
        threshold_value: draft.thresholdValue,
        threshold_status: draft.thresholdStatus,
        estimation_methodology: "Cluster scheduler logs and accelerator utilization rollup.",
        measured_at: "2026-03-10T12:00:00Z",
        compute_resources_summary: computeResourcesSummary,
        consortium_context: draft.consortiumContext ?? null,
        metadata: {
          owner: draft.owner,
          market: draft.market
        },
        record
      })
    ],
    retentionClass: "gpai_documentation",
    label: "Compute metrics",
    summary: "Compute-threshold evidence added to the GPAI provider workflow.",
    localPayloads: { record }
  });
}

async function buildReportingDeadlineStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "reporting-deadline");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "reporting_deadline",
      data: {
        deadline_id: "deadline-benefits-42",
        authority: draft.authority,
        obligation_ref: "art73_notification",
        due_at: draft.dueAt,
        status: "open",
        incident_id: "inc-benefits-42",
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("reporting_deadline.json", {
        deadline_id: "deadline-benefits-42",
        authority: draft.authority,
        obligation_ref: "art73_notification",
        due_at: draft.dueAt,
        status: "open",
        incident_id: "inc-benefits-42",
        metadata: {
          owner: draft.owner
        }
      })
    ],
    retentionClass: "risk_mgmt",
    label: "Reporting deadline",
    summary: "Deadline tracking evidence added to the incident response pack."
  });
}

async function buildRegulatorCorrespondenceStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "correspondence");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const message = {
    subject: draft.correspondenceSubject,
    reference: "inc-benefits-42"
  };
  const messageArtefact = await buildDocumentArtefact(
    "regulator_correspondence_message.json",
    message,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "regulator_correspondence",
      data: {
        correspondence_id: "corr-benefits-42",
        authority: draft.authority,
        direction: "outbound",
        status: "sent",
        occurred_at: "2026-03-08T10:00:00Z",
        message_commitment: messageArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("regulator_correspondence.json", {
        correspondence_id: "corr-benefits-42",
        authority: draft.authority,
        direction: "outbound",
        status: "sent",
        occurred_at: "2026-03-08T10:00:00Z",
        metadata: {
          owner: draft.owner
        }
      }),
      messageArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Regulator correspondence",
    summary:
      scenario.id === "py_incident_escalation"
        ? "Follow-up correspondence evidence added to the incident-response file."
        : "Follow-up correspondence evidence added to the incident pack.",
    localPayloads: { message }
  });
}

const STEP_BUILDERS = {
  technical_doc: buildTechnicalDocStep,
  risk_assessment: buildRiskAssessmentStep,
  data_governance: buildDataGovernanceStep,
  instructions_for_use: buildInstructionsStep,
  qms_record: buildQmsRecordStep,
  standards_alignment: buildStandardsAlignmentStep,
  post_market_monitoring: buildPostMarketMonitoringStep,
  corrective_action: buildCorrectiveActionStep,
  authority_submission: buildAuthoritySubmissionStep,
  fundamental_rights_assessment: buildFriaStep,
  human_oversight: buildHumanOversightStep,
  incident_report: buildIncidentReportStep,
  policy_decision: buildPolicyDecisionStep,
  authority_notification: buildAuthorityNotificationStep,
  training_provenance: buildTrainingProvenanceStep,
  compute_metrics: buildComputeMetricsStep,
  reporting_deadline: buildReportingDeadlineStep,
  regulator_correspondence: buildRegulatorCorrespondenceStep
};

export async function buildScenarioWorkflow(scenarioInput, draft, providerResult = null) {
  const scenario =
    typeof scenarioInput === "string"
      ? getPlaygroundScenario(scenarioInput)
      : scenarioInput;
  const steps = [];
  for (const step of scenario.steps) {
    if (step.kind === "interaction") {
      steps.push({
        ...(await buildInteractionStep(scenario, draft, providerResult)),
        bundleRole: step.bundleRole,
        stepId: step.id
      });
      continue;
    }
    const builder = STEP_BUILDERS[step.itemType];
    if (!builder) {
      throw new Error(`No workflow builder registered for ${step.itemType}`);
    }
    steps.push({
      ...(await builder(scenario, draft)),
      bundleRole: step.bundleRole,
      stepId: step.id
    });
  }
  return steps;
}
