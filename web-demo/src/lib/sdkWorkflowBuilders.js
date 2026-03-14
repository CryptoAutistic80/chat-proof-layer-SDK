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

async function buildInstructionsStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "instructions");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const document = {
    summary: draft.instructionsSummary,
    owner: draft.owner
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
        document_ref: "docs://hiring-assistant/operator-handbook",
        version: "2026.03",
        section: draft.instructionsSection ?? null,
        commitment: documentArtefact.commitment,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      }
    },
    artefacts: [
      documentArtefact.artefact,
      jsonArtefact("instructions_for_use.json", {
        document_ref: "docs://hiring-assistant/operator-handbook",
        version: "2026.03",
        section: draft.instructionsSection ?? null,
        metadata: {
          owner: draft.owner,
          market: draft.market
        }
      })
    ],
    retentionClass: "technical_doc",
    label: "Instructions for use",
    summary: "Operator handbook evidence captured for the governance pack.",
    localPayloads: { document }
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
  const recordArtefact = await buildDocumentArtefact(
    "qms_record_record.json",
    record,
    "application/json"
  );
  return buildSimpleEvidenceCapture({
    actor,
    subject,
    complianceProfile,
    item: {
      type: "qms_record",
      data: {
        record_id: "qms-release-approval-42",
        process: "release_approval",
        status: draft.qmsStatus ?? "approved",
        record_commitment: recordArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("qms_record.json", {
        record_id: "qms-release-approval-42",
        process: "release_approval",
        status: draft.qmsStatus ?? "approved",
        metadata: {
          owner: draft.owner
        }
      }),
      recordArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: "QMS record",
    summary: "Release approval evidence added to the provider governance story.",
    localPayloads: { record }
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
        plan_id: "pmm-claims-2026-03",
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
        plan_id: "pmm-claims-2026-03",
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
        submission_id: "sub-claims-42",
        authority: draft.authority,
        status: "submitted",
        channel: "portal",
        submitted_at: "2026-03-08T09:30:00Z",
        document_commitment: documentArtefact.commitment,
        metadata: {
          owner: draft.owner
        }
      }
    },
    artefacts: [
      jsonArtefact("authority_submission.json", {
        submission_id: "sub-claims-42",
        authority: draft.authority,
        status: "submitted",
        channel: "portal",
        submitted_at: "2026-03-08T09:30:00Z",
        metadata: {
          owner: draft.owner
        }
      }),
      documentArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Authority submission",
    summary: "Regulator submission evidence added to the monitoring pack.",
    localPayloads: { document }
  });
}

async function buildFriaStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "fria");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const report = {
    owner: draft.owner,
    finding: draft.friaSummary
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
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "technical_doc",
    label: "Fundamental rights assessment",
    summary: "FRIA evidence added to the deployer review pack.",
    localPayloads: { report }
  });
}

async function buildHumanOversightStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "human-oversight");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const notes = {
    reason: draft.friaSummary,
    reviewer: draft.reviewer,
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
        notes_commitment: notesArtefact.commitment
      }
    },
    artefacts: [
      jsonArtefact("human_oversight.json", {
        action: "manual_case_review_required",
        reviewer: draft.reviewer
      }),
      notesArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Human oversight",
    summary: "Human review evidence added to the deployer pack.",
    localPayloads: { notes }
  });
}

async function buildIncidentReportStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "incident");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const report = {
    owner: draft.owner,
    summary: draft.incidentSummary
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
        metadata: {
          owner: draft.owner
        }
      }),
      reportArtefact.artefact
    ],
    retentionClass: "risk_mgmt",
    label: "Incident report",
    summary: "Initial serious-incident evidence captured for follow-up.",
    localPayloads: { report }
  });
}

async function buildAuthorityNotificationStep(scenario, draft) {
  const actor = baseActor(scenario);
  const subject = baseSubject(draft, "authority-notification");
  const complianceProfile = serializeComplianceProfile(buildPlaygroundComplianceProfile(draft));
  const report = {
    article: "73",
    summary: "Initial authority notification draft"
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
    summary: "Follow-up correspondence evidence added to the incident pack.",
    localPayloads: { message }
  });
}

const STEP_BUILDERS = {
  instructions_for_use: buildInstructionsStep,
  qms_record: buildQmsRecordStep,
  post_market_monitoring: buildPostMarketMonitoringStep,
  authority_submission: buildAuthoritySubmissionStep,
  fundamental_rights_assessment: buildFriaStep,
  human_oversight: buildHumanOversightStep,
  incident_report: buildIncidentReportStep,
  authority_notification: buildAuthorityNotificationStep,
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
