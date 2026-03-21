const enc = new TextEncoder();

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function coerceBytes(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (typeof data === "string") {
    return enc.encode(data);
  }
  return enc.encode(prettyJson(data));
}

function defaultContentType(data) {
  if (data instanceof Uint8Array) {
    return "application/octet-stream";
  }
  if (typeof data === "string") {
    return "text/plain; charset=utf-8";
  }
  return "application/json";
}

export function encodeBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const slice = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

export async function sha256Prefixed(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

function summarizeText(text, maxLength = 220) {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, maxLength - 1)}…`;
}

function nullIfBlank(value) {
  if (value === undefined || value === null) {
    return null;
  }
  const text = String(value).trim();
  return text ? text : null;
}

export function serializeComplianceProfile(profile) {
  if (!profile) {
    return null;
  }
  return {
    intended_use: nullIfBlank(profile.intendedUse),
    prohibited_practice_screening: nullIfBlank(profile.prohibitedPracticeScreening),
    risk_tier: nullIfBlank(profile.riskTier),
    high_risk_domain: nullIfBlank(profile.highRiskDomain),
    gpai_status: nullIfBlank(profile.gpaiStatus),
    systemic_risk:
      typeof profile.systemicRisk === "boolean" ? profile.systemicRisk : null,
    fria_required:
      typeof profile.friaRequired === "boolean" ? profile.friaRequired : null,
    deployment_context: nullIfBlank(profile.deploymentContext),
    metadata: profile.metadata ?? null
  };
}

export function inlineArtefact(name, data, contentType) {
  const bytes = coerceBytes(data);
  return {
    name,
    content_type: contentType ?? defaultContentType(data),
    data_base64: encodeBase64(bytes)
  };
}

export function jsonArtefact(name, value) {
  return inlineArtefact(name, value, "application/json");
}

export function textArtefact(name, value, contentType = "text/plain; charset=utf-8") {
  return inlineArtefact(name, value, contentType);
}

export function buildCaptureRequest({
  actor,
  subject,
  complianceProfile,
  context,
  items,
  retentionClass,
  redactions = [],
  encryptionEnabled = false,
  artefacts = []
}) {
  const capture = {
    actor,
    subject,
    ...(complianceProfile ? { compliance_profile: complianceProfile } : {}),
    ...(context ? { context } : {}),
    items,
    policy: {
      redactions,
      encryption: { enabled: Boolean(encryptionEnabled) },
      retention_class: retentionClass ?? null
    }
  };

  return {
    capture,
    artefacts
  };
}

export function buildActor({
  issuer = "proof-layer-web-demo",
  appId = "web-demo",
  env = "demo",
  signingKeyId = "vault-managed",
  role = "provider"
}) {
  return {
    issuer,
    app_id: appId,
    env,
    signing_key_id: signingKeyId,
    role
  };
}

export function buildSubject({
  requestId = null,
  threadId = null,
  userRef = "demo-user",
  systemId = null,
  modelId = null,
  deploymentId = null,
  version = "2026.03"
}) {
  return {
    request_id: requestId,
    thread_id: threadId,
    user_ref: userRef,
    system_id: systemId,
    model_id: modelId,
    deployment_id: deploymentId,
    version
  };
}

export async function buildDocumentArtefact(name, value, contentType) {
  const bytes = coerceBytes(value);
  return {
    artefact: {
      name,
      content_type: contentType ?? defaultContentType(value),
      data_base64: encodeBase64(bytes)
    },
    commitment: await sha256Prefixed(bytes),
    bytes
  };
}

export async function buildSimpleEvidenceCapture({
  actor,
  subject,
  complianceProfile,
  context,
  item,
  artefacts,
  retentionClass,
  label,
  summary,
  localPayloads = {}
}) {
  return {
    label,
    itemTypes: [item.type],
    summary,
    localPayloads,
    createPayload: buildCaptureRequest({
      actor,
      subject,
      complianceProfile,
      context,
      items: [item],
      retentionClass,
      artefacts
    })
  };
}

function buildIncidentArtefact(providerResult, requestId) {
  return {
    incident_id: `incident-${requestId.slice(0, 12)}`,
    severity: "medium",
    status: "open",
    occurred_at: new Date().toISOString(),
    summary: summarizeText(providerResult.output_text),
    metadata: {
      capture_mode: providerResult.capture_mode,
      provider: providerResult.provider,
      model: providerResult.model,
      generated_by: "web-demo-derived-incident-report"
    }
  };
}

function buildAnnexIvMarkdown(providerResult) {
  return [
    "# Annex IV Governance Summary",
    "",
    `Provider capture mode: ${providerResult.capture_mode}`,
    `Provider: ${providerResult.provider}`,
    `Model: ${providerResult.model}`,
    "",
    "## Intended purpose",
    "",
    summarizeText(providerResult.output_text, 320),
    "",
    "## Known limitations",
    "",
    "- Demo-generated technical note, not a full legal dossier.",
    "- Intended to show evidence capture, sealing, disclosure, and export mechanics.",
    "- Output content should be reviewed and extended before formal filing."
  ].join("\n");
}

function buildAnnexIvDerivedPayloads(providerResult, requestId) {
  const intendedPurpose = summarizeText(providerResult.output_text, 240);
  return {
    technicalDoc: {
      document_ref: "annex_iv_summary.md",
      section: "system_description",
      annex_iv_sections: ["section_2", "section_3", "section_5", "section_7"],
      system_description_summary:
        "Provider-operated employment-screening assistant for first-pass candidate review in the EU market.",
      model_description_summary: `${providerResult.provider} ${providerResult.model} configured for structured recruiter support.`,
      capabilities_and_limitations: `${intendedPurpose} Human review remains mandatory before any adverse employment decision.`,
      design_choices_summary:
        "The workflow favors explanation, escalation, and traceability over fully automated decisioning.",
      evaluation_metrics_summary:
        "Quarterly fairness, reviewer-agreement, and false-negative checks are tracked in the provider governance file.",
      human_oversight_design_summary:
        "Borderline or adverse recommendations route to a human reviewer with documented override controls.",
      post_market_monitoring_plan_ref: "pmm-hiring-assistant-2026-03"
    },
    riskAssessment: {
      risk_id: `risk-${requestId.slice(0, 12)}`,
      severity: "high",
      status: "mitigated",
      summary: "Employment-screening workflow risk tracked for Annex IV readiness.",
      risk_description:
        "Candidate summaries could over-weight incomplete or proxy-sensitive profile signals without explicit human review.",
      likelihood: "medium",
      affected_groups: ["job_candidates", "recruiters"],
      mitigation_measures: [
        "Mandatory human review before shortlist or rejection actions.",
        "Escalation for low-confidence or incomplete-profile cases.",
        "Quarterly fairness and reviewer-agreement sampling."
      ],
      residual_risk_level: "medium",
      risk_owner: "provider-risk-team",
      vulnerable_groups_considered: true,
      test_results_summary:
        "Offline validation and reviewer-agreement checks show acceptable performance only when human oversight remains enabled.",
      metadata: {
        internal_notes: "Derived by the guided demo; replace with production review notes before filing."
      }
    },
    dataGovernance: {
      decision: "approved_with_restrictions",
      dataset_ref: "dataset://hiring-assistant/training-v3",
      dataset_name: "hiring-assistant-training-v3",
      dataset_version: "2026.03",
      source_description:
        "Curated historical recruiting assessments, interviewer notes, and QA-reviewed candidate summaries.",
      collection_period: {
        start: "2024-01-01",
        end: "2025-12-31"
      },
      geographical_scope: ["EU"],
      preprocessing_operations: ["deduplication", "pseudonymization", "label_review"],
      bias_detection_methodology:
        "Quarterly parity checks across gender, age-proxy, disability-accommodation, and language cohorts.",
      bias_metrics: [
        {
          name: "selection_rate_gap",
          value: "0.04",
          unit: "ratio",
          methodology: "Quarterly parity review sample."
        }
      ],
      mitigation_actions: [
        "Sensitive employment cases are escalated to a human reviewer.",
        "Dataset refreshes require representation and annotation-quality review."
      ],
      data_gaps: ["Limited examples for non-linear career paths and cross-border CV formats."],
      personal_data_categories: ["cv_data", "employment_history"],
      safeguards: [
        "pseudonymization",
        "role-based access",
        "retention minimization"
      ],
      metadata: {
        owner: "data-governance-board"
      }
    },
    instructionsForUse: {
      document_ref: "docs://hiring-assistant/operator-handbook",
      version: "2026.03",
      section: "employment_review_controls",
      provider_identity: "quality-team provider team",
      intended_purpose:
        "Recruiter support for first-pass candidate review with mandatory human oversight.",
      system_capabilities: [
        "candidate_summary",
        "qualification_gap_flagging",
        "follow_up_question_suggestions"
      ],
      accuracy_metrics: [
        {
          name: "review_precision",
          value: "0.91",
          unit: "ratio"
        }
      ],
      foreseeable_risks: [
        "overconfident qualification summaries",
        "missed context for non-linear career paths"
      ],
      explainability_capabilities: ["reason_summary", "criteria_trace"],
      human_oversight_guidance: [
        "Escalate adverse or borderline recommendations to a human reviewer.",
        "Document overrides before any candidate decision leaves the review queue."
      ],
      compute_requirements: ["4 vCPU", "8GB RAM"],
      service_lifetime: "Review quarterly or whenever the hiring workflow materially changes.",
      log_management_guidance: [
        "Retain runtime and review logs for post-market monitoring.",
        "Escalate incident-linked logs to provider governance operations."
      ],
      metadata: {
        distribution: "internal_reviewer_only"
      }
    },
    humanOversight: {
      action: "manual_case_review_required",
      reviewer: "quality-panel",
      actor_role: "human_reviewer",
      anomaly_detected: false,
      override_action: "Route borderline cases to manual review queue.",
      interpretation_guidance_followed: true,
      automation_bias_detected: false,
      two_person_verification: true,
      stop_triggered: false,
      stop_reason: null
    },
    qmsRecord: {
      record_id: "qms-hiring-assistant-release-42",
      process: "release_approval",
      status: "approved",
      policy_name: "Hiring Assistant Release Governance",
      revision: "3.1",
      effective_date: "2026-03-01",
      scope: "EU provider release control",
      audit_results_summary:
        "No blocking findings. Quarterly oversight-quality review requested before broader rollout.",
      continuous_improvement_actions: [
        "Extend fairness review coverage for non-linear career histories.",
        "Refresh recruiter guidance before the next release."
      ],
      metadata: {
        owner: "quality-team"
      }
    },
    standardsAlignment: {
      standard_ref: "EN ISO/IEC 42001:2023",
      status: "aligned_with_internal_controls",
      scope: "Provider governance process for the hiring-assistant system",
      metadata: {
        owner: "standards-office"
      }
    },
    postMarketMonitoring: {
      plan_id: "pmm-hiring-assistant-2026-03",
      status: "active",
      summary:
        "Weekly review of override rates, appeal signals, and fairness sampling for the provider-side employment workflow.",
      metadata: {
        owner: "post-market-ops"
      }
    }
  };
}

async function buildDerivedEvidence(preset, providerResult, requestId) {
  const items = [];
  const artefacts = [];

  if (preset.key === "incident_review") {
    const incidentPayload = buildIncidentArtefact(providerResult, requestId);
    const incidentBytes = enc.encode(prettyJson(incidentPayload));
    const incidentCommitment = await sha256Prefixed(incidentBytes);
    artefacts.push({
      name: "incident_report.json",
      content_type: "application/json",
      data_base64: encodeBase64(incidentBytes)
    });
    items.push({
      type: "incident_report",
      data: {
        incident_id: incidentPayload.incident_id,
        severity: incidentPayload.severity,
        status: incidentPayload.status,
        occurred_at: incidentPayload.occurred_at,
        summary: incidentPayload.summary,
        report_commitment: incidentCommitment,
        metadata: incidentPayload.metadata
      }
    });
  }

  if (preset.key === "annex_iv_filing") {
    const markdown = buildAnnexIvMarkdown(providerResult);
    const docBytes = enc.encode(markdown);
    const commitment = await sha256Prefixed(docBytes);
    const payloads = buildAnnexIvDerivedPayloads(providerResult, requestId);
    artefacts.push({
      name: "annex_iv_summary.md",
      content_type: "text/markdown",
      data_base64: encodeBase64(docBytes)
    });
    items.push({
      type: "technical_doc",
      data: {
        ...payloads.technicalDoc,
        commitment
      }
    });
    items.push({ type: "risk_assessment", data: payloads.riskAssessment });
    items.push({ type: "data_governance", data: payloads.dataGovernance });
    items.push({ type: "instructions_for_use", data: payloads.instructionsForUse });
    items.push({ type: "human_oversight", data: payloads.humanOversight });
    items.push({ type: "qms_record", data: payloads.qmsRecord });
    items.push({ type: "standards_alignment", data: payloads.standardsAlignment });
    items.push({ type: "post_market_monitoring", data: payloads.postMarketMonitoring });
    artefacts.push(jsonArtefact("risk_assessment.json", payloads.riskAssessment));
    artefacts.push(jsonArtefact("data_governance.json", payloads.dataGovernance));
    artefacts.push(jsonArtefact("instructions_for_use.json", payloads.instructionsForUse));
    artefacts.push(jsonArtefact("human_oversight.json", payloads.humanOversight));
    artefacts.push(jsonArtefact("qms_record.json", payloads.qmsRecord));
    artefacts.push(jsonArtefact("standards_alignment.json", payloads.standardsAlignment));
    artefacts.push(
      jsonArtefact("post_market_monitoring.json", payloads.postMarketMonitoring)
    );
  }

  return { items, artefacts };
}

export async function buildLlmInteractionCapture({
  actorRole,
  systemId,
  providerResult,
  temperature,
  maxTokens,
  packType,
  bundleFormat,
  disclosureProfile,
  complianceProfile,
  appId = "web-demo",
  issuer = "proof-layer-web-demo",
  env = "demo",
  retentionClass = "runtime_logs"
}) {
  const requestId = providerResult.trace_payload?.request_id || crypto.randomUUID();
  const systemIdValue = systemId.trim();
  const promptPayload = providerResult.prompt_payload;
  const responsePayload = {
    provider: providerResult.provider,
    model: providerResult.model,
    output_text: providerResult.output_text,
    ...providerResult.response_payload,
    response_source: providerResult.capture_mode
  };
  const tracePayload = {
    ...providerResult.trace_payload,
    request_id: requestId,
    system_id: systemIdValue,
    actor_role: actorRole,
    pack_type: packType,
    bundle_format: bundleFormat,
    disclosure_profile: disclosureProfile
  };

  const promptBytes = enc.encode(prettyJson(promptPayload));
  const responseBytes = enc.encode(prettyJson(responsePayload));
  const traceBytes = enc.encode(prettyJson(tracePayload));

  const promptCommitment = await sha256Prefixed(promptBytes);
  const responseCommitment = await sha256Prefixed(responseBytes);
  const traceCommitment = await sha256Prefixed(traceBytes);

  return {
    label: "Primary interaction",
    itemTypes: ["llm_interaction"],
    responseText: providerResult.output_text,
    captureMode: providerResult.capture_mode,
    promptPayload,
    responsePayload,
    tracePayload,
    localPayloads: {
      promptPayload,
      responsePayload,
      tracePayload
    },
    createPayload: buildCaptureRequest({
      actor: buildActor({ role: actorRole, appId, issuer, env }),
      subject: buildSubject({
        requestId,
        threadId: `thread-${requestId.slice(0, 8)}`,
        systemId: systemIdValue,
        modelId: `${providerResult.provider}:${providerResult.model}`,
        deploymentId: `${systemIdValue}-demo`
      }),
      complianceProfile: serializeComplianceProfile(complianceProfile),
      context: {
        provider: providerResult.provider,
        model: providerResult.model,
        parameters: {
          temperature,
          max_tokens: maxTokens,
          capture_mode: providerResult.capture_mode
        },
        trace_commitment: traceCommitment,
        otel_genai_semconv_version: "1.0.0"
      },
      items: [
        {
          type: "llm_interaction",
          data: {
            provider: providerResult.provider,
            model: providerResult.model,
            parameters: {
              temperature,
              max_tokens: maxTokens,
              capture_mode: providerResult.capture_mode
            },
            input_commitment: promptCommitment,
            output_commitment: responseCommitment,
            token_usage: providerResult.usage,
            latency_ms: providerResult.latency_ms,
            trace_commitment: traceCommitment,
            trace_semconv_version: "1.0.0"
          }
        }
      ],
      retentionClass,
      artefacts: [
        {
          name: "prompt.json",
          content_type: "application/json",
          data_base64: encodeBase64(promptBytes)
        },
        {
          name: "response.json",
          content_type: "application/json",
          data_base64: encodeBase64(responseBytes)
        },
        {
          name: "trace.json",
          content_type: "application/json",
          data_base64: encodeBase64(traceBytes)
        }
      ]
    })
  };
}

export async function buildCaptureEnvelope({
  preset,
  providerResult,
  actorRole,
  systemId,
  temperature,
  maxTokens
}) {
  const baseEnvelope = await buildLlmInteractionCapture({
    actorRole,
    systemId,
    providerResult,
    temperature,
    maxTokens,
    packType: preset.packType,
    bundleFormat: preset.bundleFormat,
    disclosureProfile: preset.disclosureProfile,
    retentionClass: preset.retentionClass
  });
  const requestId = baseEnvelope.tracePayload.request_id;
  const { items: derivedItems, artefacts: derivedArtefacts } = await buildDerivedEvidence(
    preset,
    providerResult,
    requestId
  );
  baseEnvelope.createPayload.capture.items.push(...derivedItems);
  baseEnvelope.createPayload.artefacts.push(...derivedArtefacts);
  baseEnvelope.itemTypes = baseEnvelope.createPayload.capture.items.map((item) => item.type);
  return baseEnvelope;
}

export function decodeJsonBytes(arrayBuffer) {
  const text = new TextDecoder().decode(arrayBuffer);
  return JSON.parse(text);
}
