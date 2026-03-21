import { Buffer } from "node:buffer";
import { hashSha256 } from "./native.js";
import type {
  AdversarialTestRequestOptions,
  AuthorityNotificationRequestOptions,
  AuthoritySubmissionRequestOptions,
  BinaryLike,
  ComplianceProfileInput,
  ConformityAssessmentRequestOptions,
  CopyrightPolicyRequestOptions,
  CorrectiveActionRequestOptions,
  ComputeMetricsRequestOptions,
  CreateBundleRequest,
  DataGovernanceRequestOptions,
  DeclarationRequestOptions,
  DownstreamDocumentationRequestOptions,
  FundamentalRightsAssessmentRequestOptions,
  HumanOversightRequestOptions,
  IncidentReportRequestOptions,
  InstructionsForUseRequestOptions,
  JsonObject,
  JsonValue,
  LiteracyAttestationRequestOptions,
  LlmInteractionRequestOptions,
  ModelEvaluationRequestOptions,
  PostMarketMonitoringRequestOptions,
  PolicyDecisionRequestOptions,
  ProofArtefactInput,
  QmsRecordRequestOptions,
  RegulatorCorrespondenceRequestOptions,
  RegistrationRequestOptions,
  ReportingDeadlineRequestOptions,
  RetrievalRequestOptions,
  RiskAssessmentRequestOptions,
  StandardsAlignmentRequestOptions,
  TechnicalDocRequestOptions,
  TrainingSummaryRequestOptions,
  TrainingProvenanceRequestOptions,
  ToolCallRequestOptions
} from "./types.js";

function encodeJson(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function defaultContentType(data: BinaryLike): string {
  if (data instanceof Uint8Array) {
    return "application/octet-stream";
  }
  if (typeof data === "string") {
    return "text/plain; charset=utf-8";
  }
  return "application/json";
}

function jsonArtefact(name: string, value: unknown): ProofArtefactInput {
  return {
    name,
    contentType: "application/json",
    data: encodeJson(value)
  };
}

function inlineArtefact(
  name: string,
  data: BinaryLike,
  contentType?: string
): ProofArtefactInput {
  return {
    name,
    contentType: contentType ?? defaultContentType(data),
    data
  };
}

function namedDataArtefact(baseName: string, data: BinaryLike): ProofArtefactInput {
  if (data instanceof Uint8Array) {
    return inlineArtefact(`${baseName}.bin`, data, "application/octet-stream");
  }
  if (typeof data === "string") {
    return inlineArtefact(`${baseName}.txt`, data, "text/plain; charset=utf-8");
  }
  return inlineArtefact(`${baseName}.json`, data, "application/json");
}

interface CaptureEnvelopeOptions {
  keyId: string;
  role?: LlmInteractionRequestOptions["role"];
  issuer?: string;
  appId?: string;
  env?: string;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  systemId?: string;
  modelId?: string;
  deploymentId?: string;
  version?: string;
  complianceProfile?: ComplianceProfileInput;
  context?: JsonObject;
  items: JsonObject[];
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts: ProofArtefactInput[];
}

function serializeComplianceProfile(
  complianceProfile: ComplianceProfileInput
): JsonObject {
  return {
    intended_use: complianceProfile.intendedUse ?? null,
    prohibited_practice_screening: complianceProfile.prohibitedPracticeScreening ?? null,
    risk_tier: complianceProfile.riskTier ?? null,
    high_risk_domain: complianceProfile.highRiskDomain ?? null,
    gpai_status: complianceProfile.gpaiStatus ?? null,
    systemic_risk: complianceProfile.systemicRisk ?? null,
    fria_required: complianceProfile.friaRequired ?? null,
    deployment_context: complianceProfile.deploymentContext ?? null,
    metadata: complianceProfile.metadata ?? null
  };
}

function createCaptureRequest(options: CaptureEnvelopeOptions): CreateBundleRequest {
  const artefacts =
    options.artefacts.length > 0
      ? options.artefacts
      : [jsonArtefact("evidence.json", { items: options.items })];

  return {
    capture: {
      actor: {
        issuer: options.issuer ?? "proof-layer-ts",
        app_id: options.appId ?? "typescript-sdk",
        env: options.env ?? "dev",
        signing_key_id: options.keyId,
        role: options.role ?? "provider"
      },
      subject: {
        request_id: options.requestId ?? null,
        thread_id: options.threadId ?? null,
        user_ref: options.userRef ?? null,
        system_id: options.systemId ?? null,
        model_id: options.modelId ?? null,
        deployment_id: options.deploymentId ?? null,
        version: options.version ?? null
      },
      ...(options.complianceProfile
        ? { compliance_profile: serializeComplianceProfile(options.complianceProfile) }
        : {}),
      ...(options.context ? { context: options.context } : {}),
      items: options.items,
      policy: {
        redactions: options.redactions ?? [],
        encryption: { enabled: Boolean(options.encryptionEnabled) },
        retention_class: options.retentionClass ?? null
      }
    },
    artefacts
  };
}

export function defaultLlmInteractionArtefacts(
  input: JsonValue | JsonObject,
  output: JsonValue | JsonObject
): ProofArtefactInput[] {
  return [
    {
      name: "prompt.json",
      contentType: "application/json",
      data: encodeJson(input)
    },
    {
      name: "response.json",
      contentType: "application/json",
      data: encodeJson(output)
    }
  ];
}

export function createLlmInteractionRequest(
  options: LlmInteractionRequestOptions
): CreateBundleRequest {
  const promptBytes = encodeJson(options.input);
  const responseBytes = encodeJson(options.output);
  const traceBytes = options.trace === undefined ? null : encodeJson(options.trace);
  const traceCommitment =
    options.traceCommitment ?? (traceBytes ? hashSha256(traceBytes) : null);
  const traceSemconvVersion =
    options.otelSemconvVersion ?? (traceCommitment ? "1.0.0" : null);

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    complianceProfile: options.complianceProfile,
    modelId: `${options.provider}:${options.model}`,
    context: {
      provider: options.provider,
      model: options.model,
      parameters: options.modelParameters ?? {},
      trace_commitment: traceCommitment,
      otel_genai_semconv_version: traceSemconvVersion
    },
    items: [
      {
        type: "llm_interaction",
        data: {
          provider: options.provider,
          model: options.model,
          parameters: options.modelParameters ?? {},
          input_commitment: hashSha256(promptBytes),
          retrieval_commitment: options.retrievalCommitment ?? null,
          output_commitment: hashSha256(responseBytes),
          tool_outputs_commitment: options.toolOutputsCommitment ?? null,
          trace_commitment: traceCommitment,
          trace_semconv_version: traceSemconvVersion,
          execution_start: options.executionStart ?? null,
          execution_end: options.executionEnd ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts: options.artefacts ?? defaultLlmInteractionArtefacts(options.input, options.output)
  });
}

export function createToolCallRequest(
  options: ToolCallRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("tool_call.json", {
        tool_name: options.toolName,
        metadata: options.metadata ?? null,
        execution_start: options.executionStart ?? null,
        execution_end: options.executionEnd ?? null
      })
    );
    if (options.input !== undefined) {
      artefacts.push(namedDataArtefact("tool_input", options.input));
    }
    if (options.output !== undefined) {
      artefacts.push(namedDataArtefact("tool_output", options.output));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "tool_call",
        data: {
          tool_name: options.toolName,
          input_commitment: options.input !== undefined ? hashSha256(options.input) : null,
          output_commitment: options.output !== undefined ? hashSha256(options.output) : null,
          metadata: options.metadata ?? null,
          execution_start: options.executionStart ?? null,
          execution_end: options.executionEnd ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createRetrievalRequest(
  options: RetrievalRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("retrieval.json", {
        corpus: options.corpus,
        metadata: options.metadata ?? null,
        database_reference: options.databaseReference ?? null,
        execution_start: options.executionStart ?? null,
        execution_end: options.executionEnd ?? null
      }),
      namedDataArtefact("retrieval_result", options.result)
    );
    if (options.query !== undefined) {
      artefacts.push(namedDataArtefact("retrieval_query", options.query));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "retrieval",
        data: {
          corpus: options.corpus,
          result_commitment: hashSha256(options.result),
          query_commitment: options.query !== undefined ? hashSha256(options.query) : null,
          metadata: options.metadata ?? null,
          database_reference: options.databaseReference ?? null,
          execution_start: options.executionStart ?? null,
          execution_end: options.executionEnd ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createHumanOversightRequest(
  options: HumanOversightRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("human_oversight.json", {
        action: options.action,
        reviewer: options.reviewer ?? null,
        actor_role: options.actorRole ?? null,
        anomaly_detected: options.anomalyDetected ?? null,
        override_action: options.overrideAction ?? null,
        interpretation_guidance_followed: options.interpretationGuidanceFollowed ?? null,
        automation_bias_detected: options.automationBiasDetected ?? null,
        two_person_verification: options.twoPersonVerification ?? null,
        stop_triggered: options.stopTriggered ?? null,
        stop_reason: options.stopReason ?? null
      })
    );
    if (options.notes !== undefined) {
      artefacts.push(namedDataArtefact("oversight_notes", options.notes));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "human_oversight",
        data: {
          action: options.action,
          reviewer: options.reviewer ?? null,
          notes_commitment: options.notes !== undefined ? hashSha256(options.notes) : null,
          actor_role: options.actorRole ?? null,
          anomaly_detected: options.anomalyDetected ?? null,
          override_action: options.overrideAction ?? null,
          interpretation_guidance_followed:
            options.interpretationGuidanceFollowed ?? null,
          automation_bias_detected: options.automationBiasDetected ?? null,
          two_person_verification: options.twoPersonVerification ?? null,
          stop_triggered: options.stopTriggered ?? null,
          stop_reason: options.stopReason ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createPolicyDecisionRequest(
  options: PolicyDecisionRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("policy_decision.json", {
        policy_name: options.policyName,
        decision: options.decision,
        metadata: options.metadata ?? null
      })
    );
    if (options.rationale !== undefined) {
      artefacts.push(namedDataArtefact("policy_rationale", options.rationale));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "policy_decision",
        data: {
          policy_name: options.policyName,
          decision: options.decision,
          rationale_commitment:
            options.rationale !== undefined ? hashSha256(options.rationale) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createRiskAssessmentRequest(
  options: RiskAssessmentRequestOptions
): CreateBundleRequest {
  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "risk_assessment",
        data: {
          risk_id: options.riskId,
          severity: options.severity,
          status: options.status,
          summary: options.summary ?? null,
          risk_description: options.riskDescription ?? null,
          likelihood: options.likelihood ?? null,
          affected_groups: options.affectedGroups ?? [],
          mitigation_measures: options.mitigationMeasures ?? [],
          residual_risk_level: options.residualRiskLevel ?? null,
          risk_owner: options.riskOwner ?? null,
          vulnerable_groups_considered: options.vulnerableGroupsConsidered ?? null,
          test_results_summary: options.testResultsSummary ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts:
      options.artefacts ?? [
        jsonArtefact("risk_assessment.json", {
          risk_id: options.riskId,
          severity: options.severity,
          status: options.status,
          summary: options.summary ?? null,
          risk_description: options.riskDescription ?? null,
          likelihood: options.likelihood ?? null,
          affected_groups: options.affectedGroups ?? [],
          mitigation_measures: options.mitigationMeasures ?? [],
          residual_risk_level: options.residualRiskLevel ?? null,
          risk_owner: options.riskOwner ?? null,
          vulnerable_groups_considered: options.vulnerableGroupsConsidered ?? null,
          test_results_summary: options.testResultsSummary ?? null,
          metadata: options.metadata ?? null,
          record: options.record ?? null
        })
      ]
  });
}

export function createDataGovernanceRequest(
  options: DataGovernanceRequestOptions
): CreateBundleRequest {
  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "data_governance",
        data: {
          decision: options.decision,
          dataset_ref: options.datasetRef ?? null,
          dataset_name: options.datasetName ?? null,
          dataset_version: options.datasetVersion ?? null,
          source_description: options.sourceDescription ?? null,
          collection_period: options.collectionPeriod ?? null,
          geographical_scope: options.geographicalScope ?? [],
          preprocessing_operations: options.preprocessingOperations ?? [],
          bias_detection_methodology: options.biasDetectionMethodology ?? null,
          bias_metrics: options.biasMetrics ?? [],
          mitigation_actions: options.mitigationActions ?? [],
          data_gaps: options.dataGaps ?? [],
          personal_data_categories: options.personalDataCategories ?? [],
          safeguards: options.safeguards ?? [],
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts:
      options.artefacts ?? [
        jsonArtefact("data_governance.json", {
          decision: options.decision,
          dataset_ref: options.datasetRef ?? null,
          dataset_name: options.datasetName ?? null,
          dataset_version: options.datasetVersion ?? null,
          source_description: options.sourceDescription ?? null,
          collection_period: options.collectionPeriod ?? null,
          geographical_scope: options.geographicalScope ?? [],
          preprocessing_operations: options.preprocessingOperations ?? [],
          bias_detection_methodology: options.biasDetectionMethodology ?? null,
          bias_metrics: options.biasMetrics ?? [],
          mitigation_actions: options.mitigationActions ?? [],
          data_gaps: options.dataGaps ?? [],
          personal_data_categories: options.personalDataCategories ?? [],
          safeguards: options.safeguards ?? [],
          metadata: options.metadata ?? null,
          record: options.record ?? null
        })
      ]
  });
}

export function createTechnicalDocRequest(
  options: TechnicalDocRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    if (options.document !== undefined) {
      artefacts.push(
        inlineArtefact(
          options.documentName ?? "technical_doc.bin",
          options.document,
          options.documentContentType
        )
      );
    }
    if (options.descriptor !== undefined || options.document === undefined) {
      artefacts.push(
        jsonArtefact("technical_doc.json", {
          document_ref: options.documentRef,
          section: options.section ?? null,
          descriptor: options.descriptor ?? null,
          annex_iv_sections: options.annexIvSections ?? [],
          system_description_summary: options.systemDescriptionSummary ?? null,
          model_description_summary: options.modelDescriptionSummary ?? null,
          capabilities_and_limitations: options.capabilitiesAndLimitations ?? null,
          design_choices_summary: options.designChoicesSummary ?? null,
          evaluation_metrics_summary: options.evaluationMetricsSummary ?? null,
          human_oversight_design_summary: options.humanOversightDesignSummary ?? null,
          post_market_monitoring_plan_ref: options.postMarketMonitoringPlanRef ?? null,
          simplified_tech_doc: options.simplifiedTechDoc ?? null
        })
      );
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "technical_doc",
        data: {
          document_ref: options.documentRef,
          section: options.section ?? null,
          commitment:
            options.commitment ??
            (options.document !== undefined ? hashSha256(options.document) : null),
          annex_iv_sections: options.annexIvSections ?? [],
          system_description_summary: options.systemDescriptionSummary ?? null,
          model_description_summary: options.modelDescriptionSummary ?? null,
          capabilities_and_limitations: options.capabilitiesAndLimitations ?? null,
          design_choices_summary: options.designChoicesSummary ?? null,
          evaluation_metrics_summary: options.evaluationMetricsSummary ?? null,
          human_oversight_design_summary: options.humanOversightDesignSummary ?? null,
          post_market_monitoring_plan_ref: options.postMarketMonitoringPlanRef ?? null,
          simplified_tech_doc: options.simplifiedTechDoc ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createInstructionsForUseRequest(
  options: InstructionsForUseRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    if (options.document !== undefined) {
      artefacts.push(
        inlineArtefact(
          options.documentName ?? "instructions_for_use.bin",
          options.document,
          options.documentContentType
        )
      );
    }
    artefacts.push(
      jsonArtefact("instructions_for_use.json", {
        document_ref: options.documentRef,
        version: options.versionTag ?? null,
        section: options.section ?? null,
        provider_identity: options.providerIdentity ?? null,
        intended_purpose: options.intendedPurpose ?? null,
        system_capabilities: options.systemCapabilities ?? [],
        accuracy_metrics: options.accuracyMetrics ?? [],
        foreseeable_risks: options.foreseeableRisks ?? [],
        explainability_capabilities: options.explainabilityCapabilities ?? [],
        human_oversight_guidance: options.humanOversightGuidance ?? [],
        compute_requirements: options.computeRequirements ?? [],
        service_lifetime: options.serviceLifetime ?? null,
        log_management_guidance: options.logManagementGuidance ?? [],
        metadata: options.metadata ?? null
      })
    );
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "instructions_for_use",
        data: {
          document_ref: options.documentRef,
          version: options.versionTag ?? null,
          section: options.section ?? null,
          commitment:
            options.commitment ??
            (options.document !== undefined ? hashSha256(options.document) : null),
          provider_identity: options.providerIdentity ?? null,
          intended_purpose: options.intendedPurpose ?? null,
          system_capabilities: options.systemCapabilities ?? [],
          accuracy_metrics: options.accuracyMetrics ?? [],
          foreseeable_risks: options.foreseeableRisks ?? [],
          explainability_capabilities: options.explainabilityCapabilities ?? [],
          human_oversight_guidance: options.humanOversightGuidance ?? [],
          compute_requirements: options.computeRequirements ?? [],
          service_lifetime: options.serviceLifetime ?? null,
          log_management_guidance: options.logManagementGuidance ?? [],
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createQmsRecordRequest(
  options: QmsRecordRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("qms_record.json", {
        record_id: options.recordId,
        process: options.process,
        status: options.status,
        policy_name: options.policyName ?? null,
        revision: options.revision ?? null,
        effective_date: options.effectiveDate ?? null,
        expiry_date: options.expiryDate ?? null,
        scope: options.scope ?? null,
        approval_commitment: options.approvalCommitment ?? null,
        audit_results_summary: options.auditResultsSummary ?? null,
        continuous_improvement_actions: options.continuousImprovementActions ?? [],
        metadata: options.metadata ?? null
      })
    );
    if (options.record !== undefined) {
      artefacts.push(namedDataArtefact("qms_record_record", options.record));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "qms_record",
        data: {
          record_id: options.recordId,
          process: options.process,
          status: options.status,
          record_commitment: options.record !== undefined ? hashSha256(options.record) : null,
          policy_name: options.policyName ?? null,
          revision: options.revision ?? null,
          effective_date: options.effectiveDate ?? null,
          expiry_date: options.expiryDate ?? null,
          scope: options.scope ?? null,
          approval_commitment: options.approvalCommitment ?? null,
          audit_results_summary: options.auditResultsSummary ?? null,
          continuous_improvement_actions: options.continuousImprovementActions ?? [],
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createFundamentalRightsAssessmentRequest(
  options: FundamentalRightsAssessmentRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("fundamental_rights_assessment.json", {
        assessment_id: options.assessmentId,
        status: options.status,
        scope: options.scope ?? null,
        legal_basis: options.legalBasis ?? null,
        affected_rights: options.affectedRights ?? [],
        stakeholder_consultation_summary: options.stakeholderConsultationSummary ?? null,
        mitigation_plan_summary: options.mitigationPlanSummary ?? null,
        assessor: options.assessor ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(
        namedDataArtefact("fundamental_rights_assessment_report", options.report)
      );
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "fundamental_rights_assessment",
        data: {
          assessment_id: options.assessmentId,
          status: options.status,
          scope: options.scope ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          legal_basis: options.legalBasis ?? null,
          affected_rights: options.affectedRights ?? [],
          stakeholder_consultation_summary:
            options.stakeholderConsultationSummary ?? null,
          mitigation_plan_summary: options.mitigationPlanSummary ?? null,
          assessor: options.assessor ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createStandardsAlignmentRequest(
  options: StandardsAlignmentRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("standards_alignment.json", {
        standard_ref: options.standardRef,
        status: options.status,
        scope: options.scope ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.mapping !== undefined) {
      artefacts.push(namedDataArtefact("standards_alignment_mapping", options.mapping));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "standards_alignment",
        data: {
          standard_ref: options.standardRef,
          status: options.status,
          scope: options.scope ?? null,
          mapping_commitment:
            options.mapping !== undefined ? hashSha256(options.mapping) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createPostMarketMonitoringRequest(
  options: PostMarketMonitoringRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("post_market_monitoring.json", {
        plan_id: options.planId,
        status: options.status,
        summary: options.summary ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("post_market_monitoring_report", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "post_market_monitoring",
        data: {
          plan_id: options.planId,
          status: options.status,
          summary: options.summary ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createCorrectiveActionRequest(
  options: CorrectiveActionRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("corrective_action.json", {
        action_id: options.actionId,
        status: options.status,
        summary: options.summary ?? null,
        due_at: options.dueAt ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.record !== undefined) {
      artefacts.push(namedDataArtefact("corrective_action_record", options.record));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "corrective_action",
        data: {
          action_id: options.actionId,
          status: options.status,
          summary: options.summary ?? null,
          due_at: options.dueAt ?? null,
          record_commitment: options.record !== undefined ? hashSha256(options.record) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createAuthorityNotificationRequest(
  options: AuthorityNotificationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("authority_notification.json", {
        notification_id: options.notificationId,
        authority: options.authority,
        status: options.status,
        incident_id: options.incidentId ?? null,
        due_at: options.dueAt ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("authority_notification_report", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "authority_notification",
        data: {
          notification_id: options.notificationId,
          authority: options.authority,
          status: options.status,
          incident_id: options.incidentId ?? null,
          due_at: options.dueAt ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createAuthoritySubmissionRequest(
  options: AuthoritySubmissionRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("authority_submission.json", {
        submission_id: options.submissionId,
        authority: options.authority,
        status: options.status,
        channel: options.channel ?? null,
        submitted_at: options.submittedAt ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.document !== undefined) {
      artefacts.push(namedDataArtefact("authority_submission_document", options.document));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "authority_submission",
        data: {
          submission_id: options.submissionId,
          authority: options.authority,
          status: options.status,
          channel: options.channel ?? null,
          submitted_at: options.submittedAt ?? null,
          document_commitment:
            options.document !== undefined ? hashSha256(options.document) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createReportingDeadlineRequest(
  options: ReportingDeadlineRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("reporting_deadline.json", {
        deadline_id: options.deadlineId,
        authority: options.authority,
        obligation_ref: options.obligationRef,
        due_at: options.dueAt,
        status: options.status,
        incident_id: options.incidentId ?? null,
        metadata: options.metadata ?? null
      })
    );
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "reporting_deadline",
        data: {
          deadline_id: options.deadlineId,
          authority: options.authority,
          obligation_ref: options.obligationRef,
          due_at: options.dueAt,
          status: options.status,
          incident_id: options.incidentId ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createRegulatorCorrespondenceRequest(
  options: RegulatorCorrespondenceRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("regulator_correspondence.json", {
        correspondence_id: options.correspondenceId,
        authority: options.authority,
        direction: options.direction,
        status: options.status,
        occurred_at: options.occurredAt ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.message !== undefined) {
      artefacts.push(
        namedDataArtefact("regulator_correspondence_message", options.message)
      );
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "regulator_correspondence",
        data: {
          correspondence_id: options.correspondenceId,
          authority: options.authority,
          direction: options.direction,
          status: options.status,
          occurred_at: options.occurredAt ?? null,
          message_commitment:
            options.message !== undefined ? hashSha256(options.message) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createModelEvaluationRequest(
  options: ModelEvaluationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("model_evaluation.json", {
        evaluation_id: options.evaluationId,
        benchmark: options.benchmark,
        status: options.status,
        summary: options.summary ?? null,
        metrics_summary: options.metricsSummary ?? [],
        group_performance: options.groupPerformance ?? [],
        evaluation_methodology: options.evaluationMethodology ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("model_evaluation_report", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "model_evaluation",
        data: {
          evaluation_id: options.evaluationId,
          benchmark: options.benchmark,
          status: options.status,
          summary: options.summary ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          metrics_summary: options.metricsSummary ?? [],
          group_performance: options.groupPerformance ?? [],
          evaluation_methodology: options.evaluationMethodology ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createAdversarialTestRequest(
  options: AdversarialTestRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("adversarial_test.json", {
        test_id: options.testId,
        focus: options.focus,
        status: options.status,
        finding_severity: options.findingSeverity ?? null,
        threat_model: options.threatModel ?? null,
        test_methodology: options.testMethodology ?? null,
        attack_classes: options.attackClasses ?? [],
        affected_components: options.affectedComponents ?? [],
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("adversarial_test_report", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "adversarial_test",
        data: {
          test_id: options.testId,
          focus: options.focus,
          status: options.status,
          finding_severity: options.findingSeverity ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          threat_model: options.threatModel ?? null,
          test_methodology: options.testMethodology ?? null,
          attack_classes: options.attackClasses ?? [],
          affected_components: options.affectedComponents ?? [],
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createTrainingProvenanceRequest(
  options: TrainingProvenanceRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("training_provenance.json", {
        dataset_ref: options.datasetRef,
        stage: options.stage,
        lineage_ref: options.lineageRef ?? null,
        compute_metrics_ref: options.computeMetricsRef ?? null,
        training_dataset_summary: options.trainingDatasetSummary ?? null,
        consortium_context: options.consortiumContext ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.record !== undefined) {
      artefacts.push(namedDataArtefact("training_provenance_record", options.record));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "training_provenance",
        data: {
          dataset_ref: options.datasetRef,
          stage: options.stage,
          lineage_ref: options.lineageRef ?? null,
          record_commitment: options.record !== undefined ? hashSha256(options.record) : null,
          compute_metrics_ref: options.computeMetricsRef ?? null,
          training_dataset_summary: options.trainingDatasetSummary ?? null,
          consortium_context: options.consortiumContext ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createComputeMetricsRequest(
  options: ComputeMetricsRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("compute_metrics.json", {
        compute_id: options.computeId,
        training_flops_estimate: options.trainingFlopsEstimate,
        threshold_basis_ref: options.thresholdBasisRef,
        threshold_value: options.thresholdValue,
        threshold_status: options.thresholdStatus,
        estimation_methodology: options.estimationMethodology ?? null,
        measured_at: options.measuredAt ?? null,
        compute_resources_summary: options.computeResourcesSummary ?? [],
        consortium_context: options.consortiumContext ?? null,
        metadata: options.metadata ?? null,
        record: options.record ?? null
      })
    );
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "compute_metrics",
        data: {
          compute_id: options.computeId,
          training_flops_estimate: options.trainingFlopsEstimate,
          threshold_basis_ref: options.thresholdBasisRef,
          threshold_value: options.thresholdValue,
          threshold_status: options.thresholdStatus,
          estimation_methodology: options.estimationMethodology ?? null,
          measured_at: options.measuredAt ?? null,
          compute_resources_summary: options.computeResourcesSummary ?? [],
          consortium_context: options.consortiumContext ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createDownstreamDocumentationRequest(
  options: DownstreamDocumentationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("downstream_documentation.json", {
        document_ref: options.documentRef,
        audience: options.audience,
        status: options.status,
        metadata: options.metadata ?? null
      })
    );
    if (options.document !== undefined) {
      artefacts.push(namedDataArtefact("downstream_documentation_document", options.document));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "downstream_documentation",
        data: {
          document_ref: options.documentRef,
          audience: options.audience,
          status: options.status,
          commitment: options.document !== undefined ? hashSha256(options.document) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createCopyrightPolicyRequest(
  options: CopyrightPolicyRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("copyright_policy.json", {
        policy_ref: options.policyRef,
        status: options.status,
        jurisdiction: options.jurisdiction ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.document !== undefined) {
      artefacts.push(namedDataArtefact("copyright_policy_document", options.document));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "copyright_policy",
        data: {
          policy_ref: options.policyRef,
          status: options.status,
          jurisdiction: options.jurisdiction ?? null,
          commitment: options.document !== undefined ? hashSha256(options.document) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createTrainingSummaryRequest(
  options: TrainingSummaryRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("training_summary.json", {
        summary_ref: options.summaryRef,
        status: options.status,
        audience: options.audience ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.document !== undefined) {
      artefacts.push(namedDataArtefact("training_summary_document", options.document));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "training_summary",
        data: {
          summary_ref: options.summaryRef,
          status: options.status,
          audience: options.audience ?? null,
          commitment: options.document !== undefined ? hashSha256(options.document) : null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass ?? "gpai_documentation",
    artefacts
  });
}

export function createConformityAssessmentRequest(
  options: ConformityAssessmentRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("conformity_assessment.json", {
        assessment_id: options.assessmentId,
        procedure: options.procedure,
        status: options.status,
        assessment_body: options.assessmentBody ?? null,
        certificate_ref: options.certificateRef ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("conformity_assessment_report", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "conformity_assessment",
        data: {
          assessment_id: options.assessmentId,
          procedure: options.procedure,
          status: options.status,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          assessment_body: options.assessmentBody ?? null,
          certificate_ref: options.certificateRef ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createDeclarationRequest(
  options: DeclarationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("declaration.json", {
        declaration_id: options.declarationId,
        jurisdiction: options.jurisdiction,
        status: options.status,
        signatory: options.signatory ?? null,
        document_version: options.documentVersion ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.document !== undefined) {
      artefacts.push(namedDataArtefact("declaration_document", options.document));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "declaration",
        data: {
          declaration_id: options.declarationId,
          jurisdiction: options.jurisdiction,
          status: options.status,
          document_commitment:
            options.document !== undefined ? hashSha256(options.document) : null,
          signatory: options.signatory ?? null,
          document_version: options.documentVersion ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createRegistrationRequest(
  options: RegistrationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("registration.json", {
        registration_id: options.registrationId,
        authority: options.authority,
        status: options.status,
        registration_number: options.registrationNumber ?? null,
        submitted_at: options.submittedAt ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.receipt !== undefined) {
      artefacts.push(namedDataArtefact("registration_receipt", options.receipt));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "registration",
        data: {
          registration_id: options.registrationId,
          authority: options.authority,
          status: options.status,
          receipt_commitment:
            options.receipt !== undefined ? hashSha256(options.receipt) : null,
          registration_number: options.registrationNumber ?? null,
          submitted_at: options.submittedAt ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createLiteracyAttestationRequest(
  options: LiteracyAttestationRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("literacy_attestation.json", {
        attested_role: options.attestedRole,
        status: options.status,
        training_ref: options.trainingRef ?? null,
        completion_date: options.completionDate ?? null,
        training_provider: options.trainingProvider ?? null,
        certificate_digest: options.certificateDigest ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.attestation !== undefined) {
      artefacts.push(namedDataArtefact("literacy_attestation_record", options.attestation));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "literacy_attestation",
        data: {
          attested_role: options.attestedRole,
          status: options.status,
          training_ref: options.trainingRef ?? null,
          attestation_commitment:
            options.attestation !== undefined ? hashSha256(options.attestation) : null,
          completion_date: options.completionDate ?? null,
          training_provider: options.trainingProvider ?? null,
          certificate_digest: options.certificateDigest ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}

export function createIncidentReportRequest(
  options: IncidentReportRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("incident_report.json", {
        incident_id: options.incidentId,
        severity: options.severity,
        status: options.status,
        occurred_at: options.occurredAt ?? null,
        summary: options.summary ?? null,
        detection_method: options.detectionMethod ?? null,
        root_cause_summary: options.rootCauseSummary ?? null,
        corrective_action_ref: options.correctiveActionRef ?? null,
        authority_notification_required: options.authorityNotificationRequired ?? null,
        authority_notification_status: options.authorityNotificationStatus ?? null,
        metadata: options.metadata ?? null
      })
    );
    if (options.report !== undefined) {
      artefacts.push(namedDataArtefact("incident_report_record", options.report));
    }
  }

  return createCaptureRequest({
    keyId: options.keyId,
    role: options.role,
    issuer: options.issuer,
    appId: options.appId,
    env: options.env,
    requestId: options.requestId,
    threadId: options.threadId,
    userRef: options.userRef,
    systemId: options.systemId,
    deploymentId: options.deploymentId,
    version: options.version,
    complianceProfile: options.complianceProfile,
    items: [
      {
        type: "incident_report",
        data: {
          incident_id: options.incidentId,
          severity: options.severity,
          status: options.status,
          occurred_at: options.occurredAt ?? null,
          summary: options.summary ?? null,
          report_commitment: options.report !== undefined ? hashSha256(options.report) : null,
          detection_method: options.detectionMethod ?? null,
          root_cause_summary: options.rootCauseSummary ?? null,
          corrective_action_ref: options.correctiveActionRef ?? null,
          authority_notification_required: options.authorityNotificationRequired ?? null,
          authority_notification_status: options.authorityNotificationStatus ?? null,
          metadata: options.metadata ?? null
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
    artefacts
  });
}
