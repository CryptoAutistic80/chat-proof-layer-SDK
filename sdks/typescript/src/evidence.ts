import { Buffer } from "node:buffer";
import { hashSha256 } from "./native.js";
import type {
  AdversarialTestRequestOptions,
  BinaryLike,
  CreateBundleRequest,
  DataGovernanceRequestOptions,
  HumanOversightRequestOptions,
  IncidentReportRequestOptions,
  JsonObject,
  JsonValue,
  LiteracyAttestationRequestOptions,
  LlmInteractionRequestOptions,
  ModelEvaluationRequestOptions,
  PolicyDecisionRequestOptions,
  ProofArtefactInput,
  RetrievalRequestOptions,
  RiskAssessmentRequestOptions,
  TechnicalDocRequestOptions,
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
  role?: "provider" | "deployer" | "integrator";
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
  context?: JsonObject;
  items: JsonObject[];
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts: ProofArtefactInput[];
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
          trace_semconv_version: traceSemconvVersion
        }
      }
    ],
    redactions: options.redactions,
    encryptionEnabled: options.encryptionEnabled,
    retentionClass: options.retentionClass,
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
        metadata: options.metadata ?? null
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
    items: [
      {
        type: "tool_call",
        data: {
          tool_name: options.toolName,
          input_commitment: options.input !== undefined ? hashSha256(options.input) : null,
          output_commitment: options.output !== undefined ? hashSha256(options.output) : null,
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

export function createRetrievalRequest(
  options: RetrievalRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("retrieval.json", {
        corpus: options.corpus,
        metadata: options.metadata ?? null
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
    items: [
      {
        type: "retrieval",
        data: {
          corpus: options.corpus,
          result_commitment: hashSha256(options.result),
          query_commitment: options.query !== undefined ? hashSha256(options.query) : null,
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

export function createHumanOversightRequest(
  options: HumanOversightRequestOptions
): CreateBundleRequest {
  const artefacts = options.artefacts ? [...options.artefacts] : [];
  if (artefacts.length === 0) {
    artefacts.push(
      jsonArtefact("human_oversight.json", {
        action: options.action,
        reviewer: options.reviewer ?? null
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
    items: [
      {
        type: "human_oversight",
        data: {
          action: options.action,
          reviewer: options.reviewer ?? null,
          notes_commitment: options.notes !== undefined ? hashSha256(options.notes) : null
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
    items: [
      {
        type: "risk_assessment",
        data: {
          risk_id: options.riskId,
          severity: options.severity,
          status: options.status,
          summary: options.summary ?? null,
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
    items: [
      {
        type: "data_governance",
        data: {
          decision: options.decision,
          dataset_ref: options.datasetRef ?? null,
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
          descriptor: options.descriptor ?? null
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
    items: [
      {
        type: "technical_doc",
        data: {
          document_ref: options.documentRef,
          section: options.section ?? null,
          commitment:
            options.commitment ??
            (options.document !== undefined ? hashSha256(options.document) : null)
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
    items: [
      {
        type: "model_evaluation",
        data: {
          evaluation_id: options.evaluationId,
          benchmark: options.benchmark,
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
    items: [
      {
        type: "adversarial_test",
        data: {
          test_id: options.testId,
          focus: options.focus,
          status: options.status,
          finding_severity: options.findingSeverity ?? null,
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
    items: [
      {
        type: "training_provenance",
        data: {
          dataset_ref: options.datasetRef,
          stage: options.stage,
          lineage_ref: options.lineageRef ?? null,
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
    items: [
      {
        type: "literacy_attestation",
        data: {
          attested_role: options.attestedRole,
          status: options.status,
          training_ref: options.trainingRef ?? null,
          attestation_commitment:
            options.attestation !== undefined ? hashSha256(options.attestation) : null,
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
