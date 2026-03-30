import {
  createAdversarialTestRequest as createAdversarialTestRequestAdvanced,
  createAuthorityNotificationRequest as createAuthorityNotificationRequestAdvanced,
  createAuthoritySubmissionRequest as createAuthoritySubmissionRequestAdvanced,
  createConformityAssessmentRequest as createConformityAssessmentRequestAdvanced,
  createComputeMetricsRequest as createComputeMetricsRequestAdvanced,
  createCopyrightPolicyRequest as createCopyrightPolicyRequestAdvanced,
  createCorrectiveActionRequest as createCorrectiveActionRequestAdvanced,
  createDataGovernanceRequest as createDataGovernanceRequestAdvanced,
  createDeclarationRequest as createDeclarationRequestAdvanced,
  createDownstreamDocumentationRequest as createDownstreamDocumentationRequestAdvanced,
  createFundamentalRightsAssessmentRequest as createFundamentalRightsAssessmentRequestAdvanced,
  createHumanOversightRequest as createHumanOversightRequestAdvanced,
  createIncidentReportRequest as createIncidentReportRequestAdvanced,
  createInstructionsForUseRequest as createInstructionsForUseRequestAdvanced,
  createLiteracyAttestationRequest as createLiteracyAttestationRequestAdvanced,
  createLlmInteractionRequest as createLlmInteractionRequestAdvanced,
  createModelEvaluationRequest as createModelEvaluationRequestAdvanced,
  createPostMarketMonitoringRequest as createPostMarketMonitoringRequestAdvanced,
  createPolicyDecisionRequest as createPolicyDecisionRequestAdvanced,
  createQmsRecordRequest as createQmsRecordRequestAdvanced,
  createRegulatorCorrespondenceRequest as createRegulatorCorrespondenceRequestAdvanced,
  createRegistrationRequest as createRegistrationRequestAdvanced,
  createReportingDeadlineRequest as createReportingDeadlineRequestAdvanced,
  createRetrievalRequest as createRetrievalRequestAdvanced,
  createRiskAssessmentRequest as createRiskAssessmentRequestAdvanced,
  createStandardsAlignmentRequest as createStandardsAlignmentRequestAdvanced,
  createTechnicalDocRequest as createTechnicalDocRequestAdvanced,
  createTrainingSummaryRequest as createTrainingSummaryRequestAdvanced,
  createTrainingProvenanceRequest as createTrainingProvenanceRequestAdvanced,
  createToolCallRequest as createToolCallRequestAdvanced,
  defaultLlmInteractionArtefacts as defaultLlmInteractionArtefactsAdvanced
} from "./evidence.js";
import { captureToolCall as captureToolCallAdvanced } from "./tooling/tool_capture.js";

export { ProofLayerClient, _internals } from "./client.js";
export { LocalProofLayerClient } from "./local_client.js";
export { ProofLayer } from "./proof_layer.js";
export {
  createDisclosurePolicy,
  createDisclosurePolicyTemplate,
  disclosurePolicyTemplateNames,
  disclosureRedactionGroups
} from "./disclosure_policy.js";
const warnedDefaultSurfaceApis = new Set<string>();

function warnDeprecatedDefaultSurface(apiName: string, advancedImport: string): void {
  if (warnedDefaultSurfaceApis.has(apiName)) {
    return;
  }
  warnedDefaultSurfaceApis.add(apiName);
  process.emitWarning(
    `${apiName} is deprecated on @proof-layer/sdk default imports. ` +
      `Use ${advancedImport} from @proof-layer/sdk/advanced.`,
    { code: "PROOF_LAYER_DEFAULT_SURFACE_DEPRECATED" }
  );
}

// Deprecated: import non-chat evidence builders from "@proof-layer/sdk/advanced".
export const createAdversarialTestRequest: typeof createAdversarialTestRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createAdversarialTestRequest", "{ createAdversarialTestRequest }");
  return createAdversarialTestRequestAdvanced(...args);
};
export const createAuthorityNotificationRequest: typeof createAuthorityNotificationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createAuthorityNotificationRequest", "{ createAuthorityNotificationRequest }");
  return createAuthorityNotificationRequestAdvanced(...args);
};
export const createAuthoritySubmissionRequest: typeof createAuthoritySubmissionRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createAuthoritySubmissionRequest", "{ createAuthoritySubmissionRequest }");
  return createAuthoritySubmissionRequestAdvanced(...args);
};
export const createConformityAssessmentRequest: typeof createConformityAssessmentRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createConformityAssessmentRequest", "{ createConformityAssessmentRequest }");
  return createConformityAssessmentRequestAdvanced(...args);
};
export const createComputeMetricsRequest: typeof createComputeMetricsRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createComputeMetricsRequest", "{ createComputeMetricsRequest }");
  return createComputeMetricsRequestAdvanced(...args);
};
export const createCopyrightPolicyRequest: typeof createCopyrightPolicyRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createCopyrightPolicyRequest", "{ createCopyrightPolicyRequest }");
  return createCopyrightPolicyRequestAdvanced(...args);
};
export const createCorrectiveActionRequest: typeof createCorrectiveActionRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createCorrectiveActionRequest", "{ createCorrectiveActionRequest }");
  return createCorrectiveActionRequestAdvanced(...args);
};
export const createDataGovernanceRequest: typeof createDataGovernanceRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createDataGovernanceRequest", "{ createDataGovernanceRequest }");
  return createDataGovernanceRequestAdvanced(...args);
};
export const createDeclarationRequest: typeof createDeclarationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createDeclarationRequest", "{ createDeclarationRequest }");
  return createDeclarationRequestAdvanced(...args);
};
export const createDownstreamDocumentationRequest: typeof createDownstreamDocumentationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface(
    "createDownstreamDocumentationRequest",
    "{ createDownstreamDocumentationRequest }"
  );
  return createDownstreamDocumentationRequestAdvanced(...args);
};
export const createFundamentalRightsAssessmentRequest: typeof createFundamentalRightsAssessmentRequestAdvanced = (
  ...args
) => {
  warnDeprecatedDefaultSurface(
    "createFundamentalRightsAssessmentRequest",
    "{ createFundamentalRightsAssessmentRequest }"
  );
  return createFundamentalRightsAssessmentRequestAdvanced(...args);
};
export const createHumanOversightRequest: typeof createHumanOversightRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createHumanOversightRequest", "{ createHumanOversightRequest }");
  return createHumanOversightRequestAdvanced(...args);
};
export const createIncidentReportRequest: typeof createIncidentReportRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createIncidentReportRequest", "{ createIncidentReportRequest }");
  return createIncidentReportRequestAdvanced(...args);
};
export const createInstructionsForUseRequest: typeof createInstructionsForUseRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createInstructionsForUseRequest", "{ createInstructionsForUseRequest }");
  return createInstructionsForUseRequestAdvanced(...args);
};
export const createLiteracyAttestationRequest: typeof createLiteracyAttestationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createLiteracyAttestationRequest", "{ createLiteracyAttestationRequest }");
  return createLiteracyAttestationRequestAdvanced(...args);
};
export const createLlmInteractionRequest: typeof createLlmInteractionRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createLlmInteractionRequest", "{ createLlmInteractionRequest }");
  return createLlmInteractionRequestAdvanced(...args);
};
export const createModelEvaluationRequest: typeof createModelEvaluationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createModelEvaluationRequest", "{ createModelEvaluationRequest }");
  return createModelEvaluationRequestAdvanced(...args);
};
export const createPostMarketMonitoringRequest: typeof createPostMarketMonitoringRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createPostMarketMonitoringRequest", "{ createPostMarketMonitoringRequest }");
  return createPostMarketMonitoringRequestAdvanced(...args);
};
export const createPolicyDecisionRequest: typeof createPolicyDecisionRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createPolicyDecisionRequest", "{ createPolicyDecisionRequest }");
  return createPolicyDecisionRequestAdvanced(...args);
};
export const createQmsRecordRequest: typeof createQmsRecordRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createQmsRecordRequest", "{ createQmsRecordRequest }");
  return createQmsRecordRequestAdvanced(...args);
};
export const createRegulatorCorrespondenceRequest: typeof createRegulatorCorrespondenceRequestAdvanced = (
  ...args
) => {
  warnDeprecatedDefaultSurface(
    "createRegulatorCorrespondenceRequest",
    "{ createRegulatorCorrespondenceRequest }"
  );
  return createRegulatorCorrespondenceRequestAdvanced(...args);
};
export const createRegistrationRequest: typeof createRegistrationRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createRegistrationRequest", "{ createRegistrationRequest }");
  return createRegistrationRequestAdvanced(...args);
};
export const createReportingDeadlineRequest: typeof createReportingDeadlineRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createReportingDeadlineRequest", "{ createReportingDeadlineRequest }");
  return createReportingDeadlineRequestAdvanced(...args);
};
export const createRetrievalRequest: typeof createRetrievalRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createRetrievalRequest", "{ createRetrievalRequest }");
  return createRetrievalRequestAdvanced(...args);
};
export const createRiskAssessmentRequest: typeof createRiskAssessmentRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createRiskAssessmentRequest", "{ createRiskAssessmentRequest }");
  return createRiskAssessmentRequestAdvanced(...args);
};
export const createStandardsAlignmentRequest: typeof createStandardsAlignmentRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createStandardsAlignmentRequest", "{ createStandardsAlignmentRequest }");
  return createStandardsAlignmentRequestAdvanced(...args);
};
export const createTechnicalDocRequest: typeof createTechnicalDocRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createTechnicalDocRequest", "{ createTechnicalDocRequest }");
  return createTechnicalDocRequestAdvanced(...args);
};
export const createTrainingSummaryRequest: typeof createTrainingSummaryRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createTrainingSummaryRequest", "{ createTrainingSummaryRequest }");
  return createTrainingSummaryRequestAdvanced(...args);
};
export const createTrainingProvenanceRequest: typeof createTrainingProvenanceRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createTrainingProvenanceRequest", "{ createTrainingProvenanceRequest }");
  return createTrainingProvenanceRequestAdvanced(...args);
};
export const createToolCallRequest: typeof createToolCallRequestAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("createToolCallRequest", "{ createToolCallRequest }");
  return createToolCallRequestAdvanced(...args);
};
export const defaultLlmInteractionArtefacts: typeof defaultLlmInteractionArtefactsAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("defaultLlmInteractionArtefacts", "{ defaultLlmInteractionArtefacts }");
  return defaultLlmInteractionArtefactsAdvanced(...args);
};
export { provedCompletion } from "./providers/openai_like.js";
export { provedMessage } from "./providers/anthropic_like.js";
// Deprecated: import captureToolCall from "@proof-layer/sdk/advanced".
export const captureToolCall: typeof captureToolCallAdvanced = (...args) => {
  warnDeprecatedDefaultSurface("captureToolCall", "{ captureToolCall }");
  return captureToolCallAdvanced(...args);
};
export {
  withAnthropicProofLayer,
  withGenericProofLayer,
  withOpenAIProofLayer,
  withVercelAiProofLayer
} from "./providers/index.js";
export { ProofLayerExporter, eventsToOtelSpans } from "./otel/index.js";
export { ProofLayerHttpError, ProofLayerSdkError } from "./utils/errors.js";
export { selectPackReadiness } from "./utils/pack_readiness.js";
export {
  buildBundle,
  canonicalizeJson,
  evaluateCompleteness,
  computeMerkleRoot,
  hashSha256,
  redactBundle,
  signBundleRoot,
  verifyBundle,
  verifyRedactedBundle,
  verifyBundleRoot
} from "./native.js";
export type {
  AdversarialTestRequestOptions,
  ActorRole,
  AuthorityNotificationRequestOptions,
  AuthoritySubmissionRequestOptions,
  BinaryLike,
  BundleCreateClient,
  CheckState,
  CompletenessProfile,
  CompletenessReport,
  CompletenessRuleResult,
  CompletenessStatus,
  ComplianceProfileInput,
  ComputeMetricsRequestOptions,
  ConformityAssessmentRequestOptions,
  CopyrightPolicyRequestOptions,
  CreatePackRequest,
  CreateBundleRequest,
  CreateBundleResponse,
  CorrectiveActionRequestOptions,
  DataGovernanceRequestOptions,
  DateRange,
  DeclarationRequestOptions,
  DisclosureConfig,
  DisclosurePolicyConfig,
  DisclosurePolicyBuilderOptions,
  DisclosureTemplateCatalog,
  DisclosureTemplateInfo,
  DisclosureTemplateRenderRequest,
  EvaluateCompletenessRequest,
  DisclosurePolicyTemplateName,
  DisclosurePolicyTemplateOptions,
  DisclosureRedactionGroup,
  DisclosureRedactionGroupInfo,
  DisclosurePreviewRequest,
  DisclosurePreviewResponse,
  DownstreamDocumentationRequestOptions,
  EvidenceActorOptions,
  EvidencePolicyOptions,
  EvidenceSubjectOptions,
  FundamentalRightsAssessmentRequestOptions,
  GenericProofLayerOptions,
  FetchLike,
  HumanOversightRequestOptions,
  HttpClientOptions,
  IncidentReportRequestOptions,
  InstructionsForUseRequestOptions,
  JsonObject,
  JsonValue,
  LiteracyAttestationRequestOptions,
  LifecycleCaptureOptions,
  LlmInteractionRequestOptions,
  LocalBuildOptions,
  LocalClientOptions,
  LocalCreateBundleRequest,
  OtelSpan,
  ProofArtefactInput,
  ProofBundle,
  ProofLayerAttachment,
  ProofLayerCaptureOptions,
  ProofLayerOptions,
  ProofLayerResult,
  PolicyDecisionRequestOptions,
  ProviderCaptureOptions,
  RegulatorCorrespondenceRequestOptions,
  RegistrationRequestOptions,
  ReportingDeadlineRequestOptions,
  RetrievalRequestOptions,
  RiskAssessmentRequestOptions,
  ModelEvaluationRequestOptions,
  GroupMetricSummary,
  MetricSummary,
  PostMarketMonitoringRequestOptions,
  QmsRecordRequestOptions,
  TechnicalDocRequestOptions,
  StandardsAlignmentRequestOptions,
  TrainingSummaryRequestOptions,
  TrainingProvenanceRequestOptions,
  ToolEvent,
  ToolCallRequestOptions,
  PackBundleEntry,
  PackBundleFormat,
  PackManifest,
  PackReadinessSummary,
  PackSummaryResponse,
  ReceiptAssessment,
  ReceiptLiveCheckMode,
  ReceiptLiveVerification,
  ReceiptVerification,
  TimestampAssessment,
  TimestampVerification,
  TrustLevel,
  VerificationCheck,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyPackageRequest,
  VerifyReceiptRequest,
  VerifyReceiptResponse,
  VerifyTimestampRequest,
  VerifyTimestampResponse,
  ProofLayerDiscloseOptions,
  RedactBundleRequest,
  RedactedBundle,
  VerifyRedactedBundleRequest,
  VerifyRedactedBundleSummary
} from "./types.js";
