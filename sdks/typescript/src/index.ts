export { ProofLayerClient, _internals } from "./client.js";
export { LocalProofLayerClient } from "./local_client.js";
export { ProofLayer } from "./proof_layer.js";
export {
  createAdversarialTestRequest,
  createDataGovernanceRequest,
  createHumanOversightRequest,
  createIncidentReportRequest,
  createLiteracyAttestationRequest,
  createLlmInteractionRequest,
  createModelEvaluationRequest,
  createPolicyDecisionRequest,
  createRetrievalRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest,
  createTrainingProvenanceRequest,
  createToolCallRequest,
  defaultLlmInteractionArtefacts
} from "./evidence.js";
export { provedCompletion } from "./providers/openai_like.js";
export { provedMessage } from "./providers/anthropic_like.js";
export { captureToolCall } from "./tooling/tool_capture.js";
export {
  withAnthropicProofLayer,
  withGenericProofLayer,
  withOpenAIProofLayer,
  withVercelAiProofLayer
} from "./providers/index.js";
export { ProofLayerExporter, eventsToOtelSpans } from "./otel/index.js";
export { ProofLayerHttpError, ProofLayerSdkError } from "./utils/errors.js";
export {
  buildBundle,
  canonicalizeJson,
  computeMerkleRoot,
  hashSha256,
  signBundleRoot,
  verifyBundle,
  verifyBundleRoot
} from "./native.js";
export type {
  AdversarialTestRequestOptions,
  BinaryLike,
  BundleCreateClient,
  CreateBundleRequest,
  CreateBundleResponse,
  DataGovernanceRequestOptions,
  EvidenceActorOptions,
  EvidencePolicyOptions,
  EvidenceSubjectOptions,
  GenericProofLayerOptions,
  FetchLike,
  HumanOversightRequestOptions,
  HttpClientOptions,
  IncidentReportRequestOptions,
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
  RetrievalRequestOptions,
  RiskAssessmentRequestOptions,
  ModelEvaluationRequestOptions,
  TechnicalDocRequestOptions,
  TrainingProvenanceRequestOptions,
  ToolEvent,
  ToolCallRequestOptions,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyPackageRequest
} from "./types.js";
