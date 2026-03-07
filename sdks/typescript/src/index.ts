export { ProofLayerClient, _internals } from "./client.js";
export { LocalProofLayerClient } from "./local_client.js";
export { ProofLayer } from "./proof_layer.js";
export {
  createDataGovernanceRequest,
  createLlmInteractionRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest,
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
  HttpClientOptions,
  JsonObject,
  JsonValue,
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
  ProviderCaptureOptions,
  RiskAssessmentRequestOptions,
  TechnicalDocRequestOptions,
  ToolEvent,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyPackageRequest
} from "./types.js";
