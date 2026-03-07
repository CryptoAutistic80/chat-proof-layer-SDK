export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = Record<string, unknown>;
export type BinaryLike = Uint8Array | string | JsonValue | JsonObject;
export type ActorRole = "provider" | "deployer" | "integrator";

export interface EvidenceSubjectOptions {
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  systemId?: string;
  modelId?: string;
  deploymentId?: string;
  version?: string;
}

export interface EvidencePolicyOptions {
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
}

export interface EvidenceActorOptions {
  keyId: string;
  role?: ActorRole;
  issuer?: string;
  appId?: string;
  env?: string;
}

export interface LifecycleCaptureOptions
  extends EvidenceActorOptions,
    EvidenceSubjectOptions,
    EvidencePolicyOptions {
  artefacts?: ProofArtefactInput[];
  bundleId?: string;
  createdAt?: string;
}

export interface ProofArtefactInput {
  name: string;
  contentType?: string;
  data: BinaryLike;
}

export interface InlineArtefactRequest {
  name: string;
  content_type: string;
  data_base64: string;
}

export interface SignatureInfo {
  format?: string;
  alg?: string;
  kid: string;
  value: string;
}

export interface IntegrityInfo extends JsonObject {
  header_digest: string;
  bundle_root: string;
  signature: SignatureInfo;
}

export interface ProofBundle extends JsonObject {
  bundle_id: string;
  bundle_version: string;
  created_at: string;
  integrity: IntegrityInfo;
}

export interface CreateBundleResponse extends JsonObject {
  bundle_id: string;
  bundle_root: string;
  signature: string;
  created_at?: string;
  bundle?: ProofBundle;
}

export interface VerifyBundleSummary extends JsonObject {
  artefact_count: number;
}

export interface FetchLike {
  (input: string, init?: RequestInit): Promise<Response>;
}

export interface ProviderCaptureOptions {
  issuer?: string;
  appId?: string;
  env?: string;
  signingKeyId?: string;
  role?: ActorRole;
  systemId?: string;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  modelParameters?: JsonValue;
  retrievalCommitment?: string | null;
  toolOutputsCommitment?: string | null;
  otelSemconvVersion?: string;
  trace?: JsonValue | JsonObject;
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts?: ProofArtefactInput[];
}

export interface ToolEvent extends JsonObject {
  event_id: string;
  timestamp: string;
  name: string;
  input: JsonValue | JsonObject;
  output: JsonValue | JsonObject;
  input_commitment: string;
  output_commitment: string;
}

export interface OtelSpan extends JsonObject {
  trace_id: string;
  span_id: string;
  name: string;
  start_time_unix_nano: string;
  end_time_unix_nano: string;
  attributes: JsonObject;
}

export interface CreateBundleRequest {
  capture: JsonObject;
  artefacts: ProofArtefactInput[];
}

export interface VerifyBundleRequest {
  bundle: string | ProofBundle;
  artefacts: Array<{ name: string; data: BinaryLike }>;
  publicKeyPem: string;
}

export interface VerifyPackageRequest {
  bundlePackage: BinaryLike;
  publicKeyPem: string;
}

export interface LocalClientOptions {
  signingKeyPem: string;
  signingKeyId?: string;
  bundleIdFactory?: () => string;
  createdAtFactory?: () => string;
}

export interface HttpClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetchImpl?: FetchLike;
}

export interface LocalBuildOptions {
  capture: JsonObject | string;
  artefacts: ProofArtefactInput[];
  keyPem: string;
  kid: string;
  bundleId: string;
  createdAt: string;
}

export interface LocalCreateBundleRequest extends CreateBundleRequest {
  bundleId?: string;
  createdAt?: string;
  signingKeyPem?: string;
  signingKeyId?: string;
}

export interface BundleCreateClient {
  createBundle(request: CreateBundleRequest | LocalCreateBundleRequest): Promise<CreateBundleResponse>;
}

export interface LlmInteractionRequestOptions {
  keyId: string;
  role?: ActorRole;
  issuer?: string;
  appId?: string;
  env?: string;
  systemId?: string;
  provider: string;
  model: string;
  input: JsonValue | JsonObject;
  output: JsonValue | JsonObject;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  modelParameters?: JsonValue;
  retrievalCommitment?: string | null;
  toolOutputsCommitment?: string | null;
  trace?: JsonValue | JsonObject;
  traceCommitment?: string | null;
  otelSemconvVersion?: string;
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts?: ProofArtefactInput[];
}

export interface RiskAssessmentRequestOptions extends LifecycleCaptureOptions {
  riskId: string;
  severity: string;
  status: string;
  summary?: string;
  metadata?: JsonValue;
  record?: JsonValue | JsonObject;
}

export interface DataGovernanceRequestOptions extends LifecycleCaptureOptions {
  decision: string;
  datasetRef?: string;
  metadata?: JsonValue;
  record?: JsonValue | JsonObject;
}

export interface TechnicalDocRequestOptions extends LifecycleCaptureOptions {
  documentRef: string;
  section?: string;
  commitment?: string;
  document?: BinaryLike;
  documentName?: string;
  documentContentType?: string;
  descriptor?: JsonValue | JsonObject;
}

export interface ToolCallRequestOptions extends LifecycleCaptureOptions {
  toolName: string;
  input?: BinaryLike;
  output?: BinaryLike;
  metadata?: JsonValue;
}

export interface RetrievalRequestOptions extends LifecycleCaptureOptions {
  corpus: string;
  result: BinaryLike;
  query?: BinaryLike;
  metadata?: JsonValue;
}

export interface HumanOversightRequestOptions extends LifecycleCaptureOptions {
  action: string;
  reviewer?: string;
  notes?: BinaryLike;
}

export interface PolicyDecisionRequestOptions extends LifecycleCaptureOptions {
  policyName: string;
  decision: string;
  rationale?: BinaryLike;
  metadata?: JsonValue;
}

export interface LiteracyAttestationRequestOptions extends LifecycleCaptureOptions {
  attestedRole: string;
  status: string;
  trainingRef?: string;
  attestation?: BinaryLike;
  metadata?: JsonValue;
}

export interface IncidentReportRequestOptions extends LifecycleCaptureOptions {
  incidentId: string;
  severity: string;
  status: string;
  occurredAt?: string;
  summary?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface ModelEvaluationRequestOptions extends LifecycleCaptureOptions {
  evaluationId: string;
  benchmark: string;
  status: string;
  summary?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface AdversarialTestRequestOptions extends LifecycleCaptureOptions {
  testId: string;
  focus: string;
  status: string;
  findingSeverity?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface TrainingProvenanceRequestOptions extends LifecycleCaptureOptions {
  datasetRef: string;
  stage: string;
  lineageRef?: string;
  record?: BinaryLike;
  metadata?: JsonValue;
}

export interface ProofLayerOptions {
  vaultUrl?: string;
  apiKey?: string;
  fetchImpl?: FetchLike;
  signingKeyPem?: string;
  signingKeyPath?: string;
  keyId?: string;
  systemId?: string;
  role?: ActorRole;
  issuer?: string;
  appId?: string;
  env?: string;
  bundleIdFactory?: () => string;
  createdAtFactory?: () => string;
}

export interface ProofLayerCaptureOptions {
  evidenceType?: "llm_interaction";
  provider: string;
  model: string;
  input: JsonValue | JsonObject;
  output: JsonValue | JsonObject;
  systemId?: string;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  modelParameters?: JsonValue;
  retrievalCommitment?: string | null;
  toolOutputsCommitment?: string | null;
  trace?: JsonValue | JsonObject;
  traceCommitment?: string | null;
  otelSemconvVersion?: string;
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts?: ProofArtefactInput[];
  bundleId?: string;
  createdAt?: string;
}

export interface GenericProofLayerOptions<
  TParams extends JsonObject = JsonObject,
  TResult extends JsonObject = JsonObject
> extends ProviderCaptureOptions {
  provider: string;
  model?: string | ((params: TParams, result: TResult) => string);
  buildTrace?: (params: TParams, result: TResult) => JsonValue | JsonObject | undefined;
}

export interface ProofLayerResult {
  bundleId: string;
  bundleRoot: string;
  signature: string;
  createdAt?: string;
  bundle?: ProofBundle;
}

export interface ProofLayerAttachment {
  bundleId: string;
  bundleRoot: string;
  signature: string;
  createdAt?: string;
  bundle?: ProofBundle;
}
