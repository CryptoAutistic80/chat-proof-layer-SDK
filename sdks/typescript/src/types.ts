export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };
export type JsonObject = Record<string, unknown>;
export type BinaryLike = Uint8Array | string | JsonValue | JsonObject;
export type ActorRole =
  | "provider"
  | "deployer"
  | "integrator"
  | "importer"
  | "distributor"
  | "authorized_representative"
  | "gpai_provider";

export interface ComplianceProfileInput extends JsonObject {
  intendedUse?: string;
  prohibitedPracticeScreening?: string;
  riskTier?: string;
  highRiskDomain?: string;
  gpaiStatus?: string;
  systemicRisk?: boolean;
  friaRequired?: boolean;
  deploymentContext?: string;
  metadata?: JsonValue;
}

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
  extends EvidenceActorOptions, EvidenceSubjectOptions, EvidencePolicyOptions {
  complianceProfile?: ComplianceProfileInput;
  artefacts?: ProofArtefactInput[];
  bundleId?: string;
  createdAt?: string;
}

export interface ProofArtefactInput {
  name: string;
  contentType?: string;
  data: BinaryLike;
}

export interface DateRange extends JsonObject {
  start?: string;
  end?: string;
}

export interface MetricSummary extends JsonObject {
  name: string;
  value: string;
  unit?: string;
  methodology?: string;
}

export interface GroupMetricSummary extends JsonObject {
  group: string;
  metrics?: MetricSummary[];
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

export interface RedactedBundle extends JsonObject {
  bundle_id: string;
  bundle_version: string;
  created_at: string;
  integrity: IntegrityInfo;
  total_items: number;
  total_artefacts: number;
  disclosed_items: DisclosedItem[];
  disclosed_artefacts: JsonObject[];
}

export interface FieldRedactedItem extends JsonObject {
  item_type: string;
  revealed_data?: JsonObject;
  field_digests?: Record<string, string>;
  redacted_fields?: string[];
  container_kinds?: Record<string, string>;
  revealed_paths?: Record<string, JsonValue>;
  path_digests?: Record<string, string>;
  redacted_paths?: string[];
}

export interface DisclosedItem extends JsonObject {
  index: number;
  item?: JsonObject;
  field_redacted_item?: FieldRedactedItem;
  proof: JsonObject;
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

export interface VerifyRedactedBundleSummary extends JsonObject {
  disclosed_item_count: number;
  disclosed_artefact_count: number;
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

export interface RedactBundleRequest {
  bundle: string | ProofBundle;
  itemIndices: number[];
  artefactIndices?: number[];
  fieldRedactions?: Record<string, string[]>;
}

export interface VerifyRedactedBundleRequest {
  bundle: string | RedactedBundle;
  artefacts: Array<{ name: string; data: BinaryLike }>;
  publicKeyPem: string;
}

export interface VerifyPackageRequest {
  bundlePackage: BinaryLike;
  publicKeyPem: string;
}

export type TrustLevel = "structural" | "trusted" | "qualified";

export type CheckState = "pass" | "warn" | "fail" | "not_run";

export interface VerificationCheck extends JsonObject {
  id: string;
  label: string;
  state: CheckState;
  detail?: string;
}

export interface TimestampVerification extends JsonObject {
  kind: string;
  provider?: string;
  generated_at: string;
  digest_algorithm: string;
  message_imprint: string;
  policy_oid: string;
  assurance_profile?: string;
  signer_count: number;
  certificate_count: number;
  assurance_profile_verified?: boolean;
  policy_oid_verified?: boolean;
  trusted?: boolean;
  chain_verified?: boolean;
  certificate_profile_verified?: boolean;
  revocation_checked?: boolean;
  ocsp_checked?: boolean;
  qualified_signer_verified?: boolean;
  signer_subject?: string;
  trust_anchor_subject?: string;
  ocsp_responder_url?: string;
}

export interface TimestampAssessment extends JsonObject {
  level: TrustLevel;
  headline: string;
  summary: string;
  next_step: string;
  checks: VerificationCheck[];
}

export type ReceiptLiveCheckMode = "off" | "best_effort" | "required";

export interface ReceiptLiveVerification extends JsonObject {
  mode: ReceiptLiveCheckMode;
  state: CheckState;
  checked_at: string;
  summary: string;
  current_tree_size?: number;
  current_root_hash?: string;
  entry_retrieved?: boolean;
  consistency_verified?: boolean;
}

export interface ReceiptVerification extends JsonObject {
  kind: string;
  provider?: string;
  log_url: string;
  entry_uuid: string;
  leaf_hash: string;
  log_id: string;
  log_index: number;
  integrated_time: string;
  tree_size: number;
  root_hash: string;
  inclusion_proof_hashes: number;
  inclusion_proof_verified: boolean;
  signed_entry_timestamp_present: boolean;
  signed_entry_timestamp_verified?: boolean;
  log_id_verified?: boolean;
  trusted?: boolean;
  timestamp_generated_at: string;
  live_verification?: ReceiptLiveVerification;
}

export interface ReceiptAssessment extends JsonObject {
  level: TrustLevel;
  headline: string;
  summary: string;
  next_step: string;
  checks: VerificationCheck[];
  live_check?: ReceiptLiveVerification;
}

export interface VerifyTimestampRequest extends JsonObject {
  bundleId?: string;
  bundleRoot?: string;
  timestamp?: JsonObject;
}

export interface VerifyTimestampResponse extends JsonObject {
  valid: boolean;
  message: string;
  verification?: TimestampVerification;
  assessment: TimestampAssessment;
}

export interface VerifyReceiptRequest extends JsonObject {
  bundleId?: string;
  bundleRoot?: string;
  receipt?: JsonObject;
  liveCheckMode?: ReceiptLiveCheckMode;
}

export interface VerifyReceiptResponse extends JsonObject {
  valid: boolean;
  message: string;
  verification?: ReceiptVerification;
  assessment: ReceiptAssessment;
}

export type CompletenessProfile =
  | "annex_iv_governance_v1"
  | "conformity_v1"
  | "fundamental_rights_v1"
  | "gpai_provider_v1"
  | "incident_response_v1"
  | "post_market_monitoring_v1"
  | "provider_governance_v1";

export type CompletenessStatus = "pass" | "warn" | "fail";

export interface CompletenessRuleResult extends JsonObject {
  rule_id: string;
  item_type: string;
  obligation_ref: string;
  status: CompletenessStatus;
  present_count: number;
  complete_count: number;
  evaluated_item_indices?: number[];
  missing_fields?: string[];
  summary: string;
}

export interface CompletenessReport extends JsonObject {
  profile: CompletenessProfile;
  status: CompletenessStatus;
  bundle_id: string;
  system_id?: string;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  rules: CompletenessRuleResult[];
}

export interface EvaluateCompletenessRequest extends JsonObject {
  profile: CompletenessProfile;
  bundle?: string | ProofBundle;
  bundleId?: string;
  packId?: string;
}

export type PackBundleFormat = "full" | "disclosure";

export interface CreatePackRequest {
  packType: string;
  bundleIds?: string[];
  systemId?: string;
  from?: string;
  to?: string;
  bundleFormat?: PackBundleFormat;
  disclosurePolicy?: string;
  disclosureTemplate?: DisclosureTemplateRenderRequest;
}

export interface PackBundleEntry extends JsonObject {
  bundle_id: string;
  created_at: string;
  actor_role: string;
  system_id?: string;
  model_id?: string;
  retention_class: string;
  item_types: string[];
  bundle_format: PackBundleFormat;
  package_name?: string;
  disclosed_item_indices?: number[];
  disclosed_item_types?: string[];
  disclosed_item_field_redactions?: Record<string, string[]>;
  disclosed_artefact_indices?: number[];
  disclosed_artefact_names?: string[];
  disclosed_artefact_bytes_included?: boolean;
  obligation_refs?: string[];
  completeness_status?: CompletenessStatus;
  matched_rules: string[];
}

export interface PackSummaryResponse extends JsonObject {
  pack_id: string;
  pack_type: string;
  created_at: string;
  system_id?: string;
  from?: string;
  to?: string;
  bundle_format: PackBundleFormat;
  disclosure_policy?: string;
  completeness_profile?: CompletenessProfile;
  completeness_status?: CompletenessStatus;
  pack_completeness_profile?: CompletenessProfile;
  pack_completeness_status?: CompletenessStatus;
  pack_completeness_pass_count?: number;
  pack_completeness_warn_count?: number;
  pack_completeness_fail_count?: number;
  bundle_count: number;
  bundle_ids: string[];
}

export interface PackManifest extends JsonObject {
  pack_id: string;
  pack_type: string;
  curation_profile: string;
  generated_at: string;
  system_id?: string;
  from?: string;
  to?: string;
  bundle_format: PackBundleFormat;
  disclosure_policy?: string;
  completeness_profile?: CompletenessProfile;
  completeness_pass_count?: number;
  completeness_warn_count?: number;
  completeness_fail_count?: number;
  pack_completeness_profile?: CompletenessProfile;
  pack_completeness_status?: CompletenessStatus;
  pack_completeness_pass_count?: number;
  pack_completeness_warn_count?: number;
  pack_completeness_fail_count?: number;
  bundle_ids: string[];
  bundles: PackBundleEntry[];
}

export interface PackReadinessSummary extends JsonObject {
  source: "pack_scoped" | "bundle_aggregate";
  profile?: CompletenessProfile;
  status?: CompletenessStatus;
  passCount?: number;
  warnCount?: number;
  failCount?: number;
}

export interface DisclosurePolicyConfig extends JsonObject {
  name: string;
  allowed_item_types?: string[];
  excluded_item_types?: string[];
  allowed_obligation_refs?: string[];
  excluded_obligation_refs?: string[];
  include_artefact_metadata?: boolean;
  include_artefact_bytes?: boolean;
  artefact_names?: string[];
  redacted_fields_by_item_type?: Record<string, string[]>;
}

export type DisclosurePolicyTemplateName =
  | "regulator_minimum"
  | "annex_iv_redacted"
  | "incident_summary"
  | "runtime_minimum"
  | "privacy_review";

export type DisclosureRedactionGroup =
  | "commitments"
  | "metadata"
  | "parameters"
  | "operational_metrics";

export interface DisclosurePolicyBuilderOptions extends JsonObject {
  name: string;
  allowedItemTypes?: string[];
  excludedItemTypes?: string[];
  allowedObligationRefs?: string[];
  excludedObligationRefs?: string[];
  includeArtefactMetadata?: boolean;
  includeArtefactBytes?: boolean;
  artefactNames?: string[];
  redactionGroups?: DisclosureRedactionGroup[];
  redactedFieldsByItemType?: Record<string, string[]>;
}

export interface DisclosurePolicyTemplateOptions extends JsonObject {
  name?: string;
  redactionGroups?: DisclosureRedactionGroup[];
  redactedFieldsByItemType?: Record<string, string[]>;
}

export interface DisclosureConfig extends JsonObject {
  policies: DisclosurePolicyConfig[];
}

export interface DisclosurePreviewRequest extends JsonObject {
  bundleId: string;
  packType?: string;
  disclosurePolicy?: string;
  policy?: DisclosurePolicyConfig;
  disclosureTemplate?: DisclosureTemplateRenderRequest;
}

export interface DisclosureTemplateRenderRequest extends JsonObject {
  profile: DisclosurePolicyTemplateName;
  name?: string;
  redactionGroups?: DisclosureRedactionGroup[];
  redactedFieldsByItemType?: Record<string, string[]>;
}

export interface DisclosureTemplateInfo extends JsonObject {
  profile: DisclosurePolicyTemplateName;
  description: string;
  default_redaction_groups?: DisclosureRedactionGroup[];
  policy: DisclosurePolicyConfig;
}

export interface DisclosureRedactionGroupInfo extends JsonObject {
  name: DisclosureRedactionGroup;
  description: string;
}

export interface DisclosureTemplateCatalog extends JsonObject {
  templates: DisclosureTemplateInfo[];
  redaction_groups: DisclosureRedactionGroupInfo[];
}

export interface DisclosurePreviewResponse extends JsonObject {
  bundle_id: string;
  policy_name: string;
  pack_type?: string;
  candidate_item_indices?: number[];
  disclosed_item_indices?: number[];
  disclosed_item_types?: string[];
  disclosed_item_obligation_refs?: string[];
  disclosed_item_field_redactions?: Record<string, string[]>;
  disclosed_artefact_indices?: number[];
  disclosed_artefact_names?: string[];
  disclosed_artefact_bytes_included?: boolean;
}

export interface RetentionPolicyConfig extends JsonObject {
  retention_class: string;
  expiry_mode?: string;
  min_duration_days: number;
  max_duration_days?: number;
  legal_basis: string;
  active: boolean;
}

export interface VaultConfigResponse extends JsonObject {
  service: JsonObject & {
    addr: string;
    max_payload_bytes: number;
    tls_enabled: boolean;
  };
  signing: JsonObject & {
    key_id: string;
    algorithm: string;
    public_key_pem: string;
    ephemeral: boolean;
  };
  storage: JsonObject & {
    metadata_backend: string;
    blob_backend: string;
  };
  retention: JsonObject & {
    grace_period_days: number;
    scan_interval_hours: number;
    policies: RetentionPolicyConfig[];
  };
  backup: JsonObject & {
    enabled: boolean;
    directory: string;
    interval_hours: number;
    retention_count: number;
    encryption: JsonObject & {
      enabled: boolean;
      algorithm?: string;
      key_id?: string;
    };
  };
  timestamp: JsonObject & {
    enabled?: boolean;
    provider?: string;
    url?: string;
    assurance?: string;
  };
  transparency: JsonObject & {
    enabled?: boolean;
    provider?: string;
    url?: string;
    scitt_format?: string;
    log_public_key_pem?: string;
  };
  disclosure: DisclosureConfig;
  auth: JsonObject & {
    enabled: boolean;
    scheme: string;
    principal_labels: string[];
  };
  tenant: JsonObject & {
    organization_id?: string;
    enforced: boolean;
  };
  audit: JsonObject & {
    enabled: boolean;
  };
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
  createBundle(
    request: CreateBundleRequest | LocalCreateBundleRequest,
  ): Promise<CreateBundleResponse>;
}

export interface LlmInteractionRequestOptions {
  keyId: string;
  role?: ActorRole;
  issuer?: string;
  appId?: string;
  env?: string;
  systemId?: string;
  complianceProfile?: ComplianceProfileInput;
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
  executionStart?: string;
  executionEnd?: string;
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts?: ProofArtefactInput[];
}

/**
 * Recommended Annex IV minimum: `riskId`, `severity`, `status`,
 * `riskDescription`, `likelihood`, `affectedGroups`, `mitigationMeasures`,
 * `residualRiskLevel`, `riskOwner`, and `testResultsSummary`.
 * Treat `metadata` as disclosure-sensitive.
 */
export interface RiskAssessmentRequestOptions extends LifecycleCaptureOptions {
  riskId: string;
  severity: string;
  status: string;
  summary?: string;
  riskDescription?: string;
  likelihood?: string;
  affectedGroups?: string[];
  mitigationMeasures?: string[];
  residualRiskLevel?: string;
  riskOwner?: string;
  vulnerableGroupsConsidered?: boolean;
  testResultsSummary?: string;
  metadata?: JsonValue;
  record?: JsonValue | JsonObject;
}

/**
 * Recommended Annex IV minimum: `decision`, `datasetRef` or `datasetName`,
 * `sourceDescription`, `collectionPeriod`, `preprocessingOperations`,
 * `biasDetectionMethodology`, `biasMetrics`, `mitigationActions`, `dataGaps`,
 * `personalDataCategories`, and `safeguards`.
 * Treat `metadata`, `personalDataCategories`, and `safeguards` as
 * disclosure-sensitive.
 */
export interface DataGovernanceRequestOptions extends LifecycleCaptureOptions {
  decision: string;
  datasetRef?: string;
  datasetName?: string;
  datasetVersion?: string;
  sourceDescription?: string;
  collectionPeriod?: DateRange;
  geographicalScope?: string[];
  preprocessingOperations?: string[];
  biasDetectionMethodology?: string;
  biasMetrics?: MetricSummary[];
  mitigationActions?: string[];
  dataGaps?: string[];
  personalDataCategories?: string[];
  safeguards?: string[];
  metadata?: JsonValue;
  record?: JsonValue | JsonObject;
}

/**
 * Recommended Annex IV minimum: `documentRef`, `annexIvSections`,
 * `systemDescriptionSummary`, `modelDescriptionSummary`,
 * `capabilitiesAndLimitations`, `designChoicesSummary`,
 * `evaluationMetricsSummary`, `humanOversightDesignSummary`, and
 * `postMarketMonitoringPlanRef`.
 */
export interface TechnicalDocRequestOptions extends LifecycleCaptureOptions {
  documentRef: string;
  section?: string;
  commitment?: string;
  annexIvSections?: string[];
  systemDescriptionSummary?: string;
  modelDescriptionSummary?: string;
  capabilitiesAndLimitations?: string;
  designChoicesSummary?: string;
  evaluationMetricsSummary?: string;
  humanOversightDesignSummary?: string;
  postMarketMonitoringPlanRef?: string;
  simplifiedTechDoc?: boolean;
  document?: BinaryLike;
  documentName?: string;
  documentContentType?: string;
  descriptor?: JsonValue | JsonObject;
}

/**
 * Recommended Annex IV minimum: `documentRef`, `versionTag`,
 * `providerIdentity`, `intendedPurpose`, `systemCapabilities`,
 * `accuracyMetrics`, `foreseeableRisks`, `humanOversightGuidance`, and
 * `logManagementGuidance`.
 * Treat `metadata` as disclosure-sensitive.
 */
export interface InstructionsForUseRequestOptions extends LifecycleCaptureOptions {
  documentRef: string;
  versionTag?: string;
  section?: string;
  commitment?: string;
  providerIdentity?: string;
  intendedPurpose?: string;
  systemCapabilities?: string[];
  accuracyMetrics?: MetricSummary[];
  foreseeableRisks?: string[];
  explainabilityCapabilities?: string[];
  humanOversightGuidance?: string[];
  computeRequirements?: string[];
  serviceLifetime?: string;
  logManagementGuidance?: string[];
  document?: BinaryLike;
  documentName?: string;
  documentContentType?: string;
  metadata?: JsonValue;
}

export interface QmsRecordRequestOptions extends LifecycleCaptureOptions {
  recordId: string;
  process: string;
  status: string;
  policyName?: string;
  revision?: string;
  effectiveDate?: string;
  expiryDate?: string;
  scope?: string;
  approvalCommitment?: string;
  auditResultsSummary?: string;
  continuousImprovementActions?: string[];
  record?: BinaryLike;
  metadata?: JsonValue;
}

export interface FundamentalRightsAssessmentRequestOptions extends LifecycleCaptureOptions {
  assessmentId: string;
  status: string;
  scope?: string;
  legalBasis?: string;
  affectedRights?: string[];
  stakeholderConsultationSummary?: string;
  mitigationPlanSummary?: string;
  assessor?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface StandardsAlignmentRequestOptions extends LifecycleCaptureOptions {
  standardRef: string;
  status: string;
  scope?: string;
  mapping?: BinaryLike;
  metadata?: JsonValue;
}

export interface PostMarketMonitoringRequestOptions extends LifecycleCaptureOptions {
  planId: string;
  status: string;
  summary?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface CorrectiveActionRequestOptions extends LifecycleCaptureOptions {
  actionId: string;
  status: string;
  summary?: string;
  dueAt?: string;
  record?: BinaryLike;
  metadata?: JsonValue;
}

export interface AuthorityNotificationRequestOptions extends LifecycleCaptureOptions {
  notificationId: string;
  authority: string;
  status: string;
  incidentId?: string;
  dueAt?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface AuthoritySubmissionRequestOptions extends LifecycleCaptureOptions {
  submissionId: string;
  authority: string;
  status: string;
  channel?: string;
  submittedAt?: string;
  document?: BinaryLike;
  metadata?: JsonValue;
}

export interface ReportingDeadlineRequestOptions extends LifecycleCaptureOptions {
  deadlineId: string;
  authority: string;
  obligationRef: string;
  dueAt: string;
  status: string;
  incidentId?: string;
  metadata?: JsonValue;
}

export interface RegulatorCorrespondenceRequestOptions extends LifecycleCaptureOptions {
  correspondenceId: string;
  authority: string;
  direction: string;
  status: string;
  occurredAt?: string;
  message?: BinaryLike;
  metadata?: JsonValue;
}

export interface ToolCallRequestOptions extends LifecycleCaptureOptions {
  toolName: string;
  input?: BinaryLike;
  output?: BinaryLike;
  metadata?: JsonValue;
  executionStart?: string;
  executionEnd?: string;
}

export interface RetrievalRequestOptions extends LifecycleCaptureOptions {
  corpus: string;
  result: BinaryLike;
  query?: BinaryLike;
  metadata?: JsonValue;
  databaseReference?: string;
  executionStart?: string;
  executionEnd?: string;
}

/**
 * Recommended Annex IV minimum: `action`, `reviewer`, `actorRole`,
 * `anomalyDetected`, `overrideAction`, `automationBiasDetected`,
 * `stopTriggered`, and `stopReason`. Supporting notes remain an artefact.
 */
export interface HumanOversightRequestOptions extends LifecycleCaptureOptions {
  action: string;
  reviewer?: string;
  notes?: BinaryLike;
  actorRole?: string;
  anomalyDetected?: boolean;
  overrideAction?: string;
  interpretationGuidanceFollowed?: boolean;
  automationBiasDetected?: boolean;
  twoPersonVerification?: boolean;
  stopTriggered?: boolean;
  stopReason?: string;
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
  completionDate?: string;
  trainingProvider?: string;
  certificateDigest?: string;
  attestation?: BinaryLike;
  metadata?: JsonValue;
}

export interface IncidentReportRequestOptions extends LifecycleCaptureOptions {
  incidentId: string;
  severity: string;
  status: string;
  occurredAt?: string;
  summary?: string;
  detectionMethod?: string;
  rootCauseSummary?: string;
  correctiveActionRef?: string;
  authorityNotificationRequired?: boolean;
  authorityNotificationStatus?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface ModelEvaluationRequestOptions extends LifecycleCaptureOptions {
  evaluationId: string;
  benchmark: string;
  status: string;
  summary?: string;
  metricsSummary?: MetricSummary[];
  groupPerformance?: GroupMetricSummary[];
  evaluationMethodology?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface AdversarialTestRequestOptions extends LifecycleCaptureOptions {
  testId: string;
  focus: string;
  status: string;
  findingSeverity?: string;
  threatModel?: string;
  testMethodology?: string;
  attackClasses?: string[];
  affectedComponents?: string[];
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface TrainingProvenanceRequestOptions extends LifecycleCaptureOptions {
  datasetRef: string;
  stage: string;
  lineageRef?: string;
  computeMetricsRef?: string;
  trainingDatasetSummary?: string;
  consortiumContext?: string;
  record?: BinaryLike;
  metadata?: JsonValue;
}

export interface ComputeMetricsRequestOptions extends LifecycleCaptureOptions {
  computeId: string;
  trainingFlopsEstimate: string;
  thresholdBasisRef: string;
  thresholdValue: string;
  thresholdStatus: string;
  estimationMethodology?: string;
  measuredAt?: string;
  computeResourcesSummary?: MetricSummary[];
  consortiumContext?: string;
  metadata?: JsonValue;
  record?: BinaryLike;
}

export interface DownstreamDocumentationRequestOptions extends LifecycleCaptureOptions {
  documentRef: string;
  audience: string;
  status: string;
  document?: BinaryLike;
  metadata?: JsonValue;
}

export interface CopyrightPolicyRequestOptions extends LifecycleCaptureOptions {
  policyRef: string;
  status: string;
  jurisdiction?: string;
  document?: BinaryLike;
  metadata?: JsonValue;
}

export interface TrainingSummaryRequestOptions extends LifecycleCaptureOptions {
  summaryRef: string;
  status: string;
  audience?: string;
  document?: BinaryLike;
  metadata?: JsonValue;
}

export interface ConformityAssessmentRequestOptions extends LifecycleCaptureOptions {
  assessmentId: string;
  procedure: string;
  status: string;
  assessmentBody?: string;
  certificateRef?: string;
  report?: BinaryLike;
  metadata?: JsonValue;
}

export interface DeclarationRequestOptions extends LifecycleCaptureOptions {
  declarationId: string;
  jurisdiction: string;
  status: string;
  signatory?: string;
  documentVersion?: string;
  document?: BinaryLike;
  metadata?: JsonValue;
}

export interface RegistrationRequestOptions extends LifecycleCaptureOptions {
  registrationId: string;
  authority: string;
  status: string;
  registrationNumber?: string;
  submittedAt?: string;
  receipt?: BinaryLike;
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
  complianceProfile?: ComplianceProfileInput;
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
  complianceProfile?: ComplianceProfileInput;
  requestId?: string;
  threadId?: string | null;
  userRef?: string | null;
  modelParameters?: JsonValue;
  retrievalCommitment?: string | null;
  toolOutputsCommitment?: string | null;
  trace?: JsonValue | JsonObject;
  traceCommitment?: string | null;
  otelSemconvVersion?: string;
  executionStart?: string;
  executionEnd?: string;
  redactions?: string[];
  encryptionEnabled?: boolean;
  retentionClass?: string;
  artefacts?: ProofArtefactInput[];
  bundleId?: string;
  createdAt?: string;
}

export interface GenericProofLayerOptions<
  TParams extends JsonObject = JsonObject,
  TResult extends JsonObject = JsonObject,
> extends ProviderCaptureOptions {
  provider: string;
  model?: string | ((params: TParams, result: TResult) => string);
  buildTrace?: (
    params: TParams,
    result: TResult,
  ) => JsonValue | JsonObject | undefined;
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

export interface ProofLayerDiscloseOptions {
  bundle: string | ProofBundle;
  itemIndices: number[];
  artefactIndices?: number[];
  fieldRedactions?: Record<string, string[]>;
}
