import { readFileSync } from "node:fs";
import {
  createAdversarialTestRequest,
  createConformityAssessmentRequest,
  createDataGovernanceRequest,
  createDeclarationRequest,
  createHumanOversightRequest,
  createIncidentReportRequest,
  createLiteracyAttestationRequest,
  createLlmInteractionRequest,
  createModelEvaluationRequest,
  createPolicyDecisionRequest,
  createRegistrationRequest,
  createRetrievalRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest,
  createTrainingProvenanceRequest,
  createToolCallRequest
} from "./evidence.js";
import { LocalProofLayerClient } from "./local_client.js";
import { ProofLayerClient } from "./client.js";
import type {
  AdversarialTestRequestOptions,
  BundleCreateClient,
  CreatePackRequest,
  ConformityAssessmentRequestOptions,
  CreateBundleRequest,
  CreateBundleResponse,
  DataGovernanceRequestOptions,
  DeclarationRequestOptions,
  DisclosureConfig,
  DisclosurePreviewRequest,
  DisclosurePreviewResponse,
  DisclosureTemplateCatalog,
  DisclosureTemplateInfo,
  DisclosureTemplateRenderRequest,
  HumanOversightRequestOptions,
  IncidentReportRequestOptions,
  LiteracyAttestationRequestOptions,
  ModelEvaluationRequestOptions,
  PackManifest,
  PackSummaryResponse,
  PolicyDecisionRequestOptions,
  ProofLayerCaptureOptions,
  ProofLayerDiscloseOptions,
  ProofLayerOptions,
  ProofLayerResult,
  RedactedBundle,
  RegistrationRequestOptions,
  RetrievalRequestOptions,
  RiskAssessmentRequestOptions,
  TechnicalDocRequestOptions,
  TrainingProvenanceRequestOptions,
  ToolCallRequestOptions,
  VaultConfigResponse,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyRedactedBundleRequest,
  VerifyRedactedBundleSummary
} from "./types.js";

function resolveSigningKeyPem(options: ProofLayerOptions): string | undefined {
  if (options.signingKeyPem) {
    return options.signingKeyPem;
  }
  if (options.signingKeyPath) {
    return readFileSync(options.signingKeyPath, "utf8");
  }
  return undefined;
}

export class ProofLayer implements BundleCreateClient {
  readonly mode: "local" | "vault";
  readonly keyId: string;
  readonly systemId?: string;
  readonly role: "provider" | "deployer" | "integrator";
  readonly issuer: string;
  readonly appId: string;
  readonly env: string;
  readonly client: BundleCreateClient;

  constructor(options: ProofLayerOptions) {
    this.keyId = options.keyId ?? "kid-dev-01";
    this.systemId = options.systemId;
    this.role = options.role ?? "provider";
    this.issuer = options.issuer ?? "proof-layer-ts";
    this.appId = options.appId ?? "typescript-sdk";
    this.env = options.env ?? "dev";

    const signingKeyPem = resolveSigningKeyPem(options);
    if (signingKeyPem) {
      this.mode = "local";
      this.client = new LocalProofLayerClient({
        signingKeyPem,
        signingKeyId: this.keyId,
        bundleIdFactory: options.bundleIdFactory,
        createdAtFactory: options.createdAtFactory
      });
      return;
    }

    if (options.vaultUrl) {
      this.mode = "vault";
      this.client = new ProofLayerClient({
        baseUrl: options.vaultUrl,
        apiKey: options.apiKey,
        fetchImpl: options.fetchImpl
      });
      return;
    }

    throw new Error("ProofLayer requires either signingKeyPem/signingKeyPath or vaultUrl");
  }

  async createBundle(request: CreateBundleRequest): Promise<CreateBundleResponse> {
    return this.client.createBundle(request);
  }

  async #submitCapture(
    request: CreateBundleRequest,
    localOptions: { bundleId?: string; createdAt?: string } = {}
  ): Promise<ProofLayerResult> {
    const create = await this.client.createBundle({
      ...request,
      ...(this.mode === "local"
        ? { bundleId: localOptions.bundleId, createdAt: localOptions.createdAt }
        : {})
    });

    return {
      bundleId: create.bundle_id,
      bundleRoot: create.bundle_root,
      signature: create.signature,
      createdAt: create.created_at,
      bundle: create.bundle
    };
  }

  async verifyBundle(request: VerifyBundleRequest): Promise<VerifyBundleSummary> {
    if ("verifyBundle" in this.client && typeof this.client.verifyBundle === "function") {
      return (this.client as LocalProofLayerClient | ProofLayerClient).verifyBundle(request);
    }
    throw new Error("underlying client does not support verifyBundle");
  }

  async disclose({
    bundle,
    itemIndices,
    artefactIndices,
    fieldRedactions
  }: ProofLayerDiscloseOptions): Promise<RedactedBundle> {
    if ("discloseBundle" in this.client && typeof this.client.discloseBundle === "function") {
      return (this.client as LocalProofLayerClient).discloseBundle({
        bundle,
        itemIndices,
        artefactIndices,
        fieldRedactions
      });
    }
    throw new Error("underlying client does not support disclose; use local signing mode");
  }

  async verifyRedactedBundle(
    request: VerifyRedactedBundleRequest
  ): Promise<VerifyRedactedBundleSummary> {
    if (
      "verifyRedactedBundle" in this.client &&
      typeof this.client.verifyRedactedBundle === "function"
    ) {
      return (this.client as LocalProofLayerClient).verifyRedactedBundle(request);
    }
    throw new Error("underlying client does not support verifyRedactedBundle");
  }

  async createPack(request: CreatePackRequest): Promise<PackSummaryResponse> {
    if ("createPack" in this.client && typeof this.client.createPack === "function") {
      return (this.client as ProofLayerClient).createPack(request);
    }
    throw new Error("underlying client does not support createPack; use vault mode");
  }

  async getPackManifest(packId: string): Promise<PackManifest> {
    if ("getPackManifest" in this.client && typeof this.client.getPackManifest === "function") {
      return (this.client as ProofLayerClient).getPackManifest(packId);
    }
    throw new Error("underlying client does not support getPackManifest; use vault mode");
  }

  async downloadPackExport(packId: string): Promise<Uint8Array> {
    if (
      "downloadPackExport" in this.client &&
      typeof this.client.downloadPackExport === "function"
    ) {
      return (this.client as ProofLayerClient).downloadPackExport(packId);
    }
    throw new Error("underlying client does not support downloadPackExport; use vault mode");
  }

  async getVaultConfig(): Promise<VaultConfigResponse> {
    if ("getConfig" in this.client && typeof this.client.getConfig === "function") {
      return (this.client as ProofLayerClient).getConfig();
    }
    throw new Error("underlying client does not support getVaultConfig; use vault mode");
  }

  async getDisclosureConfig(): Promise<DisclosureConfig> {
    if (
      "getDisclosureConfig" in this.client &&
      typeof this.client.getDisclosureConfig === "function"
    ) {
      return (this.client as ProofLayerClient).getDisclosureConfig();
    }
    throw new Error("underlying client does not support getDisclosureConfig; use vault mode");
  }

  async getDisclosureTemplates(): Promise<DisclosureTemplateCatalog> {
    if (
      "getDisclosureTemplates" in this.client &&
      typeof this.client.getDisclosureTemplates === "function"
    ) {
      return (this.client as ProofLayerClient).getDisclosureTemplates();
    }
    throw new Error("underlying client does not support getDisclosureTemplates; use vault mode");
  }

  async renderDisclosureTemplate(
    request: DisclosureTemplateRenderRequest
  ): Promise<DisclosureTemplateInfo> {
    if (
      "renderDisclosureTemplate" in this.client &&
      typeof this.client.renderDisclosureTemplate === "function"
    ) {
      return (this.client as ProofLayerClient).renderDisclosureTemplate(request);
    }
    throw new Error(
      "underlying client does not support renderDisclosureTemplate; use vault mode"
    );
  }

  async updateDisclosureConfig(config: DisclosureConfig): Promise<DisclosureConfig> {
    if (
      "updateDisclosureConfig" in this.client &&
      typeof this.client.updateDisclosureConfig === "function"
    ) {
      return (this.client as ProofLayerClient).updateDisclosureConfig(config);
    }
    throw new Error("underlying client does not support updateDisclosureConfig; use vault mode");
  }

  async previewDisclosure(request: DisclosurePreviewRequest): Promise<DisclosurePreviewResponse> {
    if ("previewDisclosure" in this.client && typeof this.client.previewDisclosure === "function") {
      return (this.client as ProofLayerClient).previewDisclosure(request);
    }
    throw new Error("underlying client does not support previewDisclosure; use vault mode");
  }

  async capture(options: ProofLayerCaptureOptions): Promise<ProofLayerResult> {
    if ((options.evidenceType ?? "llm_interaction") !== "llm_interaction") {
      throw new Error("only llm_interaction capture is implemented in the TypeScript SDK");
    }

    const request = createLlmInteractionRequest({
      keyId: this.keyId,
      role: this.role,
      issuer: this.issuer,
      appId: this.appId,
      env: this.env,
      systemId: options.systemId ?? this.systemId,
      provider: options.provider,
      model: options.model,
      input: options.input,
      output: options.output,
      requestId: options.requestId,
      threadId: options.threadId,
      userRef: options.userRef,
      modelParameters: options.modelParameters,
      retrievalCommitment: options.retrievalCommitment,
      toolOutputsCommitment: options.toolOutputsCommitment,
      trace: options.trace,
      traceCommitment: options.traceCommitment,
      otelSemconvVersion: options.otelSemconvVersion,
      redactions: options.redactions,
      encryptionEnabled: options.encryptionEnabled,
      retentionClass: options.retentionClass,
      artefacts: options.artefacts
    });

    return this.#submitCapture(request, {
      bundleId: options.bundleId,
      createdAt: options.createdAt
    });
  }

  async captureRiskAssessment(
    options: Omit<RiskAssessmentRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createRiskAssessmentRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureDataGovernance(
    options: Omit<DataGovernanceRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createDataGovernanceRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureTechnicalDoc(
    options: Omit<TechnicalDocRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createTechnicalDocRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureToolCall(
    options: Omit<ToolCallRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createToolCallRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureRetrieval(
    options: Omit<RetrievalRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createRetrievalRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureHumanOversight(
    options: Omit<HumanOversightRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createHumanOversightRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async capturePolicyDecision(
    options: Omit<PolicyDecisionRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createPolicyDecisionRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureLiteracyAttestation(
    options: Omit<
      LiteracyAttestationRequestOptions,
      "keyId" | "role" | "issuer" | "appId" | "env"
    >
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createLiteracyAttestationRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureIncidentReport(
    options: Omit<IncidentReportRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createIncidentReportRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureModelEvaluation(
    options: Omit<ModelEvaluationRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createModelEvaluationRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureAdversarialTest(
    options: Omit<AdversarialTestRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createAdversarialTestRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureTrainingProvenance(
    options: Omit<
      TrainingProvenanceRequestOptions,
      "keyId" | "role" | "issuer" | "appId" | "env"
    >
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createTrainingProvenanceRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureConformityAssessment(
    options: Omit<
      ConformityAssessmentRequestOptions,
      "keyId" | "role" | "issuer" | "appId" | "env"
    >
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createConformityAssessmentRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureDeclaration(
    options: Omit<DeclarationRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createDeclarationRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }

  async captureRegistration(
    options: Omit<RegistrationRequestOptions, "keyId" | "role" | "issuer" | "appId" | "env">
  ): Promise<ProofLayerResult> {
    return this.#submitCapture(
      createRegistrationRequest({
        keyId: this.keyId,
        role: this.role,
        issuer: this.issuer,
        appId: this.appId,
        env: this.env,
        systemId: options.systemId ?? this.systemId,
        ...options
      }),
      options
    );
  }
}
