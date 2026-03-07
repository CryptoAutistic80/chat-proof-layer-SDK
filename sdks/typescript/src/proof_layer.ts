import { readFileSync } from "node:fs";
import {
  createDataGovernanceRequest,
  createLlmInteractionRequest,
  createRiskAssessmentRequest,
  createTechnicalDocRequest
} from "./evidence.js";
import { LocalProofLayerClient } from "./local_client.js";
import { ProofLayerClient } from "./client.js";
import type {
  BundleCreateClient,
  CreateBundleRequest,
  CreateBundleResponse,
  DataGovernanceRequestOptions,
  ProofLayerCaptureOptions,
  ProofLayerOptions,
  ProofLayerResult,
  RiskAssessmentRequestOptions,
  TechnicalDocRequestOptions,
  VerifyBundleRequest,
  VerifyBundleSummary
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
      return this.client.verifyBundle(request as never);
    }
    throw new Error("underlying client does not support verifyBundle");
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
}
