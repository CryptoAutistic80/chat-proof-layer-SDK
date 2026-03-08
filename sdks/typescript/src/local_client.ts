import { randomUUID } from "node:crypto";
import { buildBundle, redactBundle, verifyBundle, verifyRedactedBundle } from "./native.js";
import type {
  CreateBundleResponse,
  LocalBuildOptions,
  LocalClientOptions,
  LocalCreateBundleRequest,
  RedactBundleRequest,
  RedactedBundle,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyRedactedBundleRequest,
  VerifyRedactedBundleSummary
} from "./types.js";

function defaultBundleId(): string {
  return `pl-local-${randomUUID()}`;
}

function defaultCreatedAt(): string {
  return new Date().toISOString();
}

export class LocalProofLayerClient {
  readonly signingKeyPem: string;
  readonly signingKeyId: string;
  readonly bundleIdFactory: () => string;
  readonly createdAtFactory: () => string;

  constructor({
    signingKeyPem,
    signingKeyId = "kid-dev-01",
    bundleIdFactory = defaultBundleId,
    createdAtFactory = defaultCreatedAt
  }: LocalClientOptions) {
    if (!signingKeyPem) {
      throw new Error("signingKeyPem is required");
    }
    this.signingKeyPem = signingKeyPem;
    this.signingKeyId = signingKeyId;
    this.bundleIdFactory = bundleIdFactory;
    this.createdAtFactory = createdAtFactory;
  }

  async createBundle({
    capture,
    artefacts,
    bundleId,
    createdAt,
    signingKeyPem,
    signingKeyId
  }: LocalCreateBundleRequest): Promise<CreateBundleResponse> {
    const bundle = buildBundle({
      capture,
      artefacts,
      keyPem: signingKeyPem ?? this.signingKeyPem,
      kid: signingKeyId ?? this.signingKeyId,
      bundleId: bundleId ?? this.bundleIdFactory(),
      createdAt: createdAt ?? this.createdAtFactory()
    } satisfies LocalBuildOptions);

    return {
      bundle_id: bundle.bundle_id,
      bundle_root: bundle.integrity.bundle_root,
      signature: bundle.integrity.signature.value,
      created_at: bundle.created_at,
      bundle
    };
  }

  async verifyBundle({
    bundle,
    artefacts,
    publicKeyPem
  }: VerifyBundleRequest): Promise<VerifyBundleSummary> {
    return verifyBundle({ bundle, artefacts, publicKeyPem });
  }

  async discloseBundle(request: RedactBundleRequest): Promise<RedactedBundle> {
    return redactBundle(request);
  }

  async verifyRedactedBundle({
    bundle,
    artefacts,
    publicKeyPem
  }: VerifyRedactedBundleRequest): Promise<VerifyRedactedBundleSummary> {
    return verifyRedactedBundle({ bundle, artefacts, publicKeyPem });
  }
}
