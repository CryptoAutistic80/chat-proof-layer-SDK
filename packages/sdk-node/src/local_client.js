import { randomUUID } from "node:crypto";
import { buildBundle, verifyBundle } from "./native.js";

function defaultBundleId() {
  return `pl-local-${randomUUID()}`;
}

function defaultCreatedAt() {
  return new Date().toISOString();
}

export class LocalProofLayerClient {
  constructor({
    signingKeyPem,
    signingKeyId = "kid-dev-01",
    bundleIdFactory = defaultBundleId,
    createdAtFactory = defaultCreatedAt
  } = {}) {
    if (!signingKeyPem) {
      throw new Error("signingKeyPem is required");
    }
    this.signingKeyPem = signingKeyPem;
    this.signingKeyId = signingKeyId;
    this.bundleIdFactory = bundleIdFactory;
    this.createdAtFactory = createdAtFactory;
  }

  async createBundle({ capture, artefacts, bundleId, createdAt, signingKeyPem, signingKeyId }) {
    const bundle = buildBundle({
      capture,
      artefacts,
      keyPem: signingKeyPem ?? this.signingKeyPem,
      kid: signingKeyId ?? this.signingKeyId,
      bundleId: bundleId ?? this.bundleIdFactory(),
      createdAt: createdAt ?? this.createdAtFactory()
    });

    return {
      bundle_id: bundle.bundle_id,
      bundle_root: bundle.integrity.bundle_root,
      signature: bundle.integrity.signature.value,
      created_at: bundle.created_at,
      bundle
    };
  }

  async verifyBundle({ bundle, artefacts, publicKeyPem }) {
    return verifyBundle({ bundle, artefacts, publicKeyPem });
  }
}
