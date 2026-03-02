import { Buffer } from "node:buffer";

function toBase64(data) {
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString("base64");
  }
  if (typeof data === "string") {
    return Buffer.from(data, "utf8").toString("base64");
  }
  return Buffer.from(JSON.stringify(data), "utf8").toString("base64");
}

function fromBase64(base64) {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

export class ProofLayerClient {
  constructor({ baseUrl, apiKey, fetchImpl } = {}) {
    if (!baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error("fetch is not available; pass fetchImpl");
    }
  }

  async createBundle({ capture, artefacts }) {
    const payload = {
      capture,
      artefacts: artefacts.map((a) => ({
        name: a.name,
        content_type: a.contentType ?? "application/octet-stream",
        data_base64: toBase64(a.data)
      }))
    };
    return this.#post("/v1/bundles", payload);
  }

  async verifyBundle({ bundle, artefacts, publicKeyPem }) {
    const payload = {
      bundle,
      artefacts: artefacts.map((a) => ({
        name: a.name,
        data_base64: toBase64(a.data)
      })),
      public_key_pem: publicKeyPem
    };
    return this.#post("/v1/verify", payload);
  }

  async verifyPackage({ bundlePackage, publicKeyPem }) {
    const payload = {
      bundle_pkg_base64: toBase64(bundlePackage),
      public_key_pem: publicKeyPem
    };
    return this.#post("/v1/verify", payload);
  }

  async getBundle(bundleId) {
    return this.#get(`/v1/bundles/${encodeURIComponent(bundleId)}`);
  }

  async getArtefact(bundleId, name) {
    const res = await this.fetchImpl(
      `${this.baseUrl}/v1/bundles/${encodeURIComponent(bundleId)}/artefacts/${encodeURIComponent(name)}`,
      { method: "GET", headers: this.#headers() }
    );
    if (!res.ok) {
      throw new Error(`getArtefact failed (${res.status})`);
    }
    const arrayBuffer = await res.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  }

  async #get(path) {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.#headers()
    });
    return this.#jsonOrThrow(res, `GET ${path}`);
  }

  async #post(path, payload) {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        ...this.#headers(),
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    return this.#jsonOrThrow(res, `POST ${path}`);
  }

  async #jsonOrThrow(response, op) {
    const text = await response.text();
    let parsed;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = { raw: text };
    }
    if (!response.ok) {
      const msg = parsed?.error ?? parsed?.message ?? JSON.stringify(parsed);
      throw new Error(`${op} failed (${response.status}): ${msg}`);
    }
    return parsed;
  }

  #headers() {
    if (!this.apiKey) {
      return {};
    }
    return { authorization: `Bearer ${this.apiKey}` };
  }
}

export const _internals = { toBase64, fromBase64 };
