import { Buffer } from "node:buffer";
import type {
  BinaryLike,
  CreatePackRequest,
  CreateBundleRequest,
  CreateBundleResponse,
  FetchLike,
  HttpClientOptions,
  InlineArtefactRequest,
  JsonObject,
  PackManifest,
  PackSummaryResponse,
  VerifyBundleRequest,
  VerifyBundleSummary,
  VerifyPackageRequest
} from "./types.js";
import { ProofLayerHttpError } from "./utils/errors.js";

function toBase64(data: BinaryLike): string {
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString("base64");
  }
  if (typeof data === "string") {
    return Buffer.from(data, "utf8").toString("base64");
  }
  return Buffer.from(JSON.stringify(data), "utf8").toString("base64");
}

function fromBase64(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, "base64"));
}

export class ProofLayerClient {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly fetchImpl: FetchLike;

  constructor({ baseUrl, apiKey, fetchImpl }: HttpClientOptions) {
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

  async createBundle({ capture, artefacts }: CreateBundleRequest): Promise<CreateBundleResponse> {
    const payload = {
      capture,
      artefacts: artefacts.map<InlineArtefactRequest>((artefact) => ({
        name: artefact.name,
        content_type: artefact.contentType ?? "application/octet-stream",
        data_base64: toBase64(artefact.data)
      }))
    };
    return this.#post("/v1/bundles", payload);
  }

  async verifyBundle({
    bundle,
    artefacts,
    publicKeyPem
  }: VerifyBundleRequest): Promise<VerifyBundleSummary> {
    const payload = {
      bundle,
      artefacts: artefacts.map(({ name, data }) => ({
        name,
        data_base64: toBase64(data)
      })),
      public_key_pem: publicKeyPem
    };
    return this.#post("/v1/verify", payload);
  }

  async verifyPackage({
    bundlePackage,
    publicKeyPem
  }: VerifyPackageRequest): Promise<VerifyBundleSummary> {
    const payload = {
      bundle_pkg_base64: toBase64(bundlePackage),
      public_key_pem: publicKeyPem
    };
    return this.#post("/v1/verify", payload);
  }

  async createPack({
    packType,
    systemId,
    from,
    to,
    bundleFormat,
    disclosurePolicy
  }: CreatePackRequest): Promise<PackSummaryResponse> {
    const payload = {
      pack_type: packType,
      system_id: systemId,
      from,
      to,
      ...(bundleFormat ? { bundle_format: bundleFormat } : {}),
      ...(disclosurePolicy ? { disclosure_policy: disclosurePolicy } : {})
    };
    return this.#post("/v1/packs", payload);
  }

  async getPack(packId: string): Promise<PackSummaryResponse> {
    return this.#get(`/v1/packs/${encodeURIComponent(packId)}`) as Promise<PackSummaryResponse>;
  }

  async getPackManifest(packId: string): Promise<PackManifest> {
    return this.#get(`/v1/packs/${encodeURIComponent(packId)}/manifest`) as Promise<PackManifest>;
  }

  async downloadPackExport(packId: string): Promise<Uint8Array> {
    const res = await this.fetchImpl(`${this.baseUrl}/v1/packs/${encodeURIComponent(packId)}/export`, {
      method: "GET",
      headers: this.#headers()
    });
    if (!res.ok) {
      const text = await res.text();
      let parsed: unknown;
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = { raw: text };
      }
      throw new ProofLayerHttpError(`GET /v1/packs/${packId}/export`, res.status, parsed);
    }
    const arrayBuffer = await res.arrayBuffer();
    return new Uint8Array(arrayBuffer);
  }

  async getBundle(bundleId: string): Promise<JsonObject> {
    return this.#get(`/v1/bundles/${encodeURIComponent(bundleId)}`);
  }

  async getArtefact(bundleId: string, name: string): Promise<Uint8Array> {
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

  async #get(path: string): Promise<JsonObject> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.#headers()
    });
    return this.#jsonOrThrow(res, `GET ${path}`);
  }

  async #post(path: string, payload: JsonObject): Promise<any> {
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

  async #jsonOrThrow(response: Response, op: string): Promise<any> {
    const text = await response.text();
    let parsed: any;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = { raw: text };
    }
    if (!response.ok) {
      throw new ProofLayerHttpError(op, response.status, parsed);
    }
    return parsed;
  }

  #headers(): Record<string, string> {
    if (!this.apiKey) {
      return {};
    }
    return { authorization: `Bearer ${this.apiKey}` };
  }
}

export const _internals = { toBase64, fromBase64 };
