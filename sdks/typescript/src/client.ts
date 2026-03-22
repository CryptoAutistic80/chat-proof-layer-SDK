import { Buffer } from "node:buffer";
import type {
  BinaryLike,
  CompletenessReport,
  CreatePackRequest,
  CreateBundleRequest,
  CreateBundleResponse,
  DisclosureConfig,
  DisclosurePreviewRequest,
  DisclosurePreviewResponse,
  DisclosureTemplateCatalog,
  DisclosureTemplateInfo,
  DisclosureTemplateRenderRequest,
  EvaluateCompletenessRequest,
  FetchLike,
  HttpClientOptions,
  InlineArtefactRequest,
  JsonObject,
  PackManifest,
  PackSummaryResponse,
  VerifyReceiptRequest,
  VerifyReceiptResponse,
  VerifyTimestampRequest,
  VerifyTimestampResponse,
  VaultConfigResponse,
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

  async verifyTimestamp({
    bundleId,
    bundleRoot,
    timestamp
  }: VerifyTimestampRequest): Promise<VerifyTimestampResponse> {
    const selectionCount =
      Number(Boolean(bundleId)) + Number(Boolean(bundleRoot || timestamp));
    if (selectionCount !== 1) {
      throw new Error("provide exactly one of bundleId or bundleRoot/timestamp");
    }
    if ((bundleRoot && !timestamp) || (!bundleRoot && timestamp)) {
      throw new Error("bundleRoot and timestamp must be provided together");
    }
    const payload = bundleId
      ? { bundle_id: bundleId }
      : { bundle_root: bundleRoot, timestamp };
    return this.#post("/v1/verify/timestamp", payload);
  }

  async verifyReceipt({
    bundleId,
    bundleRoot,
    receipt,
    liveCheckMode
  }: VerifyReceiptRequest): Promise<VerifyReceiptResponse> {
    const selectionCount =
      Number(Boolean(bundleId)) + Number(Boolean(bundleRoot || receipt));
    if (selectionCount !== 1) {
      throw new Error("provide exactly one of bundleId or bundleRoot/receipt");
    }
    if ((bundleRoot && !receipt) || (!bundleRoot && receipt)) {
      throw new Error("bundleRoot and receipt must be provided together");
    }
    const payload = bundleId
      ? {
          bundle_id: bundleId,
          ...(liveCheckMode ? { live_check_mode: liveCheckMode } : {})
        }
      : {
          bundle_root: bundleRoot,
          receipt,
          ...(liveCheckMode ? { live_check_mode: liveCheckMode } : {})
        };
    return this.#post("/v1/verify/receipt", payload);
  }

  async evaluateCompleteness({
    bundle,
    bundleId,
    packId,
    profile
  }: EvaluateCompletenessRequest): Promise<CompletenessReport> {
    const selectionCount =
      Number(Boolean(bundle)) + Number(Boolean(bundleId)) + Number(Boolean(packId));
    if (selectionCount !== 1) {
      throw new Error("provide exactly one of bundle_id, bundle, or pack_id");
    }
    const payload = {
      profile,
      ...(bundle ? { bundle } : {}),
      ...(bundleId ? { bundle_id: bundleId } : {}),
      ...(packId ? { pack_id: packId } : {})
    };
    return this.#post("/v1/completeness/evaluate", payload);
  }

  async createPack({
    packType,
    bundleIds,
    systemId,
    from,
    to,
    bundleFormat,
    disclosurePolicy,
    disclosureTemplate
  }: CreatePackRequest): Promise<PackSummaryResponse> {
    if (bundleIds && bundleIds.length > 0 && (systemId || from || to)) {
      throw new Error("bundleIds cannot be combined with systemId, from, or to");
    }
    if (disclosurePolicy && disclosureTemplate) {
      throw new Error("provide either disclosurePolicy or disclosureTemplate, not both");
    }
    const payload = {
      pack_type: packType,
      ...(bundleIds && bundleIds.length > 0 ? { bundle_ids: bundleIds } : {}),
      ...(systemId ? { system_id: systemId } : {}),
      ...(from ? { from } : {}),
      ...(to ? { to } : {}),
      ...(bundleFormat ? { bundle_format: bundleFormat } : {}),
      ...(disclosurePolicy ? { disclosure_policy: disclosurePolicy } : {}),
      ...(disclosureTemplate
        ? {
            disclosure_template: {
              profile: disclosureTemplate.profile,
              ...(disclosureTemplate.name ? { name: disclosureTemplate.name } : {}),
              ...(disclosureTemplate.redactionGroups &&
              disclosureTemplate.redactionGroups.length > 0
                ? { redaction_groups: disclosureTemplate.redactionGroups }
                : {}),
              ...(disclosureTemplate.redactedFieldsByItemType &&
              Object.keys(disclosureTemplate.redactedFieldsByItemType).length > 0
                ? {
                    redacted_fields_by_item_type:
                      disclosureTemplate.redactedFieldsByItemType
                  }
                : {})
            }
          }
        : {})
    };
    return this.#post("/v1/packs", payload);
  }

  async getPack(packId: string): Promise<PackSummaryResponse> {
    return this.#get(`/v1/packs/${encodeURIComponent(packId)}`) as Promise<PackSummaryResponse>;
  }

  async getPackManifest(packId: string): Promise<PackManifest> {
    return this.#get(`/v1/packs/${encodeURIComponent(packId)}/manifest`) as Promise<PackManifest>;
  }

  async getConfig(): Promise<VaultConfigResponse> {
    return this.#get("/v1/config") as Promise<VaultConfigResponse>;
  }

  async getDisclosureConfig(): Promise<DisclosureConfig> {
    const config = await this.getConfig();
    return config.disclosure;
  }

  async getDisclosureTemplates(): Promise<DisclosureTemplateCatalog> {
    return this.#get("/v1/disclosure/templates") as Promise<DisclosureTemplateCatalog>;
  }

  async renderDisclosureTemplate({
    profile,
    name,
    redactionGroups,
    redactedFieldsByItemType
  }: DisclosureTemplateRenderRequest): Promise<DisclosureTemplateInfo> {
    const payload = {
      profile,
      ...(name ? { name } : {}),
      ...(redactionGroups && redactionGroups.length > 0
        ? { redaction_groups: redactionGroups }
        : {}),
      ...(redactedFieldsByItemType &&
      Object.keys(redactedFieldsByItemType).length > 0
        ? { redacted_fields_by_item_type: redactedFieldsByItemType }
        : {})
    };
    return this.#post("/v1/disclosure/templates/render", payload);
  }

  async updateDisclosureConfig(config: DisclosureConfig): Promise<DisclosureConfig> {
    return this.#put("/v1/config/disclosure", config);
  }

  async previewDisclosure({
    bundleId,
    packType,
    disclosurePolicy,
    policy,
    disclosureTemplate
  }: DisclosurePreviewRequest): Promise<DisclosurePreviewResponse> {
    const selectionCount = Number(Boolean(disclosurePolicy)) +
      Number(Boolean(policy)) +
      Number(Boolean(disclosureTemplate));
    if (selectionCount > 1) {
      throw new Error(
        "provide only one of disclosurePolicy, policy, or disclosureTemplate"
      );
    }
    const payload = {
      bundle_id: bundleId,
      ...(packType ? { pack_type: packType } : {}),
      ...(disclosurePolicy ? { disclosure_policy: disclosurePolicy } : {}),
      ...(policy ? { policy } : {}),
      ...(disclosureTemplate
        ? {
            disclosure_template: {
              profile: disclosureTemplate.profile,
              ...(disclosureTemplate.name ? { name: disclosureTemplate.name } : {}),
              ...(disclosureTemplate.redactionGroups &&
              disclosureTemplate.redactionGroups.length > 0
                ? { redaction_groups: disclosureTemplate.redactionGroups }
                : {}),
              ...(disclosureTemplate.redactedFieldsByItemType &&
              Object.keys(disclosureTemplate.redactedFieldsByItemType).length > 0
                ? {
                    redacted_fields_by_item_type:
                      disclosureTemplate.redactedFieldsByItemType
                  }
                : {})
            }
          }
        : {})
    };
    return this.#post("/v1/disclosure/preview", payload);
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
    return this.#sendJson("POST", path, payload);
  }

  async #put(path: string, payload: JsonObject): Promise<any> {
    return this.#sendJson("PUT", path, payload);
  }

  async #sendJson(method: "POST" | "PUT", path: string, payload: JsonObject): Promise<any> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: {
        ...this.#headers(),
        "content-type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    return this.#jsonOrThrow(res, `${method} ${path}`);
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
