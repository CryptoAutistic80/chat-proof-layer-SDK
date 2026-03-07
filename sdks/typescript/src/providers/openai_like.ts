import { randomUUID } from "node:crypto";
import { createLlmInteractionRequest } from "../evidence.js";
import type {
  BundleCreateClient,
  CreateBundleResponse,
  JsonObject,
  ProofBundle,
  ProviderCaptureOptions
} from "../types.js";

function resolveOpenAICall(
  client: { chat?: { completions?: { create?: (params: JsonObject) => Promise<JsonObject> } } } | ((params: JsonObject) => Promise<JsonObject>)
): (params: JsonObject) => Promise<JsonObject> {
  if (typeof client === "function") {
    return client;
  }
  const completions = client.chat?.completions;
  const fn = completions?.create;
  if (typeof fn !== "function") {
    throw new Error("OpenAI-like client missing chat.completions.create");
  }
  return fn.bind(completions);
}

export async function provedCompletion(
  client:
    | { chat?: { completions?: { create?: (params: JsonObject) => Promise<JsonObject> } } }
    | ((params: JsonObject) => Promise<JsonObject>),
  params: JsonObject,
  proofClient: BundleCreateClient,
  captureOptions: ProviderCaptureOptions = {}
): Promise<{
  completion: JsonObject;
  bundleId: string;
  bundleRoot: string;
  signature: string;
  createdAt?: string;
  bundle?: ProofBundle;
}> {
  const call = resolveOpenAICall(client);
  const completion = await call(params);

  const create = await proofClient.createBundle(
    createLlmInteractionRequest({
      keyId: captureOptions.signingKeyId ?? "kid-dev-01",
      role: captureOptions.role ?? "provider",
      issuer: captureOptions.issuer ?? "proof-layer-ts",
      appId: captureOptions.appId ?? "typescript-sdk",
      env: captureOptions.env ?? "dev",
      systemId: captureOptions.systemId,
      provider: "openai",
      model:
        typeof completion.model === "string"
          ? completion.model
          : typeof params.model === "string"
            ? params.model
            : "unknown",
      input: params,
      output: completion,
      requestId: captureOptions.requestId ?? randomUUID(),
      threadId: captureOptions.threadId ?? null,
      userRef: captureOptions.userRef ?? null,
      modelParameters: captureOptions.modelParameters ?? {
        temperature: typeof params.temperature === "number" ? params.temperature : null,
        max_tokens: typeof params.max_tokens === "number" ? params.max_tokens : null
      },
      retrievalCommitment: captureOptions.retrievalCommitment ?? null,
      toolOutputsCommitment: captureOptions.toolOutputsCommitment ?? null,
      trace:
        captureOptions.trace ??
        ({
          usage: completion.usage,
          system_fingerprint: completion.system_fingerprint,
          provider: "openai"
        } satisfies JsonObject),
      otelSemconvVersion: captureOptions.otelSemconvVersion,
      redactions: captureOptions.redactions,
      encryptionEnabled: captureOptions.encryptionEnabled,
      retentionClass: captureOptions.retentionClass,
      artefacts: captureOptions.artefacts
    })
  ) as CreateBundleResponse;

  return {
    completion,
    bundleId: create.bundle_id,
    bundleRoot: create.bundle_root,
    signature: create.signature,
    createdAt: create.created_at,
    bundle: create.bundle
  };
}
