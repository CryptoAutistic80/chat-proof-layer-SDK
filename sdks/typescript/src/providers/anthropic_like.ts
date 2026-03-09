import { randomUUID } from "node:crypto";
import { createLlmInteractionRequest } from "../evidence.js";
import type {
  BundleCreateClient,
  CreateBundleResponse,
  JsonObject,
  ProofBundle,
  ProviderCaptureOptions
} from "../types.js";

function resolveAnthropicCall(
  client: { messages?: { create?: (params: JsonObject) => Promise<JsonObject> } } | ((params: JsonObject) => Promise<JsonObject>)
): (params: JsonObject) => Promise<JsonObject> {
  if (typeof client === "function") {
    return client;
  }
  const messages = client.messages;
  const fn = messages?.create;
  if (typeof fn !== "function") {
    throw new Error("Anthropic-like client missing messages.create");
  }
  return fn.bind(messages);
}

export async function provedMessage(
  client:
    | { messages?: { create?: (params: JsonObject) => Promise<JsonObject> } }
    | ((params: JsonObject) => Promise<JsonObject>),
  params: JsonObject,
  proofClient: BundleCreateClient,
  captureOptions: ProviderCaptureOptions = {}
): Promise<{
  message: JsonObject;
  bundleId: string;
  bundleRoot: string;
  signature: string;
  createdAt?: string;
  bundle?: ProofBundle;
}> {
  const call = resolveAnthropicCall(client);
  const message = await call(params);

  const create = await proofClient.createBundle(
    createLlmInteractionRequest({
      keyId: captureOptions.signingKeyId ?? "kid-dev-01",
      role: captureOptions.role ?? "provider",
      issuer: captureOptions.issuer ?? "proof-layer-ts",
      appId: captureOptions.appId ?? "typescript-sdk",
      env: captureOptions.env ?? "dev",
      systemId: captureOptions.systemId,
      provider: "anthropic",
      model:
        typeof message.model === "string"
          ? message.model
          : typeof params.model === "string"
            ? params.model
            : "unknown",
      input: params,
      output: message,
      requestId: captureOptions.requestId ?? randomUUID(),
      threadId: captureOptions.threadId ?? null,
      userRef: captureOptions.userRef ?? null,
      modelParameters: captureOptions.modelParameters ?? {
        max_tokens: typeof params.max_tokens === "number" ? params.max_tokens : null,
        temperature: typeof params.temperature === "number" ? params.temperature : null
      },
      retrievalCommitment: captureOptions.retrievalCommitment ?? null,
      toolOutputsCommitment: captureOptions.toolOutputsCommitment ?? null,
      trace:
        captureOptions.trace ??
        ({
          usage: message.usage,
          stop_reason: message.stop_reason,
          provider: "anthropic"
        } satisfies JsonObject),
      otelSemconvVersion: captureOptions.otelSemconvVersion,
      redactions: captureOptions.redactions,
      encryptionEnabled: captureOptions.encryptionEnabled,
      retentionClass: captureOptions.retentionClass,
      artefacts: captureOptions.artefacts
    })
  ) as CreateBundleResponse;

  return {
    message,
    bundleId: create.bundle_id,
    bundleRoot: create.bundle_root,
    signature: create.signature,
    createdAt: create.created_at,
    bundle: create.bundle
  };
}
