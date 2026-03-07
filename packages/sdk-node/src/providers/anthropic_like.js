import { randomUUID } from "node:crypto";
import { hashSha256 } from "../native.js";

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function resolveAnthropicCall(client) {
  if (typeof client === "function") {
    return client;
  }
  const fn = client?.messages?.create;
  if (typeof fn !== "function") {
    throw new Error("Anthropic-like client missing messages.create");
  }
  return fn.bind(client.messages);
}

export async function provedMessage(
  client,
  params,
  proofClient,
  captureOptions = {}
) {
  const call = resolveAnthropicCall(client);
  const message = await call(params);

  const promptBytes = encodeJson(params);
  const responseBytes = encodeJson(message);
  const traceBytes = encodeJson({
    usage: message?.usage,
    stop_reason: message?.stop_reason,
    provider: "anthropic"
  });

  const requestId = captureOptions.requestId ?? randomUUID();
  const capture = {
    actor: {
      issuer: captureOptions.issuer ?? "proof-layer-node",
      app_id: captureOptions.appId ?? "node-demo",
      env: captureOptions.env ?? "dev",
      signing_key_id: captureOptions.signingKeyId ?? "kid-dev-01"
    },
    subject: {
      request_id: requestId,
      thread_id: captureOptions.threadId ?? null,
      user_ref: captureOptions.userRef ?? null
    },
    model: {
      provider: "anthropic",
      model: message?.model ?? params?.model ?? "unknown",
      parameters: captureOptions.modelParameters ?? {
        max_tokens: params?.max_tokens,
        temperature: params?.temperature
      }
    },
    inputs: {
      messages_commitment: hashSha256(promptBytes),
      retrieval_commitment: captureOptions.retrievalCommitment ?? null
    },
    outputs: {
      assistant_text_commitment: hashSha256(responseBytes),
      tool_outputs_commitment: captureOptions.toolOutputsCommitment ?? null
    },
    trace: {
      otel_genai_semconv_version: captureOptions.otelSemconvVersion ?? "1.0.0",
      trace_commitment: hashSha256(traceBytes)
    },
    policy: {
      redactions: captureOptions.redactions ?? [],
      encryption: { enabled: Boolean(captureOptions.encryptionEnabled) }
    }
  };

  const create = await proofClient.createBundle({
    capture,
    artefacts: [
      {
        name: "prompt.json",
        contentType: "application/json",
        data: promptBytes
      },
      {
        name: "response.json",
        contentType: "application/json",
        data: responseBytes
      }
    ]
  });

  return {
    message,
    bundleId: create.bundle_id,
    bundleRoot: create.bundle_root,
    signature: create.signature,
    createdAt: create.created_at,
    bundle: create.bundle
  };
}
