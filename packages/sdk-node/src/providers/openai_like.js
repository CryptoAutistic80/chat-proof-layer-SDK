import { createHash, randomUUID } from "node:crypto";

function sha256Prefixed(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function resolveOpenAICall(client) {
  if (typeof client === "function") {
    return client;
  }
  const fn = client?.chat?.completions?.create;
  if (typeof fn !== "function") {
    throw new Error("OpenAI-like client missing chat.completions.create");
  }
  return fn.bind(client.chat.completions);
}

export async function provedCompletion(
  client,
  params,
  proofClient,
  captureOptions = {}
) {
  const call = resolveOpenAICall(client);
  const completion = await call(params);

  const promptBytes = encodeJson(params);
  const responseBytes = encodeJson(completion);
  const traceBytes = encodeJson({
    usage: completion?.usage,
    system_fingerprint: completion?.system_fingerprint,
    provider: "openai"
  });

  const requestId = captureOptions.requestId ?? randomUUID();
  const threadId = captureOptions.threadId ?? null;
  const userRef = captureOptions.userRef ?? null;

  const capture = {
    actor: {
      issuer: captureOptions.issuer ?? "proof-layer-node",
      app_id: captureOptions.appId ?? "node-demo",
      env: captureOptions.env ?? "dev",
      signing_key_id: captureOptions.signingKeyId ?? "kid-dev-01"
    },
    subject: {
      request_id: requestId,
      thread_id: threadId,
      user_ref: userRef
    },
    model: {
      provider: "openai",
      model: completion?.model ?? params?.model ?? "unknown",
      parameters: captureOptions.modelParameters ?? {
        temperature: params?.temperature,
        max_tokens: params?.max_tokens
      }
    },
    inputs: {
      messages_commitment: sha256Prefixed(promptBytes),
      retrieval_commitment: captureOptions.retrievalCommitment ?? null
    },
    outputs: {
      assistant_text_commitment: sha256Prefixed(responseBytes),
      tool_outputs_commitment: captureOptions.toolOutputsCommitment ?? null
    },
    trace: {
      otel_genai_semconv_version: captureOptions.otelSemconvVersion ?? "1.0.0",
      trace_commitment: sha256Prefixed(traceBytes)
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
    completion,
    bundleId: create.bundle_id,
    bundleRoot: create.bundle_root,
    signature: create.signature,
    createdAt: create.created_at
  };
}
