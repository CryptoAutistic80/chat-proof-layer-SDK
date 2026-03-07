import type {
  GenericProofLayerOptions,
  JsonObject,
  ProofLayerAttachment
} from "../types.js";
import type { ProofLayer } from "../proof_layer.js";

function resolveModel<TParams extends JsonObject, TResult extends JsonObject>(
  options: GenericProofLayerOptions<TParams, TResult>,
  params: TParams,
  result: TResult
): string {
  if (typeof options.model === "function") {
    return options.model(params, result);
  }
  if (typeof options.model === "string") {
    return options.model;
  }
  if (typeof result.model === "string") {
    return result.model;
  }
  if (typeof params.model === "string") {
    return params.model;
  }
  return "unknown";
}

export function withProofLayer<TParams extends JsonObject, TResult extends JsonObject>(
  call: (params: TParams) => Promise<TResult>,
  proofLayer: ProofLayer,
  options: GenericProofLayerOptions<TParams, TResult>
): (params: TParams) => Promise<TResult & { proofLayer: ProofLayerAttachment }> {
  return async (params: TParams) => {
    const result = await call(params);
    const proof = await proofLayer.capture({
      provider: options.provider,
      model: resolveModel(options, params, result),
      input: params,
      output: result,
      systemId: options.systemId,
      requestId: options.requestId,
      threadId: options.threadId,
      userRef: options.userRef,
      modelParameters: options.modelParameters,
      retrievalCommitment: options.retrievalCommitment,
      toolOutputsCommitment: options.toolOutputsCommitment,
      trace: options.buildTrace ? options.buildTrace(params, result) : options.trace,
      otelSemconvVersion: options.otelSemconvVersion,
      redactions: options.redactions,
      encryptionEnabled: options.encryptionEnabled,
      artefacts: options.artefacts
    });

    return {
      ...result,
      proofLayer: {
        bundleId: proof.bundleId,
        bundleRoot: proof.bundleRoot,
        signature: proof.signature,
        createdAt: proof.createdAt,
        bundle: proof.bundle
      }
    };
  };
}
