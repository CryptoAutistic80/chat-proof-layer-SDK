import type {
  GenericProofLayerOptions,
  JsonObject,
  ProofLayerAttachment
} from "../types.js";
import type { ProofLayer } from "../proof_layer.js";
import { withProofLayer as withGenericProofLayer } from "./generic.js";

export function withProofLayer<TParams extends JsonObject, TResult extends JsonObject>(
  call: (params: TParams) => Promise<TResult>,
  proofLayer: ProofLayer,
  options: Omit<GenericProofLayerOptions<TParams, TResult>, "provider"> = {}
): (params: TParams) => Promise<TResult & { proofLayer: ProofLayerAttachment }> {
  return withGenericProofLayer(call, proofLayer, {
    provider: "vercel-ai",
    ...options,
    buildTrace:
      options.buildTrace ??
      ((params, result) => ({
        provider: "vercel-ai",
        usage: result.usage,
        finish_reason: result.finishReason,
        requested_model: params.model,
        resolved_model: result.model
      }))
  });
}
