import { provedMessage } from "./anthropic_like.js";
import type {
  JsonObject,
  ProofLayerAttachment,
  ProviderCaptureOptions
} from "../types.js";
import type { ProofLayer } from "../proof_layer.js";

export function withProofLayer(
  client: {
    messages?: { create?: (params: JsonObject) => Promise<JsonObject> };
  },
  proofLayer: ProofLayer,
  captureOptions: ProviderCaptureOptions = {}
): {
  messages: {
    create: (params: JsonObject) => Promise<JsonObject & { proofLayer: ProofLayerAttachment }>;
  };
} {
  return {
    messages: {
      create: async (params: JsonObject) => {
        const result = await provedMessage(client, params, proofLayer, captureOptions);
        return {
          ...result.message,
          proofLayer: {
            bundleId: result.bundleId,
            bundleRoot: result.bundleRoot,
            signature: result.signature,
            createdAt: result.createdAt,
            bundle: result.bundle
          }
        };
      }
    }
  };
}
