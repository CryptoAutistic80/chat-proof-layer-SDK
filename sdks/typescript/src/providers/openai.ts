import { provedCompletion } from "./openai_like.js";
import type {
  JsonObject,
  ProofLayerAttachment,
  ProviderCaptureOptions
} from "../types.js";
import type { ProofLayer } from "../proof_layer.js";

export function withProofLayer(
  client: {
    chat?: { completions?: { create?: (params: JsonObject) => Promise<JsonObject> } };
  },
  proofLayer: ProofLayer,
  captureOptions: ProviderCaptureOptions = {}
): {
  chat: {
    completions: {
      create: (params: JsonObject) => Promise<JsonObject & { proofLayer: ProofLayerAttachment }>;
    };
  };
} {
  return {
    chat: {
      completions: {
        create: async (params: JsonObject) => {
          const result = await provedCompletion(client, params, proofLayer, captureOptions);
          return {
            ...result.completion,
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
    }
  };
}
