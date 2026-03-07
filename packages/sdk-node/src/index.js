export { ProofLayerClient } from "./client.js";
export { LocalProofLayerClient } from "./local_client.js";
export { provedCompletion } from "./providers/openai_like.js";
export { provedMessage } from "./providers/anthropic_like.js";
export { captureToolCall } from "./tooling/tool_capture.js";
export { eventsToOtelSpans } from "./export/otel_genai.js";
export {
  buildBundle,
  canonicalizeJson,
  computeMerkleRoot,
  hashSha256,
  signBundleRoot,
  verifyBundle,
  verifyBundleRoot
} from "./native.js";
