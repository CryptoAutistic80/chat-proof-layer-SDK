import { randomUUID } from "node:crypto";
import { hashSha256 } from "../native.js";

export function captureToolCall(name, input, output) {
  return {
    event_id: randomUUID(),
    timestamp: new Date().toISOString(),
    name,
    input,
    output,
    input_commitment: hashSha256(JSON.stringify(input)),
    output_commitment: hashSha256(JSON.stringify(output))
  };
}
