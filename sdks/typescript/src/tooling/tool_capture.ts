import { randomUUID } from "node:crypto";
import { hashSha256 } from "../native.js";
import type { JsonObject, JsonValue, ToolEvent } from "../types.js";

export function captureToolCall(
  name: string,
  input: JsonValue | JsonObject,
  output: JsonValue | JsonObject
): ToolEvent {
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
