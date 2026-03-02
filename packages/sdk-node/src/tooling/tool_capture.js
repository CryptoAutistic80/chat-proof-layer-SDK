import { createHash, randomUUID } from "node:crypto";

function sha256Prefixed(value) {
  const bytes = Buffer.from(JSON.stringify(value), "utf8");
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function captureToolCall(name, input, output) {
  return {
    event_id: randomUUID(),
    timestamp: new Date().toISOString(),
    name,
    input,
    output,
    input_commitment: sha256Prefixed(input),
    output_commitment: sha256Prefixed(output)
  };
}
