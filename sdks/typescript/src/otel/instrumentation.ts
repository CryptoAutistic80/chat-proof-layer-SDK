import { randomUUID } from "node:crypto";
import type { JsonObject, OtelSpan, ToolEvent } from "../types.js";

function hexId(length: number): string {
  return randomUUID().replace(/-/g, "").slice(0, length);
}

export function eventsToOtelSpans(
  events: ToolEvent[],
  options: { traceId?: string; system?: string } = {}
): OtelSpan[] {
  const traceId = options.traceId ?? hexId(32);
  const nowNs = BigInt(Date.now()) * 1000000n;

  return events.map((event, idx) => {
    const startNs = nowNs + BigInt(idx * 1000000);
    const endNs = startNs + 500000n;
    return {
      trace_id: traceId,
      span_id: hexId(16),
      name: `gen_ai.tool.${event.name ?? "event"}`,
      start_time_unix_nano: startNs.toString(),
      end_time_unix_nano: endNs.toString(),
      attributes: {
        "gen_ai.system": options.system ?? "proof-layer",
        "gen_ai.operation.name": "tool_call",
        "proof.event_id": event.event_id,
        "proof.input_commitment": event.input_commitment,
        "proof.output_commitment": event.output_commitment
      } as JsonObject
    };
  });
}
