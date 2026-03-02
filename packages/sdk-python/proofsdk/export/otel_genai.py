from __future__ import annotations

import time
import uuid
from typing import Any


def events_to_otel_spans(events: list[dict[str, Any]], system: str = "proof-layer") -> list[dict[str, Any]]:
    trace_id = uuid.uuid4().hex
    now_ns = int(time.time() * 1_000_000_000)
    spans: list[dict[str, Any]] = []
    for idx, event in enumerate(events):
        start = now_ns + idx * 1_000_000
        spans.append(
            {
                "trace_id": trace_id,
                "span_id": uuid.uuid4().hex[:16],
                "name": f"gen_ai.tool.{event.get('name', 'event')}",
                "start_time_unix_nano": str(start),
                "end_time_unix_nano": str(start + 500_000),
                "attributes": {
                    "gen_ai.system": system,
                    "gen_ai.operation.name": "tool_call",
                    "proof.event_id": event.get("event_id"),
                    "proof.input_commitment": event.get("input_commitment"),
                    "proof.output_commitment": event.get("output_commitment"),
                },
            }
        )
    return spans
