import os
import sys

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "packages", "sdk-python")
    ),
)

from proofsdk.export.otel_genai import events_to_otel_spans
from proofsdk.tooling.tool_capture import capture_tool_call


def main() -> None:
    events = [
        capture_tool_call(
            "retrieval.search",
            {"query": "proof layer canonicalization"},
            {"documents": ["doc-1", "doc-2"]},
        ),
        capture_tool_call(
            "calculator",
            {"expression": "2+2"},
            {"result": 4},
        ),
    ]

    spans = events_to_otel_spans(events)
    print("captured_events:", len(events))
    print("generated_spans:", len(spans))
    print("first_span_name:", spans[0]["name"])


if __name__ == "__main__":
    main()
