from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from proofsdk.native import hash_sha256


def capture_tool_call(name: str, input: Any, output: Any) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": name,
        "input": input,
        "output": output,
        "input_commitment": hash_sha256(json.dumps(input, sort_keys=True).encode("utf-8")),
        "output_commitment": hash_sha256(json.dumps(output, sort_keys=True).encode("utf-8")),
    }
