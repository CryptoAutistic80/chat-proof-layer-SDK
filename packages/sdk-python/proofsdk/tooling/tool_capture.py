from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _sha256_prefixed(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def capture_tool_call(name: str, input: Any, output: Any) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "name": name,
        "input": input,
        "output": output,
        "input_commitment": _sha256_prefixed(input),
        "output_commitment": _sha256_prefixed(output),
    }
