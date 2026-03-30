#!/usr/bin/env python3
"""Ensure smoke tests cover required public web-demo routes."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE_TEST = ROOT / "web-demo/tests/demo.smoke.spec.js"
REQUIRED_ROUTES = ["/chat-demo", "/verify", "/share"]


def main() -> int:
    text = SMOKE_TEST.read_text(encoding="utf-8")
    missing = [route for route in REQUIRED_ROUTES if route not in text]
    if missing:
        print("ERROR: web-demo smoke tests are missing required routes:")
        for route in missing:
            print(f" - {route}")
        return 1

    print("Web demo smoke route coverage check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
