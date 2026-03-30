#!/usr/bin/env python3
"""CI checks for chat-first primary docs and smoke-route coverage guards."""

from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

PRIMARY_DOCS = [
    ROOT / "README.md",
    ROOT / "get_started.md",
    ROOT / "sdks/typescript/README.md",
    ROOT / "packages/sdk-python/README.md",
]

CHAT_KEYWORDS = [
    "chat",
    "chatbot",
    "chat session",
    "chat-proof",
    "chat proof",
]

ADVANCED_ONLY_PATTERNS = [
    r"/advanced",
    r"advanced\s+playground",
    r"legacy\s+playground",
]


def fail(message: str) -> None:
    print(f"ERROR: {message}")


def has_chat_keyword(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in CHAT_KEYWORDS)


def has_advanced_reference(text: str) -> str | None:
    for pattern in ADVANCED_ONLY_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return pattern
    return None


def main() -> int:
    errors: list[str] = []

    for path in PRIMARY_DOCS:
        text = path.read_text(encoding="utf-8")
        if not has_chat_keyword(text):
            errors.append(f"{path.relative_to(ROOT)} missing chatbot-oriented keyword.")
        advanced_pattern = has_advanced_reference(text)
        if advanced_pattern:
            errors.append(
                f"{path.relative_to(ROOT)} references advanced-only flow pattern: {advanced_pattern}"
            )

    if errors:
        for error in errors:
            fail(error)
        return 1

    print("Primary docs checks passed: chat-first keywords present and advanced-only references absent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
