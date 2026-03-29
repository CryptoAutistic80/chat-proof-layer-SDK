import json
import os
import sys
from pathlib import Path

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "packages", "sdk-python")
    ),
)

from proofsdk import LocalChatProofSession, verify_local_chat_bundle


REPO_ROOT = Path(__file__).resolve().parents[2]
SIGNING_KEY = (REPO_ROOT / "fixtures" / "golden" / "signing_key.txt").read_text(encoding="utf-8")
VERIFY_KEY = (REPO_ROOT / "fixtures" / "golden" / "verify_key.txt").read_text(encoding="utf-8")


def main() -> None:
    session = LocalChatProofSession(
        signing_key_pem=SIGNING_KEY,
        key_id="kid-dev-01",
        provider="openai",
        model="gpt-4.1-mini",
        session_id="example-chat-session-001",
        system_id="support-assistant",
    )
    session.log_turn(role="user", content="What's the status of ticket #491?")
    session.log_turn(role="assistant", content="Ticket #491 is in progress and assigned to Dana.")

    sealed = session.finalize_bundle(
        bundle_id="PLFIXEDCHATEXAMPLE000000000001",
        created_at="2026-03-29T00:00:00+00:00",
    )

    bundle_path = REPO_ROOT / "examples" / "bundles" / "chat-session.bundle.json"
    bundle_path.write_text(json.dumps(sealed["bundle"], indent=2), encoding="utf-8")

    verification = verify_local_chat_bundle(sealed["bundle"], sealed["transcript"], VERIFY_KEY)

    print("bundle_path:", bundle_path)
    print("bundle_id:", sealed["bundle_id"])
    print("bundle_root:", sealed["bundle_root"])
    print("verified:", verification["verified"])


if __name__ == "__main__":
    main()
