import copy
import unittest
from pathlib import Path

from proofsdk.chat_proof import LocalChatProofSession, verify_local_chat_bundle

REPO_ROOT = Path(__file__).resolve().parents[3]
SIGNING_KEY = (REPO_ROOT / "fixtures" / "golden" / "signing_key.txt").read_text(encoding="utf-8")
VERIFY_KEY = (REPO_ROOT / "fixtures" / "golden" / "verify_key.txt").read_text(encoding="utf-8")


class ChatProofSessionTest(unittest.TestCase):
    def test_transcript_hash_is_deterministic(self) -> None:
        s1 = LocalChatProofSession(
            signing_key_pem=SIGNING_KEY,
            provider="openai",
            model="gpt-4.1-mini",
            session_id="session-fixed",
        )
        s2 = LocalChatProofSession(
            signing_key_pem=SIGNING_KEY,
            provider="openai",
            model="gpt-4.1-mini",
            session_id="session-fixed",
        )

        turns = [
            ("user", "How many legs does a spider have?"),
            ("assistant", "A spider has eight legs."),
        ]
        for role, content in turns:
            s1.log_turn(role=role, content=content)
            s2.log_turn(role=role, content=content)

        self.assertEqual(s1.transcript_hash(), s2.transcript_hash())

    def test_verifier_detects_tampering(self) -> None:
        session = LocalChatProofSession(
            signing_key_pem=SIGNING_KEY,
            provider="openai",
            model="gpt-4.1-mini",
            session_id="session-tamper-test",
        )
        session.log_turn(role="user", content="Say hello")
        session.log_turn(role="assistant", content="Hello!")
        finalized = session.finalize_bundle(
            bundle_id="PLFIXEDCHAT000000000000000001",
            created_at="2026-03-29T00:00:00+00:00",
        )

        bundle = finalized["bundle"]
        clean_result = verify_local_chat_bundle(bundle, finalized["transcript"], VERIFY_KEY)
        self.assertTrue(clean_result["verified"])

        tampered_transcript = copy.deepcopy(finalized["transcript"])
        tampered_transcript[1]["content"] = "Goodbye!"

        tampered_result = verify_local_chat_bundle(bundle, tampered_transcript, VERIFY_KEY)
        self.assertFalse(tampered_result["verified"])
        self.assertFalse(tampered_result["checks"]["transcript_hash_matches"])


if __name__ == "__main__":
    unittest.main()
