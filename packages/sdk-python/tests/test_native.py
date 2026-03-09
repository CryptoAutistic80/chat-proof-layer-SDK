import json
import unittest
from pathlib import Path

from proofsdk.native import (
    build_bundle,
    hash_sha256,
    redact_bundle,
    sign_bundle_root,
    verify_bundle,
    verify_bundle_root,
    verify_redacted_bundle,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"


class TestNativeBindings(unittest.TestCase):
    def test_native_sign_and_verify_round_trip(self):
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")
        bundle_root = hash_sha256("python-native-roundtrip")
        jws = sign_bundle_root(bundle_root, signing_key_pem, "kid-dev-01")

        self.assertIsInstance(jws, str)
        self.assertTrue(verify_bundle_root(jws, bundle_root, public_key_pem))

    def test_native_verify_bundle_uses_rust_core(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")
        artefacts = [
            {
                "name": artefact["name"],
                "data": (GOLDEN_DIR / "fixed_bundle" / "artefacts" / artefact["name"]).read_bytes(),
            }
            for artefact in bundle["artefacts"]
        ]

        summary = verify_bundle(bundle=bundle, artefacts=artefacts, public_key_pem=public_key_pem)
        self.assertEqual(summary, {"artefact_count": len(artefacts)})

    def test_native_build_bundle_reproduces_the_deterministic_golden_bundle(self):
        capture = json.loads((GOLDEN_DIR / "capture.json").read_text(encoding="utf-8"))
        expected_bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        signing_key_pem = (GOLDEN_DIR / "signing_key.txt").read_text(encoding="utf-8")
        artefacts = [
            {
                "name": "prompt.json",
                "content_type": "application/json",
                "data": (GOLDEN_DIR / "prompt.json").read_bytes(),
            },
            {
                "name": "response.json",
                "content_type": "application/json",
                "data": (GOLDEN_DIR / "response.json").read_bytes(),
            },
        ]

        bundle = build_bundle(
            capture=capture,
            artefacts=artefacts,
            key_pem=signing_key_pem,
            kid="kid-dev-01",
            bundle_id=expected_bundle["bundle_id"],
            created_at=expected_bundle["created_at"],
        )

        self.assertEqual(bundle, expected_bundle)

    def test_native_redact_bundle_and_verify_redacted_bundle_round_trip(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))
        public_key_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")

        redacted = redact_bundle(bundle=bundle, item_indices=[0])
        summary = verify_redacted_bundle(bundle=redacted, artefacts=[], public_key_pem=public_key_pem)

        self.assertEqual(len(redacted["disclosed_items"]), 1)
        self.assertEqual(len(redacted["disclosed_artefacts"]), 0)
        self.assertEqual(
            summary,
            {
                "disclosed_item_count": 1,
                "disclosed_artefact_count": 0,
            },
        )

    def test_native_redact_bundle_supports_field_level_redaction(self):
        bundle = json.loads((GOLDEN_DIR / "fixed_bundle" / "proof_bundle.json").read_text(encoding="utf-8"))

        redacted = redact_bundle(
            bundle=bundle,
            item_indices=[0],
            field_redactions={0: ["output_commitment"]},
        )

        self.assertIsNone(redacted["disclosed_items"][0].get("item"))
        self.assertEqual(
            redacted["disclosed_items"][0]["field_redacted_item"]["redacted_fields"],
            ["output_commitment"],
        )


if __name__ == "__main__":
    unittest.main()
