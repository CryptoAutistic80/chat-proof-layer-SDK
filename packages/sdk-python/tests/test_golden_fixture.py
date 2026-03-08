import json
import unittest
from pathlib import Path

from proofsdk.native import (
    canonicalize_json,
    compute_merkle_root,
    hash_sha256,
    verify_bundle_root,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"
FIXED_BUNDLE_DIR = GOLDEN_DIR / "fixed_bundle"
RFC_VECTOR_PATH = GOLDEN_DIR / "rfc8785_vectors.json"


class TestGoldenFixture(unittest.TestCase):
    def test_golden_fixture_digest_and_signature_assertions(self):
        expected = json.loads((GOLDEN_DIR / "expected_bundle_values.json").read_text(encoding="utf-8"))
        bundle = json.loads((FIXED_BUNDLE_DIR / "proof_bundle.json").read_text(encoding="utf-8"))
        canonical_fixture = (FIXED_BUNDLE_DIR / "proof_bundle.canonical.json").read_bytes()
        signature_fixture = (FIXED_BUNDLE_DIR / "proof_bundle.sig").read_text(encoding="utf-8").strip()
        verify_pem = (GOLDEN_DIR / "verify_key.txt").read_text(encoding="utf-8")

        self.assertEqual(bundle["bundle_id"], expected["bundle_id"])
        self.assertEqual(bundle["created_at"], expected["created_at"])
        self.assertEqual(bundle["integrity"]["header_digest"], expected["header_digest"])
        self.assertEqual(bundle["integrity"]["bundle_root"], expected["bundle_root"])
        self.assertEqual(
            bundle["integrity"]["bundle_root_algorithm"],
            expected["bundle_root_algorithm"],
        )
        self.assertEqual(bundle["integrity"]["signature"]["kid"], expected["signing_kid"])
        self.assertEqual(bundle["integrity"]["signature"]["value"], expected["signature_jws"])
        self.assertEqual(signature_fixture, expected["signature_jws"])

        projection = {
            "bundle_version": bundle["bundle_version"],
            "bundle_id": bundle["bundle_id"],
            "created_at": bundle["created_at"],
            "actor": bundle["actor"],
            "subject": bundle["subject"],
            "context": bundle["context"],
            "policy": bundle["policy"],
            "item_count": len(bundle["items"]),
            "artefact_count": len(bundle["artefacts"]),
        }
        canonical = canonicalize_json(projection)
        self.assertEqual(canonical, canonical_fixture)
        self.assertEqual(hash_sha256(canonical), expected["header_digest"])

        for artefact in bundle["artefacts"]:
            bytes_ = (FIXED_BUNDLE_DIR / "artefacts" / artefact["name"]).read_bytes()
            self.assertEqual(hash_sha256(bytes_), artefact["digest"])
            self.assertEqual(hash_sha256(bytes_), expected["artefact_digests"][artefact["name"]])
            self.assertEqual(len(bytes_), artefact["size"])

        for name, entry in expected["manifest_entries"].items():
            bytes_ = (FIXED_BUNDLE_DIR / name).read_bytes()
            self.assertEqual(hash_sha256(bytes_), entry["digest"])
            self.assertEqual(len(bytes_), entry["size"])

        ordered_digests = [expected["header_digest"]]
        ordered_digests.extend(
            hash_sha256(canonicalize_json(item)) for item in bundle["items"]
        )
        ordered_digests.extend(
            hash_sha256(canonicalize_json(artefact)) for artefact in bundle["artefacts"]
        )
        root_one = compute_merkle_root(ordered_digests)
        root_two = compute_merkle_root(ordered_digests)
        self.assertEqual(root_one, root_two)
        self.assertEqual(root_one, expected["bundle_root"])

        self.assertTrue(verify_bundle_root(expected["signature_jws"], expected["bundle_root"], verify_pem))

    def test_rfc8785_vectors_canonicalize_as_expected(self):
        fixture = json.loads(RFC_VECTOR_PATH.read_text(encoding="utf-8"))
        for vector in fixture["vectors"]:
            canonical = canonicalize_json(vector["raw_json"]).decode("utf-8")
            self.assertEqual(canonical, vector["canonical_json"], vector["name"])


if __name__ == "__main__":
    unittest.main()
