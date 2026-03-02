import base64
import hashlib
import json
import unittest
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO_ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DIR = REPO_ROOT / "fixtures" / "golden"
FIXED_BUNDLE_DIR = GOLDEN_DIR / "fixed_bundle"
RFC_VECTOR_PATH = GOLDEN_DIR / "rfc8785_vectors.json"


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_digest_bytes(digest: str) -> bytes:
    if not digest.startswith("sha256:"):
        raise ValueError(f"invalid digest prefix: {digest}")
    value = digest[len("sha256:") :]
    if len(value) != 64:
        raise ValueError(f"invalid digest length: {digest}")
    return bytes.fromhex(value)


def _compute_bundle_root(digests: list[str]) -> str:
    level = [hashlib.sha256(b"\x00" + _parse_digest_bytes(d)).digest() for d in digests]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        level = next_level
    return "sha256:" + hashlib.sha256(level[0]).hexdigest()


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _extract_public_key_bytes(pem: str) -> bytes:
    begin = "-----BEGIN PROOF LAYER ED25519 PUBLIC KEY-----"
    end = "-----END PROOF LAYER ED25519 PUBLIC KEY-----"
    lines = [line.strip() for line in pem.strip().splitlines() if line.strip()]
    if not lines or lines[0] != begin or lines[-1] != end:
        raise ValueError("invalid proof-layer public key PEM")
    return base64.b64decode("".join(lines[1:-1]))


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
        self.assertEqual(bundle["integrity"]["signature"]["kid"], expected["signing_kid"])
        self.assertEqual(bundle["integrity"]["signature"]["value"], expected["signature_jws"])
        self.assertEqual(signature_fixture, expected["signature_jws"])

        projection = {
            "bundle_version": bundle["bundle_version"],
            "bundle_id": bundle["bundle_id"],
            "created_at": bundle["created_at"],
            "actor": bundle["actor"],
            "subject": bundle["subject"],
            "model": bundle["model"],
            "inputs": bundle["inputs"],
            "outputs": bundle["outputs"],
            "trace": bundle["trace"],
            "artefacts": bundle["artefacts"],
            "policy": bundle["policy"],
        }
        canonical = rfc8785.dumps(projection)
        self.assertEqual(canonical, canonical_fixture)
        self.assertEqual(_sha256_prefixed(canonical), expected["header_digest"])

        for artefact in bundle["artefacts"]:
            bytes_ = (FIXED_BUNDLE_DIR / "artefacts" / artefact["name"]).read_bytes()
            self.assertEqual(_sha256_prefixed(bytes_), artefact["digest"])
            self.assertEqual(_sha256_prefixed(bytes_), expected["artefact_digests"][artefact["name"]])
            self.assertEqual(len(bytes_), artefact["size"])

        for name, entry in expected["manifest_entries"].items():
            bytes_ = (FIXED_BUNDLE_DIR / name).read_bytes()
            self.assertEqual(_sha256_prefixed(bytes_), entry["digest"])
            self.assertEqual(len(bytes_), entry["size"])

        ordered_digests = [expected["header_digest"]] + [artefact["digest"] for artefact in bundle["artefacts"]]
        root_one = _compute_bundle_root(ordered_digests)
        root_two = _compute_bundle_root(ordered_digests)
        self.assertEqual(root_one, root_two)
        self.assertEqual(root_one, expected["bundle_root"])

        parts = expected["signature_jws"].split(".")
        self.assertEqual(len(parts), 3)
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["kid"], expected["signing_kid"])
        payload = _b64url_decode(parts[1]).decode("utf-8")
        self.assertEqual(payload, expected["bundle_root"])

        signature_bytes = _b64url_decode(parts[2])
        public_key = Ed25519PublicKey.from_public_bytes(_extract_public_key_bytes(verify_pem))
        public_key.verify(signature_bytes, f"{parts[0]}.{parts[1]}".encode("utf-8"))

    def test_rfc8785_vectors_canonicalize_as_expected(self):
        fixture = json.loads(RFC_VECTOR_PATH.read_text(encoding="utf-8"))
        for vector in fixture["vectors"]:
            parsed = json.loads(vector["raw_json"])
            canonical = rfc8785.dumps(parsed).decode("utf-8")
            self.assertEqual(canonical, vector["canonical_json"], vector["name"])


if __name__ == "__main__":
    unittest.main()
