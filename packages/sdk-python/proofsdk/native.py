from __future__ import annotations

import base64
import json
from typing import Any

try:
    from . import _native as _native_impl
except ImportError as exc:
    raise ImportError(
        "Failed to load native proof-layer bindings. Run `python3 ./scripts/build_native.py` in packages/sdk-python first."
    ) from exc


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, default=str).encode("utf-8")


def _to_base64(value: Any) -> str:
    return base64.b64encode(_to_bytes(value)).decode("ascii")


def _normalize_artefacts(artefacts: Any) -> list[dict[str, str]]:
    if isinstance(artefacts, list):
        return [{"name": artefact["name"], "data_base64": _to_base64(artefact["data"])} for artefact in artefacts]
    if isinstance(artefacts, dict):
        return [{"name": name, "data_base64": _to_base64(data)} for name, data in artefacts.items()]
    raise TypeError("artefacts must be a list of {'name', 'data'} dicts or a name->data mapping")


def canonicalize_json(value: Any) -> bytes:
    return _native_impl.canonicalize(_to_bytes(value))


def hash_sha256(value: Any) -> str:
    return _native_impl.hash_sha256(_to_bytes(value))


def compute_merkle_root(digests: list[str]) -> str:
    return _native_impl.compute_merkle_root(digests)


def sign_bundle_root(bundle_root: str, key_pem: str, kid: str) -> str:
    return _native_impl.sign_bundle_root(bundle_root, key_pem, kid)


def verify_bundle_root(jws: str, expected_root: str, public_key_pem: str) -> bool:
    return _native_impl.verify_bundle_root(jws, expected_root, public_key_pem)


def build_bundle(
    *,
    capture: Any,
    artefacts: Any,
    key_pem: str,
    kid: str,
    bundle_id: str,
    created_at: str,
) -> dict[str, Any]:
    capture_json = capture if isinstance(capture, str) else json.dumps(capture)
    artefacts_json = json.dumps(
        [
            {
                "name": artefact["name"],
                "content_type": artefact.get("content_type", "application/octet-stream"),
                "data_base64": _to_base64(artefact["data"]),
            }
            for artefact in artefacts
        ]
    )
    return json.loads(
        _native_impl.build_bundle_json(capture_json, artefacts_json, key_pem, kid, bundle_id, created_at)
    )


def verify_bundle(*, bundle: Any, artefacts: Any, public_key_pem: str) -> dict[str, Any]:
    bundle_json = bundle if isinstance(bundle, str) else json.dumps(bundle)
    artefacts_json = json.dumps(_normalize_artefacts(artefacts))
    return json.loads(_native_impl.verify_bundle(bundle_json, artefacts_json, public_key_pem))


def redact_bundle(
    *,
    bundle: Any,
    item_indices: list[int],
    artefact_indices: list[int] | None = None,
    field_redactions: dict[int, list[str]] | dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    bundle_json = bundle if isinstance(bundle, str) else json.dumps(bundle)
    return json.loads(
        _native_impl.redact_bundle_json(
            bundle_json,
            json.dumps(item_indices),
            json.dumps(artefact_indices or []),
            json.dumps(field_redactions or {}),
        )
    )


def verify_redacted_bundle(*, bundle: Any, artefacts: Any, public_key_pem: str) -> dict[str, Any]:
    bundle_json = bundle if isinstance(bundle, str) else json.dumps(bundle)
    artefacts_json = json.dumps(_normalize_artefacts(artefacts))
    return json.loads(_native_impl.verify_redacted_bundle_json(bundle_json, artefacts_json, public_key_pem))
