from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from proofsdk.native import build_bundle, redact_bundle, verify_bundle, verify_redacted_bundle


def _default_bundle_id() -> str:
    return f"pl-local-{uuid.uuid4()}"


def _default_created_at() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalProofLayerClient:
    def __init__(
        self,
        *,
        signing_key_pem: str,
        signing_key_id: str = "kid-dev-01",
        bundle_id_factory: Callable[[], str] = _default_bundle_id,
        created_at_factory: Callable[[], str] = _default_created_at,
    ) -> None:
        if not signing_key_pem:
            raise ValueError("signing_key_pem is required")
        self.signing_key_pem = signing_key_pem
        self.signing_key_id = signing_key_id
        self.bundle_id_factory = bundle_id_factory
        self.created_at_factory = created_at_factory

    def create_bundle(
        self,
        capture: dict[str, Any],
        artefacts: list[dict[str, Any]],
        *,
        bundle_id: str | None = None,
        created_at: str | None = None,
        signing_key_pem: str | None = None,
        signing_key_id: str | None = None,
    ) -> dict[str, Any]:
        bundle = build_bundle(
            capture=capture,
            artefacts=artefacts,
            key_pem=signing_key_pem or self.signing_key_pem,
            kid=signing_key_id or self.signing_key_id,
            bundle_id=bundle_id or self.bundle_id_factory(),
            created_at=created_at or self.created_at_factory(),
        )

        return {
            "bundle_id": bundle["bundle_id"],
            "bundle_root": bundle["integrity"]["bundle_root"],
            "signature": bundle["integrity"]["signature"]["value"],
            "created_at": bundle["created_at"],
            "bundle": bundle,
        }

    def verify_bundle(
        self,
        bundle: dict[str, Any],
        artefacts: list[dict[str, Any]],
        public_key_pem: str,
    ) -> dict[str, Any]:
        return verify_bundle(bundle=bundle, artefacts=artefacts, public_key_pem=public_key_pem)

    def disclose_bundle(
        self,
        bundle: dict[str, Any],
        *,
        item_indices: list[int],
        artefact_indices: list[int] | None = None,
    ) -> dict[str, Any]:
        return redact_bundle(
            bundle=bundle,
            item_indices=item_indices,
            artefact_indices=artefact_indices or [],
        )

    def verify_redacted_bundle(
        self,
        bundle: dict[str, Any],
        artefacts: list[dict[str, Any]],
        public_key_pem: str,
    ) -> dict[str, Any]:
        return verify_redacted_bundle(bundle=bundle, artefacts=artefacts, public_key_pem=public_key_pem)
