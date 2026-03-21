from __future__ import annotations

import base64
import json
from typing import Any, Callable
from urllib.request import Request, urlopen


def _to_base64(data: Any) -> str:
    if isinstance(data, bytes):
        return base64.b64encode(data).decode("ascii")
    if isinstance(data, str):
        return base64.b64encode(data.encode("utf-8")).decode("ascii")
    return base64.b64encode(json.dumps(data).encode("utf-8")).decode("ascii")


class ProofLayerClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        request_fn: Callable[[str, str, dict[str, str], bytes | None], dict[str, Any]] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._request_fn = request_fn or self._default_request

    def create_bundle(self, capture: dict[str, Any], artefacts: list[dict[str, Any]]) -> dict[str, Any]:
        payload = {
            "capture": capture,
            "artefacts": [
                {
                    "name": a["name"],
                    "content_type": a.get("content_type", "application/octet-stream"),
                    "data_base64": _to_base64(a["data"]),
                }
                for a in artefacts
            ],
        }
        return self._request_fn("POST", "/v1/bundles", self._headers_json(), json.dumps(payload).encode("utf-8"))

    def verify_bundle(
        self,
        bundle: dict[str, Any],
        artefacts: list[dict[str, Any]],
        public_key_pem: str,
    ) -> dict[str, Any]:
        payload = {
            "bundle": bundle,
            "artefacts": [
                {"name": a["name"], "data_base64": _to_base64(a["data"])} for a in artefacts
            ],
            "public_key_pem": public_key_pem,
        }
        return self._request_fn("POST", "/v1/verify", self._headers_json(), json.dumps(payload).encode("utf-8"))

    def verify_package(self, bundle_pkg: bytes | str, public_key_pem: str) -> dict[str, Any]:
        payload = {
            "bundle_pkg_base64": _to_base64(bundle_pkg),
            "public_key_pem": public_key_pem,
        }
        return self._request_fn("POST", "/v1/verify", self._headers_json(), json.dumps(payload).encode("utf-8"))

    def evaluate_completeness(
        self,
        *,
        profile: str,
        bundle: dict[str, Any] | None = None,
        bundle_id: str | None = None,
    ) -> dict[str, Any]:
        selection_count = sum(1 for value in (bundle, bundle_id) if value is not None)
        if selection_count != 1:
            raise ValueError("provide exactly one of bundle or bundle_id")
        payload: dict[str, Any] = {"profile": profile}
        if bundle is not None:
            payload["bundle"] = bundle
        if bundle_id is not None:
            payload["bundle_id"] = bundle_id
        return self._request_fn(
            "POST",
            "/v1/completeness/evaluate",
            self._headers_json(),
            json.dumps(payload).encode("utf-8"),
        )

    def create_pack(
        self,
        *,
        pack_type: str,
        system_id: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        bundle_format: str | None = None,
        disclosure_policy: str | None = None,
        disclosure_template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if disclosure_policy is not None and disclosure_template is not None:
            raise ValueError("provide either disclosure_policy or disclosure_template, not both")
        payload: dict[str, Any] = {
            "pack_type": pack_type,
            "system_id": system_id,
            "from": from_date,
            "to": to_date,
        }
        if bundle_format is not None:
            payload["bundle_format"] = bundle_format
        if disclosure_policy is not None:
            payload["disclosure_policy"] = disclosure_policy
        if disclosure_template is not None:
            payload["disclosure_template"] = disclosure_template
        return self._request_fn("POST", "/v1/packs", self._headers_json(), json.dumps(payload).encode("utf-8"))

    def get_pack(self, pack_id: str) -> dict[str, Any]:
        return self._request_fn("GET", f"/v1/packs/{pack_id}", self._headers(), None)

    def get_pack_manifest(self, pack_id: str) -> dict[str, Any]:
        return self._request_fn("GET", f"/v1/packs/{pack_id}/manifest", self._headers(), None)

    def download_pack_export(self, pack_id: str) -> bytes:
        return self._request_bytes("GET", f"/v1/packs/{pack_id}/export", self._headers(), None)

    def get_config(self) -> dict[str, Any]:
        return self._request_fn("GET", "/v1/config", self._headers(), None)

    def get_disclosure_config(self) -> dict[str, Any]:
        return self.get_config()["disclosure"]

    def get_disclosure_templates(self) -> dict[str, Any]:
        return self._request_fn("GET", "/v1/disclosure/templates", self._headers(), None)

    def render_disclosure_template(
        self,
        *,
        profile: str,
        name: str | None = None,
        redaction_groups: list[str] | None = None,
        redacted_fields_by_item_type: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"profile": profile}
        if name is not None:
            payload["name"] = name
        if redaction_groups:
            payload["redaction_groups"] = redaction_groups
        if redacted_fields_by_item_type:
            payload["redacted_fields_by_item_type"] = redacted_fields_by_item_type
        return self._request_fn(
            "POST",
            "/v1/disclosure/templates/render",
            self._headers_json(),
            json.dumps(payload).encode("utf-8"),
        )

    def update_disclosure_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return self._request_fn(
            "PUT",
            "/v1/config/disclosure",
            self._headers_json(),
            json.dumps(config).encode("utf-8"),
        )

    def preview_disclosure(
        self,
        *,
        bundle_id: str,
        pack_type: str | None = None,
        disclosure_policy: str | None = None,
        policy: dict[str, Any] | None = None,
        disclosure_template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        selection_count = sum(
            1
            for value in (disclosure_policy, policy, disclosure_template)
            if value is not None
        )
        if selection_count > 1:
            raise ValueError(
                "provide only one of disclosure_policy, policy, or disclosure_template"
            )
        payload: dict[str, Any] = {"bundle_id": bundle_id}
        if pack_type is not None:
            payload["pack_type"] = pack_type
        if disclosure_policy is not None:
            payload["disclosure_policy"] = disclosure_policy
        if policy is not None:
            payload["policy"] = policy
        if disclosure_template is not None:
            payload["disclosure_template"] = disclosure_template
        return self._request_fn(
            "POST",
            "/v1/disclosure/preview",
            self._headers_json(),
            json.dumps(payload).encode("utf-8"),
        )

    def get_bundle(self, bundle_id: str) -> dict[str, Any]:
        return self._request_fn("GET", f"/v1/bundles/{bundle_id}", self._headers(), None)

    def get_artefact(self, bundle_id: str, name: str) -> bytes:
        response = self._request_bytes("GET", f"/v1/bundles/{bundle_id}/artefacts/{name}", self._headers(), None)
        return response

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    def _headers_json(self) -> dict[str, str]:
        headers = self._headers()
        headers["content-type"] = "application/json"
        return headers

    def _request_bytes(self, method: str, path: str, headers: dict[str, str], body: bytes | None) -> bytes:
        req = Request(
            f"{self.base_url}{path}",
            method=method,
            headers=headers,
            data=body,
        )
        with urlopen(req) as res:
            return res.read()

    def _default_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> dict[str, Any]:
        raw = self._request_bytes(method, path, headers, body)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))
