from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from proofsdk.client import ProofLayerClient
from proofsdk.evidence import (
    create_adversarial_test_request,
    create_conformity_assessment_request,
    create_data_governance_request,
    create_declaration_request,
    create_human_oversight_request,
    create_incident_report_request,
    create_literacy_attestation_request,
    create_llm_interaction_request,
    create_model_evaluation_request,
    create_policy_decision_request,
    create_registration_request,
    create_retrieval_request,
    create_risk_assessment_request,
    create_technical_doc_request,
    create_training_provenance_request,
    create_tool_call_request,
)
from proofsdk.local_client import LocalProofLayerClient


class ProofLayer:
    def __init__(
        self,
        *,
        vault_url: str | None = None,
        api_key: str | None = None,
        request_fn: Callable[[str, str, dict[str, str], bytes | None], dict[str, Any]] | None = None,
        signing_key_pem: str | None = None,
        signing_key_path: str | None = None,
        key_id: str = "kid-dev-01",
        system_id: str | None = None,
        role: str = "provider",
        issuer: str = "proof-layer-python",
        app_id: str = "python-sdk",
        env: str = "dev",
        bundle_id_factory: Callable[[], str] | None = None,
        created_at_factory: Callable[[], str] | None = None,
    ) -> None:
        if signing_key_pem is None and signing_key_path:
            signing_key_pem = Path(signing_key_path).read_text(encoding="utf-8")

        self.key_id = key_id
        self.system_id = system_id
        self.role = role
        self.issuer = issuer
        self.app_id = app_id
        self.env = env

        if signing_key_pem:
            self.mode = "local"
            kwargs: dict[str, Any] = {
                "signing_key_pem": signing_key_pem,
                "signing_key_id": key_id,
            }
            if bundle_id_factory is not None:
                kwargs["bundle_id_factory"] = bundle_id_factory
            if created_at_factory is not None:
                kwargs["created_at_factory"] = created_at_factory
            self.client = LocalProofLayerClient(**kwargs)
        elif vault_url:
            self.mode = "vault"
            self.client = ProofLayerClient(base_url=vault_url, api_key=api_key, request_fn=request_fn)
        else:
            raise ValueError("ProofLayer requires either signing_key_pem/signing_key_path or vault_url")

    def create_bundle(
        self,
        capture: dict[str, Any],
        artefacts: list[dict[str, Any]],
        *,
        bundle_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        if self.mode == "local":
            return self.client.create_bundle(capture, artefacts, bundle_id=bundle_id, created_at=created_at)
        return self.client.create_bundle(capture, artefacts)

    def verify_bundle(
        self,
        bundle: dict[str, Any],
        artefacts: list[dict[str, Any]],
        public_key_pem: str,
    ) -> dict[str, Any]:
        return self.client.verify_bundle(bundle, artefacts, public_key_pem)

    def disclose(
        self,
        *,
        bundle: dict[str, Any],
        item_indices: list[int],
        artefact_indices: list[int] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "disclose_bundle"):
            return self.client.disclose_bundle(
                bundle,
                item_indices=item_indices,
                artefact_indices=artefact_indices or [],
            )
        raise ValueError("underlying client does not support disclose; use local signing mode")

    def verify_redacted_bundle(
        self,
        bundle: dict[str, Any],
        artefacts: list[dict[str, Any]],
        public_key_pem: str,
    ) -> dict[str, Any]:
        if hasattr(self.client, "verify_redacted_bundle"):
            return self.client.verify_redacted_bundle(bundle, artefacts, public_key_pem)
        raise ValueError("underlying client does not support verify_redacted_bundle")

    def create_pack(
        self,
        *,
        pack_type: str,
        system_id: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        bundle_format: str | None = None,
        disclosure_policy: str | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "create_pack"):
            return self.client.create_pack(
                pack_type=pack_type,
                system_id=system_id,
                from_date=from_date,
                to_date=to_date,
                bundle_format=bundle_format,
                disclosure_policy=disclosure_policy,
            )
        raise ValueError("underlying client does not support create_pack; use vault mode")

    def get_pack_manifest(self, pack_id: str) -> dict[str, Any]:
        if hasattr(self.client, "get_pack_manifest"):
            return self.client.get_pack_manifest(pack_id)
        raise ValueError("underlying client does not support get_pack_manifest; use vault mode")

    def download_pack_export(self, pack_id: str) -> bytes:
        if hasattr(self.client, "download_pack_export"):
            return self.client.download_pack_export(pack_id)
        raise ValueError("underlying client does not support download_pack_export; use vault mode")

    def get_vault_config(self) -> dict[str, Any]:
        if hasattr(self.client, "get_config"):
            return self.client.get_config()
        raise ValueError("underlying client does not support get_vault_config; use vault mode")

    def get_disclosure_config(self) -> dict[str, Any]:
        if hasattr(self.client, "get_disclosure_config"):
            return self.client.get_disclosure_config()
        raise ValueError("underlying client does not support get_disclosure_config; use vault mode")

    def update_disclosure_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if hasattr(self.client, "update_disclosure_config"):
            return self.client.update_disclosure_config(config)
        raise ValueError("underlying client does not support update_disclosure_config; use vault mode")

    def _submit_capture(
        self,
        request: dict[str, Any],
        *,
        bundle_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        return self.create_bundle(
            request["capture"],
            request["artefacts"],
            bundle_id=bundle_id,
            created_at=created_at,
        )

    @staticmethod
    def _split_local_options(kwargs: dict[str, Any]) -> tuple[dict[str, Any], str | None, str | None]:
        params = dict(kwargs)
        bundle_id = params.pop("bundle_id", None)
        created_at = params.pop("created_at", None)
        return params, bundle_id, created_at

    def capture(
        self,
        *,
        provider: str,
        model: str,
        input: Any,
        output: Any,
        system_id: str | None = None,
        request_id: str | None = None,
        thread_id: str | None = None,
        user_ref: str | None = None,
        model_parameters: Any = None,
        retrieval_commitment: str | None = None,
        tool_outputs_commitment: str | None = None,
        trace: Any = None,
        trace_commitment: str | None = None,
        otel_semconv_version: str | None = None,
        redactions: list[str] | None = None,
        encryption_enabled: bool = False,
        retention_class: str | None = None,
        artefacts: list[dict[str, Any]] | None = None,
        bundle_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        return self._submit_capture(
            create_llm_interaction_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=system_id or self.system_id,
                provider=provider,
                model=model,
                input=input,
                output=output,
                request_id=request_id,
                thread_id=thread_id,
                user_ref=user_ref,
                model_parameters=model_parameters,
                retrieval_commitment=retrieval_commitment,
                tool_outputs_commitment=tool_outputs_commitment,
                trace=trace,
                trace_commitment=trace_commitment,
                otel_semconv_version=otel_semconv_version,
                redactions=redactions,
                encryption_enabled=encryption_enabled,
                retention_class=retention_class,
                artefacts=artefacts,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_tool_call(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_tool_call_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_retrieval(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_retrieval_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_human_oversight(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_human_oversight_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_policy_decision(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_policy_decision_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_risk_assessment(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_risk_assessment_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_data_governance(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_data_governance_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_technical_doc(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_technical_doc_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_literacy_attestation(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_literacy_attestation_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_incident_report(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_incident_report_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_model_evaluation(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_model_evaluation_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_adversarial_test(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_adversarial_test_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_training_provenance(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_training_provenance_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_conformity_assessment(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_conformity_assessment_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_declaration(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_declaration_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )

    def capture_registration(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_registration_request(
                key_id=self.key_id,
                role=self.role,
                issuer=self.issuer,
                app_id=self.app_id,
                env=self.env,
                system_id=params.pop("system_id", None) or self.system_id,
                **params,
            ),
            bundle_id=bundle_id,
            created_at=created_at,
        )
