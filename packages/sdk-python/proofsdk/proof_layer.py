from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from proofsdk.client import ProofLayerClient
from proofsdk.evidence import (
    create_adversarial_test_request,
    create_authority_notification_request,
    create_authority_submission_request,
    create_conformity_assessment_request,
    create_compute_metrics_request,
    create_corrective_action_request,
    create_copyright_policy_request,
    create_data_governance_request,
    create_declaration_request,
    create_downstream_documentation_request,
    create_fundamental_rights_assessment_request,
    create_human_oversight_request,
    create_incident_report_request,
    create_instructions_for_use_request,
    create_literacy_attestation_request,
    create_llm_interaction_request,
    create_model_evaluation_request,
    create_post_market_monitoring_request,
    create_policy_decision_request,
    create_qms_record_request,
    create_regulator_correspondence_request,
    create_registration_request,
    create_reporting_deadline_request,
    create_retrieval_request,
    create_risk_assessment_request,
    create_standards_alignment_request,
    create_technical_doc_request,
    create_training_summary_request,
    create_training_provenance_request,
    create_tool_call_request,
)
from proofsdk.local_client import LocalProofLayerClient




class ChatProofSession:
    def __init__(
        self,
        proof_layer: "ProofLayer",
        *,
        provider: str,
        model: str,
        system_id: str | None = None,
        request_id: str | None = None,
        thread_id: str | None = None,
        user_ref: str | None = None,
        model_parameters: Any = None,
        compliance_profile: dict[str, Any] | None = None,
        retention_class: str | None = None,
        artefacts: list[dict[str, Any]] | None = None,
    ) -> None:
        self._proof_layer = proof_layer
        self._provider = provider
        self._model = model
        self._system_id = system_id
        self._request_id = request_id
        self._thread_id = thread_id
        self._user_ref = user_ref
        self._model_parameters = model_parameters
        self._compliance_profile = compliance_profile
        self._retention_class = retention_class
        self._artefacts = artefacts
        self._transcript: list[dict[str, str]] = []

    def log_user(self, content: str) -> None:
        self._transcript.append({"role": "user", "content": content})

    def log_ai(self, content: str) -> None:
        self._transcript.append({"role": "assistant", "content": content})

    def finish_session(self) -> dict[str, Any]:
        user_messages = [entry["content"] for entry in self._transcript if entry["role"] == "user"]
        assistant_messages = [
            entry["content"] for entry in self._transcript if entry["role"] == "assistant"
        ]
        proof = self._proof_layer.capture(
            provider=self._provider,
            model=self._model,
            input=user_messages,
            output="\n\n".join(assistant_messages),
            system_id=self._system_id,
            request_id=self._request_id,
            thread_id=self._thread_id,
            user_ref=self._user_ref,
            model_parameters=self._model_parameters,
            compliance_profile=self._compliance_profile,
            retention_class=self._retention_class,
            artefacts=self._artefacts,
        )
        return {"transcript": list(self._transcript), "proof": proof}

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
        compliance_profile: dict[str, Any] | None = None,
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
        self.compliance_profile = compliance_profile
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

    @classmethod
    def load(cls, **kwargs: Any) -> "ProofLayer":
        return cls(**kwargs)

    def start_chat_session(
        self,
        *,
        provider: str,
        model: str,
        system_id: str | None = None,
        request_id: str | None = None,
        thread_id: str | None = None,
        user_ref: str | None = None,
        model_parameters: Any = None,
        compliance_profile: dict[str, Any] | None = None,
        retention_class: str | None = None,
        artefacts: list[dict[str, Any]] | None = None,
    ) -> ChatProofSession:
        return ChatProofSession(
            self,
            provider=provider,
            model=model,
            system_id=system_id,
            request_id=request_id,
            thread_id=thread_id,
            user_ref=user_ref,
            model_parameters=model_parameters,
            compliance_profile=compliance_profile,
            retention_class=retention_class,
            artefacts=artefacts,
        )

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

    def verify_timestamp(
        self,
        *,
        bundle_id: str | None = None,
        bundle_root: str | None = None,
        timestamp: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "verify_timestamp"):
            return self.client.verify_timestamp(
                bundle_id=bundle_id,
                bundle_root=bundle_root,
                timestamp=timestamp,
            )
        raise ValueError("underlying client does not support verify_timestamp")

    def verify_receipt(
        self,
        *,
        bundle_id: str | None = None,
        bundle_root: str | None = None,
        receipt: dict[str, Any] | None = None,
        live_check_mode: str | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "verify_receipt"):
            return self.client.verify_receipt(
                bundle_id=bundle_id,
                bundle_root=bundle_root,
                receipt=receipt,
                live_check_mode=live_check_mode,
            )
        raise ValueError("underlying client does not support verify_receipt")

    def evaluate_completeness(
        self,
        *,
        profile: str,
        bundle: dict[str, Any] | None = None,
        bundle_id: str | None = None,
        pack_id: str | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "evaluate_completeness"):
            return self.client.evaluate_completeness(
                profile=profile,
                bundle=bundle,
                bundle_id=bundle_id,
                pack_id=pack_id,
            )
        raise ValueError("underlying client does not support evaluate_completeness")

    def disclose(
        self,
        *,
        bundle: dict[str, Any],
        item_indices: list[int],
        artefact_indices: list[int] | None = None,
        field_redactions: dict[int, list[str]] | dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "disclose_bundle"):
            return self.client.disclose_bundle(
                bundle,
                item_indices=item_indices,
                artefact_indices=artefact_indices or [],
                field_redactions=field_redactions or {},
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
        bundle_ids: list[str] | None = None,
        system_id: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        bundle_format: str | None = None,
        disclosure_policy: str | None = None,
        disclosure_template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "create_pack"):
            return self.client.create_pack(
                pack_type=pack_type,
                bundle_ids=bundle_ids,
                system_id=system_id,
                from_date=from_date,
                to_date=to_date,
                bundle_format=bundle_format,
                disclosure_policy=disclosure_policy,
                disclosure_template=disclosure_template,
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

    def get_disclosure_templates(self) -> dict[str, Any]:
        if hasattr(self.client, "get_disclosure_templates"):
            return self.client.get_disclosure_templates()
        raise ValueError("underlying client does not support get_disclosure_templates; use vault mode")

    def render_disclosure_template(
        self,
        *,
        profile: str,
        name: str | None = None,
        redaction_groups: list[str] | None = None,
        redacted_fields_by_item_type: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "render_disclosure_template"):
            return self.client.render_disclosure_template(
                profile=profile,
                name=name,
                redaction_groups=redaction_groups,
                redacted_fields_by_item_type=redacted_fields_by_item_type,
            )
        raise ValueError(
            "underlying client does not support render_disclosure_template; use vault mode"
        )

    def update_disclosure_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if hasattr(self.client, "update_disclosure_config"):
            return self.client.update_disclosure_config(config)
        raise ValueError("underlying client does not support update_disclosure_config; use vault mode")

    def preview_disclosure(
        self,
        *,
        bundle_id: str,
        pack_type: str | None = None,
        disclosure_policy: str | None = None,
        policy: dict[str, Any] | None = None,
        disclosure_template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if hasattr(self.client, "preview_disclosure"):
            return self.client.preview_disclosure(
                bundle_id=bundle_id,
                pack_type=pack_type,
                disclosure_policy=disclosure_policy,
                policy=policy,
                disclosure_template=disclosure_template,
            )
        raise ValueError("underlying client does not support preview_disclosure; use vault mode")

    def _submit_capture(
        self,
        request: dict[str, Any],
        *,
        bundle_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        if self.compliance_profile is not None and request["capture"].get("compliance_profile") is None:
            request["capture"]["compliance_profile"] = self.compliance_profile
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
        compliance_profile: dict[str, Any] | None = None,
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
                compliance_profile=compliance_profile,
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

    def capture_compute_metrics(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_compute_metrics_request(
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

    def capture_instructions_for_use(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_instructions_for_use_request(
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

    def capture_qms_record(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_qms_record_request(
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

    def capture_fundamental_rights_assessment(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_fundamental_rights_assessment_request(
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

    def capture_standards_alignment(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_standards_alignment_request(
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

    def capture_post_market_monitoring(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_post_market_monitoring_request(
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

    def capture_corrective_action(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_corrective_action_request(
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

    def capture_authority_notification(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_authority_notification_request(
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

    def capture_authority_submission(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_authority_submission_request(
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

    def capture_reporting_deadline(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_reporting_deadline_request(
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

    def capture_regulator_correspondence(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_regulator_correspondence_request(
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

    def capture_downstream_documentation(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_downstream_documentation_request(
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

    def capture_copyright_policy(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_copyright_policy_request(
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

    def capture_training_summary(self, **kwargs: Any) -> dict[str, Any]:
        params, bundle_id, created_at = self._split_local_options(kwargs)
        return self._submit_capture(
            create_training_summary_request(
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
