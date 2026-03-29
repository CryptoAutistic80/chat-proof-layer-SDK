from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from proofsdk.evidence import create_llm_interaction_request
from proofsdk.local_client import LocalProofLayerClient
from proofsdk.native import canonicalize_json, hash_sha256, sign_bundle_root, verify_bundle, verify_bundle_root


@dataclass(frozen=True)
class ChatTurn:
    role: str
    content: str


class LocalChatProofSession:
    def __init__(
        self,
        *,
        signing_key_pem: str,
        key_id: str = "kid-dev-01",
        session_id: str | None = None,
        provider: str,
        model: str,
        system_id: str | None = None,
        actor: dict[str, Any] | None = None,
    ) -> None:
        self.signing_key_pem = signing_key_pem
        self.key_id = key_id
        self.session_id = session_id or f"chat-session-{uuid.uuid4()}"
        self.provider = provider
        self.model = model
        self.system_id = system_id
        self.actor = actor or {
            "role": "provider",
            "issuer": "proof-layer-python",
            "app_id": "python-sdk",
            "env": "dev",
        }
        self._turns: list[ChatTurn] = []

    def log_turn(self, *, role: str, content: str) -> None:
        if role not in {"user", "assistant", "system", "tool"}:
            raise ValueError("role must be one of: user, assistant, system, tool")
        self._turns.append(ChatTurn(role=role, content=content))

    def transcript(self) -> list[dict[str, str]]:
        return [{"role": turn.role, "content": turn.content} for turn in self._turns]

    def transcript_hash(self) -> str:
        return hash_sha256(canonicalize_json(self.transcript()))

    def session_signature(self) -> str:
        return sign_bundle_root(self.transcript_hash(), self.signing_key_pem, self.key_id)

    def finalize_bundle(
        self,
        *,
        bundle_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        transcript = self.transcript()
        transcript_hash = self.transcript_hash()
        session_signature = self.session_signature()
        user_turns = [turn["content"] for turn in transcript if turn["role"] == "user"]
        assistant_turns = [turn["content"] for turn in transcript if turn["role"] == "assistant"]

        request = create_llm_interaction_request(
            key_id=self.key_id,
            provider=self.provider,
            model=self.model,
            input=user_turns,
            output="\n\n".join(assistant_turns),
            role=self.actor.get("role", "provider"),
            issuer=self.actor.get("issuer", "proof-layer-python"),
            app_id=self.actor.get("app_id", "python-sdk"),
            env=self.actor.get("env", "dev"),
            system_id=self.system_id,
            thread_id=self.session_id,
            model_parameters={
                "chat_proof": {
                    "transcript_hash": transcript_hash,
                    "session_signature": {
                        "format": "JWS",
                        "alg": "EdDSA",
                        "kid": self.key_id,
                        "value": session_signature,
                    },
                    "turn_count": len(transcript),
                }
            },
            artefacts=[
                {
                    "name": "transcript.json",
                    "content_type": "application/json",
                    "data": json.dumps(transcript, separators=(",", ":")).encode("utf-8"),
                }
            ],
        )

        artefact_record = request["artefacts"][0]
        client = LocalProofLayerClient(signing_key_pem=self.signing_key_pem, signing_key_id=self.key_id)
        sealed = client.create_bundle(
            request["capture"],
            request["artefacts"],
            bundle_id=bundle_id,
            created_at=created_at or datetime.now(timezone.utc).isoformat(),
        )
        sealed["transcript"] = transcript
        sealed["artefacts"] = [artefact_record]
        return sealed


def verify_local_chat_bundle(bundle: dict[str, Any], transcript: list[dict[str, str]], public_key_pem: str) -> dict[str, Any]:
    computed_transcript_hash = hash_sha256(canonicalize_json(transcript))

    llm_item = next((entry for entry in bundle.get("items", []) if entry.get("type") == "llm_interaction"), None)
    if llm_item is None:
        return {"verified": False, "reason": "missing llm_interaction item"}

    chat_proof = llm_item.get("data", {}).get("parameters", {}).get("chat_proof", {})
    expected_transcript_hash = chat_proof.get("transcript_hash")
    signature_jws = chat_proof.get("session_signature", {}).get("value", "")

    transcript_hash_matches = computed_transcript_hash == expected_transcript_hash
    session_signature_valid = verify_bundle_root(signature_jws, expected_transcript_hash, public_key_pem)
    normalized_artefacts = [
        {
            "name": "transcript.json",
            "data": json.dumps(transcript, separators=(",", ":")).encode("utf-8"),
        }
    ]
    try:
        bundle_integrity = verify_bundle(bundle=bundle, artefacts=normalized_artefacts, public_key_pem=public_key_pem)
        bundle_integrity_valid = bundle_integrity.get("artefact_count", 0) == 1
    except ValueError:
        bundle_integrity_valid = False

    return {
        "verified": bool(
            transcript_hash_matches
            and session_signature_valid
            and bundle_integrity_valid
        ),
        "checks": {
            "transcript_hash_matches": transcript_hash_matches,
            "session_signature_valid": session_signature_valid,
            "bundle_signature_valid": bundle_integrity_valid,
        },
        "transcript_hash": {
            "expected": expected_transcript_hash,
            "computed": computed_transcript_hash,
        },
    }
