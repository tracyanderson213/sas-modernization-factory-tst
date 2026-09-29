"""Trusted prerequisite verification for governed provider attempts."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.ai.models import AIProviderRequest, AIProviderState
from smf.security.ai_manifest import load_ai_context_result
from smf.security.ai_policy import canonical_ai_json
from smf.security.schema import validate_security_schema

_SLOTS = {
    "prompt_policy": ("prompt_policy_ref", "prompt_policy_digest"),
    "prompt_template": ("prompt_template_ref", "prompt_template_digest"),
    "transport_policy": ("transport_policy_ref", "transport_policy_digest"),
    "configuration": ("configuration_ref", "configuration_digest"),
    "retention_policy": ("retention_policy_ref", "retention_policy_digest"),
    "access_policy": ("access_policy_ref", "access_policy_digest"),
}


@dataclass(frozen=True)
class AIProviderPrerequisites:
    """Untrusted locations of evidence to verify before provider invocation."""

    sec02_result_path: Path
    evidence_paths: Mapping[str, Path]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_paths", MappingProxyType(dict(self.evidence_paths)))


@dataclass(frozen=True)
class AIProviderVerifierConfiguration:
    """Governed trust roots configured independently of prerequisite evidence."""

    sec02_keys: Mapping[str, Ed25519PublicKey]
    authority_keys: Mapping[str, Ed25519PublicKey]

    def __post_init__(self) -> None:
        object.__setattr__(self, "sec02_keys", MappingProxyType(dict(self.sec02_keys)))
        object.__setattr__(self, "authority_keys", MappingProxyType(dict(self.authority_keys)))


@dataclass(frozen=True)
class PrerequisiteVerification:
    state: AIProviderState | None
    blocker_code: str | None
    evidence_refs: tuple[str, ...]
    snapshots: tuple[bytes, ...]


def _read_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid AI provider prerequisite evidence") from exc
    if not isinstance(payload, dict):
        raise ValueError("AI provider prerequisite evidence must be an object")
    return payload, bytes(raw)


def _verify_proof(
    payload: dict[str, Any], verification_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("AI provider prerequisite lacks trusted proof")
    key_id = proof.get("key_id")
    if (
        proof.get("algorithm") != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in verification_keys
    ):
        raise ValueError("AI provider prerequisite proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    try:
        signature = base64.b64decode(proof.get("value", ""), validate=True)
        verification_keys[key_id].verify(signature, canonical_ai_json(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("AI provider prerequisite proof is invalid") from exc


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("AI provider prerequisite timestamp lacks timezone")
    return parsed.astimezone(UTC)


def _sec02_bindings_valid(request: AIProviderRequest, payload: dict[str, Any]) -> bool:
    binding = payload["request"]
    expected = {
        "client_id": request.client_id,
        "deployment_id": request.deployment_id,
        "environment_id": request.environment_id,
        "workload_id": request.workload_id,
        "workload_digest": request.workload_digest,
        "boundary_id": request.boundary_id,
        "subject_id": request.subject_id,
        "source_closure_digest": request.source_closure_digest,
        "run_id": request.run_id,
        "attempt_id": request.workflow_attempt_id,
        "provider_id": request.provider_id,
        "model_id": request.model_id,
        "endpoint_binding_id": request.endpoint_binding_id,
    }
    return (
        payload["state"] == "qualified_offline"
        and payload["decision_id"] == request.sec02_decision_id
        and payload["content_digest"] == request.sec02_result_digest
        and payload["context_digest"] == request.context_digest
        and payload["context_byte_count"] == request.context_byte_count
        and payload["permitted_artifact_ids"] == list(request.source_artifact_ids)
        and all(binding.get(name) == value for name, value in expected.items())
    )


def verify_provider_prerequisites(
    request: AIProviderRequest,
    prerequisites: AIProviderPrerequisites | None,
    *,
    verifier_configuration: AIProviderVerifierConfiguration | None = None,
    now: datetime | None = None,
) -> PrerequisiteVerification:
    """Authenticate every prerequisite and bind it to this exact request."""

    refs = (
        request.sec02_result_ref,
        request.prompt_policy_ref,
        request.prompt_template_ref,
        request.transport_policy_ref,
        request.configuration_ref,
        request.retention_policy_ref,
        request.access_policy_ref,
    )
    if prerequisites is None or verifier_configuration is None:
        return PrerequisiteVerification(
            AIProviderState.BLOCKED_MISSING,
            "trusted_prerequisites_unavailable",
            refs,
            (),
        )
    if set(prerequisites.evidence_paths) != set(_SLOTS):
        return PrerequisiteVerification(
            AIProviderState.BLOCKED_MISSING,
            "trusted_prerequisites_unavailable",
            refs,
            (),
        )

    current = (now or datetime.now(UTC)).astimezone(UTC)
    snapshots: list[bytes] = []
    try:
        sec02_raw = prerequisites.sec02_result_path.read_bytes()
        sec02 = load_ai_context_result(
            prerequisites.sec02_result_path,
            verification_keys=verifier_configuration.sec02_keys,
        )
        if not _sec02_bindings_valid(request, sec02):
            raise ValueError("SEC-02 result binding mismatch")
        snapshots.append(bytes(sec02_raw))

        for kind, (ref_field, digest_field) in _SLOTS.items():
            payload, snapshot = _read_object(prerequisites.evidence_paths[kind])
            validate_security_schema("ai-provider-prerequisite.schema.json", payload)
            _verify_proof(payload, verifier_configuration.authority_keys)
            if (
                payload["kind"] != kind
                or payload["evidence_ref"] != getattr(request, ref_field)
                or payload["evidence_digest"] != getattr(request, digest_field)
                or payload["request_digest"] != request.request_digest
            ):
                raise ValueError("AI provider prerequisite binding mismatch")
            if _parse_timestamp(payload["issued_at"]) > current:
                raise ValueError("AI provider prerequisite is not yet effective")
            if current >= _parse_timestamp(payload["expires_at"]):
                return PrerequisiteVerification(
                    AIProviderState.INVALID_BINDING,
                    "trusted_prerequisite_expired",
                    refs,
                    tuple(snapshots),
                )
            if payload["state"] == "pending":
                return PrerequisiteVerification(
                    AIProviderState.BLOCKED_PENDING,
                    "trusted_prerequisite_pending",
                    refs,
                    tuple(snapshots),
                )
            if payload["state"] == "denied":
                return PrerequisiteVerification(
                    AIProviderState.DENIED,
                    "trusted_prerequisite_denied",
                    refs,
                    tuple(snapshots),
                )
            snapshots.append(snapshot)
    except FileNotFoundError:
        return PrerequisiteVerification(
            AIProviderState.BLOCKED_MISSING,
            "trusted_prerequisites_unavailable",
            refs,
            tuple(snapshots),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return PrerequisiteVerification(
            AIProviderState.INVALID_BINDING,
            "trusted_prerequisite_invalid",
            refs,
            tuple(snapshots),
        )
    return PrerequisiteVerification(None, None, refs, tuple(snapshots))
