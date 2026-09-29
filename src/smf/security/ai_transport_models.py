"""Strict, provider-neutral contracts for governed AI transport."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, SupportsIndex

from smf.security.ai_policy import canonical_ai_json

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF = re.compile(r"^evidence://[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
_PROTECTED = re.compile(
    r"(?i)(?:\d{3}-\d{2}-\d{4}|(?:ssn|mrn|member|patient|password|passwd|secret|token|"
    r"api[-_]?key)[._:-][A-Za-z0-9])"
)


class AITransportState(StrEnum):
    PREPARED = "prepared"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    INVALID_BINDING = "invalid_binding"
    REDIRECT_REJECTED = "redirect_rejected"
    TRANSPORT_FAILED = "transport_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"
    RESPONSE_RECEIVED = "response_received"


class AITransportCancelled(Exception):
    """Categorical cancellation signal accepted from a transport sender."""


def _safe(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or _PROTECTED.search(value):
        raise ValueError(f"{label} must be a safe non-protected identifier")


@dataclass(frozen=True)
class AITransportRequest:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    source_closure_digest: str
    permitted_artifact_ids: tuple[str, ...]
    run_id: str
    workflow_attempt_id: str
    provider_request_id: str
    transport_attempt_id: str
    retry_ordinal: int
    consumer_id: str
    consumer_contract_version: str
    provider_id: str
    model_id: str
    endpoint_binding_id: str
    strategy_version: str
    sec02_decision_id: str
    sec02_result_digest: str
    sec02_result_ref: str
    context_digest: str
    context_byte_count: int
    readiness_result_id: str
    readiness_manifest_digest: str
    classification_evidence_id: str
    classification_decision_id: str
    transport_policy_id: str
    transport_policy_version: str
    transport_policy_digest: str
    endpoint_binding_digest: str
    endpoint_binding_ref: str
    identity_binding_id: str
    identity_evidence_id: str
    identity_evidence_digest: str
    credential_resolution_id: str
    credential_evidence_id: str
    credential_evidence_digest: str
    payload_classification_evidence_id: str
    payload_classification_evidence_digest: str
    payload_digest: str
    payload_byte_count: int
    media_type: str
    method: str
    submission_evidence_id: str
    submission_evidence_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported AI transport request contract")
        for name, value in asdict(self).items():
            if name == "permitted_artifact_ids":
                if not value or len({item.casefold() for item in value}) != len(value):
                    raise ValueError("permitted_artifact_ids must be non-empty and unambiguous")
                for item in value:
                    _safe(item, name)
            elif name.endswith("digest"):
                if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                    raise ValueError(f"{name} must be a canonical SHA-256 digest")
            elif name.endswith("_ref"):
                if (
                    not isinstance(value, str)
                    or not _SAFE_REF.fullmatch(value)
                    or ".." in value
                    or _PROTECTED.search(value)
                ):
                    raise ValueError(f"{name} must be a safe evidence reference")
            elif name in {"retry_ordinal", "context_byte_count", "payload_byte_count"}:
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
            elif name == "method":
                if value != "POST":
                    raise ValueError("Only POST transport is supported")
            elif name == "media_type":
                if value != "application/json":
                    raise ValueError("Only application/json transport is supported")
            else:
                _safe(value, name)
        if self.context_byte_count < 1 or self.payload_byte_count < 1:
            raise ValueError("AI transport requires non-empty context and payload")
        object.__setattr__(self, "permitted_artifact_ids", tuple(self.permitted_artifact_ids))

    def bindings(self) -> dict[str, Any]:
        value = json.loads(json.dumps(asdict(self)))
        assert isinstance(value, dict)
        return value

    def evidence_bindings(self, evidence_kind: str) -> dict[str, Any]:
        """Return the exact request projection without the evidence's self-digest."""

        value = self.bindings()
        if evidence_kind not in {
            "submission",
            "identity_binding",
            "credential_resolution",
            "payload_classification",
        }:
            raise ValueError("Unsupported transport evidence kind")
        # These three independently signed records are peers. Omitting only the record's
        # own digest would create circular cross-digests and make issuance impossible.
        for field in (
            "submission_evidence_digest",
            "identity_evidence_digest",
            "credential_evidence_digest",
            "payload_classification_evidence_digest",
        ):
            value.pop(field)
        return value

    @property
    def request_digest(self) -> str:
        return hashlib.sha256(canonical_ai_json(self.bindings())).hexdigest()


class TransientAIBytes:
    """Non-copyable byte buffer cleared by the transport guard."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes | bytearray) -> None:
        if not value:
            raise ValueError("Transient transport bytes cannot be empty")
        self._value = bytearray(value)

    @property
    def value(self) -> bytes:
        return bytes(self._value)

    def clear(self) -> None:
        self._value[:] = b"\x00" * len(self._value)

    def __repr__(self) -> str:
        return "TransientAIBytes(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Transient AI bytes cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Transient AI bytes cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Transient AI bytes cannot be serialized")


@dataclass(frozen=True)
class AITransportResponse:
    status_code: int
    body: bytes
    media_type: str
    redirect_location: str | None = None


@dataclass(frozen=True)
class AITransportResult:
    schema_version: str
    decision_id: str
    request: dict[str, Any]
    state: AITransportState
    blocker_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    response_status: int | None
    response_digest: str | None
    response_byte_count: int | None
    elapsed_ms: int
    context_qualified: bool
    submission_authorized: bool
    transport_attempted: bool
    response_received: bool
    generated: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    certified: bool = False
    human_approved: bool = False
    human_assisted: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized
