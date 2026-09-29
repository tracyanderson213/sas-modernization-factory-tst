"""Provider-neutral models for offline AI-context qualification."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, SupportsIndex

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROTECTED_IDENTIFIER = re.compile(
    r"(?i)(?:\d{3}-\d{2}-\d{4}|(?:ssn|mrn|member|patient|password|passwd|secret|token|apikey|api-key)[._-][A-Za-z0-9])"
)


class AIAdmissionState(StrEnum):
    QUALIFIED_OFFLINE = "qualified_offline"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    BLOCKED_AMBIGUOUS = "blocked_ambiguous"
    INVALID_BINDING = "invalid_binding"


@dataclass(frozen=True)
class AIContextRequest:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    source_closure_digest: str
    run_id: str
    attempt_id: str
    consumer_id: str
    consumer_contract_version: str
    strategy_version: str
    readiness_result_id: str
    readiness_manifest_digest: str
    context_policy_id: str
    context_policy_version: str
    context_policy_digest: str
    classification_policy_id: str
    classification_policy_version: str
    classification_policy_digest: str
    provider_id: str
    model_id: str
    endpoint_binding_id: str
    retention_policy_ref: str
    access_policy_ref: str
    classification_evidence_id: str
    classification_evidence_digest: str
    requested_artifact_ids: tuple[str, ...]
    requested_fields: tuple[str, ...]
    decision_purpose: str = "offline_ai_context_qualification"

    def __post_init__(self) -> None:
        if (
            self.schema_version != "1.0"
            or self.decision_purpose != "offline_ai_context_qualification"
        ):
            raise ValueError("Unsupported AI context request contract")
        for name, value in asdict(self).items():
            if name in {"requested_artifact_ids", "requested_fields"}:
                if not value or len({item.casefold() for item in value}) != len(value):
                    raise ValueError(f"{name} must be non-empty and case-unambiguous")
                if any(not _SAFE_ID.fullmatch(item) for item in value):
                    raise ValueError(f"{name} contains an unsafe identifier")
                if any(_PROTECTED_IDENTIFIER.search(item) for item in value):
                    raise ValueError(f"{name} contains protected data")
            elif name.endswith("digest"):
                if not isinstance(value, str) or not _SHA256.fullmatch(value):
                    raise ValueError(f"{name} must be a canonical SHA-256 digest")
            elif not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise ValueError(f"{name} must be a safe non-empty identifier")
            elif _PROTECTED_IDENTIFIER.search(value):
                raise ValueError(f"{name} contains protected data")

    def safe_bindings(self) -> dict[str, Any]:
        value = json.loads(json.dumps(asdict(self)))
        assert isinstance(value, dict)
        return value


@dataclass(frozen=True)
class AIContextAdmissionResult:
    schema_version: str
    decision_id: str
    request: dict[str, Any]
    state: AIAdmissionState
    blocker_codes: tuple[str, ...]
    checks: tuple[dict[str, str], ...]
    evidence_refs: tuple[str, ...]
    permitted_artifact_ids: tuple[str, ...]
    permitted_fields: tuple[str, ...]
    context_digest: str | None
    context_byte_count: int | None
    terminal_disposition: str
    context_qualified: bool
    transport_attempted: bool = False
    submission_authorized: bool = False
    generated: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    certified: bool = False
    human_approved: bool = False
    human_assisted: bool = False
    content_digest: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized


class QualifiedAIContext:
    """Transient qualified bytes; deliberately not serializable or copyable."""

    __slots__ = ("_value", "_decision_id", "_digest")

    def __init__(self, value: bytearray, decision_id: str, digest: str) -> None:
        if not value or not _SAFE_ID.fullmatch(decision_id) or not _SHA256.fullmatch(digest):
            raise ValueError("Qualified AI context is invalid")
        self._value = bytearray(value)
        self._decision_id = decision_id
        self._digest = digest

    @property
    def value(self) -> bytes:
        return bytes(self._value)

    @property
    def decision_id(self) -> str:
        return self._decision_id

    @property
    def digest(self) -> str:
        return self._digest

    def clear(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0

    def __repr__(self) -> str:
        return f"QualifiedAIContext(value=<redacted>, decision_id={self.decision_id!r})"

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Qualified AI context cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Qualified AI context cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Qualified AI context cannot be serialized")


@dataclass(frozen=True)
class AIAdmissionOutcome:
    result: AIContextAdmissionResult
    context: QualifiedAIContext | None
