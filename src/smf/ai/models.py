"""Strict provider-neutral contracts for bounded AI invocations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, SupportsIndex

from smf.security.ai_admission import contains_protected_data
from smf.security.ai_policy import canonical_ai_json

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF = re.compile(r"^evidence://[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")


class AIOperation(StrEnum):
    CONVERT = "convert"
    REMEDIATE = "remediate"


class AITarget(StrEnum):
    DATABRICKS_PYSPARK = "databricks_pyspark"
    DATABRICKS_SQL = "databricks_sql"


class AIConfigurationState(StrEnum):
    VERIFIED = "verified"
    MISSING = "missing"
    PENDING = "pending"
    DENIED = "denied"


class AIFinishReason(StrEnum):
    STOP = "stop"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    REFUSAL = "refusal"


class AIProviderState(StrEnum):
    SUCCEEDED = "succeeded"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    INVALID_BINDING = "invalid_binding"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"


class AIEvidenceClass(StrEnum):
    SYNTHETIC_CONTRACT = "synthetic_contract"
    OPERATIONAL_VERIFIED = "operational_verified"


def _safe_id(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or contains_protected_data(value)
    ):
        raise ValueError(f"{label} must be a safe non-protected identifier")


def _safe_ref(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not _SAFE_REF.fullmatch(value)
        or ".." in value
        or contains_protected_data(value)
    ):
        raise ValueError(f"{label} must be a safe evidence reference")


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a canonical SHA-256 digest")


@dataclass(frozen=True)
class AdvisoryEvidenceReference:
    evidence_ref: str
    origin_id: str
    applicability_id: str
    version: str
    selection_reason_id: str
    client_id: str
    source_digest: str
    policy_digest: str
    conflict_disposition: str

    def __post_init__(self) -> None:
        _safe_ref(self.evidence_ref, "advisory evidence_ref")
        for name in (
            "origin_id",
            "applicability_id",
            "version",
            "selection_reason_id",
            "client_id",
        ):
            _safe_id(getattr(self, name), f"advisory {name}")
        _digest(self.source_digest, "advisory source_digest")
        _digest(self.policy_digest, "advisory policy_digest")
        if self.conflict_disposition not in {"none", "resolved", "unresolved", "rejected"}:
            raise ValueError("Unsupported advisory conflict disposition")


@dataclass(frozen=True)
class AIProviderRequest:
    schema_version: str
    operation: AIOperation
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    source_closure_digest: str
    source_artifact_ids: tuple[str, ...]
    run_id: str
    workflow_attempt_id: str
    provider_request_id: str
    provider_attempt_id: str
    retry_ordinal: int
    target: AITarget
    consumer_id: str
    consumer_contract_version: str
    strategy_id: str
    strategy_version: str
    strategy_digest: str
    provider_id: str
    model_id: str
    endpoint_binding_id: str
    sec02_decision_id: str
    sec02_result_ref: str
    sec02_result_digest: str
    context_digest: str
    context_byte_count: int
    prompt_policy_ref: str
    prompt_policy_digest: str
    prompt_template_ref: str
    prompt_template_digest: str
    transport_policy_ref: str
    transport_policy_digest: str
    configuration_ref: str
    configuration_digest: str
    configuration_state: AIConfigurationState
    retention_policy_ref: str
    retention_policy_digest: str
    access_policy_ref: str
    access_policy_digest: str
    advisory_evidence: tuple[AdvisoryEvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported AI provider request contract")
        if not isinstance(self.operation, AIOperation) or not isinstance(self.target, AITarget):
            raise ValueError("AI provider operation and target must use strict enums")
        if not isinstance(self.configuration_state, AIConfigurationState):
            raise ValueError("AI provider configuration state must use a strict enum")
        values = asdict(self)
        for name, value in values.items():
            if name in {"operation", "target", "configuration_state", "advisory_evidence"}:
                continue
            if name == "source_artifact_ids":
                if not value or len({item.casefold() for item in value}) != len(value):
                    raise ValueError("source_artifact_ids must be non-empty and unambiguous")
                for item in value:
                    _safe_id(item, name)
            elif name.endswith("_digest"):
                _digest(value, name)
            elif name.endswith("_ref"):
                _safe_ref(value, name)
            elif name in {"retry_ordinal", "context_byte_count"}:
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"{name} must be a non-negative integer")
            else:
                _safe_id(value, name)
        if self.context_byte_count < 1:
            raise ValueError("AI provider context must not be empty")
        advisory_keys = [item.evidence_ref.casefold() for item in self.advisory_evidence]
        if len(set(advisory_keys)) != len(advisory_keys):
            raise ValueError("advisory_evidence contains duplicate references")
        for item in self.advisory_evidence:
            if (
                item.client_id != self.client_id
                or item.source_digest != self.source_closure_digest
                or item.policy_digest != self.prompt_policy_digest
            ):
                raise ValueError("Advisory evidence crosses the request boundary")
        object.__setattr__(self, "source_artifact_ids", tuple(self.source_artifact_ids))
        object.__setattr__(self, "advisory_evidence", tuple(self.advisory_evidence))

    def bindings(self) -> dict[str, Any]:
        value = asdict(self)
        value["operation"] = self.operation.value
        value["target"] = self.target.value
        value["configuration_state"] = self.configuration_state.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized

    @property
    def request_digest(self) -> str:
        return hashlib.sha256(canonical_ai_json(self.bindings())).hexdigest()


class TransientAIProviderBytes:
    """Immutable-view, non-copyable and non-serializable transient bytes."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes | bytearray) -> None:
        if not value:
            raise ValueError("Transient AI provider bytes cannot be empty")
        self._value = bytearray(bytes(value))

    @property
    def value(self) -> bytes:
        return bytes(self._value)

    def clear(self) -> None:
        self._value[:] = b"\x00" * len(self._value)

    def __repr__(self) -> str:
        return "TransientAIProviderBytes(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Transient AI provider bytes cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Transient AI provider bytes cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Transient AI provider bytes cannot be serialized")


@dataclass(frozen=True)
class AIProviderResponse:
    content: bytes
    finish_reason: AIFinishReason
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise ValueError("AI provider response content must be bytes")
        if not isinstance(self.finish_reason, AIFinishReason):
            raise ValueError("AI provider finish reason must use a strict enum")
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class AIProviderResult:
    schema_version: str
    decision_id: str
    request: dict[str, Any]
    state: AIProviderState
    blocker_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    evidence_class: AIEvidenceClass
    response_digest: str | None
    response_byte_count: int | None
    finish_reason: AIFinishReason | None
    input_tokens: int
    output_tokens: int
    elapsed_ms: int
    provider_invoked: bool
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
        value["evidence_class"] = self.evidence_class.value
        value["finish_reason"] = self.finish_reason.value if self.finish_reason else None
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized


@dataclass(frozen=True)
class AIProviderOutcome:
    result: AIProviderResult
    output: TransientAIProviderBytes | None
