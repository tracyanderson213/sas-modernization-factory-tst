"""Strict contracts for offline Databricks validation-compute qualification."""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from smf.readiness.policy import digest_value

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_EVIDENCE = re.compile(r"^evidence://[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
_SECRET = re.compile(r"(?i)(?:dapi[a-z0-9]{16,}|password|secret|token|bearer|credential)")


def _safe(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SAFE.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{name} must be a safe identifier")
    if _SECRET.search(value):
        raise ValueError(f"{name} must not contain secret-shaped material")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a canonical SHA-256 digest")


def _time(name: str, value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{name} must be UTC")
    return parsed


class ComputePolicyState(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    DENIED = "denied"
    SUPERSEDED = "superseded"


class ComputeType(StrEnum):
    JOB_CLUSTER = "job_cluster"


class AccessMode(StrEnum):
    SINGLE_USER = "single_user"
    USER_ISOLATION = "user_isolation"


class AvailabilityState(StrEnum):
    AVAILABLE = "available"
    PENDING = "pending"
    DENIED = "denied"
    QUOTA_EXHAUSTED = "quota_exhausted"
    ALLOCATION_UNAVAILABLE = "allocation_unavailable"
    INCOMPATIBLE_RUNTIME = "incompatible_runtime"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


class ComputeSelectionState(StrEnum):
    SELECTED_OFFLINE = "selected_offline"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    QUOTA_EXHAUSTED = "quota_exhausted"
    ALLOCATION_UNAVAILABLE = "allocation_unavailable"
    INCOMPATIBLE_RUNTIME = "incompatible_runtime"
    INVALID_BINDING = "invalid_binding"
    EXPIRED = "expired"
    OUTCOME_UNKNOWN = "outcome_unknown"


@dataclass(frozen=True)
class ValidationComputeProfile:
    profile_id: str
    priority: int
    compute_type: ComputeType
    access_mode: AccessMode
    dbr_version: str
    spark_version: str
    scala_version: str
    jvm_version: str
    node_type: str
    min_workers: int
    max_workers: int
    max_concurrent_workloads: int
    max_cost_usd: float
    max_runtime_seconds: int
    max_retries: int
    cancellation_deadline_seconds: int
    forced_termination_deadline_seconds: int
    network_policy_id: str
    source_scope_id: str
    output_scope_id: str
    target: str
    workload_class: str
    single_workload_isolation: bool = True

    def __post_init__(self) -> None:
        for name in (
            "profile_id",
            "dbr_version",
            "spark_version",
            "scala_version",
            "jvm_version",
            "node_type",
            "network_policy_id",
            "source_scope_id",
            "output_scope_id",
            "workload_class",
        ):
            _safe(name, getattr(self, name))
        if not isinstance(self.compute_type, ComputeType) or not isinstance(
            self.access_mode, AccessMode
        ):
            raise ValueError("Unsupported compute or access mode")
        if self.target not in {"pyspark", "sparksql"}:
            raise ValueError("Unsupported compute target")
        if self.priority < 0 or self.min_workers < 1 or self.max_workers < self.min_workers:
            raise ValueError("Invalid compute priority or worker bounds")
        if self.max_concurrent_workloads < 1 or self.max_runtime_seconds < 1:
            raise ValueError("Compute quota and runtime must be positive")
        if self.max_retries < 0:
            raise ValueError("Compute retry allowance must be non-negative")
        if not math.isfinite(self.max_cost_usd) or self.max_cost_usd <= 0:
            raise ValueError("Compute cost ceiling must be finite and positive")
        if self.cancellation_deadline_seconds < 1:
            raise ValueError("Cancellation deadline must be positive")
        if self.forced_termination_deadline_seconds < self.cancellation_deadline_seconds:
            raise ValueError("Forced termination cannot precede cancellation")
        if self.single_workload_isolation is not True:
            raise ValueError("Validation compute requires single-workload isolation")

    def bindings(self) -> dict[str, Any]:
        value = asdict(self)
        value["compute_type"] = self.compute_type.value
        value["access_mode"] = self.access_mode.value
        return value

    @property
    def profile_digest(self) -> str:
        return digest_value({"contract": "smf-validation-compute-profile-v1", **self.bindings()})


@dataclass(frozen=True)
class ValidationComputePolicy:
    schema_version: str
    policy_id: str
    policy_version: str
    policy_state: ComputePolicyState
    client_id: str
    deployment_id: str
    environment_id: str
    workspace_binding_id: str
    authority_ref: str | None
    authority_key_id: str | None
    authority_signature: str | None
    valid_from: str | None
    valid_until: str | None
    supersedes_policy_digest: str | None
    owner_requirement_refs: tuple[str, ...]
    max_availability_age_seconds: int | None
    profiles: tuple[ValidationComputeProfile, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != "1.0" or not _VERSION.fullmatch(self.policy_version):
            raise ValueError("Unsupported compute policy schema or version")
        for name in (
            "policy_id",
            "client_id",
            "deployment_id",
            "environment_id",
            "workspace_binding_id",
        ):
            _safe(name, getattr(self, name))
        for name in ("authority_ref", "authority_key_id"):
            value = getattr(self, name)
            if value is not None:
                _safe(name, value)
        if not isinstance(self.policy_state, ComputePolicyState):
            raise ValueError("Unknown compute policy state")
        if (self.valid_from is None) != (self.valid_until is None):
            raise ValueError("Compute policy validity interval must be complete")
        if self.valid_from is not None and self.valid_until is not None:
            start, end = (
                _time("valid_from", self.valid_from),
                _time("valid_until", self.valid_until),
            )
            if end <= start:
                raise ValueError("Compute policy validity interval is empty")
        if self.supersedes_policy_digest is not None:
            _digest("supersedes_policy_digest", self.supersedes_policy_digest)
        if not self.owner_requirement_refs:
            raise ValueError("Compute policy requires owner requirement references")
        for ref in self.owner_requirement_refs:
            _safe("owner_requirement_ref", ref)
        if len({item.casefold() for item in self.owner_requirement_refs}) != len(
            self.owner_requirement_refs
        ):
            raise ValueError("Duplicate compute owner requirement")
        if self.max_availability_age_seconds is not None and (
            isinstance(self.max_availability_age_seconds, bool)
            or not isinstance(self.max_availability_age_seconds, int)
            or self.max_availability_age_seconds < 1
        ):
            raise ValueError("Availability maximum age must be a positive integer")
        if self.policy_state is ComputePolicyState.ACTIVE and (
            self.authority_ref is None
            or self.authority_key_id is None
            or self.authority_signature is None
            or self.valid_from is None
            or self.valid_until is None
            or self.max_availability_age_seconds is None
        ):
            raise ValueError("Active compute policy requires verified authority and validity")
        if self.policy_state is ComputePolicyState.PENDING and any(
            value is not None
            for value in (
                self.authority_ref,
                self.authority_key_id,
                self.authority_signature,
                self.valid_from,
                self.valid_until,
                self.max_availability_age_seconds,
            )
        ):
            raise ValueError(
                "Pending compute policy cannot assert authority, validity, or freshness"
            )
        if not self.profiles and self.max_availability_age_seconds is not None:
            raise ValueError(
                "Compute policy without selectable profiles must leave "
                "availability maximum age pending"
            )
        if self.policy_state is ComputePolicyState.ACTIVE and not self.profiles:
            raise ValueError("Active compute policy requires at least one bounded profile")
        ids = [item.profile_id.casefold() for item in self.profiles]
        priorities = [item.priority for item in self.profiles]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate compute profile identity")
        if len(priorities) != len(set(priorities)):
            raise ValueError("Ambiguous compute profile priority")
        _digest("policy_digest", self.policy_digest)
        if self.policy_digest != self.computed_digest:
            raise ValueError("Compute policy digest mismatch")

    def bindings(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = asdict(self)
        value["policy_state"] = self.policy_state.value
        value["profiles"] = [item.bindings() for item in self.profiles]
        value["owner_requirement_refs"] = list(self.owner_requirement_refs)
        if not include_digest:
            value.pop("policy_digest")
        return value

    @property
    def computed_digest(self) -> str:
        return digest_value(
            {"contract": "smf-validation-compute-policy-v1", **self.bindings(include_digest=False)}
        )

    def authority_bindings(self) -> dict[str, Any]:
        """Return the exact policy bytes covered by the external authority proof."""

        value = self.bindings(include_digest=False)
        value.pop("authority_signature")
        return {"contract": "smf-validation-compute-policy-authority-v1", **value}


@dataclass(frozen=True)
class ComputeAvailabilityObservation:
    schema_version: str
    observation_id: str
    authority_ref: str
    observed_at: str
    expires_at: str
    provider_version: str
    workspace_binding_id: str
    profile_id: str
    state: AvailabilityState
    quota_limit: int
    quota_used: int
    observation_digest: str
    verification_key_id: str | None = None
    verification_signature: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported availability schema_version")
        for name in (
            "observation_id",
            "authority_ref",
            "provider_version",
            "workspace_binding_id",
            "profile_id",
        ):
            _safe(name, getattr(self, name))
        if not isinstance(self.state, AvailabilityState):
            raise ValueError("Unknown compute availability state")
        observed, expires = (
            _time("observed_at", self.observed_at),
            _time("expires_at", self.expires_at),
        )
        if expires <= observed:
            raise ValueError("Availability observation validity interval is empty")
        if self.quota_limit < 0 or self.quota_used < 0 or self.quota_used > self.quota_limit:
            raise ValueError("Invalid compute quota observation")
        _digest("observation_digest", self.observation_digest)
        if self.observation_digest != self.computed_digest:
            raise ValueError("Availability observation digest mismatch")

    def bindings(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = asdict(self)
        value.pop("verification_key_id")
        value.pop("verification_signature")
        value["state"] = self.state.value
        if not include_digest:
            value.pop("observation_digest")
        return value

    @property
    def computed_digest(self) -> str:
        return digest_value(
            {"contract": "smf-compute-availability-v1", **self.bindings(include_digest=False)}
        )


@dataclass(frozen=True)
class ComputeSelectionRequest:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    workspace_binding_id: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    executable_entrypoint_id: str
    qualified_snapshot_ref: str
    source_sha256: str
    source_closure_digest: str
    generated_sha256: str
    configuration_digest: str
    bundle_digest: str
    readiness_result_id: str
    readiness_manifest_digest: str
    readiness_policy_id: str
    readiness_policy_version: str
    readiness_policy_digest: str
    readiness_activation_authority_ref: str
    readiness_manifest: dict[str, Any]
    target: str
    workload_class: str
    run_id: str
    workflow_attempt_id: str
    selection_attempt_id: str
    policy_id: str
    policy_version: str
    policy_digest: str
    policy_bytes_sha256: str
    policy_snapshot: dict[str, Any]
    observation_id: str | None
    observation_digest: str | None
    requested_profile_id: str | None = None
    evaluated_at: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != "1.0" or not _VERSION.fullmatch(self.policy_version):
            raise ValueError("Unsupported compute selection schema or policy version")
        identifiers = (
            "client_id",
            "deployment_id",
            "environment_id",
            "workspace_binding_id",
            "workload_id",
            "boundary_id",
            "subject_id",
            "executable_entrypoint_id",
            "readiness_result_id",
            "readiness_policy_id",
            "readiness_policy_version",
            "readiness_activation_authority_ref",
            "workload_class",
            "run_id",
            "workflow_attempt_id",
            "selection_attempt_id",
            "policy_id",
        )
        for name in identifiers:
            _safe(name, getattr(self, name))
        if self.observation_id is not None:
            _safe("observation_id", self.observation_id)
        if self.requested_profile_id is not None:
            _safe("requested_profile_id", self.requested_profile_id)
        for name in (
            "workload_digest",
            "source_sha256",
            "source_closure_digest",
            "generated_sha256",
            "configuration_digest",
            "bundle_digest",
            "readiness_manifest_digest",
            "readiness_policy_digest",
            "policy_digest",
            "policy_bytes_sha256",
        ):
            _digest(name, getattr(self, name))
        if self.observation_digest is not None:
            _digest("observation_digest", self.observation_digest)
        if (
            not _EVIDENCE.fullmatch(self.qualified_snapshot_ref)
            or ".." in self.qualified_snapshot_ref
        ):
            raise ValueError("qualified_snapshot_ref must be a bounded evidence reference")
        if self.target not in {"pyspark", "sparksql"}:
            raise ValueError("Unsupported compute selection target")
        _time("evaluated_at", self.evaluated_at)
        identity_group = [
            self.workload_id,
            self.boundary_id,
            self.subject_id,
            self.executable_entrypoint_id,
        ]
        if len({item.casefold() for item in identity_group}) != len(identity_group):
            raise ValueError("Duplicate canonical compute subject identity")

    def bindings(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def request_digest(self) -> str:
        return digest_value({"contract": "smf-compute-selection-request-v1", **self.bindings()})

    @property
    def selection_request_id(self) -> str:
        return "dcs-" + self.request_digest

    @property
    def decision_id(self) -> str:
        return "dcd-" + digest_value(
            {"contract": "smf-compute-selection-decision-v1", "request": self.bindings()}
        )


@dataclass(frozen=True)
class ComputeSelectionResult:
    schema_version: str
    request: dict[str, Any]
    request_digest: str
    selection_request_id: str
    selection_attempt_id: str
    decision_id: str
    state: ComputeSelectionState
    reason_code: str
    selected_profile_id: str | None
    effective_profile: dict[str, Any] | None
    effective_profile_digest: str | None
    evaluated_at: str
    availability_observation: dict[str, Any] | None
    availability_proof: dict[str, str] | None
    evidence_refs: tuple[str, ...]
    retryable: bool = False
    generated: bool = True
    allocated: bool = False
    submitted: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    human_assisted: bool = False
    blocked: bool = True
    certified: bool = False
    human_approved: bool = False
    content_digest: str = field(default="")

    def __post_init__(self) -> None:
        selected = self.state is ComputeSelectionState.SELECTED_OFFLINE
        if selected != (self.selected_profile_id is not None):
            raise ValueError("Compute selection profile contradicts state")
        if selected != (
            self.effective_profile is not None and self.effective_profile_digest is not None
        ):
            raise ValueError("Compute selection evidence contradicts state")
        if self.blocked is selected:
            raise ValueError("Compute selection blocked claim contradicts state")
        if any(
            (
                self.allocated,
                self.submitted,
                self.executed,
                self.validated,
                self.parity_passed,
                self.certified,
                self.human_approved,
            )
        ):
            raise ValueError("Offline compute qualification cannot assert downstream success")
        if selected and self.effective_profile_digest != digest_value(
            {"contract": "smf-validation-compute-profile-v1", **(self.effective_profile or {})}
        ):
            raise ValueError("Effective compute profile digest mismatch")
        untrusted_without_proof = (
            self.state is ComputeSelectionState.INVALID_BINDING
            and self.reason_code == "availability_untrusted"
            and self.availability_observation is not None
            and self.availability_proof is None
        )
        if (self.availability_observation is None) != (
            self.availability_proof is None
        ) and not untrusted_without_proof:
            raise ValueError("Availability observation and proof must be persisted together")
        _time("evaluated_at", self.evaluated_at)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized
