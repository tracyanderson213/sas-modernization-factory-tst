"""Strict, credential-free contracts for governed Databricks authentication."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from smf.readiness.policy import digest_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_SHAPED = re.compile(
    r"(?i)(?:^dapi[a-z0-9]{16,}$|(?:^|[-_.])(?:bearer|credential|password|secret|token)(?:[-_.]|$))"
)


def _safe_id(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{name} must be a safe non-empty identifier")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a canonical SHA-256 digest")


def _opaque_reference(name: str, value: str) -> None:
    _safe_id(name, value)
    if _SECRET_SHAPED.search(value):
        raise ValueError(f"{name} must be an opaque non-secret reference")


def canonical_workspace_origin(value: str) -> str:
    """Return one canonical HTTPS workspace origin, rejecting fallback-friendly URLs."""

    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("workspace_origin must be a canonical HTTPS origin")
    if parsed.port not in {None, 443}:
        raise ValueError("workspace_origin must use the canonical HTTPS port")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "127.0.0.1", "::1"} or "." not in hostname:
        raise ValueError("workspace_origin must identify an enterprise workspace")
    return f"https://{hostname}"


class DatabricksAuthenticationState(StrEnum):
    VERIFIED = "verified"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    EXPIRED = "expired"
    INVALID_BINDING = "invalid_binding"
    WRONG_WORKSPACE = "wrong_workspace"
    WRONG_IDENTITY = "wrong_identity"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"


class PermissionKind(StrEnum):
    WORKSPACE_ACCESS = "workspace_access"
    CATALOG_USE = "catalog_use"
    SCHEMA_USE = "schema_use"
    SOURCE_READ = "source_read"
    OUTPUT_WRITE = "output_write"


class PermissionResult(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


@dataclass(frozen=True)
class DatabricksPermissionProbe:
    probe_id: str
    kind: PermissionKind
    resource_binding_id: str

    def __post_init__(self) -> None:
        _safe_id("probe_id", self.probe_id)
        _safe_id("resource_binding_id", self.resource_binding_id)
        if not isinstance(self.kind, PermissionKind):
            raise ValueError("Unsupported permission kind")


@dataclass(frozen=True)
class DatabricksPermissionObservation:
    probe_id: str
    resource_binding_id: str
    result: PermissionResult

    def __post_init__(self) -> None:
        _safe_id("probe_id", self.probe_id)
        _safe_id("resource_binding_id", self.resource_binding_id)
        if not isinstance(self.result, PermissionResult):
            raise ValueError("Unsupported permission result")


@dataclass(frozen=True)
class DatabricksAuthenticationRequest:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    configuration_digest: str
    bundle_digest: str
    workspace_binding_id: str
    workspace_origin: str
    identity_binding_id: str
    expected_principal_ref: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    qualified_snapshot_ref: str
    source_sha256: str
    generated_sha256: str
    source_closure_digest: str
    target: str
    run_id: str
    workflow_attempt_id: str
    authentication_attempt_id: str
    retry_ordinal: int
    readiness_result_id: str
    readiness_manifest_digest: str
    readiness_policy_id: str
    readiness_policy_version: str
    readiness_policy_digest: str
    security_policy_id: str
    security_policy_version: str
    security_policy_digest: str
    permission_policy_digest: str
    activation_evidence_id: str
    activation_evidence_digest: str
    secret_resolution_id: str
    secret_resolution_digest: str
    secret_binding_id: str
    consumer_id: str
    consumer_contract_version: str
    provider_version: str
    adapter_version: str
    permission_probes: tuple[DatabricksPermissionProbe, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("Unsupported Databricks authentication schema_version")
        identifiers = (
            "client_id",
            "deployment_id",
            "environment_id",
            "workspace_binding_id",
            "identity_binding_id",
            "workload_id",
            "boundary_id",
            "subject_id",
            "run_id",
            "workflow_attempt_id",
            "authentication_attempt_id",
            "readiness_result_id",
            "readiness_policy_id",
            "readiness_policy_version",
            "security_policy_id",
            "security_policy_version",
            "activation_evidence_id",
            "secret_resolution_id",
            "secret_binding_id",
            "consumer_id",
            "consumer_contract_version",
            "provider_version",
            "adapter_version",
        )
        for name in identifiers:
            _safe_id(name, getattr(self, name))
        _opaque_reference("expected_principal_ref", self.expected_principal_ref)
        for name in (
            "configuration_digest",
            "bundle_digest",
            "workload_digest",
            "source_sha256",
            "generated_sha256",
            "source_closure_digest",
            "readiness_manifest_digest",
            "readiness_policy_digest",
            "security_policy_digest",
            "permission_policy_digest",
            "activation_evidence_digest",
            "secret_resolution_digest",
        ):
            _digest(name, getattr(self, name))
        if canonical_workspace_origin(self.workspace_origin) != self.workspace_origin:
            raise ValueError("workspace_origin is not canonical")
        if not self.qualified_snapshot_ref.startswith("evidence://"):
            raise ValueError("qualified_snapshot_ref must be an evidence reference")
        if self.target not in {"pyspark", "sparksql"}:
            raise ValueError("Unsupported Databricks target")
        if self.retry_ordinal < 0:
            raise ValueError("retry_ordinal must be non-negative")
        probe_ids = [probe.probe_id.casefold() for probe in self.permission_probes]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("Duplicate permission probe identity")
        resource_ids = [probe.resource_binding_id.casefold() for probe in self.permission_probes]
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("Duplicate permission resource binding identity")
        observed_kinds = {probe.kind for probe in self.permission_probes}
        if observed_kinds != set(PermissionKind) or len(self.permission_probes) != len(
            PermissionKind
        ):
            raise ValueError("Authentication requires the complete configured permission set")
        expected_permission_digest = digest_value(
            {
                "contract": "smf-databricks-permission-policy-v1",
                "probes": [
                    {
                        "probe_id": probe.probe_id,
                        "kind": probe.kind.value,
                        "resource_binding_id": probe.resource_binding_id,
                    }
                    for probe in self.permission_probes
                ],
            }
        )
        if self.permission_policy_digest != expected_permission_digest:
            raise ValueError("permission_policy_digest does not bind the configured permission set")
        binding_ids = [
            self.workspace_binding_id.casefold(),
            self.identity_binding_id.casefold(),
            self.secret_binding_id.casefold(),
        ]
        if len(binding_ids) != len(set(binding_ids)):
            raise ValueError("Duplicate Databricks authentication binding identity")
        evidence_ids = [
            self.readiness_result_id.casefold(),
            self.activation_evidence_id.casefold(),
            self.secret_resolution_id.casefold(),
        ]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Duplicate Databricks authentication evidence identity")

    def bindings(self) -> dict[str, Any]:
        value = asdict(self)
        value["permission_probes"] = [
            {**asdict(probe), "kind": probe.kind.value} for probe in self.permission_probes
        ]
        return value

    @property
    def request_digest(self) -> str:
        return digest_value({"contract": "smf-databricks-auth-request-v1", **self.bindings()})

    @property
    def authentication_request_id(self) -> str:
        return "dba-" + self.request_digest

    @property
    def decision_id(self) -> str:
        return "dbd-" + digest_value(
            {"contract": "smf-databricks-auth-decision-v1", "request": self.bindings()}
        )


@dataclass(frozen=True)
class DatabricksAuthenticationResponse:
    workspace_origin: str
    principal_ref: str
    observations: tuple[DatabricksPermissionObservation, ...]
    provider_request_id: str
    provider_version: str
    adapter_version: str

    def __post_init__(self) -> None:
        if canonical_workspace_origin(self.workspace_origin) != self.workspace_origin:
            raise ValueError("Transport workspace_origin is not canonical")
        for name in ("principal_ref", "provider_request_id", "provider_version", "adapter_version"):
            _safe_id(name, getattr(self, name))
        ids = [item.probe_id.casefold() for item in self.observations]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate permission observation")


@dataclass(frozen=True)
class DatabricksAuthenticationResult:
    schema_version: str
    request: dict[str, Any]
    request_digest: str
    authentication_request_id: str
    authentication_attempt_id: str
    decision_id: str
    state: DatabricksAuthenticationState
    reason_code: str
    transport_attempted: bool
    workspace_verified: bool
    identity_verified: bool
    permissions_verified: bool
    provider_request_id: str | None
    elapsed_ms: int
    retryable: bool
    evidence_refs: tuple[str, ...]
    generated: bool = True
    authenticated: bool = False
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
        verified = self.state is DatabricksAuthenticationState.VERIFIED
        if self.authenticated is not verified or self.blocked is verified:
            raise ValueError("Authentication lifecycle claims contradict state")
        if any(
            (
                self.submitted,
                self.executed,
                self.validated,
                self.parity_passed,
                self.certified,
                self.human_approved,
            )
        ):
            raise ValueError("Authentication evidence cannot assert downstream success")
        if verified and not all(
            (
                self.transport_attempted,
                self.workspace_verified,
                self.identity_verified,
                self.permissions_verified,
                self.provider_request_id,
            )
        ):
            raise ValueError("Verified authentication lacks reconstructable probe evidence")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized
