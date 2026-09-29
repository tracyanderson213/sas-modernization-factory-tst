"""Provider-neutral models for workload identity and secret resolution."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, SupportsIndex

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BindingStatus(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    DENIED = "denied"


class ResolutionState(StrEnum):
    RESOLVED = "resolved"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    EXPIRED = "expired"
    INVALID_BINDING = "invalid_binding"
    AUTHENTICATION_FAILED = "authentication_failed"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ReasonCode(StrEnum):
    RESOLVED = "resolved"
    CONFIGURATION_MISSING = "configuration_missing"
    CONFIGURATION_INVALID = "configuration_invalid"
    CONFIGURATION_PENDING = "configuration_pending"
    APPROVAL_MISSING = "approval_missing"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_EXPIRED = "approval_expired"
    ACTIVATION_INVALID = "activation_invalid"
    BINDING_MISMATCH = "binding_mismatch"
    IDENTITY_REJECTED = "identity_rejected"
    VAULT_DENIED = "vault_denied"
    CREDENTIAL_DISABLED = "credential_disabled"
    CREDENTIAL_EXPIRED = "credential_expired"
    LEASE_INVALID = "lease_invalid"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TRANSPORT_TIMEOUT = "transport_timeout"
    CANCELLED = "cancelled"
    MALFORMED_RESPONSE = "malformed_response"


@dataclass(frozen=True)
class SecretResolutionRequest:
    schema_version: str
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    workload_digest: str
    boundary_id: str
    subject_id: str
    source_sha256: str
    run_id: str
    attempt_id: str
    consumer_id: str
    consumer_contract_version: str
    identity_binding_id: str
    secret_binding_id: str
    security_policy_id: str
    security_policy_version: str
    security_policy_digest: str
    configuration_digest: str
    readiness_result_id: str
    readiness_manifest_digest: str
    qualified_snapshot_ref: str
    activation_evidence_id: str
    activation_evidence_digest: str

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name.endswith("digest") or name.endswith("sha256"):
                if not isinstance(value, str) or not _SHA256.fullmatch(value):
                    raise ValueError(f"{name} must be a canonical SHA-256 digest")
            elif name == "qualified_snapshot_ref":
                if not isinstance(value, str) or not value.startswith("evidence://"):
                    raise ValueError("qualified_snapshot_ref must be an evidence reference")
            elif not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
                raise ValueError(f"{name} must be a safe non-empty identifier")

    def safe_bindings(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class SafeLeaseMetadata:
    version: str
    issued_at: str
    expires_at: str
    renewable: bool
    rotation_observed: bool = False


@dataclass(frozen=True)
class SecretResolutionReceipt:
    schema_version: str
    resolution_id: str
    decision_id: str
    request: dict[str, str]
    provider: str
    adapter_version: str
    state: ResolutionState
    reason_code: ReasonCode
    transport_attempted: bool
    retryable: bool
    elapsed_ms: int
    lease: SafeLeaseMetadata | None
    evidence_refs: tuple[str, ...]
    terminal_disposition: str
    generated: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    certified: bool = False
    human_approved: bool = False
    content_digest: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        value["reason_code"] = self.reason_code.value
        serialized = json.loads(json.dumps(value))
        assert isinstance(serialized, dict)
        return serialized


class IdentityResponse:
    """A deliberately non-dataclass transport envelope for credential material."""

    __slots__ = ("_audience", "_expires_at", "_issuer", "_token")

    def __init__(self, token: bytearray, issuer: str, audience: str, expires_at: str) -> None:
        if not isinstance(token, bytearray) or not token:
            raise ValueError("Identity token must be non-empty mutable material")
        self._token = token
        self._issuer = issuer
        self._audience = audience
        self._expires_at = expires_at

    @property
    def token(self) -> bytearray:
        return self._token

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def expires_at(self) -> str:
        return self._expires_at

    def clear(self) -> None:
        for index in range(len(self.token)):
            self.token[index] = 0

    def __repr__(self) -> str:
        return (
            "IdentityResponse(token=<redacted>, "
            f"issuer={self.issuer!r}, audience={self.audience!r}, expires_at={self.expires_at!r})"
        )

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Identity response cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Identity response cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Identity response cannot be serialized")


class SecretResponse:
    """A deliberately non-dataclass transport envelope for credential material."""

    __slots__ = (
        "_enabled",
        "_expires_at",
        "_issued_at",
        "_renewable",
        "_value",
        "_version",
    )

    def __init__(
        self,
        value: bytearray,
        version: str,
        issued_at: str,
        expires_at: str,
        renewable: bool,
        enabled: bool = True,
    ) -> None:
        if not isinstance(value, bytearray) or not value:
            raise ValueError("Secret value must be non-empty mutable material")
        self._value = value
        self._version = version
        self._issued_at = issued_at
        self._expires_at = expires_at
        self._renewable = renewable
        self._enabled = enabled

    @property
    def value(self) -> bytearray:
        return self._value

    @property
    def version(self) -> str:
        return self._version

    @property
    def issued_at(self) -> str:
        return self._issued_at

    @property
    def expires_at(self) -> str:
        return self._expires_at

    @property
    def renewable(self) -> bool:
        return self._renewable

    @property
    def enabled(self) -> bool:
        return self._enabled

    def clear(self) -> None:
        for index in range(len(self.value)):
            self.value[index] = 0

    def __repr__(self) -> str:
        return (
            "SecretResponse(value=<redacted>, "
            f"version={self.version!r}, issued_at={self.issued_at!r}, "
            f"expires_at={self.expires_at!r}, renewable={self.renewable!r}, "
            f"enabled={self.enabled!r})"
        )

    __str__ = __repr__

    def __copy__(self) -> Any:
        raise TypeError("Secret response cannot be copied")

    def __deepcopy__(self, memo: object) -> Any:
        raise TypeError("Secret response cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("Secret response cannot be serialized")
