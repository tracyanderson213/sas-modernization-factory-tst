"""Provider-neutral secret boundary and fail-closed HashiCorp Vault adapter."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any, Protocol, cast

from smf.readiness.policy import digest_value
from smf.security.attestation import verify_activation
from smf.security.configuration import (
    SecretBinding,
    SecurityConfiguration,
    load_security_configuration,
)
from smf.security.identity import (
    EntraWorkloadIdentityProvider,
    IdentityRejectedError,
    ProviderUnavailableError,
    WorkloadIdentityProvider,
)
from smf.security.manifest import validate_receipt_payload
from smf.security.models import (
    BindingStatus,
    ReasonCode,
    ResolutionState,
    SafeLeaseMetadata,
    SecretResolutionReceipt,
    SecretResolutionRequest,
    SecretResponse,
)
from smf.security.transient import TransientMaterial


class VaultTransport(Protocol):
    def read(
        self, *, token: memoryview, request: SecretResolutionRequest, binding: SecretBinding
    ) -> SecretResponse: ...


class VaultDeniedError(Exception):
    pass


class SecretProvider(Protocol):
    def resolve(
        self,
        request: SecretResolutionRequest,
        config: SecurityConfiguration,
        activation: dict[str, Any] | None,
    ) -> Iterator[tuple[TransientMaterial | None, VerifiedSecretResolutionReceipt]]: ...


_VERIFIED_RECEIPT_SEAL = object()


class VerifiedSecretResolutionReceipt(Mapping[str, Any]):
    """Process-local capability proving a receipt crossed the canonical provider boundary."""

    __slots__ = ("_payload", "_receipt", "_seal")

    def __init__(self, receipt: SecretResolutionReceipt, *, _seal: object) -> None:
        if _seal is not _VERIFIED_RECEIPT_SEAL:
            raise TypeError("Verified secret receipts are issued only by the secret provider")
        payload = receipt.to_dict()
        validate_receipt_payload(payload)
        self._payload = payload
        self._receipt = receipt
        self._seal = _seal

    def __getitem__(self, key: str) -> Any:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._receipt, name)

    def to_dict(self) -> dict[str, Any]:
        return dict(self._payload)

    def is_provider_issued(self) -> bool:
        return self._seal is _VERIFIED_RECEIPT_SEAL


def _seal_secret_resolution_receipt(
    receipt: SecretResolutionReceipt,
) -> VerifiedSecretResolutionReceipt:
    return VerifiedSecretResolutionReceipt(receipt, _seal=_VERIFIED_RECEIPT_SEAL)


class HashiCorpVaultSecretProvider:
    provider_name = "hashicorp-vault"
    adapter_version = "1.0"

    def __init__(
        self,
        identity_provider: WorkloadIdentityProvider | EntraWorkloadIdentityProvider,
        transport: VaultTransport | Callable[..., SecretResponse],
    ) -> None:
        self._identity = identity_provider
        self._transport = transport

    def _receipt(
        self,
        request: SecretResolutionRequest,
        state: ResolutionState,
        reason: ReasonCode,
        decision_id: str,
        started: float,
        *,
        attempted: bool = False,
        lease: SafeLeaseMetadata | None = None,
    ) -> SecretResolutionReceipt:
        resolution_id = digest_value(
            {"contract": "smf-secret-resolution-v1", **request.safe_bindings()}
        )
        unsigned = SecretResolutionReceipt(
            schema_version="1.0",
            resolution_id=resolution_id,
            decision_id=decision_id,
            request=request.safe_bindings(),
            provider=self.provider_name,
            adapter_version=self.adapter_version,
            state=state,
            reason_code=reason,
            transport_attempted=attempted,
            retryable=state in {ResolutionState.PROVIDER_UNAVAILABLE, ResolutionState.TIMED_OUT},
            elapsed_ms=max(0, int((monotonic() - started) * 1000)),
            lease=lease,
            evidence_refs=(request.readiness_result_id, request.activation_evidence_id),
            terminal_disposition="secret_available_transiently"
            if state is ResolutionState.RESOLVED
            else "not_resolved",
        )
        return SecretResolutionReceipt(
            **{**unsigned.__dict__, "content_digest": digest_value(unsigned.to_dict())}
        )

    @contextmanager
    def resolve_configured(
        self,
        request: SecretResolutionRequest,
        policy_path: Path,
        binding_path: Path,
        activation: dict[str, Any] | None,
    ) -> Iterator[tuple[TransientMaterial | None, VerifiedSecretResolutionReceipt]]:
        """Load configuration and resolve, returning evidence for every admission outcome."""

        started = monotonic()
        try:
            config = load_security_configuration(policy_path, binding_path)
        except FileNotFoundError:
            yield (
                None,
                _seal_secret_resolution_receipt(
                    self._receipt(
                        request,
                        ResolutionState.BLOCKED_MISSING,
                        ReasonCode.CONFIGURATION_MISSING,
                        "unverified",
                        started,
                    )
                ),
            )
            return
        except (OSError, ValueError):
            yield (
                None,
                _seal_secret_resolution_receipt(
                    self._receipt(
                        request,
                        ResolutionState.INVALID_BINDING,
                        ReasonCode.CONFIGURATION_INVALID,
                        "unverified",
                        started,
                    )
                ),
            )
            return
        with self.resolve(request, config, activation) as result:
            yield result

    @contextmanager
    def resolve(
        self,
        request: SecretResolutionRequest,
        config: SecurityConfiguration,
        activation: dict[str, Any] | None,
    ) -> Iterator[tuple[TransientMaterial | None, VerifiedSecretResolutionReceipt]]:
        with self._resolve_unsealed(request, config, activation) as (material, receipt):
            yield material, _seal_secret_resolution_receipt(receipt)

    @contextmanager
    def _resolve_unsealed(
        self,
        request: SecretResolutionRequest,
        config: SecurityConfiguration,
        activation: dict[str, Any] | None,
    ) -> Iterator[tuple[TransientMaterial | None, SecretResolutionReceipt]]:
        started = monotonic()
        if (
            config.configuration_digest != request.configuration_digest
            or config.policy_digest != request.security_policy_digest
            or config.policy_id != request.security_policy_id
            or config.policy_version != request.security_policy_version
        ):
            yield (
                None,
                self._receipt(
                    request,
                    ResolutionState.INVALID_BINDING,
                    ReasonCode.BINDING_MISMATCH,
                    "unverified",
                    started,
                ),
            )
            return
        if config.status is BindingStatus.PENDING:
            yield (
                None,
                self._receipt(
                    request,
                    ResolutionState.BLOCKED_PENDING,
                    ReasonCode.CONFIGURATION_PENDING,
                    "unverified",
                    started,
                ),
            )
            return
        if config.status is BindingStatus.DENIED:
            yield (
                None,
                self._receipt(
                    request,
                    ResolutionState.DENIED,
                    ReasonCode.APPROVAL_DENIED,
                    "unverified",
                    started,
                ),
            )
            return
        if (
            request.identity_binding_id not in config.identity_bindings
            or request.secret_binding_id not in config.secret_bindings
        ):
            yield (
                None,
                self._receipt(
                    request,
                    ResolutionState.INVALID_BINDING,
                    ReasonCode.BINDING_MISMATCH,
                    "unverified",
                    started,
                ),
            )
            return
        if activation is not None and (
            activation.get("packet_kind") == "architecture_security_review_evidence"
            or activation.get("authority") == "non_authorizing"
        ):
            yield (
                None,
                self._receipt(
                    request,
                    ResolutionState.INVALID_BINDING,
                    ReasonCode.ACTIVATION_INVALID,
                    "unverified",
                    started,
                ),
            )
            return
        activation_state, activation_reason, decision_id = verify_activation(
            activation, request, config, purpose="vault-secret-read"
        )
        if activation_state is not None and activation_reason is not None:
            yield (
                None,
                self._receipt(request, activation_state, activation_reason, "unverified", started),
            )
            return
        assert decision_id is not None
        token: TransientMaterial | None = None
        secret: TransientMaterial | None = None
        response: SecretResponse | None = None
        attempted = False
        outcome_state = ResolutionState.FAILED
        outcome_reason = ReasonCode.MALFORMED_RESPONSE
        lease: SafeLeaseMetadata | None = None
        try:
            attempted = True
            token = self._identity.acquire(request, config, activation)
            binding = config.secret_bindings[request.secret_binding_id]
            read = cast(Callable[..., Any], getattr(self._transport, "read", self._transport))
            response = read(token=token.view(), request=request, binding=binding)
            if isinstance(response, SecretResponse) and response.value:
                issued = datetime.fromisoformat(response.issued_at.replace("Z", "+00:00"))
                expires = datetime.fromisoformat(response.expires_at.replace("Z", "+00:00"))
                now = datetime.now(UTC)
                if response.version != binding.version:
                    outcome_state = ResolutionState.INVALID_BINDING
                    outcome_reason = ReasonCode.BINDING_MISMATCH
                elif not response.enabled:
                    outcome_state = ResolutionState.DENIED
                    outcome_reason = ReasonCode.CREDENTIAL_DISABLED
                elif issued.tzinfo is None or expires.tzinfo is None or expires <= now:
                    outcome_state = ResolutionState.EXPIRED
                    outcome_reason = ReasonCode.CREDENTIAL_EXPIRED
                elif (expires - now).total_seconds() < config.min_lease_seconds:
                    outcome_state = ResolutionState.EXPIRED
                    outcome_reason = ReasonCode.LEASE_INVALID
                else:
                    outcome_state = ResolutionState.RESOLVED
                    outcome_reason = ReasonCode.RESOLVED
                    lease = SafeLeaseMetadata(
                        response.version,
                        response.issued_at,
                        response.expires_at,
                        response.renewable,
                        rotation_observed=binding.previous_version is not None,
                    )
                    secret = TransientMaterial(response.value)
        except IdentityRejectedError:
            outcome_state = ResolutionState.AUTHENTICATION_FAILED
            outcome_reason = ReasonCode.IDENTITY_REJECTED
        except VaultDeniedError:
            outcome_state = ResolutionState.DENIED
            outcome_reason = ReasonCode.VAULT_DENIED
        except ProviderUnavailableError:
            outcome_state = ResolutionState.PROVIDER_UNAVAILABLE
            outcome_reason = ReasonCode.PROVIDER_UNAVAILABLE
        except TimeoutError:
            outcome_state = ResolutionState.TIMED_OUT
            outcome_reason = ReasonCode.TRANSPORT_TIMEOUT
        except asyncio.CancelledError:
            outcome_state = ResolutionState.CANCELLED
            outcome_reason = ReasonCode.CANCELLED
        except Exception:
            outcome_state = ResolutionState.FAILED
            outcome_reason = ReasonCode.MALFORMED_RESPONSE
        finally:
            if token is not None:
                token.close()
            if response is not None:
                response.clear()
        receipt = self._receipt(
            request,
            outcome_state,
            outcome_reason,
            decision_id,
            started,
            attempted=attempted,
            lease=lease,
        )
        try:
            yield secret, receipt
        finally:
            if secret is not None:
                secret.close()
