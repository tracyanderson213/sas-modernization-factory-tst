"""Provider-neutral workload identity boundary and offline Entra adapter."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from smf.security.attestation import verify_activation
from smf.security.configuration import IdentityBinding, SecurityConfiguration
from smf.security.models import BindingStatus, IdentityResponse, SecretResolutionRequest
from smf.security.transient import TransientMaterial


class IdentityTransport(Protocol):
    def exchange(
        self, *, request: SecretResolutionRequest, binding: IdentityBinding
    ) -> IdentityResponse: ...


class WorkloadIdentityProvider(Protocol):
    def acquire(
        self,
        request: SecretResolutionRequest,
        config: SecurityConfiguration,
        activation: dict[str, Any] | None,
    ) -> TransientMaterial: ...


class IdentityRejectedError(Exception):
    pass


class ProviderUnavailableError(Exception):
    pass


class EntraWorkloadIdentityProvider:
    """Entra binding with no networking implementation or retained token state."""

    provider_name = "microsoft-entra-id-active-directory"
    adapter_version = "1.0"

    def __init__(self, transport: IdentityTransport | Callable[..., IdentityResponse]) -> None:
        self._transport = transport

    def acquire(
        self,
        request: SecretResolutionRequest,
        config: SecurityConfiguration,
        activation: dict[str, Any] | None,
    ) -> TransientMaterial:
        if (
            config.status is not BindingStatus.ACTIVE
            or config.configuration_digest != request.configuration_digest
            or config.policy_digest != request.security_policy_digest
            or config.policy_id != request.security_policy_id
            or config.policy_version != request.security_policy_version
        ):
            raise IdentityRejectedError("Identity request is not authorized")
        binding = config.identity_bindings.get(request.identity_binding_id)
        if binding is None:
            raise IdentityRejectedError("Identity request is not authorized")
        activation_state, activation_reason, decision_id = verify_activation(
            activation, request, config, purpose="vault-secret-read"
        )
        if activation_state is not None or activation_reason is not None or decision_id is None:
            raise IdentityRejectedError("Identity request is not authorized")
        exchange = cast(Callable[..., Any], getattr(self._transport, "exchange", self._transport))
        response: IdentityResponse | None = None
        try:
            response = exchange(request=request, binding=binding)
            if not isinstance(response, IdentityResponse) or not response.token:
                raise ValueError("Malformed identity response")
            expires = datetime.fromisoformat(response.expires_at.replace("Z", "+00:00"))
            if (
                response.issuer != binding.issuer
                or response.audience != binding.audience
                or expires.tzinfo is None
                or expires <= datetime.now(UTC)
            ):
                raise IdentityRejectedError("Identity claims do not match the protected binding")
            return TransientMaterial(response.token)
        except (
            IdentityRejectedError,
            ProviderUnavailableError,
            TimeoutError,
            asyncio.CancelledError,
        ):
            raise
        except Exception:
            raise ValueError("Malformed identity response") from None
        finally:
            if response is not None:
                response.clear()
