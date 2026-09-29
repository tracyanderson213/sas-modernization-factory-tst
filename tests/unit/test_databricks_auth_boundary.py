import asyncio
from typing import Any

import pytest
from tests.unit.test_databricks_auth_models import build_request, secret_request

from smf.execution.databricks_auth import (
    DatabricksProviderUnavailableError,
    authenticate_databricks,
)
from smf.execution.databricks_auth_models import (
    DatabricksAuthenticationResponse,
    DatabricksPermissionObservation,
    PermissionResult,
)
from smf.readiness.policy import digest_value
from smf.security.models import (
    ReasonCode,
    ResolutionState,
    SafeLeaseMetadata,
    SecretResolutionReceipt,
)
from smf.security.secrets import _seal_secret_resolution_receipt
from smf.security.transient import TransientMaterial


def resolved_receipt(request=None) -> dict[str, Any]:
    auth_request = request or build_request()
    secret = secret_request()
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "resolution_id": auth_request.secret_resolution_id,
        "decision_id": "authority-decision-1",
        "request": secret.safe_bindings(),
        "provider": "hashicorp-vault",
        "adapter_version": "1.0",
        "state": "resolved",
        "reason_code": "resolved",
        "transport_attempted": True,
        "retryable": False,
        "elapsed_ms": 1,
        "lease": {
            "version": "version-1",
            "issued_at": "2026-09-16T00:00:00Z",
            "expires_at": "2026-09-17T00:00:00Z",
            "renewable": False,
            "rotation_observed": False,
        },
        "evidence_refs": [secret.readiness_result_id, secret.activation_evidence_id],
        "terminal_disposition": "secret_available_transiently",
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "content_digest": "",
    }
    payload["content_digest"] = digest_value(payload)
    object.__setattr__(auth_request, "secret_resolution_digest", payload["content_digest"])
    return payload


def trusted_receipt(payload: dict[str, Any]):
    lease = payload["lease"]
    receipt = SecretResolutionReceipt(
        **{
            **payload,
            "state": ResolutionState(payload["state"]),
            "reason_code": ReasonCode(payload["reason_code"]),
            "lease": SafeLeaseMetadata(**lease) if lease is not None else None,
            "evidence_refs": tuple(payload["evidence_refs"]),
        }
    )
    return _seal_secret_resolution_receipt(receipt)


class Transport:
    def __init__(self, response: DatabricksAuthenticationResponse) -> None:
        self.response = response
        self.calls = 0

    def verify(self, **_: object) -> DatabricksAuthenticationResponse:
        self.calls += 1
        return self.response


def response(request=None) -> DatabricksAuthenticationResponse:
    auth_request = request or build_request()
    return DatabricksAuthenticationResponse(
        workspace_origin=auth_request.workspace_origin,
        principal_ref=auth_request.expected_principal_ref,
        observations=tuple(
            DatabricksPermissionObservation(
                item.probe_id, item.resource_binding_id, PermissionResult.ALLOWED
            )
            for item in auth_request.permission_probes
        ),
        provider_request_id="provider-request-1",
        provider_version=auth_request.provider_version,
        adapter_version=auth_request.adapter_version,
    )


def request_and_receipt():
    request = build_request()
    receipt = trusted_receipt(resolved_receipt(request))
    return request, receipt


def test_verified_authentication_is_not_execution_or_parity() -> None:
    request, receipt = request_and_receipt()
    transport = Transport(response(request))
    credential = TransientMaterial(b"secret-canary")
    result = authenticate_databricks(
        request, credential=credential, secret_receipt=receipt, transport=transport
    )
    assert result.state.value == "verified"
    assert result.authenticated is True
    assert result.submitted is result.executed is result.validated is result.parity_passed is False
    assert credential.closed is True
    assert "secret-canary" not in str(result.to_dict())


def test_self_asserted_or_unbound_receipt_cannot_call_transport() -> None:
    request, receipt = request_and_receipt()
    receipt = receipt.to_dict()
    receipt["request"]["run_id"] = "another-run"
    transport = Transport(response(request))
    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=transport,
    )
    assert result.state.value == "invalid_binding"
    assert transport.calls == 0


def test_caller_authored_secret_receipt_cannot_authenticate() -> None:
    request, receipt = request_and_receipt()
    receipt = receipt.to_dict()
    receipt["provider"] = "caller-authored-provider"
    receipt["decision_id"] = "caller-authored-decision"
    receipt["content_digest"] = ""
    receipt["content_digest"] = digest_value(receipt)
    object.__setattr__(request, "secret_resolution_digest", receipt["content_digest"])
    transport = Transport(response(request))

    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=transport,
    )

    assert result.state.value == "invalid_binding"
    assert result.authenticated is False
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("receipt_state", "reason", "authentication_state"),
    [
        ("blocked_missing", "approval_missing", "blocked_missing"),
        ("blocked_pending", "approval_pending", "blocked_pending"),
        ("denied", "approval_denied", "denied"),
        ("expired", "approval_expired", "expired"),
    ],
)
def test_denial_pending_missing_and_expiry_remain_distinct(
    receipt_state: str, reason: str, authentication_state: str
) -> None:
    request, receipt = request_and_receipt()
    receipt = receipt.to_dict()
    receipt["state"] = receipt_state
    receipt["reason_code"] = reason
    receipt["decision_id"] = "unverified"
    receipt["lease"] = None
    receipt["transport_attempted"] = False
    receipt["terminal_disposition"] = "not_resolved"
    receipt["content_digest"] = ""
    receipt["content_digest"] = digest_value(receipt)
    object.__setattr__(request, "secret_resolution_digest", receipt["content_digest"])
    receipt = trusted_receipt(receipt)
    transport = Transport(response(request))
    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=transport,
    )
    assert result.state.value == authentication_state
    assert result.reason_code == reason
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("mutation", "state"),
    [
        ("workspace", "wrong_workspace"),
        ("identity", "wrong_identity"),
        ("denied", "permission_denied"),
        ("missing", "invalid_binding"),
    ],
)
def test_workspace_identity_and_exact_permissions_fail_closed(mutation: str, state: str) -> None:
    request, receipt = request_and_receipt()
    good = response(request)
    values = good.__dict__.copy()
    if mutation == "workspace":
        values["workspace_origin"] = "https://other.cloud.databricks.com"
    elif mutation == "identity":
        values["principal_ref"] = "principal-2"
    elif mutation == "denied":
        first = good.observations[0]
        values["observations"] = (
            DatabricksPermissionObservation(
                first.probe_id, first.resource_binding_id, PermissionResult.DENIED
            ),
            *good.observations[1:],
        )
    else:
        values["observations"] = good.observations[:-1]
    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=Transport(DatabricksAuthenticationResponse(**values)),
    )
    assert result.state.value == state
    assert result.authenticated is False


def test_provider_exception_is_sanitized_terminal_evidence() -> None:
    request, receipt = request_and_receipt()

    def broken(**_: object):
        raise RuntimeError("Bearer secret-canary")

    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=broken,
    )
    assert result.state.value == "failed"
    assert result.reason_code == "malformed_response"
    assert "secret-canary" not in str(result.to_dict())


@pytest.mark.parametrize(
    ("error", "state", "reason"),
    [
        (TimeoutError("secret-canary"), "timed_out", "transport_timeout"),
        (asyncio.CancelledError("secret-canary"), "cancelled", "cancelled"),
        (
            DatabricksProviderUnavailableError("secret-canary"),
            "provider_unavailable",
            "provider_unavailable",
        ),
    ],
)
def test_provider_terminal_failures_are_categorical_and_sanitized(
    error: BaseException, state: str, reason: str
) -> None:
    request, receipt = request_and_receipt()

    def broken(**_: object):
        raise error

    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=broken,
    )
    assert result.state.value == state
    assert result.reason_code == reason
    assert "secret-canary" not in str(result.to_dict())
