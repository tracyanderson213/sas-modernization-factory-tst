"""Governed Databricks workspace authentication verification boundary."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from time import monotonic
from typing import Any, Protocol, cast

from smf.deployment.configuration import load_deployment_snapshot, preflight_deployment
from smf.execution.databricks_auth_models import (
    DatabricksAuthenticationRequest,
    DatabricksAuthenticationResponse,
    DatabricksAuthenticationResult,
    DatabricksAuthenticationState,
    DatabricksPermissionProbe,
    PermissionKind,
    PermissionResult,
    canonical_workspace_origin,
)
from smf.readiness.policy import digest_value
from smf.security.admission import has_executable_sas_entrypoint
from smf.security.models import SecretResolutionRequest
from smf.security.secrets import VerifiedSecretResolutionReceipt
from smf.security.transient import TransientMaterial


class DatabricksAuthenticationTransport(Protocol):
    def verify(
        self,
        *,
        request: DatabricksAuthenticationRequest,
        credential: memoryview,
        probes: tuple[DatabricksPermissionProbe, ...],
    ) -> DatabricksAuthenticationResponse: ...


class DatabricksPermissionDeniedError(Exception):
    pass


class DatabricksProviderUnavailableError(Exception):
    pass


def build_databricks_authentication_request(
    secret_request: SecretResolutionRequest,
    *,
    source_bytes: bytes,
    generated_bytes: bytes,
    configuration_digest: str,
    bundle_digest: str,
    workspace_binding_id: str,
    workspace_origin: str,
    expected_principal_ref: str,
    source_closure_digest: str,
    target: str,
    authentication_attempt_id: str,
    retry_ordinal: int,
    readiness_policy_id: str,
    readiness_policy_version: str,
    readiness_policy_digest: str,
    permission_policy_digest: str,
    secret_resolution_id: str,
    secret_resolution_digest: str,
    provider_version: str,
    adapter_version: str,
    permission_probes: tuple[DatabricksPermissionProbe, ...],
) -> DatabricksAuthenticationRequest:
    """Compose an auth request from readiness-bound secret admission and immutable bytes."""

    if not has_executable_sas_entrypoint(source_bytes):
        raise ValueError("Qualified source has no executable SAS entry point")
    if not generated_bytes.strip():
        raise ValueError("Generated target must contain meaningful bytes")
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    if source_digest != secret_request.source_sha256:
        raise ValueError("Qualified source bytes changed after readiness admission")
    if configuration_digest != secret_request.configuration_digest:
        raise ValueError("Deployment configuration changed after secret admission")
    return DatabricksAuthenticationRequest(
        schema_version="1.0",
        client_id=secret_request.client_id,
        deployment_id=secret_request.deployment_id,
        environment_id=secret_request.environment_id,
        configuration_digest=configuration_digest,
        bundle_digest=bundle_digest,
        workspace_binding_id=workspace_binding_id,
        workspace_origin=canonical_workspace_origin(workspace_origin),
        identity_binding_id=secret_request.identity_binding_id,
        expected_principal_ref=expected_principal_ref,
        workload_id=secret_request.workload_id,
        workload_digest=secret_request.workload_digest,
        boundary_id=secret_request.boundary_id,
        subject_id=secret_request.subject_id,
        qualified_snapshot_ref=secret_request.qualified_snapshot_ref,
        source_sha256=source_digest,
        generated_sha256=hashlib.sha256(generated_bytes).hexdigest(),
        source_closure_digest=source_closure_digest,
        target=target,
        run_id=secret_request.run_id,
        workflow_attempt_id=secret_request.attempt_id,
        authentication_attempt_id=authentication_attempt_id,
        retry_ordinal=retry_ordinal,
        readiness_result_id=secret_request.readiness_result_id,
        readiness_manifest_digest=secret_request.readiness_manifest_digest,
        readiness_policy_id=readiness_policy_id,
        readiness_policy_version=readiness_policy_version,
        readiness_policy_digest=readiness_policy_digest,
        security_policy_id=secret_request.security_policy_id,
        security_policy_version=secret_request.security_policy_version,
        security_policy_digest=secret_request.security_policy_digest,
        permission_policy_digest=permission_policy_digest,
        activation_evidence_id=secret_request.activation_evidence_id,
        activation_evidence_digest=secret_request.activation_evidence_digest,
        secret_resolution_id=secret_resolution_id,
        secret_resolution_digest=secret_resolution_digest,
        secret_binding_id=secret_request.secret_binding_id,
        consumer_id=secret_request.consumer_id,
        consumer_contract_version=secret_request.consumer_contract_version,
        provider_version=provider_version,
        adapter_version=adapter_version,
        permission_probes=permission_probes,
    )


def request_from_governed_deployment(
    secret_request: SecretResolutionRequest,
    *,
    factory_path: Path,
    readiness_manifest: Path,
    source_path: Path,
    generated_path: Path,
    source_closure_digest: str,
    target: str,
    authentication_attempt_id: str,
    retry_ordinal: int,
    secret_receipt: VerifiedSecretResolutionReceipt,
    provider_version: str,
    adapter_version: str,
) -> DatabricksAuthenticationRequest:
    """Compose DBX authentication only from qualified HENV and SEC evidence."""

    preflight = preflight_deployment(
        factory_path,
        readiness_manifest,
        workload_id=secret_request.workload_id,
        run_id=secret_request.run_id,
        attempt_id=secret_request.attempt_id,
    )
    if preflight.status != "qualified" or preflight.readiness_evidence is None:
        raise ValueError("Databricks deployment prerequisites are not qualified")
    snapshot = load_deployment_snapshot(factory_path)
    if (
        snapshot.client_id != secret_request.client_id
        or snapshot.deployment_id != secret_request.deployment_id
        or snapshot.environment_id != secret_request.environment_id
        or snapshot.configuration_digest != secret_request.configuration_digest
    ):
        raise ValueError("Databricks deployment identity is not readiness-bound")
    by_role = {item["role"]: item for item in snapshot.bindings}
    required_roles = (
        "workspace",
        "identity",
        "catalog",
        "target_schema",
        "source_read_scope",
        "output_scope",
    )
    if any(role not in by_role or by_role[role]["state"] != "active" for role in required_roles):
        raise ValueError("Databricks authentication bindings are not active and complete")
    readiness = preflight.readiness_evidence
    receipt_id = secret_receipt.get("resolution_id")
    receipt_digest = secret_receipt.get("content_digest")
    if not isinstance(receipt_id, str) or not isinstance(receipt_digest, str):
        raise ValueError("Secret resolution receipt reference is missing")
    probes = (
        DatabricksPermissionProbe(
            "workspace-access",
            PermissionKind.WORKSPACE_ACCESS,
            by_role["workspace"]["binding_id"],
        ),
        DatabricksPermissionProbe(
            "catalog-use", PermissionKind.CATALOG_USE, by_role["catalog"]["binding_id"]
        ),
        DatabricksPermissionProbe(
            "schema-use", PermissionKind.SCHEMA_USE, by_role["target_schema"]["binding_id"]
        ),
        DatabricksPermissionProbe(
            "source-read",
            PermissionKind.SOURCE_READ,
            by_role["source_read_scope"]["binding_id"],
        ),
        DatabricksPermissionProbe(
            "output-write",
            PermissionKind.OUTPUT_WRITE,
            by_role["output_scope"]["binding_id"],
        ),
    )
    permission_policy_digest = digest_value(
        {
            "contract": "smf-databricks-permission-policy-v1",
            "probes": [
                {
                    "probe_id": item.probe_id,
                    "kind": item.kind.value,
                    "resource_binding_id": item.resource_binding_id,
                }
                for item in probes
            ],
        }
    )
    return build_databricks_authentication_request(
        secret_request,
        source_bytes=source_path.read_bytes(),
        generated_bytes=generated_path.read_bytes(),
        configuration_digest=snapshot.configuration_digest,
        bundle_digest=snapshot.bundle_digest,
        workspace_binding_id=by_role["workspace"]["binding_id"],
        workspace_origin=by_role["workspace"]["value"],
        expected_principal_ref=by_role["identity"]["value"],
        source_closure_digest=source_closure_digest,
        target=target,
        authentication_attempt_id=authentication_attempt_id,
        retry_ordinal=retry_ordinal,
        readiness_policy_id=readiness["policy_id"],
        readiness_policy_version=readiness["policy_version"],
        readiness_policy_digest=readiness["policy_digest"],
        permission_policy_digest=permission_policy_digest,
        secret_resolution_id=receipt_id,
        secret_resolution_digest=receipt_digest,
        provider_version=provider_version,
        adapter_version=adapter_version,
        permission_probes=probes,
    )


def _receipt_outcome(
    request: DatabricksAuthenticationRequest, receipt: Mapping[str, Any]
) -> tuple[DatabricksAuthenticationState, str] | None:
    bound = receipt.get("request")
    if not isinstance(bound, Mapping):
        return DatabricksAuthenticationState.INVALID_BINDING, "secret_receipt_invalid"
    exact = {
        "client_id": request.client_id,
        "deployment_id": request.deployment_id,
        "environment_id": request.environment_id,
        "workload_id": request.workload_id,
        "workload_digest": request.workload_digest,
        "boundary_id": request.boundary_id,
        "subject_id": request.subject_id,
        "source_sha256": request.source_sha256,
        "run_id": request.run_id,
        "attempt_id": request.workflow_attempt_id,
        "consumer_id": request.consumer_id,
        "consumer_contract_version": request.consumer_contract_version,
        "identity_binding_id": request.identity_binding_id,
        "secret_binding_id": request.secret_binding_id,
        "security_policy_id": request.security_policy_id,
        "security_policy_version": request.security_policy_version,
        "security_policy_digest": request.security_policy_digest,
        "configuration_digest": request.configuration_digest,
        "readiness_result_id": request.readiness_result_id,
        "readiness_manifest_digest": request.readiness_manifest_digest,
        "qualified_snapshot_ref": request.qualified_snapshot_ref,
        "activation_evidence_id": request.activation_evidence_id,
        "activation_evidence_digest": request.activation_evidence_digest,
    }
    unsigned = dict(receipt)
    unsigned["content_digest"] = ""
    bound_and_intact = (
        all(bound.get(key) == value for key, value in exact.items())
        and receipt.get("resolution_id") == request.secret_resolution_id
        and receipt.get("content_digest") == request.secret_resolution_digest
        and receipt.get("content_digest") == digest_value(unsigned)
    )
    if not bound_and_intact:
        return DatabricksAuthenticationState.INVALID_BINDING, "secret_receipt_invalid"
    state = receipt.get("state")
    reason = receipt.get("reason_code")
    if state == "resolved":
        if (
            reason == "resolved"
            and receipt.get("transport_attempted") is True
            and receipt.get("decision_id") not in {None, "unverified"}
            and receipt.get("lease") is not None
        ):
            return None
        return DatabricksAuthenticationState.INVALID_BINDING, "secret_receipt_invalid"
    mapped = {
        "blocked_missing": DatabricksAuthenticationState.BLOCKED_MISSING,
        "blocked_pending": DatabricksAuthenticationState.BLOCKED_PENDING,
        "denied": DatabricksAuthenticationState.DENIED,
        "expired": DatabricksAuthenticationState.EXPIRED,
        "invalid_binding": DatabricksAuthenticationState.INVALID_BINDING,
        "authentication_failed": DatabricksAuthenticationState.DENIED,
        "provider_unavailable": DatabricksAuthenticationState.PROVIDER_UNAVAILABLE,
        "timed_out": DatabricksAuthenticationState.TIMED_OUT,
        "cancelled": DatabricksAuthenticationState.CANCELLED,
        "failed": DatabricksAuthenticationState.FAILED,
    }
    mapped_state = mapped.get(state) if isinstance(state, str) else None
    if mapped_state is None or not isinstance(reason, str):
        return DatabricksAuthenticationState.INVALID_BINDING, "secret_receipt_invalid"
    return mapped_state, reason


def _result(
    request: DatabricksAuthenticationRequest,
    state: DatabricksAuthenticationState,
    reason: str,
    started: float,
    *,
    attempted: bool = False,
    workspace: bool = False,
    identity: bool = False,
    permissions: bool = False,
    provider_request_id: str | None = None,
) -> DatabricksAuthenticationResult:
    unsigned = DatabricksAuthenticationResult(
        schema_version="1.0",
        request=request.bindings(),
        request_digest=request.request_digest,
        authentication_request_id=request.authentication_request_id,
        authentication_attempt_id=request.authentication_attempt_id,
        decision_id=request.decision_id,
        state=state,
        reason_code=reason,
        transport_attempted=attempted,
        workspace_verified=workspace,
        identity_verified=identity,
        permissions_verified=permissions,
        provider_request_id=provider_request_id,
        elapsed_ms=max(0, int((monotonic() - started) * 1000)),
        retryable=state
        in {
            DatabricksAuthenticationState.PROVIDER_UNAVAILABLE,
            DatabricksAuthenticationState.TIMED_OUT,
        },
        evidence_refs=(
            request.readiness_result_id,
            request.activation_evidence_id,
            request.secret_resolution_id,
            request.qualified_snapshot_ref,
        ),
        authenticated=state is DatabricksAuthenticationState.VERIFIED,
        blocked=state is not DatabricksAuthenticationState.VERIFIED,
    )
    payload = unsigned.to_dict()
    payload["content_digest"] = ""
    return DatabricksAuthenticationResult(
        **{**unsigned.__dict__, "content_digest": digest_value(payload)}
    )


def authenticate_databricks(
    request: DatabricksAuthenticationRequest,
    *,
    credential: TransientMaterial,
    secret_receipt: Mapping[str, Any],
    transport: DatabricksAuthenticationTransport | Callable[..., DatabricksAuthenticationResponse],
) -> DatabricksAuthenticationResult:
    """Verify workspace, identity and permissions without persisting credential material."""

    started = monotonic()
    if (
        type(secret_receipt) is not VerifiedSecretResolutionReceipt
        or not secret_receipt.is_provider_issued()
    ):
        credential.close()
        return _result(
            request,
            DatabricksAuthenticationState.INVALID_BINDING,
            "secret_receipt_untrusted",
            started,
        )
    receipt_outcome = _receipt_outcome(request, secret_receipt)
    if receipt_outcome is not None:
        credential.close()
        return _result(
            request,
            receipt_outcome[0],
            receipt_outcome[1],
            started,
        )
    try:
        verify = cast(Callable[..., Any], getattr(transport, "verify", transport))
        response = verify(
            request=request,
            credential=credential.view(),
            probes=request.permission_probes,
        )
        if not isinstance(response, DatabricksAuthenticationResponse):
            return _result(
                request,
                DatabricksAuthenticationState.FAILED,
                "malformed_response",
                started,
                attempted=True,
            )
        if (
            response.provider_version != request.provider_version
            or response.adapter_version != request.adapter_version
        ):
            return _result(
                request,
                DatabricksAuthenticationState.INVALID_BINDING,
                "provider_version_mismatch",
                started,
                attempted=True,
            )
        if response.workspace_origin != request.workspace_origin:
            return _result(
                request,
                DatabricksAuthenticationState.WRONG_WORKSPACE,
                "wrong_workspace",
                started,
                attempted=True,
                provider_request_id=response.provider_request_id,
            )
        if response.principal_ref != request.expected_principal_ref:
            return _result(
                request,
                DatabricksAuthenticationState.WRONG_IDENTITY,
                "wrong_identity",
                started,
                attempted=True,
                workspace=True,
                provider_request_id=response.provider_request_id,
            )
        expected = {probe.probe_id.casefold(): probe for probe in request.permission_probes}
        observed = {item.probe_id.casefold(): item for item in response.observations}
        if set(observed) != set(expected) or any(
            observed[key].resource_binding_id != probe.resource_binding_id
            for key, probe in expected.items()
        ):
            return _result(
                request,
                DatabricksAuthenticationState.INVALID_BINDING,
                "permission_evidence_incomplete",
                started,
                attempted=True,
                workspace=True,
                identity=True,
                provider_request_id=response.provider_request_id,
            )
        if any(item.result is not PermissionResult.ALLOWED for item in observed.values()):
            return _result(
                request,
                DatabricksAuthenticationState.PERMISSION_DENIED,
                "permission_denied",
                started,
                attempted=True,
                workspace=True,
                identity=True,
                provider_request_id=response.provider_request_id,
            )
        return _result(
            request,
            DatabricksAuthenticationState.VERIFIED,
            "verified",
            started,
            attempted=True,
            workspace=True,
            identity=True,
            permissions=True,
            provider_request_id=response.provider_request_id,
        )
    except DatabricksPermissionDeniedError:
        return _result(
            request,
            DatabricksAuthenticationState.PERMISSION_DENIED,
            "permission_denied",
            started,
            attempted=True,
        )
    except DatabricksProviderUnavailableError:
        return _result(
            request,
            DatabricksAuthenticationState.PROVIDER_UNAVAILABLE,
            "provider_unavailable",
            started,
            attempted=True,
        )
    except TimeoutError:
        return _result(
            request,
            DatabricksAuthenticationState.TIMED_OUT,
            "transport_timeout",
            started,
            attempted=True,
        )
    except asyncio.CancelledError:
        return _result(
            request,
            DatabricksAuthenticationState.CANCELLED,
            "cancelled",
            started,
            attempted=True,
        )
    except Exception:
        return _result(
            request,
            DatabricksAuthenticationState.FAILED,
            "malformed_response",
            started,
            attempted=True,
        )
    finally:
        credential.close()
