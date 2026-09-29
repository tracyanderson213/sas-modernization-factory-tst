import hashlib

import pytest

from smf.execution.databricks_auth import build_databricks_authentication_request
from smf.execution.databricks_auth_models import (
    DatabricksPermissionProbe,
    PermissionKind,
    canonical_workspace_origin,
)
from smf.readiness.policy import digest_value
from smf.security.models import SecretResolutionRequest


def secret_request(source: bytes = b"proc sql; select 1; quit;") -> SecretResolutionRequest:
    return SecretResolutionRequest(
        schema_version="1.0",
        client_id="client-1",
        deployment_id="deployment-1",
        environment_id="environment-1",
        workload_id="workload-1",
        workload_digest="1" * 64,
        boundary_id="boundary-1",
        subject_id="subject-1",
        source_sha256=hashlib.sha256(source).hexdigest(),
        run_id="run-1",
        attempt_id="attempt-1",
        consumer_id="databricks-auth",
        consumer_contract_version="1.0",
        identity_binding_id="identity-1",
        secret_binding_id="secret-1",
        security_policy_id="security-1",
        security_policy_version="1.0",
        security_policy_digest="2" * 64,
        configuration_digest="3" * 64,
        readiness_result_id="readiness-1",
        readiness_manifest_digest="4" * 64,
        qualified_snapshot_ref="evidence://readiness/snapshot-1",
        activation_evidence_id="activation-1",
        activation_evidence_digest="5" * 64,
    )


def build_request(source: bytes = b"proc sql; select 1; quit;"):
    secret = secret_request(source)
    permission_probes = (
        DatabricksPermissionProbe("probe-1", PermissionKind.WORKSPACE_ACCESS, "workspace-1"),
        DatabricksPermissionProbe("probe-2", PermissionKind.CATALOG_USE, "catalog-1"),
        DatabricksPermissionProbe("probe-3", PermissionKind.SCHEMA_USE, "schema-1"),
        DatabricksPermissionProbe("probe-4", PermissionKind.SOURCE_READ, "source-1"),
        DatabricksPermissionProbe("probe-5", PermissionKind.OUTPUT_WRITE, "output-1"),
    )
    permission_policy_digest = digest_value(
        {
            "contract": "smf-databricks-permission-policy-v1",
            "probes": [
                {
                    "probe_id": probe.probe_id,
                    "kind": probe.kind.value,
                    "resource_binding_id": probe.resource_binding_id,
                }
                for probe in permission_probes
            ],
        }
    )
    return build_databricks_authentication_request(
        secret,
        source_bytes=source,
        generated_bytes=b"spark.sql('select 1')",
        configuration_digest="3" * 64,
        bundle_digest="6" * 64,
        workspace_binding_id="workspace-1",
        workspace_origin="https://example.cloud.databricks.com",
        expected_principal_ref="principal-1",
        source_closure_digest="7" * 64,
        target="pyspark",
        authentication_attempt_id="auth-attempt-1",
        retry_ordinal=0,
        readiness_policy_id="readiness-policy-1",
        readiness_policy_version="1.0",
        readiness_policy_digest="8" * 64,
        permission_policy_digest=permission_policy_digest,
        secret_resolution_id=digest_value(
            {"contract": "smf-secret-resolution-v1", **secret.safe_bindings()}
        ),
        secret_resolution_digest="a" * 64,
        provider_version="1.0",
        adapter_version="1.0",
        permission_probes=permission_probes,
    )


def test_request_identity_is_deterministic_and_bound_to_artifacts() -> None:
    first = build_request()
    second = build_request()
    assert first.authentication_request_id == second.authentication_request_id
    assert first.decision_id == second.decision_id
    assert first.generated_sha256 == hashlib.sha256(b"spark.sql('select 1')").hexdigest()


@pytest.mark.parametrize(
    "value",
    [
        "http://example.cloud.databricks.com",
        "https://user@example.cloud.databricks.com",
        "https://example.cloud.databricks.com/path",
        "https://example.cloud.databricks.com?profile=other",
        "https://localhost",
    ],
)
def test_workspace_origin_rejects_fallback_and_boundary_escape(value: str) -> None:
    with pytest.raises(ValueError, match="workspace_origin"):
        canonical_workspace_origin(value)


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"   ",
        b"/* data fake; run; */",
        b"* proc sql; select 1; quit;;",
        b"%let harmless = proc sql; %put &=harmless;",
        b"%put data fake;",
    ],
)
def test_empty_or_nonconvertible_source_cannot_authenticate(source: bytes) -> None:
    with pytest.raises(ValueError, match="executable SAS entry point"):
        build_request(source)


def test_duplicate_and_malformed_permission_types_fail_closed() -> None:
    with pytest.raises(ValueError):
        DatabricksPermissionProbe("probe-1", "trust_me", "workspace-1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Duplicate permission"):
        request = build_request()
        type(request)(
            **{
                **request.__dict__,
                "permission_probes": (request.permission_probes[0], request.permission_probes[0]),
            }
        )


def test_incomplete_permission_policy_cannot_authenticate() -> None:
    request = build_request()
    with pytest.raises(ValueError, match="complete configured permission set"):
        type(request)(**{**request.__dict__, "permission_probes": request.permission_probes[:1]})


@pytest.mark.parametrize(
    "principal_ref",
    ["secret-canary", "token-canary", "password-canary", "dapi" + "a" * 32],
)
def test_secret_shaped_principal_reference_is_rejected(principal_ref: str) -> None:
    request = build_request()
    with pytest.raises(ValueError, match="expected_principal_ref"):
        type(request)(**{**request.__dict__, "expected_principal_ref": principal_ref})


def test_duplicate_binding_and_evidence_identities_fail_closed() -> None:
    request = build_request()
    with pytest.raises(ValueError, match="binding identity"):
        type(request)(**{**request.__dict__, "secret_binding_id": request.identity_binding_id})
    with pytest.raises(ValueError, match="evidence identity"):
        type(request)(**{**request.__dict__, "activation_evidence_id": request.readiness_result_id})
