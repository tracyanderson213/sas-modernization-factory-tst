from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.test_databricks_auth_models import build_request

from smf.execution.databricks_auth_manifest import (
    authentication_evidence_dir,
    claim_authentication_attempt,
)
from smf.execution.databricks_auth_schema import validate_databricks_authentication_schema


def test_concurrent_identical_claimants_have_exactly_one_winner(tmp_path: Path) -> None:
    request = build_request()
    key = Ed25519PrivateKey.generate()

    def claim() -> bool:
        return claim_authentication_attempt(tmp_path, request, signing_key=key, key_id="test-key")[
            1
        ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: claim(), range(16)))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 15


def test_unrelated_workloads_have_isolated_evidence_paths(tmp_path: Path) -> None:
    first = build_request()
    second = type(first)(
        **{
            **first.__dict__,
            "workload_id": "workload-2",
            "workload_digest": "b" * 64,
            "authentication_attempt_id": "auth-attempt-2",
        }
    )
    first_path = authentication_evidence_dir(tmp_path, first)
    second_path = authentication_evidence_dir(tmp_path, second)
    assert first_path != second_path
    assert first_path.parts[-7:-5] == ("workloads", "workload-1")
    assert second_path.parts[-7:-5] == ("workloads", "workload-2")


def test_unknown_state_cannot_bypass_result_schema() -> None:
    request = build_request()
    payload = {
        "schema_version": "1.0",
        "request": request.bindings(),
        "request_digest": request.request_digest,
        "authentication_request_id": request.authentication_request_id,
        "authentication_attempt_id": request.authentication_attempt_id,
        "decision_id": request.decision_id,
        "state": "trust_me",
        "reason_code": "approved",
        "transport_attempted": False,
        "workspace_verified": False,
        "identity_verified": False,
        "permissions_verified": False,
        "provider_request_id": None,
        "elapsed_ms": 0,
        "retryable": False,
        "evidence_refs": ["a", "b", "c", "d"],
        "generated": True,
        "authenticated": True,
        "submitted": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "blocked": False,
        "certified": False,
        "human_approved": False,
        "content_digest": "0" * 64,
    }
    try:
        validate_databricks_authentication_schema(
            "databricks-authentication-result.schema.json", payload
        )
    except ValueError as exc:
        assert "trust_me" in str(exc)
    else:
        raise AssertionError("Unknown authentication state bypassed the schema")
