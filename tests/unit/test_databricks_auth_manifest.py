import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.unit.test_databricks_auth_boundary import (
    Transport,
    request_and_receipt,
    response,
)

from smf.execution.databricks_auth import authenticate_databricks
from smf.execution.databricks_auth_manifest import (
    authentication_evidence_dir,
    claim_authentication_attempt,
    load_authentication_result,
    recover_authentication_evidence,
    write_authentication_preparation,
    write_authentication_result,
)
from smf.security.transient import TransientMaterial


def test_append_only_result_and_telemetry_recovery(tmp_path: Path) -> None:
    request, receipt = request_and_receipt()
    key = Ed25519PrivateKey.generate()
    keys = {"test-key": key.public_key()}
    write_authentication_preparation(tmp_path, request, signing_key=key, key_id="test-key")
    _, claimed = claim_authentication_attempt(tmp_path, request, signing_key=key, key_id="test-key")
    assert claimed is True
    _, claimed_again = claim_authentication_attempt(
        tmp_path, request, signing_key=key, key_id="test-key"
    )
    assert claimed_again is False
    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=Transport(response(request)),
    )
    result_path = write_authentication_result(
        tmp_path, request, result, signing_key=key, key_id="test-key"
    )
    assert load_authentication_result(result_path, verification_keys=keys) == result
    telemetry = result_path.with_name("telemetry.json")
    telemetry.unlink()
    assert recover_authentication_evidence(tmp_path, request, verification_keys=keys) == result
    assert telemetry.exists()
    assert "secret-canary" not in result_path.read_text(encoding="utf-8")


def test_claim_without_result_is_outcome_unknown_and_not_retried(tmp_path: Path) -> None:
    request, _ = request_and_receipt()
    key = Ed25519PrivateKey.generate()
    write_authentication_preparation(tmp_path, request, signing_key=key, key_id="test-key")
    claim_authentication_attempt(tmp_path, request, signing_key=key, key_id="test-key")
    with pytest.raises(RuntimeError, match="outcome is unknown"):
        recover_authentication_evidence(
            tmp_path, request, verification_keys={"test-key": key.public_key()}
        )


def test_conflicting_evidence_and_tampering_are_rejected(tmp_path: Path) -> None:
    request, receipt = request_and_receipt()
    key = Ed25519PrivateKey.generate()
    keys = {"test-key": key.public_key()}
    write_authentication_preparation(tmp_path, request, signing_key=key, key_id="test-key")
    claim_authentication_attempt(tmp_path, request, signing_key=key, key_id="test-key")
    result = authenticate_databricks(
        request,
        credential=TransientMaterial(b"secret-canary"),
        secret_receipt=receipt,
        transport=Transport(response(request)),
    )
    path = write_authentication_result(
        tmp_path, request, result, signing_key=key, key_id="test-key"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["authenticated"] = False
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid|integrity"):
        load_authentication_result(path, verification_keys=keys)
    assert authentication_evidence_dir(tmp_path, request).is_relative_to(tmp_path)
