"""Append-only Databricks authentication evidence and restart recovery."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from smf.execution.databricks_auth_models import (
    DatabricksAuthenticationRequest,
    DatabricksAuthenticationResult,
    DatabricksAuthenticationState,
    DatabricksPermissionProbe,
    PermissionKind,
)
from smf.execution.databricks_auth_schema import validate_databricks_authentication_schema
from smf.readiness.policy import digest_value

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if not _SAFE.fullmatch(key_id):
        raise ValueError("Unsafe Databricks authentication signing key identity")
    signed = dict(payload)
    signed["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(_canonical(payload))).decode("ascii"),
    }
    return signed


def _verify(payload: dict[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Databricks authentication evidence lacks trusted proof")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("Databricks authentication evidence proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    try:
        signature = base64.b64decode(proof.get("value", ""), validate=True)
        keys[key_id].verify(signature, _canonical(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Databricks authentication evidence proof is invalid") from exc


def authentication_evidence_dir(root: Path, request: DatabricksAuthenticationRequest) -> Path:
    for value in (
        request.run_id,
        request.workload_id,
        request.workflow_attempt_id,
        request.authentication_request_id,
        request.authentication_attempt_id,
    ):
        if not _SAFE.fullmatch(value) or value in {".", ".."}:
            raise ValueError("Unsafe Databricks authentication evidence identity")
    path = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.workflow_attempt_id
        / "databricks-auth"
        / request.authentication_request_id
        / request.authentication_attempt_id
    )
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Databricks authentication evidence path escapes output root")
    return path


def _publish(path: Path, payload: dict[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return False
        raise FileExistsError(f"Conflicting immutable Databricks authentication evidence: {path}")
    descriptor, name = tempfile.mkstemp(prefix=".databricks-auth-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if json.loads(path.read_text(encoding="utf-8")) != payload:
                raise FileExistsError(
                    f"Conflicting immutable Databricks authentication evidence: {path}"
                ) from None
            return False
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _load_bound_record(
    path: Path,
    request: DatabricksAuthenticationRequest,
    state: str,
    verification_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        _verify(payload, verification_keys)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Databricks authentication control evidence") from exc
    unsigned = dict(payload)
    unsigned.pop("proof")
    content_digest = unsigned.pop("content_digest", None)
    if (
        content_digest != digest_value(unsigned)
        or unsigned.get("state") != state
        or unsigned.get("decision_id") != request.decision_id
        or unsigned.get("request_digest") != request.request_digest
    ):
        raise ValueError("Databricks authentication control evidence binding mismatch")
    return payload


def write_authentication_preparation(
    root: Path,
    request: DatabricksAuthenticationRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    validate_databricks_authentication_schema(
        "databricks-authentication-request.schema.json", request.bindings()
    )
    payload = {
        "schema_version": "1.0",
        "state": "prepared",
        "decision_id": request.decision_id,
        "request_digest": request.request_digest,
        "request": request.bindings(),
    }
    payload["content_digest"] = digest_value(payload)
    path = authentication_evidence_dir(root, request) / "preparation.json"
    _publish(path, _sign(payload, signing_key, key_id))
    return path


def claim_authentication_attempt(
    root: Path,
    request: DatabricksAuthenticationRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> tuple[Path, bool]:
    payload = {
        "schema_version": "1.0",
        "state": "authentication_started",
        "decision_id": request.decision_id,
        "request_digest": request.request_digest,
    }
    payload["content_digest"] = digest_value(payload)
    path = authentication_evidence_dir(root, request) / "attempt.json"
    return path, _publish(path, _sign(payload, signing_key, key_id))


def authentication_telemetry(result: DatabricksAuthenticationResult) -> dict[str, Any]:
    request = result.request
    return {
        "schema_version": "1.0",
        "event": "databricks_authentication_terminal",
        "client_id": request["client_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["workflow_attempt_id"],
        "authentication_request_id": result.authentication_request_id,
        "authentication_attempt_id": result.authentication_attempt_id,
        "decision_id": result.decision_id,
        "state": result.state.value,
        "reason_code": result.reason_code,
        "retry_ordinal": request["retry_ordinal"],
        "workspace_probe_attempted": result.transport_attempted,
        "identity_verified": result.identity_verified,
        "permissions_verified": result.permissions_verified,
        "elapsed_ms": result.elapsed_ms,
        "generated": result.generated,
        "authenticated": result.authenticated,
        "submitted": result.submitted,
        "executed": result.executed,
        "validated": result.validated,
        "parity_passed": result.parity_passed,
        "human_assisted": result.human_assisted,
        "blocked": result.blocked,
        "certified": result.certified,
        "human_approved": result.human_approved,
    }


def write_authentication_result(
    root: Path,
    request: DatabricksAuthenticationRequest,
    result: DatabricksAuthenticationResult,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    if (
        result.request_digest != request.request_digest
        or result.decision_id != request.decision_id
        or result.authentication_attempt_id != request.authentication_attempt_id
    ):
        raise ValueError("Databricks authentication result binding mismatch")
    directory = authentication_evidence_dir(root, request)
    verification_keys = {key_id: signing_key.public_key()}
    _load_bound_record(directory / "preparation.json", request, "prepared", verification_keys)
    marker = directory / "attempt.json"
    _load_bound_record(marker, request, "authentication_started", verification_keys)
    payload = result.to_dict()
    validate_databricks_authentication_schema(
        "databricks-authentication-result.schema.json", payload
    )
    path = directory / "result.json"
    _publish(path, _sign(payload, signing_key, key_id))
    _publish(directory / "telemetry.json", authentication_telemetry(result))
    return path


def _request_from_payload(payload: dict[str, Any]) -> DatabricksAuthenticationRequest:
    request = dict(payload)
    probes = request.get("permission_probes")
    if not isinstance(probes, list):
        raise ValueError("Authentication request permission inventory is invalid")
    request["permission_probes"] = tuple(
        DatabricksPermissionProbe(
            probe_id=item["probe_id"],
            kind=PermissionKind(item["kind"]),
            resource_binding_id=item["resource_binding_id"],
        )
        for item in probes
    )
    return DatabricksAuthenticationRequest(**request)


def load_authentication_result(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> DatabricksAuthenticationResult:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        _verify(payload, verification_keys)
        unsigned_payload = dict(payload)
        unsigned_payload.pop("proof")
        request = _request_from_payload(unsigned_payload["request"])
        result = DatabricksAuthenticationResult(
            **{
                **unsigned_payload,
                "state": DatabricksAuthenticationState(unsigned_payload["state"]),
                "evidence_refs": tuple(unsigned_payload["evidence_refs"]),
            }
        )
    except (OSError, TypeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Databricks authentication result evidence") from exc
    unsigned = result.to_dict()
    expected = unsigned["content_digest"]
    unsigned["content_digest"] = ""
    validate_databricks_authentication_schema(
        "databricks-authentication-result.schema.json", result.to_dict()
    )
    if (
        expected != digest_value(unsigned)
        or result.request_digest != request.request_digest
        or result.authentication_request_id != request.authentication_request_id
        or result.decision_id != request.decision_id
    ):
        raise ValueError("Databricks authentication result integrity mismatch")
    return result


def recover_authentication_evidence(
    root: Path,
    request: DatabricksAuthenticationRequest,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
) -> DatabricksAuthenticationResult | None:
    """Recover terminal evidence/telemetry; a claimed unknown outcome is never retried."""

    directory = authentication_evidence_dir(root, request)
    result_path = directory / "result.json"
    if result_path.exists():
        result = load_authentication_result(result_path, verification_keys=verification_keys)
        if (
            result.request_digest != request.request_digest
            or result.decision_id != request.decision_id
        ):
            raise ValueError("Recovered Databricks authentication result binding mismatch")
        _publish(directory / "telemetry.json", authentication_telemetry(result))
        return result
    marker = directory / "attempt.json"
    if marker.exists():
        _load_bound_record(directory / "preparation.json", request, "prepared", verification_keys)
        _load_bound_record(marker, request, "authentication_started", verification_keys)
        raise RuntimeError("Databricks authentication outcome is unknown; retry is prohibited")
    return None
