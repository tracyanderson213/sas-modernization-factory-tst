"""Append-only persistence and recovery for DBX-03 compute decisions."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from smf.execution.databricks_compute_models import (
    ComputeSelectionRequest,
    ComputeSelectionResult,
    ComputeSelectionState,
)
from smf.execution.databricks_compute_schema import validate_databricks_compute_schema
from smf.readiness.policy import digest_value

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _authorized_regular_file(path: Path, root: Path) -> Path:
    """Resolve a file only when every component remains inside a non-symlink root."""

    root_resolved = root.resolve()
    if root.is_symlink() or not root_resolved.is_dir():
        raise ValueError("Authorized evidence root must be a regular directory")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Evidence path is outside the authorized root") from exc
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Evidence path is outside the authorized root")
    candidate = root / relative
    if any(
        root.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ):
        raise ValueError("Evidence path contains a symlink")
    try:
        mode = candidate.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise ValueError("Evidence file is missing") from exc
    if not stat.S_ISREG(mode) or not candidate.resolve().is_relative_to(root_resolved):
        raise ValueError("Evidence must be a regular file inside the authorized root")
    return candidate


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if not _SAFE.fullmatch(key_id):
        raise ValueError("Unsafe compute evidence signing key identity")
    return {
        **payload,
        "proof": {
            "algorithm": "ed25519",
            "key_id": key_id,
            "value": base64.b64encode(key.sign(_canonical(payload))).decode("ascii"),
        },
    }


def _verify(payload: dict[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> dict[str, Any]:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("Compute evidence lacks trusted proof")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("Compute evidence proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    try:
        signature = base64.b64decode(proof.get("value", ""), validate=True)
        keys[key_id].verify(signature, _canonical(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("Compute evidence proof is invalid") from exc
    return unsigned


def compute_evidence_dir(root: Path, request: ComputeSelectionRequest) -> Path:
    values = (
        request.run_id,
        request.workload_id,
        request.workflow_attempt_id,
        request.selection_attempt_id,
    )
    if any(not _SAFE.fullmatch(value) or value in {".", ".."} for value in values):
        raise ValueError("Unsafe compute evidence identity")
    path = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.workflow_attempt_id
        / "databricks-compute"
        / request.selection_attempt_id
    )
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Compute evidence path escapes output root")
    return path


def _compute_evidence_root(root: Path, request: ComputeSelectionRequest) -> Path:
    return compute_evidence_dir(root, request).parent


def _attempt_identity(request: ComputeSelectionRequest) -> tuple[str, str, str, str]:
    return (
        request.run_id,
        request.workload_id,
        request.workflow_attempt_id,
        request.selection_attempt_id,
    )


def _attempt_evidence_dirs(root: Path, request: ComputeSelectionRequest) -> list[Path]:
    """Locate stable and legacy evidence paths for one governed selection attempt."""

    base = _compute_evidence_root(root, request)
    stable = compute_evidence_dir(root, request)
    candidates: set[Path] = set()
    if (stable / "preparation.json").exists() or (stable / "result.json").exists():
        candidates.add(stable)
    if base.exists():
        for child in base.iterdir():
            if child == stable or child.is_symlink() or not child.is_dir():
                continue
            legacy = child / request.selection_attempt_id
            if (legacy / "preparation.json").exists() or (legacy / "result.json").exists():
                candidates.add(legacy)
    return sorted(candidates, key=lambda item: str(item))


def _publish(path: Path, payload: dict[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return False
        raise FileExistsError(f"Conflicting immutable compute evidence: {path}")
    descriptor, name = tempfile.mkstemp(prefix=".databricks-compute-", dir=path.parent)
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
                raise FileExistsError(f"Conflicting immutable compute evidence: {path}") from None
            return False
        return True
    finally:
        temporary.unlink(missing_ok=True)


def write_compute_preparation(
    root: Path,
    request: ComputeSelectionRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    validate_databricks_compute_schema("databricks-compute-request.schema.json", request.bindings())
    payload = {
        "schema_version": "1.0",
        "state": "prepared",
        "decision_id": request.decision_id,
        "request_digest": request.request_digest,
        "policy_bytes_sha256": request.policy_bytes_sha256,
        "request": request.bindings(),
    }
    payload["content_digest"] = digest_value(payload)
    directory = compute_evidence_dir(root, request)
    existing = _attempt_evidence_dirs(root, request)
    if any(candidate != directory for candidate in existing):
        raise FileExistsError("Conflicting or ambiguous immutable compute attempt evidence")
    path = directory / "preparation.json"
    _publish(path, _sign(payload, signing_key, key_id))
    return path


def compute_telemetry(result: ComputeSelectionResult) -> dict[str, Any]:
    request = result.request
    observation = result.availability_observation or {}
    return {
        "schema_version": "1.0",
        "event": "databricks_compute_selection_terminal",
        "client_id": request["client_id"],
        "workload_id": request["workload_id"],
        "run_id": request["run_id"],
        "attempt_id": request["workflow_attempt_id"],
        "selection_attempt_id": result.selection_attempt_id,
        "decision_id": result.decision_id,
        "evaluated_at": result.evaluated_at,
        "state": result.state.value,
        "reason_code": result.reason_code,
        "profile_id": result.selected_profile_id,
        "policy_id": request["policy_id"],
        "policy_version": request["policy_version"],
        "policy_digest": request["policy_digest"],
        "observation_id": observation.get("observation_id"),
        "observation_authority_ref": observation.get("authority_ref"),
        "observation_provider_version": observation.get("provider_version"),
        "observation_observed_at": observation.get("observed_at"),
        "observation_expires_at": observation.get("expires_at"),
        "quota_limit": observation.get("quota_limit"),
        "quota_used": observation.get("quota_used"),
        "generated": result.generated,
        "allocated": result.allocated,
        "submitted": result.submitted,
        "executed": result.executed,
        "validated": result.validated,
        "parity_passed": result.parity_passed,
        "human_assisted": result.human_assisted,
        "blocked": result.blocked,
        "certified": result.certified,
        "human_approved": result.human_approved,
    }


def write_compute_result(
    root: Path,
    request: ComputeSelectionRequest,
    result: ComputeSelectionResult,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    if (
        result.request != request.bindings()
        or result.request_digest != request.request_digest
        or result.decision_id != request.decision_id
        or result.selection_attempt_id != request.selection_attempt_id
    ):
        raise ValueError("Compute selection result binding mismatch")
    directory = compute_evidence_dir(root, request)
    if _attempt_evidence_dirs(root, request) != [directory]:
        raise ValueError("Compute selection attempt evidence is missing or ambiguous")
    preparation_path = directory / "preparation.json"
    try:
        preparation_request = load_compute_preparation(
            preparation_path, verification_keys={key_id: signing_key.public_key()}
        )
    except ValueError as exc:
        raise ValueError("Compute selection preparation is missing or invalid") from exc
    if preparation_request != request:
        raise ValueError("Compute selection preparation binding mismatch")
    path = directory / "result.json"
    validate_databricks_compute_schema("databricks-compute-result.schema.json", result.to_dict())
    _publish(path, _sign(result.to_dict(), signing_key, key_id))
    _publish(directory / "telemetry.json", compute_telemetry(result))
    return path


def _request_from_dict(value: dict[str, Any]) -> ComputeSelectionRequest:
    return ComputeSelectionRequest(**value)


def load_compute_preparation(
    path: Path,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
    authorized_root: Path | None = None,
) -> ComputeSelectionRequest:
    try:
        if authorized_root is not None:
            path = _authorized_regular_file(path, authorized_root)
        elif path.is_symlink() or not path.is_file():
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        unsigned = _verify(payload, verification_keys)
        content_digest = unsigned.pop("content_digest", None)
        request_value = unsigned.get("request")
        if not isinstance(request_value, dict):
            raise TypeError
        request = _request_from_dict(request_value)
        validate_databricks_compute_schema(
            "databricks-compute-request.schema.json", request.bindings()
        )
    except (OSError, TypeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Databricks compute preparation evidence") from exc
    if (
        content_digest != digest_value(unsigned)
        or unsigned.get("schema_version") != "1.0"
        or unsigned.get("state") != "prepared"
        or unsigned.get("decision_id") != request.decision_id
        or unsigned.get("request_digest") != request.request_digest
        or unsigned.get("policy_bytes_sha256") != request.policy_bytes_sha256
        or set(unsigned)
        != {
            "schema_version",
            "state",
            "decision_id",
            "request_digest",
            "policy_bytes_sha256",
            "request",
        }
    ):
        raise ValueError("Databricks compute preparation integrity mismatch")
    return request


def load_compute_result(
    path: Path,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
    authorized_root: Path | None = None,
) -> ComputeSelectionResult:
    try:
        if authorized_root is not None:
            path = _authorized_regular_file(path, authorized_root)
        elif path.is_symlink() or not path.is_file():
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        unsigned = _verify(payload, verification_keys)
        request = _request_from_dict(unsigned["request"])
        result = ComputeSelectionResult(
            **{
                **unsigned,
                "state": ComputeSelectionState(unsigned["state"]),
                "evidence_refs": tuple(unsigned["evidence_refs"]),
            }
        )
    except (OSError, TypeError, KeyError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Databricks compute result evidence") from exc
    value = result.to_dict()
    expected = value["content_digest"]
    value["content_digest"] = ""
    validate_databricks_compute_schema("databricks-compute-result.schema.json", result.to_dict())
    if (
        expected != digest_value(value)
        or result.request_digest != request.request_digest
        or result.selection_request_id != request.selection_request_id
        or result.selection_attempt_id != request.selection_attempt_id
        or result.decision_id != request.decision_id
    ):
        raise ValueError("Databricks compute result integrity mismatch")
    return result


def recover_compute_evidence(
    root: Path,
    request: ComputeSelectionRequest,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
    authorized_root: Path,
    source_path: Path | None = None,
    generated_path: Path | None = None,
    deployment_factory_path: Path | None = None,
    readiness_manifest_path: Path | None = None,
) -> ComputeSelectionResult | ComputeSelectionRequest | None:
    root_resolved = root.resolve()
    if root.is_symlink() or not root_resolved.is_relative_to(authorized_root.resolve()):
        raise ValueError("Compute evidence root is outside the authorized root")
    directories = _attempt_evidence_dirs(root, request)
    if not directories:
        return None
    if len(directories) != 1:
        raise ValueError("Ambiguous Databricks compute attempt evidence")
    directory = directories[0]
    captured_request = load_compute_preparation(
        directory / "preparation.json",
        verification_keys=verification_keys,
        authorized_root=authorized_root,
    )
    if _attempt_identity(captured_request) != _attempt_identity(request):
        raise ValueError("Recovered compute preparation attempt binding mismatch")
    stable = compute_evidence_dir(root, request)
    if directory != stable and (
        directory.name != request.selection_attempt_id
        or directory.parent.name != captured_request.selection_request_id
    ):
        raise ValueError("Recovered legacy compute preparation path binding mismatch")
    result_path = directory / "result.json"
    if not result_path.exists():
        return captured_request
    result = load_compute_result(
        result_path,
        verification_keys=verification_keys,
        authorized_root=authorized_root,
    )
    if (
        result.request != captured_request.bindings()
        or result.request_digest != captured_request.request_digest
        or result.decision_id != captured_request.decision_id
    ):
        raise ValueError("Recovered compute result binding mismatch")
    if any(
        item is None
        for item in (
            source_path,
            generated_path,
            deployment_factory_path,
            readiness_manifest_path,
        )
    ):
        raise ValueError("Governed replay inputs are incomplete")
    from smf.deployment.configuration import load_deployment_snapshot
    from smf.execution.databricks_compute import verify_compute_result

    assert source_path is not None
    assert generated_path is not None
    assert deployment_factory_path is not None
    assert readiness_manifest_path is not None
    source = _authorized_regular_file(source_path, authorized_root).read_bytes()
    generated = _authorized_regular_file(generated_path, authorized_root).read_bytes()
    factory = _authorized_regular_file(deployment_factory_path, authorized_root)
    readiness = _authorized_regular_file(readiness_manifest_path, authorized_root)
    deployment = load_deployment_snapshot(factory)
    verify_compute_result(
        result,
        request=captured_request,
        source_bytes=source,
        generated_bytes=generated,
        deployment_snapshot=deployment,
        readiness_manifest_path=readiness,
    )
    _publish(directory / "telemetry.json", compute_telemetry(result))
    return result
