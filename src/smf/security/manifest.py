"""Append-only receipt persistence with idempotent telemetry repair."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from smf.readiness.policy import digest_value
from smf.security.models import SecretResolutionReceipt, SecretResolutionRequest
from smf.security.schema import validate_security_schema
from smf.security.telemetry import secret_resolution_event

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUEST_FIELDS = {
    "schema_version",
    "client_id",
    "deployment_id",
    "environment_id",
    "workload_id",
    "workload_digest",
    "boundary_id",
    "subject_id",
    "source_sha256",
    "run_id",
    "attempt_id",
    "consumer_id",
    "consumer_contract_version",
    "identity_binding_id",
    "secret_binding_id",
    "security_policy_id",
    "security_policy_version",
    "security_policy_digest",
    "configuration_digest",
    "readiness_result_id",
    "readiness_manifest_digest",
    "qualified_snapshot_ref",
    "activation_evidence_id",
    "activation_evidence_digest",
}


def _component(value: str, label: str) -> str:
    if not _SAFE.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    return value


def receipt_path(root: Path, receipt: SecretResolutionReceipt) -> Path:
    request = receipt.request
    return (
        root
        / "runs"
        / _component(request["run_id"], "run_id")
        / "workloads"
        / _component(request["workload_id"], "workload_id")
        / "attempts"
        / _component(request["attempt_id"], "attempt_id")
        / "security"
        / _component(receipt.resolution_id, "resolution_id")
        / "secret-resolution.receipt.json"
    )


def validate_receipt_payload(payload: dict[str, Any]) -> None:
    """Validate the complete canonical secret-receipt contract."""

    validate_security_schema("secret-resolution-result.schema.json", payload)
    if set(payload.get("request", {})) != _REQUEST_FIELDS:
        raise ValueError("Secret receipt request binding inventory mismatch")
    try:
        SecretResolutionRequest(**payload["request"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Secret receipt request binding is invalid") from exc
    if payload.get("provider") != "hashicorp-vault":
        raise ValueError("Secret receipt provider is unsupported")
    expected_resolution_id = digest_value(
        {"contract": "smf-secret-resolution-v1", **payload["request"]}
    )
    if payload.get("resolution_id") != expected_resolution_id:
        raise ValueError("Secret receipt resolution identity mismatch")
    if payload.get("state") == "resolved" and (
        payload.get("reason_code") != "resolved"
        or payload.get("decision_id") == "unverified"
        or payload.get("transport_attempted") is not True
        or payload.get("lease") is None
        or payload.get("terminal_disposition") != "secret_available_transiently"
    ):
        raise ValueError("Resolved secret receipt is not reconstructable")
    if payload.get("state") != "resolved" and payload.get("terminal_disposition") != "not_resolved":
        raise ValueError("Non-success secret receipt disposition mismatch")
    if payload.get("evidence_refs") != [
        payload["request"]["readiness_result_id"],
        payload["request"]["activation_evidence_id"],
    ]:
        raise ValueError("Secret receipt evidence references are not request-bound")
    retryable = payload.get("state") in {"provider_unavailable", "timed_out"}
    if payload.get("retryable") is not retryable:
        raise ValueError("Secret receipt retry semantics mismatch")
    expected = payload.get("content_digest")
    unsigned = dict(payload)
    unsigned["content_digest"] = ""
    if expected != digest_value(unsigned):
        raise ValueError("Secret receipt content digest mismatch")
    if any(
        payload.get(flag) is not False
        for flag in (
            "generated",
            "executed",
            "validated",
            "parity_passed",
            "certified",
            "human_approved",
        )
    ):
        raise ValueError("Secret receipt cannot assert downstream success")


def load_receipt(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Secret receipt must be an object")
    validate_receipt_payload(value)
    return value


def _publish(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return
        raise FileExistsError(f"Conflicting immutable security evidence: {path}")
    descriptor, name = tempfile.mkstemp(prefix=".security-evidence-", dir=path.parent)
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
                raise FileExistsError(f"Conflicting immutable security evidence: {path}") from None
    finally:
        temporary.unlink(missing_ok=True)


def write_receipt(root: Path, receipt: SecretResolutionReceipt) -> Path:
    path = receipt_path(root, receipt)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Secret receipt path escapes output root")
    payload = receipt.to_dict()
    validate_receipt_payload(payload)
    _publish(path, payload)
    canonical = load_receipt(path)
    _publish(path.with_name("secret-resolution.telemetry.json"), secret_resolution_event(canonical))
    return path
