"""Fail-closed orchestration for trusted SAS baseline acquisition."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from smf.baseline.approved_export import (
    acquire_output_bytes,
    approval_subject_digest,
    receipt_digest,
    verify_approval,
    verify_receipt,
)
from smf.baseline.models import AcquisitionDisposition, AcquisitionMode, BaselineAcquisitionRequest
from smf.baseline.policy import BaselineAcquisitionPolicy, load_baseline_policy
from smf.baseline.schema import validate_request, validate_result
from smf.intake import load_intake_result, verify_intake_workload
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True)
class PreparedBaselineAcquisition:
    result: dict[str, Any]
    output_bytes: tuple[tuple[str, bytes], ...] = ()


def _identity(value: str, label: str) -> str:
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"Unsafe baseline {label}")
    return value


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be an object")
    return raw


def _boundary_subject(
    intake: dict[str, Any], workload_id: str, boundary_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches = [item for item in intake["decisions"] if item["workload_id"] == workload_id]
    if len(matches) != 1 or matches[0]["state"] != "admitted":
        raise ValueError("Baseline workload identity is missing, ambiguous, or not admitted")
    workload = matches[0]["discovery"]
    boundaries = [item for item in workload["boundaries"] if item["boundary_id"] == boundary_id]
    if len(boundaries) != 1:
        raise ValueError("Baseline boundary identity is missing or ambiguous")
    return workload, boundaries[0]


def _base_result(
    request: BaselineAcquisitionRequest,
    policy: BaselineAcquisitionPolicy,
    *,
    mode: AcquisitionMode,
    workload: dict[str, Any],
    source_closure: list[dict[str, Any]],
    acquired_at: str,
    elapsed_ms: int,
) -> dict[str, Any]:
    identity = {
        "acquisition_id": request.acquisition_id,
        "workload_id": request.workload_id,
        "workload_revision_id": request.workload_revision_id,
        "workload_digest": digest_value(workload),
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "policy_digest": policy.policy_digest,
    }
    return {
        "schema_version": "1.0",
        "baseline_result_id": stable_id("BASE", identity),
        "acquisition_id": request.acquisition_id,
        "acquisition_mode": mode.value,
        "client_id": policy.payload["client_id"],
        "workload_id": request.workload_id,
        "workload_revision_id": request.workload_revision_id,
        "workload_digest": digest_value(workload),
        "closure_digest": request.closure_digest,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "policy_id": policy.payload["policy_id"],
        "policy_version": policy.payload["policy_version"],
        "policy_digest": policy.policy_digest,
        "provider": policy.payload["provider"],
        "provider_version": policy.payload["provider_version"],
        "source_closure": source_closure,
        "input_snapshots": [],
        "execution": None,
        "receipt_digest": None,
        "approval_subject_digest": None,
        "approval": None,
        "outputs": [],
        "disposition": AcquisitionDisposition.BLOCKED.value,
        "blockers": [],
        "human_intervention": False,
        "acquired_at": acquired_at,
        "elapsed_ms": elapsed_ms,
        "claims": {
            "baseline_acquired": False,
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_approved": False,
        },
        "policy_snapshot": json.loads(json.dumps(policy.payload)),
        "receipt_snapshot": None,
        "content_digest": "",
    }


def _finalize(payload: dict[str, Any]) -> dict[str, Any]:
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    validate_result(payload)
    return payload


def evaluate_baseline_acquisition(
    request: BaselineAcquisitionRequest, *, _now: datetime | None = None
) -> PreparedBaselineAcquisition:
    """Verify one acquisition attempt without publishing any caller-owned bytes."""

    started = time.monotonic_ns()
    validate_request(
        {
            "schema_version": "1.0",
            "acquisition_id": request.acquisition_id,
            "mode": str(request.mode),
            "workload_id": request.workload_id,
            "workload_revision_id": request.workload_revision_id,
            "closure_digest": request.closure_digest,
            "boundary_id": request.boundary_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
        }
    )
    for label in (
        "acquisition_id",
        "workload_id",
        "workload_revision_id",
        "closure_digest",
        "boundary_id",
        "run_id",
        "attempt_id",
    ):
        _identity(str(getattr(request, label)), label)
    try:
        mode = AcquisitionMode(request.mode)
    except ValueError as exc:
        raise ValueError("Unsupported baseline acquisition mode") from exc
    policy = load_baseline_policy(request.policy_path)
    if mode.value not in policy.payload["allowed_modes"]:
        raise ValueError("Baseline acquisition mode is not allowed by policy")
    verified = verify_intake_workload(
        request.intake_result_path,
        output_root=request.output_root,
        trusted_policy=request.intake_policy,
        workload_id=request.workload_id,
        workload_revision_id=request.workload_revision_id,
        closure_digest=request.closure_digest,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
    )
    intake = load_intake_result(
        request.intake_result_path,
        output_root=request.output_root,
        trusted_policy=request.intake_policy,
    )
    if intake["client_id"] != policy.payload["client_id"]:
        raise ValueError("Baseline client does not match admitted intake")
    workload, boundary = _boundary_subject(intake, request.workload_id, request.boundary_id)
    source_closure: list[dict[str, Any]] = [
        {
            "script_id": item.script_id,
            "logical_path": item.logical_path,
            "sha256": item.sha256,
            "byte_count": len(item.data),
        }
        for item in verified.sources
    ]
    source_closure.sort(key=lambda item: str(item["script_id"]))
    now = _now or datetime.now(UTC)
    acquired_at = now.isoformat()
    elapsed = int((time.monotonic_ns() - started) / 1_000_000)
    payload = _base_result(
        request,
        policy,
        mode=mode,
        workload=workload,
        source_closure=source_closure,
        acquired_at=acquired_at,
        elapsed_ms=elapsed,
    )
    if mode is AcquisitionMode.SAS_EXECUTION:
        payload["blockers"] = ["sas_execution_provider_unavailable"]
        return PreparedBaselineAcquisition(_finalize(payload))
    if request.package_root is None or request.receipt_path is None:
        payload["blockers"] = ["approved_export_package_missing"]
        payload["disposition"] = AcquisitionDisposition.NEEDS_EVIDENCE.value
        return PreparedBaselineAcquisition(_finalize(payload))
    package_root = request.package_root.resolve()
    if request.package_root.is_symlink() or not package_root.is_dir():
        raise ValueError("Baseline export package root is missing or unsafe")
    receipt_path = request.receipt_path.resolve()
    try:
        receipt_parts = request.receipt_path.absolute().relative_to(package_root).parts
    except ValueError as exc:
        raise ValueError("Baseline export receipt escapes package root") from exc
    if (
        request.receipt_path.is_symlink()
        or any(
            package_root.joinpath(*receipt_parts[:index]).is_symlink()
            for index in range(1, len(receipt_parts) + 1)
        )
        or not receipt_path.is_relative_to(package_root)
    ):
        raise ValueError("Baseline export receipt escapes package root")
    receipt = _load_object(receipt_path, "Baseline export receipt")
    producer_key_id = verify_receipt(receipt, policy, now=now)
    expected = {
        "acquisition_id": request.acquisition_id,
        "client_id": policy.payload["client_id"],
        "workload_id": request.workload_id,
        "workload_revision_id": request.workload_revision_id,
        "workload_digest": digest_value(workload),
        "closure_digest": request.closure_digest,
        "boundary_id": request.boundary_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "acquisition_policy_digest": policy.policy_digest,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("Baseline export receipt identity binding mismatch")
    if receipt["source_closure"] != source_closure:
        raise ValueError("Baseline export source closure does not match admitted source bytes")
    if receipt["execution"]["executed_at"] != receipt["executed_at"]:
        raise ValueError("Baseline export execution timestamp binding mismatch")
    canonical_outputs = {
        item["output_id"]: item["dataset_id"] for item in workload.get("outputs", [])
    }
    selected_output_ids = set(boundary.get("output_ids", []))
    receipt_output_ids = {item["output_id"] for item in receipt["outputs"]}
    if not selected_output_ids or receipt_output_ids != selected_output_ids:
        raise ValueError("Baseline export output inventory does not match selected boundary")
    if any(
        canonical_outputs.get(item["output_id"]) != item["dataset_id"]
        for item in receipt["outputs"]
    ):
        raise ValueError("Baseline export output dataset binding mismatch")
    input_dataset_ids = {
        item["target_id"]
        for item in workload.get("relationships", [])
        if item.get("kind") in {"reads", "consumes"}
        and item.get("source_id") in set(boundary.get("artifact_ids", []))
    }
    supplied_inputs = [item["dataset_id"] for item in receipt["input_snapshots"]]
    if (
        len(supplied_inputs) != len(set(supplied_inputs))
        or set(supplied_inputs) != input_dataset_ids
    ):
        raise ValueError("Baseline export input snapshot inventory is incomplete or ambiguous")
    if request.approval_path is None:
        payload.update(
            receipt_digest=receipt_digest(receipt),
            approval_subject_digest=approval_subject_digest(receipt, policy.policy_digest),
            receipt_snapshot=receipt,
            input_snapshots=receipt["input_snapshots"],
            execution=receipt["execution"],
            disposition=AcquisitionDisposition.NEEDS_EVIDENCE.value,
            blockers=["approval_missing"],
        )
        return PreparedBaselineAcquisition(_finalize(payload))
    approval = _load_object(request.approval_path, "Baseline acquisition decision")
    try:
        decision_state, _ = verify_approval(
            approval, receipt, policy, producer_key_id=producer_key_id, now=now
        )
    except ValueError as exc:
        if "not currently valid" not in str(exc):
            raise
        payload.update(
            receipt_digest=receipt_digest(receipt),
            approval_subject_digest=approval_subject_digest(receipt, policy.policy_digest),
            receipt_snapshot=receipt,
            input_snapshots=receipt["input_snapshots"],
            execution=receipt["execution"],
            approval=approval,
            disposition=AcquisitionDisposition.NEEDS_EVIDENCE.value,
            blockers=["approval_expired_or_not_yet_valid"],
            human_intervention=True,
        )
        return PreparedBaselineAcquisition(_finalize(payload))
    common = {
        "receipt_digest": receipt_digest(receipt),
        "approval_subject_digest": approval_subject_digest(receipt, policy.policy_digest),
        "receipt_snapshot": receipt,
        "input_snapshots": receipt["input_snapshots"],
        "execution": receipt["execution"],
        "approval": approval,
        "human_intervention": True,
    }
    if decision_state == "pending":
        payload.update(**common, disposition=AcquisitionDisposition.HUMAN_REQUIRED.value)
        payload["blockers"] = ["approval_pending"]
        return PreparedBaselineAcquisition(_finalize(payload))
    if decision_state == "denied":
        payload.update(**common, disposition=AcquisitionDisposition.BLOCKED.value)
        payload["blockers"] = ["approval_denied"]
        return PreparedBaselineAcquisition(_finalize(payload))
    acquired = acquire_output_bytes(receipt, package_root, policy)
    output_records: list[dict[str, Any]] = []
    bytes_to_publish: list[tuple[str, bytes]] = []
    for item in acquired:
        data = item["data"]
        relative = (
            Path("runs")
            / request.run_id
            / "workloads"
            / request.workload_id
            / "attempts"
            / request.attempt_id
            / "baseline"
            / request.acquisition_id
            / "artifacts"
            / item["content_digest"]
        ).as_posix()
        output_records.append(
            {
                key: value
                for key, value in {**item, "artifact_uri": relative}.items()
                if key not in {"data", "artifact_path", "status", "origin"}
            }
        )
        bytes_to_publish.append((item["content_digest"], data))
    payload.update(
        **common,
        outputs=output_records,
        disposition=AcquisitionDisposition.ACQUIRED.value,
        blockers=[],
    )
    payload["claims"]["baseline_acquired"] = True
    return PreparedBaselineAcquisition(_finalize(payload), tuple(bytes_to_publish))
