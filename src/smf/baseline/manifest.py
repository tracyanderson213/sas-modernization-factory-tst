"""Append-only publication, replay verification, and derivative recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from smf.baseline.approved_export import (
    approval_subject_digest,
    receipt_digest,
    verify_approval,
    verify_receipt,
)
from smf.baseline.engine import PreparedBaselineAcquisition
from smf.baseline.policy import BaselineAcquisitionPolicy
from smf.baseline.schema import validate_result
from smf.baseline.telemetry import baseline_event
from smf.readiness.policy import digest_value
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe baseline acquisition identity")
    return value


def baseline_result_path(root: Path, payload: dict[str, Any]) -> Path:
    return (
        root
        / "runs"
        / _component(payload["run_id"])
        / "workloads"
        / _component(payload["workload_id"])
        / "attempts"
        / _component(payload["attempt_id"])
        / "baseline"
        / _component(payload["acquisition_id"])
        / "baseline.result.json"
    )


def _has_symlink_component(root: Path, path: Path) -> bool:
    try:
        parts = path.absolute().relative_to(root.absolute()).parts
    except ValueError:
        return True
    return any(
        root.absolute().joinpath(*parts[:index]).is_symlink() for index in range(1, len(parts) + 1)
    )


def _publish(path: Path, data: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            return
        raise FileExistsError(f"Conflicting immutable baseline {label}: {path}")
    descriptor, name = tempfile.mkstemp(prefix=".baseline-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise FileExistsError(f"Conflicting immutable baseline {label}: {path}") from None
        path.chmod(0o444)
    finally:
        temporary.unlink(missing_ok=True)


def _encoded(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate(
    root: Path, payload: dict[str, Any], trusted_policy: BaselineAcquisitionPolicy
) -> None:
    validate_result(payload)
    if payload["content_digest"] != digest_value({**payload, "content_digest": ""}):
        raise ValueError("Baseline result content digest mismatch")
    if (
        payload["policy_digest"] != trusted_policy.policy_digest
        or payload["policy_snapshot"] != trusted_policy.payload
    ):
        raise ValueError("Baseline result trusted policy binding mismatch")
    expected_id = stable_id(
        "BASE",
        {
            "acquisition_id": payload["acquisition_id"],
            "workload_id": payload["workload_id"],
            "workload_revision_id": payload["workload_revision_id"],
            "workload_digest": payload["workload_digest"],
            "boundary_id": payload["boundary_id"],
            "run_id": payload["run_id"],
            "attempt_id": payload["attempt_id"],
            "policy_digest": payload["policy_digest"],
        },
    )
    if payload["baseline_result_id"] != expected_id:
        raise ValueError("Baseline result identity mismatch")
    acquired = payload["disposition"] == "acquired"
    if payload["claims"]["baseline_acquired"] is not acquired:
        raise ValueError("Baseline acquisition claim does not match disposition")
    if any(
        payload["claims"][key]
        for key in (
            "generated",
            "executed",
            "validated",
            "parity_passed",
            "certified",
            "human_approved",
        )
    ):
        raise ValueError("Baseline result asserts an unauthorized downstream claim")
    receipt = payload["receipt_snapshot"]
    approval = payload["approval"]
    if payload["human_intervention"] is not (approval is not None):
        raise ValueError("Baseline human-intervention state is not attributable")
    producer_key: str | None = None
    if receipt is not None:
        if not isinstance(receipt, dict):
            raise ValueError("Baseline receipt snapshot is malformed")
        observed = datetime.fromisoformat(payload["acquired_at"].replace("Z", "+00:00"))
        producer_key = verify_receipt(receipt, trusted_policy, now=observed)
        expected_receipt = {
            "acquisition_id": payload["acquisition_id"],
            "client_id": payload["client_id"],
            "workload_id": payload["workload_id"],
            "workload_revision_id": payload["workload_revision_id"],
            "workload_digest": payload["workload_digest"],
            "closure_digest": payload["closure_digest"],
            "boundary_id": payload["boundary_id"],
            "run_id": payload["run_id"],
            "attempt_id": payload["attempt_id"],
            "acquisition_policy_digest": payload["policy_digest"],
            "provider": payload["provider"],
            "provider_version": payload["provider_version"],
        }
        if any(receipt.get(key) != value for key, value in expected_receipt.items()):
            raise ValueError("Baseline receipt-to-result binding mismatch")
        if (
            receipt["source_closure"] != payload["source_closure"]
            or receipt["input_snapshots"] != payload["input_snapshots"]
            or receipt["execution"] != payload["execution"]
            or receipt["execution"]["executed_at"] != receipt["executed_at"]
            or payload["receipt_digest"] != receipt_digest(receipt)
            or payload["approval_subject_digest"]
            != approval_subject_digest(receipt, payload["policy_digest"])
        ):
            raise ValueError("Baseline receipt evidence does not reconstruct the result")
    elif (
        any(
            payload[field] is not None
            for field in ("receipt_digest", "approval_subject_digest", "execution")
        )
        or payload["input_snapshots"]
    ):
        raise ValueError("Baseline result contains unbound receipt-derived evidence")

    decision_state: str | None = None
    if approval is not None:
        if not isinstance(approval, dict) or producer_key is None or receipt is None:
            raise ValueError("Baseline approval lacks producer evidence")
        observed = datetime.fromisoformat(payload["acquired_at"].replace("Z", "+00:00"))
        approval_time = observed
        if payload["blockers"] == ["approval_expired_or_not_yet_valid"]:
            approval_time = datetime.fromisoformat(approval["issued_at"].replace("Z", "+00:00"))
        decision_state, _ = verify_approval(
            approval,
            receipt,
            trusted_policy,
            producer_key_id=producer_key,
            now=approval_time,
        )
        expected_disposition = {
            "approved": "acquired",
            "pending": "human_required",
            "denied": "blocked",
        }[decision_state]
        if payload["blockers"] == ["approval_expired_or_not_yet_valid"]:
            issued = datetime.fromisoformat(approval["issued_at"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
            if issued <= observed < expires or payload["disposition"] != "needs_evidence":
                raise ValueError("Baseline expired-approval disposition is invalid")
        elif payload["disposition"] != expected_disposition:
            raise ValueError("Baseline approval state does not match disposition")
    elif receipt is not None and (
        payload["disposition"] != "needs_evidence" or payload["blockers"] != ["approval_missing"]
    ):
        raise ValueError("Baseline missing-approval disposition is invalid")

    if acquired:
        if decision_state != "approved" or not payload["outputs"] or receipt is None:
            raise ValueError(
                "Acquired baseline lacks reconstructable producer or approval evidence"
            )
        receipt_outputs = []
        for item in receipt["outputs"]:
            artifact_uri = (
                (baseline_result_path(root, payload).parent / "artifacts" / item["content_digest"])
                .relative_to(root)
                .as_posix()
            )
            receipt_outputs.append(
                {
                    key: value
                    for key, value in {**item, "artifact_uri": artifact_uri}.items()
                    if key not in {"artifact_path", "status", "origin"}
                }
            )
        if payload["outputs"] != receipt_outputs:
            raise ValueError("Baseline output inventory does not reconstruct the signed receipt")
        for output in payload["outputs"]:
            lexical = root / output["artifact_uri"]
            expected_lexical = (
                baseline_result_path(root, payload).parent / "artifacts" / output["content_digest"]
            )
            path = lexical.resolve()
            expected = expected_lexical.resolve()
            if (
                lexical.absolute() != expected_lexical.absolute()
                or _has_symlink_component(root, lexical)
                or path != expected
                or not path.is_relative_to(root.resolve())
                or not path.is_file()
                or path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise ValueError("Baseline output artifact is missing, mutable, or unsafe")
            data = path.read_bytes()
            if (
                len(data) != output["byte_count"]
                or hashlib.sha256(data).hexdigest() != output["content_digest"]
            ):
                raise ValueError("Baseline output artifact digest mismatch")
    elif payload["outputs"]:
        raise ValueError("Non-acquired baseline result contains authoritative outputs")


def load_baseline_result(
    path: Path, *, output_root: Path, trusted_policy: BaselineAcquisitionPolicy
) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Baseline result must be an object")
    _validate(output_root, raw, trusted_policy)
    expected_path = baseline_result_path(output_root, raw)
    if (
        path.absolute() != expected_path.absolute()
        or _has_symlink_component(output_root, path)
        or path.resolve() != expected_path.resolve()
    ):
        raise ValueError("Baseline result is outside its canonical evidence path")
    return raw


def recover_baseline_result(
    path: Path, *, output_root: Path, trusted_policy: BaselineAcquisitionPolicy
) -> Path:
    """Recover missing deterministic projections without re-reading the export package."""

    canonical = load_baseline_result(path, output_root=output_root, trusted_policy=trusted_policy)
    return write_baseline_result(
        output_root,
        PreparedBaselineAcquisition(canonical),
        trusted_policy=trusted_policy,
    )


def readiness_evidence(result: dict[str, Any]) -> list[dict[str, Any]]:
    if result["disposition"] != "acquired":
        return []
    evidence: list[dict[str, Any]] = []
    result_uri = (
        Path("runs")
        / result["run_id"]
        / "workloads"
        / result["workload_id"]
        / "attempts"
        / result["attempt_id"]
        / "baseline"
        / result["acquisition_id"]
        / "baseline.result.json"
    ).as_posix()
    for output in result["outputs"]:
        evidence.append(
            {
                "schema_version": "1.0",
                "evidence_id": stable_id(
                    "BEV", {"result": result["baseline_result_id"], "output": output["output_id"]}
                ),
                "kind": "baseline",
                "status": "pass",
                "client_id": result["client_id"],
                "workload_id": result["workload_id"],
                "workload_revision_id": result["workload_revision_id"],
                "workload_digest": result["workload_digest"],
                "qualified_boundary_id": result["boundary_id"],
                "subject_id": output["dataset_id"],
                "output_id": output["output_id"],
                "checksum": output["content_digest"],
                "artifact_uri": output["artifact_uri"],
                "artifact_digest": output["content_digest"],
                "schema_digest": output["schema_digest"],
                "measurement_ids": ["content", "schema"],
                "authority": result["receipt_snapshot"]["producer_authority"],
                "acquisition_source": "governed-baseline-store",
                "source_execution_id": result["execution"]["sas_execution_id"],
                "observed_at": result["execution"]["executed_at"],
                "baseline_result_id": result["baseline_result_id"],
                "acquisition_id": result["acquisition_id"],
                "acquisition_mode": result["acquisition_mode"],
                "acquisition_policy_digest": result["policy_digest"],
                "execution_receipt_digest": result["receipt_digest"],
                "input_snapshot_digest": digest_value(result["input_snapshots"]),
                "runtime_configuration_digest": result["execution"]["runtime_configuration_digest"],
                "evidence_run_id": result["run_id"],
                "evidence_attempt_id": result["attempt_id"],
                "result_uri": result_uri,
                "result_digest": result["content_digest"],
            }
        )
    return evidence


def write_baseline_result(
    root: Path,
    prepared: PreparedBaselineAcquisition,
    *,
    trusted_policy: BaselineAcquisitionPolicy,
) -> Path:
    payload = prepared.result
    path = baseline_result_path(root, payload)
    if not path.parent.resolve().is_relative_to(root.resolve()) or _has_symlink_component(
        root, path.parent
    ):
        raise ValueError("Baseline acquisition output escapes root")
    for digest, data in prepared.output_bytes:
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Qualified baseline output changed before publication")
        _publish(path.parent / "artifacts" / digest, data, "output artifact")
    _validate(root, payload, trusted_policy)
    _publish(path, _encoded(payload), "result")
    canonical = load_baseline_result(path, output_root=root, trusted_policy=trusted_policy)
    if canonical["receipt_snapshot"] is not None:
        _publish(
            path.with_name("source-receipt.json"),
            _encoded(canonical["receipt_snapshot"]),
            "receipt",
        )
    _publish(path.with_name("telemetry.json"), _encoded(baseline_event(canonical)), "telemetry")
    _publish(
        path.with_name("readiness-evidence.json"),
        _encoded({"evidence": readiness_evidence(canonical)}),
        "readiness projection",
    )
    return path
