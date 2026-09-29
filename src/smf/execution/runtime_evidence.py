"""Offline, fail-closed DBX-04 runtime-evidence receipts.

This module records only bounded synthetic observations.  It never submits work,
contacts Databricks, or upgrades synthetic observations into execution authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator

from smf.execution.databricks_remote import (
    CurrentRemoteEvidence,
    RemoteExecutionRequest,
    verify_remote_execution_plan,
)
from smf.immutable_files import publish_json, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REFERENCE = re.compile(r"^evidence://[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe DBX-04 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"DBX-04 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"DBX-04 {label} is not canonical RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"DBX-04 {label} is not canonical RFC3339 UTC")
    return parsed


@dataclass(frozen=True)
class RuntimeEvidenceRequest:
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    package_id: str
    package_digest: str
    execution_plan_id: str
    execution_plan_digest: str
    evaluation_time: str

    def binding(self) -> dict[str, str]:
        for name in (
            "client_id",
            "deployment_id",
            "environment_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "package_id",
            "execution_plan_id",
        ):
            _safe(getattr(self, name), name)
        for name in ("package_digest", "execution_plan_digest"):
            _sha(getattr(self, name), name)
        _time(self.evaluation_time, "evaluation_time")
        return asdict(self)


@dataclass(frozen=True)
class TaskObservation:
    state: Literal["queued", "running", "succeeded", "failed", "cancelled", "outcome_unknown"]
    observed_at: str

    def binding(self) -> dict[str, str]:
        if self.state not in {
            "queued",
            "running",
            "succeeded",
            "failed",
            "cancelled",
            "outcome_unknown",
        }:
            raise ValueError("DBX-04 task observation state is invalid")
        _time(self.observed_at, "task observed_at")
        return asdict(self)


@dataclass(frozen=True)
class OutputReference:
    reference: str
    content_digest: str
    valid_until: str

    def binding(self) -> dict[str, str]:
        if (
            not isinstance(self.reference, str)
            or not _REFERENCE.fullmatch(self.reference)
            or ".." in self.reference.split("/")
            or contains_protected_data(self.reference)
        ):
            raise ValueError("DBX-04 output reference is unsafe")
        _sha(self.content_digest, "output content_digest")
        _time(self.valid_until, "output valid_until")
        return asdict(self)


@dataclass(frozen=True)
class SyntheticRuntimeObservation:
    evidence_class: Literal["synthetic_contract"]
    observation_id: str
    remote_run_id: str | None
    remote_task_id: str | None
    tasks: tuple[TaskObservation, ...]
    safe_logs: tuple[str, ...]
    outputs: tuple[OutputReference, ...]
    elapsed_seconds: int | None = None
    machine_seconds: int | None = None

    def binding(self) -> dict[str, Any]:
        if self.evidence_class != "synthetic_contract":
            raise ValueError("DBX-04 accepts only synthetic contract observations")
        _safe(self.observation_id, "observation_id")
        for name in ("remote_run_id", "remote_task_id"):
            value = getattr(self, name)
            if value is not None:
                _safe(value, name)
        if (self.remote_run_id is None) != (self.remote_task_id is None):
            raise ValueError("DBX-04 remote identities must be present or absent together")
        if len(self.tasks) > 1_000 or len(self.safe_logs) > 100 or len(self.outputs) > 100:
            raise ValueError("DBX-04 observation exceeds bounded evidence limits")
        for name in ("elapsed_seconds", "machine_seconds"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 0):
                raise ValueError(f"DBX-04 {name} is invalid")
        logs: list[str] = []
        for entry in self.safe_logs:
            if (
                not isinstance(entry, str)
                or not entry
                or len(entry) > 512
                or contains_protected_data(entry)
            ):
                raise ValueError("DBX-04 log entry is unsafe")
            logs.append(entry)
        return {
            "evidence_class": self.evidence_class,
            "observation_id": self.observation_id,
            "remote_run_id": self.remote_run_id,
            "remote_task_id": self.remote_task_id,
            "tasks": [item.binding() for item in self.tasks],
            "safe_logs": logs,
            "outputs": [item.binding() for item in self.outputs],
            "elapsed_seconds": self.elapsed_seconds,
            "machine_seconds": self.machine_seconds,
        }


@dataclass(frozen=True)
class CurrentExecutionPlanEvidence:
    result: dict[str, Any]
    request: RemoteExecutionRequest
    evidence: CurrentRemoteEvidence


def _schema() -> dict[str, Any]:
    value = json.loads(
        files("smf.schemas").joinpath("databricks-runtime-evidence.schema.json").read_text()
    )
    if not isinstance(value, dict):
        raise ValueError("DBX-04 packaged schema is invalid")
    return value


def _manifest() -> list[dict[str, str]]:
    resources = (
        (
            "smf/execution/runtime_evidence.py",
            files("smf.execution").joinpath("runtime_evidence.py"),
        ),
        (
            "smf/execution/databricks_remote.py",
            files("smf.execution").joinpath("databricks_remote.py"),
        ),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/databricks-runtime-evidence.schema.json",
            files("smf.schemas").joinpath("databricks-runtime-evidence.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _plan_identity(request: RuntimeEvidenceRequest, plan: dict[str, Any]) -> None:
    binding = request.binding()
    expected = {
        "client_id": binding["client_id"],
        "deployment_id": binding["deployment_id"],
        "environment_id": binding["environment_id"],
        "workload_id": binding["workload_id"],
        "source_id": binding["source_id"],
        "run_id": binding["run_id"],
        "attempt_id": binding["attempt_id"],
        "package_id": binding["package_id"],
        "package_digest": binding["package_digest"],
        "evaluation_time": binding["evaluation_time"],
    }
    if any(plan.get("request", {}).get(key) != value for key, value in expected.items()):
        raise ValueError("DBX-04 execution-plan identity mismatch")
    if (
        plan.get("result_id") != request.execution_plan_id
        or plan.get("content_digest") != request.execution_plan_digest
    ):
        raise ValueError("DBX-04 execution-plan digest mismatch")


def _blockers(observation: dict[str, Any], evaluation_time: datetime) -> list[str]:
    blockers = ["live_runtime_evidence_required"]
    tasks = observation["tasks"]
    if not tasks:
        blockers.append("missing_task_observations")
    if not observation["safe_logs"]:
        blockers.append("missing_safe_logs")
    if not observation["outputs"]:
        blockers.append("missing_output_references")
    terminal = {"succeeded", "failed", "cancelled", "outcome_unknown"}
    terminal_states = [item["state"] for item in tasks if item["state"] in terminal]
    if tasks and not terminal_states:
        blockers.append("missing_terminal_outcome")
    if len(set(terminal_states)) > 1 or any(
        item["state"] not in terminal
        for index, item in enumerate(tasks)
        if any(prior["state"] in terminal for prior in tasks[:index])
    ):
        blockers.append("contradictory_task_states")
    if any(item["state"] == "outcome_unknown" for item in tasks):
        blockers.append("outcome_unknown")
    if any(
        _time(item["valid_until"], "output valid_until") <= evaluation_time
        for item in observation["outputs"]
    ):
        blockers.append("expired_output_reference")
    return sorted(set(blockers))


def prepare_runtime_evidence(
    request: RuntimeEvidenceRequest,
    observation: SyntheticRuntimeObservation,
    current_plan: CurrentExecutionPlanEvidence,
) -> dict[str, Any]:
    plan = deepcopy(current_plan.result)
    verify_remote_execution_plan(plan, current_plan.request, current_plan.evidence)
    _plan_identity(request, plan)
    binding = request.binding()
    observed = observation.binding()
    evaluation_time = _time(request.evaluation_time, "evaluation_time")
    task_times = [_time(item["observed_at"], "task observed_at") for item in observed["tasks"]]
    if task_times != sorted(task_times) or any(item > evaluation_time for item in task_times):
        raise ValueError("DBX-04 task timestamps are non-monotonic or in the future")
    blockers = _blockers(observed, evaluation_time)
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "dbx-04.1.0",
        "receipt_id": "pending",
        "content_digest": "",
        "request": binding,
        "request_digest": digest_value(binding),
        "execution_plan": {
            "result_id": plan["result_id"],
            "content_digest": plan["content_digest"],
            "state": plan["state"],
        },
        "observation": observed,
        "state": "blocked_evidence_gaps",
        "blockers": blockers,
        "implementation_manifest": _manifest(),
        "claims": {
            "captured": True,
            "generated": True,
            "blocked": True,
            "submitted": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "human_assisted": False,
            "humana_ready": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    decision = {
        key: value for key, value in result.items() if key not in {"receipt_id", "content_digest"}
    }
    result["receipt_id"] = stable_id("DBX04", decision)
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    _verify_structure(result)
    return result


def _verify_structure(result: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(result), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError("DBX-04 schema validation failed: " + errors[0].message)
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("DBX-04 request digest mismatch")
    decision = {
        key: value for key, value in result.items() if key not in {"receipt_id", "content_digest"}
    }
    if result["receipt_id"] != stable_id("DBX04", decision):
        raise ValueError("DBX-04 receipt identity mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("DBX-04 content digest mismatch")
    if result["implementation_manifest"] != _manifest():
        raise ValueError("DBX-04 implementation manifest mismatch")
    if any(
        value
        for key, value in result["claims"].items()
        if key not in {"captured", "generated", "blocked"}
    ):
        raise ValueError("DBX-04 unauthorized runtime claim")


def verify_runtime_evidence(
    result: dict[str, Any],
    request: RuntimeEvidenceRequest,
    observation: SyntheticRuntimeObservation,
    current_plan: CurrentExecutionPlanEvidence,
) -> None:
    _verify_structure(result)
    if result != prepare_runtime_evidence(request, observation, current_plan):
        raise ValueError("DBX-04 receipt differs from current governed inputs")


def publish_runtime_evidence(
    result: dict[str, Any],
    request: RuntimeEvidenceRequest,
    observation: SyntheticRuntimeObservation,
    current_plan: CurrentExecutionPlanEvidence,
    *,
    output_root: Path,
) -> Path:
    verify_runtime_evidence(result, request, observation, current_plan)
    path = (
        output_root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "dbx04"
        / "receipt.json"
    )
    publish_json(path, result, "DBX-04 runtime evidence", root=output_root)
    if read_published_json(path, root=output_root, label="DBX-04 runtime evidence") != result:
        raise ValueError("DBX-04 publication replay mismatch")
    return path


__all__ = [
    "CurrentExecutionPlanEvidence",
    "OutputReference",
    "RuntimeEvidenceRequest",
    "SyntheticRuntimeObservation",
    "TaskObservation",
    "prepare_runtime_evidence",
    "publish_runtime_evidence",
    "verify_runtime_evidence",
]
