"""Fail-closed ORCH-03 retry and restart planning.

This module never executes or retries a workload.  It verifies a synthetic,
signed attempt inventory, fully replays each referenced ORCH-01 lifecycle, and
emits an immutable plan describing the only defensible resume point.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from smf.immutable_files import (
    publish_json,
    published_file_exists,
    read_published_bytes,
    read_published_json,
)
from smf.orchestration.lifecycle import (
    LifecycleEvidenceReference,
    LifecyclePolicy,
    LifecycleRequest,
    PreparedLifecycle,
    verify_lifecycle,
)
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value, verify_proof
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RESULT_NAME = "restart-plan.result.json"
_TELEMETRY_NAME = "restart-plan.telemetry.json"


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe ORCH-03 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"ORCH-03 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"ORCH-03 {label} is not canonical RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"ORCH-03 {label} is not canonical RFC3339 UTC")
    return parsed


@dataclass(frozen=True)
class RestartRequest:
    output_root: Path
    evidence_root: Path
    client_id: str
    deployment_id: str
    environment_id: str
    source_id: str
    source_artifact_id: str
    source_artifact_digest: str
    workload_id: str
    run_id: str
    restart_id: str
    evaluation_time: str
    expected_latest_attempt_id: str | None
    expected_latest_result_id: str | None

    def binding(self) -> dict[str, Any]:
        values: dict[str, Any] = {
            name: _safe(getattr(self, name), name)
            for name in (
                "client_id",
                "deployment_id",
                "environment_id",
                "source_id",
                "source_artifact_id",
                "workload_id",
                "run_id",
                "restart_id",
            )
        }
        values["source_artifact_digest"] = _sha(
            self.source_artifact_digest, "source_artifact_digest"
        )
        values["evaluation_time"] = self.evaluation_time
        _time(self.evaluation_time, "evaluation_time")
        for name in ("expected_latest_attempt_id", "expected_latest_result_id"):
            value = getattr(self, name)
            if value is not None:
                _safe(value, name)
            values[name] = value
        return values


@dataclass(frozen=True)
class RestartAuthority:
    authority_id: str
    key_id: str
    public_key: str
    evidence_class: str = "synthetic_contract"

    def binding(self) -> dict[str, str]:
        _safe(self.authority_id, "authority_id")
        _safe(self.key_id, "key_id")
        if self.evidence_class != "synthetic_contract":
            raise ValueError("ORCH-03 lineage authority is not synthetic")
        try:
            decoded = base64.b64decode(self.public_key, validate=True)
        except ValueError as exc:
            raise ValueError("ORCH-03 lineage authority key is invalid") from exc
        if len(decoded) != 32:
            raise ValueError("ORCH-03 lineage authority key is invalid")
        return asdict(self)


@dataclass(frozen=True)
class RestartPolicy:
    policy_id: str
    version: str
    issued_at: str
    valid_until: str
    max_attempts: int
    max_lineage_age_seconds: int
    authority: RestartAuthority

    def binding(self) -> dict[str, Any]:
        _safe(self.policy_id, "policy_id")
        if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", self.version):
            raise ValueError("ORCH-03 policy version is invalid")
        if _time(self.issued_at, "policy issued_at") >= _time(
            self.valid_until, "policy valid_until"
        ):
            raise ValueError("ORCH-03 policy interval is invalid")
        if (
            not isinstance(self.max_attempts, int)
            or isinstance(self.max_attempts, bool)
            or not 1 <= self.max_attempts <= 64
        ):
            raise ValueError("ORCH-03 max_attempts is invalid")
        if (
            not isinstance(self.max_lineage_age_seconds, int)
            or isinstance(self.max_lineage_age_seconds, bool)
            or not 1 <= self.max_lineage_age_seconds <= 86400
        ):
            raise ValueError("ORCH-03 max_lineage_age_seconds is invalid")
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "max_attempts": self.max_attempts,
            "max_lineage_age_seconds": self.max_lineage_age_seconds,
            "authority": self.authority.binding(),
        }


@dataclass(frozen=True)
class AttemptReplay:
    request: LifecycleRequest
    policy: LifecyclePolicy
    events: tuple[LifecycleEvidenceReference, ...]


@dataclass(frozen=True)
class LineageReference:
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class PreparedRestart:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"ORCH-03 packaged {name} is invalid")
    return value


def _validate(name: str, value: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(value), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError(
            f"ORCH-03 {name} validation failed: " + "; ".join(item.message for item in errors)
        )


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/orchestration/resume.py", files("smf.orchestration").joinpath("resume.py")),
        (
            "smf/orchestration/lifecycle.py",
            files("smf.orchestration").joinpath("lifecycle.py"),
        ),
        ("smf/failure_taxonomy.py", files("smf").joinpath("failure_taxonomy.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/restart-plan-result.schema.json",
            files("smf.schemas").joinpath("restart-plan-result.schema.json"),
        ),
        (
            "smf/schemas/restart-plan-telemetry.schema.json",
            files("smf.schemas").joinpath("restart-plan-telemetry.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _relative_under(root: Path, path: Path, label: str) -> Path:
    if ".." in root.parts or ".." in path.parts:
        raise ValueError(f"ORCH-03 {label} contains traversal")
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    try:
        return absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise ValueError(f"ORCH-03 {label} escapes the authorized evidence root") from exc


def _lineage_identity(request: RestartRequest) -> dict[str, str]:
    binding = request.binding()
    return {
        key: binding[key]
        for key in (
            "client_id",
            "deployment_id",
            "environment_id",
            "source_id",
            "source_artifact_id",
            "source_artifact_digest",
            "workload_id",
            "run_id",
        )
    }


def _load_lineage(
    request: RestartRequest, policy: RestartPolicy, reference: LineageReference
) -> dict[str, Any]:
    if (
        not isinstance(reference.relative_path, str)
        or len(reference.relative_path) > 512
        or contains_protected_data(reference.relative_path)
    ):
        raise ValueError("Unsafe ORCH-03 lineage reference")
    relative = Path(reference.relative_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("ORCH-03 lineage reference escapes the authorized root")
    _sha(reference.sha256, "lineage sha256")
    raw = read_published_bytes(
        request.evidence_root / relative,
        root=request.evidence_root,
        label="ORCH-03 lineage manifest",
    )
    if hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise ValueError("ORCH-03 lineage bytes differ from the governed digest")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ORCH-03 lineage manifest is invalid JSON") from exc
    if not isinstance(manifest, dict):
        raise ValueError("ORCH-03 lineage manifest is not an object")
    required = {
        "schema_version",
        "lineage_id",
        "observed_at",
        "identity",
        "attempts",
        "authority_id",
        "proof",
    }
    if set(manifest) != required or manifest["schema_version"] != "1.0":
        raise ValueError("ORCH-03 lineage manifest is malformed")
    if manifest["identity"] != _lineage_identity(request):
        raise ValueError("ORCH-03 lineage identity mismatch")
    observed = _time(manifest["observed_at"], "lineage observed_at")
    evaluated = _time(request.evaluation_time, "evaluation_time")
    if observed > evaluated:
        raise ValueError("ORCH-03 lineage manifest is from the future")
    if observed < _time(policy.issued_at, "policy issued_at"):
        raise ValueError("ORCH-03 lineage manifest predates its policy")
    if (evaluated - observed).total_seconds() > policy.max_lineage_age_seconds:
        raise ValueError("ORCH-03 lineage manifest is stale")
    authority = policy.authority
    if manifest["authority_id"] != authority.authority_id:
        raise ValueError("ORCH-03 lineage authority mismatch")
    verify_proof(
        manifest,
        trusted_keys={authority.key_id: authority.public_key},
        allowed_key_ids={authority.key_id},
    )
    expected_id = stable_id(
        "ORCHLINEAGE",
        {key: value for key, value in manifest.items() if key not in {"lineage_id", "proof"}},
    )
    if manifest["lineage_id"] != expected_id:
        raise ValueError("ORCH-03 lineage identity is invalid")
    attempts = manifest["attempts"]
    if not isinstance(attempts, list) or len(attempts) > policy.max_attempts:
        raise ValueError("ORCH-03 lineage attempt inventory is invalid")
    expected_attempt_keys = {
        "ordinal",
        "attempt_id",
        "result_id",
        "result_digest",
        "state",
    }
    seen: set[str] = set()
    for ordinal, item in enumerate(attempts, 1):
        if not isinstance(item, dict) or set(item) != expected_attempt_keys:
            raise ValueError("ORCH-03 lineage attempt is malformed")
        if item["ordinal"] != ordinal:
            raise ValueError("ORCH-03 lineage ordinals are stale or discontinuous")
        _safe(item["attempt_id"], "lineage attempt_id")
        _safe(item["result_id"], "lineage result_id")
        _sha(item["result_digest"], "lineage result_digest")
        if item["attempt_id"] in seen:
            raise ValueError("ORCH-03 lineage attempt IDs are duplicated")
        seen.add(item["attempt_id"])
    return manifest


def _verify_attempts(
    request: RestartRequest,
    manifest: dict[str, Any],
    replays: tuple[AttemptReplay, ...],
) -> list[PreparedLifecycle]:
    attempts = manifest["attempts"]
    if len(attempts) != len(replays):
        raise ValueError("ORCH-03 complete attempt replay inventory is required")
    prepared: list[PreparedLifecycle] = []
    for item, replay in zip(attempts, replays, strict=True):
        _relative_under(request.evidence_root, replay.request.output_root, "ORCH-01 output root")
        _relative_under(
            request.evidence_root,
            replay.request.evidence_root,
            "ORCH-01 evidence root",
        )
        expected_identity = _lineage_identity(request)
        lifecycle_identity = replay.request.binding()
        for key, value in expected_identity.items():
            if lifecycle_identity[key] != value:
                raise ValueError(f"ORCH-03 replay {key} mismatch")
        if replay.request.attempt_id != item["attempt_id"]:
            raise ValueError("ORCH-03 replay attempt identity mismatch")
        if _time(replay.request.evaluation_time, "ORCH-01 evaluation_time") > _time(
            request.evaluation_time, "evaluation_time"
        ):
            raise ValueError("ORCH-03 replay is from the future")
        current = verify_lifecycle(replay.request, replay.policy, replay.events)
        result = current.result
        if any(
            (
                result["result_id"] != item["result_id"],
                result["content_digest"] != item["result_digest"],
                result["state"] != item["state"],
            )
        ):
            raise ValueError("ORCH-03 lineage differs from current ORCH-01 evidence")
        prepared.append(current)
    return prepared


def _decision(
    request: RestartRequest,
    policy: RestartPolicy,
    attempts: list[PreparedLifecycle],
) -> dict[str, Any]:
    if not attempts:
        if (
            request.expected_latest_attempt_id is not None
            or request.expected_latest_result_id is not None
        ):
            raise ValueError("ORCH-03 empty lineage contradicts the expected latest pointer")
        return {
            "state": "blocked_missing_attempt_evidence",
            "action": "supply_governed_attempt_evidence",
            "resume_stage": None,
            "new_attempt_id": None,
            "side_effect_disposition": "not_observed",
            "blockers": ["governed_attempt_evidence_required"],
        }
    latest = attempts[-1].result
    latest_identity = latest["identity"]
    if (
        request.expected_latest_attempt_id != latest_identity["attempt_id"]
        or request.expected_latest_result_id != latest["result_id"]
    ):
        raise ValueError("ORCH-03 expected latest pointer is stale")
    if any(item.result["state"] == "outcome_unknown" for item in attempts):
        return {
            "state": "blocked_unknown_external_effect",
            "action": "reconcile_external_effects_before_retry",
            "resume_stage": None,
            "new_attempt_id": None,
            "side_effect_disposition": "unknown_must_reconcile",
            "blockers": ["attributable_external_effect_reconciliation_required"],
        }
    state = latest["state"]
    if state == "validated":
        action, stage, side_effect = "none_validated", None, "validated_terminal"
    elif state in {"cancelled", "human_denied"}:
        action, stage, side_effect = "stop", None, "terminal_no_new_side_effect"
    elif state == "human_pending":
        action, stage, side_effect = (
            "await_separate_human_decision",
            None,
            "human_decision_required",
        )
    elif state in {"blocked", "unsupported"}:
        action, stage, side_effect = (
            "resolve_blocker_in_new_governed_run",
            None,
            "blocked_no_new_side_effect",
        )
    elif state == "human_approved":
        action, stage, side_effect = (
            "start_new_attempt",
            "readiness",
            "separate_decision_observed",
        )
    elif state == "pending_readiness":
        action, stage, side_effect = "start_new_attempt", "readiness", "not_observed"
    elif state == "ready":
        action, stage, side_effect = (
            "start_new_attempt",
            "deterministic_conversion",
            "not_observed",
        )
    elif state == "converted":
        action, stage, side_effect = "start_new_attempt", "execution", "not_observed"
    elif state == "executed":
        action, stage, side_effect = (
            "start_new_attempt",
            "validation",
            "execution_completed_validation_pending",
        )
    elif state == "failed" and latest["last_failure"] is not None:
        governed_action = latest["last_failure"]["next_action"]
        stages = {
            "route_to_bounded_ai_repair": "ai_repair",
            "retry_deterministic_conversion": "deterministic_conversion",
            "repair_then_reexecute_and_revalidate": "repair_execution_validation",
        }
        stage = stages.get(governed_action)
        action = "start_new_attempt" if stage is not None else "stop_failed"
        side_effect = "governed_failure_action"
    else:
        action, stage, side_effect = "stop_failed", None, "terminal_no_new_side_effect"
    new_attempt_id: str | None = None
    blockers: list[str] = []
    if action == "start_new_attempt":
        if len(attempts) >= policy.max_attempts:
            return {
                "state": "retry_exhausted",
                "action": "stop_retry_budget_exhausted",
                "resume_stage": None,
                "new_attempt_id": None,
                "side_effect_disposition": side_effect,
                "blockers": ["maximum_attempt_count_reached"],
            }
        new_attempt_id = stable_id(
            "ORCHATTEMPT",
            {
                "run_id": request.run_id,
                "workload_id": request.workload_id,
                "previous_attempt_id": latest_identity["attempt_id"],
                "previous_result_id": latest["result_id"],
                "ordinal": len(attempts) + 1,
                "resume_stage": stage,
            },
        )
    result_state = "restart_planned" if action == "start_new_attempt" else "no_restart_authorized"
    return {
        "state": result_state,
        "action": action,
        "resume_stage": stage,
        "new_attempt_id": new_attempt_id,
        "side_effect_disposition": side_effect,
        "blockers": blockers,
    }


def _claims() -> dict[str, bool]:
    return {
        "retry_executed": False,
        "external_submission_performed": False,
        "external_effect_reconciled": False,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "humana_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }


def prepare_restart_plan(
    request: RestartRequest,
    policy: RestartPolicy,
    lineage_reference: LineageReference,
    replays: tuple[AttemptReplay, ...],
) -> PreparedRestart:
    binding = request.binding()
    policy_binding = policy.binding()
    evaluated = _time(request.evaluation_time, "evaluation_time")
    if not (
        _time(policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(policy.valid_until, "policy valid_until")
    ):
        raise ValueError("ORCH-03 policy is not current")
    lineage = _load_lineage(request, policy, lineage_reference)
    attempts = _verify_attempts(request, lineage, replays)
    decision = _decision(request, policy, attempts)
    attempt_summary = [
        {
            "ordinal": ordinal,
            "attempt_id": item.result["identity"]["attempt_id"],
            "result_id": item.result["result_id"],
            "result_digest": item.result["content_digest"],
            "state": item.result["state"],
            "next_action": item.result["next_action"],
        }
        for ordinal, item in enumerate(attempts, 1)
    ]
    idempotency_key = stable_id(
        "ORCHRESTART",
        {
            "request": binding,
            "policy_digest": digest_value(policy_binding),
            "lineage_id": lineage["lineage_id"],
            "lineage_sha256": lineage_reference.sha256,
            "attempts": attempt_summary,
            "decision": decision,
        },
    )
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "orch-03.1.0",
        "result_id": "pending",
        "content_digest": "",
        "canonical_evidence_reference": (
            f"runs/{request.run_id}/workloads/{request.workload_id}/restarts/"
            f"{request.restart_id}/{_RESULT_NAME}"
        ),
        "request": binding,
        "request_digest": digest_value(binding),
        "policy": policy_binding,
        "policy_digest": digest_value(policy_binding),
        "lineage": {
            "lineage_id": lineage["lineage_id"],
            "relative_path": lineage_reference.relative_path,
            "sha256": lineage_reference.sha256,
            "authority_scope": "synthetic_contract",
        },
        "attempts": attempt_summary,
        "decision": {**decision, "idempotency_key": idempotency_key},
        "implementation_manifest": _implementation_manifest(),
        "claims": _claims(),
    }
    result["result_id"] = stable_id(
        "ORCH03",
        {key: value for key, value in result.items() if key not in {"result_id", "content_digest"}},
    )
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    telemetry = telemetry_from_restart(result)
    _verify_restart_structure(result)
    _validate("restart-plan-telemetry.schema.json", telemetry)
    return PreparedRestart(result, telemetry)


def telemetry_from_restart(result: dict[str, Any]) -> dict[str, Any]:
    latest = result["attempts"][-1] if result["attempts"] else None
    telemetry = {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "workload_id": result["request"]["workload_id"],
        "run_id": result["request"]["run_id"],
        "restart_id": result["request"]["restart_id"],
        "attempt_count": len(result["attempts"]),
        "latest_attempt_state": latest["state"] if latest else None,
        "decision_state": result["decision"]["state"],
        "action": result["decision"]["action"],
        "blocked": bool(result["decision"]["blockers"]),
        "claims": dict(result["claims"]),
    }
    _validate("restart-plan-telemetry.schema.json", telemetry)
    return telemetry


def _verify_restart_structure(result: dict[str, Any]) -> None:
    _validate("restart-plan-result.schema.json", result)
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("ORCH-03 request digest mismatch")
    if result["policy_digest"] != digest_value(result["policy"]):
        raise ValueError("ORCH-03 policy digest mismatch")
    decision = {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }
    if result["result_id"] != stable_id("ORCH03", decision):
        raise ValueError("ORCH-03 result identity mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("ORCH-03 content digest mismatch")
    if result["implementation_manifest"] != _implementation_manifest() or any(
        result["claims"].values()
    ):
        raise ValueError("ORCH-03 implementation or claim boundary mismatch")


def verify_restart_plan(
    result: dict[str, Any],
    request: RestartRequest,
    policy: RestartPolicy,
    lineage_reference: LineageReference,
    replays: tuple[AttemptReplay, ...],
) -> None:
    _verify_restart_structure(result)
    if result != prepare_restart_plan(request, policy, lineage_reference, replays).result:
        raise ValueError("ORCH-03 result differs from current governed inputs")


def _paths(request: RestartRequest) -> tuple[Path, Path]:
    result = (
        request.output_root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "restarts"
        / request.restart_id
        / _RESULT_NAME
    )
    return result, result.with_name(_TELEMETRY_NAME)


def publish_restart_plan(
    prepared: PreparedRestart,
    request: RestartRequest,
    policy: RestartPolicy,
    lineage_reference: LineageReference,
    replays: tuple[AttemptReplay, ...],
) -> tuple[Path, Path]:
    verify_restart_plan(prepared.result, request, policy, lineage_reference, replays)
    if prepared.telemetry != telemetry_from_restart(prepared.result):
        raise ValueError("ORCH-03 telemetry differs from the canonical result")
    result_path, telemetry_path = _paths(request)
    publish_json(result_path, prepared.result, "ORCH-03 result", root=request.output_root)
    publish_json(telemetry_path, prepared.telemetry, "ORCH-03 telemetry", root=request.output_root)
    return result_path, telemetry_path


def verify_published_restart(
    request: RestartRequest,
    policy: RestartPolicy,
    lineage_reference: LineageReference,
    replays: tuple[AttemptReplay, ...],
) -> PreparedRestart:
    result_path, telemetry_path = _paths(request)
    result = read_published_json(result_path, root=request.output_root, label="ORCH-03 result")
    telemetry = read_published_json(
        telemetry_path, root=request.output_root, label="ORCH-03 telemetry"
    )
    if not isinstance(result, dict) or not isinstance(telemetry, dict):
        raise ValueError("ORCH-03 published evidence is malformed")
    expected = prepare_restart_plan(request, policy, lineage_reference, replays)
    if result != expected.result or telemetry != expected.telemetry:
        raise ValueError("ORCH-03 evidence differs from current governed inputs")
    return expected


def recover_restart_plan(
    request: RestartRequest,
    policy: RestartPolicy,
    lineage_reference: LineageReference,
    replays: tuple[AttemptReplay, ...],
) -> tuple[Path, Path]:
    expected = prepare_restart_plan(request, policy, lineage_reference, replays)
    result_path, telemetry_path = _paths(request)
    result_exists = published_file_exists(
        result_path, root=request.output_root, label="ORCH-03 result"
    )
    telemetry_exists = published_file_exists(
        telemetry_path, root=request.output_root, label="ORCH-03 telemetry"
    )
    if result_exists and not telemetry_exists:
        observed = read_published_json(
            result_path, root=request.output_root, label="ORCH-03 result"
        )
        if observed != expected.result:
            raise ValueError("ORCH-03 recovery result differs from current governed inputs")
        publish_json(
            telemetry_path,
            expected.telemetry,
            "ORCH-03 telemetry",
            root=request.output_root,
        )
    verify_published_restart(request, policy, lineage_reference, replays)
    return result_path, telemetry_path


__all__ = [
    "AttemptReplay",
    "LineageReference",
    "PreparedRestart",
    "RestartAuthority",
    "RestartPolicy",
    "RestartRequest",
    "prepare_restart_plan",
    "publish_restart_plan",
    "recover_restart_plan",
    "verify_published_restart",
    "verify_restart_plan",
]
