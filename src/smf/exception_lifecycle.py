"""Versioned, fail-closed exception disposition lifecycle for TASK-24."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from smf.failure_taxonomy import FailureClassificationRequest, verify_failure_classification
from smf.immutable_files import publish_json, read_published_bytes, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id

_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class ExceptionState(StrEnum):
    OPEN = "open"
    PENDING_OWNER = "pending_owner"
    RESOLUTION_AUTHORIZED = "resolution_authorized"
    DENIED = "denied"
    CLOSED = "closed"


class ResolutionAction(StrEnum):
    RETRY_AFTER_EVIDENCE = "retry_after_evidence"
    RETRY_FROM_CHECKPOINT = "retry_from_checkpoint"
    REPAIR_AND_REVALIDATE = "repair_and_revalidate"
    ACCEPT_UNSUPPORTED = "accept_unsupported"
    NO_ACTION = "no_action"


_ACTION_BY_NEXT_STEP: dict[str, ResolutionAction] = {
    "supply_governed_prerequisite": ResolutionAction.RETRY_AFTER_EVIDENCE,
    "create_actionable_exception": ResolutionAction.ACCEPT_UNSUPPORTED,
    "resolve_dependency_evidence": ResolutionAction.RETRY_AFTER_EVIDENCE,
    "route_to_bounded_ai_repair": ResolutionAction.REPAIR_AND_REVALIDATE,
    "retry_deterministic_conversion": ResolutionAction.REPAIR_AND_REVALIDATE,
    "obtain_gateway_authority": ResolutionAction.RETRY_AFTER_EVIDENCE,
    "request_bounded_human_disposition": ResolutionAction.ACCEPT_UNSUPPORTED,
    # Unknown remote outcomes and security decisions cannot authorize execution
    # from this lifecycle.  They require a new governed failure observation.
    "investigate_unknown_gateway_outcome": ResolutionAction.NO_ACTION,
    "resolve_execution_authority": ResolutionAction.RETRY_AFTER_EVIDENCE,
    "retry_execution_from_checkpoint": ResolutionAction.RETRY_FROM_CHECKPOINT,
    "perform_target_readback_before_retry": ResolutionAction.NO_ACTION,
    "repair_then_reexecute_and_revalidate": ResolutionAction.REPAIR_AND_REVALIDATE,
    "complete_partition_reconciliation": ResolutionAction.REPAIR_AND_REVALIDATE,
    "obtain_validation_policy": ResolutionAction.RETRY_AFTER_EVIDENCE,
    "quarantine_and_reconstruct_evidence": ResolutionAction.REPAIR_AND_REVALIDATE,
    "request_security_decision": ResolutionAction.NO_ACTION,
    "retry_after_external_recovery": ResolutionAction.RETRY_AFTER_EVIDENCE,
}


@dataclass(frozen=True)
class ExceptionEvidence:
    evidence_id: str
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class ExceptionEvent:
    event_id: str
    sequence: int
    state: ExceptionState
    event_time: str
    actor_id: str
    owner_role: str
    evidence: tuple[ExceptionEvidence, ...]
    resolution_action: ResolutionAction | None = None
    authority_id: str | None = None
    valid_until: str | None = None
    authorization_event_id: str | None = None


@dataclass(frozen=True)
class ExceptionLifecycleRequest:
    output_root: Path
    evidence_root: Path
    failure_result: dict[str, Any]
    failure_request: FailureClassificationRequest
    exception_id: str
    evaluation_time: str
    events: tuple[ExceptionEvent, ...]


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _safe(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE.fullmatch(value)
        or contains_protected_data(value)
        or value in {".", ".."}
    ):
        raise ValueError(f"Unsafe exception {label}")
    return value


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"Exception {label} must be canonical UTC RFC3339")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"Exception {label} must be canonical UTC RFC3339")
    return parsed


def _schema() -> dict[str, Any]:
    value = json.loads(
        files("smf.schemas").joinpath("exception-lifecycle-result.schema.json").read_text()
    )
    return cast(dict[str, Any], value)


def _validate(payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(payload),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.absolute_path)) or '<root>'}: {item.message}"
            for item in errors
        )
        raise ValueError(f"Exception lifecycle schema validation failed: {detail}")


def _manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/exception_lifecycle.py", files("smf").joinpath("exception_lifecycle.py")),
        ("smf/failure_taxonomy.py", files("smf").joinpath("failure_taxonomy.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/exception-lifecycle-result.schema.json",
            files("smf.schemas").joinpath("exception-lifecycle-result.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _evidence(request: ExceptionLifecycleRequest, event: ExceptionEvent) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for item in event.evidence:
        _safe(item.evidence_id, "evidence_id")
        if item.evidence_id in seen or not _SHA.fullmatch(item.sha256):
            raise ValueError("Exception evidence identity or digest is invalid")
        relative = Path(item.relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or contains_protected_data(item.relative_path)
        ):
            raise ValueError("Exception evidence path is unsafe")
        raw = read_published_bytes(
            request.evidence_root / relative,
            root=request.evidence_root,
            label="TASK-24 resolution evidence",
        )
        if hashlib.sha256(raw).hexdigest() != item.sha256:
            raise ValueError("Exception evidence digest differs")
        seen.add(item.evidence_id)
        result.append(asdict(item))
    return result


def evaluate_exception_lifecycle(request: ExceptionLifecycleRequest) -> dict[str, Any]:
    verify_failure_classification(request.failure_result, request.failure_request)
    _safe(request.exception_id, "exception_id")
    evaluation = _time(request.evaluation_time, "evaluation_time")
    failure = request.failure_result
    expected_owner = failure["classification"]["owner"]
    reason_code = failure["classification"]["reason_code"]
    next_action = failure["classification"]["next_action"]
    try:
        expected_action = _ACTION_BY_NEXT_STEP[next_action]
    except KeyError as exc:
        raise ValueError("Failure next_action lacks an explicit exception disposition") from exc
    expected_states = {
        ExceptionState.OPEN: {ExceptionState.PENDING_OWNER},
        ExceptionState.PENDING_OWNER: {
            ExceptionState.RESOLUTION_AUTHORIZED,
            ExceptionState.DENIED,
        },
        ExceptionState.RESOLUTION_AUTHORIZED: {ExceptionState.CLOSED},
        ExceptionState.DENIED: set(),
        ExceptionState.CLOSED: set(),
    }
    if not request.events:
        raise ValueError("Exception lifecycle must begin open")
    if not isinstance(request.events[0].state, ExceptionState):
        raise ValueError("Exception state or resolution action is unknown")
    if request.events[0].state is not ExceptionState.OPEN:
        raise ValueError("Exception lifecycle must begin open")
    prior_time: datetime | None = None
    prior_state: ExceptionState | None = None
    ids: set[str] = set()
    authorized: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    for index, event in enumerate(request.events, start=1):
        if event.sequence != index or event.event_id in ids:
            raise ValueError("Exception event sequence or identity is invalid")
        _safe(event.event_id, "event_id")
        _safe(event.actor_id, "actor_id")
        if event.owner_role != expected_owner:
            raise ValueError("Exception owner differs from failure classification")
        if not isinstance(event.state, ExceptionState) or (
            event.resolution_action is not None
            and not isinstance(event.resolution_action, ResolutionAction)
        ):
            raise ValueError("Exception state or resolution action is unknown")
        observed_time = _time(event.event_time, "event_time")
        if observed_time > evaluation or (prior_time is not None and observed_time <= prior_time):
            raise ValueError("Exception event time is stale, future, or unordered")
        if prior_state is not None and event.state not in expected_states[prior_state]:
            raise ValueError("Exception disposition transition is not allowed")
        if event.state is ExceptionState.RESOLUTION_AUTHORIZED:
            if (
                event.resolution_action is None
                or event.resolution_action is ResolutionAction.NO_ACTION
                or event.authority_id is None
                or event.valid_until is None
                or not event.evidence
            ):
                raise ValueError(
                    "Authorized resolution lacks authority, action, validity, or evidence"
                )
            if event.resolution_action is not expected_action:
                raise ValueError("Authorized resolution action contradicts failure disposition")
            _safe(event.authority_id, "authority_id")
            valid_until = _time(event.valid_until, "valid_until")
            if valid_until <= evaluation:
                raise ValueError("Authorized resolution is expired at evaluation time")
            authorized = {"event_id": event.event_id, "valid_until": event.valid_until}
        elif any(
            value is not None
            for value in (
                event.resolution_action,
                event.authority_id,
                event.valid_until,
            )
        ):
            raise ValueError("Non-authorization event carries resolution authority")
        if event.state is ExceptionState.CLOSED:
            if authorized is None or event.authorization_event_id != authorized["event_id"]:
                raise ValueError("Closure is not bound to the exact authorization event")
            if not event.evidence:
                raise ValueError("Closure lacks governed disposition evidence")
        elif event.authorization_event_id is not None:
            raise ValueError("Only closure may reference authorization")
        evidence = _evidence(request, event)
        events.append(
            {
                "event_id": event.event_id,
                "sequence": event.sequence,
                "state": event.state.value,
                "event_time": event.event_time,
                "actor_id": event.actor_id,
                "owner_role": event.owner_role,
                "evidence": evidence,
                "resolution_action": (
                    event.resolution_action.value if event.resolution_action else None
                ),
                "authority_id": event.authority_id,
                "valid_until": event.valid_until,
                "authorization_event_id": event.authorization_event_id,
            }
        )
        ids.add(event.event_id)
        prior_time, prior_state = observed_time, event.state
    current = events[-1]["state"]
    projection: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "task-24.1.0",
        "exception_id": request.exception_id,
        "failure": {
            "failure_id": failure["failure_id"],
            "failure_content_digest": failure["content_digest"],
            "client_id": failure["identity"]["client_id"],
            "source_id": failure["identity"]["source_id"],
            "workload_id": failure["identity"]["workload_id"],
            "run_id": failure["identity"]["run_id"],
            "attempt_id": failure["identity"]["attempt_id"],
            "reason_code": reason_code,
            "owner_role": expected_owner,
        },
        "evaluation_time": request.evaluation_time,
        "current_state": current,
        "events": events,
        "implementation_manifest": _manifest(),
        "claims": {
            "resolution_authorized": current in {"resolution_authorized", "closed"},
            "resolution_executed": False,
            "exception_closed": current == "closed",
            "validated": False,
            "parity_passed": False,
            "migration_ready": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    result = {"result_id": stable_id("EXCRES", projection), **projection}
    result["content_digest"] = _digest(result)
    _validate(result)
    return result


def verify_exception_lifecycle(result: dict[str, Any], request: ExceptionLifecycleRequest) -> None:
    _validate(result)
    if result != evaluate_exception_lifecycle(request):
        raise ValueError("Exception lifecycle differs from current governed inputs")


def publish_exception_lifecycle(
    request: ExceptionLifecycleRequest,
) -> tuple[dict[str, Any], Path]:
    result = evaluate_exception_lifecycle(request)
    failure = result["failure"]
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    path = (
        root
        / "runs"
        / failure["run_id"]
        / "workloads"
        / failure["workload_id"]
        / "attempts"
        / failure["attempt_id"]
        / "exceptions"
        / request.exception_id
        / "exception-lifecycle.result.json"
    )
    publish_json(path, result, "TASK-24 exception lifecycle", root=root)
    observed = read_published_json(path, root=root, label="TASK-24 exception lifecycle")
    if not isinstance(observed, dict):
        raise ValueError("Published exception lifecycle is not an object")
    verify_exception_lifecycle(observed, request)
    return observed, path
