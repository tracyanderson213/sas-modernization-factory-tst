"""Replay-first, attempt-bound workload lifecycle orchestration.

ORCH-01 consumes immutable, signed stage receipts and fully replayed FAIL-01
classifications. It records state; it does not execute a stage, contact a provider,
approve an exception, or turn a synthetic receipt into customer evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from smf.failure_taxonomy import (
    FailureClassificationRequest,
    verify_failure_classification,
)
from smf.immutable_files import (
    publish_json,
    published_file_exists,
    read_published_bytes,
    read_published_json,
)
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value, verify_proof
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RESULT_NAME = "workload-lifecycle.result.json"
_TELEMETRY_NAME = "workload-lifecycle.telemetry.json"
_STAGE_KINDS = {
    "readiness_qualified": ("ready", "ready"),
    "conversion_succeeded": ("converted", "converted"),
    "execution_succeeded": ("executed", "executed"),
    "validation_succeeded": ("validated", "validated"),
    "repair_succeeded": ("repaired", "converted"),
    "human_approved": ("approved", "human_approved"),
    "human_denied": ("denied", "human_denied"),
    "cancellation_requested": ("cancelled", "cancelled"),
}
_ALLOWED_STAGE_TRANSITIONS = {
    ("pending_readiness", "readiness_qualified"): "ready",
    ("ready", "conversion_succeeded"): "converted",
    ("converted", "execution_succeeded"): "executed",
    ("executed", "validation_succeeded"): "validated",
    ("failed", "repair_succeeded"): "converted",
    ("human_pending", "human_approved"): "human_approved",
    ("human_pending", "human_denied"): "human_denied",
}
_TERMINAL = {
    "validated",
    "blocked",
    "unsupported",
    "outcome_unknown",
    "human_approved",
    "human_denied",
    "cancelled",
}
_REPAIR_ACTIONS = {
    "route_to_bounded_ai_repair",
    "retry_deterministic_conversion",
    "repair_then_reexecute_and_revalidate",
}
_ALLOWED_FAILURE_STAGES = {
    "pending_readiness": {
        "readiness",
        "discovery",
        "dependency_resolution",
        "environment",
        "governance",
        "evidence",
    },
    "ready": {
        "deterministic_conversion",
        "ai_fallback",
        "dependency_resolution",
        "environment",
        "governance",
        "evidence",
    },
    "converted": {"execution", "environment", "governance", "evidence"},
    "executed": {"validation", "reconciliation", "environment", "governance", "evidence"},
    "failed": {"ai_fallback", "governance", "evidence"},
    "human_pending": {"governance", "evidence"},
}


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe ORCH-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"ORCH-01 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"ORCH-01 {label} is not canonical RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"ORCH-01 {label} is not canonical RFC3339 UTC")
    return parsed


@dataclass(frozen=True)
class LifecycleRequest:
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
    attempt_id: str
    evaluation_time: str

    def binding(self) -> dict[str, str]:
        values = {
            name: _safe(getattr(self, name), name)
            for name in (
                "client_id",
                "deployment_id",
                "environment_id",
                "source_id",
                "source_artifact_id",
                "workload_id",
                "run_id",
                "attempt_id",
            )
        }
        values["source_artifact_digest"] = _sha(
            self.source_artifact_digest, "source_artifact_digest"
        )
        values["evaluation_time"] = self.evaluation_time
        _time(self.evaluation_time, "evaluation_time")
        return values


@dataclass(frozen=True)
class StageAuthority:
    authority_id: str
    key_id: str
    public_key: str
    permitted_kinds: tuple[str, ...]
    evidence_class: str = "synthetic_contract"

    def binding(self) -> dict[str, Any]:
        _safe(self.authority_id, "authority_id")
        _safe(self.key_id, "key_id")
        if self.evidence_class != "synthetic_contract":
            raise ValueError("ORCH-01 authority evidence class is invalid")
        try:
            decoded = base64.b64decode(self.public_key, validate=True)
        except ValueError as exc:
            raise ValueError("ORCH-01 authority public key is invalid") from exc
        if len(decoded) != 32:
            raise ValueError("ORCH-01 authority public key is invalid")
        if (
            not self.permitted_kinds
            or len(self.permitted_kinds) != len(set(self.permitted_kinds))
            or any(kind not in _STAGE_KINDS for kind in self.permitted_kinds)
        ):
            raise ValueError("ORCH-01 authority stage permissions are invalid")
        return {
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "permitted_kinds": list(self.permitted_kinds),
            "evidence_class": self.evidence_class,
        }


@dataclass(frozen=True)
class LifecyclePolicy:
    policy_id: str
    version: str
    issued_at: str
    valid_until: str
    authorities: tuple[StageAuthority, ...]
    max_events: int = 64

    def binding(self) -> dict[str, Any]:
        _safe(self.policy_id, "policy_id")
        if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", self.version):
            raise ValueError("ORCH-01 policy version is invalid")
        if _time(self.issued_at, "policy issued_at") >= _time(
            self.valid_until, "policy valid_until"
        ):
            raise ValueError("ORCH-01 policy interval is invalid")
        if not 1 <= self.max_events <= 256:
            raise ValueError("ORCH-01 max_events is invalid")
        authority_values = [authority.binding() for authority in self.authorities]
        if not authority_values:
            raise ValueError("ORCH-01 policy requires at least one stage authority")
        ids = [item["authority_id"] for item in authority_values]
        keys = [item["key_id"] for item in authority_values]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("ORCH-01 authority inventory is ambiguous")
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "max_events": self.max_events,
            "authorities": authority_values,
        }


@dataclass(frozen=True)
class LifecycleEvidenceReference:
    sequence: int
    event_id: str
    evidence_type: str
    relative_path: str
    sha256: str
    failure_request: FailureClassificationRequest | None = None


@dataclass(frozen=True)
class PreparedLifecycle:
    result: dict[str, Any]
    telemetry: dict[str, Any]


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"ORCH-01 packaged {name} is invalid")
    return value


def _validate(name: str, value: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(value), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError(
            f"ORCH-01 {name} validation failed: " + "; ".join(item.message for item in errors)
        )


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/orchestration/lifecycle.py", files("smf.orchestration").joinpath("lifecycle.py")),
        ("smf/failure_taxonomy.py", files("smf").joinpath("failure_taxonomy.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/workload-lifecycle-result.schema.json",
            files("smf.schemas").joinpath("workload-lifecycle-result.schema.json"),
        ),
        (
            "smf/schemas/workload-lifecycle-telemetry.schema.json",
            files("smf.schemas").joinpath("workload-lifecycle-telemetry.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _read_reference(
    reference: LifecycleEvidenceReference, root: Path
) -> tuple[bytes, dict[str, Any]]:
    if (
        not isinstance(reference.sequence, int)
        or isinstance(reference.sequence, bool)
        or reference.sequence < 1
        or reference.evidence_type
        not in {
            "stage_receipt",
            "failure_classification",
        }
    ):
        raise ValueError("ORCH-01 evidence reference is invalid")
    _safe(reference.event_id, "event_id")
    _sha(reference.sha256, "evidence sha256")
    relative = Path(reference.relative_path)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("ORCH-01 evidence reference escapes the authorized root")
    raw = read_published_bytes(root / relative, root=root, label="lifecycle evidence")
    if hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise ValueError("ORCH-01 evidence bytes differ from their governed digest")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ORCH-01 evidence is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("ORCH-01 evidence is not an object")
    return raw, value


def _relative_to_lifecycle_root(root: Path, path: Path, label: str) -> Path:
    if ".." in root.parts or ".." in path.parts:
        raise ValueError(f"ORCH-01 {label} contains traversal")
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    try:
        return absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise ValueError(f"ORCH-01 {label} escapes the authorized lifecycle root") from exc


def _verify_failure_request_boundary(
    request: LifecycleRequest,
    reference: LifecycleEvidenceReference,
    failure_request: FailureClassificationRequest,
    failure_result: dict[str, Any],
) -> None:
    output_relative = _relative_to_lifecycle_root(
        request.evidence_root, failure_request.output_root, "FAIL-01 output root"
    )
    _relative_to_lifecycle_root(
        request.evidence_root, failure_request.evidence_root, "FAIL-01 evidence root"
    )
    canonical = failure_result.get("canonical_evidence_reference")
    if not isinstance(canonical, str):
        raise ValueError("ORCH-01 FAIL-01 canonical reference is invalid")
    canonical_path = Path(canonical)
    if (
        canonical_path.is_absolute()
        or not canonical_path.parts
        or any(part in {"", ".", ".."} for part in canonical_path.parts)
    ):
        raise ValueError("ORCH-01 FAIL-01 canonical reference is invalid")
    if output_relative / canonical_path != Path(reference.relative_path):
        raise ValueError("ORCH-01 FAIL-01 result is not bound to its authorized output root")


def _verify_stage_receipt(
    value: dict[str, Any],
    reference: LifecycleEvidenceReference,
    request: LifecycleRequest,
    policy: LifecyclePolicy,
) -> tuple[str, str, str]:
    required = {
        "schema_version",
        "receipt_id",
        "event_id",
        "sequence",
        "kind",
        "status",
        "observed_at",
        "identity",
        "artifact_id",
        "artifact_digest",
        "authority_id",
        "proof",
    }
    if set(value) != required or value["schema_version"] != "1.0":
        raise ValueError("ORCH-01 stage receipt contract is malformed")
    kind = str(value["kind"])
    expected = _STAGE_KINDS.get(kind)
    if expected is None or value["status"] != expected[0]:
        raise ValueError("ORCH-01 stage receipt kind/status is invalid")
    binding = request.binding()
    if value["identity"] != {key: binding[key] for key in binding if key != "evaluation_time"}:
        raise ValueError("ORCH-01 stage receipt identity mismatch")
    if value["event_id"] != reference.event_id or value["sequence"] != reference.sequence:
        raise ValueError("ORCH-01 stage receipt event binding mismatch")
    if not isinstance(value["sequence"], int) or isinstance(value["sequence"], bool):
        raise ValueError("ORCH-01 stage receipt sequence is invalid")
    for label in ("receipt_id", "artifact_id", "authority_id"):
        _safe(value[label], label)
    _sha(value["artifact_digest"], "stage artifact_digest")
    observed = _time(value["observed_at"], "stage observed_at")
    if observed > _time(request.evaluation_time, "evaluation_time"):
        raise ValueError("ORCH-01 stage receipt is from the future")
    authority = next(
        (item for item in policy.authorities if item.authority_id == value["authority_id"]), None
    )
    if authority is None or kind not in authority.permitted_kinds:
        raise ValueError("ORCH-01 stage receipt authority is not permitted")
    key_id = verify_proof(
        value,
        trusted_keys={authority.key_id: authority.public_key},
        allowed_key_ids={authority.key_id},
    )
    expected_id = stable_id(
        "ORCHREC", {key: item for key, item in value.items() if key not in {"receipt_id", "proof"}}
    )
    if value["receipt_id"] != expected_id:
        raise ValueError("ORCH-01 stage receipt identity is invalid")
    return kind, key_id, authority.evidence_class


def _failure_state(result: dict[str, Any]) -> str:
    disposition = result["classification"]["terminal_disposition"]
    if disposition not in {"blocked", "unsupported", "failed", "human_pending", "outcome_unknown"}:
        raise ValueError("ORCH-01 failure disposition is unsupported")
    return str(disposition)


def _is_terminal(state: str, last_failure: dict[str, Any] | None) -> bool:
    if state in _TERMINAL:
        return True
    return bool(
        state == "failed"
        and (last_failure is None or last_failure["next_action"] not in _REPAIR_ACTIONS)
    )


def _next_action(state: str, last_failure: dict[str, Any] | None) -> str:
    return {
        "pending_readiness": "supply_governed_readiness_receipt",
        "ready": "run_deterministic_conversion",
        "converted": "execute_generated_artifact",
        "executed": "run_validation_and_reconciliation",
        "failed": last_failure["next_action"] if last_failure else "stop_and_investigate",
        "human_pending": "obtain_separate_human_decision",
        "blocked": "resolve_blocker_in_new_attempt",
        "unsupported": "record_actionable_exception",
        "outcome_unknown": "reconcile_external_side_effects_do_not_retry",
        "validated": "await_separate_completion_or_promotion_decision",
        "human_approved": "start_new_governed_attempt",
        "human_denied": "stop",
        "cancelled": "stop",
    }[state]


def _verify_history_projection(result: dict[str, Any]) -> None:
    state = "pending_readiness"
    last_failure_id: str | None = None
    for sequence, event in enumerate(result["history"], 1):
        _safe(event["event_id"], "history event_id")
        _safe(event["evidence_id"], "history evidence_id")
        _sha(event["evidence_sha256"], "history evidence_sha256")
        _time(event["observed_at"], "history observed_at")
        _safe(event["authority"]["authority_id"], "history authority_id")
        if event["authority"]["key_id"] is not None:
            _safe(event["authority"]["key_id"], "history key_id")
        if event["sequence"] != sequence or event["state_before"] != state:
            raise ValueError("ORCH-01 history is stale or out of order")
        if state in _TERMINAL:
            raise ValueError("ORCH-01 history advances a terminal state")
        kind = event["event_kind"]
        if kind == "failure_classified":
            if event["state_after"] not in {
                "blocked",
                "unsupported",
                "failed",
                "human_pending",
                "outcome_unknown",
            }:
                raise ValueError("ORCH-01 history failure state is invalid")
            if event["authority"] != {
                "authority_id": "FAIL-01-current-input-replay",
                "key_id": None,
                "evidence_class": "governed_failure_classification",
            }:
                raise ValueError("ORCH-01 history failure authority is invalid")
            last_failure_id = event["evidence_id"]
            state = event["state_after"]
            continue
        if (
            event["authority"]["key_id"] is None
            or event["authority"]["evidence_class"] != "synthetic_contract"
        ):
            raise ValueError("ORCH-01 history stage authority is invalid")
        expected: str | None
        if kind == "cancellation_requested":
            expected = "cancelled"
        else:
            expected = _ALLOWED_STAGE_TRANSITIONS.get((state, kind))
        if expected is None or event["state_after"] != expected:
            raise ValueError("ORCH-01 history transition is invalid")
        if kind == "repair_succeeded" and (
            last_failure_id is None
            or result["last_failure"] is None
            or result["last_failure"]["next_action"] not in _REPAIR_ACTIONS
        ):
            raise ValueError("ORCH-01 history repair lacks an eligible failure")
        state = expected
    if state != result["state"]:
        raise ValueError("ORCH-01 history final state mismatch")
    if last_failure_id is None:
        if result["last_failure"] is not None:
            raise ValueError("ORCH-01 history has an unbound failure")
    elif result["last_failure"] is None or result["last_failure"]["failure_id"] != last_failure_id:
        raise ValueError("ORCH-01 history failure projection mismatch")
    if result["next_action"] != _next_action(state, result["last_failure"]):
        raise ValueError("ORCH-01 next action differs from lifecycle state")


def _claims() -> dict[str, bool]:
    return {
        "live_external_execution": False,
        "humana_validated": False,
        "semantic_parity": False,
        "production_ready": False,
        "migration_complete": False,
        "exception_approved": False,
        "promotion_authorized": False,
    }


def prepare_lifecycle(
    request: LifecycleRequest,
    policy: LifecyclePolicy,
    events: tuple[LifecycleEvidenceReference, ...],
) -> PreparedLifecycle:
    binding = request.binding()
    policy_binding = policy.binding()
    evaluated = _time(request.evaluation_time, "evaluation_time")
    if not (
        _time(policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(policy.valid_until, "policy valid_until")
    ):
        raise ValueError("ORCH-01 policy is not current")
    if len(events) > policy.max_events:
        raise ValueError("ORCH-01 event bound exceeded")
    state = "pending_readiness"
    previous_observed: datetime | None = None
    seen: set[str] = set()
    history: list[dict[str, Any]] = []
    last_failure: dict[str, Any] | None = None
    for expected_sequence, reference in enumerate(events, 1):
        if reference.sequence != expected_sequence or reference.event_id in seen:
            raise ValueError("ORCH-01 events are stale, duplicated, or out of order")
        if _is_terminal(state, last_failure):
            raise ValueError("ORCH-01 terminal or cancelled attempt cannot advance")
        seen.add(reference.event_id)
        _, evidence = _read_reference(reference, request.evidence_root)
        before = state
        authority_class: str
        event_kind: str
        evidence_id: str
        observed_at: str
        if reference.evidence_type == "stage_receipt":
            event_kind, key_id, authority_class = _verify_stage_receipt(
                evidence, reference, request, policy
            )
            observed_at = str(evidence["observed_at"])
            if event_kind == "cancellation_requested":
                state = "cancelled"
            else:
                target = _ALLOWED_STAGE_TRANSITIONS.get((state, event_kind))
                if target is None:
                    raise ValueError("ORCH-01 stage transition precondition failed")
                if event_kind == "repair_succeeded" and (
                    last_failure is None or last_failure["next_action"] not in _REPAIR_ACTIONS
                ):
                    raise ValueError("ORCH-01 repair has no eligible governed failure")
                state = target
            evidence_id = str(evidence["receipt_id"])
            authority = {
                "authority_id": evidence["authority_id"],
                "key_id": key_id,
                "evidence_class": authority_class,
            }
        else:
            failure_request = reference.failure_request
            if failure_request is None:
                raise ValueError("ORCH-01 failure event lacks replay inputs")
            _verify_failure_request_boundary(request, reference, failure_request, evidence)
            verify_failure_classification(evidence, failure_request)
            failure_identity = evidence["identity"]
            expected_identity = {
                key: binding[key]
                for key in ("client_id", "source_id", "workload_id", "run_id", "attempt_id")
            }
            if any(failure_identity[key] != value for key, value in expected_identity.items()):
                raise ValueError("ORCH-01 failure identity mismatch")
            if failure_identity["event_id"] != reference.event_id:
                raise ValueError("ORCH-01 failure event identity mismatch")
            observed_at = str(failure_identity["evaluation_time"])
            failure_stage = str(evidence["classification"]["stage"])
            if failure_stage not in _ALLOWED_FAILURE_STAGES.get(state, set()):
                raise ValueError("ORCH-01 failure transition precondition failed")
            state = _failure_state(evidence)
            event_kind = "failure_classified"
            evidence_id = str(evidence["failure_id"])
            authority = {
                "authority_id": "FAIL-01-current-input-replay",
                "key_id": None,
                "evidence_class": "governed_failure_classification",
            }
            last_failure = {
                "failure_id": evidence_id,
                "stage": evidence["classification"]["stage"],
                "reason_code": evidence["classification"]["reason_code"],
                "retryability": evidence["classification"]["retryability"],
                "next_action": evidence["classification"]["next_action"],
                "side_effect_state": evidence["classification"]["side_effect_state"],
            }
        observed = _time(observed_at, "event observed_at")
        if previous_observed is not None and observed < previous_observed:
            raise ValueError("ORCH-01 event time moved backwards")
        if observed > evaluated:
            raise ValueError("ORCH-01 event is from the future")
        previous_observed = observed
        history.append(
            {
                "sequence": reference.sequence,
                "event_id": reference.event_id,
                "event_kind": event_kind,
                "observed_at": observed_at,
                "evidence_id": evidence_id,
                "evidence_sha256": reference.sha256,
                "state_before": before,
                "state_after": state,
                "authority": authority,
            }
        )
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "orch-01.1.0",
        "result_id": "pending",
        "content_digest": "",
        "canonical_evidence_reference": (
            f"runs/{request.run_id}/workloads/{request.workload_id}/attempts/"
            f"{request.attempt_id}/orchestration/{_RESULT_NAME}"
        ),
        "identity": binding,
        "policy": policy_binding,
        "policy_digest": digest_value(policy_binding),
        "state": state,
        "terminal": _is_terminal(state, last_failure),
        "history": history,
        "history_digest": digest_value(history),
        "authority_scope": "synthetic_stage_contract_with_governed_failure_replay",
        "last_failure": last_failure,
        "next_action": _next_action(state, last_failure),
        "implementation_manifest": _implementation_manifest(),
        "claims": _claims(),
    }
    decision = {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }
    result["result_id"] = stable_id("ORCH01", decision)
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    telemetry = telemetry_from_lifecycle(result)
    _verify_lifecycle_result_structure(result)
    _validate("workload-lifecycle-telemetry.schema.json", telemetry)
    return PreparedLifecycle(result, telemetry)


def telemetry_from_lifecycle(result: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": "1.0",
        "result_id": result["result_id"],
        "client_id": result["identity"]["client_id"],
        "workload_id": result["identity"]["workload_id"],
        "run_id": result["identity"]["run_id"],
        "attempt_id": result["identity"]["attempt_id"],
        "state": result["state"],
        "terminal": result["terminal"],
        "event_count": len(result["history"]),
        "authority_scope": result["authority_scope"],
        "next_action": result["next_action"],
        "claims": dict(result["claims"]),
    }
    _validate("workload-lifecycle-telemetry.schema.json", value)
    return value


def _verify_lifecycle_result_structure(result: dict[str, Any]) -> None:
    _validate("workload-lifecycle-result.schema.json", result)
    for name in (
        "client_id",
        "deployment_id",
        "environment_id",
        "source_id",
        "source_artifact_id",
        "workload_id",
        "run_id",
        "attempt_id",
    ):
        _safe(result["identity"][name], f"identity {name}")
    _sha(result["identity"]["source_artifact_digest"], "identity source artifact digest")
    _time(result["identity"]["evaluation_time"], "identity evaluation_time")
    policy_value = result["policy"]
    reconstructed_policy = LifecyclePolicy(
        policy_value["policy_id"],
        policy_value["version"],
        policy_value["issued_at"],
        policy_value["valid_until"],
        tuple(
            StageAuthority(
                item["authority_id"],
                item["key_id"],
                item["public_key"],
                tuple(item["permitted_kinds"]),
                item["evidence_class"],
            )
            for item in policy_value["authorities"]
        ),
        policy_value["max_events"],
    )
    if reconstructed_policy.binding() != policy_value:
        raise ValueError("ORCH-01 policy projection is invalid")
    evaluated = _time(result["identity"]["evaluation_time"], "identity evaluation_time")
    if not (
        _time(reconstructed_policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(reconstructed_policy.valid_until, "policy valid_until")
    ):
        raise ValueError("ORCH-01 result policy is not current")
    _verify_history_projection(result)
    if result["policy_digest"] != digest_value(result["policy"]):
        raise ValueError("ORCH-01 policy digest mismatch")
    if result["history_digest"] != digest_value(result["history"]):
        raise ValueError("ORCH-01 history digest mismatch")
    decision = {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }
    if result["result_id"] != stable_id("ORCH01", decision):
        raise ValueError("ORCH-01 result identity mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("ORCH-01 content digest mismatch")
    if result["implementation_manifest"] != _implementation_manifest() or any(
        result["claims"].values()
    ):
        raise ValueError("ORCH-01 implementation or claim boundary mismatch")
    if result["terminal"] != _is_terminal(result["state"], result["last_failure"]):
        raise ValueError("ORCH-01 terminal state invariant failed")


def verify_lifecycle_result(
    result: dict[str, Any],
    request: LifecycleRequest,
    policy: LifecyclePolicy,
    events: tuple[LifecycleEvidenceReference, ...],
) -> None:
    """Verify a result only by replaying every current governed event input."""

    _verify_lifecycle_result_structure(result)
    if result != prepare_lifecycle(request, policy, events).result:
        raise ValueError("ORCH-01 result differs from current governed inputs")


def _result_path(request: LifecycleRequest) -> Path:
    return (
        request.output_root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "orchestration"
        / _RESULT_NAME
    )


def publish_lifecycle(
    request: LifecycleRequest,
    policy: LifecyclePolicy,
    events: tuple[LifecycleEvidenceReference, ...],
    prepared: PreparedLifecycle,
) -> tuple[Path, Path]:
    replayed = prepare_lifecycle(request, policy, events)
    if replayed != prepared:
        raise ValueError("ORCH-01 candidate differs from current governed inputs")
    result_path = _result_path(request)
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    publish_json(result_path, prepared.result, "ORCH-01 result", root=request.output_root)
    publish_json(telemetry_path, prepared.telemetry, "ORCH-01 telemetry", root=request.output_root)
    return result_path, telemetry_path


def verify_lifecycle(
    request: LifecycleRequest,
    policy: LifecyclePolicy,
    events: tuple[LifecycleEvidenceReference, ...],
) -> PreparedLifecycle:
    observed = read_published_json(
        _result_path(request), root=request.output_root, label="ORCH-01 result"
    )
    telemetry_path = _result_path(request).with_name(_TELEMETRY_NAME)
    telemetry = read_published_json(
        telemetry_path, root=request.output_root, label="ORCH-01 telemetry"
    )
    if not isinstance(observed, dict) or not isinstance(telemetry, dict):
        raise ValueError("ORCH-01 published evidence is malformed")
    verify_lifecycle_result(observed, request, policy, events)
    expected = prepare_lifecycle(request, policy, events)
    if observed != expected.result or telemetry != expected.telemetry:
        raise ValueError("ORCH-01 evidence differs from current governed inputs")
    return expected


def recover_lifecycle(
    request: LifecycleRequest,
    policy: LifecyclePolicy,
    events: tuple[LifecycleEvidenceReference, ...],
) -> tuple[Path, Path]:
    expected = prepare_lifecycle(request, policy, events)
    result_path = _result_path(request)
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    result_exists = published_file_exists(
        result_path, root=request.output_root, label="ORCH-01 result"
    )
    telemetry_exists = published_file_exists(
        telemetry_path, root=request.output_root, label="ORCH-01 telemetry"
    )
    if result_exists and not telemetry_exists:
        observed = read_published_json(
            result_path, root=request.output_root, label="ORCH-01 result"
        )
        if observed != expected.result:
            raise ValueError("ORCH-01 recovery result differs from current governed inputs")
        publish_json(
            telemetry_path, expected.telemetry, "ORCH-01 telemetry", root=request.output_root
        )
    verify_lifecycle(request, policy, events)
    return result_path, telemetry_path


__all__ = [
    "LifecycleEvidenceReference",
    "LifecyclePolicy",
    "LifecycleRequest",
    "PreparedLifecycle",
    "StageAuthority",
    "prepare_lifecycle",
    "publish_lifecycle",
    "recover_lifecycle",
    "telemetry_from_lifecycle",
    "verify_lifecycle",
    "verify_lifecycle_result",
]
