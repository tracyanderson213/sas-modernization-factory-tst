"""Fail-closed, machine-actionable migration failure classification.

FAIL-01 records a bounded classification of an already observed failure.  It does
not execute a retry, invoke a model provider, contact an external system, or turn
an evidence reference into authority.  Upstream producers remain responsible for
their governed evidence; this contract makes orchestration decisions explicit and
replayable without persisting unsafe diagnostics.
"""

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
from typing import Any

from jsonschema import Draft202012Validator

from smf.immutable_files import (
    ensure_directory,
    publish_json,
    published_file_exists,
    read_published_bytes,
    read_published_json,
)
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RESULT_NAME = "failure-classification.result.json"
_TELEMETRY_NAME = "failure-classification.telemetry.json"


class FailureStage(StrEnum):
    READINESS = "readiness"
    DISCOVERY = "discovery"
    DEPENDENCY = "dependency_resolution"
    DETERMINISTIC_CONVERSION = "deterministic_conversion"
    AI_FALLBACK = "ai_fallback"
    EXECUTION = "execution"
    VALIDATION = "validation"
    RECONCILIATION = "reconciliation"
    EVIDENCE = "evidence"
    GOVERNANCE = "governance"
    ENVIRONMENT = "environment"


class FailureReason(StrEnum):
    PREREQUISITE_MISSING = "prerequisite_missing"
    UNSUPPORTED_SOURCE = "unsupported_source"
    DEPENDENCY_UNRESOLVED = "dependency_unresolved"
    DETERMINISTIC_CONVERSION_FAILED = "deterministic_conversion_failed"
    DETERMINISTIC_CONVERSION_TRANSIENT = "deterministic_conversion_transient"
    AI_GATEWAY_AUTHORITY_REQUIRED = "ai_gateway_authority_required"
    AI_FALLBACK_EXHAUSTED = "ai_fallback_exhausted"
    AI_OUTCOME_UNKNOWN = "ai_outcome_unknown"
    EXECUTION_REJECTED = "execution_rejected"
    EXECUTION_FAILED_NO_SIDE_EFFECT = "execution_failed_no_side_effect"
    EXECUTION_OUTCOME_UNKNOWN = "execution_outcome_unknown"
    VALIDATION_MISMATCH = "validation_mismatch"
    RECONCILIATION_INCOMPLETE = "reconciliation_incomplete"
    VALIDATION_POLICY_MISSING = "validation_policy_missing"
    EVIDENCE_INTEGRITY_FAILED = "evidence_integrity_failed"
    SECURITY_BOUNDARY = "security_boundary"
    EXTERNAL_SYSTEM_UNAVAILABLE = "external_system_unavailable"


class EvidenceClass(StrEnum):
    READINESS_RESULT = "readiness_result"
    DISCOVERY_RESULT = "discovery_result"
    DEPENDENCY_RESULT = "dependency_result"
    DETERMINISTIC_CONVERSION_RESULT = "deterministic_conversion_result"
    AI_REPAIR_RESULT = "ai_repair_result"
    EXECUTION_RESULT = "execution_result"
    VALIDATION_RESULT = "validation_result"
    RECONCILIATION_RESULT = "reconciliation_result"
    POLICY_RESULT = "policy_result"
    EVIDENCE_INTEGRITY_RESULT = "evidence_integrity_result"
    SECURITY_RESULT = "security_result"
    EXTERNAL_OBSERVATION = "external_observation"


@dataclass(frozen=True)
class FailureEvidenceReference:
    evidence_id: str
    evidence_class: EvidenceClass
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class FailureCauseReference:
    cause_id: str
    content_digest: str
    relation: str = "caused_by"


@dataclass(frozen=True)
class FailureClassificationRequest:
    output_root: Path
    evidence_root: Path
    client_id: str
    source_id: str
    workload_id: str
    run_id: str
    attempt_id: str
    event_id: str
    stage: FailureStage
    reason: FailureReason
    evaluation_time: str
    evidence: tuple[FailureEvidenceReference, ...]
    causes: tuple[FailureCauseReference, ...] = ()


@dataclass(frozen=True)
class PreparedFailureClassification:
    result: dict[str, Any]
    telemetry: dict[str, Any]


@dataclass(frozen=True)
class _Policy:
    stage: FailureStage
    category: str
    owner: str
    retryability: str
    repairability: str
    blocker_class: str
    terminal_disposition: str
    next_action: str
    side_effect_state: str
    required_evidence: EvidenceClass
    generated_state: str
    execution_state: str
    validation_state: str
    parity_state: str


_POLICIES: dict[FailureReason, _Policy] = {
    FailureReason.PREREQUISITE_MISSING: _Policy(
        FailureStage.READINESS,
        "prerequisite",
        "migration_engineering",
        "retry_after_evidence",
        "external_input",
        "external_input",
        "blocked",
        "supply_governed_prerequisite",
        "not_attempted",
        EvidenceClass.READINESS_RESULT,
        "not_attempted",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.UNSUPPORTED_SOURCE: _Policy(
        FailureStage.DISCOVERY,
        "unsupported",
        "source_owner",
        "not_retryable",
        "unsupported",
        "unsupported",
        "unsupported",
        "create_actionable_exception",
        "not_attempted",
        EvidenceClass.DISCOVERY_RESULT,
        "not_attempted",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.DEPENDENCY_UNRESOLVED: _Policy(
        FailureStage.DEPENDENCY,
        "dependency",
        "source_owner",
        "retry_after_evidence",
        "external_input",
        "external_input",
        "blocked",
        "resolve_dependency_evidence",
        "not_attempted",
        EvidenceClass.DEPENDENCY_RESULT,
        "not_attempted",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.DETERMINISTIC_CONVERSION_FAILED: _Policy(
        FailureStage.DETERMINISTIC_CONVERSION,
        "conversion",
        "migration_engineering",
        "not_retryable",
        "ai_candidate",
        "technical",
        "failed",
        "route_to_bounded_ai_repair",
        "not_attempted",
        EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
        "failed",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.DETERMINISTIC_CONVERSION_TRANSIENT: _Policy(
        FailureStage.DETERMINISTIC_CONVERSION,
        "conversion",
        "migration_engineering",
        "bounded_retry",
        "deterministic",
        "technical",
        "failed",
        "retry_deterministic_conversion",
        "not_attempted",
        EvidenceClass.DETERMINISTIC_CONVERSION_RESULT,
        "failed",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.AI_GATEWAY_AUTHORITY_REQUIRED: _Policy(
        FailureStage.AI_FALLBACK,
        "remediation",
        "gateway_owner",
        "retry_after_authority",
        "external_authority",
        "protected_action",
        "blocked",
        "obtain_gateway_authority",
        "not_attempted",
        EvidenceClass.AI_REPAIR_RESULT,
        "failed",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.AI_FALLBACK_EXHAUSTED: _Policy(
        FailureStage.AI_FALLBACK,
        "remediation",
        "migration_engineering",
        "not_retryable",
        "human_decision",
        "technical",
        "human_pending",
        "request_bounded_human_disposition",
        "not_attempted",
        EvidenceClass.AI_REPAIR_RESULT,
        "failed",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.AI_OUTCOME_UNKNOWN: _Policy(
        FailureStage.AI_FALLBACK,
        "remediation",
        "security_owner",
        "outcome_unknown_do_not_retry",
        "human_decision",
        "security_boundary",
        "outcome_unknown",
        "investigate_unknown_gateway_outcome",
        "unknown",
        EvidenceClass.AI_REPAIR_RESULT,
        "unknown",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.EXECUTION_REJECTED: _Policy(
        FailureStage.EXECUTION,
        "execution",
        "platform_owner",
        "retry_after_authority",
        "external_authority",
        "protected_action",
        "blocked",
        "resolve_execution_authority",
        "none_confirmed",
        EvidenceClass.EXECUTION_RESULT,
        "succeeded",
        "rejected",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.EXECUTION_FAILED_NO_SIDE_EFFECT: _Policy(
        FailureStage.EXECUTION,
        "execution",
        "platform_owner",
        "bounded_retry",
        "deterministic",
        "technical",
        "failed",
        "retry_execution_from_checkpoint",
        "none_confirmed",
        EvidenceClass.EXECUTION_RESULT,
        "succeeded",
        "failed",
        "not_attempted",
        "not_attempted",
    ),
    FailureReason.EXECUTION_OUTCOME_UNKNOWN: _Policy(
        FailureStage.EXECUTION,
        "execution",
        "platform_owner",
        "outcome_unknown_do_not_retry",
        "external_owner",
        "external_input",
        "outcome_unknown",
        "perform_target_readback_before_retry",
        "unknown",
        EvidenceClass.EXECUTION_RESULT,
        "succeeded",
        "unknown",
        "unknown",
        "unknown",
    ),
    FailureReason.VALIDATION_MISMATCH: _Policy(
        FailureStage.VALIDATION,
        "validation",
        "data_validation_owner",
        "not_retryable",
        "deterministic",
        "technical",
        "failed",
        "repair_then_reexecute_and_revalidate",
        "observed",
        EvidenceClass.VALIDATION_RESULT,
        "succeeded",
        "succeeded",
        "failed",
        "failed",
    ),
    FailureReason.RECONCILIATION_INCOMPLETE: _Policy(
        FailureStage.RECONCILIATION,
        "validation",
        "data_validation_owner",
        "retry_after_evidence",
        "external_input",
        "external_input",
        "blocked",
        "complete_partition_reconciliation",
        "observed",
        EvidenceClass.RECONCILIATION_RESULT,
        "succeeded",
        "succeeded",
        "incomplete",
        "unknown",
    ),
    FailureReason.VALIDATION_POLICY_MISSING: _Policy(
        FailureStage.VALIDATION,
        "governance",
        "business_owner",
        "retry_after_authority",
        "human_decision",
        "business_decision",
        "human_pending",
        "obtain_validation_policy",
        "observed",
        EvidenceClass.POLICY_RESULT,
        "succeeded",
        "succeeded",
        "blocked",
        "unknown",
    ),
    FailureReason.EVIDENCE_INTEGRITY_FAILED: _Policy(
        FailureStage.EVIDENCE,
        "evidence",
        "security_owner",
        "not_retryable",
        "deterministic",
        "security_boundary",
        "failed",
        "quarantine_and_reconstruct_evidence",
        "unknown",
        EvidenceClass.EVIDENCE_INTEGRITY_RESULT,
        "unknown",
        "unknown",
        "unknown",
        "unknown",
    ),
    FailureReason.SECURITY_BOUNDARY: _Policy(
        FailureStage.GOVERNANCE,
        "governance",
        "security_owner",
        "not_retryable",
        "human_decision",
        "security_boundary",
        "human_pending",
        "request_security_decision",
        "not_attempted",
        EvidenceClass.SECURITY_RESULT,
        "unknown",
        "unknown",
        "unknown",
        "unknown",
    ),
    FailureReason.EXTERNAL_SYSTEM_UNAVAILABLE: _Policy(
        FailureStage.ENVIRONMENT,
        "environment",
        "platform_owner",
        "bounded_retry",
        "external_owner",
        "external_input",
        "blocked",
        "retry_after_external_recovery",
        "none_confirmed",
        EvidenceClass.EXTERNAL_OBSERVATION,
        "unknown",
        "not_attempted",
        "not_attempted",
        "not_attempted",
    ),
}


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _safe_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
    ):
        raise ValueError(f"Unsafe failure-classification {label}")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"Failure-classification {label} must be a SHA-256 digest")
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError("Failure-classification evaluation_time must use canonical UTC RFC3339")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError("Failure-classification evaluation_time must use canonical UTC RFC3339")
    return parsed


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return value


def _validate(name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload), key=lambda item: list(item.path)
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Failure-classification schema validation failed: {detail}")


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/failure_taxonomy.py", files("smf").joinpath("failure_taxonomy.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/failure-classification-result.schema.json",
            files("smf.schemas").joinpath("failure-classification-result.schema.json"),
        ),
        (
            "smf/schemas/failure-classification-telemetry.schema.json",
            files("smf.schemas").joinpath("failure-classification-telemetry.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _request_binding(request: FailureClassificationRequest) -> dict[str, Any]:
    for name in ("client_id", "source_id", "workload_id", "run_id", "attempt_id", "event_id"):
        _safe_id(getattr(request, name), name)
    _time(request.evaluation_time)
    if not isinstance(request.stage, FailureStage) or not isinstance(request.reason, FailureReason):
        raise ValueError("Failure-classification stage and reason must use strict enums")
    policy = _POLICIES[request.reason]
    if request.stage is not policy.stage:
        raise ValueError("Failure-classification reason contradicts its authoritative stage")
    if not request.evidence:
        raise ValueError("Failure-classification requires governed evidence references")
    seen_evidence: set[str] = set()
    seen_paths: set[str] = set()
    evidence: list[dict[str, str]] = []
    for evidence_ref in request.evidence:
        _safe_id(evidence_ref.evidence_id, "evidence_id")
        if not isinstance(evidence_ref.evidence_class, EvidenceClass):
            raise ValueError("Failure-classification evidence_class must use the strict enum")
        _sha(evidence_ref.sha256, "evidence sha256")
        relative = Path(evidence_ref.relative_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or contains_protected_data(evidence_ref.relative_path)
        ):
            raise ValueError("Unsafe failure-classification evidence reference")
        if evidence_ref.evidence_id in seen_evidence:
            raise ValueError("Failure-classification evidence references must be unique")
        if evidence_ref.relative_path in seen_paths:
            raise ValueError("Failure-classification evidence paths must be unique")
        raw = read_published_bytes(
            request.evidence_root / relative,
            root=request.evidence_root,
            label="FAIL-01 upstream evidence",
        )
        if hashlib.sha256(raw).hexdigest() != evidence_ref.sha256:
            raise ValueError("Failure-classification upstream evidence digest differs")
        seen_evidence.add(evidence_ref.evidence_id)
        seen_paths.add(evidence_ref.relative_path)
        evidence.append(
            {
                "evidence_id": evidence_ref.evidence_id,
                "evidence_class": evidence_ref.evidence_class.value,
                "relative_path": evidence_ref.relative_path,
                "sha256": evidence_ref.sha256,
            }
        )
    if policy.required_evidence.value not in {item["evidence_class"] for item in evidence}:
        raise ValueError("Failure-classification lacks the reason-specific evidence class")
    if not request.causes:
        raise ValueError("Failure-classification requires an explicit cause")
    seen_causes: set[str] = set()
    causes: list[dict[str, str]] = []
    for cause_ref in request.causes:
        _safe_id(cause_ref.cause_id, "cause_id")
        _sha(cause_ref.content_digest, "cause content_digest")
        if cause_ref.relation not in {"observed_in", "caused_by"}:
            raise ValueError("Failure-classification cause relation is unsupported")
        if cause_ref.cause_id == request.event_id or cause_ref.cause_id in seen_causes:
            raise ValueError("Failure-classification causal chain is cyclic or duplicated")
        if cause_ref.relation == "observed_in":
            matched = next(
                (
                    item
                    for item in evidence
                    if item["evidence_id"] == cause_ref.cause_id
                    and item["sha256"] == cause_ref.content_digest
                ),
                None,
            )
            if matched is None:
                raise ValueError(
                    "Failure-classification observed cause is not bound to acquired evidence"
                )
        seen_causes.add(cause_ref.cause_id)
        causes.append(asdict(cause_ref))
    if not any(item["relation"] == "observed_in" for item in causes):
        raise ValueError("Failure-classification lacks a root observed cause")
    return {
        "client_id": request.client_id,
        "source_id": request.source_id,
        "workload_id": request.workload_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "event_id": request.event_id,
        "stage": request.stage.value,
        "reason_code": request.reason.value,
        "evaluation_time": request.evaluation_time,
        "evidence": evidence,
        "causes": causes,
    }


def _claims() -> dict[str, bool]:
    return {
        "retry_executed": False,
        "ai_gateway_invoked": False,
        "provider_invoked": False,
        "external_system_contacted": False,
        "exception_approved": False,
        "human_decision_obtained": False,
        "validated": False,
        "parity_passed": False,
        "migration_ready": False,
        "production_ready": False,
        "migration_complete": False,
    }


def prepare_failure_classification(
    request: FailureClassificationRequest,
) -> PreparedFailureClassification:
    """Classify a governed failure observation without executing the next action."""

    binding = _request_binding(request)
    policy = _POLICIES[request.reason]
    implementation = _implementation_manifest()
    identity = {
        **{
            key: binding[key]
            for key in ("client_id", "source_id", "workload_id", "run_id", "attempt_id", "event_id")
        },
        "evaluation_time": request.evaluation_time,
        "evidence_digest": _digest(binding["evidence"]),
        "causal_chain_digest": _digest(binding["causes"]),
        "implementation_digest": _digest(implementation),
        "taxonomy_version": "fail-01.1.0",
    }
    classification = {
        "stage": policy.stage.value,
        "reason_code": request.reason.value,
        "category": policy.category,
        "owner": policy.owner,
        "retryability": policy.retryability,
        "repairability": policy.repairability,
        "blocker_class": policy.blocker_class,
        "terminal_disposition": policy.terminal_disposition,
        "next_action": policy.next_action,
        "side_effect_state": policy.side_effect_state,
    }
    lifecycle = {
        "generated": policy.generated_state,
        "executed": policy.execution_state,
        "validated": policy.validation_state,
        "parity": policy.parity_state,
        "human_assisted": "pending" if policy.repairability == "human_decision" else "not_observed",
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "fail-01.1.0",
        "failure_id": "pending",
        "content_digest": "0" * 64,
        "canonical_evidence_reference": (
            f"runs/{request.run_id}/workloads/{request.workload_id}/attempts/"
            f"{request.attempt_id}/failures/{request.event_id}/{_RESULT_NAME}"
        ),
        "identity": identity,
        "classification": classification,
        "lifecycle": lifecycle,
        "evidence": binding["evidence"],
        "causes": binding["causes"],
        "implementation_manifest": implementation,
        "claims": _claims(),
    }
    result["failure_id"] = stable_id(
        "FAILRES",
        {
            key: value
            for key, value in result.items()
            if key not in {"failure_id", "content_digest"}
        },
    )
    result["content_digest"] = _digest(
        {key: value for key, value in result.items() if key != "content_digest"}
    )
    telemetry = telemetry_from_failure(result)
    _validate("failure-classification-result.schema.json", result)
    _validate("failure-classification-telemetry.schema.json", telemetry)
    return PreparedFailureClassification(result=result, telemetry=telemetry)


def telemetry_from_failure(result: dict[str, Any]) -> dict[str, Any]:
    classification = result["classification"]
    telemetry = {
        "schema_version": "1.0",
        "failure_id": result["failure_id"],
        "workload_id": result["identity"]["workload_id"],
        "run_id": result["identity"]["run_id"],
        "attempt_id": result["identity"]["attempt_id"],
        "stage": classification["stage"],
        "reason_code": classification["reason_code"],
        "terminal_disposition": classification["terminal_disposition"],
        "retryability": classification["retryability"],
        "next_action": classification["next_action"],
        "lifecycle": dict(result["lifecycle"]),
        "evidence_count": len(result["evidence"]),
        "cause_count": len(result["causes"]),
        "claims": dict(result["claims"]),
    }
    _validate("failure-classification-telemetry.schema.json", telemetry)
    return telemetry


def verify_failure_telemetry(telemetry: dict[str, Any], result: dict[str, Any]) -> None:
    """Verify that telemetry is the exact strict projection of a canonical result."""

    _validate("failure-classification-telemetry.schema.json", telemetry)
    if telemetry != telemetry_from_failure(result):
        raise ValueError("Failure telemetry differs from the canonical result")


def verify_failure_classification(
    result: dict[str, Any], request: FailureClassificationRequest
) -> None:
    _validate("failure-classification-result.schema.json", result)
    expected_digest = _digest(
        {key: value for key, value in result.items() if key != "content_digest"}
    )
    if result["content_digest"] != expected_digest:
        raise ValueError("Failure-classification content digest is invalid")
    expected_id = stable_id(
        "FAILRES",
        {
            key: value
            for key, value in result.items()
            if key not in {"failure_id", "content_digest"}
        },
    )
    if result["failure_id"] != expected_id:
        raise ValueError("Failure-classification identity is invalid")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("Failure-classification implementation manifest differs from runtime")
    if any(result["claims"].values()):
        raise ValueError("Failure-classification contains an unauthorized operational claim")
    replayed = prepare_failure_classification(request)
    if result != replayed.result:
        raise ValueError("Failure-classification differs from current governed inputs")


def publish_failure_classification(
    request: FailureClassificationRequest, prepared: PreparedFailureClassification
) -> tuple[Path, Path]:
    replayed = prepare_failure_classification(request)
    if replayed != prepared:
        raise ValueError("Prepared failure classification differs from current governed inputs")
    verify_failure_classification(prepared.result, request)
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    reference = Path(prepared.result["canonical_evidence_reference"])
    if reference.is_absolute() or ".." in reference.parts:
        raise ValueError("Failure-classification evidence reference escapes output root")
    result_path = root / reference
    ensure_directory(result_path.parent, root=root)
    publish_json(result_path, prepared.result, "FAIL-01 result", root=root)
    canonical = read_published_json(result_path, root=root, label="FAIL-01 result")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical failure classification is not an object")
    verify_failure_classification(canonical, request)
    telemetry = telemetry_from_failure(canonical)
    if telemetry != prepared.telemetry:
        raise ValueError("Failure telemetry is not derived from the canonical result")
    verify_failure_telemetry(telemetry, canonical)
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    publish_json(telemetry_path, telemetry, "FAIL-01 telemetry", root=root)
    return result_path, telemetry_path


def recover_failure_classification(
    request: FailureClassificationRequest,
) -> PreparedFailureClassification | None:
    """Recover only a missing telemetry projection after full current-input replay."""

    replayed = prepare_failure_classification(request)
    root = Path(os.path.abspath(os.fspath(request.output_root)))
    result_path = root / Path(replayed.result["canonical_evidence_reference"])
    telemetry_path = result_path.with_name(_TELEMETRY_NAME)
    if not published_file_exists(result_path, root=root, label="FAIL-01 result"):
        return None
    if published_file_exists(telemetry_path, root=root, label="FAIL-01 telemetry"):
        return None
    payload = read_published_json(result_path, root=root, label="FAIL-01 result")
    if not isinstance(payload, dict):
        raise ValueError("Canonical failure classification is not an object")
    verify_failure_classification(payload, request)
    if payload != replayed.result:
        raise ValueError("Canonical failure classification differs from current governed inputs")
    return PreparedFailureClassification(payload, telemetry_from_failure(payload))
