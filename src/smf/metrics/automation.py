"""HMET-01 distinct-workload automation and throughput metrics.

The evaluator reads immutable attempt receipts and never infers parity from
generation, execution, validation, or lifecycle completion alone.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft202012Validator

from smf.immutable_files import publish_json, read_published_json

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

Outcome = Literal[
    "validated_parity",
    "validated_no_parity",
    "generated_only",
    "executed_unvalidated",
    "blocked",
    "failed",
    "unsupported",
    "cancelled",
    "outcome_unknown",
    "skipped",
]
HumanTouch = Literal["none", "review", "repair", "business_decision"]
ConversionPath = Literal["deterministic", "ai_assisted"]
_CATEGORIES = (
    "straight_through_parity",
    "eventual_automated_parity",
    "human_assisted_parity",
    "validated_no_parity",
    "generated_only",
    "executed_unvalidated",
    "blocked",
    "failed",
    "unsupported",
    "cancelled",
    "outcome_unknown",
    "skipped",
    "unresolved",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe(value: str, label: str) -> str:
    lowered = value.casefold()
    if (
        not isinstance(value, str)
        or not _ID.fullmatch(value)
        or value in {".", ".."}
        or any(word in lowered for word in ("secret", "password", "bearer", "token", "api-key"))
    ):
        raise ValueError(f"Unsafe HMET-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"HMET-01 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"HMET-01 {label} is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"HMET-01 {label} is not canonical UTC")
    return parsed


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text("utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{name} must contain an object")
    return cast(dict[str, Any], value)


def _validate(payload: dict[str, Any], name: str, label: str) -> None:
    errors = sorted(
        Draft202012Validator(_schema(name)).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"{label} schema validation failed: {detail}")


@dataclass(frozen=True)
class CohortMember:
    workload_id: str
    source_artifact_id: str
    source_artifact_digest: str
    script_ids: tuple[str, ...]

    def binding(self) -> dict[str, Any]:
        _safe(self.workload_id, "workload_id")
        _safe(self.source_artifact_id, "source_artifact_id")
        _sha(self.source_artifact_digest, "source_artifact_digest")
        if not self.script_ids or len(set(self.script_ids)) != len(self.script_ids):
            raise ValueError("HMET-01 script identities must be nonempty and unique per workload")
        for script_id in self.script_ids:
            _safe(script_id, "script_id")
        return {
            "workload_id": self.workload_id,
            "source_artifact_id": self.source_artifact_id,
            "source_artifact_digest": self.source_artifact_digest,
            "script_ids": list(self.script_ids),
        }


@dataclass(frozen=True)
class HMETPolicy:
    policy_id: str
    policy_version: str
    authority_id: str
    authority_digest: str
    client_id: str
    cohort_id: str
    cohort_version: str
    window_started_at: str
    window_ended_at: str
    evaluated_at: str
    members: tuple[CohortMember, ...]

    def binding(self) -> dict[str, Any]:
        for name in (
            "policy_id",
            "policy_version",
            "authority_id",
            "client_id",
            "cohort_id",
            "cohort_version",
        ):
            _safe(cast(str, getattr(self, name)), name)
        _sha(self.authority_digest, "authority_digest")
        started = _time(self.window_started_at, "window_started_at")
        ended = _time(self.window_ended_at, "window_ended_at")
        evaluated = _time(self.evaluated_at, "evaluated_at")
        if not started < ended <= evaluated:
            raise ValueError("HMET-01 measurement window is invalid")
        bindings = [member.binding() for member in self.members]
        workload_ids = [item["workload_id"] for item in bindings]
        if (
            not bindings
            or workload_ids != sorted(workload_ids)
            or len(set(workload_ids)) != len(workload_ids)
        ):
            raise ValueError("HMET-01 cohort members must be nonempty, unique, and sorted")
        script_ids = [script for item in bindings for script in item["script_ids"]]
        if len(script_ids) != len(set(script_ids)):
            raise ValueError("HMET-01 script identity cannot belong to multiple workloads")
        return {
            "schema_version": "1.0",
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
            "client_id": self.client_id,
            "cohort_id": self.cohort_id,
            "cohort_version": self.cohort_version,
            "window_started_at": self.window_started_at,
            "window_ended_at": self.window_ended_at,
            "evaluated_at": self.evaluated_at,
            "members": bindings,
        }


@dataclass(frozen=True)
class AttemptEvidenceReference:
    workload_id: str
    attempt_id: str
    content_digest: str
    relative_path: str

    def binding(self) -> dict[str, str]:
        _safe(self.workload_id, "reference workload_id")
        _safe(self.attempt_id, "reference attempt_id")
        _sha(self.content_digest, "reference content_digest")
        path = Path(self.relative_path)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("HMET-01 evidence reference path is unsafe")
        return asdict(self)


def _verify_attempt(payload: dict[str, Any]) -> None:
    _validate(payload, "hmet01-attempt-evidence.schema.json", "HMET-01 attempt evidence")
    for name in (
        "evidence_id",
        "client_id",
        "cohort_id",
        "workload_id",
        "source_artifact_id",
        "run_id",
        "attempt_id",
        "lifecycle_result_id",
        "evidence_authority_id",
    ):
        _safe(cast(str, payload[name]), name)
    for name in (
        "source_artifact_digest",
        "lifecycle_result_digest",
        "evidence_authority_digest",
    ):
        _sha(cast(str, payload[name]), name)
    _time(cast(str, payload["observed_at"]), "observed_at")
    claims = cast(dict[str, bool], payload["claims"])
    generated = claims["generated"]
    executed = claims["executed"]
    validated = claims["validated"]
    parity = claims["parity_passed"]
    if parity and not validated or validated and not executed or executed and not generated:
        raise ValueError("HMET-01 attempt claim progression is invalid")
    outcome = payload["outcome"]
    expected = {
        "validated_parity": (True, True, True, True),
        "validated_no_parity": (True, True, True, False),
        "generated_only": (True, False, False, False),
        "executed_unvalidated": (True, True, False, False),
    }.get(outcome)
    if expected is not None and (generated, executed, validated, parity) != expected:
        raise ValueError("HMET-01 outcome does not match stage claims")
    if outcome != "validated_parity" and parity:
        raise ValueError("HMET-01 non-parity outcome cannot assert parity")
    if payload["human_touch"] == "none" and payload["human_minutes"] != 0:
        raise ValueError("HMET-01 human minutes require an explicit human touch")
    if payload["human_touch"] != "none" and payload["human_minutes"] == 0:
        raise ValueError("HMET-01 explicit human touch requires measured minutes")
    if (
        outcome in {"blocked", "failed", "unsupported", "outcome_unknown", "skipped"}
        and not payload["blocker_codes"]
    ):
        raise ValueError("HMET-01 non-success outcome must retain blocker codes")
    expected_digest = _digest({**payload, "content_digest": ""})
    if payload["content_digest"] != expected_digest:
        raise ValueError("HMET-01 attempt evidence content digest mismatch")


def _load_attempt(root: Path, reference: AttemptEvidenceReference) -> dict[str, Any]:
    ref = reference.binding()
    payload = read_published_json(
        root / ref["relative_path"], root=root, label="HMET-01 attempt evidence"
    )
    if not isinstance(payload, dict):
        raise ValueError("HMET-01 attempt evidence must be an object")
    _verify_attempt(payload)
    if (
        payload["workload_id"] != ref["workload_id"]
        or payload["attempt_id"] != ref["attempt_id"]
        or payload["content_digest"] != ref["content_digest"]
    ):
        raise ValueError("HMET-01 attempt evidence reference mismatch")
    return payload


def _rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000000"
    return str(
        (Decimal(numerator) / Decimal(denominator)).quantize(
            Decimal("0.000001"), rounding=ROUND_HALF_UP
        )
    )


def _member_outcome(member: CohortMember, attempts: list[dict[str, Any]]) -> dict[str, Any]:
    if not attempts:
        return {
            "workload_id": member.workload_id,
            "script_ids": list(member.script_ids),
            "attempt_count": 0,
            "selected_attempt_id": None,
            "category": "unresolved",
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "human_assisted": False,
            "ai_assisted": False,
            "blocker_codes": ["attempt_evidence_missing"],
            "elapsed_ms": 0,
            "machine_ms": 0,
            "human_minutes": 0,
            "repair_attempts": 0,
        }
    attempts.sort(key=lambda item: item["attempt_ordinal"])
    ordinals = [item["attempt_ordinal"] for item in attempts]
    if ordinals != list(range(1, len(attempts) + 1)):
        raise ValueError("HMET-01 attempt ordinals must be contiguous from one")
    successes = [item for item in attempts if item["claims"]["parity_passed"]]
    if len(successes) > 1 or (successes and successes[0] is not attempts[-1]):
        raise ValueError("HMET-01 attempts advance after parity or multiply success")
    selected = successes[0] if successes else attempts[-1]
    human = any(item["human_touch"] != "none" for item in attempts)
    if selected["claims"]["parity_passed"]:
        if human:
            category = "human_assisted_parity"
        elif (
            selected["attempt_ordinal"] == 1
            and selected["conversion_path"] == "deterministic"
            and selected["repair_attempts"] == 0
        ):
            category = "straight_through_parity"
        else:
            category = "eventual_automated_parity"
    else:
        category = cast(str, selected["outcome"])
    blockers = sorted({code for item in attempts for code in item["blocker_codes"]})
    return {
        "workload_id": member.workload_id,
        "script_ids": list(member.script_ids),
        "attempt_count": len(attempts),
        "selected_attempt_id": selected["attempt_id"],
        "category": category,
        "generated": any(item["claims"]["generated"] for item in attempts),
        "executed": any(item["claims"]["executed"] for item in attempts),
        "validated": any(item["claims"]["validated"] for item in attempts),
        "parity_passed": bool(selected["claims"]["parity_passed"]),
        "human_assisted": human,
        "ai_assisted": any(item["conversion_path"] == "ai_assisted" for item in attempts),
        "blocker_codes": blockers,
        "elapsed_ms": sum(item["elapsed_ms"] for item in attempts),
        "machine_ms": sum(item["machine_ms"] for item in attempts),
        "human_minutes": sum(item["human_minutes"] for item in attempts),
        "repair_attempts": sum(item["repair_attempts"] for item in attempts),
    }


def evaluate_automation_metrics(
    policy: HMETPolicy,
    evidence_root: Path,
    references: tuple[AttemptEvidenceReference, ...],
) -> dict[str, Any]:
    policy_binding = policy.binding()
    members = {member.workload_id: member for member in policy.members}
    grouped: dict[str, list[dict[str, Any]]] = {workload_id: [] for workload_id in members}
    seen_attempts: set[tuple[str, str]] = set()
    loaded: list[dict[str, Any]] = []
    for reference in references:
        payload = _load_attempt(evidence_root, reference)
        key = (payload["workload_id"], payload["attempt_id"])
        if key in seen_attempts:
            raise ValueError("HMET-01 duplicate attempt evidence")
        seen_attempts.add(key)
        member = members.get(payload["workload_id"])
        if member is None:
            raise ValueError("HMET-01 attempt is outside the governed cohort")
        if (
            payload["client_id"] != policy.client_id
            or payload["cohort_id"] != policy.cohort_id
            or payload["evidence_authority_id"] != policy.authority_id
            or payload["evidence_authority_digest"] != policy.authority_digest
            or payload["source_artifact_id"] != member.source_artifact_id
            or payload["source_artifact_digest"] != member.source_artifact_digest
        ):
            raise ValueError("HMET-01 attempt identity differs from the cohort")
        observed = _time(payload["observed_at"], "attempt observed_at")
        if (
            not _time(policy.window_started_at, "window_started_at")
            <= observed
            <= _time(policy.window_ended_at, "window_ended_at")
        ):
            raise ValueError("HMET-01 attempt is outside the measurement window")
        grouped[member.workload_id].append(payload)
        loaded.append(payload)
    member_results = [
        _member_outcome(member, grouped[member.workload_id]) for member in policy.members
    ]
    distribution = Counter(item["category"] for item in member_results)
    denominator = len(member_results)
    generated = sum(item["generated"] for item in member_results)
    executed = sum(item["executed"] for item in member_results)
    validated = sum(item["validated"] for item in member_results)
    parity = sum(item["parity_passed"] for item in member_results)
    straight = distribution["straight_through_parity"]
    eventual = distribution["eventual_automated_parity"]
    human = distribution["human_assisted_parity"]
    window_seconds = int(
        (
            _time(policy.window_ended_at, "window_ended_at")
            - _time(policy.window_started_at, "window_started_at")
        ).total_seconds()
    )
    metrics = {
        "workload_denominator": denominator,
        "script_denominator": sum(len(member.script_ids) for member in policy.members),
        "attempt_count": len(loaded),
        "retry_count": sum(max(0, item["attempt_count"] - 1) for item in member_results),
        "generated_workloads": generated,
        "executed_workloads": executed,
        "validated_workloads": validated,
        "parity_workloads": parity,
        "straight_through_parity_workloads": straight,
        "eventual_automated_parity_workloads": eventual,
        "human_assisted_parity_workloads": human,
        "blocked_or_unresolved_workloads": denominator - parity,
        "generated_rate": _rate(generated, denominator),
        "executed_rate": _rate(executed, denominator),
        "validated_rate": _rate(validated, denominator),
        "parity_rate": _rate(parity, denominator),
        "straight_through_rate": _rate(straight, denominator),
        "eventual_automated_rate": _rate(eventual, denominator),
        "human_assisted_rate": _rate(human, denominator),
        "window_seconds": window_seconds,
        "parity_workloads_per_hour": str(
            (Decimal(parity) * Decimal(3600) / Decimal(window_seconds)).quantize(
                Decimal("0.000001"), rounding=ROUND_HALF_UP
            )
        ),
        "elapsed_ms_total": sum(item["elapsed_ms"] for item in member_results),
        "machine_ms_total": sum(item["machine_ms"] for item in member_results),
        "human_minutes_total": sum(item["human_minutes"] for item in member_results),
        "repair_attempts_total": sum(item["repair_attempts"] for item in member_results),
    }
    bound_references = sorted(
        (reference.binding() for reference in references),
        key=lambda item: (item["workload_id"], item["attempt_id"]),
    )
    projection: dict[str, Any] = {
        "schema_version": "1.0",
        "policy": policy_binding,
        "policy_digest": _digest(policy_binding),
        "evidence_references": bound_references,
        "evidence_set_digest": _digest(bound_references),
        "member_outcomes": member_results,
        "outcome_distribution": {name: distribution[name] for name in _CATEGORIES},
        "metrics": metrics,
        "claims": {
            "measured_from_immutable_evidence": True,
            "real_humana_cohort": False,
            "humana_validated": False,
            "production_throughput": False,
            "migration_complete": False,
        },
    }
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_automation_metrics(result)
    return result


def verify_automation_metrics(result: dict[str, Any]) -> None:
    _validate(result, "hmet01-automation-result.schema.json", "HMET-01 result")
    content = dict(result)
    content_digest = cast(str, content.pop("content_digest"))
    if content_digest != _digest(content):
        raise ValueError("HMET-01 result content digest mismatch")
    projection = dict(content)
    result_id = cast(str, projection.pop("result_id"))
    if result_id != _digest(projection):
        raise ValueError("HMET-01 result identity mismatch")
    policy_value = cast(dict[str, Any], result["policy"])
    policy = HMETPolicy(
        policy_id=policy_value["policy_id"],
        policy_version=policy_value["policy_version"],
        authority_id=policy_value["authority_id"],
        authority_digest=policy_value["authority_digest"],
        client_id=policy_value["client_id"],
        cohort_id=policy_value["cohort_id"],
        cohort_version=policy_value["cohort_version"],
        window_started_at=policy_value["window_started_at"],
        window_ended_at=policy_value["window_ended_at"],
        evaluated_at=policy_value["evaluated_at"],
        members=tuple(
            CohortMember(
                item["workload_id"],
                item["source_artifact_id"],
                item["source_artifact_digest"],
                tuple(item["script_ids"]),
            )
            for item in policy_value["members"]
        ),
    )
    if policy.binding() != policy_value or result["policy_digest"] != _digest(policy_value):
        raise ValueError("HMET-01 policy projection or digest mismatch")
    references = [
        AttemptEvidenceReference(**item).binding() for item in result["evidence_references"]
    ]
    if references != sorted(
        references, key=lambda item: (item["workload_id"], item["attempt_id"])
    ) or result["evidence_set_digest"] != _digest(references):
        raise ValueError("HMET-01 evidence reference set is not canonical")
    metrics = cast(dict[str, Any], result["metrics"])
    denominator = metrics["workload_denominator"]
    distribution = cast(dict[str, int], result["outcome_distribution"])
    outcomes = cast(list[dict[str, Any]], result["member_outcomes"])
    if [item["workload_id"] for item in outcomes] != [
        member.workload_id for member in policy.members
    ]:
        raise ValueError("HMET-01 member outcomes do not match the governed cohort")
    for item, member in zip(outcomes, policy.members, strict=True):
        if item["script_ids"] != list(member.script_ids):
            raise ValueError("HMET-01 member script denominator changed")
        if (item["attempt_count"] == 0) != (item["selected_attempt_id"] is None):
            raise ValueError("HMET-01 selected attempt is inconsistent")
        parity_category = item["category"] in {
            "straight_through_parity",
            "eventual_automated_parity",
            "human_assisted_parity",
        }
        if item["parity_passed"] != parity_category:
            raise ValueError("HMET-01 parity category is inconsistent")
        if parity_category and not (item["generated"] and item["executed"] and item["validated"]):
            raise ValueError("HMET-01 parity category lacks prerequisite stages")
        if parity_category and item["human_assisted"] != (
            item["category"] == "human_assisted_parity"
        ):
            raise ValueError("HMET-01 human-assisted category is inconsistent")
        if item["category"] == "unresolved" and item["attempt_count"] != 0:
            raise ValueError("HMET-01 unresolved member has attempt evidence")
    expected_distribution = Counter(item["category"] for item in outcomes)
    if distribution != {name: expected_distribution[name] for name in _CATEGORIES}:
        raise ValueError("HMET-01 outcome distribution is not derived from members")
    if sum(distribution.values()) != denominator:
        raise ValueError("HMET-01 outcome distribution omits or duplicates workloads")
    if metrics["parity_workloads"] != sum(
        metrics[name]
        for name in (
            "straight_through_parity_workloads",
            "eventual_automated_parity_workloads",
            "human_assisted_parity_workloads",
        )
    ):
        raise ValueError("HMET-01 parity categories are not mutually complete")
    if metrics["blocked_or_unresolved_workloads"] != denominator - metrics["parity_workloads"]:
        raise ValueError("HMET-01 blocked or unresolved work disappeared")
    expected_counts = {
        "workload_denominator": len(outcomes),
        "script_denominator": sum(len(item["script_ids"]) for item in outcomes),
        "attempt_count": sum(item["attempt_count"] for item in outcomes),
        "retry_count": sum(max(0, item["attempt_count"] - 1) for item in outcomes),
        "generated_workloads": sum(item["generated"] for item in outcomes),
        "executed_workloads": sum(item["executed"] for item in outcomes),
        "validated_workloads": sum(item["validated"] for item in outcomes),
        "parity_workloads": sum(item["parity_passed"] for item in outcomes),
        "straight_through_parity_workloads": distribution["straight_through_parity"],
        "eventual_automated_parity_workloads": distribution["eventual_automated_parity"],
        "human_assisted_parity_workloads": distribution["human_assisted_parity"],
    }
    if any(metrics[name] != value for name, value in expected_counts.items()):
        raise ValueError("HMET-01 metric counts are not derived from member outcomes")
    if metrics["attempt_count"] != len(references):
        raise ValueError("HMET-01 attempt denominator differs from evidence references")
    totals = {
        "elapsed_ms_total": "elapsed_ms",
        "machine_ms_total": "machine_ms",
        "human_minutes_total": "human_minutes",
        "repair_attempts_total": "repair_attempts",
    }
    if any(
        metrics[metric] != sum(item[field] for item in outcomes) for metric, field in totals.items()
    ):
        raise ValueError("HMET-01 effort totals do not reconstruct from member outcomes")
    expected_window = int(
        (
            _time(policy.window_ended_at, "window_ended_at")
            - _time(policy.window_started_at, "window_started_at")
        ).total_seconds()
    )
    if metrics["window_seconds"] != expected_window:
        raise ValueError("HMET-01 throughput window differs from policy")
    rate_pairs = {
        "generated_rate": "generated_workloads",
        "executed_rate": "executed_workloads",
        "validated_rate": "validated_workloads",
        "parity_rate": "parity_workloads",
        "straight_through_rate": "straight_through_parity_workloads",
        "eventual_automated_rate": "eventual_automated_parity_workloads",
        "human_assisted_rate": "human_assisted_parity_workloads",
    }
    if any(
        metrics[rate] != _rate(metrics[count], denominator) for rate, count in rate_pairs.items()
    ):
        raise ValueError("HMET-01 rates do not reconstruct from metric counts")
    expected_throughput = str(
        (
            Decimal(metrics["parity_workloads"])
            * Decimal(3600)
            / Decimal(metrics["window_seconds"])
        ).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    )
    if metrics["parity_workloads_per_hour"] != expected_throughput:
        raise ValueError("HMET-01 throughput does not reconstruct")


def result_path(root: Path, policy: HMETPolicy) -> Path:
    policy.binding()
    return root / policy.client_id / policy.cohort_id / policy.cohort_version / "hmet01.json"


def publish_automation_metrics(
    output_root: Path,
    policy: HMETPolicy,
    evidence_root: Path,
    references: tuple[AttemptEvidenceReference, ...],
) -> Path:
    result = evaluate_automation_metrics(policy, evidence_root, references)
    path = result_path(output_root, policy)
    publish_json(path, result, "HMET-01 automation metrics", root=output_root)
    verify_current_automation_metrics(path, output_root, policy, evidence_root, references)
    return path


def verify_current_automation_metrics(
    path: Path,
    output_root: Path,
    policy: HMETPolicy,
    evidence_root: Path,
    references: tuple[AttemptEvidenceReference, ...],
) -> dict[str, Any]:
    if path != result_path(output_root, policy):
        raise ValueError("HMET-01 result path is not policy-bound")
    observed = read_published_json(path, root=output_root, label="HMET-01 automation metrics")
    if not isinstance(observed, dict):
        raise ValueError("HMET-01 published result must be an object")
    verify_automation_metrics(observed)
    current = evaluate_automation_metrics(policy, evidence_root, references)
    if observed != current:
        raise ValueError("HMET-01 current inputs do not reconstruct immutable evidence")
    return observed
