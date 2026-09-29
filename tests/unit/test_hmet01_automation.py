from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from smf.immutable_files import publish_json
from smf.metrics.automation import (
    AttemptEvidenceReference,
    CohortMember,
    HMETPolicy,
    evaluate_automation_metrics,
    publish_automation_metrics,
    verify_automation_metrics,
    verify_current_automation_metrics,
)

SHA_A = "a" * 64
SHA_B = "b" * 64


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reseal(result: dict[str, Any]) -> None:
    result["content_digest"] = ""
    projection = {key: value for key, value in result.items() if key != "result_id"}
    projection.pop("content_digest")
    result["result_id"] = _digest(projection)
    content = {key: value for key, value in result.items() if key != "content_digest"}
    result["content_digest"] = _digest(content)


def _members() -> tuple[CohortMember, ...]:
    return tuple(
        CohortMember(f"workload-{index}", f"source-{index}", SHA_A, (f"script-{index}",))
        for index in range(1, 6)
    )


def _policy(**changes: object) -> HMETPolicy:
    values: dict[str, object] = {
        "policy_id": "competition-automation-kpi",
        "policy_version": "1.0.0",
        "authority_id": "synthetic-cohort-authority",
        "authority_digest": SHA_B,
        "client_id": "synthetic-client",
        "cohort_id": "competition-cohort",
        "cohort_version": "v1",
        "window_started_at": "2026-09-21T00:00:00Z",
        "window_ended_at": "2026-09-21T01:00:00Z",
        "evaluated_at": "2026-09-21T01:00:00Z",
        "members": _members(),
    }
    values.update(changes)
    return HMETPolicy(**values)  # type: ignore[arg-type]


def _attempt(
    workload: int,
    ordinal: int,
    outcome: str,
    *,
    conversion_path: str = "deterministic",
    human_touch: str = "none",
    human_minutes: int = 0,
    repair_attempts: int = 0,
    claims: tuple[bool, bool, bool, bool] | None = None,
    blockers: tuple[str, ...] = (),
) -> dict[str, object]:
    defaults = {
        "validated_parity": (True, True, True, True),
        "validated_no_parity": (True, True, True, False),
        "generated_only": (True, False, False, False),
        "executed_unvalidated": (True, True, False, False),
        "failed": (True, False, False, False),
        "blocked": (False, False, False, False),
        "skipped": (False, False, False, False),
    }
    generated, executed, validated, parity = claims or defaults[outcome]
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "evidence_id": f"evidence-{workload}-{ordinal}",
        "evidence_authority_id": "synthetic-cohort-authority",
        "evidence_authority_digest": SHA_B,
        "client_id": "synthetic-client",
        "cohort_id": "competition-cohort",
        "workload_id": f"workload-{workload}",
        "source_artifact_id": f"source-{workload}",
        "source_artifact_digest": SHA_A,
        "run_id": "run-1",
        "attempt_id": f"attempt-{workload}-{ordinal}",
        "attempt_ordinal": ordinal,
        "lifecycle_result_id": f"lifecycle-{workload}-{ordinal}",
        "lifecycle_result_digest": SHA_B,
        "observed_at": f"2026-09-21T00:{workload}{ordinal}:00Z",
        "elapsed_ms": 1000,
        "machine_ms": 800,
        "human_minutes": human_minutes,
        "repair_attempts": repair_attempts,
        "conversion_path": conversion_path,
        "human_touch": human_touch,
        "outcome": outcome,
        "blocker_codes": list(blockers),
        "claims": {
            "generated": generated,
            "executed": executed,
            "validated": validated,
            "parity_passed": parity,
        },
        "content_digest": "",
    }
    payload["content_digest"] = _digest(payload)
    return payload


def _publish_attempt(root: Path, payload: dict[str, object]) -> AttemptEvidenceReference:
    relative = f"attempts/{payload['workload_id']}/{payload['attempt_id']}.json"
    publish_json(root / relative, payload, "synthetic HMET attempt", root=root)
    return AttemptEvidenceReference(
        str(payload["workload_id"]),
        str(payload["attempt_id"]),
        str(payload["content_digest"]),
        relative,
    )


def _mixed_receipts(root: Path) -> tuple[AttemptEvidenceReference, ...]:
    payloads = (
        _attempt(1, 1, "validated_parity"),
        _attempt(2, 1, "failed", blockers=("conversion_failed",)),
        _attempt(2, 2, "validated_parity", conversion_path="ai_assisted", repair_attempts=1),
        _attempt(
            3,
            1,
            "validated_parity",
            human_touch="repair",
            human_minutes=20,
            repair_attempts=1,
        ),
        _attempt(4, 1, "blocked", blockers=("external_authority_missing",)),
    )
    return tuple(_publish_attempt(root, payload) for payload in payloads)


def test_distinct_workload_metrics_are_mutually_explainable(tmp_path: Path) -> None:
    result = evaluate_automation_metrics(_policy(), tmp_path, _mixed_receipts(tmp_path))
    metrics = result["metrics"]
    assert metrics["workload_denominator"] == 5
    assert metrics["script_denominator"] == 5
    assert metrics["attempt_count"] == 5
    assert metrics["retry_count"] == 1
    assert metrics["parity_workloads"] == 3
    assert metrics["straight_through_parity_workloads"] == 1
    assert metrics["eventual_automated_parity_workloads"] == 1
    assert metrics["human_assisted_parity_workloads"] == 1
    assert metrics["blocked_or_unresolved_workloads"] == 2
    assert metrics["parity_rate"] == "0.600000"
    assert metrics["parity_workloads_per_hour"] == "3.000000"
    assert result["outcome_distribution"]["blocked"] == 1
    assert result["outcome_distribution"]["unresolved"] == 1


def test_retries_do_not_multiply_success_and_blockers_do_not_disappear(tmp_path: Path) -> None:
    refs = _mixed_receipts(tmp_path)
    result = evaluate_automation_metrics(_policy(), tmp_path, refs)
    workload_two = result["member_outcomes"][1]
    assert workload_two["attempt_count"] == 2
    assert workload_two["parity_passed"] is True
    assert workload_two["blocker_codes"] == ["conversion_failed"]
    assert result["metrics"]["parity_workloads"] == 3


def test_generated_or_executed_work_never_counts_as_parity(tmp_path: Path) -> None:
    policy = _policy(members=_members()[:2])
    refs = (
        _publish_attempt(tmp_path, _attempt(1, 1, "generated_only")),
        _publish_attempt(tmp_path, _attempt(2, 1, "executed_unvalidated")),
    )
    result = evaluate_automation_metrics(policy, tmp_path, refs)
    assert result["metrics"]["generated_workloads"] == 2
    assert result["metrics"]["executed_workloads"] == 1
    assert result["metrics"]["validated_workloads"] == 0
    assert result["metrics"]["parity_workloads"] == 0


def test_human_touch_cannot_be_relabelled_as_autonomous(tmp_path: Path) -> None:
    invalid = _attempt(1, 1, "validated_parity", human_minutes=5)
    ref = _publish_attempt(tmp_path, invalid)
    with pytest.raises(ValueError, match="human minutes"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))


def test_invalid_stage_claim_progression_and_outcome_are_rejected(tmp_path: Path) -> None:
    invalid = _attempt(1, 1, "validated_parity", claims=(True, False, True, True))
    ref = _publish_attempt(tmp_path, invalid)
    with pytest.raises(ValueError, match="progression"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))


@pytest.mark.parametrize(
    "outcome",
    [
        "validated_no_parity",
        "blocked",
        "failed",
        "unsupported",
        "cancelled",
        "outcome_unknown",
        "skipped",
    ],
)
def test_non_parity_outcomes_cannot_assert_parity(tmp_path: Path, outcome: str) -> None:
    blockers = () if outcome in {"validated_no_parity", "cancelled"} else ("not_parity",)
    payload = _attempt(
        1,
        1,
        outcome,
        claims=(True, True, True, True),
        blockers=blockers,
    )
    ref = _publish_attempt(tmp_path, payload)
    with pytest.raises(ValueError, match="non-parity|outcome"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))


@pytest.mark.parametrize("touch", ["review", "repair", "business_decision"])
def test_earlier_human_touch_prevents_automated_relabel(tmp_path: Path, touch: str) -> None:
    policy = _policy(members=_members()[:1])
    refs = (
        _publish_attempt(
            tmp_path,
            _attempt(
                1,
                1,
                "failed",
                human_touch=touch,
                human_minutes=5,
                blockers=("first_attempt_failed",),
            ),
        ),
        _publish_attempt(tmp_path, _attempt(1, 2, "validated_parity")),
    )
    result = evaluate_automation_metrics(policy, tmp_path, refs)
    assert result["member_outcomes"][0]["category"] == "human_assisted_parity"
    assert result["member_outcomes"][0]["human_assisted"] is True
    assert result["metrics"]["eventual_automated_parity_workloads"] == 0
    assert result["metrics"]["human_minutes_total"] == 5


def test_skipped_workload_remains_visible_and_never_counts_as_parity(tmp_path: Path) -> None:
    ref = _publish_attempt(tmp_path, _attempt(1, 1, "skipped", blockers=("unsupported_selection",)))
    result = evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))
    assert result["outcome_distribution"]["skipped"] == 1
    assert result["metrics"]["parity_workloads"] == 0
    assert result["metrics"]["blocked_or_unresolved_workloads"] == 1


def test_duplicate_attempt_and_success_after_success_are_rejected(tmp_path: Path) -> None:
    first = _publish_attempt(tmp_path, _attempt(1, 1, "validated_parity"))
    with pytest.raises(ValueError, match="duplicate"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (first, first))
    second = _publish_attempt(
        tmp_path, _attempt(1, 2, "validated_parity", conversion_path="ai_assisted")
    )
    with pytest.raises(ValueError, match="multiply success"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (first, second))


def test_attempt_scope_source_and_window_are_governed(tmp_path: Path) -> None:
    outside = _attempt(1, 1, "blocked", blockers=("blocked",))
    outside["cohort_id"] = "other-cohort"
    outside["content_digest"] = ""
    outside["content_digest"] = _digest(outside)
    ref = _publish_attempt(tmp_path, outside)
    with pytest.raises(ValueError, match="differs from the cohort"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))


def test_evidence_mutation_and_reference_substitution_fail(tmp_path: Path) -> None:
    payload = _attempt(1, 1, "validated_parity")
    ref = _publish_attempt(tmp_path, payload)
    path = tmp_path / ref.relative_path
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_automation_metrics(_policy(members=_members()[:1]), tmp_path, (ref,))


def test_immutable_publication_replay_and_workload_isolation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    refs = _mixed_receipts(evidence)
    path = publish_automation_metrics(output, _policy(), evidence, refs)
    assert publish_automation_metrics(output, _policy(), evidence, refs) == path
    assert verify_current_automation_metrics(path, output, _policy(), evidence, refs)["result_id"]
    alternate = replace(_policy(), cohort_id="other-cohort", members=_members()[:1])
    alternate_attempt = _attempt(1, 1, "blocked", blockers=("blocked",))
    alternate_attempt["cohort_id"] = "other-cohort"
    alternate_attempt["content_digest"] = ""
    alternate_attempt["content_digest"] = _digest(alternate_attempt)
    alternate_evidence = tmp_path / "alternate-evidence"
    alternate_ref = _publish_attempt(alternate_evidence, alternate_attempt)
    alternate_path = publish_automation_metrics(
        output, alternate, alternate_evidence, (alternate_ref,)
    )
    assert alternate_path != path
    (evidence / refs[0].relative_path).write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation"):
        verify_current_automation_metrics(path, output, _policy(), evidence, refs)


def test_coherent_result_claim_escalation_is_rejected(tmp_path: Path) -> None:
    result = evaluate_automation_metrics(_policy(), tmp_path, _mixed_receipts(tmp_path))
    escalated = copy.deepcopy(result)
    escalated["claims"]["real_humana_cohort"] = True
    with pytest.raises(ValueError, match="schema validation"):
        verify_automation_metrics(escalated)


def test_coherent_metric_and_category_mutations_are_rejected(tmp_path: Path) -> None:
    result = evaluate_automation_metrics(_policy(), tmp_path, _mixed_receipts(tmp_path))
    mutated = copy.deepcopy(result)
    mutated["metrics"]["parity_rate"] = "1.000000"
    _reseal(mutated)
    with pytest.raises(ValueError, match="rates"):
        verify_automation_metrics(mutated)
    category = copy.deepcopy(result)
    category["member_outcomes"][0]["category"] = "blocked"
    category["outcome_distribution"]["straight_through_parity"] -= 1
    category["outcome_distribution"]["blocked"] += 1
    _reseal(category)
    with pytest.raises(ValueError, match="parity category"):
        verify_automation_metrics(category)
    for metric in (
        "elapsed_ms_total",
        "machine_ms_total",
        "human_minutes_total",
        "repair_attempts_total",
    ):
        totals = copy.deepcopy(result)
        totals["metrics"][metric] += 1
        _reseal(totals)
        with pytest.raises(ValueError, match="effort totals"):
            verify_automation_metrics(totals)


def test_policy_rejects_duplicate_scripts_and_unsafe_identity() -> None:
    members = list(_members()[:2])
    members[1] = replace(members[1], script_ids=members[0].script_ids)
    with pytest.raises(ValueError, match="multiple workloads"):
        _policy(members=tuple(members)).binding()
    with pytest.raises(ValueError, match="Unsafe"):
        _policy(client_id="bearer-token").binding()


def test_public_and_packaged_schemas_match() -> None:
    root = Path(__file__).parents[2]
    for name in ("hmet01-attempt-evidence.schema.json", "hmet01-automation-result.schema.json"):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()
