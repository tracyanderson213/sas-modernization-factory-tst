"""Pure deterministic representativeness and anti-cherry-picking selection."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from smf.pilot.inventory import verify_inventory
from smf.pilot.models import (
    AdmissionState,
    CandidateDecision,
    Membership,
    PilotSelectionRequest,
    PilotSelectionResult,
    SelectionDisposition,
)
from smf.pilot.policy import policy_digest
from smf.readiness.policy import digest_value
from smf.workload.identity import stable_id


def _dimensions(candidate: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    return {
        "complexity": (candidate["complexity"],),
        "construct": tuple(sorted(candidate["constructs"])),
        "macro_behavior": tuple(sorted(candidate["macro_behaviors"])),
        "dependency": tuple(sorted(candidate["dependency_characteristics"])),
        "data_access": tuple(sorted(candidate["data_access_categories"])),
        "validation_difficulty": (candidate["validation_difficulty"],),
    }


def _admission(reasons: tuple[str, ...]) -> AdmissionState:
    if any("prerequisite_denied:" in reason for reason in reasons):
        return AdmissionState.DENIED
    if any("prerequisite_pending:" in reason for reason in reasons):
        return AdmissionState.PENDING
    if reasons:
        return AdmissionState.BLOCKED
    return AdmissionState.ELIGIBLE


def _coverage(
    selected: list[dict[str, Any]], criteria: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, int]], tuple[str, ...]]:
    coverage: dict[str, dict[str, int]] = {}
    uncovered: list[str] = []
    for criterion in criteria:
        actual = sum(
            1
            for candidate in selected
            if criterion["value"] in _dimensions(candidate)[criterion["dimension"]]
        )
        coverage[criterion["criterion_id"]] = {
            "required": criterion["minimum_count"],
            "actual": actual,
        }
        if actual < criterion["minimum_count"]:
            uncovered.append(criterion["criterion_id"])
    return coverage, tuple(uncovered)


def evaluate_pilot_selection(
    request: PilotSelectionRequest, *, evaluated_at: datetime | None = None
) -> PilotSelectionResult:
    policy = request.policy.payload
    if policy_digest(policy) != request.policy.policy_digest:
        raise ValueError("Pilot policy object is not canonical")
    inventory = deepcopy(request.inventory)
    blockers_by_workload, denominator = verify_inventory(
        inventory,
        request.inventory_root,
        policy,
        request.run_id,
        request.attempt_id,
        verified_at=evaluated_at,
    )
    candidates = inventory["candidates"]
    permitted = set(policy["permitted_origins"])
    enriched: list[tuple[dict[str, Any], tuple[str, ...], AdmissionState]] = []
    for candidate in candidates:
        candidate_reasons = list(blockers_by_workload[candidate["workload_id"]])
        if candidate["source_origin"] not in permitted:
            candidate_reasons.append("source_origin_not_permitted")
        reasons_tuple = tuple(sorted(set(candidate_reasons)))
        enriched.append((candidate, reasons_tuple, _admission(reasons_tuple)))

    pool = [
        item
        for item in enriched
        if item[2] is AdmissionState.ELIGIBLE or policy["blocked_members_occupy_slots"]
    ]
    selected: list[dict[str, Any]] = []
    if policy["dependency_grouping"] == "atomic":
        grouped: dict[str, list[tuple[dict[str, Any], tuple[str, ...], AdmissionState]]] = {}
        for item in pool:
            group_id = item[0]["coupling_group"] or f"workload:{item[0]['workload_id']}"
            grouped.setdefault(group_id, []).append(item)
        remaining = [tuple(value) for _, value in sorted(grouped.items())]
    else:
        remaining = [(item,) for item in pool]
    criteria = policy["criteria"]
    while remaining and len(selected) < policy["cohort_size"]:
        current, _ = _coverage(selected, criteria)

        def rank(
            unit: tuple[tuple[dict[str, Any], tuple[str, ...], AdmissionState], ...],
            coverage_state: dict[str, dict[str, int]] = current,
        ) -> tuple[int, int, str]:
            unit_candidates = [item[0] for item in unit]
            gain = sum(
                1
                for criterion in criteria
                if coverage_state[criterion["criterion_id"]]["actual"] < criterion["minimum_count"]
                and any(
                    criterion["value"] in _dimensions(candidate)[criterion["dimension"]]
                    for candidate in unit_candidates
                )
            )
            return (
                -gain,
                -max(candidate["complexity_score"] for candidate in unit_candidates),
                min(candidate["workload_id"] for candidate in unit_candidates),
            )

        chosen = min(remaining, key=rank)
        remaining.remove(chosen)
        if len(selected) + len(chosen) <= policy["cohort_size"]:
            selected.extend(item[0] for item in chosen)

    selected_ids = {item["workload_id"] for item in selected}
    coverage, uncovered = _coverage(selected, criteria)
    decisions: list[CandidateDecision] = []
    for candidate, reasons, state in enriched:
        owners = tuple(
            sorted(
                {item["owner"] for item in candidate["prerequisites"] if item["state"] != "passed"}
            )
        )
        if reasons and not owners:
            owners = (policy["owner_roles"]["selection_exception"],)
        included = candidate["workload_id"] in selected_ids
        decision_reasons = list(reasons)
        if not included:
            decision_reasons.append("not_selected_by_deterministic_rank")
        decisions.append(
            CandidateDecision(
                workload_id=candidate["workload_id"],
                boundary_id=candidate["boundary_id"],
                source_closure_digest=candidate["source_closure_digest"],
                script_ids=tuple(candidate["script_ids"]),
                membership=Membership.INCLUDED if included else Membership.EXCLUDED,
                admission_state=state,
                dimensions=_dimensions(candidate),
                complexity_score=candidate["complexity_score"],
                reasons=tuple(sorted(set(decision_reasons))),
                owners=owners,
            )
        )

    blockers: list[dict[str, str]] = []
    if (
        denominator != policy["expected_inventory_size"]
        or denominator != inventory["expected_competition_denominator"]
    ):
        blockers.append(
            {"code": "inventory_denominator_mismatch", "owner": policy["owner_roles"]["inventory"]}
        )
    if inventory["unprocessable"]:
        blockers.append(
            {"code": "unprocessable_inventory_records", "owner": policy["owner_roles"]["inventory"]}
        )
    for criterion_id in uncovered:
        blockers.append(
            {
                "code": f"uncovered_criterion:{criterion_id}",
                "owner": policy["owner_roles"]["selection_exception"],
            }
        )
    for decision in decisions:
        if (
            decision.membership is Membership.INCLUDED
            and decision.admission_state is not AdmissionState.ELIGIBLE
        ):
            blockers.append(
                {
                    "code": f"selected_{decision.admission_state.value}:{decision.workload_id}",
                    "owner": (decision.owners or (policy["owner_roles"]["selection_exception"],))[
                        0
                    ],
                }
            )
    if len(selected) != policy["cohort_size"]:
        blockers.append(
            {"code": "cohort_capacity_unmet", "owner": policy["owner_roles"]["selection_exception"]}
        )

    instant_dt = (evaluated_at or datetime.now(UTC)).astimezone(UTC)
    valid_from = datetime.fromisoformat(policy["valid_from"].replace("Z", "+00:00"))
    valid_until = (
        datetime.fromisoformat(policy["valid_until"].replace("Z", "+00:00"))
        if policy["valid_until"]
        else None
    )
    if (
        policy["status"] != "active"
        or instant_dt < valid_from
        or (valid_until is not None and instant_dt > valid_until)
    ):
        blockers.append(
            {
                "code": "selection_policy_inactive",
                "owner": policy["owner_roles"]["selection_exception"],
            }
        )
    disposition = SelectionDisposition.QUALIFIED
    if blockers:
        pending_only = all(item["code"].startswith("selected_pending:") for item in blockers)
        disposition = (
            SelectionDisposition.HUMAN_REQUIRED
            if pending_only and not uncovered and not inventory["unprocessable"]
            else SelectionDisposition.BLOCKED
        )
    instant = instant_dt.isoformat()
    identity = {
        "client_id": inventory["client_id"],
        "inventory_id": inventory["inventory_id"],
        "policy_id": policy["policy_id"],
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
    }
    result = PilotSelectionResult(
        schema_version="1.0",
        selection_id=stable_id("PSEL", identity),
        client_id=inventory["client_id"],
        inventory_id=inventory["inventory_id"],
        inventory_version=inventory["inventory_version"],
        inventory_digest=inventory["inventory_digest"],
        policy_id=policy["policy_id"],
        policy_version=policy["policy_version"],
        policy_digest=request.policy.policy_digest,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
        evaluated_at=instant,
        full_inventory_denominator=denominator,
        expected_competition_denominator=inventory["expected_competition_denominator"],
        selected_count=len(selected),
        excluded_count=len(candidates) - len(selected),
        unprocessable_count=len(inventory["unprocessable"]),
        coverage=coverage,
        uncovered_criteria=uncovered,
        decisions=tuple(decisions),
        blockers=tuple(blockers),
        disposition=disposition,
        inventory_snapshot=inventory,
        policy_snapshot=policy,
    )
    payload = result.to_dict()
    payload.pop("content_digest")
    return PilotSelectionResult(**{**result.__dict__, "content_digest": digest_value(payload)})
