from __future__ import annotations

from collections.abc import Mapping

from .models import BacklogItem, CandidateAssessment, Readiness

_PRIORITY = {"P0": 0, "P1": 1, "P2": 2}


def assess_candidates(
    items: tuple[BacklogItem, ...],
    dependencies: Mapping[str, tuple[str, ...]] | None = None,
    *,
    focus: str | None = None,
) -> tuple[CandidateAssessment, ...]:
    deps = dependencies or {}
    by_key = {item.key: item for item in items}
    assessments: list[CandidateAssessment] = []
    focus_item = by_key.get(focus) if focus else None
    if focus and (focus_item is None or not focus_item.is_epic):
        raise ValueError(f"Focus must identify an existing epic: {focus}")

    for item in items:
        if item.is_epic:
            continue
        if focus and item.parent != focus:
            continue
        required = deps.get(item.key, ())
        missing = tuple(key for key in required if key not in by_key or not by_key[key].complete)
        if item.complete:
            state = Readiness.COMPLETE
            reasons = ("already Foundation Complete",)
        elif missing:
            state = Readiness.BLOCKED
            reasons = ("one or more explicit dependencies are incomplete",)
        elif item.active:
            state = Readiness.ACTIVE
            reasons = ("historically partial/in progress; dependencies are satisfied",)
        else:
            state = Readiness.READY
            reasons = ("all explicit dependencies are satisfied",)
        if focus and state in {Readiness.ACTIVE, Readiness.READY}:
            incomplete_siblings = tuple(
                sibling
                for sibling in items
                if sibling.parent == focus and not sibling.is_epic and not sibling.complete
            )
            if len(incomplete_siblings) == 1:
                reasons = (
                    f"only remaining incomplete child of focused epic {focus}; "
                    "dependencies are satisfied",
                )
            else:
                reasons = (f"ready child of focused epic {focus}",)
        assessments.append(
            CandidateAssessment(
                item=item,
                readiness=state,
                blockers=missing,
                reasons=reasons,
                rank=(
                    _PRIORITY.get(item.priority, 9),
                    0 if item.implementation_state == "Partial" else 1,
                    item.key,
                ),
            )
        )
    return tuple(sorted(assessments, key=lambda item: item.rank))


def recommend_next(
    assessments: tuple[CandidateAssessment, ...],
) -> CandidateAssessment | None:
    return next(
        (item for item in assessments if item.readiness in {Readiness.ACTIVE, Readiness.READY}),
        None,
    )
