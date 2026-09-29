"""Strict domain records for offline pilot-cohort selection."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class SelectionDisposition(StrEnum):
    QUALIFIED = "qualified"
    BLOCKED = "blocked"
    HUMAN_REQUIRED = "human_required"


class AdmissionState(StrEnum):
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    PENDING = "pending"
    DENIED = "denied"


class Membership(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


@dataclass(frozen=True)
class PilotSelectionPolicy:
    payload: dict[str, Any]
    policy_digest: str


@dataclass(frozen=True)
class PilotSelectionRequest:
    inventory: dict[str, Any]
    policy: PilotSelectionPolicy
    inventory_root: Path
    run_id: str
    attempt_id: str


@dataclass(frozen=True)
class CandidateDecision:
    workload_id: str
    boundary_id: str
    source_closure_digest: str
    script_ids: tuple[str, ...]
    membership: Membership
    admission_state: AdmissionState
    dimensions: dict[str, tuple[str, ...]]
    complexity_score: int
    reasons: tuple[str, ...]
    owners: tuple[str, ...]


@dataclass(frozen=True)
class PilotSelectionResult:
    schema_version: str
    selection_id: str
    client_id: str
    inventory_id: str
    inventory_version: str
    inventory_digest: str
    policy_id: str
    policy_version: str
    policy_digest: str
    run_id: str
    attempt_id: str
    evaluated_at: str
    full_inventory_denominator: int
    expected_competition_denominator: int
    selected_count: int
    excluded_count: int
    unprocessable_count: int
    coverage: dict[str, dict[str, int]]
    uncovered_criteria: tuple[str, ...]
    decisions: tuple[CandidateDecision, ...]
    blockers: tuple[dict[str, str], ...]
    disposition: SelectionDisposition
    inventory_snapshot: dict[str, Any]
    policy_snapshot: dict[str, Any]
    generated: bool = False
    executed: bool = False
    validated: bool = False
    parity_passed: bool = False
    certified: bool = False
    human_approved: bool = False
    human_assisted: bool = False
    content_digest: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        payload = json.loads(json.dumps(asdict(self)))
        assert isinstance(payload, dict)
        return payload
