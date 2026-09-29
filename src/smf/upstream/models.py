"""Typed contracts for offline upstream qualification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class AdoptionDisposition(StrEnum):
    ADOPT_DIRECTLY = "adopt_directly"
    WRAP = "wrap"
    REUSE_TRANSITIVELY = "reuse_transitively"
    REUSE_SELECTED_LICENSED_COMPONENTS = "reuse_selected_licensed_components"
    PATTERNS_ONLY = "patterns_only"
    REJECT = "reject"
    FORK_AND_HARDEN = "fork_and_harden"


class QualificationOutcome(StrEnum):
    QUALIFIED = "qualified"
    BLOCKED_MISSING = "blocked_missing"
    BLOCKED_PENDING = "blocked_pending"
    DENIED = "denied"
    INCOMPATIBLE = "incompatible"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


@dataclass(frozen=True)
class UpstreamQualificationRequest:
    policy_path: Path
    inventory_path: Path
    evidence_root: Path
    output_root: Path
    scope_id: str
    run_id: str
    attempt_id: str
    evaluation_time: str
    signing_key_path: Path
    signing_key_id: str
    signing_authority: str
