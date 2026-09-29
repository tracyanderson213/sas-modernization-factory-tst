"""Immutable models for trusted SAS baseline acquisition."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from smf.intake.policy import IntakePolicy


class AcquisitionMode(StrEnum):
    APPROVED_EXPORT = "approved_export"
    SAS_EXECUTION = "sas_execution"


class AcquisitionDisposition(StrEnum):
    ACQUIRED = "acquired"
    NEEDS_EVIDENCE = "needs_evidence"
    HUMAN_REQUIRED = "human_required"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class BaselineAcquisitionRequest:
    """Exact acquisition attempt and its already-admitted source workload."""

    acquisition_id: str
    mode: AcquisitionMode | str
    policy_path: Path
    intake_result_path: Path
    intake_policy: IntakePolicy
    package_root: Path | None
    receipt_path: Path | None
    approval_path: Path | None
    output_root: Path
    workload_id: str
    workload_revision_id: str
    closure_digest: str
    boundary_id: str
    run_id: str
    attempt_id: str
