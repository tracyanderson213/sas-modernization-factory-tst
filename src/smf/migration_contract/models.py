"""Frozen models for the non-operational migration CLI contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class MigrationCommand(StrEnum):
    CONVERT = "convert"
    MODERNIZE = "modernize"
    STATUS = "status"
    RESUME = "resume"
    EXCEPTIONS_LIST = "exceptions.list"
    EXCEPTIONS_SUBMIT = "exceptions.submit"
    EXCEPTIONS_DECIDE = "exceptions.decide"
    APPROVE = "approve"
    PROMOTE = "promote"
    AI_GATEWAY_PREFLIGHT = "ai-gateway.preflight"


@dataclass(frozen=True)
class MigrationContractRequest:
    command: MigrationCommand
    run_id: str
    attempt_id: str | None
    output_root: Path
    workload_id: str | None = None
    source_root: Path | None = None
    workload_config: Path | None = None
    factory_config: Path | None = None
    role_paths: tuple[tuple[str, Path], ...] = ()
    action_target: str | None = None


@dataclass(frozen=True)
class PreparedMigrationResult:
    result: dict[str, Any]
    telemetry: dict[str, Any]
