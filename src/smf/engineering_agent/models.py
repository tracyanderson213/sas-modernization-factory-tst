from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class RunState(StrEnum):
    CREATED = "created"
    ARCHITECTURE = "architecture"
    DEVELOPMENT = "development"
    GATES = "gates"
    REVIEW = "review"
    REPAIR = "repair"
    HUMAN_REVIEW = "human_review"
    STOPPED = "stopped"


class Readiness(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    ACTIVE = "active"
    COMPLETE = "complete"


def is_foundation_complete(status: str, implementation_state: str) -> bool:
    """Canonical completion contract; issue closure alone never proves implementation."""
    return status == "Done" and implementation_state == "Foundation Complete"


@dataclass(frozen=True)
class BacklogItem:
    key: str
    title: str
    work_type: str
    priority: str
    readiness: str
    status: str
    implementation_state: str
    parent: str = ""
    issue_number: int | None = None
    issue_body: str = ""

    @property
    def is_epic(self) -> bool:
        return self.work_type.lower() == "epic"

    @property
    def complete(self) -> bool:
        return is_foundation_complete(self.status, self.implementation_state)

    @property
    def active(self) -> bool:
        return self.status == "In Progress" or self.implementation_state == "Partial"


@dataclass(frozen=True)
class CandidateAssessment:
    item: BacklogItem
    readiness: Readiness
    blockers: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    rank: tuple[int, int, str] = field(default=(99, 99, ""), repr=False)


@dataclass(frozen=True)
class AgentInvocation:
    role: str
    returncode: int
    stdout_path: Path
    stderr_path: Path
    final_message_path: Path

    def final_message(self) -> str:
        if not self.final_message_path.exists():
            return ""
        return self.final_message_path.read_text(encoding="utf-8")


@dataclass(frozen=True)
class RunOutcome:
    state: RunState
    run_dir: Path
    worktree: Path
    message: str
