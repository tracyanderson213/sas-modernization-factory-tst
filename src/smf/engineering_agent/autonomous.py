"""Safe, local-only autonomous draining of the Humana competition backlog."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .acceptance_sync import GitHub, require_current_acceptance
from .competition_plan import competition_queue, validate_plan
from .models import BacklogItem, RunState
from .orchestrator import execute_supervised_run
from .policy import forbidden_developer_changes
from .workspace import commit_candidate, git_changed_paths

DrainState = Literal["running", "exhausted", "human_decision_required", "failed"]


@dataclass(frozen=True)
class DrainItemResult:
    key: str
    disposition: Literal["committed", "skipped", "stopped"]
    message: str
    worktree: str = ""
    run_dir: str = ""
    commit: str = ""


@dataclass(frozen=True)
class DrainOutcome:
    state: DrainState
    drain_dir: Path
    message: str
    items: tuple[DrainItemResult, ...]


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def require_safe_base(root: Path, *, base_branch: str | None = None) -> str:
    """Require a clean explicit base; default main must match the remote-tracking ref."""
    branch = _git(root, "branch", "--show-current")
    expected = base_branch or "main"
    if branch != expected:
        raise ValueError(f"Autonomous drain must start from the {expected} branch")
    if _git(root, "status", "--porcelain"):
        raise ValueError("Autonomous drain requires a clean primary checkout")
    head = _git(root, "rev-parse", "HEAD")
    if expected != "main":
        return head
    try:
        remote = _git(root, "rev-parse", "origin/main")
    except subprocess.CalledProcessError as exc:
        raise ValueError("Autonomous drain requires an existing origin/main ref") from exc
    if head != remote:
        raise ValueError(
            "Local main must exactly match origin/main; update it explicitly before draining"
        )
    return head


def _create_drain_dir(root: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base = root / ".smf-agent" / "drains"
    target = base / stamp
    suffix = 1
    while target.exists():
        target = base / f"{stamp}-{suffix}"
        suffix += 1
    target.mkdir(parents=True)
    return target


def _write_state(
    drain_dir: Path,
    state: DrainState,
    message: str,
    base_commit: str,
    items: list[DrainItemResult],
    *,
    blocked: list[dict[str, Any]] | None = None,
) -> None:
    payload = {
        "schema_version": 1,
        "state": state,
        "message": message,
        "updated_at": datetime.now(UTC).isoformat(),
        "base_commit": base_commit,
        "items": [asdict(item) for item in items],
        "blocked_queue": blocked or [],
    }
    (drain_dir / "drain.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _items_from_snapshot(rows: list[dict[str, Any]]) -> dict[str, BacklogItem]:
    result: dict[str, BacklogItem] = {}
    for row in rows:
        fields = row.get("fields") or {}
        content = row.get("content") or {}
        key = str(fields.get("Backlog Key") or "")
        if not key:
            continue
        result[key] = BacklogItem(
            key=key,
            title=str(content.get("title") or ""),
            work_type=str(fields.get("Work Type") or ""),
            priority=str(fields.get("Priority") or "P2"),
            readiness=str(fields.get("Readiness") or ""),
            status=str(fields.get("Status") or ""),
            implementation_state=str(fields.get("Implementation State") or ""),
            parent=str(fields.get("Parent") or ""),
            issue_number=content.get("number"),
            issue_body=str(content.get("body") or ""),
        )
    return result


def _row(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get("fields", {}).get("Backlog Key") == key]
    if len(matches) != 1:
        raise ValueError(f"{key}: expected exactly one live Project record")
    return matches[0]


def _row_digest(row: dict[str, Any]) -> str:
    import hashlib

    payload = json.dumps(row, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_to_skip(message: str) -> bool:
    """Limit skipping to an isolated role-process failure with no accepted candidate."""
    return (
        message
        in {
            "Architect agent failed.",
            "Reviewer agent failed.",
        }
        or re.fullmatch(r"Developer attempt [1-9][0-9]* failed\.", message) is not None
    )


def execute_competition_drain(
    root: Path,
    *,
    runner: str | None = None,
    max_repairs: int = 2,
    github: GitHub | None = None,
    allowed_keys: frozenset[str] | None = None,
    base_branch: str | None = None,
    continue_external_blockers: bool = False,
) -> DrainOutcome:
    """Drain locally eligible competition work; never push, merge, or mutate GitHub."""
    if max_repairs < 0:
        raise ValueError("max_repairs must be non-negative")
    base_commit = (
        require_safe_base(root, base_branch=base_branch)
        if base_branch is not None
        else require_safe_base(root)
    )
    plan = validate_plan(root)
    if allowed_keys is not None:
        plan_keys = {row["backlog_key"] for row in plan["items"]}
        if not allowed_keys:
            raise ValueError("Autonomous drain scope must not be empty")
        unknown = sorted(allowed_keys - plan_keys)
        if unknown:
            raise ValueError(f"Autonomous drain scope contains unknown keys: {', '.join(unknown)}")
    client = github or GitHub()
    snapshot = client.snapshot(plan["project"]["number"])
    drain_dir = _create_drain_dir(root)
    completed: set[str] = set()
    attempted: set[str] = set()
    results: list[DrainItemResult] = []
    (drain_dir / "scope.json").write_text(
        json.dumps(
            {
                "allowed_keys": sorted(allowed_keys) if allowed_keys is not None else None,
                "base_branch": base_branch or "main",
                "continue_external_blockers": continue_external_blockers,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_state(drain_dir, "running", "Autonomous drain started.", base_commit, results)

    while True:
        try:
            queue = competition_queue(plan, snapshot, assumed_complete=frozenset(completed))
        except (KeyError, TypeError, ValueError) as exc:
            message = f"Live backlog cannot be scheduled safely: {exc}"
            _write_state(drain_dir, "human_decision_required", message, base_commit, results)
            return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
        scoped_queue = [row for row in queue if allowed_keys is None or row["key"] in allowed_keys]
        eligible = [
            row
            for row in scoped_queue
            if row["dependency_state"] == "eligible-for-review" and row["key"] not in attempted
        ]
        if not eligible:
            blocked = [row for row in scoped_queue if row["key"] not in completed]
            message = "Eligible scoped Humana competition backlog exhausted."
            _write_state(drain_dir, "exhausted", message, base_commit, results, blocked=blocked)
            return DrainOutcome("exhausted", drain_dir, message, tuple(results))

        selected = eligible[0]
        key = str(selected["key"])
        attempted.add(key)
        live_items = _items_from_snapshot(snapshot)
        item = live_items[key]
        selected_row = _row(snapshot, key)
        selected_digest = _row_digest(selected_row)
        content_type = selected_row["content"].get("__typename")
        if content_type != "Issue" or item.issue_number is None:
            message = f"{key}: external promotion/start action is required before execution"
            disposition: Literal["skipped", "stopped"] = (
                "skipped" if continue_external_blockers else "stopped"
            )
            result = DrainItemResult(key, disposition, message)
            results.append(result)
            if disposition == "skipped":
                _write_state(
                    drain_dir,
                    "running",
                    f"{key} recorded as externally blocked; continuing.",
                    base_commit,
                    results,
                )
                continue
            _write_state(drain_dir, "human_decision_required", message, base_commit, results)
            return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
        try:
            require_current_acceptance(root, key, item.issue_body, offline=False)
        except ValueError as exc:
            message = str(exc)
            result = DrainItemResult(key, "stopped", message)
            results.append(result)
            _write_state(drain_dir, "human_decision_required", message, base_commit, results)
            return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))

        _write_state(drain_dir, "running", f"Running {key}.", base_commit, results)
        try:
            outcome = execute_supervised_run(
                root,
                item,
                runner=runner,
                max_repairs=max_repairs,
                base=base_commit,
                autonomous=True,
            )
        except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
            message = f"{key}: orchestration could not start safely: {exc}"
            results.append(DrainItemResult(key, "stopped", message))
            _write_state(drain_dir, "human_decision_required", message, base_commit, results)
            return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
        if outcome.state is RunState.HUMAN_REVIEW:
            protected = forbidden_developer_changes(git_changed_paths(outcome.worktree))
            if protected:
                message = f"{key}: protected paths require human review: {', '.join(protected)}"
                results.append(
                    DrainItemResult(
                        key,
                        "stopped",
                        message,
                        str(outcome.worktree),
                        str(outcome.run_dir),
                    )
                )
                _write_state(drain_dir, "human_decision_required", message, base_commit, results)
                return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
            try:
                fresh_snapshot = client.snapshot(plan["project"]["number"])
                fresh_queue = competition_queue(
                    plan, fresh_snapshot, assumed_complete=frozenset(completed)
                )
                fresh_row = _row(fresh_snapshot, key)
            except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
                message = f"{key}: live backlog changed during execution: {exc}"
                results.append(
                    DrainItemResult(
                        key,
                        "stopped",
                        message,
                        str(outcome.worktree),
                        str(outcome.run_dir),
                    )
                )
                _write_state(drain_dir, "human_decision_required", message, base_commit, results)
                return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
            fresh_candidate = next((row for row in fresh_queue if row["key"] == key), None)
            if (
                _row_digest(fresh_row) != selected_digest
                or fresh_candidate is None
                or fresh_candidate["dependency_state"] != "eligible-for-review"
            ):
                message = f"{key}: live backlog or acceptance changed during execution"
                results.append(
                    DrainItemResult(
                        key,
                        "stopped",
                        message,
                        str(outcome.worktree),
                        str(outcome.run_dir),
                    )
                )
                _write_state(drain_dir, "human_decision_required", message, base_commit, results)
                return DrainOutcome("human_decision_required", drain_dir, message, tuple(results))
            try:
                base_commit = commit_candidate(outcome.worktree, key)
            except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
                message = f"{key}: local commit failed: {exc}"
                results.append(
                    DrainItemResult(
                        key,
                        "stopped",
                        message,
                        str(outcome.worktree),
                        str(outcome.run_dir),
                    )
                )
                _write_state(drain_dir, "failed", message, base_commit, results)
                return DrainOutcome("failed", drain_dir, message, tuple(results))
            completed.add(key)
            snapshot = fresh_snapshot
            results.append(
                DrainItemResult(
                    key,
                    "committed",
                    "Gates and independent review passed; committed locally.",
                    str(outcome.worktree),
                    str(outcome.run_dir),
                    base_commit,
                )
            )
            continue

        result = DrainItemResult(
            key,
            "skipped" if _safe_to_skip(outcome.message) else "stopped",
            outcome.message,
            str(outcome.worktree),
            str(outcome.run_dir),
        )
        results.append(result)
        if result.disposition == "skipped":
            _write_state(
                drain_dir,
                "running",
                f"{key} recorded as technically blocked; continuing.",
                base_commit,
                results,
            )
            try:
                snapshot = client.snapshot(plan["project"]["number"])
            except (OSError, RuntimeError) as exc:
                message = f"Live backlog refresh failed after {key}: {exc}"
                _write_state(drain_dir, "failed", message, base_commit, results)
                return DrainOutcome("failed", drain_dir, message, tuple(results))
            continue
        _write_state(drain_dir, "human_decision_required", outcome.message, base_commit, results)
        return DrainOutcome("human_decision_required", drain_dir, outcome.message, tuple(results))
