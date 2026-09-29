import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from smf.engineering_agent import autonomous
from smf.engineering_agent.models import BacklogItem, RunOutcome, RunState


def test_safe_skip_is_narrow() -> None:
    assert autonomous._safe_to_skip("Architect agent failed.")
    assert autonomous._safe_to_skip("Reviewer agent failed.")
    assert not autonomous._safe_to_skip("Reviewer still rejects after repair budget.")
    assert not autonomous._safe_to_skip("Gate verify still fails after repair budget.")
    assert not autonomous._safe_to_skip(
        "Developer touched protected evidence/security/quality-control paths."
    )


def test_safe_base_requires_clean_synced_main(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    (tmp_path / "tracked").write_text("base\n")
    subprocess.run(["git", "add", "tracked"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "update-ref", "refs/remotes/origin/main", "HEAD"], cwd=tmp_path, check=True
    )
    expected = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert autonomous.require_safe_base(tmp_path) == expected
    (tmp_path / "tracked").write_text("dirty\n")
    with pytest.raises(ValueError, match="clean"):
        autonomous.require_safe_base(tmp_path)


def test_safe_base_accepts_explicit_clean_review_branch(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "review/recovery"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    (tmp_path / "tracked").write_text("base\n")
    subprocess.run(["git", "add", "tracked"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=tmp_path, check=True)
    expected = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert autonomous.require_safe_base(tmp_path, base_branch="review/recovery") == expected


def test_drain_scope_skips_draft_and_never_selects_outside_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    draft = _remote("A-01")
    draft["content"]["__typename"] = "DraftIssue"
    draft["content"]["number"] = None
    outside = _remote("OUT-01")
    rows = [draft, outside]
    monkeypatch.setattr(autonomous, "require_safe_base", lambda *args, **kwargs: "BASE")
    monkeypatch.setattr(
        autonomous,
        "validate_plan",
        lambda root: {
            "project": {"number": 2},
            "items": [{"backlog_key": "A-01"}, {"backlog_key": "OUT-01"}],
        },
    )
    monkeypatch.setattr(
        autonomous,
        "competition_queue",
        lambda *args, **kwargs: [
            {"key": "A-01", "dependency_state": "eligible-for-review", "blockers": []},
            {"key": "OUT-01", "dependency_state": "eligible-for-review", "blockers": []},
        ],
    )
    monkeypatch.setattr(
        autonomous,
        "execute_supervised_run",
        lambda *args, **kwargs: pytest.fail("no draft or out-of-scope record may execute"),
    )
    outcome = autonomous.execute_competition_drain(
        tmp_path,
        github=SimpleNamespace(snapshot=lambda number: rows),
        allowed_keys=frozenset({"A-01"}),
        base_branch="review/recovery",
        continue_external_blockers=True,
    )
    assert outcome.state == "exhausted"
    assert [(item.key, item.disposition) for item in outcome.items] == [("A-01", "skipped")]
    scope = json.loads((outcome.drain_dir / "scope.json").read_text())
    assert scope["allowed_keys"] == ["A-01"]


def _remote(key: str) -> dict[str, Any]:
    return {
        "fields": {
            "Backlog Key": key,
            "Work Type": "Feature",
            "Priority": "P0",
            "Readiness": "Pre-Humana",
            "Status": "Todo",
            "Implementation State": "Not Started",
            "Parent": "",
        },
        "content": {
            "__typename": "Issue",
            "number": 1,
            "title": key,
            "body": "accepted",
        },
    }


def test_drain_commits_success_and_uses_it_as_next_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_remote("A-01"), _remote("B-01")]
    plan = {"project": {"number": 2}}
    monkeypatch.setattr(autonomous, "require_safe_base", lambda root: "BASE")
    monkeypatch.setattr(autonomous, "validate_plan", lambda root: plan)
    monkeypatch.setattr(autonomous, "require_current_acceptance", lambda *args, **kwargs: None)
    monkeypatch.setattr(autonomous, "git_changed_paths", lambda path: ("src/change.py",))
    queue_calls = 0

    def queue(*args: Any, assumed_complete: frozenset[str]) -> list[dict[str, Any]]:
        nonlocal queue_calls
        queue_calls += 1
        pending = [key for key in ("A-01", "B-01") if key not in assumed_complete]
        return [
            {"key": key, "dependency_state": "eligible-for-review", "blockers": []}
            for key in pending
        ]

    bases: list[str] = []

    def run(root: Path, item: BacklogItem, **kwargs: Any) -> RunOutcome:
        bases.append(kwargs["base"])
        worktree = tmp_path / item.key
        worktree.mkdir()
        run_dir = tmp_path / f"run-{item.key}"
        run_dir.mkdir()
        return RunOutcome(RunState.HUMAN_REVIEW, run_dir, worktree, "ready")

    commits = iter(("COMMIT-A", "COMMIT-B"))
    monkeypatch.setattr(autonomous, "competition_queue", queue)
    monkeypatch.setattr(autonomous, "execute_supervised_run", run)
    monkeypatch.setattr(autonomous, "commit_candidate", lambda worktree, key: next(commits))
    outcome = autonomous.execute_competition_drain(
        tmp_path, github=SimpleNamespace(snapshot=lambda number: rows)
    )
    assert outcome.state == "exhausted"
    assert [item.disposition for item in outcome.items] == ["committed", "committed"]
    assert bases == ["BASE", "COMMIT-A"]
    assert queue_calls == 5
    payload = json.loads((outcome.drain_dir / "drain.json").read_text())
    assert payload["base_commit"] == "COMMIT-B"


def test_drain_skips_isolated_technical_failure_but_stops_on_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [_remote("A-01"), _remote("B-01")]
    monkeypatch.setattr(autonomous, "require_safe_base", lambda root: "BASE")
    monkeypatch.setattr(autonomous, "validate_plan", lambda root: {"project": {"number": 2}})
    monkeypatch.setattr(autonomous, "require_current_acceptance", lambda *args, **kwargs: None)
    attempted: set[str] = set()

    def queue(*args: Any, assumed_complete: frozenset[str]) -> list[dict[str, Any]]:
        return [
            {"key": key, "dependency_state": "eligible-for-review", "blockers": []}
            for key in ("A-01", "B-01")
            if key not in assumed_complete and key not in attempted
        ]

    messages = iter(("Architect agent failed.", "Reviewer still rejects after repair budget."))

    def run(root: Path, item: BacklogItem, **kwargs: Any) -> RunOutcome:
        attempted.add(item.key)
        worktree = tmp_path / item.key
        worktree.mkdir()
        run_dir = tmp_path / f"run-{item.key}"
        run_dir.mkdir()
        return RunOutcome(RunState.STOPPED, run_dir, worktree, next(messages))

    monkeypatch.setattr(autonomous, "competition_queue", queue)
    monkeypatch.setattr(autonomous, "execute_supervised_run", run)
    outcome = autonomous.execute_competition_drain(
        tmp_path, github=SimpleNamespace(snapshot=lambda number: rows)
    )
    assert outcome.state == "human_decision_required"
    assert [item.disposition for item in outcome.items] == ["skipped", "stopped"]


def test_drain_stops_before_commit_when_live_record_drifts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = [_remote("A-01")]
    changed = [_remote("A-01")]
    changed[0]["fields"]["Status"] = "In Progress"
    snapshots = iter((original, changed))
    monkeypatch.setattr(autonomous, "require_safe_base", lambda root: "BASE")
    monkeypatch.setattr(autonomous, "validate_plan", lambda root: {"project": {"number": 2}})
    monkeypatch.setattr(autonomous, "require_current_acceptance", lambda *args, **kwargs: None)
    monkeypatch.setattr(autonomous, "git_changed_paths", lambda path: ("src/change.py",))
    monkeypatch.setattr(
        autonomous,
        "competition_queue",
        lambda *args, **kwargs: [
            {"key": "A-01", "dependency_state": "eligible-for-review", "blockers": []}
        ],
    )
    worktree = tmp_path / "candidate"
    worktree.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(
        autonomous,
        "execute_supervised_run",
        lambda *args, **kwargs: RunOutcome(RunState.HUMAN_REVIEW, run_dir, worktree, "ready"),
    )
    monkeypatch.setattr(
        autonomous,
        "commit_candidate",
        lambda *args: pytest.fail("drifted candidate was committed"),
    )
    outcome = autonomous.execute_competition_drain(
        tmp_path, github=SimpleNamespace(snapshot=lambda number: next(snapshots))
    )
    assert outcome.state == "human_decision_required"
    assert "changed during execution" in outcome.message
