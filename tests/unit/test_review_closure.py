from __future__ import annotations

import json
import shutil
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from smf.engineering_agent.models import BacklogItem, RunState
from smf.engineering_agent.review_feedback import ReviewMode, parse_review, write_review_packet
from smf.engineering_agent.review_scope import (
    ReviewScope,
    classify_closure,
    discovery_scope,
    load_review_scope,
    write_review_scope,
)


def _item() -> BacklogItem:
    return BacklogItem("X-01", "Closure", "Feature", "P0", "Pre-Humana", "Todo", "Partial")


def _packet(*titles: str) -> str:
    findings = "\n".join(
        f"{index}. **High - {title}**\n   - Reproduction: probe {index}"
        for index, title in enumerate(titles, 1)
    )
    return f"FAIL\n{findings}"


def _repo(path: Path) -> Path:
    path.mkdir()
    shutil.copytree(Path("scripts/engineering-agent"), path / "scripts/engineering-agent")
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "baseline",
        ],
        cwd=path,
        check=True,
    )
    return path


def test_discovery_establishes_all_findings_as_stable_blockers() -> None:
    scope = discovery_scope(parse_review(_packet("First defect", "Second defect")))

    assert scope.mode is ReviewMode.CLOSURE
    assert [item.blocking_id for item in scope.unresolved] == ["BF-001", "BF-002"]


def test_closure_only_blocks_original_and_defers_new_sibling() -> None:
    scope = discovery_scope(parse_review(_packet("Original mutable-input defect")))
    closure = parse_review(
        "FAIL\n"
        "1. **High - Original mutable-input defect**\n"
        "   - Reproduction: original probe still fails\n"
        "2. **Medium - Adjacent mutable control-file variation**\n"
        "   - Closure disposition: deferred\n"
        "   - Reproduction: new sibling probe"
    )

    result = classify_closure(closure, scope, acceptance_context="Evidence survives restart/retry")

    assert [item.blocking_id for item in result.unresolved] == ["BF-001"]
    assert [item.finding.title for item in result.deferred] == [
        "Adjacent mutable control-file variation"
    ]


def test_closure_new_finding_only_closes_item_and_retains_learning() -> None:
    scope = discovery_scope(parse_review(_packet("Original defect")))
    closure = parse_review(
        "FAIL\n1. **Medium - Brand-new adjacent edge case**\n"
        "   - Closure disposition: deferred\n   - Reproduction: adjacent probe"
    )

    result = classify_closure(closure, scope, acceptance_context="Evidence survives restart/retry")

    assert result.unresolved == ()
    assert [item.blocking_id for item in result.resolved] == ["BF-001"]
    assert result.deferred[0].finding.title == "Brand-new adjacent edge case"


def test_closure_explicit_acceptance_regression_is_blocking() -> None:
    scope = discovery_scope(parse_review(_packet("Original defect")))
    closure = parse_review(
        "FAIL\n1. **High - Restart loses attributable evidence**\n"
        "   - Closure disposition: acceptance_criteria_regression\n"
        "   - Acceptance criterion: Evidence survives restart/retry\n"
        "   - Reproduction: restart and inspect evidence"
    )

    result = classify_closure(closure, scope, acceptance_context="Evidence survives restart/retry")

    assert result.unresolved[0].origin == "acceptance_regression"
    assert result.unresolved[0].blocking_id == "BF-002"


def test_unattributable_acceptance_regression_cannot_broaden_closure() -> None:
    scope = discovery_scope(parse_review(_packet("Original defect")))
    closure = parse_review(
        "FAIL\n1. **High - Invented enterprise requirement**\n"
        "   - Closure disposition: acceptance_criteria_regression\n"
        "   - Acceptance criterion: Must support an unplanned runtime\n"
        "   - Reproduction: unsupported combination"
    )

    result = classify_closure(closure, scope, acceptance_context="Evidence survives restart/retry")

    assert result.unresolved == ()
    assert "not attributable" in result.deferred[0].reason


def test_unknown_closure_disposition_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unsupported closure disposition"):
        parse_review(
            "FAIL\n1. **High - Defect**\n"
            "   - Closure disposition: maybe_blocking\n   - Reproduction: probe"
        )


def test_review_scope_round_trip_preserves_blocking_and_deferred(tmp_path: Path) -> None:
    initial = discovery_scope(parse_review(_packet("Original defect")))
    scope = classify_closure(
        parse_review(
            "FAIL\n1. **Medium - New edge**\n"
            "   - Closure disposition: deferred\n   - Reproduction: edge"
        ),
        initial,
    )
    path = tmp_path / "review-scope.json"

    write_review_scope(path, scope)

    assert load_review_scope(path) == scope


def test_interrupted_scope_publication_recovers_without_rerunning_review(tmp_path: Path) -> None:
    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.runlog import initialize_run

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    initialize_run(run_dir, _item(), tmp_path / "worktree")
    discovery = parse_review(_packet("Original defect"))
    write_review_packet(run_dir / "review-findings-1.json", discovery)
    write_review_scope(run_dir / "review-scope-1.json", discovery_scope(discovery))
    closure = parse_review(
        "FAIL\n1. **Medium - New adjacent edge**\n"
        "   - Closure disposition: deferred\n   - Reproduction: edge"
    )
    write_review_packet(run_dir / "review-findings-2.json", closure)

    recovered = orchestrator._inherited_review_scope(run_dir, (discovery, closure))

    assert recovered.unresolved == ()
    assert recovered.deferred[0].finding.title == "New adjacent edge"
    assert load_review_scope(run_dir / "review-scope-2.json") == recovered


def test_orchestrator_deferred_only_closure_finishes_and_records_learning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.review_learning import learned_patterns_for_prompt
    from smf.engineering_agent.runlog import initialize_run

    repo = _repo(tmp_path / "repo")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    initialize_run(run_dir, _item(), repo)
    messages = iter(
        (
            _packet("Original defect"),
            "FAIL\n1. **Medium - Brand-new adjacent edge case**\n"
            "   - Closure disposition: deferred\n   - Reproduction: adjacent probe",
        )
    )

    def fake_agent(
        worktree: Path,
        role: str,
        prompt: str,
        output_dir: Path,
        command: str | None,
        attempt: int,
    ) -> SimpleNamespace:
        del worktree, prompt, output_dir, command, attempt
        message = next(messages) if role == "reviewer" else "implemented"
        return SimpleNamespace(returncode=0, final_message=lambda: message)

    monkeypatch.setattr(orchestrator, "run_external_agent", fake_agent)
    monkeypatch.setattr(orchestrator, "run_gates", lambda _: ())
    monkeypatch.setattr(orchestrator, "implementation_fingerprint", lambda _: "stable")
    monkeypatch.setattr(orchestrator, "disposable_review_workspace", lambda path: nullcontext(path))

    outcome = orchestrator._repair_window(
        repo,
        _item(),
        repo,
        run_dir,
        runner="fake",
        max_repairs=1,
        initial_repair_context="",
        first_state=RunState.DEVELOPMENT,
    )

    assert outcome.state is RunState.HUMAN_REVIEW
    assert "Brand-new adjacent edge case" in learned_patterns_for_prompt(repo)
    payload = json.loads((run_dir / "run.json").read_text())
    terminal = payload["events"][-1]
    assert terminal["details"]["closure_disposition"] == "deferred_findings_non_blocking"


def test_continuation_prompt_contains_only_unresolved_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.runlog import initialize_run

    repo = _repo(tmp_path / "repo")
    first, second = discovery_scope(
        parse_review(_packet("Closed historical defect", "Still unresolved defect"))
    ).unresolved
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "run.json").write_text(json.dumps({"state": "stopped", "events": []}))
    (prior / "reviewer-final-1.md").write_text(
        _packet("Closed historical defect", "Still unresolved defect")
    )
    write_review_scope(
        prior / "review-scope-1.json",
        ReviewScope(ReviewMode.CLOSURE, unresolved=(second,), resolved=(first,)),
    )
    run_dir = tmp_path / "continuation"
    run_dir.mkdir()
    initialize_run(run_dir, _item(), repo, continuation_of=prior)
    developer_prompts: list[str] = []

    def fake_agent(
        worktree: Path,
        role: str,
        prompt: str,
        output_dir: Path,
        command: str | None,
        attempt: int,
    ) -> SimpleNamespace:
        del worktree, output_dir, command, attempt
        if role == "developer":
            developer_prompts.append(prompt)
        return SimpleNamespace(returncode=0, final_message=lambda: "PASS")

    monkeypatch.setattr(orchestrator, "run_external_agent", fake_agent)
    monkeypatch.setattr(orchestrator, "run_gates", lambda _: ())
    monkeypatch.setattr(orchestrator, "implementation_fingerprint", lambda _: "stable")
    monkeypatch.setattr(orchestrator, "disposable_review_workspace", lambda path: nullcontext(path))

    outcome = orchestrator._repair_window(
        repo,
        _item(),
        repo,
        run_dir,
        runner="fake",
        max_repairs=0,
        initial_repair_context="continuation",
        first_state=RunState.REPAIR,
    )

    assert outcome.state is RunState.HUMAN_REVIEW
    assert "Still unresolved defect" in developer_prompts[0]
    assert "Closed historical defect" not in developer_prompts[0]


def test_deterministic_gate_regression_still_blocks_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.gates import GateResult
    from smf.engineering_agent.runlog import initialize_run

    repo = _repo(tmp_path / "repo")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    initialize_run(run_dir, _item(), repo)
    reviews = 0

    def fake_agent(
        worktree: Path,
        role: str,
        prompt: str,
        output_dir: Path,
        command: str | None,
        attempt: int,
    ) -> SimpleNamespace:
        nonlocal reviews
        del worktree, prompt, output_dir, command, attempt
        if role == "reviewer":
            reviews += 1
            return SimpleNamespace(returncode=0, final_message=lambda: _packet("Original defect"))
        return SimpleNamespace(returncode=0, final_message=lambda: "implemented")

    gate_results = iter(((GateResult("verify", 0),), (GateResult("verify", 1, "", "boom"),)))
    monkeypatch.setattr(orchestrator, "run_external_agent", fake_agent)
    monkeypatch.setattr(orchestrator, "run_gates", lambda _: next(gate_results))
    monkeypatch.setattr(orchestrator, "implementation_fingerprint", lambda _: "stable")
    monkeypatch.setattr(orchestrator, "disposable_review_workspace", lambda path: nullcontext(path))

    outcome = orchestrator._repair_window(
        repo,
        _item(),
        repo,
        run_dir,
        runner="fake",
        max_repairs=1,
        initial_repair_context="",
        first_state=RunState.DEVELOPMENT,
    )

    assert outcome.state is RunState.STOPPED
    assert outcome.message == "Gate verify still fails after repair budget."
    assert reviews == 1
