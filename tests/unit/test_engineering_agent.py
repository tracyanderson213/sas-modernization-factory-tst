from pathlib import Path

import pytest

from smf.engineering_agent.backlog import load_project_items
from smf.engineering_agent.models import BacklogItem, Readiness, RunState
from smf.engineering_agent.policy import forbidden_developer_changes, role_write_violations
from smf.engineering_agent.readiness import assess_candidates, recommend_next
from smf.engineering_agent.runner import codex_command
from smf.engineering_agent.workspace import commit_candidate, disposable_review_workspace


def item(
    key: str,
    *,
    status: str = "Todo",
    impl: str = "Not Started",
    priority: str = "P0",
    work_type: str = "Feature",
    parent: str = "",
) -> BacklogItem:
    return BacklogItem(key, key, work_type, priority, "Pre-Humana", status, impl, parent=parent)


def test_partial_work_is_not_global_active_execution_claim() -> None:
    assessments = assess_candidates(
        (
            item("P0-NEW"),
            item("P1-PARTIAL", status="In Progress", impl="Partial", priority="P1"),
        )
    )
    result = recommend_next(assessments)
    assert result is not None and result.item.key == "P0-NEW"


def test_priority_orders_ready_work() -> None:
    assessments = assess_candidates(
        (item("P2", priority="P2"), item("P0"), item("P1", priority="P1"))
    )
    result = recommend_next(assessments)
    assert result is not None and result.item.key == "P0"


def test_explicit_incomplete_dependency_blocks_item() -> None:
    assessments = assess_candidates((item("A"), item("B")), {"B": ("A",)})
    candidate = next(result for result in assessments if result.item.key == "B")
    assert candidate.readiness is Readiness.BLOCKED
    assert candidate.blockers == ("A",)


def test_complete_dependency_unblocks_item() -> None:
    complete = item("A", status="Done", impl="Foundation Complete")
    assessments = assess_candidates((complete, item("B")), {"B": ("A",)})
    candidate = next(result for result in assessments if result.item.key == "B")
    assert candidate.readiness is Readiness.READY


def test_epics_are_not_recommended_as_engineering_work() -> None:
    result = recommend_next(assess_candidates((item("EPIC", work_type="Epic"), item("TASK"))))
    assert result is not None and result.item.key == "TASK"


def test_loader_reads_project_audit_shape(tmp_path: Path) -> None:
    path = tmp_path / "items.json"
    path.write_text(
        '{"items":[{"backlog Key":"X-01","title":"X","work Type":"Feature",'
        '"priority":"P0","readiness":"Pre-Humana","status":"In Progress",'
        '"implementation State":"Partial","content":{"number":42,"body":"criteria"}}]}'
    )
    loaded = load_project_items(path)
    assert loaded[0].key == "X-01"
    assert loaded[0].issue_number == 42
    assert loaded[0].issue_body == "criteria"


def test_current_audit_can_be_loaded_offline() -> None:
    path = Path(".project-audit/items.json")
    if not path.exists():
        return
    assert load_project_items(path)


def test_commit_candidate_ignores_agent_artifacts(tmp_path: Path) -> None:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("agent-artifacts/\n")
    (repo / "tracked.txt").write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
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
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    (repo / "tracked.txt").write_text("after\n")
    artifacts = repo / "agent-artifacts"
    artifacts.mkdir()
    (artifacts / "review.md").write_text("transient\n")

    commit = commit_candidate(repo, "TEST-01")

    assert (
        commit
        == subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    assert subprocess.run(
        ["git", "show", "--format=", "--name-only", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines() == ["tracked.txt"]
    assert (artifacts / "review.md").read_text() == "transient\n"


def test_focus_restricts_recommendation_to_epic_children() -> None:
    epic = item("EPIC-CORPUS", work_type="Epic")
    corpus = item("CORPUS-02", status="In Progress", impl="Partial", parent="EPIC-CORPUS")
    unrelated = item("AD-02", status="In Progress", impl="Partial", parent="EPIC-AD")
    assessments = assess_candidates((epic, corpus, unrelated), focus="EPIC-CORPUS")
    result = recommend_next(assessments)
    assert result is not None and result.item.key == "CORPUS-02"
    assert "only remaining incomplete child" in result.reasons[0]


def test_focus_rejects_unknown_or_non_epic_key() -> None:
    with pytest.raises(ValueError, match="existing epic"):
        assess_candidates((item("TASK"),), focus="TASK")


def test_focus_still_honors_explicit_dependencies() -> None:
    epic = item("EPIC-X", work_type="Epic")
    dependency = item("A", parent="EPIC-X")
    target = item("B", parent="EPIC-X")
    assessments = assess_candidates((epic, dependency, target), {"B": ("A",)}, focus="EPIC-X")
    candidate = next(result for result in assessments if result.item.key == "B")
    assert candidate.readiness is Readiness.BLOCKED


def test_developer_cannot_modify_public_evidence_or_quality_controls() -> None:
    violations = forbidden_developer_changes(
        (
            "src/smf/example.py",
            "tests/corpus/workloads/public/upstream.sas",
            "Makefile",
        )
    )
    assert violations == ("Makefile", "tests/corpus/workloads/public/upstream.sas")


def test_architect_and_reviewer_are_write_restricted() -> None:
    assert role_write_violations((), ("agent-artifacts/architect.md",), role="architect") == ()
    assert role_write_violations((), ("src/smf/bad.py",), role="architect") == ("src/smf/bad.py",)
    assert role_write_violations((), ("agent-artifacts/review.md",), role="reviewer") == ()


def test_run_state_requires_human_review_terminal_success() -> None:
    assert RunState.HUMAN_REVIEW.value == "human_review"
    assert RunState.STOPPED.value == "stopped"


def test_autonomous_architect_requires_explicit_clearance() -> None:
    from smf.engineering_agent.orchestrator import architect_stop

    assert architect_stop("PROCEED\n\n# Plan", require_clearance=True) is None
    assert "ambiguity" in architect_stop("HUMAN_DECISION_REQUIRED\nReason", require_clearance=False)
    assert "PROCEED" in architect_stop("# Plan without marker", require_clearance=True)
    assert architect_stop("# Supervised plan without marker", require_clearance=False) is None


def test_quality_control_paths_are_explicitly_protected() -> None:
    assert forbidden_developer_changes(("pyproject.toml",)) == ("pyproject.toml",)
    assert forbidden_developer_changes(("scripts/test-discovery-confidence.sh",)) == (
        "scripts/test-discovery-confidence.sh",
    )
    assert forbidden_developer_changes(("src/smf/engineering_agent/policy.py",)) == (
        "src/smf/engineering_agent/policy.py",
    )
    assert forbidden_developer_changes((".gitignore",)) == (".gitignore",)
    assert forbidden_developer_changes((".github/workflows/ci.yml",)) == (
        ".github/workflows/ci.yml",
    )
    assert forbidden_developer_changes(("src/smf/workload/sanitization.py",)) == (
        "src/smf/workload/sanitization.py",
    )
    assert forbidden_developer_changes(("competition/generated/issue-specs/AIP-01.md",)) == (
        "competition/generated/issue-specs/AIP-01.md",
    )
    assert forbidden_developer_changes(("scripts/project-tools/complete-backlog-item.sh",)) == (
        "scripts/project-tools/complete-backlog-item.sh",
    )


def test_codex_architect_is_read_only_and_ephemeral(tmp_path: Path) -> None:
    output = tmp_path / "architect.md"
    command = codex_command(tmp_path, "architect", output, executable="/opt/homebrew/bin/codex")
    assert command[:4] == [
        "/opt/homebrew/bin/codex",
        "--ask-for-approval",
        "never",
        "exec",
    ]
    assert command[command.index("--sandbox") + 1] == "read-only"
    assert "--ephemeral" in command
    assert command[-1] == "-"


def test_codex_developer_is_workspace_write(tmp_path: Path) -> None:
    command = codex_command(
        tmp_path,
        "developer",
        tmp_path / "developer.md",
        executable="codex",
    )
    assert command[command.index("--sandbox") + 1] == "workspace-write"
    assert "danger-full-access" not in command
    assert "--dangerously-bypass-approvals-and-sandbox" not in command


def test_codex_reviewer_uses_workspace_write_in_disposable_snapshot(tmp_path: Path) -> None:
    command = codex_command(tmp_path, "reviewer", tmp_path / "review.md", executable="codex")
    assert command[command.index("--sandbox") + 1] == "workspace-write"
    assert command[command.index("--output-last-message") + 1] == str(tmp_path / "review.md")


def test_codex_rejects_unknown_role(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported agent role"):
        codex_command(tmp_path, "admin", tmp_path / "bad.md")


def test_latest_stopped_run_selects_newest_stopped(tmp_path: Path) -> None:
    from smf.engineering_agent.runlog import latest_stopped_run

    base = tmp_path / ".smf-agent/runs/X-01"
    for name, state in (
        ("20260101T000000Z", "stopped"),
        ("20260102T000000Z", "human_review"),
        ("20260103T000000Z", "stopped"),
    ):
        run = base / name
        run.mkdir(parents=True)
        (run / "run.json").write_text(f'{{"state":"{state}"}}')
    assert latest_stopped_run(tmp_path, "X-01").name == "20260103T000000Z"


def test_latest_reviewer_findings_uses_final_review(tmp_path: Path) -> None:
    from smf.engineering_agent.runlog import latest_reviewer_findings

    (tmp_path / "reviewer-final-1.md").write_text("FAIL\nfirst")
    (tmp_path / "reviewer-final-3.md").write_text("FAIL\nthird")
    assert latest_reviewer_findings(tmp_path) == "FAIL\nthird"


def test_continuation_run_records_parent(tmp_path: Path) -> None:
    import json

    from smf.engineering_agent.runlog import initialize_run

    run = tmp_path / "run"
    run.mkdir()
    parent = tmp_path / "parent"
    initialize_run(run, item("X-01"), tmp_path / "worktree", continuation_of=parent)
    payload = json.loads((run / "run.json").read_text())
    assert payload["continuation_of"] == str(parent)


def _init_candidate_repo(path: Path) -> None:
    import subprocess

    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "agent-test@example.invalid"], cwd=path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Agent Test"], cwd=path, check=True)
    (path / "tracked.txt").write_text("baseline\n")
    (path / "deleted.txt").write_text("delete me\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=path, check=True)


def test_disposable_review_workspace_mirrors_candidate_without_mutating_source(
    tmp_path: Path,
) -> None:
    import subprocess

    candidate = tmp_path / "candidate"
    _init_candidate_repo(candidate)
    (candidate / "tracked.txt").write_text("candidate change\n")
    (candidate / "deleted.txt").unlink()
    (candidate / "untracked.txt").write_text("new candidate file\n")
    artifacts = candidate / "agent-artifacts"
    artifacts.mkdir()
    (artifacts / "architect.md").write_text("architecture\n")
    (artifacts / "review.md").write_text("OLD REVIEW\n")

    before = subprocess.run(
        ["git", "status", "--porcelain=v1", "-uall"],
        cwd=candidate,
        text=True,
        capture_output=True,
        check=True,
    ).stdout

    with disposable_review_workspace(candidate) as review:
        assert (review / "tracked.txt").read_text() == "candidate change\n"
        assert not (review / "deleted.txt").exists()
        assert (review / "untracked.txt").read_text() == "new candidate file\n"
        assert (review / "agent-artifacts/architect.md").exists()
        assert not (review / "agent-artifacts/review.md").exists()
        assert (review / ".git").is_dir()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-uall"],
            cwd=review,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        assert "tracked.txt" in status
        assert "deleted.txt" in status
        assert "untracked.txt" in status
        (review / "tracked.txt").write_text("reviewer mutation\n")
        scratch = Path(__import__("tempfile").mkdtemp(dir=review))
        (scratch / "probe.txt").write_text("SMF_TMP_OK\n")
        assert (scratch / "probe.txt").read_text().strip() == "SMF_TMP_OK"

    assert (candidate / "tracked.txt").read_text() == "candidate change\n"
    after = subprocess.run(
        ["git", "status", "--porcelain=v1", "-uall"],
        cwd=candidate,
        text=True,
        capture_output=True,
        check=True,
    ).stdout
    assert after == before


def test_review_parser_creates_machine_readable_findings() -> None:
    from smf.engineering_agent.review_feedback import parse_review

    packet = parse_review(
        "FAIL\n\n"
        "1. **High - Source can change after admission**\n"
        "   - Violated invariant: exact bytes\n"
        "   - Reproduction: mutate source\n\n"
        "2. **Medium - Denial is pending**\n"
        "   - Observed: HUMAN_REQUIRED\n"
    )
    assert packet.verdict == "FAIL"
    assert len(packet.findings) == 2
    assert packet.findings[0].severity == "HIGH"
    assert "Source can change" in packet.findings[0].title


def test_review_parser_rejects_unstructured_verdict() -> None:
    from smf.engineering_agent.review_feedback import parse_review

    with pytest.raises(ValueError, match="begin with PASS or FAIL"):
        parse_review("Looks good")


def test_repair_brief_maps_findings_and_requires_family_closure() -> None:
    from smf.engineering_agent.review_feedback import parse_review, render_repair_brief
    from smf.engineering_agent.review_learning import classify_finding

    prior = parse_review("FAIL\n1. **High - Old defect**\n   - Reproduction: old")
    current = parse_review(
        "FAIL\n1. **High - Mutable source bytes can change after admission**\n"
        "   - Reproduction: mutate the qualified file before conversion"
    )
    family = classify_finding(Path.cwd(), current.findings[0])
    brief = render_repair_brief(
        current,
        (prior,),
        "- TOCTOU_MUTABLE_INPUT: probe mutation",
        finding_families={current.findings[0].finding_id: family},
    )
    assert "Mutable source bytes can change" in brief
    assert "Old defect" in brief
    assert "Durable defect family: TOCTOU_MUTABLE_INPUT" in brief
    assert "sibling manifestations" in brief
    assert "reproduce each defect first" in brief


def test_reviewer_history_traverses_continuation_chain(tmp_path: Path) -> None:
    import json

    from smf.engineering_agent.runlog import reviewer_history

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "run.json").write_text(json.dumps({"state": "stopped", "events": []}))
    (second / "run.json").write_text(
        json.dumps({"state": "stopped", "events": [], "continuation_of": str(first)})
    )
    (first / "reviewer-final-1.md").write_text("FAIL\n1. first")
    (second / "reviewer-final-1.md").write_text("FAIL\n1. second")
    assert reviewer_history(second) == ("FAIL\n1. first", "FAIL\n1. second")


def test_reviewer_convergence_context_carries_history_and_families() -> None:
    from smf.engineering_agent.review_feedback import (
        parse_review,
        render_reviewer_convergence_context,
    )

    first = parse_review(
        "FAIL\n1. **High - Mutable source bytes can change after admission**\n"
        "   - Reproduction: mutate the exact source before conversion"
    )
    second = parse_review(
        "FAIL\n1. **Medium - Explicit denial reported as pending human**\n"
        "   - Reproduction: deny approval and inspect state"
    )
    families = {
        first.findings[0].title: "TOCTOU_MUTABLE_INPUT",
        second.findings[0].title: "DENIAL_VS_PENDING",
    }
    context = render_reviewer_convergence_context((first, second), families)

    assert "Mutable source bytes can change" in context
    assert "Explicit denial reported as pending" in context
    assert "TOCTOU_MUTABLE_INPUT" in context
    assert "DENIAL_VS_PENDING" in context
    assert "complete unresolved blocking set" in context
    assert "Record new sibling manifestations" in context


def test_reviewer_convergence_context_is_bounded() -> None:
    from smf.engineering_agent.review_feedback import (
        parse_review,
        render_reviewer_convergence_context,
    )

    packets = tuple(
        parse_review(
            f"FAIL\n1. **Medium - Historical convergence defect {index}**\n"
            f"   Reproduction detail {index} " + ("x" * 2_000)
        )
        for index in range(30)
    )
    context = render_reviewer_convergence_context(packets, {}, limit=8)

    assert context.count("### ") == 8
    assert "Historical convergence defect 29" in context
    assert "Historical convergence defect 0" not in context
    assert len(context) < 10_000


def test_role_prompts_receive_durable_adversarial_patterns() -> None:
    from smf.engineering_agent.prompts import render_role_prompt

    prompt = render_role_prompt(Path.cwd(), "architect", item("X-01"))
    assert "TOCTOU_MUTABLE_INPUT" in prompt
    assert "ASSERTION_NOT_EVIDENCE" in prompt
    assert "EMPTY_OR_NONCONVERTIBLE_SUCCESS" in prompt


def test_reviewer_prompt_requires_prior_family_convergence_before_pass() -> None:
    from smf.engineering_agent.prompts import render_role_prompt

    prompt = render_role_prompt(
        Path.cwd(),
        "reviewer",
        item("X-01"),
        reviewer_context=(
            "Prior family TOCTOU_MUTABLE_INPUT: mutable include remained exploitable."
        ),
    )

    assert "Prior family TOCTOU_MUTABLE_INPUT" in prompt
    assert "speculative hardening opportunity" in prompt
    assert "Same-family sibling variations" in prompt
    assert "DEFERRED" in prompt


def test_repair_window_passes_prior_findings_to_developer_and_reviewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import shutil
    import subprocess
    from contextlib import nullcontext
    from types import SimpleNamespace

    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.runlog import initialize_run

    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copytree(Path("scripts/engineering-agent"), repo / "scripts/engineering-agent")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
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
        cwd=repo,
        check=True,
    )
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    initialize_run(run_dir, item("X-01"), repo)
    prompts: list[tuple[str, str]] = []
    reviewer_messages = iter(
        (
            "FAIL\n1. **High - Mutable source bytes can change after admission**\n"
            "   - Reproduction: mutate an admitted include before conversion\n\n"
            "2. **High - Explicit denial reported as pending human**\n"
            "   - Reproduction: deny approval and inspect state",
            "PASS\nIndependent exact and sibling probes passed.",
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
        del worktree, output_dir, command, attempt
        prompts.append((role, prompt))
        message = next(reviewer_messages) if role == "reviewer" else "implemented"
        return SimpleNamespace(returncode=0, final_message=lambda: message)

    monkeypatch.setattr(orchestrator, "run_external_agent", fake_agent)
    monkeypatch.setattr(orchestrator, "run_gates", lambda _: ())
    monkeypatch.setattr(orchestrator, "implementation_fingerprint", lambda _: "stable")
    monkeypatch.setattr(orchestrator, "disposable_review_workspace", lambda path: nullcontext(path))

    outcome = orchestrator._repair_window(
        repo,
        item("X-01"),
        repo,
        run_dir,
        runner="fake",
        max_repairs=1,
        initial_repair_context="",
        first_state=RunState.DEVELOPMENT,
    )

    assert outcome.state is RunState.HUMAN_REVIEW
    developer_prompts = [prompt for role, prompt in prompts if role == "developer"]
    reviewer_prompts = [prompt for role, prompt in prompts if role == "reviewer"]
    assert "Durable defect family: TOCTOU_MUTABLE_INPUT" in developer_prompts[1]
    assert "underlying invariant" in developer_prompts[1]
    assert "Explicit denial reported as pending human" in developer_prompts[1]
    assert "BF-001" in developer_prompts[1]
    assert "BF-002" in developer_prompts[1]
    assert "Mutable source bytes can change" in reviewer_prompts[1]
    assert "TOCTOU_MUTABLE_INPUT" in reviewer_prompts[1]
    payload = json.loads((run_dir / "run.json").read_text())
    convergence = next(
        event
        for event in payload["events"]
        if event["message"] == "Reviewer findings classified for convergence."
    )
    classification = convergence["details"]["findings"][0]
    assert classification["durable_family_id"] == "TOCTOU_MUTABLE_INPUT"
    assert classification["discovery_kind"] == "known_static_family_first_manifestation"
    assert convergence["details"]["blocking_findings"] == ["BF-001", "BF-002"]


def test_repair_window_carries_continuation_history_into_first_reviewer_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import shutil
    import subprocess
    from contextlib import nullcontext
    from types import SimpleNamespace

    from smf.engineering_agent import orchestrator
    from smf.engineering_agent.runlog import initialize_run

    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copytree(Path("scripts/engineering-agent"), repo / "scripts/engineering-agent")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
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
        cwd=repo,
        check=True,
    )
    prior = tmp_path / "prior"
    prior.mkdir()
    (prior / "run.json").write_text(json.dumps({"state": "stopped", "events": []}))
    (prior / "reviewer-final-1.md").write_text(
        "FAIL\n1. **Medium - Explicit denial reported as pending human**\n"
        "   - Reproduction: deny approval and inspect state"
    )
    run_dir = tmp_path / "continuation"
    run_dir.mkdir()
    initialize_run(run_dir, item("X-01"), repo, continuation_of=prior)
    reviewer_prompts: list[str] = []

    def fake_agent(
        worktree: Path,
        role: str,
        prompt: str,
        output_dir: Path,
        command: str | None,
        attempt: int,
    ) -> SimpleNamespace:
        del worktree, output_dir, command, attempt
        if role == "reviewer":
            reviewer_prompts.append(prompt)
            return SimpleNamespace(returncode=0, final_message=lambda: "PASS")
        return SimpleNamespace(returncode=0, final_message=lambda: "implemented")

    monkeypatch.setattr(orchestrator, "run_external_agent", fake_agent)
    monkeypatch.setattr(orchestrator, "run_gates", lambda _: ())
    monkeypatch.setattr(orchestrator, "implementation_fingerprint", lambda _: "stable")
    monkeypatch.setattr(orchestrator, "disposable_review_workspace", lambda path: nullcontext(path))

    outcome = orchestrator._repair_window(
        repo,
        item("X-01"),
        repo,
        run_dir,
        runner="fake",
        max_repairs=0,
        initial_repair_context="authorized continuation",
        first_state=RunState.REPAIR,
    )

    assert outcome.state is RunState.HUMAN_REVIEW
    assert "Explicit denial reported as pending human" in reviewer_prompts[0]
    assert "DENIAL_VS_PENDING" in reviewer_prompts[0]


def test_review_learning_records_static_pattern_in_future_prompts(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import (
        learned_patterns_for_prompt,
        load_learning_registry,
        record_review_learning,
    )

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    finding = parse_review(
        "FAIL\n1. **High - Qualified source bytes can change after admission**\n"
        "   Mutable source content was observed by conversion."
    ).findings[0]
    learned = record_review_learning(
        tmp_path,
        finding,
        backlog_key="READY-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures=set(),
    )
    assert learned["static_pattern_id"] == "TOCTOU_MUTABLE_INPUT"
    assert learned["escape_analysis"]["escaped_architect_specification"] is True
    assert learned["escape_analysis"]["novel_reviewer_discovery"] is False
    assert "TOCTOU_MUTABLE_INPUT" in load_learning_registry(tmp_path)["findings"]
    prompt = learned_patterns_for_prompt(tmp_path)
    assert "TOCTOU_MUTABLE_INPUT" in prompt
    assert "[HIGH]" in prompt
    assert "seen 1x" in prompt
    assert "Qualified source bytes can change" in prompt
    assert "Mutable source content was observed" in prompt


def test_static_learning_retains_multiple_family_manifestations(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import (
        learned_patterns_for_prompt,
        load_learning_registry,
        record_review_learning,
    )

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    first = parse_review(
        "FAIL\n1. **High - Mutable source bytes can change after admission**\n"
        "   Conversion rereads changed content."
    ).findings[0]
    second = parse_review(
        "FAIL\n1. **Medium - Mutable control file changes after admission**\n"
        "   A qualified include is reread from mutable storage."
    ).findings[0]
    learned_first = record_review_learning(
        tmp_path,
        first,
        backlog_key="X-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures=set(),
    )
    learned_second = record_review_learning(
        tmp_path,
        second,
        backlog_key="X-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures={learned_first["signature"]},
    )

    assert learned_second["learning_id"] == "TOCTOU_MUTABLE_INPUT"
    assert learned_second["escape_analysis"]["same_static_family_new_manifestation"] is True
    assert learned_second["escape_analysis"]["exact_repeated_finding"] is False
    registry = load_learning_registry(tmp_path)
    examples = registry["findings"]["TOCTOU_MUTABLE_INPUT"]["examples"]
    assert {example["signature"] for example in examples} == {
        "mutable source bytes can change after admission",
        "mutable control file changes after admission",
    }
    assert registry["findings"]["TOCTOU_MUTABLE_INPUT"]["signatures"] == [
        "mutable control file changes after admission",
        "mutable source bytes can change after admission",
    ]
    prompt = learned_patterns_for_prompt(tmp_path)
    assert "Mutable source bytes can change" in prompt
    assert "Mutable control file changes" in prompt


def test_exact_repeat_has_distinct_escape_classification(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import record_review_learning

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    finding = parse_review(
        "FAIL\n1. **High - Mutable source bytes can change after admission**\n"
        "   Conversion rereads changed content."
    ).findings[0]
    first = record_review_learning(
        tmp_path,
        finding,
        backlog_key="X-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures=set(),
    )
    repeated = record_review_learning(
        tmp_path,
        finding,
        backlog_key="X-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures={first["signature"]},
    )
    assert repeated["escape_analysis"]["exact_repeated_finding"] is True
    assert repeated["escape_analysis"]["same_static_family_new_manifestation"] is False


def test_review_learning_promotes_novel_finding_across_backlog_items(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import (
        learned_patterns_for_prompt,
        load_learning_registry,
        record_review_learning,
    )

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    finding = parse_review(
        "FAIL\n1. **High - Result digest ignores policy epoch**\n"
        "   Reproduction: change only the policy epoch and observe the same digest."
    ).findings[0]
    first = record_review_learning(
        tmp_path,
        finding,
        backlog_key="READY-01",
        run_dir=tmp_path / "run-1",
        previously_seen_signatures=set(),
    )
    second = record_review_learning(
        tmp_path,
        finding,
        backlog_key="VAL-01",
        run_dir=tmp_path / "run-2",
        previously_seen_signatures={first["signature"]},
    )
    assert first["learning_id"].startswith("LEARNED-")
    assert second["occurrences"] == 2
    assert second["backlog_keys"] == ["READY-01", "VAL-01"]
    assert second["escape_analysis"]["known_before_review"] is True
    registry = load_learning_registry(tmp_path)
    assert registry["findings"][first["learning_id"]]["occurrences"] == 2
    prompt = learned_patterns_for_prompt(tmp_path)
    assert first["learning_id"] in prompt
    assert "Result digest ignores policy epoch" in prompt


def test_learned_pattern_prompt_is_bounded(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import (
        learned_patterns_for_prompt,
        record_review_learning,
    )

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    for index in range(15):
        finding = parse_review(
            f"FAIL\n1. **Medium - Novel state invariant {index}**\n"
            f"   Unique reviewer discovery number {index}."
        ).findings[0]
        record_review_learning(
            tmp_path,
            finding,
            backlog_key=f"X-{index}",
            run_dir=tmp_path / f"run-{index}",
            previously_seen_signatures=set(),
        )
    prompt = learned_patterns_for_prompt(tmp_path, limit=12)
    assert prompt.count("LEARNED-") == 12
    assert len(prompt) < 12_000


def test_bounded_learning_prompt_represents_static_and_novel_findings(tmp_path: Path) -> None:
    import shutil

    from smf.engineering_agent.review_feedback import parse_review
    from smf.engineering_agent.review_learning import (
        learned_patterns_for_prompt,
        record_review_learning,
    )

    prompts = tmp_path / "scripts/engineering-agent"
    prompts.mkdir(parents=True)
    shutil.copy(
        Path("scripts/engineering-agent/review-patterns.yaml"),
        prompts / "review-patterns.yaml",
    )
    for text in (
        "FAIL\n1. **Critical - Novel policy epoch collision**\n   Unique collision detail.",
        "FAIL\n1. **Low - Mutable source bytes can change after admission**\n"
        "   Conversion rereads changed content.",
    ):
        finding = parse_review(text).findings[0]
        record_review_learning(
            tmp_path,
            finding,
            backlog_key="X-01",
            run_dir=tmp_path / "run-1",
            previously_seen_signatures=set(),
        )

    prompt = learned_patterns_for_prompt(tmp_path, limit=2)
    assert "LEARNED-" in prompt
    assert "TOCTOU_MUTABLE_INPUT" in prompt
