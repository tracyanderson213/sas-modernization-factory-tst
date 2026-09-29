from __future__ import annotations

from pathlib import Path

from .gates import GateResult, run_gates
from .models import BacklogItem, RunOutcome, RunState
from .policy import forbidden_developer_changes, role_write_violations
from .prompts import _review_patterns, render_role_prompt
from .review_feedback import (
    ReviewMode,
    ReviewPacket,
    finding_signature,
    load_review_packet,
    parse_review,
    render_repair_brief,
    render_reviewer_convergence_context,
    write_review_packet,
)
from .review_learning import classify_finding, record_review_learning
from .review_scope import (
    ReviewScope,
    blocking_packet,
    classify_closure,
    discovery_scope,
    load_review_scope,
    write_review_scope,
)
from .runlog import (
    continuation_chain,
    create_run_dir,
    initialize_run,
    latest_reviewer_findings,
    load_run_payload,
    record_event,
    reviewer_history,
    write_final_report,
    write_json,
)
from .runner import run_external_agent
from .workspace import (
    create_worktree,
    disposable_review_workspace,
    git_changed_paths,
    implementation_fingerprint,
)


def _gate_payload(results: tuple[GateResult, ...]) -> list[dict[str, object]]:
    return [
        {
            "name": r.name,
            "returncode": r.returncode,
            "passed": r.passed,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }
        for r in results
    ]


def _review_passed(packet: ReviewPacket) -> bool:
    return packet.passed


def _review_packets_from_texts(texts: tuple[str, ...]) -> tuple[ReviewPacket, ...]:
    packets: list[ReviewPacket] = []
    for text in texts:
        try:
            packets.append(parse_review(text))
        except ValueError:
            continue
    return tuple(packets)


def _repeated_findings(history: tuple[ReviewPacket, ...], current: ReviewPacket) -> tuple[str, ...]:
    prior = {finding_signature(f) for packet in history for f in packet.findings}
    return tuple(
        finding.title for finding in current.findings if finding_signature(finding) in prior
    )


def _finding_families(repo_root: Path, packets: tuple[ReviewPacket, ...]) -> dict[str, str | None]:
    return {
        finding_signature(finding): classify_finding(repo_root, finding)
        for packet in packets
        for finding in packet.findings
    }


def _blocking_ids(scope: ReviewScope) -> dict[str, str]:
    return {finding_signature(item.finding): item.blocking_id for item in scope.unresolved}


def _inherited_review_scope(
    run_dir: Path,
    historical_packets: tuple[ReviewPacket, ...],
    *,
    acceptance_context: str = "",
) -> ReviewScope:
    scope = ReviewScope(ReviewMode.DISCOVERY)
    found_artifact = False
    for candidate in continuation_chain(run_dir):
        scopes = {
            int(path.stem.rsplit("-", 1)[-1]): path
            for path in candidate.glob("review-scope-*.json")
        }
        packets = {
            int(path.stem.rsplit("-", 1)[-1]): path
            for path in candidate.glob("review-findings-*.json")
        }
        for attempt in sorted(scopes.keys() | packets.keys()):
            if attempt in scopes:
                scope = load_review_scope(scopes[attempt])
                found_artifact = True
                continue
            packet = load_review_packet(packets[attempt])
            scope = (
                discovery_scope(packet)
                if scope.mode is ReviewMode.DISCOVERY
                else classify_closure(packet, scope, acceptance_context=acceptance_context)
            )
            write_review_scope(candidate / f"review-scope-{attempt}.json", scope)
            found_artifact = True
    if found_artifact:
        return scope
    if historical_packets:
        return discovery_scope(historical_packets[-1])
    return scope


def _stop(run_dir: Path, worktree: Path, message: str, **details: object) -> RunOutcome:
    record_event(run_dir, RunState.STOPPED, message, **details)
    write_final_report(run_dir, RunState.STOPPED, message)
    return RunOutcome(RunState.STOPPED, run_dir, worktree, message)


def architect_stop(architect_text: str, *, require_clearance: bool) -> str | None:
    """Translate the Architect's explicit autonomous clearance marker into a stop reason."""
    first_line = architect_text.splitlines()[0].strip()
    if first_line == "HUMAN_DECISION_REQUIRED":
        return (
            "Architect identified contractual, business, security, data-boundary, or systemic "
            "architecture ambiguity requiring human judgment."
        )
    if require_clearance and first_line != "PROCEED":
        return (
            "Architect did not provide the explicit PROCEED clearance required for autonomous "
            "execution."
        )
    return None


def _repair_window(
    repo_root: Path,
    item: BacklogItem,
    worktree: Path,
    run_dir: Path,
    *,
    runner: str | None,
    max_repairs: int,
    initial_repair_context: str,
    first_state: RunState,
) -> RunOutcome:
    artifacts = worktree / "agent-artifacts"
    artifacts.mkdir(exist_ok=True)
    repair_context = initial_repair_context
    historical_packets = _review_packets_from_texts(reviewer_history(run_dir))
    review_scope = _inherited_review_scope(
        run_dir, historical_packets, acceptance_context=item.issue_body
    )
    patterns = _review_patterns(repo_root)
    for attempt in range(1, max_repairs + 2):
        state = first_state if attempt == 1 else RunState.REPAIR
        current_packet = blocking_packet(review_scope)
        finding_families = _finding_families(repo_root, historical_packets)
        brief = render_repair_brief(
            current_packet,
            (),
            patterns,
            gate_failure=repair_context if repair_context.startswith("Deterministic gate") else "",
            finding_families=finding_families,
            blocking_ids=_blocking_ids(review_scope),
        )
        brief_path = run_dir / f"repair-brief-{attempt}.md"
        brief_path.write_text(brief, encoding="utf-8")
        combined_context = repair_context
        if current_packet is not None or repair_context.startswith("Deterministic gate"):
            combined_context = brief
        record_event(
            run_dir, state, f"Developer attempt {attempt} started.", repair_brief=str(brief_path)
        )
        developer = run_external_agent(
            worktree,
            "developer",
            render_role_prompt(repo_root, "developer", item, repair_context=combined_context),
            run_dir,
            runner,
            attempt,
        )
        if developer.returncode != 0:
            return _stop(run_dir, worktree, f"Developer attempt {attempt} failed.")
        forbidden = forbidden_developer_changes(git_changed_paths(worktree))
        if forbidden:
            return _stop(
                run_dir,
                worktree,
                "Developer touched protected evidence/security/quality-control paths.",
                paths=list(forbidden),
            )

        record_event(run_dir, RunState.GATES, f"Gates started after attempt {attempt}.")
        gates = run_gates(worktree)
        write_json(run_dir / f"gates-{attempt}.json", _gate_payload(gates))
        if not all(g.passed for g in gates):
            failed = next(g for g in gates if not g.passed)
            repair_context = (
                f"Deterministic gate '{failed.name}' failed.\n\nstdout:\n{failed.stdout}\n\n"
                f"stderr:\n{failed.stderr}\nRepair the implementation without weakening the gate."
            )
            if attempt <= max_repairs:
                continue
            return _stop(run_dir, worktree, f"Gate {failed.name} still fails after repair budget.")

        before_review = implementation_fingerprint(worktree)
        record_event(
            run_dir,
            RunState.REVIEW,
            f"Reviewer started after attempt {attempt}.",
            review_mode=review_scope.mode.value,
            blocking_findings=[item.blocking_id for item in review_scope.unresolved],
        )
        with disposable_review_workspace(worktree) as review_workspace:
            scoped_packet = blocking_packet(review_scope)
            reviewer_context = render_reviewer_convergence_context(
                (scoped_packet,) if scoped_packet is not None else (),
                _finding_families(repo_root, (scoped_packet,) if scoped_packet is not None else ()),
                mode=review_scope.mode,
                blocking_ids=_blocking_ids(review_scope),
            )
            reviewer = run_external_agent(
                review_workspace,
                "reviewer",
                render_role_prompt(
                    repo_root,
                    "reviewer",
                    item,
                    reviewer_context=reviewer_context,
                    review_mode=review_scope.mode,
                ),
                run_dir,
                runner,
                attempt,
            )
        if reviewer.returncode != 0:
            return _stop(run_dir, worktree, "Reviewer agent failed.")
        if implementation_fingerprint(worktree) != before_review:
            return _stop(run_dir, worktree, "Reviewer modified implementation files.")
        reviewer_text = reviewer.final_message().strip()
        try:
            packet = parse_review(reviewer_text)
        except ValueError as exc:
            return _stop(run_dir, worktree, f"Reviewer output contract failed: {exc}")
        (artifacts / "review.md").write_text(reviewer_text + "\n", encoding="utf-8")
        packet_path = run_dir / f"review-findings-{attempt}.json"
        write_review_packet(packet_path, packet)
        record_event(
            run_dir,
            RunState.REVIEW,
            "Reviewer defect packet persisted.",
            packet=str(packet_path),
            findings=len(packet.findings),
            verdict=packet.verdict,
            review_mode=review_scope.mode.value,
        )
        reviewed_mode = review_scope.mode
        try:
            review_scope = (
                discovery_scope(packet)
                if reviewed_mode is ReviewMode.DISCOVERY
                else classify_closure(packet, review_scope, acceptance_context=item.issue_body)
            )
        except ValueError as exc:
            return _stop(run_dir, worktree, f"Reviewer closure contract failed: {exc}")
        scope_path = run_dir / f"review-scope-{attempt}.json"
        write_review_scope(scope_path, review_scope)
        record_event(
            run_dir,
            RunState.REVIEW,
            "Reviewer scope disposition persisted.",
            review_mode=reviewed_mode.value,
            scope=str(scope_path),
            blocking_findings=[
                {"id": item.blocking_id, "title": item.finding.title}
                for item in review_scope.unresolved
            ],
            deferred_findings=[item.finding.title for item in review_scope.deferred],
            closure_disposition=(
                "not_applicable"
                if reviewed_mode is ReviewMode.DISCOVERY
                else ("blocked" if review_scope.unresolved else "closed")
            ),
        )
        repeated = _repeated_findings(historical_packets, packet)
        prior_signatures = {
            finding_signature(finding)
            for prior_packet in historical_packets
            for finding in prior_packet.findings
        }
        blocking_signatures = {finding_signature(item.finding) for item in review_scope.unresolved}
        learning = [
            record_review_learning(
                repo_root,
                finding,
                backlog_key=item.key,
                run_dir=run_dir,
                previously_seen_signatures=prior_signatures,
                review_disposition=(
                    "blocking"
                    if reviewed_mode is ReviewMode.DISCOVERY
                    or finding_signature(finding) in blocking_signatures
                    else "deferred"
                ),
            )
            for finding in packet.findings
        ]
        if packet.findings:
            historical_packets = (*historical_packets, packet)
        if _review_passed(packet) or (
            reviewed_mode is ReviewMode.CLOSURE and not review_scope.unresolved
        ):
            message = "READY FOR HUMAN APPROVAL"
            record_event(
                run_dir,
                RunState.HUMAN_REVIEW,
                message,
                review_mode=reviewed_mode.value,
                deferred_findings=[item.finding.title for item in review_scope.deferred],
                closure_disposition=("pass" if packet.passed else "deferred_findings_non_blocking"),
            )
            write_final_report(run_dir, RunState.HUMAN_REVIEW, message)
            return RunOutcome(RunState.HUMAN_REVIEW, run_dir, worktree, message)
        unresolved_packet = blocking_packet(review_scope)
        if unresolved_packet is None:
            return _stop(run_dir, worktree, "Review scope lost all blockers unexpectedly.")
        repair_context = render_repair_brief(
            unresolved_packet,
            (),
            patterns,
            finding_families=_finding_families(repo_root, historical_packets),
            blocking_ids=_blocking_ids(review_scope),
        )
        postmortem = run_dir / f"review-postmortem-{attempt}.md"
        postmortem_lines = [
            "# Reviewer Escape Analysis",
            "",
            f"Reviewer findings: {len(packet.findings)}",
            "",
            f"Repeated finding titles: {list(repeated)}",
            "",
            "## Finding classification",
            "",
        ]
        for finding, learned in zip(packet.findings, learning, strict=True):
            escape = learned["escape_analysis"]
            postmortem_lines.extend(
                [
                    f"### {finding.finding_id} {finding.title}",
                    "",
                    f"- Learning ID: {learned['learning_id']}",
                    f"- Known before review: {escape['known_before_review']}",
                    f"- Escaped Architect specification: "
                    f"{escape['escaped_architect_specification']}",
                    f"- Escaped Developer self-review: {escape['escaped_developer_self_review']}",
                    f"- Escaped deterministic gates: {escape['escaped_deterministic_gates']}",
                    f"- Novel Reviewer discovery: {escape['novel_reviewer_discovery']}",
                    f"- Durable family: {escape['durable_family_id']}",
                    f"- Convergence classification: {escape['discovery_kind']}",
                    f"- Exact repeated finding: {escape['exact_repeated_finding']}",
                    "- Same static family, new manifestation: "
                    f"{escape['same_static_family_new_manifestation']}",
                    "",
                ]
            )
        postmortem_lines.extend(
            [
                "The next Developer attempt receives the complete unresolved blocking set. "
                "Deferred findings remain learning for future work and do not broaden this "
                "repair cycle.",
                "",
            ]
        )
        postmortem.write_text("\n".join(postmortem_lines), encoding="utf-8")
        record_event(
            run_dir,
            RunState.REPAIR,
            "Reviewer findings classified for convergence.",
            review_mode=reviewed_mode.value,
            findings=[
                {
                    "title": finding.title,
                    "signature": finding_signature(finding),
                    "learning_id": learned["learning_id"],
                    "durable_family_id": learned["escape_analysis"]["durable_family_id"],
                    "discovery_kind": learned["escape_analysis"]["discovery_kind"],
                }
                for finding, learned in zip(packet.findings, learning, strict=True)
            ],
            blocking_findings=[item.blocking_id for item in review_scope.unresolved],
            deferred_findings=[item.finding.title for item in review_scope.deferred],
            postmortem=str(postmortem),
        )
        if repeated:
            record_event(
                run_dir,
                RunState.REPAIR,
                "Reviewer repeated previously known defect classes.",
                findings=list(repeated),
                postmortem=str(postmortem),
            )
        if attempt > max_repairs:
            return _stop(run_dir, worktree, "Reviewer still rejects after repair budget.")
    return _stop(run_dir, worktree, "Repair loop exhausted unexpectedly.")


def execute_supervised_run(
    repo_root: Path,
    item: BacklogItem,
    *,
    runner: str | None,
    max_repairs: int = 2,
    base: str = "main",
    autonomous: bool = False,
) -> RunOutcome:
    worktree = create_worktree(repo_root, item.key, base=base)
    run_dir = create_run_dir(repo_root, item.key)
    initialize_run(run_dir, item, worktree)
    artifacts = worktree / "agent-artifacts"
    artifacts.mkdir(exist_ok=True)
    before = git_changed_paths(worktree)
    record_event(run_dir, RunState.ARCHITECTURE, "Architect agent started.")
    architect = run_external_agent(
        worktree, "architect", render_role_prompt(repo_root, "architect", item), run_dir, runner
    )
    if architect.returncode != 0:
        return _stop(run_dir, worktree, "Architect agent failed.")
    violations = role_write_violations(before, git_changed_paths(worktree), role="architect")
    if violations:
        return _stop(
            run_dir, worktree, "Architect modified implementation files.", paths=list(violations)
        )
    architect_text = architect.final_message().strip()
    if not architect_text:
        return _stop(run_dir, worktree, "Architect returned no final architecture plan.")
    stop_reason = architect_stop(architect_text, require_clearance=autonomous)
    if stop_reason is not None:
        return _stop(run_dir, worktree, stop_reason)
    (artifacts / "architect.md").write_text(architect_text + "\n", encoding="utf-8")
    return _repair_window(
        repo_root,
        item,
        worktree,
        run_dir,
        runner=runner,
        max_repairs=max_repairs,
        initial_repair_context="",
        first_state=RunState.DEVELOPMENT,
    )


def continue_supervised_run(
    repo_root: Path,
    item: BacklogItem,
    prior_run_dir: Path,
    *,
    runner: str | None,
    max_repairs: int = 2,
) -> RunOutcome:
    prior = load_run_payload(prior_run_dir)
    if prior.get("state") != RunState.STOPPED.value:
        raise ValueError("Only a stopped run may be continued.")
    if prior.get("backlog_key") != item.key:
        raise ValueError("Stopped run backlog key does not match requested item.")
    worktree = Path(str(prior.get("worktree", "")))
    if not worktree.is_dir():
        raise ValueError(f"Stopped run worktree no longer exists: {worktree}")
    latest_reviewer_findings(prior_run_dir)
    run_dir = create_run_dir(repo_root, item.key)
    initialize_run(run_dir, item, worktree, continuation_of=prior_run_dir)
    record_event(
        run_dir,
        RunState.REPAIR,
        "Human authorized a new bounded continuation window.",
        prior_run=str(prior_run_dir),
    )
    context = (
        "A prior bounded autonomous run stopped after exhausting its repair budget. "
        "A human explicitly authorized this continuation window. Preserve the existing "
        "implementation. Repair only the unresolved blocking set carried in the durable "
        "review-scope artifact; closed historical findings do not reopen.\n"
    )
    return _repair_window(
        repo_root,
        item,
        worktree,
        run_dir,
        runner=runner,
        max_repairs=max_repairs,
        initial_repair_context=context,
        first_state=RunState.REPAIR,
    )
