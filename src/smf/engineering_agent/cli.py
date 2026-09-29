from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from .acceptance_sync import require_current_acceptance
from .autonomous import execute_competition_drain
from .backlog import load_live_project_items, load_project_items
from .models import BacklogItem, CandidateAssessment
from .orchestrator import continue_supervised_run, execute_supervised_run
from .readiness import assess_candidates, recommend_next
from .runlog import latest_stopped_run


def _root() -> Path:
    root = Path.cwd()
    if not (root / ".git").exists() or not (root / "pyproject.toml").exists():
        raise SystemExit("Run smf-agent from the repository root.")
    return root


def _config(root: Path) -> dict[str, object]:
    path = root / "scripts/engineering-agent/config.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _dependencies(config: dict[str, object]) -> dict[str, tuple[str, ...]]:
    raw = config.get("dependencies") or {}
    if not isinstance(raw, dict):
        return {}
    return {
        str(key): tuple(str(value) for value in values)
        for key, values in raw.items()
        if isinstance(values, list)
    }


def _items(root: Path, offline: bool) -> tuple[BacklogItem, ...]:
    if offline:
        return load_project_items(root / ".project-audit/items.json")
    return load_live_project_items()


def _find(items: tuple[BacklogItem, ...], key: str) -> BacklogItem:
    try:
        return next(item for item in items if item.key == key)
    except StopIteration as exc:
        raise SystemExit(f"Backlog item not found: {key}") from exc


def _assessment(
    root: Path,
    items: tuple[BacklogItem, ...],
    key: str,
) -> CandidateAssessment:
    return next(
        item
        for item in assess_candidates(items, _dependencies(_config(root)))
        if item.item.key == key
    )


def command_next(args: argparse.Namespace) -> int:
    root = _root()
    items = _items(root, args.offline)
    candidate = recommend_next(
        assess_candidates(items, _dependencies(_config(root)), focus=args.focus)
    )
    if candidate is None:
        print("No ready backlog item found.")
        return 1
    item = candidate.item
    print(f"Recommended:            {item.key}")
    print(f"Title:                  {item.title}")
    print(f"Priority:               {item.priority}")
    print(f"State:                  {candidate.readiness.value}")
    print(f"Status:                 {item.status}")
    print(f"Implementation State:   {item.implementation_state}")
    print(f"Reason:                 {candidate.reasons[0]}")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    root = _root()
    items = _items(root, args.offline)
    item = _find(items, args.key)
    assessment = _assessment(root, items, item.key)
    payload = {
        "key": item.key,
        "title": item.title,
        "priority": item.priority,
        "status": item.status,
        "implementation_state": item.implementation_state,
        "readiness": assessment.readiness.value,
        "blockers": list(assessment.blockers),
        "issue_number": item.issue_number,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key, value in payload.items():
            print(f"{key:24} {value}")
    return 0


def command_work(args: argparse.Namespace) -> int:
    root = _root()
    items = _items(root, args.offline)
    item = _find(items, args.key)
    assessment = _assessment(root, items, item.key)
    if assessment.blockers:
        raise SystemExit(f"Blocked by: {', '.join(assessment.blockers)}")
    if item.complete:
        raise SystemExit(f"{item.key} is already Foundation Complete.")

    try:
        require_current_acceptance(root, item.key, item.issue_body, offline=args.offline)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    outcome = execute_supervised_run(root, item, runner=args.runner, max_repairs=args.max_repairs)
    print(f"Worktree: {outcome.worktree}")
    print(f"Run record: {outcome.run_dir}")
    print(outcome.message)
    if outcome.state.value == "human_review":
        print("No commit, push, issue close, or Project completion was performed.")
        return 0
    return 1


def command_continue(args: argparse.Namespace) -> int:
    root = _root()
    items = _items(root, args.offline)
    item = _find(items, args.key)
    if item.complete:
        raise SystemExit(f"{item.key} is already Foundation Complete.")
    try:
        require_current_acceptance(root, item.key, item.issue_body, offline=args.offline)
        prior_run = latest_stopped_run(root, item.key)
        outcome = continue_supervised_run(
            root, item, prior_run, runner=args.runner, max_repairs=args.max_repairs
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Continuing from: {prior_run}")
    print(f"Worktree: {outcome.worktree}")
    print(f"Run record: {outcome.run_dir}")
    print(outcome.message)
    if outcome.state.value == "human_review":
        print("No commit, push, issue close, or Project completion was performed.")
        return 0
    return 1


def command_drain(args: argparse.Namespace) -> int:
    root = _root()
    try:
        outcome = execute_competition_drain(
            root,
            runner=args.runner,
            max_repairs=args.max_repairs,
            allowed_keys=frozenset(args.scope_key) if args.scope_key else None,
            base_branch=args.base_branch,
            continue_external_blockers=args.continue_external_blockers,
        )
    except (ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    for item in outcome.items:
        suffix = f" @ {item.commit[:12]}" if item.commit else ""
        print(f"{item.key}: {item.disposition}{suffix} - {item.message}")
    print(f"Drain record: {outcome.drain_dir}")
    print(outcome.message)
    if outcome.state == "exhausted":
        committed = [item for item in outcome.items if item.disposition == "committed"]
        if committed:
            print(f"Cumulative branch: agent/{committed[-1].key.lower()}")
            print(f"Final local commit: {committed[-1].commit}")
        print("No push, merge, issue close, or Project completion was performed.")
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smf-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    next_parser = subparsers.add_parser("next", help="Recommend the next ready item")
    next_parser.add_argument("--offline", action="store_true")
    next_parser.add_argument(
        "--focus",
        metavar="EPIC-KEY",
        help="Restrict recommendation to ready children of an explicit epic",
    )
    next_parser.set_defaults(func=command_next)

    plan = subparsers.add_parser("plan", help="Show deterministic item readiness")
    plan.add_argument("key")
    plan.add_argument("--offline", action="store_true")
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=command_plan)

    work = subparsers.add_parser("work", help="Run supervised engineering agents")
    work.add_argument("key")
    work.add_argument("--offline", action="store_true")
    work.add_argument("--runner")
    work.add_argument("--max-repairs", type=int, default=2)
    work.set_defaults(func=command_work)

    continuation = subparsers.add_parser(
        "continue", help="Authorize a new bounded repair window for a stopped run"
    )
    continuation.add_argument("key")
    continuation.add_argument("--offline", action="store_true")
    continuation.add_argument("--runner")
    continuation.add_argument("--max-repairs", type=int, default=2)
    continuation.set_defaults(func=command_continue)

    drain = subparsers.add_parser(
        "drain", help="Autonomously drain eligible Humana competition work"
    )
    drain.add_argument("--runner")
    drain.add_argument("--max-repairs", type=int, default=2)
    drain.add_argument(
        "--scope-key",
        action="append",
        default=[],
        help="Restrict execution to an explicitly named backlog key; repeat for a bounded wave",
    )
    drain.add_argument(
        "--base-branch",
        help="Use an explicitly named clean review branch instead of the synced main default",
    )
    drain.add_argument(
        "--continue-external-blockers",
        action="store_true",
        help="Record unpromoted drafts as blocked and continue with other scoped runnable work",
    )
    drain.set_defaults(func=command_drain)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))
