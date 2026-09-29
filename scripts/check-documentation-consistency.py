#!/usr/bin/env python3
"""Check current documentation against parsers, generated plans, and status metadata."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import yaml

from smf.cli.main import build_parser as build_smf_parser
from smf.engineering_agent.cli import build_parser as build_agent_parser
from smf.engineering_agent.competition_plan import validate_plan

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "competition/SEPTEMBER-27-DEADLINE-DASHBOARD.md"
CLI_SURFACE = ROOT / "docs/generated/cli-surface.json"
OWNERSHIP = ROOT / "competition/ACTIVE-OWNERSHIP.yaml"
DOCS = (
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "docs/README.md",
    ROOT / "docs/IMPLEMENTATION_STATUS.md",
    ROOT / "docs/CLI.md",
    ROOT / "docs/TEAM_ONBOARDING.md",
    ROOT / "docs/architecture/overview.md",
    ROOT / "docs/operations/runbook.md",
    DASHBOARD,
    ROOT / "competition/SAS_MIGRATION_RECOVERY_REPORT.md",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parser_surface(parser: argparse.ArgumentParser) -> dict[str, Any]:
    def visit(current: argparse.ArgumentParser, path: tuple[str, ...]) -> dict[str, Any]:
        options: set[str] = set()
        positionals: list[str] = []
        choices: dict[str, list[str]] = {}
        children: dict[str, Any] = {}
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in sorted(action.choices.items()):
                    children[name] = visit(child, (*path, name))
                continue
            if action.dest == "help":
                continue
            if action.option_strings:
                options.update(action.option_strings)
                if action.choices is not None:
                    choices[action.dest] = sorted(str(item) for item in action.choices)
            else:
                positionals.append(action.dest)
        return {
            "path": " ".join(path),
            "options": sorted(options),
            "positionals": positionals,
            "choices": choices,
            "commands": children,
        }

    return visit(parser, (parser.prog,))


def cli_surface() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "smf": _parser_surface(build_smf_parser()),
        "smf-agent": _parser_surface(build_agent_parser()),
    }


def _dashboard_metadata() -> dict[str, Any]:
    text = DASHBOARD.read_text(encoding="utf-8")
    match = re.search(r"<!-- smf-doc-status: (\{.*\}) -->", text)
    if match is None:
        raise ValueError("dashboard status metadata is missing")
    return json.loads(match.group(1))


def _dashboard_active_keys() -> list[str]:
    text = DASHBOARD.read_text(encoding="utf-8")
    block = text.split("<!-- active-day1:begin -->", 1)[1].split("<!-- active-day1:end -->", 1)[0]
    return sorted(set(re.findall(r"^\| `([A-Z0-9-]+)` \|", block, flags=re.MULTILINE)))


def _check_revision(metadata: dict[str, Any]) -> None:
    revision = metadata["source_revision"]
    tree = metadata["source_tree"]
    actual_tree = subprocess.run(
        ["git", "rev-parse", f"{revision}^{{tree}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if actual_tree != tree:
        raise ValueError("dashboard source revision/tree mismatch")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"], cwd=ROOT, check=False
    )
    if ancestor.returncode != 0:
        raise ValueError("dashboard source revision is not an ancestor of HEAD")


def _check_ownership(plan: dict[str, Any]) -> None:
    ownership = yaml.safe_load(OWNERSHIP.read_text(encoding="utf-8"))
    records = {item["backlog_key"] for item in plan["items"]}
    seen_work: set[str] = set()
    owned_paths: list[tuple[str, str]] = []
    for assignment in ownership["assignments"]:
        work_id = assignment["work_id"]
        if work_id in seen_work:
            raise ValueError(f"duplicate active ownership: {work_id}")
        seen_work.add(work_id)
        backlog = assignment.get("backlog_record")
        if assignment["kind"] == "backlog_record" and backlog not in records:
            raise ValueError(f"ownership references unknown backlog record: {backlog}")
        if assignment["kind"] != "backlog_record" and not assignment.get("authorization"):
            raise ValueError(f"maintenance work lacks authorization: {work_id}")
        for path in assignment["files"]:
            for other_work, other in owned_paths:
                if _ownership_paths_overlap(path, other):
                    raise ValueError(
                        f"overlapping active ownership: {work_id}:{path} and {other_work}:{other}"
                    )
            owned_paths.append((work_id, path))


def _ownership_paths_overlap(left: str, right: str) -> bool:
    left = left.removeprefix("./")
    right = right.removeprefix("./")
    left_glob = any(marker in left for marker in "*?[")
    right_glob = any(marker in right for marker in "*?[")
    left_scope = left.rstrip("/")
    right_scope = right.rstrip("/")
    if left == right:
        return True
    if left_glob and not right_glob and fnmatch.fnmatchcase(right_scope, left):
        return True
    if right_glob and not left_glob and fnmatch.fnmatchcase(left_scope, right):
        return True

    def fixed_prefix(pattern: str) -> str:
        positions = [pattern.find(marker) for marker in "*?[" if marker in pattern]
        return pattern[: min(positions)].rstrip("/") if positions else pattern.rstrip("/")

    left_prefix = fixed_prefix(left)
    right_prefix = fixed_prefix(right)
    if left_glob or right_glob:
        return bool(left_prefix and right_prefix) and (
            left_prefix == right_prefix
            or left_prefix.startswith(f"{right_prefix}/")
            or right_prefix.startswith(f"{left_prefix}/")
            or left_prefix.startswith(right_prefix)
            or right_prefix.startswith(left_prefix)
        )
    return (
        left_scope == right_scope
        or left_scope.startswith(f"{right_scope}/")
        or right_scope.startswith(f"{left_scope}/")
    )


def _check_links() -> None:
    pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for document in DOCS:
        text = document.read_text(encoding="utf-8")
        for target in pattern.findall(text):
            raw = target.strip().strip("<>")
            if not raw or raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = raw.split("#", 1)[0]
            if not path_text or "<deployment>" in path_text:
                continue
            resolved = (document.parent / path_text).resolve()
            if not resolved.exists():
                raise ValueError(f"broken link in {document.relative_to(ROOT)}: {target}")


def _check_markdown() -> None:
    for document in DOCS:
        text = document.read_text(encoding="utf-8")
        if text.count("```") % 2:
            raise ValueError(f"unbalanced fenced code block: {document.relative_to(ROOT)}")
        if not text.startswith("# "):
            raise ValueError(f"missing level-one title: {document.relative_to(ROOT)}")


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction | None:
    return next(
        (action for action in parser._actions if isinstance(action, argparse._SubParsersAction)),
        None,
    )


def _validate_cli_invocation(tokens: list[str], document: Path) -> None:
    parser = build_smf_parser() if tokens[0] == "smf" else build_agent_parser()
    allowed_options: set[str] = set()
    index = 1
    while True:
        allowed_options.update(
            option
            for action in parser._actions
            for option in action.option_strings
            if option != "-h"
        )
        nested = _subparsers(parser)
        if nested is None or index >= len(tokens) or tokens[index] not in nested.choices:
            break
        parser = nested.choices[tokens[index]]
        index += 1
    for token in tokens[index:]:
        if token.startswith("--") and token not in allowed_options:
            raise ValueError(f"undocumented parser drift in {document.relative_to(ROOT)}: {token}")


def _check_cli_examples() -> None:
    for document in (
        ROOT / "README.md",
        ROOT / "docs/CLI.md",
        ROOT / "docs/TEAM_ONBOARDING.md",
        ROOT / "docs/operations/runbook.md",
    ):
        text = document.read_text(encoding="utf-8").replace("\\\n", " ")
        for raw in text.splitlines():
            line = raw.strip()
            if not line.startswith(("smf ", "smf-agent ")):
                continue
            try:
                tokens = shlex.split(line)
            except ValueError as error:
                raise ValueError(f"invalid CLI example in {document.relative_to(ROOT)}") from error
            _validate_cli_invocation(tokens, document)


def check() -> None:
    plan_summary = validate_plan(ROOT)
    plan = yaml.safe_load((ROOT / "competition/generated/replan.yaml").read_text(encoding="utf-8"))
    metadata = _dashboard_metadata()
    if metadata["plan_sha256"] != _sha256(ROOT / "competition/generated/replan.yaml"):
        raise ValueError("dashboard generated-plan digest is stale")
    _check_revision(metadata)
    active = _dashboard_active_keys()
    if active != sorted(metadata["active_records"]):
        raise ValueError("dashboard active table differs from status metadata")
    overlap = set(metadata["active_records"]) & set(metadata["completed_records"])
    if overlap:
        raise ValueError(f"completed records still shown active: {sorted(overlap)}")
    if cli_surface() != json.loads(CLI_SURFACE.read_text(encoding="utf-8")):
        raise ValueError("CLI parser surface differs from docs/generated/cli-surface.json")
    _check_ownership(plan)
    _check_links()
    _check_markdown()
    _check_cli_examples()

    recovery = (ROOT / "competition/SAS_MIGRATION_RECOVERY_REPORT.md").read_text(encoding="utf-8")
    if "Historical recovery and authorization record" not in recovery:
        raise ValueError("historical recovery report warning is missing")
    if len(plan_summary["items"]) != 208:
        raise ValueError("unexpected validated competition record count")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-cli-surface", action="store_true")
    args = parser.parse_args()
    if args.write_cli_surface:
        CLI_SURFACE.parent.mkdir(parents=True, exist_ok=True)
        CLI_SURFACE.write_text(
            json.dumps(cli_surface(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    check()
    print("documentation consistency: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
