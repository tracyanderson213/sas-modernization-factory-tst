from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

from smf.cli.main import build_parser as build_smf_parser
from smf.engineering_agent.cli import build_parser as build_agent_parser

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs/operations/runbook.md"
ACCEPTANCE = ROOT / "docs/OPS-03_ACCEPTANCE.md"
AFFECTED_REGRESSIONS = ROOT / "scripts/ops03-affected-regressions.sh"


def _commands(parser: argparse.ArgumentParser) -> set[str]:
    action = next(item for item in parser._actions if isinstance(item, argparse._SubParsersAction))
    return set(action.choices)


def _nested_commands(parser: argparse.ArgumentParser, command: str) -> set[str]:
    action = next(item for item in parser._actions if isinstance(item, argparse._SubParsersAction))
    nested = next(
        item
        for item in action.choices[command]._actions
        if isinstance(item, argparse._SubParsersAction)
    )
    return set(nested.choices)


def _documented_commands(text: str, program: str) -> set[str]:
    pattern = rf"^\| `{re.escape(program)} ([a-z][a-z0-9-]*)` \|"
    return set(re.findall(pattern, text, flags=re.MULTILINE))


def test_runbook_command_inventory_matches_current_parsers() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert _documented_commands(text, "smf") == _commands(build_smf_parser())
    assert _documented_commands(text, "smf-agent") == _commands(build_agent_parser())
    assert _nested_commands(build_smf_parser(), "architecture-review") == {"assemble"}
    assert _nested_commands(build_smf_parser(), "deployment-config") == {
        "init",
        "plan",
        "preflight",
    }
    assert _nested_commands(build_smf_parser(), "upstream") == {"qualify"}
    assert _nested_commands(build_smf_parser(), "ai-gateway") == {"preflight"}
    assert _nested_commands(build_smf_parser(), "migrate") == {
        "convert",
        "modernize",
        "status",
        "resume",
        "exceptions",
        "approve",
        "promote",
    }
    for command in (
        "smf architecture-review assemble",
        "smf deployment-config init",
        "smf deployment-config plan",
        "smf deployment-config preflight",
        "smf upstream qualify",
        "smf ai-gateway preflight",
        "smf migrate convert",
    ):
        assert f"`{command}`" in text


def test_runbook_rejects_invented_commands_and_documents_non_success_zeroes() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "`smf run` does not exist" in text
    assert "`smf-agent supervised-run` does not exist" in text
    required_warnings = (
        "`smf validate --json` may exit `0` when `status` is `failed`",
        "`smf convert` exits `0` for `review_required`",
        "`smf-agent plan` exits `0` even when `blockers` is non-empty",
        "`submitted` is not `executed`",
        "`READY FOR HUMAN APPROVAL` is not",
    )
    for warning in required_warnings:
        assert warning in text


def test_runbook_preserves_stopped_run_identity_and_distinct_outcomes() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    for phrase in (
        "existing worktree",
        ".smf-agent/runs/<key>/<run-id>/",
        "never create a replacement workspace",
        "never automatically retry `outcome_unknown`",
    ):
        assert phrase in text

    outcomes = {
        "pending",
        "denied",
        "failed",
        "cancelled",
        "skipped",
        "blocked",
        "unsupported",
        "review_required",
        "outcome_unknown",
    }
    for outcome in outcomes:
        assert re.search(rf"\b{outcome}\b", text)


def test_runbook_contains_complete_incident_playbooks() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    playbooks = (
        "Readiness state incident",
        "Conversion disposition incident",
        "Local execution or validation failure",
        "Missing workspace, identity, secret, catalog, schema, or permission",
        "Engineering-agent stop",
        "Interrupted canonical or derived publication",
        "Partial acceptance-body publication",
        "Sensitive-data or credential exposure",
        "Mutable or conflicting evidence",
        "Completion-state disagreement",
    )
    for playbook in playbooks:
        section = text.split(f"### {playbook}", maxsplit=1)[1].split("\n### ", maxsplit=1)[0]
        for step in ("Detect", "Preserve", "Contain", "Diagnose", "Recover", "Verify", "Escalate"):
            assert f"- **{step}:**" in section


def test_runbook_keeps_claims_and_authority_domains_separate() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    for claim in (
        "generated",
        "authenticated",
        "submitted",
        "executed",
        "validated",
        "parity-passed",
        "certified",
        "human-approved",
    ):
        assert f"`{claim}`" in text
    assert "No claim implies another claim" in text
    for domain in (
        "Product CLI authority",
        "Engineering-agent authority",
        "GitHub Project authority",
    ):
        assert domain in text


def test_runbook_references_existing_paths_and_test_selectors() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    block = text.split("<!-- verified-references:begin -->", maxsplit=1)[1].split(
        "<!-- verified-references:end -->", maxsplit=1
    )[0]

    references = re.findall(r"^- `([^`]+)`$", block, flags=re.MULTILINE)
    assert references
    for reference in references:
        path_text, separator, selector = reference.partition("::")
        path = ROOT / path_text
        assert path.exists(), reference
        if separator:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            functions = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
            assert selector in functions, reference


def test_acceptance_results_resolve_to_checked_in_executable_regression_command() -> None:
    acceptance = ACCEPTANCE.read_text(encoding="utf-8")
    assert "`bash scripts/ops03-affected-regressions.sh`" in acceptance
    assert "Affected regression command from the issue" not in acceptance

    script = AFFECTED_REGRESSIONS.read_text(encoding="utf-8")
    references = re.findall(r'^\s+"(tests/[^" ]+(?:::[^" ]+)?)"$', script, re.MULTILINE)
    assert references
    for reference in references:
        assert (ROOT / reference.partition("::")[0]).exists(), reference

    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *references],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert collected.returncode == 0, collected.stdout + collected.stderr
    for reference in references:
        assert reference in collected.stdout
