"""Validate the local competition plan and display a read-only, phase-scoped queue."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .acceptance_sync import SPECS, GitHub, load_specs
from .models import is_foundation_complete

PHASES = {
    "competition-critical": "P0",
    "competition-conditional": "P1",
    "phase2": "P2",
    "later": "P3",
}


EXPECTED_RECORDS = 208
DBENV_KEYS = {"DBENV-01", "DBENV-02", "DBENV-03"}
RECOVERY_REPORT = Path("competition/SAS_MIGRATION_RECOVERY_REPORT.md")
RECOVERY_NEW_KEYS = {
    "AIGW-01",
    "AIREP-01",
    "BASE-11",
    "CLICON-01",
    "CORPUS-11",
    "DBPKG-04",
    "LIC-01",
    "MIGCLI-01",
    "MIGOPS-01",
    "MODAP-01",
    "MODCLI-01",
    "PKG-DES-01",
    "PKG-QUAL-01",
    "PROV-02",
    "READY-02",
    "SCALE-01",
    "SCHEMA-INT-01",
    "UPQ-01",
    "VS-01",
}
INITIAL_RECOVERY_ROOTS = [
    "UPQ-01",
    "CLICON-01",
    "WLD-03",
    "DBX-03",
    "SASSEM-01",
    "SASSEM-02",
    "SASSEM-04",
]


def _recovery_mutations(root: Path) -> dict[str, dict[str, Any]]:
    text = (root / RECOVERY_REPORT).read_text()
    try:
        section = text.split("## 10. Exact proposed Project mutations", 1)[1]
        section = section.split("### 10.1 Corrected sequence and first execution wave", 1)[0]
    except IndexError as error:
        raise ValueError("Recovery report mutation table is missing") from error
    result: dict[str, dict[str, Any]] = {}
    for line in section.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise ValueError("Malformed recovery mutation row")
        record_cell, _, dependency_cell, mutation_cell = cells
        is_new = " new" in record_cell
        keys = record_cell.replace("`", "").removesuffix(" new").split(",")
        dependency_cell = dependency_cell.replace("`", "").replace("**", "").strip()
        scope = mutation_cell.replace("`", "").replace("**", "").strip()
        dependencies = (
            None
            if dependency_cell == "unchanged"
            else [value.strip() for value in dependency_cell.split(",") if value.strip()]
        )
        for key in (value.strip() for value in keys):
            if key in result:
                raise ValueError(f"Duplicate recovery mutation: {key}")
            result[key] = {"depends_on": dependencies, "scope": scope, "new": is_new}
    return result


def validate_plan(root: Path) -> dict[str, Any]:
    plan, specs = load_specs(root)
    items = {row["backlog_key"]: row for row in plan["items"]}
    requirements = yaml.safe_load((root / "competition/requirements.yaml").read_text())
    config = yaml.safe_load((root / "scripts/engineering-agent/config.yaml").read_text())
    if len(items) != EXPECTED_RECORDS:
        raise ValueError(f"Competition inventory must contain exactly {EXPECTED_RECORDS} records")
    for key, row in items.items():
        phase = row.get("delivery_phase")
        if phase not in PHASES or row.get("competition_horizon") != PHASES[phase]:
            raise ValueError(f"Invalid phase/horizon: {key}")
        expected = "P2" if PHASES[phase] == "P3" else PHASES[phase]
        if row.get("project_fields", {}).get("Priority") != expected:
            raise ValueError(f"Invalid Project priority: {key}")
        if row["disposition"] == "DEFER" and phase.startswith("competition-"):
            raise ValueError(f"Deferred item activated: {key}")
        if not isinstance(row.get("execution_wave"), int):
            raise ValueError(f"Missing wave: {key}")
        if f"{key}-AC04" not in specs[key]:
            raise ValueError(f"Missing cohort/integration criterion: {key}")
        for field in ("competition_scope", "phase2_scope", "entry_condition", "evidence_review"):
            if not row.get(field):
                raise ValueError(f"Missing {field}: {key}")
        for reference in row["evidence_review"]["references"]:
            path = (root / reference).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                raise ValueError(f"Missing/unsafe evidence reference: {key}")
        for reference in row["client_requirement_refs"]:
            if reference not in requirements["requirements"]:
                raise ValueError(f"Unknown client requirement: {key}: {reference}")
        parent = row.get("parent_reference")
        if parent and parent not in items:
            raise ValueError(f"Unknown parent: {key}")
        if row.get("implementation_owner") and row["implementation_owner"] != parent:
            raise ValueError(f"Task owner differs from parent: {key}")
        if sorted(row["depends_on"]) != sorted(config["dependencies"].get(key, [])):
            raise ValueError(f"Runner dependency drift: {key}")
        if any(dep not in items for dep in row["depends_on"]):
            raise ValueError(f"Unknown dependency: {key}")
    if set(config["dependencies"]) - set(items):
        raise ValueError("Runner config has unknown keys")
    visited: set[str] = set()

    def visit(key: str, stack: set[str]) -> None:
        if key in stack:
            raise ValueError(f"Dependency cycle: {key}")
        if key in visited:
            return
        for dependency in items[key]["depends_on"]:
            visit(dependency, stack | {key})
        visited.add(key)

    for key in items:
        visit(key, set())

    mutations = _recovery_mutations(root)
    if {key for key, value in mutations.items() if value["new"]} != RECOVERY_NEW_KEYS:
        raise ValueError(
            "Recovery report new-record inventory differs from the accepted 19 records"
        )
    for key, mutation in mutations.items():
        if key not in items:
            raise ValueError(f"Recovery record missing from plan: {key}")
        row = items[key]
        if mutation["depends_on"] is not None and row["depends_on"] != mutation["depends_on"]:
            raise ValueError(f"Recovery dependency drift: {key}")
        if key == "DP-01":
            if row["depends_on"] or "recovery_scope" in row:
                raise ValueError("DP-01 must remain unchanged with no recovery dependency or scope")
            continue
        if row.get("recovery_scope") != mutation["scope"]:
            raise ValueError(f"Recovery scope drift: {key}")
        expected_priority = "P2" if key == "TASK-06" else "P0"
        if row.get("project_fields", {}).get("Priority") != expected_priority:
            raise ValueError(f"Recovery priority drift: {key}")
    if not all(items[key].get("create") is True for key in RECOVERY_NEW_KEYS):
        raise ValueError("Every new recovery record must remain an unpublished create proposal")
    if plan.get("planning_basis", {}).get("initially_runnable_roots") != INITIAL_RECOVERY_ROOTS:
        raise ValueError("Initial recovery-root inventory drift")
    if not DBENV_KEYS.issubset(items):
        raise ValueError("Approved DBENV record inventory is incomplete")
    dbenv_expectations = {
        "DBENV-01": {
            "priority": "P0",
            "phase": "competition-critical",
            "wave": 0,
            "dependencies": ["HENV-01", "HENV-02", "SEC-01", "SEC-02", "CLICON-01"],
        },
        "DBENV-02": {
            "priority": "P0",
            "phase": "competition-critical",
            "wave": 2,
            "dependencies": ["DBENV-01", "DBX-02", "DBX-03", "AIGW-01"],
        },
        "DBENV-03": {
            "priority": "P1",
            "phase": "competition-conditional",
            "wave": 5,
            "dependencies": ["DBENV-01", "DBX-03", "LIC-01", "PKG-DES-01"],
        },
    }
    for key, expected_record in dbenv_expectations.items():
        row = items[key]
        if (
            row.get("disposition") != "NEW"
            or row.get("create") is not True
            or row.get("parent_reference") != "EPIC-HENV"
            or row.get("project_fields", {}).get("Priority") != expected_record["priority"]
            or row.get("delivery_phase") != expected_record["phase"]
            or row.get("execution_wave") != expected_record["wave"]
            or row.get("depends_on") != expected_record["dependencies"]
        ):
            raise ValueError(f"Approved DBENV record drift: {key}")
    if plan.get("planning_basis", {}).get("dbenv_publication_authorized") != sorted(DBENV_KEYS):
        raise ValueError("DBENV publication authorization drift")
    if plan.get("planning_basis", {}).get("dbenv_launch_authorized") != ["DBENV-01"]:
        raise ValueError("DBENV launch authorization drift")
    if plan.get("planning_basis", {}).get("dbenv_initially_runnable_roots") != ["DBENV-01"]:
        raise ValueError("DBENV runnable-root inventory drift")
    task = items["TASK-06"]
    if (
        task.get("disposition") != "DEFER"
        or task.get("delivery_phase") != "phase2"
        or task.get("lifecycle_constraints")
        != {
            "status": "Todo",
            "implementation_state": "Partial",
            "worktree": "preserve-dirty-pending-separate-approval",
        }
    ):
        raise ValueError("TASK-06 preservation constraints drifted")
    coverage = (root / SPECS / "_ACCEPTANCE-COVERAGE.md").read_text()
    covered = set(re.findall(r"^\| \[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\]", coverage, re.M))
    if covered != set(items):
        raise ValueError("Acceptance coverage inventory differs from the replan")
    delivery_plan = (root / "competition/COMPETITION-PLAN.md").read_text()
    materialized = delivery_plan.split("## Materialized OSS-first recovery backlog", 1)
    if len(materialized) != 2:
        raise ValueError("Competition plan recovery inventory differs from the report")
    for key, mutation in mutations.items():
        row = items[key]
        dependencies = ", ".join(row["depends_on"]) or "unchanged/none"
        expected = (
            f"| `{key}` | {row['project_fields']['Priority']} | {row['delivery_phase']} | "
            f"{row['execution_wave']} | {dependencies} | {mutation['scope']} |"
        )
        if expected not in materialized[1]:
            raise ValueError(f"Competition plan recovery rendering drift: {key}")
    return plan


def lifecycle_issues(row: dict[str, Any]) -> list[str]:
    """Surface contradictory state without treating closure as successful completion."""
    fields = row["fields"]
    done = fields.get("Status") == "Done"
    implemented = fields.get("Implementation State") == "Foundation Complete"
    issues = []
    if done != implemented:
        issues.append("Status and Implementation State disagree about completion")
    if row["content"].get("state") == "CLOSED" and not is_foundation_complete(
        fields.get("Status", ""), fields.get("Implementation State", "")
    ):
        issues.append("Closed issue lacks canonical completion; reconcile its disposition")
    return issues


def competition_queue(
    plan: dict[str, Any],
    remote: list[dict[str, Any]],
    *,
    assumed_complete: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Return the competition-critical queue without mutating live Project state.

    assumed_complete is limited to a single autonomous drain. It lets later items consume
    locally committed predecessors before any pull request merge or Project closeout occurs.
    """
    by_key: dict[str, dict[str, Any]] = {}
    for row in remote:
        key = row["fields"].get("Backlog Key")
        if key:
            if key in by_key:
                raise ValueError(f"Duplicate live key: {key}")
            by_key[key] = row
    local_keys = {row["backlog_key"] for row in plan["items"]}
    if set(by_key) != local_keys:
        raise ValueError("Live/local key inventory differs; reconcile before scheduling")

    def complete(key: str) -> bool:
        if key in assumed_complete:
            return True
        row = by_key[key]
        fields = row["fields"]
        return is_foundation_complete(
            fields.get("Status", ""), fields.get("Implementation State", "")
        )

    result = []
    for item in plan["items"]:
        key = item["backlog_key"]
        row = by_key[key]
        if row["fields"].get("Parent", "") != (item.get("parent_reference") or ""):
            raise ValueError(f"Live parent drift: {key}")
        if row["fields"].get("Work Type", "") != item["work_type_reference"]:
            raise ValueError(f"Live work type drift: {key}")
        if row["content"].get("__typename") == "Issue":
            if row["content"].get("repository", {}).get("nameWithOwner") != plan["repository"]:
                raise ValueError(f"Foreign live issue: {key}")
            if item.get("issue_number") not in (None, row["content"].get("number")):
                raise ValueError(f"Live issue identity drift: {key}")
        if (
            item["delivery_phase"] != "competition-critical"
            or item["disposition"] == "DEFER"
            or item["work_type_reference"] == "Epic"
            or item.get("implementation_owner")
            or complete(key)
        ):
            continue
        blockers = [dep for dep in item["depends_on"] if not complete(dep)]
        issues = [f"{key}: {message}" for message in lifecycle_issues(row)]
        for dependency in blockers:
            issues.extend(
                f"{dependency}: {message}" for message in lifecycle_issues(by_key[dependency])
            )
        result.append(
            {
                "key": key,
                "title": item["title"],
                "wave": item["execution_wave"],
                "dependency_state": "blocked" if blockers or issues else "eligible-for-review",
                "blockers": blockers,
                "lifecycle_issues": issues,
                "live_priority": row["fields"].get("Priority"),
                "planned_priority": item["project_fields"]["Priority"],
                "target": row["content"].get("number") or "draft",
            }
        )
    return sorted(
        result,
        key=lambda row: (row["dependency_state"] != "eligible-for-review", row["wave"], row["key"]),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    try:
        plan = validate_plan(root)
        print(
            json.dumps(
                {
                    "records": len(plan["items"]),
                    "phases": dict(Counter(row["delivery_phase"] for row in plan["items"])),
                },
                indent=2,
            )
        )
        if not args.validate_only:
            queue = competition_queue(plan, GitHub().snapshot(plan["project"]["number"]))
            print("Read-only queue: dependency eligibility is NOT client or launch approval.")
            print(json.dumps(queue, indent=2))
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
        parser.exit(1, f"Competition plan check failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
