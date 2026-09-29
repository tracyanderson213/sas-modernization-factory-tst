#!/usr/bin/env python3
"""Validate the materialized recovery backlog without mutating GitHub or Project state."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from smf.engineering_agent.acceptance_sync import digest, load_specs  # noqa: E402
from smf.engineering_agent.competition_plan import (  # noqa: E402
    INITIAL_RECOVERY_ROOTS,
    RECOVERY_NEW_KEYS,
    _recovery_mutations,
    validate_plan,
)

RECOVERY_BODY_UPDATE_KEYS = {
    "BASE-02",
    "BASE-04",
    "BASE-06",
    "BASE-07",
    "BASE-08",
    "BASE-09",
    "BASE-10",
    "COMP-01",
    "CV-04",
    "DBPKG-01",
    "DBX-01",
    "DBX-03",
    "DBX-04",
    "DP-02",
    "DP-03",
    "DP-04",
    "DP-05",
    "HPILOT-04",
    "ORCH-02",
    "SASSEM-01",
    "SASSEM-02",
    "SASSEM-04",
    "TASK-06",
    "VAL-01",
    "WLD-03",
}
RECOVERY_PRIORITY_KEYS = {
    "BASE-06",
    "BASE-07",
    "BASE-08",
    "BASE-09",
    "BASE-10",
    "CV-04",
    "SASSEM-01",
    "SASSEM-02",
    "SASSEM-04",
    "TASK-06",
    "WLD-03",
}


def git_text(ref: str, relative: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{ref}:{relative}"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"Cannot read {relative} from baseline {ref}")
    return result.stdout


def check(name: str, passed: bool, **evidence: Any) -> dict[str, Any]:
    return {"name": name, "pass": passed, **evidence}


def audit(
    acceptance_report: Path,
    baseline_ref: str,
    *,
    require_published: bool = False,
    prepublication_report: Path | None = None,
) -> dict[str, Any]:
    plan = validate_plan(ROOT)
    _, specs = load_specs(ROOT)
    items = {row["backlog_key"]: row for row in plan["items"]}
    mutations = _recovery_mutations(ROOT)
    report = json.loads(acceptance_report.read_text())
    entries = {row["key"]: row for row in report["entries"]}
    completed = {
        key
        for key, row in entries.items()
        if row.get("reason") == "completed-item-needs-follow-up-review"
    }

    baseline = yaml.safe_load(git_text(baseline_ref, "competition/generated/replan.yaml"))
    baseline_items = {row["backlog_key"]: row for row in baseline["items"]}
    changed_completed: list[dict[str, Any]] = []
    for key in sorted(completed & set(baseline_items)):
        current = items[key]
        previous = baseline_items[key]
        changes = []
        if current["depends_on"] != previous["depends_on"]:
            changes.append("dependencies")
        relative = f"competition/generated/issue-specs/{key}.md"
        if (ROOT / relative).read_text() != git_text(baseline_ref, relative):
            changes.append("acceptance-specification")
        if changes:
            changed_completed.append({"key": key, "changes": changes})

    unfinished_priority_violations = []
    for key, row in items.items():
        if row["project_fields"]["Priority"] != "P0" or key in completed:
            continue
        for dependency in row["depends_on"]:
            if (
                dependency not in completed
                and items[dependency]["project_fields"]["Priority"] != "P0"
            ):
                unfinished_priority_violations.append(
                    {
                        "record": key,
                        "dependency": dependency,
                        "priority": items[dependency]["project_fields"]["Priority"],
                    }
                )

    proposed_p0 = {
        key
        for key in mutations
        if key not in completed and items[key]["project_fields"]["Priority"] == "P0"
    }
    roots = sorted(
        key
        for key in proposed_p0
        if all(dependency in completed for dependency in items[key]["depends_on"])
    )
    downstream = sorted(proposed_p0 - set(roots))
    unblocked_downstream = [
        key
        for key in downstream
        if all(dependency in completed for dependency in items[key]["depends_on"])
    ]

    missing_live = {key for key, row in entries.items() if row.get("reason") == "missing-live-item"}
    expected_missing = set() if require_published else RECOVERY_NEW_KEYS
    published_acceptance_violations = []
    if require_published:
        for key in sorted(RECOVERY_NEW_KEYS | RECOVERY_BODY_UPDATE_KEYS):
            if entries[key].get("action") != "unchanged":
                published_acceptance_violations.append(
                    {"key": key, "action": entries[key].get("action")}
                )
    new_field_violations = []
    if require_published:
        for key in sorted(RECOVERY_NEW_KEYS):
            row = items[key]
            fields = entries[key].get("metadata", {}).get("fields", {})
            expected_fields = {
                "Backlog Key": key,
                "Status": "Todo",
                "Implementation State": "Not Started",
                "Priority": "P0",
                "Work Type": row["work_type_reference"],
                "Area": row["project_fields"]["Area"],
                "Parent": row.get("parent_reference", ""),
            }
            for field, expected in expected_fields.items():
                if fields.get(field, "") != expected:
                    new_field_violations.append(
                        {
                            "key": key,
                            "field": field,
                            "expected": expected,
                            "actual": fields.get(field, ""),
                        }
                    )
    priority_violations = []
    if require_published:
        for key in sorted(RECOVERY_PRIORITY_KEYS):
            if entries[key].get("live_priority") != items[key]["project_fields"]["Priority"]:
                priority_violations.append(
                    {
                        "key": key,
                        "expected": items[key]["project_fields"]["Priority"],
                        "actual": entries[key].get("live_priority"),
                    }
                )
    task_fields = entries["TASK-06"].get("metadata", {}).get("fields", {})
    task_lifecycle_matches = (
        task_fields.get("Status") == "Todo" and task_fields.get("Implementation State") == "Partial"
    )
    unauthorized_scope_violations = []
    if prepublication_report:
        prior = json.loads(prepublication_report.read_text())
        prior_entries = {row["key"]: row for row in prior["entries"]}
        prior_unrelated_updates = {
            key
            for key, row in prior_entries.items()
            if row.get("action") == "update" and key not in RECOVERY_BODY_UPDATE_KEYS
        }
        current_updates = {key for key, row in entries.items() if row.get("action") == "update"}
        if current_updates != prior_unrelated_updates:
            unauthorized_scope_violations.append(
                {
                    "kind": "acceptance-update-set",
                    "expected": sorted(prior_unrelated_updates),
                    "actual": sorted(current_updates),
                }
            )
        prior_priority_differences = {
            key
            for key, row in prior_entries.items()
            if row.get("live_priority") != row.get("planned_priority")
            and key not in RECOVERY_PRIORITY_KEYS
            and key not in RECOVERY_NEW_KEYS
        }
        current_priority_differences = {
            key
            for key, row in entries.items()
            if row.get("live_priority") != row.get("planned_priority")
        }
        if current_priority_differences != prior_priority_differences:
            unauthorized_scope_violations.append(
                {
                    "kind": "priority-discrepancy-set",
                    "expected": sorted(prior_priority_differences),
                    "actual": sorted(current_priority_differences),
                }
            )
    unexpected_blocked = [
        {"key": key, "reason": row.get("reason")}
        for key, row in entries.items()
        if row.get("action") == "blocked"
        and row.get("reason") not in {"completed-item-needs-follow-up-review", "missing-live-item"}
    ]
    unexplained_updates = [
        key
        for key, row in entries.items()
        if row.get("action") == "update"
        and (
            row.get("reason") or not all(field in row for field in ("before", "after", "metadata"))
        )
    ]

    checks = [
        check(
            "acceptance report matches current plan",
            report.get("plan_hash") == digest(plan),
            plan_hash=report.get("plan_hash"),
        ),
        check(
            "every referenced dependency exists",
            all(dep in items for row in items.values() for dep in row["depends_on"]),
        ),
        check(
            "record identifiers are unique", len(items) == len(plan["items"]), records=len(items)
        ),
        check("dependency graph is acyclic", True, validator="validate_plan"),
        check(
            "all unfinished dependencies are P0",
            not unfinished_priority_violations,
            violations=unfinished_priority_violations,
        ),
        check(
            "completed records received no new scope or dependencies",
            not changed_completed,
            violations=changed_completed,
        ),
        check(
            (
                "all 19 recovery records are published"
                if require_published
                else "all 19 unpublished records are the only missing live items"
            ),
            missing_live == expected_missing,
            missing_live=sorted(missing_live),
        ),
        check(
            "approved recovery acceptance bodies match live Project",
            not published_acceptance_violations,
            violations=published_acceptance_violations,
        ),
        check(
            "new recovery record fields match the approved plan",
            not new_field_violations,
            violations=new_field_violations,
        ),
        check(
            "approved recovery priorities match the live Project",
            not priority_violations,
            violations=priority_violations,
        ),
        check(
            "TASK-06 is deferred Todo while preserving Partial",
            task_lifecycle_matches if require_published else True,
            expected={"Status": "Todo", "Implementation State": "Partial"},
            actual={
                "Status": task_fields.get("Status"),
                "Implementation State": task_fields.get("Implementation State"),
            },
        ),
        check(
            "unrelated acceptance and priority discrepancies remain untouched",
            not unauthorized_scope_violations,
            violations=unauthorized_scope_violations,
        ),
        check(
            "acceptance synchronization has no unexplained blocked results",
            not unexpected_blocked,
            violations=unexpected_blocked,
        ),
        check(
            "acceptance synchronization has no unexplained updates",
            not unexplained_updates,
            violations=unexplained_updates,
        ),
        check(
            "seven initially runnable roots remain exact",
            roots == sorted(INITIAL_RECOVERY_ROOTS),
            roots=roots,
        ),
        check(
            "all downstream recovery records remain dependency-blocked",
            not unblocked_downstream and bool(downstream),
            records=downstream,
            violations=unblocked_downstream,
        ),
    ]
    return {
        "schema_version": 1,
        "mode": "read-only",
        "repository": str(ROOT),
        "baseline_ref": baseline_ref,
        "acceptance_report": str(acceptance_report),
        "counts": {
            "records": len(items),
            "recovery_new_records": len(RECOVERY_NEW_KEYS),
            "new_unpublished": len(missing_live & RECOVERY_NEW_KEYS),
            "completed_protected": len(completed),
            "acceptance_actions": report["counts"],
            "runnable_roots": len(roots),
            "dependency_blocked_recovery_records": len(downstream),
        },
        "checks": checks,
        "overall_pass": all(row["pass"] for row in checks),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance-report", type=Path, required=True)
    parser.add_argument("--baseline-ref", default="main")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-published", action="store_true")
    parser.add_argument("--prepublication-report", type=Path)
    args = parser.parse_args()
    result = audit(
        args.acceptance_report.resolve(),
        args.baseline_ref,
        require_published=args.require_published,
        prepublication_report=(
            args.prepublication_report.resolve() if args.prepublication_report else None
        ),
    )
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        destination = args.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered)
    print(rendered, end="")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
