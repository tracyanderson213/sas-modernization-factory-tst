import copy
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from smf.engineering_agent.acceptance_sync import PLAN
from smf.engineering_agent.competition_plan import (
    DBENV_KEYS,
    INITIAL_RECOVERY_ROOTS,
    RECOVERY_NEW_KEYS,
    competition_queue,
    main,
    validate_plan,
)
from smf.engineering_agent.models import BacklogItem

REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    plan = yaml.safe_load((REPOSITORY / PLAN).read_text())
    paths = {
        str(PLAN),
        "competition/requirements.yaml",
        "competition/generated/issue-specs/_ACCEPTANCE-POLICY.md",
        "competition/generated/issue-specs/_ACCEPTANCE-COVERAGE.md",
        "competition/SAS_MIGRATION_RECOVERY_REPORT.md",
        "competition/COMPETITION-PLAN.md",
        "scripts/engineering-agent/config.yaml",
    }
    for item in plan["items"]:
        paths.add(item["body_file"])
        paths.update(item["evidence_review"]["references"])
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY / relative, target)
    return tmp_path


def store_plan(root: Path, plan: dict[str, Any]) -> None:
    (root / PLAN).write_text(yaml.safe_dump(plan))


def remote(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "fields": {
                "Backlog Key": item["backlog_key"],
                "Parent": item.get("parent_reference", ""),
                "Work Type": item["work_type_reference"],
                "Status": "Todo",
                "Implementation State": "Not Started",
                "Priority": "P2",
            },
            "content": {"__typename": "DraftIssue"},
        }
        for item in plan["items"]
    ]


def test_complete_plan_and_confirmed_envelope(root: Path) -> None:
    plan = validate_plan(root)
    requirements = yaml.safe_load((root / "competition/requirements.yaml").read_text())
    security_policy = yaml.safe_load((root / "deployments/humana/security-policy.yaml").read_text())
    assert len(plan["items"]) == 208
    assert plan["planning_basis"]["confirmed_envelope"]["weeks"] == 10
    assert plan["planning_basis"]["confirmed_envelope"]["sas_scripts"] == 1000
    assert sum(item["disposition"] == "DEFER" for item in plan["items"]) == 11
    assert requirements["confirmed_by_user"]["customer_ecosystem"] == {
        "secret_platform": "HashiCorp Vault",
        "identity_provider": "Microsoft Entra ID / Active Directory",
        "approved_llm_provider": "Anthropic",
        "source": "user clarification in this planning conversation",
        "caveat": (
            "Exact deployment, workload identity federation mechanism, scopes, endpoints, "
            "models and owner approvals remain pending."
        ),
    }
    art_02_boundary = requirements["confirmed_by_user"]["art_02_implementation_boundary"]
    assert art_02_boundary["status"] == "approved"
    assert "block network access" in art_02_boundary["activation_boundary"]
    assert "not isolated offline implementation" in art_02_boundary["activation_boundary"]
    by_key = {item["backlog_key"]: item for item in plan["items"]}
    assert by_key["AIP-02"]["delivery_phase"] == "competition-critical"
    assert by_key["AIP-03"]["delivery_phase"] == "later"
    assert by_key["ART-02"]["title"] == "Enterprise secret provider and workload identity"
    assert security_policy["ai"]["allowed_providers"] == ["anthropic"]
    assert security_policy["ai"]["binding_status"] == "pending"
    assert security_policy["identity"]["provider"] == "microsoft-entra-id-active-directory"
    assert security_policy["secrets"]["provider"] == "hashicorp-vault"
    assert security_policy["secrets"]["binding_status"] == "pending"


def test_recovery_materialization_preserves_completion_and_task_boundaries(root: Path) -> None:
    plan = validate_plan(root)
    by_key = {item["backlog_key"]: item for item in plan["items"]}
    assert set(RECOVERY_NEW_KEYS).issubset(by_key)
    assert by_key["DP-01"]["depends_on"] == []
    assert "recovery_scope" not in by_key["DP-01"]
    assert by_key["TASK-06"]["project_fields"]["Priority"] == "P2"
    assert by_key["TASK-06"]["lifecycle_constraints"] == {
        "status": "Todo",
        "implementation_state": "Partial",
        "worktree": "preserve-dirty-pending-separate-approval",
    }
    assert plan["planning_basis"]["initially_runnable_roots"] == INITIAL_RECOVERY_ROOTS
    for key in ("SASSEM-01", "SASSEM-02", "SASSEM-04"):
        assert by_key[key]["project_fields"]["Priority"] == "P0"
        assert by_key[key]["delivery_phase"] == "competition-critical"
    assert {"DBENV-01", "DBENV-02", "DBENV-03"} == DBENV_KEYS
    assert by_key["DBENV-01"]["depends_on"] == [
        "HENV-01",
        "HENV-02",
        "SEC-01",
        "SEC-02",
        "CLICON-01",
    ]
    assert by_key["DBENV-02"]["depends_on"] == [
        "DBENV-01",
        "DBX-02",
        "DBX-03",
        "AIGW-01",
    ]
    assert by_key["DBENV-03"]["depends_on"] == [
        "DBENV-01",
        "DBX-03",
        "LIC-01",
        "PKG-DES-01",
    ]
    assert plan["planning_basis"]["dbenv_publication_authorized"] == sorted(DBENV_KEYS)
    assert plan["planning_basis"]["dbenv_launch_authorized"] == ["DBENV-01"]


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("competition_horizon", "P3", "Invalid phase/horizon"),
        ("depends_on", ["NOT-REAL"], "dependency drift"),
        ("client_requirement_refs", ["UNKNOWN"], "Unknown client requirement"),
        ("project_fields", {"Priority": "P2"}, "Invalid Project priority"),
        ("disposition", "DEFER", "Deferred item activated"),
        ("parent_reference", "UNKNOWN", "Unknown parent"),
        ("competition_scope", "", "Missing competition_scope"),
    ],
)
def test_rejects_inconsistent_plan(root: Path, field: str, value: Any, match: str) -> None:
    plan = validate_plan(root)
    plan["items"][0][field] = value
    store_plan(root, plan)
    with pytest.raises(ValueError, match=match):
        validate_plan(root)


def test_cycle_rejected_even_when_runner_agrees(root: Path) -> None:
    plan = validate_plan(root)
    key = plan["items"][0]["backlog_key"]
    plan["items"][0]["depends_on"] = [key]
    store_plan(root, plan)
    path = root / "scripts/engineering-agent/config.yaml"
    config = yaml.safe_load(path.read_text())
    config["dependencies"][key] = [key]
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(ValueError, match="Dependency cycle"):
        validate_plan(root)


def test_missing_integration_acceptance_rejected(root: Path) -> None:
    plan = validate_plan(root)
    item = plan["items"][0]
    path = root / item["body_file"]
    path.write_text(path.read_text().replace(item["backlog_key"] + "-AC04", "MISSING"))
    with pytest.raises(ValueError, match="Missing cohort/integration"):
        validate_plan(root)


def test_queue_excludes_epics_tasks_later_and_completed(root: Path) -> None:
    plan = validate_plan(root)
    rows = remote(plan)
    original = copy.deepcopy(rows)
    queue = competition_queue(plan, rows)
    assert rows == original
    assert not any(row["key"].startswith(("EPIC-", "TASK-")) for row in queue)
    assert not any(row["key"] in {"AIP-03", "LEARN-01", "API-01"} for row in queue)
    anthropic = next(row for row in queue if row["key"] == "AIP-02")
    assert anthropic["blockers"] == ["AIP-01", "AIP-05", "SEC-04", "ART-02"]
    assert next(row for row in queue if row["key"] == "AIP-01")["blockers"] == ["CV-02"]
    for row in rows:
        if row["fields"]["Backlog Key"] == "CV-02":
            row["fields"]["Status"] = "Done"
            row["fields"]["Implementation State"] = "Foundation Complete"
    queue = competition_queue(plan, rows)
    assert not any(row["key"] == "CV-02" for row in queue)
    aip = next(row for row in queue if row["key"] == "AIP-01")
    assert aip["dependency_state"] == "eligible-for-review"
    assert aip["live_priority"] == "P2" and aip["planned_priority"] == "P0"


def test_queue_accepts_session_local_completion_without_mutating_live_state(root: Path) -> None:
    plan = validate_plan(root)
    rows = remote(plan)
    original = copy.deepcopy(rows)
    queue = competition_queue(plan, rows, assumed_complete=frozenset({"CV-02"}))
    assert rows == original
    assert not any(row["key"] == "CV-02" for row in queue)
    assert next(row for row in queue if row["key"] == "AIP-01")["dependency_state"] == (
        "eligible-for-review"
    )


@pytest.mark.parametrize(
    ("status", "implementation", "state", "complete", "conflict"),
    [
        ("In Progress", "Foundation Complete", "OPEN", False, True),
        ("Done", "Partial", "OPEN", False, True),
        ("In Progress", "Partial", "CLOSED", False, True),
        ("Todo", "Not Started", "CLOSED", False, True),
        ("Todo", "Not Started", "OPEN", False, False),
        ("Done", "Foundation Complete", "OPEN", True, False),
        ("Done", "Foundation Complete", "CLOSED", True, False),
    ],
)
def test_queue_uses_runner_completion_and_flags_conflicts(
    root: Path, status: str, implementation: str, state: str, complete: bool, conflict: bool
) -> None:
    plan = validate_plan(root)
    rows = remote(plan)
    dependency = next(row for row in rows if row["fields"]["Backlog Key"] == "CV-02")
    dependency["fields"].update({"Status": status, "Implementation State": implementation})
    dependency["content"] = {
        "__typename": "Issue",
        "number": next(
            item["issue_number"] for item in plan["items"] if item["backlog_key"] == "CV-02"
        ),
        "repository": {"nameWithOwner": plan["repository"]},
        "state": state,
    }
    original = copy.deepcopy(rows)
    queue = competition_queue(plan, rows)
    assert rows == original
    canonical = BacklogItem("CV-02", "Dependency", "Feature", "P0", "", status, implementation)
    assert canonical.complete is complete
    aip = next(row for row in queue if row["key"] == "AIP-01")
    assert aip["blockers"] == ([] if complete else ["CV-02"])
    assert bool(aip["lifecycle_issues"]) is conflict
    assert aip["dependency_state"] == ("eligible-for-review" if complete else "blocked")
    own_rows = [row for row in queue if row["key"] == "CV-02"]
    assert bool(own_rows) is not complete
    if conflict:
        assert own_rows[0]["dependency_state"] == "blocked"
        assert own_rows[0]["lifecycle_issues"]


@pytest.mark.parametrize("change", ["missing", "duplicate", "parent", "foreign"])
def test_queue_fails_closed_on_live_identity_drift(root: Path, change: str) -> None:
    plan = validate_plan(root)
    rows = remote(plan)
    if change == "missing":
        rows.pop()
    elif change == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif change == "parent":
        rows[0]["fields"]["Parent"] = "UNKNOWN"
    else:
        rows[0]["content"] = {
            "__typename": "Issue",
            "repository": {"nameWithOwner": "foreign/repo"},
        }
    with pytest.raises(ValueError):
        competition_queue(plan, rows)


def test_validate_only_does_not_contact_github(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden() -> None:
        pytest.fail("Offline validation attempted GitHub access")

    monkeypatch.setattr("smf.engineering_agent.competition_plan.GitHub", forbidden)
    assert main(["--repo-root", str(root), "--validate-only"]) == 0
