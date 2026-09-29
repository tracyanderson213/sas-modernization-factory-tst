import copy
import json
import subprocess
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
import yaml

from smf.engineering_agent.acceptance_sync import (
    AUDIT,
    BEGIN,
    END,
    FINGERPRINT_PREFIX,
    PLAN,
    SPECS,
    GitHub,
    apply_report,
    digest,
    load_sources,
    load_specs,
    main,
    make_report,
    managed,
    map_node,
    reconcile_priority_text,
    replace_managed,
    require_current_acceptance,
    text_digest,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    directory = tmp_path / SPECS
    directory.mkdir(parents=True)
    (directory / "_ACCEPTANCE-POLICY.md").write_text("Shared approved policy")
    text = "# AIP-01 - Interface\n" + "\n".join(
        [f"**AIP-01-AC{i:02}:** concrete criterion" for i in range(1, 4)]
        + [f"**HC-{i:02}:** shared gate" for i in range(1, 6)]
    )
    (directory / "AIP-01.md").write_text(text)
    (tmp_path / PLAN).write_text(
        yaml.safe_dump(
            {
                "repository": "owner/repo",
                "project": {"owner": "@me", "number": 2},
                "items": [
                    {
                        "backlog_key": "AIP-01",
                        "body_file": str(SPECS / "AIP-01.md"),
                        "disposition": "MODIFY",
                        "issue_number": None,
                    }
                ],
            }
        )
    )
    return tmp_path


def remote(kind: str = "Issue") -> dict[str, Any]:
    content: dict[str, Any] = {
        "__typename": kind,
        "id": "CONTENT",
        "title": "Interface",
        "body": "Original metadata and acceptance",
        "updatedAt": "before",
    }
    if kind == "Issue":
        content.update(number=93, state="OPEN", repository={"nameWithOwner": "owner/repo"})
    return {
        "item_id": "ITEM",
        "fields": {
            "Backlog Key": "AIP-01",
            "Status": "In Progress",
            "Implementation State": "Partial",
            "Parent": "EPIC-AIP",
            "Priority": "P0",
        },
        "content": content,
    }


class FakeGitHub(GitHub):
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = copy.deepcopy(rows)
        self.writes: list[str] = []
        self.tamper_readback = False
        self.race = False

    def snapshot(self, number: int) -> list[dict[str, Any]]:
        return copy.deepcopy(self.rows)

    def get(self, item_id: str) -> dict[str, Any]:
        value = copy.deepcopy(next(r for r in self.rows if r["item_id"] == item_id))
        if self.race:
            value["content"]["body"] += " concurrent edit"
        return value

    def update(self, item: dict[str, Any], body: str, repository: str) -> None:
        self.writes.append(item["item_id"])
        target = next(r for r in self.rows if r["item_id"] == item["item_id"])
        target["content"]["body"] = body
        target["content"]["updatedAt"] = "after"
        if self.tamper_readback:
            target["fields"]["Status"] = "Done"


def test_priority_difference_reported_but_not_applied(root: Path) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    plan["items"][0]["project_fields"] = {"Priority": "P1"}
    plan["items"][0]["delivery_phase"] = "competition-conditional"
    plan["items"][0]["depends_on"] = ["CV-02"]
    (root / PLAN).write_text(yaml.safe_dump(plan))
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    entry = report["entries"][0]
    assert entry["live_priority"] == "P0"
    assert entry["planned_priority"] == "P1"
    assert report["planned_priority_changes"] == 1
    assert report["project_fields_applied"] is False
    assert entry["depends_on"] == ["CV-02"]
    apply_report(root, report, ["AIP-01"], fake)
    assert fake.rows[0]["fields"]["Priority"] == "P0"


def test_default_is_read_only_dry_run(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGitHub([remote()])
    monkeypatch.setattr("smf.engineering_agent.acceptance_sync.GitHub", lambda: fake)
    assert main(["--repo-root", str(root)]) == 0
    assert fake.writes == []
    reports = list((root / AUDIT).glob("dry-run-*.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text())["counts"] == {"update": 1}


def test_priority_line_correction_is_reviewed_and_does_not_change_fields(root: Path) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    plan["items"][0]["competition_horizon"] = "P0"
    (root / PLAN).write_text(yaml.safe_dump(plan))
    row = remote()
    row["content"]["body"] = "# Original\n- Competition Priority: P1\nUnrelated instructions.\n"
    row["fields"]["Priority"] = "P1"
    fake = FakeGitHub([row])
    report = make_report(root, fake.snapshot(2))
    edit = report["entries"][0]["unmanaged_priority_edit"]
    assert edit == {"before": "- Competition Priority: P1", "after": "- Competition Priority: P0"}
    assert fake.writes == []
    apply_report(root, report, ["AIP-01"], fake)
    assert fake.rows[0]["content"]["body"].startswith(
        "# Original\n- Competition Priority: P0\nUnrelated instructions.\n"
    )
    assert fake.rows[0]["fields"]["Priority"] == "P1"
    repeated = make_report(root, fake.snapshot(2))
    assert repeated["entries"][0]["unmanaged_priority_edit"] is None
    assert repeated["counts"] == {"unchanged": 1}


def test_priority_reconciliation_preserves_managed_and_unrelated_text() -> None:
    block = f"{BEGIN}\n- Competition Priority: P3\n{END}"
    body = "Prose mentioning P1 is unchanged.\n" + block + "\n- Competition Priority: P1\nTail\n"
    updated, edit = reconcile_priority_text(body, "P0")
    assert block in updated
    assert updated.startswith("Prose mentioning P1 is unchanged.\n")
    assert updated.endswith("- Competition Priority: P0\nTail\n")
    assert edit is not None


@pytest.mark.parametrize("priority", ["P0", "P2", "P3"])
def test_repeated_legacy_labels_block_instead_of_guessing(priority: str) -> None:
    with pytest.raises(ValueError, match="Multiple unmanaged priority"):
        reconcile_priority_text("- Competition Priority: P1\n- Competition Priority: P2", priority)


def test_task_parent_reconciliation_blocks_publication_and_launch(root: Path) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    plan["items"][0]["review_disposition"] = "reconcile-task-with-completed-parent"
    (root / PLAN).write_text(yaml.safe_dump(plan))
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    entry = report["entries"][0]
    assert entry["action"] == "blocked"
    assert entry["reason"] == "task-parent-evidence-reconciliation-required"
    with pytest.raises(ValueError, match="blocked records"):
        apply_report(root, report, ["AIP-01"], fake)
    _, specs = load_specs(root)
    with pytest.raises(ValueError, match="reconcile task/parent"):
        require_current_acceptance(root, "AIP-01", specs["AIP-01"], offline=False)
    assert fake.writes == []


def test_missing_and_duplicate_keys_are_blocked(root: Path) -> None:
    assert make_report(root, [])["entries"][0]["reason"] == "missing-live-item"
    assert make_report(root, [remote(), remote()])["entries"][0]["reason"] == "duplicate-live-key"


@pytest.mark.parametrize("case", ["foreign", "closed", "done", "complete", "unsupported"])
def test_unsafe_targets_are_blocked(root: Path, case: str) -> None:
    row = remote()
    if case == "foreign":
        row["content"]["repository"]["nameWithOwner"] = "other/repo"
    elif case == "closed":
        row["content"]["state"] = "CLOSED"
    elif case == "done":
        row["fields"]["Status"] = "Done"
    elif case == "complete":
        row["fields"]["Implementation State"] = "Foundation Complete"
    else:
        row["content"]["__typename"] = "PullRequest"
    report = make_report(root, [row])
    assert report["entries"][0]["action"] == "blocked"
    assert "after" not in report["entries"][0]


def test_known_issue_mismatch_blocks(root: Path) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    plan["items"][0]["issue_number"] = 94
    (root / PLAN).write_text(yaml.safe_dump(plan))
    assert make_report(root, [remote()])["entries"][0]["reason"] == "planned-issue-mismatch"


def test_duplicate_content_mapping_is_blocked(root: Path) -> None:
    other = remote()
    other["fields"]["Backlog Key"] = "OTHER-01"
    assert make_report(root, [remote(), other])["entries"][0]["action"] == "blocked"


@pytest.mark.parametrize("kind", ["Issue", "DraftIssue"])
def test_apply_preserves_metadata_reads_back_and_is_idempotent(root: Path, kind: str) -> None:
    fake = FakeGitHub([remote(kind)])
    original = copy.deepcopy(fake.rows[0])
    report = make_report(root, fake.snapshot(2))
    assert apply_report(root, report, ["AIP-01"], fake) == ["AIP-01"]
    assert fake.rows[0]["content"]["body"].startswith(original["content"]["body"] + "\n\n")
    assert fake.rows[0]["fields"] == original["fields"]
    assert fake.rows[0]["content"]["title"] == original["content"]["title"]
    assert len(list((root / AUDIT).glob("*/AIP-01-verified.json"))) == 1
    repeated = make_report(root, fake.snapshot(2))
    assert repeated["counts"] == {"unchanged": 1}
    assert apply_report(root, repeated, ["AIP-01"], fake) == ["AIP-01"]
    assert fake.writes == ["ITEM"]


@pytest.mark.parametrize("kind", ["Issue", "DraftIssue"])
@pytest.mark.parametrize("terminal_newline", [False, True])
def test_exact_source_adoption_is_canonical_and_idempotent(
    root: Path, kind: str, terminal_newline: bool
) -> None:
    _, raw_specs, specs, policy = load_sources(root)
    row = remote(kind)
    row["content"]["body"] = raw_specs["AIP-01"] + ("\n" if terminal_newline else "")
    original = copy.deepcopy(row)
    fake = FakeGitHub([row])
    report = make_report(
        root,
        fake.snapshot(2),
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )
    entry = report["entries"][0]
    assert report["selected_keys"] == ["AIP-01"]
    assert report["exact_source_adoption"] is True
    assert entry["action"] == "update"
    assert entry["operation"] == "exact-source-adoption"
    assert entry["after"] == specs["AIP-01"] + "\n"
    assert entry["before_bytes"] == len(entry["before"].encode())
    assert entry["after_bytes"] == len(entry["after"].encode())
    assert entry["before_sha256"] == text_digest(entry["before"])
    assert entry["after_sha256"] == text_digest(entry["after"])
    assert entry["raw_spec_sha256"] == text_digest(raw_specs["AIP-01"])
    assert entry["shared_policy_sha256"] == text_digest(policy)
    assert entry["managed_block_sha256"] == text_digest(specs["AIP-01"])
    assert entry["source_fingerprint"] == digest({"spec": raw_specs["AIP-01"], "policy": policy})
    assert entry["source_fingerprint_occurrences"] == 1
    assert entry["raw_source_occurrences"] == 1
    assert entry["shared_policy_occurrences"] == 1
    assert entry["begin_marker_occurrences"] == 1
    assert entry["end_marker_occurrences"] == 1
    assert entry["project_fields_modified"] is False
    assert entry["lifecycle_values_modified"] is False
    assert apply_report(root, report, ["AIP-01"], fake) == ["AIP-01"]
    assert fake.rows[0]["fields"] == original["fields"]
    assert fake.rows[0]["content"]["title"] == original["content"]["title"]
    repeated = make_report(
        root,
        fake.snapshot(2),
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )
    assert repeated["entries"][0]["action"] == "unchanged"
    assert repeated["entries"][0]["operation"] == "managed-section-reconciliation"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda source: "x" + source,
        lambda source: source + "x",
        lambda source: source.replace("Interface", "Interfacf", 1),
        lambda source: source + " ",
        lambda source: source.replace(" concrete", "  concrete", 1),
        lambda source: source + "\n\n",
    ],
)
def test_exact_source_adoption_rejects_any_extra_or_changed_content(
    root: Path, mutation: Any
) -> None:
    _, raw_specs, _, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = mutation(raw_specs["AIP-01"])
    entry = make_report(
        root,
        [row],
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )["entries"][0]
    assert entry["action"] == "blocked"
    assert "before" not in entry and "after" not in entry


def test_exact_source_adoption_rejects_duplicate_source(root: Path) -> None:
    _, raw_specs, _, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = raw_specs["AIP-01"] + "\n" + raw_specs["AIP-01"]
    entry = make_report(
        root,
        [row],
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )["entries"][0]
    assert entry["reason"] == "Exact-source adoption requires exactly one raw source occurrence"


@pytest.mark.parametrize("marker", [BEGIN, END, BEGIN + "\npartial"])
def test_exact_source_adoption_rejects_partial_markers(root: Path, marker: str) -> None:
    _, raw_specs, _, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = raw_specs["AIP-01"] + "\n" + marker
    entry = make_report(
        root,
        [row],
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )["entries"][0]
    assert entry["action"] == "blocked"
    assert "Malformed" in entry["reason"]


def test_exact_source_adoption_preserves_existing_managed_behavior(root: Path) -> None:
    _, _, specs, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = specs["AIP-01"] + "\n"
    entry = make_report(
        root,
        [row],
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )["entries"][0]
    assert entry["action"] == "unchanged"
    assert entry["operation"] == "managed-section-reconciliation"


def test_exact_source_adoption_is_limited_to_explicit_selection(root: Path) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    second = copy.deepcopy(plan["items"][0])
    second["backlog_key"] = "SECOND-01"
    second["body_file"] = str(SPECS / "SECOND-01.md")
    plan["items"].append(second)
    (root / PLAN).write_text(yaml.safe_dump(plan))
    first_text = (root / SPECS / "AIP-01.md").read_text()
    (root / SPECS / "SECOND-01.md").write_text(first_text.replace("AIP-01", "SECOND-01"))
    _, raw_specs, _, _ = load_sources(root)
    other = remote()
    other["item_id"] = "ITEM-2"
    other["content"]["id"] = "CONTENT-2"
    other["fields"]["Backlog Key"] = "SECOND-01"
    other["content"]["body"] = raw_specs["SECOND-01"]
    first = remote()
    first["content"]["body"] = raw_specs["AIP-01"]
    report = make_report(
        root,
        [first, other],
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )
    assert [entry["key"] for entry in report["entries"]] == ["AIP-01"]
    fake = FakeGitHub([first, other])
    with pytest.raises(ValueError, match="exactly match"):
        apply_report(root, report, ["AIP-01", "SECOND-01"], fake)
    assert fake.writes == []


@pytest.mark.parametrize("change", ["source", "policy", "remote", "race"])
def test_exact_source_adoption_rechecks_all_authority_before_write(root: Path, change: str) -> None:
    _, raw_specs, _, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = raw_specs["AIP-01"]
    fake = FakeGitHub([row])
    report = make_report(
        root,
        fake.snapshot(2),
        selected_keys={"AIP-01"},
        exact_source_adoption=True,
    )
    if change in {"source", "policy"}:
        path = root / SPECS / ("AIP-01.md" if change == "source" else "_ACCEPTANCE-POLICY.md")
        path.write_text(path.read_text() + "\nchanged")
    elif change == "remote":
        fake.rows[0]["content"]["body"] += " changed"
    else:
        fake.race = True
    with pytest.raises(ValueError):
        apply_report(root, report, ["AIP-01"], fake)
    assert fake.writes == []


def test_exact_source_dry_run_never_writes(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, raw_specs, _, _ = load_sources(root)
    row = remote()
    row["content"]["body"] = raw_specs["AIP-01"]
    fake = FakeGitHub([row])
    monkeypatch.setattr("smf.engineering_agent.acceptance_sync.GitHub", lambda: fake)
    assert (
        main(
            [
                "dry-run",
                "--repo-root",
                str(root),
                "--exact-source-adoption",
                "--key",
                "AIP-01",
            ]
        )
        == 0
    )
    assert fake.writes == []
    saved = json.loads(next((root / AUDIT).glob("dry-run-*.json")).read_text())
    assert saved["selected_keys"] == ["AIP-01"]


def test_exact_source_cli_requires_unique_selection(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeGitHub([remote()])
    monkeypatch.setattr("smf.engineering_agent.acceptance_sync.GitHub", lambda: fake)
    with pytest.raises(SystemExit):
        main(
            [
                "dry-run",
                "--repo-root",
                str(root),
                "--exact-source-adoption",
                "--key",
                "AIP-01",
                "--key",
                "AIP-01",
            ]
        )
    assert fake.writes == []


def test_replacement_preserves_prefix_and_suffix() -> None:
    body = f"prefix\n{BEGIN}\nold\n{END}\nsuffix"
    new = f"{BEGIN}\nnew\n{END}"
    assert replace_managed(body, new) == f"prefix\n{new}\nsuffix"


@pytest.mark.parametrize(
    "body", [BEGIN, END, END + BEGIN, BEGIN + END + BEGIN, "<!-- smf-acceptance:broken -->"]
)
def test_malformed_markers_fail_closed(body: str) -> None:
    with pytest.raises(ValueError):
        managed(body)


@pytest.mark.parametrize("change", ["local", "policy", "remote", "edited-report", "race"])
def test_stale_review_prevents_writes(root: Path, change: str) -> None:
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    if change in {"local", "policy"}:
        path = root / SPECS / ("AIP-01.md" if change == "local" else "_ACCEPTANCE-POLICY.md")
        path.write_text(path.read_text() + "\nchanged")
    elif change == "remote":
        fake.rows[0]["content"]["body"] += " changed"
    elif change == "race":
        fake.race = True
    else:
        report["entries"][0]["after"] = "unreviewed replacement"
    with pytest.raises(ValueError):
        apply_report(root, report, ["AIP-01"], fake)
    assert fake.writes == []


def test_partial_failure_retains_intent_without_false_verification(root: Path) -> None:
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    fake.tamper_readback = True
    with pytest.raises(ValueError, match="read-back mismatch"):
        apply_report(root, report, ["AIP-01"], fake)
    assert len(list((root / AUDIT).glob("*/AIP-01-intent.json"))) == 1
    assert not list((root / AUDIT).glob("*/AIP-01-verified.json"))


def test_no_implicit_bulk_apply(root: Path) -> None:
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    for keys in ([], ["AIP-01", "AIP-01"], ["MISSING-01"]):
        with pytest.raises(ValueError):
            apply_report(root, report, keys, fake)
    assert fake.writes == []


def test_blocked_record_cannot_be_applied(root: Path) -> None:
    row = remote()
    row["content"]["state"] = "CLOSED"
    fake = FakeGitHub([row])
    with pytest.raises(ValueError, match="blocked records"):
        apply_report(root, make_report(root, fake.snapshot(2)), ["AIP-01"], fake)
    assert fake.writes == []


def test_secret_body_is_not_exported(root: Path) -> None:
    row = remote()
    row["content"]["body"] = "DB_PASSWORD=synthetic-private-canary"
    report = make_report(root, [row])
    assert report["entries"][0]["action"] == "blocked"
    assert "synthetic-private-canary" not in json.dumps(report)


@pytest.mark.parametrize("change", ["duplicate", "path", "symlink", "owner", "missing-id"])
def test_invalid_local_sources_fail_closed(root: Path, change: str) -> None:
    plan = yaml.safe_load((root / PLAN).read_text())
    if change == "duplicate":
        plan["items"].append(plan["items"][0])
    elif change == "path":
        plan["items"][0]["body_file"] = "../escape.md"
    elif change == "owner":
        plan["project"]["owner"] = "different-owner"
    else:
        path = root / SPECS / "AIP-01.md"
        if change == "symlink":
            path.unlink()
            path.symlink_to(root / SPECS / "_ACCEPTANCE-POLICY.md")
        else:
            path.write_text("# AIP-01 - missing acceptance")
    (root / PLAN).write_text(yaml.safe_dump(plan))
    with pytest.raises(ValueError):
        load_specs(root)


def test_launch_requires_current_live_full_spec_and_policy(root: Path) -> None:
    _, specs = load_specs(root)
    for body, offline in [("old text", False), (specs["AIP-01"], True)]:
        with pytest.raises(ValueError):
            require_current_acceptance(root, "AIP-01", body, offline=offline)
    require_current_acceptance(root, "AIP-01", specs["AIP-01"], offline=False)
    (root / SPECS / "_ACCEPTANCE-POLICY.md").write_text("Changed policy")
    with pytest.raises(ValueError):
        require_current_acceptance(root, "AIP-01", specs["AIP-01"], offline=False)


def test_field_pagination_is_not_silently_truncated() -> None:
    with pytest.raises(ValueError, match="pagination"):
        map_node({"fieldValues": {"pageInfo": {"hasNextPage": True}}})


def test_source_hash_covers_complete_published_contract(root: Path) -> None:
    _, specs = load_specs(root)
    entry = make_report(root, [remote()])["entries"][0]
    assert entry["source_hash"] == digest(specs["AIP-01"])
    assert managed(entry["after"]) == specs["AIP-01"]


def test_replan_change_invalidates_review(root: Path) -> None:
    fake = FakeGitHub([remote()])
    report = make_report(root, fake.snapshot(2))
    plan = yaml.safe_load((root / PLAN).read_text())
    plan["items"][0]["competition_horizon"] = "P1"
    (root / PLAN).write_text(yaml.safe_dump(plan))
    with pytest.raises(ValueError, match="Replan changed"):
        apply_report(root, report, ["AIP-01"], fake)
    assert fake.writes == []


def test_empty_shared_policy_blocks_publication(root: Path) -> None:
    (root / SPECS / "_ACCEPTANCE-POLICY.md").write_text("")
    with pytest.raises(ValueError, match="empty"):
        load_specs(root)


@pytest.mark.parametrize("name", ["AIP-01.md", "_ACCEPTANCE-POLICY.md"])
def test_reviewed_sources_reject_terminal_whitespace_beyond_one_lf(root: Path, name: str) -> None:
    path = root / SPECS / name
    path.write_text(path.read_text() + " ")
    with pytest.raises(ValueError, match="terminal whitespace"):
        load_specs(root)


@pytest.mark.parametrize("name", ["AIP-01.md", "_ACCEPTANCE-POLICY.md"])
def test_reviewed_sources_reject_reserved_fingerprint_markers(root: Path, name: str) -> None:
    path = root / SPECS / name
    path.write_text(path.read_text() + f"\n{FINGERPRINT_PREFIX}{'0' * 64} -->")
    with pytest.raises(ValueError, match="reserved acceptance marker"):
        load_specs(root)


@pytest.mark.parametrize("name", ["AIP-01.md", "_ACCEPTANCE-POLICY.md"])
def test_reviewed_sources_reject_crlf_without_normalization(root: Path, name: str) -> None:
    path = root / SPECS / name
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b"\n", b"\r\n") if b"\n" in raw else raw + b"\r\nextra")
    with pytest.raises(ValueError, match="carriage-return"):
        load_specs(root)


def test_report_files_are_private(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGitHub([remote()])
    monkeypatch.setattr("smf.engineering_agent.acceptance_sync.GitHub", lambda: fake)
    assert main(["--repo-root", str(root)]) == 0
    for path in (root / AUDIT).glob("dry-run-*"):
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "text",
    [
        "DB_PASSWORD=synthetic-secret-canary",
        "Authorization: Bearer synthetic-long-token",
        "AccountKey=synthetic-azure-secret",
        "https://user:synthetic-password@example.invalid",
        "https://example.invalid?sig=synthetic-signature",
        # Construct the header-only canary without embedding a key marker in source.
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
def test_publication_lint_rejects_explicit_credentials(root: Path, text: str) -> None:
    row = remote()
    row["content"]["body"] = text
    entry = make_report(root, [row])["entries"][0]
    assert entry["action"] == "blocked"
    assert "before" not in entry and "after" not in entry


def test_security_prose_is_not_a_credential(root: Path) -> None:
    row = remote()
    row["content"]["body"] = "Enterprise authentication model and authorization requirements"
    assert make_report(root, [row])["entries"][0]["action"] == "update"


@pytest.mark.parametrize("kind", ["Issue", "DraftIssue"])
def test_transport_only_updates_body(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any], str]] = []
    client = GitHub()

    def api(endpoint: str, payload: dict[str, Any], method: str = "POST") -> dict[str, Any]:
        calls.append((endpoint, payload, method))
        return {}

    monkeypatch.setattr(client, "api", api)
    client.update(remote(kind), "approved body", "owner/repo")
    assert len(calls) == 1
    endpoint, payload, method = calls[0]
    if kind == "Issue":
        assert endpoint == "repos/owner/repo/issues/93"
        assert method == "PATCH" and payload == {"body": "approved body"}
    else:
        assert endpoint == "graphql"
        assert payload["variables"] == {"id": "CONTENT", "body": "approved body"}
        assert "updateProjectV2DraftIssue" in payload["query"]
        assert "title:" not in payload["query"]


@pytest.mark.parametrize("command", ["command_work", "command_continue"])
def test_cli_blocks_stale_acceptance_before_worktree_or_run(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    from smf.engineering_agent import cli
    from smf.engineering_agent.models import BacklogItem

    item = BacklogItem(
        "AIP-01",
        "Interface",
        "Feature",
        "P0",
        "",
        "In Progress",
        "Partial",
        issue_number=93,
        issue_body="old body",
    )
    monkeypatch.setattr(cli, "_root", lambda: root)
    monkeypatch.setattr(cli, "_items", lambda *_: (item,))
    monkeypatch.setattr(cli, "_assessment", lambda *_: Namespace(blockers=[]))

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Runner or prior-run lookup was reached with stale acceptance")

    monkeypatch.setattr(cli, "execute_supervised_run", forbidden)
    monkeypatch.setattr(cli, "latest_stopped_run", forbidden)
    with pytest.raises(SystemExit, match="missing or stale"):
        getattr(cli, command)(Namespace(key="AIP-01", offline=False))


def test_ignore_exceptions_expose_only_intended_documents(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    (tmp_path / ".gitignore").write_text((repo / ".gitignore").read_text())
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    visible = [
        "competition/generated/replan.yaml",
        "competition/generated/issue-specs/AIP-01.md",
        "competition/generated/REPLAN-REPORT.md",
    ]
    ignored = [
        "competition/generated/runtime.json",
        "competition/generated/issue-specs/secret.csv",
        "other/generated/output.md",
        ".project-audit/report.json",
    ]
    for name in visible + ignored:
        result = subprocess.run(["git", "check-ignore", "-q", name], cwd=tmp_path, check=False)
        assert result.returncode == (0 if name in ignored else 1), name
