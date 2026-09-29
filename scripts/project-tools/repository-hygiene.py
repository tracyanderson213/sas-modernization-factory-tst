#!/usr/bin/env python3
"""Inventory and conservatively assess SMF branches and worktrees.

The inventory path is read-only with respect to Git and GitHub. It writes only the requested
manifest. Cleanup is deliberately not implemented here: removals remain explicit, individually
reviewed Git commands backed by the manifest.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from smf.engineering_agent.policy import forbidden_developer_changes


def _run(args: list[str], *, cwd: Path, check: bool = True) -> str:
    completed = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n{completed.stderr}"
        )
    return completed.stdout


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return _run(["git", *args], cwd=repo, check=check)


def _reachable(repo: Path, commit: str, main: str) -> bool | None:
    for candidate in (commit, main):
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{candidate}^{{commit}}"], cwd=repo, capture_output=True
        )
        if exists.returncode != 0:
            return None
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, main], cwd=repo, capture_output=True
    )
    return result.returncode == 0


def _unique_commits(repo: Path, ref: str, main: str) -> list[str] | None:
    for candidate in (ref, main):
        exists = subprocess.run(
            ["git", "cat-file", "-e", f"{candidate}^{{commit}}"], cwd=repo, capture_output=True
        )
        if exists.returncode != 0:
            return None
    return [line for line in _git(repo, "rev-list", "--reverse", f"{main}..{ref}").splitlines()]


def _ahead_behind(repo: Path, ref: str, main: str) -> dict[str, int] | None:
    if _reachable(repo, ref, main) is None:
        return None
    left, right = _git(repo, "rev-list", "--left-right", "--count", f"{main}...{ref}").split()
    return {"behind_origin_main": int(left), "ahead_of_origin_main": int(right)}


def _worktrees(repo: Path) -> list[dict[str, Any]]:
    raw = _git(repo, "worktree", "list", "--porcelain", "-z")
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for field in raw.split("\0"):
        if not field:
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = field.partition(" ")
        if key in {"bare", "detached", "locked", "prunable"}:
            current[key] = value or True
        else:
            current[key] = value
    if current:
        records.append(current)
    return records


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _associated_keys(*values: str, keys: set[str]) -> list[str]:
    haystack = "-".join(_normalize(value) for value in values if value)
    matches = []
    for key in keys:
        token = _normalize(key)
        if re.search(rf"(?:^|-){re.escape(token)}(?:-|$)", haystack):
            matches.append(key)
    return sorted(matches)


def _project_state(repo: Path) -> tuple[dict[str, dict[str, Any]], dict[int, str]]:
    project = json.loads(
        _run(
            [
                "gh",
                "project",
                "item-list",
                "2",
                "--owner",
                "@me",
                "--format",
                "json",
                "--limit",
                "1000",
            ],
            cwd=repo,
        )
    )
    issue_states: dict[int, str] = {}
    issues = json.loads(
        _run(
            [
                "gh",
                "api",
                "--paginate",
                "--slurp",
                "-X",
                "GET",
                "repos/tbarry3c/sas-modernization-factory/issues",
                "-f",
                "state=all",
                "-f",
                "per_page=100",
            ],
            cwd=repo,
        )
    )
    if isinstance(issues, list):
        for page in issues:
            for issue in page if isinstance(page, list) else []:
                if isinstance(issue, dict) and "pull_request" not in issue:
                    issue_states[int(issue["number"])] = str(issue["state"])

    result: dict[str, dict[str, Any]] = {}
    for item in project["items"]:
        key = item.get("backlog Key")
        if not key:
            continue
        content = item.get("content") or {}
        number = content.get("number")
        result[key] = {
            "status": item.get("status"),
            "implementation_state": item.get("implementation State"),
            "content_type": content.get("type"),
            "number": number,
            "issue_state": issue_states.get(number) if isinstance(number, int) else None,
            "title": content.get("title") or item.get("title"),
        }
    return result, issue_states


def _pull_requests(repo: Path) -> list[dict[str, Any]]:
    return json.loads(
        _run(
            [
                "gh",
                "pr",
                "list",
                "--state",
                "all",
                "--limit",
                "1000",
                "--json",
                "number,state,title,headRefName,baseRefName,headRefOid,mergeCommit,mergedAt,closedAt,url,isDraft",
            ],
            cwd=repo,
        )
    )


def _canonical_complete(keys: list[str], project: dict[str, dict[str, Any]]) -> bool:
    if len(keys) != 1:
        return False
    item = project.get(keys[0], {})
    return (
        item.get("status") == "Done"
        and item.get("implementation_state") == "Foundation Complete"
        and item.get("issue_state") == "closed"
    )


def _standalone_repositories(
    scan_root: Path,
    primary_repo: Path,
    origin_main: str,
    project: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    primary_common = Path(_git(primary_repo, "rev-parse", "--git-common-dir").strip())
    if not primary_common.is_absolute():
        primary_common = (primary_repo / primary_common).resolve()
    keys = set(project)
    repositories: list[dict[str, Any]] = []
    for git_dir in sorted(scan_root.glob("smf-*/.git")) + sorted(scan_root.glob("smf-*/*/.git")):
        root = git_dir.parent.resolve()
        remote = _git(root, "remote", "get-url", "origin", check=False).strip()
        if "tbarry3c/sas-modernization-factory" not in remote:
            continue
        common = Path(_git(root, "rev-parse", "--git-common-dir").strip())
        if not common.is_absolute():
            common = (root / common).resolve()
        if common == primary_common:
            continue
        head = _git(root, "rev-parse", "HEAD").strip()
        branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False).strip()
        status = _git(root, "status", "--porcelain=v1", "-uall").splitlines()
        ignored_files = [
            line
            for line in _git(root, "status", "--ignored", "--porcelain=v1", "-uall").splitlines()
            if line.startswith("!! ")
        ]
        evidence_paths = []
        for relative in (".smf-agent", ".project-audit"):
            candidate = root / relative
            if candidate.is_dir() and any(item.is_file() for item in candidate.rglob("*")):
                evidence_paths.append(relative)
        subject = _git(root, "show", "-s", "--format=%s", head).strip()
        associated = _associated_keys(root.name, branch, subject, keys=keys)
        reachable = _reachable(root, head, origin_main)
        unique = _unique_commits(root, head, origin_main)
        branches = []
        raw = _git(root, "for-each-ref", "--format=%(refname:short)%00%(objectname)", "refs/heads")
        for line in raw.splitlines():
            name, commit = line.split("\0")
            branches.append(
                {
                    "name": name,
                    "commit": commit,
                    "reachable_from_origin_main": _reachable(root, commit, origin_main),
                    "unique_commits": _unique_commits(root, commit, origin_main),
                }
            )
        if status:
            disposition = "preserve_dirty"
        elif ignored_files:
            disposition = "preserve_ignored_untracked"
        elif evidence_paths:
            disposition = "preserve_evidence_bearing"
        elif reachable is not True or unique:
            disposition = "preserve_unique_or_unavailable_history"
        elif not _canonical_complete(associated, project):
            disposition = "preserve_incomplete_or_ambiguous_record"
        else:
            disposition = "safe_remove_candidate_after_manual_clone_review"
        repositories.append(
            {
                "path": str(root),
                "git_common_dir": str(common),
                "head": head,
                "branch": branch or None,
                "detached": not bool(branch),
                "dirty_files": status,
                "ignored_files": ignored_files,
                "evidence_paths": evidence_paths,
                "associated_backlog_records": associated,
                "canonical_complete": _canonical_complete(associated, project),
                "head_reachable_from_origin_main": reachable,
                "ahead_behind": _ahead_behind(root, head, origin_main),
                "unique_commits": unique,
                "local_branches": branches,
                "recommended_disposition": disposition,
            }
        )
    return repositories


def _status_path(line: str) -> str:
    return line[3:].split(" -> ", 1)[-1]


def _ownership_paths_overlap(left: str, right: str) -> bool:
    """Return whether two literal, directory, or glob ownership scopes can intersect."""

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


def _ownership_findings(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"available": False, "duplicate_work_ids": [], "overlapping_paths": []}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    work_ids: set[str] = set()
    duplicates: list[str] = []
    paths: list[tuple[str, str]] = []
    overlaps: list[dict[str, str]] = []
    for assignment in data.get("assignments", []):
        work_id = assignment["work_id"]
        if work_id in work_ids:
            duplicates.append(work_id)
        work_ids.add(work_id)
        for owned in assignment.get("files", []):
            for other_work, other in paths:
                if _ownership_paths_overlap(owned, other):
                    overlaps.append(
                        {
                            "work_id": work_id,
                            "path": owned,
                            "conflicts_with": other_work,
                            "conflicting_path": other,
                        }
                    )
            paths.append((work_id, owned))
    return {
        "available": True,
        "duplicate_work_ids": sorted(set(duplicates)),
        "overlapping_paths": overlaps,
    }


def build_manifest(
    repo: Path, scan_root: Path | None = None, ownership_path: Path | None = None
) -> dict[str, Any]:
    repo = repo.resolve()
    origin_main = _git(repo, "rev-parse", "origin/main").strip()
    remote_main = _git(repo, "ls-remote", "origin", "refs/heads/main").split()[0]
    project, _ = _project_state(repo)
    keys = set(project)
    prs = _pull_requests(repo)
    prs_by_head: dict[str, list[dict[str, Any]]] = {}
    for pr in prs:
        prs_by_head.setdefault(pr["headRefName"], []).append(pr)

    worktrees: list[dict[str, Any]] = []
    for record in _worktrees(repo):
        path = Path(record["worktree"])
        head = record.get("HEAD") or _git(path, "rev-parse", "HEAD").strip()
        branch_ref = record.get("branch")
        branch = branch_ref.removeprefix("refs/heads/") if branch_ref else None
        status_lines = _git(path, "status", "--porcelain=v1", "-uall").splitlines()
        ignored_files = [
            line
            for line in _git(path, "status", "--ignored", "--porcelain=v1", "-uall").splitlines()
            if line.startswith("!! ")
        ]
        evidence_paths = []
        for relative in (".smf-agent", ".project-audit"):
            candidate = path / relative
            if candidate.is_dir() and any(item.is_file() for item in candidate.rglob("*")):
                evidence_paths.append(relative)
        subject = _git(path, "show", "-s", "--format=%s", head).strip()
        associated = _associated_keys(path.name, branch or "", subject, keys=keys)
        head_reachable = _reachable(repo, head, origin_main)
        pr_records = prs_by_head.get(branch or "", [])
        open_prs = [pr["number"] for pr in pr_records if pr["state"] == "OPEN"]
        complete = _canonical_complete(associated, project)
        if status_lines:
            disposition = "preserve_dirty"
        elif ignored_files:
            disposition = "preserve_ignored_untracked"
        elif evidence_paths:
            disposition = "preserve_evidence_bearing"
        elif open_prs:
            disposition = "preserve_open_pr"
        elif head_reachable is not True:
            disposition = "preserve_unique_or_unavailable_history"
        elif not complete:
            disposition = "preserve_incomplete_or_ambiguous_record"
        else:
            disposition = "safe_remove_candidate"
        worktrees.append(
            {
                "path": str(path),
                "head": head,
                "branch": branch,
                "detached": bool(record.get("detached")),
                "locked": record.get("locked", False),
                "prunable": record.get("prunable", False),
                "dirty_files": status_lines,
                "ignored_files": ignored_files,
                "evidence_paths": evidence_paths,
                "associated_backlog_records": associated,
                "canonical_complete": complete,
                "head_reachable_from_origin_main": head_reachable,
                "open_prs": open_prs,
                "recommended_disposition": disposition,
            }
        )

    local_branches = []
    raw_local = _git(
        repo,
        "for-each-ref",
        "--format=%(refname:short)%00%(objectname)%00%(upstream:short)",
        "refs/heads",
    )
    worktree_by_branch = {item["branch"]: item for item in worktrees if item["branch"]}
    for line in raw_local.splitlines():
        branch, commit, upstream = line.split("\0")
        subject = _git(repo, "show", "-s", "--format=%s", commit).strip()
        associated = _associated_keys(branch, subject, keys=keys)
        reachable = _reachable(repo, commit, origin_main)
        unique = _unique_commits(repo, branch, origin_main)
        pr_records = prs_by_head.get(branch, [])
        open_prs = [pr["number"] for pr in pr_records if pr["state"] == "OPEN"]
        worktree = worktree_by_branch.get(branch)
        complete = _canonical_complete(associated, project)
        if worktree:
            disposition = "preserve_until_worktree_disposition"
        elif open_prs:
            disposition = "preserve_open_pr"
        elif reachable is not True or unique:
            disposition = "preserve_unique_or_unavailable_history"
        elif not complete:
            disposition = "preserve_incomplete_or_ambiguous_record"
        else:
            disposition = "safe_delete_candidate_after_worktree"
        local_branches.append(
            {
                "name": branch,
                "commit": commit,
                "upstream": upstream or None,
                "associated_backlog_records": associated,
                "canonical_complete": complete,
                "reachable_from_origin_main": reachable,
                "ahead_behind": _ahead_behind(repo, branch, origin_main),
                "unique_commits": unique,
                "open_prs": open_prs,
                "recommended_disposition": disposition,
            }
        )

    remote_branches = []
    for line in _git(repo, "ls-remote", "--heads", "origin").splitlines():
        commit, ref = line.split()
        branch = ref.removeprefix("refs/heads/")
        subject = ""
        if _reachable(repo, commit, origin_main) is not None:
            subject = _git(repo, "show", "-s", "--format=%s", commit).strip()
        associated = _associated_keys(branch, subject, keys=keys)
        reachable = _reachable(repo, commit, origin_main)
        unique = _unique_commits(repo, commit, origin_main)
        pr_records = prs_by_head.get(branch, [])
        pr_terminal = bool(pr_records) and all(pr["state"] != "OPEN" for pr in pr_records)
        open_prs = [pr["number"] for pr in pr_records if pr["state"] == "OPEN"]
        if branch == "main":
            disposition = "preserve_canonical_main"
        elif open_prs:
            disposition = "preserve_open_pr"
        elif reachable is True and not unique and pr_terminal:
            disposition = "safe_delete_candidate"
        else:
            disposition = "preserve_unmerged_ambiguous_or_unreachable"
        remote_branches.append(
            {
                "name": branch,
                "commit": commit,
                "associated_backlog_records": associated,
                "reachable_from_origin_main": reachable,
                "unique_commits": unique,
                "pull_requests": [pr["number"] for pr in pr_records],
                "open_prs": open_prs,
                "pull_requests_terminal": pr_terminal,
                "recommended_disposition": disposition,
            }
        )

    standalone = (
        _standalone_repositories(scan_root.resolve(), repo, origin_main, project)
        if scan_root is not None
        else []
    )
    protected_dirty = []
    for item in worktrees:
        protected = forbidden_developer_changes(_status_path(line) for line in item["dirty_files"])
        if protected:
            protected_dirty.append({"worktree": item["path"], "paths": list(protected)})
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "repository": str(repo),
        "origin_main": origin_main,
        "remote_main": remote_main,
        "origin_main_matches_remote": origin_main == remote_main,
        "policy": {
            "cleanup_requires": [
                "clean worktree",
                "no unique or ignored evidence",
                "complete history reachable from origin/main",
                "canonical Issue closed and Project Done / Foundation Complete",
                "no open pull request",
            ],
            "default": "preserve on ambiguity",
        },
        "project_records": project,
        "pull_requests": prs,
        "worktrees": worktrees,
        "local_branches": local_branches,
        "remote_branches": remote_branches,
        "standalone_repositories": standalone,
        "hygiene_findings": {
            "stale_worktree_candidates": [
                item["path"]
                for item in worktrees
                if item["recommended_disposition"] == "safe_remove_candidate"
            ],
            "merged_local_branch_candidates": [
                item["name"]
                for item in local_branches
                if item["recommended_disposition"] == "safe_delete_candidate_after_worktree"
            ],
            "obsolete_revision_branches": [
                {"name": item["name"], **(item["ahead_behind"] or {})}
                for item in local_branches
                if item["ahead_behind"] and item["ahead_behind"]["behind_origin_main"] > 0
            ],
            "duplicate_active_ownership": _ownership_findings(ownership_path),
            "documentation_revision_drift_check": (
                "python scripts/check-documentation-consistency.py"
            ),
            "undocumented_cli_change_check": "docs/generated/cli-surface.json parity",
            "generated_plan_consistency_check": (
                "smf.engineering_agent.competition_plan.validate_plan"
            ),
            "dirty_protected_files": protected_dirty,
            "work_without_single_canonical_backlog_record": {
                "worktrees": [
                    item["path"]
                    for item in worktrees
                    if len(item["associated_backlog_records"]) != 1
                ],
                "local_branches": [
                    item["name"]
                    for item in local_branches
                    if len(item["associated_backlog_records"]) != 1
                ],
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scan-root", type=Path, default=None)
    parser.add_argument("--ownership", type=Path, default=None)
    args = parser.parse_args()
    manifest = build_manifest(args.repo, args.scan_root, args.ownership)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
