"""Deterministic whole-candidate manifests for independent protected review."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, cast

from smf.readiness.policy import digest_value


def _changed_paths(root: Path) -> list[tuple[str, str]]:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    fields = completed.stdout.decode("utf-8").split("\0")
    paths: list[tuple[str, str]] = []
    index = 0
    while index < len(fields) and fields[index]:
        record = fields[index]
        status, path = record[:2], record[3:]
        if "R" in status or "C" in status:
            index += 1
            path = fields[index]
        paths.append((status, path))
        index += 1
    return paths


def candidate_manifest(
    root: Path, *, manifest_path: str = "docs/architecture/DBX-03_CANDIDATE_MANIFEST.json"
) -> dict[str, Any]:
    """Describe every changed candidate byte except the necessarily self-excluded manifest."""

    files: list[dict[str, str]] = []
    for status, relative in _changed_paths(root):
        if relative == manifest_path:
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Candidate manifest only accepts regular files: {relative}")
        files.append(
            {
                "path": relative,
                "status": status,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    files.sort(key=lambda item: item["path"])
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    governed = {"base_revision": base, "files": files}
    return {
        "schema_version": "1.0",
        "backlog_key": "DBX-03",
        "review_status": "pending_independent_protected_review",
        "uncommitted_candidate": True,
        "manifest_path": manifest_path,
        "manifest_self_excluded": True,
        **governed,
        "candidate_fingerprint": digest_value(governed),
    }


def _committed_candidate_manifest(
    root: Path, recorded: dict[str, Any], *, manifest_path: str
) -> dict[str, Any]:
    """Reconstruct the immutable commit that last published the manifest.

    A candidate manifest is generated while the complete candidate is staged, so
    committing it necessarily makes ``git status`` clean.  In that state, bind
    verification to the latest committed revision that changed the manifest and
    read every governed byte from that revision.  Later unrelated commits cannot
    silently expand or alter the reviewed candidate.
    """

    if _changed_paths(root):
        raise ValueError("Committed candidate verification requires a clean working tree")
    base = recorded.get("base_revision")
    if not isinstance(base, str) or len(base) != 40:
        raise ValueError("Candidate manifest has an invalid base revision")
    revision = subprocess.run(
        ["git", "log", "-1", "--format=%H", "HEAD", "--", manifest_path],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not revision:
        raise ValueError("Candidate manifest is not bound to a committed revision")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, revision],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if ancestry.returncode != 0:
        raise ValueError("Candidate base is not an ancestor of the reviewed revision")

    completed = subprocess.run(
        ["git", "diff", "--name-status", "-z", base, revision, "--"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    fields = completed.stdout.decode("utf-8").split("\0")
    files: list[dict[str, str]] = []
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index]
        index += 1
        if status.startswith(("R", "C")):
            raise ValueError("Candidate manifest does not permit renamed or copied paths")
        relative = fields[index]
        index += 1
        if relative == manifest_path:
            continue
        if status not in {"A", "M"}:
            raise ValueError(f"Candidate manifest does not permit status {status}: {relative}")
        blob = subprocess.run(
            ["git", "show", f"{revision}:{relative}"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        files.append(
            {
                "path": relative,
                "status": f"{status} ",
                "sha256": hashlib.sha256(blob).hexdigest(),
            }
        )
    files.sort(key=lambda item: item["path"])
    governed = {"base_revision": base, "files": files}
    return {
        "schema_version": "1.0",
        "backlog_key": "DBX-03",
        "review_status": "pending_independent_protected_review",
        "uncommitted_candidate": True,
        "manifest_path": manifest_path,
        "manifest_self_excluded": True,
        **governed,
        "candidate_fingerprint": digest_value(governed),
    }


def verify_candidate_manifest(root: Path, path: Path) -> dict[str, Any]:
    """Recompute and compare the exact current candidate manifest."""

    recorded = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    manifest_path = path.relative_to(root).as_posix()
    expected = candidate_manifest(root, manifest_path=manifest_path)
    if recorded == expected:
        return recorded
    expected = _committed_candidate_manifest(root, recorded, manifest_path=manifest_path)
    if recorded != expected:
        raise ValueError("DBX-03 candidate manifest does not match the complete working tree")
    return recorded
