"""Workload-isolated publication for qualified static code-dependency evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, replace
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlparse

from smf.discovery.code_dependency_analysis import derive_code_dependency_analysis
from smf.immutable_files import ensure_directory
from smf.immutable_files import publish_json as _secure_publish_json
from smf.immutable_files import published_file_exists as _secure_published_file_exists
from smf.immutable_files import read_published_json as _secure_read_published_json
from smf.workload.identity import stable_id
from smf.workload.models import ArtifactKind, Workload
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ELIGIBLE_KINDS = {
    ArtifactKind.SAS_PROGRAM,
    ArtifactKind.SAS_MACRO,
    ArtifactKind.SAS_INCLUDE,
}


def _component(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    return value


def _source_path(root: Path, logical_path: str) -> Path:
    if not logical_path or urlparse(logical_path).scheme:
        raise ValueError("Unsafe code dependency source reference")
    decoded = logical_path
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    relative = Path(decoded)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Unsafe code dependency source reference")
    resolved_root = root.resolve()
    candidate = root / relative
    if any(
        root.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ):
        raise ValueError("Code dependency source is symlink-mediated")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("Code dependency source escapes or is missing")
    return resolved


def reverify_code_dependency_sources(workload: Workload, source_root: Path) -> None:
    analysis = workload.code_dependency_analysis
    if analysis is None:
        raise ValueError("Code dependency analysis is required")
    for item in analysis.inventory:
        data = _source_path(source_root, item.logical_path).read_bytes()
        if len(data) != item.size_bytes or hashlib.sha256(data).hexdigest() != item.checksum:
            raise ValueError("Qualified code dependency source bytes changed")


def qualify_code_dependencies(
    workload: Workload,
    *,
    source_root: Path,
    client_id: str,
    subject_id: str,
    run_id: str,
    attempt_id: str,
    execution_id: str,
) -> dict[str, object]:
    """Bind a derived analysis to an exact subject and execution identity."""

    for value, label in (
        (client_id, "client_id"),
        (workload.workload_id, "workload_id"),
        (subject_id, "subject_id"),
        (run_id, "run_id"),
        (attempt_id, "attempt_id"),
        (execution_id, "execution_id"),
    ):
        _component(value, label)
    supplied_analysis = workload.code_dependency_analysis
    if supplied_analysis is None or supplied_analysis.workload_id != workload.workload_id:
        raise ValueError("Code dependency analysis is missing or workload-unbound")
    derived_workload = derive_code_dependency_analysis(
        replace(workload, code_dependency_analysis=None)
    )
    analysis = derived_workload.code_dependency_analysis
    if analysis is None or supplied_analysis != analysis:
        raise ValueError("Code dependency analysis does not replay from discovery evidence")
    matches = [
        item
        for item in analysis.inventory
        if item.artifact_id == subject_id and item.kind in _ELIGIBLE_KINDS
    ]
    if len(matches) != 1:
        raise ValueError("Subject must identify exactly one eligible SAS artifact")
    reverify_code_dependency_sources(derived_workload, source_root)
    blocker_ids = tuple(item.blocker_id for item in analysis.blockers)
    disposition = (
        "qualified"
        if analysis.analysis_complete and analysis.ordering_eligible and not blocker_ids
        else "blocked"
    )
    identity = {
        "client_id": client_id,
        "workload_id": workload.workload_id,
        "subject_id": subject_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "execution_id": execution_id,
        "analysis_id": analysis.analysis_id,
        "source_closure_digest": analysis.source_closure_digest,
        "policy_digest": analysis.policy_digest,
        "disposition": disposition,
        "blocker_ids": blocker_ids,
    }
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "qualification_id": stable_id("CODEQUAL", identity),
        **identity,
        "analysis": asdict(analysis),
        "disposition": disposition,
        "blocker_ids": blocker_ids,
        "claims": {
            "code_analyzed": True,
            "analysis_complete": analysis.analysis_complete,
            "ordering_eligible": analysis.ordering_eligible,
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_assisted": False,
            "human_approved": False,
        },
    }
    sanitized = sanitize_discovery_value(payload)
    if not isinstance(sanitized, dict):
        raise ValueError("Invalid code dependency qualification payload")
    return sanitized


def code_dependency_result_path(output_root: Path, payload: dict[str, object]) -> Path:
    return (
        output_root
        / "runs"
        / _component(str(payload["run_id"]), "run_id")
        / "workloads"
        / _component(str(payload["workload_id"]), "workload_id")
        / "attempts"
        / _component(str(payload["attempt_id"]), "attempt_id")
        / "code-dependencies"
        / _component(str(payload["subject_id"]), "subject_id")
        / "result.json"
    )


def _published_file_exists(path: Path, *, root: Path, label: str) -> bool:
    try:
        return _secure_published_file_exists(path, root=root, label=label)
    except ValueError as exc:
        raise ValueError(f"Code dependency evidence path is unsafe: {path}") from exc


def _read_published_json(path: Path, *, root: Path, label: str) -> object:
    try:
        return _secure_read_published_json(path, root=root, label=label)
    except ValueError as exc:
        raise ValueError(f"Code dependency evidence path is unsafe: {path}") from exc


def _publish_json(path: Path, payload: dict[str, object], label: str, *, root: Path) -> None:
    try:
        _secure_publish_json(path, payload, label, root=root)
    except ValueError as exc:
        raise ValueError(f"Code dependency evidence path is unsafe: {path}") from exc


def _verify_canonical_bindings(
    canonical: object,
    supplied: dict[str, object],
    *,
    workload: Workload,
    path: Path,
    root: Path,
) -> dict[str, object]:
    if not isinstance(canonical, dict) or canonical != supplied:
        raise FileExistsError(f"Code dependency decision already exists: {path}")
    if code_dependency_result_path(root, canonical) != path:
        raise ValueError("Code dependency evidence identity does not match its canonical path")
    analysis = workload.code_dependency_analysis
    if analysis is None or canonical.get("analysis") != json.loads(
        json.dumps(asdict(analysis), sort_keys=True)
    ):
        raise ValueError("Code dependency evidence is not bound to the workload analysis")
    if canonical.get("workload_id") != workload.workload_id:
        raise ValueError("Code dependency evidence is not bound to the workload")
    matching_subjects = [
        item
        for item in analysis.inventory
        if item.artifact_id == canonical.get("subject_id") and item.kind in _ELIGIBLE_KINDS
    ]
    if len(matching_subjects) != 1:
        raise ValueError("Code dependency evidence is not bound to an eligible subject")
    stored_analysis = canonical["analysis"]
    assert isinstance(stored_analysis, dict)
    for key in ("workload_id", "analysis_id", "source_closure_digest", "policy_digest"):
        if canonical.get(key) != stored_analysis.get(key):
            raise ValueError(f"Code dependency evidence has inconsistent {key}")
    blocker_ids = [item.blocker_id for item in analysis.blockers]
    disposition = (
        "qualified"
        if analysis.analysis_complete and analysis.ordering_eligible and not blocker_ids
        else "blocked"
    )
    if canonical.get("blocker_ids") != blocker_ids or canonical.get("disposition") != disposition:
        raise ValueError("Code dependency evidence has inconsistent disposition")
    expected_claims = {
        "code_analyzed": True,
        "analysis_complete": analysis.analysis_complete,
        "ordering_eligible": analysis.ordering_eligible,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "human_approved": False,
    }
    if canonical.get("schema_version") != "1.0" or canonical.get("claims") != expected_claims:
        raise ValueError("Code dependency evidence has invalid canonical claims")
    identity = {
        key: canonical.get(key)
        for key in (
            "client_id",
            "workload_id",
            "subject_id",
            "run_id",
            "attempt_id",
            "execution_id",
            "analysis_id",
            "source_closure_digest",
            "policy_digest",
            "disposition",
            "blocker_ids",
        )
    }
    if canonical.get("qualification_id") != stable_id("CODEQUAL", identity):
        raise ValueError("Code dependency qualification identity is inconsistent")
    return canonical


def _telemetry(payload: dict[str, object]) -> dict[str, object]:
    analysis = payload["analysis"]
    assert isinstance(analysis, dict)
    occurrences = analysis["occurrences"]
    groups = analysis["ordering_groups"]
    assert isinstance(occurrences, list)
    assert isinstance(groups, list)
    claims = cast(dict[str, object], payload["claims"])
    return {
        "qualification_id": payload["qualification_id"],
        "client_id": payload["client_id"],
        "workload_id": payload["workload_id"],
        "subject_id": payload["subject_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "execution_id": payload["execution_id"],
        "analysis_id": payload["analysis_id"],
        "source_closure_digest": payload["source_closure_digest"],
        "policy_digest": payload["policy_digest"],
        "resolved_edge_count": sum(item["resolution"] == "resolved" for item in occurrences),
        "unresolved_code_count": sum(item["resolution"] != "resolved" for item in occurrences),
        "cyclic_group_count": sum(bool(item["cyclic"]) for item in groups),
        "blocked": payload["disposition"] == "blocked",
        "pending_human_selection": False,
        **claims,
    }


def write_code_dependency_result(
    output_root: Path,
    payload: dict[str, object],
    *,
    workload: Workload,
    source_root: Path,
) -> Path:
    """Publish canonical evidence first and recover telemetry idempotently."""

    bindings: dict[str, str] = {}
    for key in (
        "client_id",
        "subject_id",
        "run_id",
        "attempt_id",
        "execution_id",
    ):
        value = payload.get(key)
        if not isinstance(value, str):
            raise ValueError(f"Code dependency result has invalid {key}")
        bindings[key] = value
    relative_path = code_dependency_result_path(Path(), payload)
    root = Path(os.path.abspath(os.fspath(output_root)))
    path = root / relative_path
    ensure_directory(path.parent, root=root)
    normalized_payload = json.loads(json.dumps(payload, sort_keys=True))
    if _published_file_exists(path, root=root, label="code dependency evidence"):
        canonical = _verify_canonical_bindings(
            _read_published_json(path, root=root, label="code dependency evidence"),
            normalized_payload,
            workload=workload,
            path=path,
            root=root,
        )
        _publish_json(
            path.with_name("telemetry.json"),
            _telemetry(canonical),
            "code dependency telemetry",
            root=root,
        )
        return code_dependency_result_path(output_root, payload)

    expected = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id=bindings["client_id"],
        subject_id=bindings["subject_id"],
        run_id=bindings["run_id"],
        attempt_id=bindings["attempt_id"],
        execution_id=bindings["execution_id"],
    )
    normalized_expected = json.loads(json.dumps(expected, sort_keys=True))
    if normalized_payload != normalized_expected:
        raise ValueError("Code dependency result does not replay from canonical evidence")
    _publish_json(path, payload, "code dependency evidence", root=root)
    canonical = _verify_canonical_bindings(
        _read_published_json(path, root=root, label="code dependency evidence"),
        normalized_expected,
        workload=workload,
        path=path,
        root=root,
    )
    _publish_json(
        path.with_name("telemetry.json"),
        _telemetry(canonical),
        "code dependency telemetry",
        root=root,
    )
    return code_dependency_result_path(output_root, payload)
