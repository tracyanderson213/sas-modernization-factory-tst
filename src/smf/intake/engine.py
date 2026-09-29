"""Deterministic evaluation of signed batch manifests into canonical workloads."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.discovery import discover_source
from smf.intake.policy import IntakePolicy, verify_intake_policy
from smf.intake.schema import validate_manifest, validate_result
from smf.readiness.policy import digest_value
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.models import ArtifactKind, DependencyDomain

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEANINGFUL_SAS = re.compile(
    r"(?is)(?:^|;)\s*(?:(?:data\s+[A-Za-z_%][\w.%]*|proc\s+[A-Za-z][\w]*)\b[^;]*;.*?(?:run|quit)\s*;|%macro\s+[A-Za-z_%][\w%]*\b.*?%mend\s*;)"
)
_KINDS = {item.value for item in ArtifactKind}


@dataclass(frozen=True)
class IntakeRequest:
    manifest: dict[str, Any]
    policy: IntakePolicy
    source_root: Path
    output_root: Path
    run_id: str
    attempt_id: str


def manifest_digest(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("manifest_digest", None)
    unsigned.pop("proof", None)
    return digest_value(unsigned)


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    if contains_protected_data(value):
        raise ValueError(f"Unsafe {label}")
    return value


def _safe_source(root: Path, value: object) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or urlparse(value).scheme
        or contains_protected_data(value)
    ):
        raise ValueError("source_reference_unsafe")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    relative = Path(decoded)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("source_reference_unsafe")
    if root.is_symlink():
        raise ValueError("source_reference_unsafe")
    resolved_root = root.resolve()
    candidate = root.joinpath(relative)
    if any(
        root.joinpath(*relative.parts[:i]).is_symlink() for i in range(1, len(relative.parts) + 1)
    ):
        raise ValueError("source_reference_unsafe")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("source_reference_missing")
    return resolved


def verify_manifest_envelope(raw: dict[str, Any], policy: IntakePolicy) -> None:
    verify_intake_policy(policy)
    validate_manifest(raw)
    for field in ("client_id", "batch_id", "batch_version", "authority"):
        _safe_id(raw[field], field)
    for artifact in raw["artifacts"]:
        _safe_id(artifact["script_id"], "script identity")
        _safe_id(artifact["alias"], "artifact alias")
        if contains_protected_data(artifact["logical_path"]) or contains_protected_data(
            artifact["source_uri"]
        ):
            raise ValueError("Unsafe source identity")
    for workload in raw["workloads"]:
        _safe_id(workload["alias"], "workload alias")
        for field in ("script_ids", "entrypoint_ids", "closure_ids"):
            for value in workload[field]:
                _safe_id(value, "workload source identity")
    for item in raw["unprocessable"]:
        _safe_id(item["script_id"], "unprocessable script identity")
        _safe_id(item["owner"], "unprocessable owner")
    if raw["client_id"] != policy.payload["client_id"]:
        raise ValueError("Batch intake client binding mismatch")
    actual = manifest_digest(raw)
    if raw["manifest_digest"] != actual:
        raise ValueError("Batch intake manifest digest mismatch")
    proof = raw["proof"]
    provenance = policy.payload["manifest_provenance"]
    if (
        raw["authority"] not in provenance["authorities"]
        or proof["key_id"] not in provenance["key_ids"]
    ):
        raise ValueError("Batch intake manifest authority is not permitted")
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(policy.payload["verification_keys"][proof["key_id"]], validate=True)
        )
        key.verify(base64.b64decode(proof["value"], validate=True), bytes.fromhex(actual))
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ValueError("Batch intake manifest attestation is invalid") from exc


def _publish_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == data:
            path.chmod(0o444)
            return
        raise FileExistsError("Conflicting immutable intake snapshot")
    descriptor, name = tempfile.mkstemp(prefix=".intake-source-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise FileExistsError("Conflicting immutable intake snapshot") from None
        path.chmod(0o444)
    finally:
        temporary.unlink(missing_ok=True)


def _block(alias: str, workload_id: str, blockers: set[str]) -> dict[str, Any]:
    return {
        "workload_alias": alias,
        "workload_id": workload_id,
        "workload_revision_id": None,
        "state": "blocked",
        "blockers": sorted(blockers),
        "closure_digest": None,
        "artifact_ids": [],
        "entrypoint_artifact_ids": [],
        "snapshot_refs": [],
        "discovery": None,
        "readiness_input": None,
        "telemetry": _telemetry(False, True),
    }


def _telemetry(admitted: bool, blocked: bool) -> dict[str, bool]:
    return {
        "source_admitted": admitted,
        "source_snapshotted": admitted,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "blocked": blocked,
    }


def _workload_decision(
    request: IntakeRequest,
    workload: dict[str, Any],
    artifact_by_id: dict[str, dict[str, Any]],
    batch_revision_id: str,
    global_blockers: set[str],
) -> dict[str, Any]:
    alias = workload.get("alias") if isinstance(workload.get("alias"), str) else "invalid"
    try:
        safe_alias = _safe_id(alias, "workload alias")
    except ValueError:
        safe_alias = "invalid"
        global_blockers = {*global_blockers, "unsafe_workload_identity"}
    logical_id = stable_id("WL", {"namespace": request.manifest["client_id"], "name": safe_alias})
    blockers = set(global_blockers)
    script_ids = workload.get("script_ids")
    entrypoint_ids = workload.get("entrypoint_ids")
    closure_ids = workload.get("closure_ids")
    if not all(
        isinstance(value, list) and value for value in (script_ids, entrypoint_ids, closure_ids)
    ):
        blockers.add("workload_closure_missing")
        return _block(safe_alias, logical_id, blockers)
    script_ids = cast(list[str], script_ids)
    entrypoint_ids = cast(list[str], entrypoint_ids)
    closure_ids = cast(list[str], closure_ids)
    if len(script_ids) != len(set(script_ids)) or len(closure_ids) != len(set(closure_ids)):
        blockers.add("duplicate_workload_reference")
    if not set(entrypoint_ids).issubset(set(closure_ids)) or not set(script_ids).issubset(
        set(closure_ids)
    ):
        blockers.add("incomplete_declared_closure")
    artifacts: list[dict[str, Any]] = []
    acquired: dict[str, bytes] = {}
    for script_id in closure_ids:
        artifact = artifact_by_id.get(script_id)
        if artifact is None:
            blockers.add("declared_source_missing")
            continue
        artifacts.append(artifact)
        try:
            _safe_id(artifact.get("script_id"), "script identity")
            _safe_id(artifact.get("alias"), "artifact alias")
            if artifact.get("kind") not in _KINDS:
                blockers.add("unsupported_artifact_kind")
                continue
            source = _safe_source(request.source_root, artifact.get("source_uri"))
            data = source.read_bytes()
            if len(data) != artifact.get("size_bytes") or hashlib.sha256(
                data
            ).hexdigest() != artifact.get("sha256"):
                blockers.add("source_bytes_changed")
                continue
            if not data:
                blockers.add("empty_source_artifact")
                continue
            if contains_protected_data(data.decode("utf-8", errors="replace")):
                blockers.add("protected_source_content")
                continue
            acquired[script_id] = data
        except (OSError, ValueError):
            blockers.add("source_artifact_missing_or_unsafe")
    meaningful = False
    for entrypoint_id in entrypoint_ids:
        artifact = artifact_by_id.get(entrypoint_id)
        entry_data = acquired.get(entrypoint_id)
        if artifact is None or artifact.get("kind") != "sas_program" or entry_data is None:
            blockers.add("entrypoint_missing_or_not_sas_program")
            continue
        try:
            meaningful = meaningful or bool(_MEANINGFUL_SAS.search(entry_data.decode("utf-8")))
        except UnicodeDecodeError:
            blockers.add("entrypoint_not_utf8")
    if not meaningful:
        blockers.add("no_meaningful_sas_entrypoint")
    if blockers:
        return _block(safe_alias, logical_id, blockers)

    closure_projection = sorted(
        (
            {
                "script_id": item["script_id"],
                "logical_path": item["logical_path"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "kind": item["kind"],
            }
            for item in artifacts
        ),
        key=lambda item: item["script_id"],
    )
    closure_digest = digest_value(closure_projection)
    revision_id = stable_id(
        "WREV",
        {
            "workload_id": logical_id,
            "closure_digest": closure_digest,
            "manifest_version": request.manifest["batch_version"],
            "policy_digest": request.policy.policy_digest,
            "provider": request.policy.payload["provider"],
            "provider_version": request.policy.payload["provider_version"],
            "discovery_strategy_version": request.policy.payload["discovery_strategy_version"],
        },
    )
    attempt_root = (
        request.output_root
        / "runs"
        / request.run_id
        / "batch-intakes"
        / request.manifest["batch_id"]
        / "revisions"
        / batch_revision_id
        / "attempts"
        / request.attempt_id
    )
    snapshot_root = attempt_root / "workloads" / logical_id / "source"
    snapshot_refs: list[dict[str, Any]] = []
    for artifact in artifacts:
        logical_path = Path(unquote(artifact["logical_path"]))
        if logical_path.is_absolute() or any(
            part in {"", ".", ".."} for part in logical_path.parts
        ):
            return _block(safe_alias, logical_id, {"logical_path_escape"})
        target = snapshot_root / logical_path
        if not target.resolve().is_relative_to(snapshot_root.resolve()):
            return _block(safe_alias, logical_id, {"logical_path_escape"})
        _publish_bytes(target, acquired[artifact["script_id"]])
        snapshot_refs.append(
            {
                "script_id": artifact["script_id"],
                "logical_path": artifact["logical_path"],
                "snapshot_uri": target.relative_to(request.output_root).as_posix(),
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
            }
        )
    discovered = discover_source(
        snapshot_root,
        provider=request.policy.payload["provider"],
        namespace=request.manifest["client_id"],
        logical_name=safe_alias,
        source_locator=f"intake://{batch_revision_id}/{logical_id}/{revision_id}",
    ).workloads[0]
    canonical_by_path = {item.logical_path: item for item in discovered.artifacts if item.checksum}
    if len(canonical_by_path) != len(closure_projection) or any(
        canonical_by_path.get(item["logical_path"]) is None
        or canonical_by_path[item["logical_path"]].checksum != item["sha256"]
        for item in closure_projection
    ):
        return _block(safe_alias, logical_id, {"canonical_source_closure_mismatch"})
    unresolved = discovered.dependency_graph.unresolved if discovered.dependency_graph else ()
    if any(item.domain is DependencyDomain.CODE for item in unresolved):
        return _block(safe_alias, logical_id, {"unresolved_code_dependency"})
    discovery_payload = discovered.to_dict()
    prerequisite_items = [
        {"kind": item["kind"], "state": "missing", "owner": item["owner"]}
        for item in request.policy.payload["readiness_prerequisites"]
    ]
    readiness_input = {
        "schema_version": "1.0",
        "client_id": request.manifest["client_id"],
        "batch_revision_id": batch_revision_id,
        "workload_id": logical_id,
        "workload_revision_id": revision_id,
        "closure_digest": closure_digest,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "policy_digest": request.policy.policy_digest,
        "snapshot_refs": snapshot_refs,
        "prerequisites": prerequisite_items,
        "workload": discovery_payload,
        "authorizes_readiness": False,
    }
    return {
        "workload_alias": safe_alias,
        "workload_id": logical_id,
        "workload_revision_id": revision_id,
        "state": "admitted",
        "blockers": [],
        "closure_digest": closure_digest,
        "artifact_ids": [
            canonical_by_path[item["logical_path"]].artifact_id for item in closure_projection
        ],
        "entrypoint_artifact_ids": [
            canonical_by_path[artifact_by_id[item]["logical_path"]].artifact_id
            for item in entrypoint_ids
        ],
        "snapshot_refs": snapshot_refs,
        "discovery": discovery_payload,
        "readiness_input": readiness_input,
        "telemetry": _telemetry(True, False),
    }


def evaluate_batch_intake(request: IntakeRequest) -> dict[str, Any]:
    _safe_id(request.run_id, "run_id")
    _safe_id(request.attempt_id, "attempt_id")
    verify_manifest_envelope(request.manifest, request.policy)
    if request.policy.payload["provider"] != "filesystem":
        raise ValueError("Unsupported batch intake provider")
    manifest = json.loads(json.dumps(request.manifest))
    artifacts = manifest["artifacts"]
    artifact_by_id: dict[str, dict[str, Any]] = {}
    artifact_duplicates: set[str] = set()
    path_owners: dict[str, set[str]] = {}
    artifact_aliases: dict[str, set[str]] = {}
    for artifact in artifacts:
        script_id = artifact.get("script_id")
        if isinstance(script_id, str):
            if script_id in artifact_by_id:
                artifact_duplicates.add(script_id)
            else:
                artifact_by_id[script_id] = artifact
        path = artifact.get("logical_path")
        if isinstance(path, str) and isinstance(script_id, str):
            path_owners.setdefault(path.casefold(), set()).add(script_id)
        alias = artifact.get("alias")
        if isinstance(alias, str) and isinstance(script_id, str):
            artifact_aliases.setdefault(alias.casefold(), set()).add(script_id)
    ambiguous_paths = {
        item for values in path_owners.values() if len(values) > 1 for item in values
    }
    duplicate_artifact_aliases = {
        item for values in artifact_aliases.values() if len(values) > 1 for item in values
    }
    aliases: dict[str, int] = {}
    owners: dict[str, set[str]] = {}
    for workload in manifest["workloads"]:
        alias = workload.get("alias")
        if isinstance(alias, str):
            aliases[alias.casefold()] = aliases.get(alias.casefold(), 0) + 1
        for script_id in workload.get("script_ids", []):
            if isinstance(script_id, str):
                owners.setdefault(script_id, set()).add(
                    alias if isinstance(alias, str) else "invalid"
                )
    batch_revision_id = stable_id(
        "BREV",
        {
            "manifest_digest": manifest["manifest_digest"],
            "policy_digest": request.policy.policy_digest,
        },
    )
    decisions: list[dict[str, Any]] = []
    for workload in manifest["workloads"]:
        blockers: set[str] = set()
        alias = workload.get("alias")
        refs = set(workload.get("closure_ids", [])) | set(workload.get("script_ids", []))
        if isinstance(alias, str) and aliases.get(alias.casefold(), 0) > 1:
            blockers.add("duplicate_workload_alias")
        if refs & artifact_duplicates:
            blockers.add("duplicate_script_identity")
        if refs & ambiguous_paths:
            blockers.add("duplicate_logical_path")
        if refs & duplicate_artifact_aliases:
            blockers.add("duplicate_artifact_alias")
        if any(len(owners.get(item, ())) > 1 for item in workload.get("script_ids", [])):
            blockers.add("duplicate_script_ownership")
        decisions.append(
            _workload_decision(request, workload, artifact_by_id, batch_revision_id, blockers)
        )
    inventory_ids = {
        item.get("script_id") for item in artifacts if isinstance(item.get("script_id"), str)
    }
    unprocessable_ids = {
        item.get("script_id")
        for item in manifest["unprocessable"]
        if isinstance(item.get("script_id"), str)
    }
    mapped_ids = {
        script_id
        for workload in manifest["workloads"]
        for script_id in workload.get("closure_ids", [])
        if isinstance(script_id, str)
    }
    unassigned_ids = sorted(inventory_ids - mapped_ids)
    denominator = len(inventory_ids | unprocessable_ids)
    denominator_ok = (
        denominator == manifest["expected_script_count"]
        and not inventory_ids.intersection(unprocessable_ids)
        and len(artifacts) == len(inventory_ids)
        and len(manifest["unprocessable"]) == len(unprocessable_ids)
        and not unassigned_ids
    )
    admitted = sum(item["state"] == "admitted" for item in decisions)
    blocked = len(decisions) - admitted
    disposition = (
        "admitted"
        if admitted and not blocked and denominator_ok and not unprocessable_ids
        else ("partial" if admitted else "blocked")
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": stable_id(
            "BINT",
            {
                "batch_revision_id": batch_revision_id,
                "run_id": request.run_id,
                "attempt_id": request.attempt_id,
            },
        ),
        "client_id": manifest["client_id"],
        "batch_id": manifest["batch_id"],
        "batch_version": manifest["batch_version"],
        "batch_revision_id": batch_revision_id,
        "manifest_digest": manifest["manifest_digest"],
        "policy_id": request.policy.payload["policy_id"],
        "policy_version": request.policy.payload["policy_version"],
        "policy_digest": request.policy.policy_digest,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "expected_script_count": manifest["expected_script_count"],
        "observed_unique_script_count": denominator,
        "denominator_reconciled": denominator_ok,
        "admitted_count": admitted,
        "blocked_count": blocked,
        "unprocessable_count": len(unprocessable_ids),
        "unassigned_scripts": [
            {"script_id": script_id, "reason_code": "unmapped_inventory_script"}
            for script_id in unassigned_ids
        ],
        "disposition": disposition,
        "decisions": decisions,
        "manifest_snapshot": manifest,
        "policy_snapshot": json.loads(json.dumps(request.policy.payload)),
        "content_digest": "",
    }
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    validate_result(payload)
    return payload
