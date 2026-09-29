"""Reconcile static ``%include`` placeholders with inventoried artifacts.

Static SAS analysis can observe an include before filesystem inventory has seen the
referenced file. The analyzer therefore creates a placeholder. Once acquisition is
complete, this module resolves placeholders only when the include path maps
unambiguously to an inventoried artifact. Ambiguous or missing references remain
explicit placeholders rather than being guessed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import replace
from pathlib import PurePosixPath

from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    EvidenceMethod,
    IncludeResolutionKind,
    Relationship,
    RelationshipKind,
    Workload,
)

_DYNAMIC_INCLUDE_RE = re.compile(r"(?:&[A-Za-z_][A-Za-z0-9_]*\.?|%[A-Za-z_][A-Za-z0-9_]*\b)")
_WINDOWS_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_INCLUDE_EDGES = 50_000
RESOLVER_ID = "smf-static-include-resolver"
RESOLVER_VERSION = "1.0"
_POLICY = {
    "resolver_id": RESOLVER_ID,
    "resolver_version": RESOLVER_VERSION,
    "candidate_roots": ["acquisition_root", "including_artifact_parent"],
    "case_policy": "casefold_and_reject_collisions",
    "absolute_paths": "reject",
    "root_escape": "reject",
    "multiple_matches": "ambiguous",
}
INCLUDE_POLICY_DIGEST = hashlib.sha256(
    json.dumps(_POLICY, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()


def _normalize_path(value: str) -> str | None:
    normalized = value.replace("\\", "/").strip()
    if normalized.startswith("/") or _WINDOWS_DRIVE_PATH_RE.match(normalized):
        return None
    parts: list[str] = []
    for part in PurePosixPath(normalized).parts:
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return "/".join(parts).lower()


def _candidate_paths(source_path: str | None, include_path: str) -> tuple[str, ...]:
    portable_include = include_path.replace("\\", "/").strip()
    if portable_include.startswith("/") or _WINDOWS_DRIVE_PATH_RE.match(portable_include):
        return ()
    direct = _normalize_path(include_path)
    candidates = {direct} if direct else set()
    if source_path:
        parent = PurePosixPath(source_path.replace("\\", "/")).parent
        relative = _normalize_path(str(parent / include_path))
        if relative:
            candidates.add(relative)
    return tuple(sorted(candidates))


def _boundary_escape(source_path: str | None, include_path: str) -> bool:
    portable = include_path.replace("\\", "/").strip()
    if portable.startswith("/") or _WINDOWS_DRIVE_PATH_RE.match(portable):
        return True
    return not _candidate_paths(source_path, include_path)


def _unsupported_path(include_path: str) -> bool:
    return (
        not include_path.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in include_path)
        or _PERCENT_ESCAPE_RE.search(include_path) is not None
    )


def _is_inventory_backed(artifact: Artifact) -> bool:
    return (
        artifact.checksum is not None
        and re.fullmatch(r"[a-f0-9]{64}", artifact.checksum) is not None
        and any(evidence.method is EvidenceMethod.FILESYSTEM for evidence in artifact.evidence)
    )


def _cyclic_edges(edges: tuple[tuple[str, str], ...]) -> set[tuple[str, str]]:
    """Return only edges internal to deterministic cyclic components."""

    forward: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()
    for source, target in edges:
        forward[source].add(target)
        reverse[target].add(source)
        nodes.update((source, target))
    order: list[str] = []
    visited: set[str] = set()
    for start in sorted(nodes):
        if start in visited:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend((item, False) for item in sorted(forward[node], reverse=True))
    assigned: set[str] = set()
    cyclic: set[tuple[str, str]] = set()
    for start in reversed(order):
        if start in assigned:
            continue
        component: set[str] = set()
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.add(node)
            for item in sorted(reverse[node], reverse=True):
                if item not in assigned:
                    assigned.add(item)
                    pending.append(item)
        if len(component) > 1 or any(node in forward[node] for node in component):
            cyclic.update(
                (source, target)
                for source in component
                for target in forward[source]
                if target in component
            )
    return cyclic


def _resolution_metadata(
    workload: Workload,
    relationship: Relationship,
    source: Artifact | None,
    reference: str,
    state: IncludeResolutionKind,
    candidate_paths: tuple[str, ...],
    candidates: tuple[Artifact, ...],
) -> dict[str, object]:
    evidence_metadata = relationship.evidence[0].metadata if relationship.evidence else {}
    candidate_artifacts = tuple(
        {
            "artifact_id": item.artifact_id,
            "logical_path": item.logical_path,
            "checksum": item.checksum,
        }
        for item in sorted(
            candidates,
            key=lambda item: (item.logical_path or "", item.artifact_id, item.checksum or ""),
        )
    )
    normalized_reference = reference.replace("\\", "/").strip()
    identity = {
        "workload": workload.workload_id,
        "source_artifact": relationship.source_id,
        "source_checksum": source.checksum if source else None,
        "byte_start": evidence_metadata.get("byte_start"),
        "byte_end": evidence_metadata.get("byte_end"),
        "span_digest": evidence_metadata.get("span_digest"),
        "reference": normalized_reference,
        "policy": INCLUDE_POLICY_DIGEST,
        "candidates": candidate_artifacts,
        "state": state.value,
    }
    return {
        **relationship.metadata,
        "include_resolution": state.value,
        "include_resolution_id": stable_id("IRES", identity),
        "include_resolver_id": RESOLVER_ID,
        "include_resolver_version": RESOLVER_VERSION,
        "include_policy_digest": INCLUDE_POLICY_DIGEST,
        "source_checksum": source.checksum if source else None,
        "line": evidence_metadata.get("line"),
        "column": evidence_metadata.get("column", 1),
        "byte_start": evidence_metadata.get("byte_start"),
        "byte_end": evidence_metadata.get("byte_end"),
        "span_digest": evidence_metadata.get("span_digest"),
        "normalized_reference": normalized_reference,
        "considered_candidate_paths": candidate_paths,
        "candidate_artifact_ids": tuple(item["artifact_id"] for item in candidate_artifacts),
        "candidate_artifacts": candidate_artifacts,
    }


def reconcile_include_artifacts(workload: Workload) -> Workload:
    """Resolve include placeholders to real inventoried artifacts when unambiguous."""

    placeholder_ids = {
        artifact.artifact_id
        for artifact in workload.artifacts
        if artifact.metadata.get("placeholder")
    }
    artifact_ids = [artifact.artifact_id for artifact in workload.artifacts]
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("Duplicate artifact identity in include inventory")
    normalized_artifacts = tuple(
        replace(
            artifact,
            metadata={
                key: value for key, value in artifact.metadata.items() if key != "placeholder"
            },
        )
        if artifact.metadata.get("placeholder") and _is_inventory_backed(artifact)
        else artifact
        for artifact in workload.artifacts
    )
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in normalized_artifacts}
    real_by_path: dict[str, list[Artifact]] = {}
    for artifact in normalized_artifacts:
        if (
            artifact.metadata.get("placeholder")
            or not artifact.logical_path
            or not _is_inventory_backed(artifact)
        ):
            continue
        normalized_path = _normalize_path(artifact.logical_path)
        if normalized_path:
            real_by_path.setdefault(normalized_path, []).append(artifact)

    relationships = []
    resolved_placeholder_ids: set[str] = set()
    for relationship in workload.relationships:
        target = artifacts_by_id.get(relationship.target_id)
        source = artifacts_by_id.get(relationship.source_id)
        if (
            relationship.kind is not RelationshipKind.INCLUDES
            or target is None
            or relationship.target_id not in placeholder_ids
            or target.logical_path is None
        ):
            relationships.append(relationship)
            continue

        candidate_paths = _candidate_paths(
            source.logical_path if source else None, target.logical_path
        )
        if source is None or (
            source.metadata.get("acquisition_boundary_safe") is False
            or source.metadata.get("symlink_mediated") is True
        ):
            state = IncludeResolutionKind.BOUNDARY_ESCAPE
            relationships.append(
                replace(
                    relationship,
                    metadata=_resolution_metadata(
                        workload,
                        relationship,
                        source,
                        target.logical_path,
                        state,
                        candidate_paths,
                        (),
                    ),
                )
            )
            continue
        if _unsupported_path(target.logical_path):
            state = IncludeResolutionKind.UNSUPPORTED
            relationships.append(
                replace(
                    relationship,
                    metadata=_resolution_metadata(
                        workload,
                        relationship,
                        source,
                        target.logical_path,
                        state,
                        candidate_paths,
                        (),
                    ),
                )
            )
            continue
        if _DYNAMIC_INCLUDE_RE.search(target.logical_path):
            state = IncludeResolutionKind.DYNAMIC
            relationships.append(
                replace(
                    relationship,
                    metadata=_resolution_metadata(
                        workload,
                        relationship,
                        source,
                        target.logical_path,
                        state,
                        candidate_paths,
                        (),
                    ),
                )
            )
            continue

        matches: list[Artifact] = []
        for candidate in candidate_paths:
            matches.extend(real_by_path.get(candidate, ()))
        unsafe_matches = [
            item
            for item in matches
            if item.metadata.get("acquisition_boundary_safe") is False
            or item.metadata.get("symlink_mediated") is True
        ]
        matches = [item for item in matches if item not in unsafe_matches]
        unique_matches = {
            (item.artifact_id, item.logical_path, item.checksum): item for item in matches
        }
        matches = list(unique_matches.values())

        if len(matches) != 1:
            state = (
                IncludeResolutionKind.BOUNDARY_ESCAPE
                if unsafe_matches
                or _boundary_escape(source.logical_path if source else None, target.logical_path)
                else IncludeResolutionKind.AMBIGUOUS
                if matches
                else IncludeResolutionKind.MISSING
            )
            relationships.append(
                replace(
                    relationship,
                    metadata=_resolution_metadata(
                        workload,
                        relationship,
                        source,
                        target.logical_path,
                        state,
                        candidate_paths,
                        tuple(matches),
                    ),
                )
            )
            continue

        resolved_id = matches[0].artifact_id
        resolved_placeholder_ids.add(target.artifact_id)
        identity = {
            "workload": workload.workload_id,
            "source": relationship.source_id,
            "kind": relationship.kind.value,
            "target": resolved_id,
            "occurrence": {
                key: relationship.evidence[0].metadata.get(key)
                for key in ("byte_start", "byte_end", "span_digest")
            },
        }
        relationships.append(
            replace(
                relationship,
                relationship_id=stable_id("REL", identity),
                target_id=resolved_id,
                metadata=_resolution_metadata(
                    workload,
                    relationship,
                    source,
                    target.logical_path,
                    IncludeResolutionKind.RESOLVED,
                    candidate_paths,
                    (matches[0],),
                ),
            )
        )

    resolved_edges = tuple(
        (item.source_id, item.target_id)
        for item in relationships
        if item.kind is RelationshipKind.INCLUDES
        and item.metadata.get("include_resolution") == IncludeResolutionKind.RESOLVED.value
    )
    limit_exceeded = len(resolved_edges) > _MAX_INCLUDE_EDGES
    cycle_edges = set() if limit_exceeded else _cyclic_edges(resolved_edges)
    relationships = [
        replace(
            item,
            metadata={
                **item.metadata,
                "include_resolution": (
                    IncludeResolutionKind.LIMIT_EXCEEDED.value
                    if limit_exceeded
                    else IncludeResolutionKind.CYCLIC.value
                ),
                "pre_cycle_resolution_id": item.metadata.get("include_resolution_id"),
                "include_resolution_id": stable_id(
                    "IRES",
                    {
                        "prior_resolution": item.metadata.get("include_resolution_id"),
                        "state": (
                            IncludeResolutionKind.LIMIT_EXCEEDED.value
                            if limit_exceeded
                            else IncludeResolutionKind.CYCLIC.value
                        ),
                    },
                ),
            },
        )
        if item.kind is RelationshipKind.INCLUDES
        and item.metadata.get("include_resolution") == IncludeResolutionKind.RESOLVED.value
        and (limit_exceeded or (item.source_id, item.target_id) in cycle_edges)
        else item
        for item in relationships
    ]

    remaining_targets = {relationship.target_id for relationship in relationships}
    artifacts = tuple(
        artifact
        for artifact in normalized_artifacts
        if not (
            artifact.artifact_id in resolved_placeholder_ids
            and artifact.artifact_id not in remaining_targets
        )
    )
    return replace(workload, artifacts=artifacts, relationships=tuple(relationships))
