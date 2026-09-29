"""Governed, revision-bound static SAS code-closure analysis."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import replace
from typing import Any

from smf.discovery.include_reconciliation import INCLUDE_POLICY_DIGEST
from smf.discovery.sas_static import is_sas_system_macro_operation
from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    CodeDependencyAnalysis,
    CodeDependencyBlocker,
    CodeDependencyBlockerReason,
    CodeDependencyGroup,
    CodeDependencyInventoryEntry,
    CodeDependencyOccurrence,
    CodeDependencyResolutionKind,
    EvidenceMethod,
    MacroRelationshipKind,
    MacroResolutionKind,
    RelationshipKind,
    Workload,
)

ANALYZER_ID = "smf-static-code-closure"
ANALYZER_VERSION = "1.0"
_ELIGIBLE_KINDS = {
    ArtifactKind.SAS_PROGRAM,
    ArtifactKind.SAS_MACRO,
    ArtifactKind.SAS_INCLUDE,
}


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Code dependency occurrence has invalid {field}")
    return value


def _required_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"Code dependency occurrence has invalid {field}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"Code dependency occurrence has invalid {field}") from exc
    return value


def _inventory(workload: Workload) -> tuple[CodeDependencyInventoryEntry, ...]:
    seen: set[str] = set()
    entries: list[CodeDependencyInventoryEntry] = []
    for artifact in workload.artifacts:
        if artifact.artifact_id in seen:
            raise ValueError("Duplicate artifact identity in code dependency inventory")
        seen.add(artifact.artifact_id)
        acquisition_ids = tuple(
            sorted(
                item.evidence_id
                for item in artifact.evidence
                if item.method is EvidenceMethod.FILESYSTEM
            )
        )
        if artifact.checksum is None or not acquisition_ids or artifact.metadata.get("placeholder"):
            continue
        entries.append(
            CodeDependencyInventoryEntry(
                artifact_id=artifact.artifact_id,
                kind=artifact.kind,
                logical_path=artifact.logical_path or artifact.name,
                checksum=_required_digest(artifact.checksum, "artifact checksum"),
                size_bytes=_integer(artifact.metadata.get("size_bytes"), "artifact size"),
                acquisition_evidence_ids=acquisition_ids,
            )
        )
    return tuple(sorted(entries, key=lambda item: item.artifact_id))


def _location(raw: dict[str, Any], artifact: Artifact) -> tuple[int, int, int, int, str, str]:
    line = _integer(raw.get("line"), "line")
    column = _integer(raw.get("column", 1), "column")
    byte_start = _integer(raw.get("byte_start"), "byte_start")
    byte_end = _integer(raw.get("byte_end"), "byte_end")
    if byte_end <= byte_start:
        raise ValueError("Code dependency occurrence has an empty source span")
    source_checksum = _required_digest(raw.get("source_checksum"), "source_checksum")
    if source_checksum != artifact.checksum:
        raise ValueError("Code dependency occurrence source revision does not match inventory")
    span_digest = _required_digest(raw.get("span_digest"), "span_digest")
    return line, column, byte_start, byte_end, source_checksum, span_digest


def _include_occurrences(
    workload: Workload,
    artifacts: dict[str, Artifact],
) -> list[CodeDependencyOccurrence]:
    occurrences: list[CodeDependencyOccurrence] = []
    for relationship in workload.relationships:
        if relationship.kind is not RelationshipKind.INCLUDES:
            continue
        source = artifacts.get(relationship.source_id)
        if source is None:
            raise ValueError("Include occurrence source is outside the workload inventory")
        raw = relationship.metadata
        try:
            resolution = CodeDependencyResolutionKind(str(raw.get("include_resolution")))
        except ValueError as exc:
            raise ValueError(
                f"Unsupported code dependency resolution: {raw.get('include_resolution')!r}"
            ) from exc
        line, column, byte_start, byte_end, source_checksum, span_digest = _location(raw, source)
        occurrence_id = raw.get("include_resolution_id")
        if not isinstance(occurrence_id, str) or not occurrence_id:
            raise ValueError("Include occurrence is missing its governed resolution identity")
        policy_digest = _required_digest(raw.get("include_policy_digest"), "include policy digest")
        if policy_digest != INCLUDE_POLICY_DIGEST:
            raise ValueError("Include occurrence uses an unsupported resolver policy")
        target = artifacts.get(relationship.target_id)
        target_is_inventory_backed = (
            target is not None
            and target.checksum is not None
            and not target.metadata.get("placeholder")
        )
        if resolution is CodeDependencyResolutionKind.RESOLVED and not target_is_inventory_backed:
            raise ValueError("Resolved include target is not acquisition-backed")
        target_artifact_id = (
            target.artifact_id if target is not None and target_is_inventory_backed else None
        )
        target_checksum = (
            target.checksum if target is not None and target_is_inventory_backed else None
        )
        evidence_ids = tuple(sorted(item.evidence_id for item in relationship.evidence))
        if not evidence_ids:
            raise ValueError("Include occurrence has no reconstructable evidence")
        occurrences.append(
            CodeDependencyOccurrence(
                occurrence_id=occurrence_id,
                source_artifact_id=source.artifact_id,
                source_checksum=source_checksum,
                relationship_kind=RelationshipKind.INCLUDES,
                reference=str(
                    raw.get("normalized_reference", target.logical_path if target else "")
                ),
                resolution=resolution,
                line=line,
                column=column,
                byte_start=byte_start,
                byte_end=byte_end,
                span_digest=span_digest,
                policy_digest=policy_digest,
                target_artifact_id=target_artifact_id,
                target_checksum=target_checksum,
                candidate_artifact_ids=tuple(sorted(raw.get("candidate_artifact_ids", ()))),
                evidence_ids=evidence_ids,
            )
        )
    return occurrences


def _call_occurrences(
    workload: Workload,
    artifacts: dict[str, Artifact],
    macro_strategy_digest: str,
) -> list[CodeDependencyOccurrence]:
    occurrences: list[CodeDependencyOccurrence] = []
    for artifact in workload.artifacts:
        for raw_value in artifact.metadata.get("macro_call_findings", ()):
            if not isinstance(raw_value, dict):
                raise ValueError("Malformed macro call finding")
            raw = raw_value
            try:
                resolution = CodeDependencyResolutionKind(str(raw.get("resolution")))
            except ValueError as exc:
                raise ValueError(
                    f"Unsupported code dependency resolution: {raw.get('resolution')!r}"
                ) from exc
            occurrence_id = raw.get("macro_resolution_id")
            if not isinstance(occurrence_id, str) or not occurrence_id:
                raise ValueError(
                    "Macro call occurrence is missing its governed resolution identity"
                )
            line, column, byte_start, byte_end, source_checksum, span_digest = _location(
                raw, artifact
            )
            policy_digest = _required_digest(
                raw.get("macro_strategy_digest"), "macro strategy digest"
            )
            if policy_digest != macro_strategy_digest:
                raise ValueError("Macro call occurrence uses an unsupported strategy")
            target_id = raw.get("target_artifact_id")
            target = artifacts.get(target_id) if isinstance(target_id, str) else None
            candidate_ids = tuple(
                sorted(str(item) for item in raw.get("candidate_artifact_ids", ()))
            )
            if (
                target is None
                and resolution
                in {
                    CodeDependencyResolutionKind.CYCLIC,
                    CodeDependencyResolutionKind.RECURSIVE,
                }
                and len(candidate_ids) == 1
            ):
                target = artifacts.get(candidate_ids[0])
            if resolution is CodeDependencyResolutionKind.RESOLVED and (
                target is None or target.checksum is None or target.metadata.get("placeholder")
            ):
                raise ValueError("Resolved macro call target is not acquisition-backed")
            evidence_id = stable_id("EV", {"macro_resolution_id": occurrence_id})
            occurrences.append(
                CodeDependencyOccurrence(
                    occurrence_id=occurrence_id,
                    source_artifact_id=artifact.artifact_id,
                    source_checksum=source_checksum,
                    relationship_kind=RelationshipKind.CALLS,
                    reference=str(raw.get("reference", "")),
                    resolution=resolution,
                    line=line,
                    column=column,
                    byte_start=byte_start,
                    byte_end=byte_end,
                    span_digest=span_digest,
                    policy_digest=policy_digest,
                    target_artifact_id=target.artifact_id if target is not None else None,
                    target_checksum=target.checksum if target is not None else None,
                    definition_id=(
                        str(raw["target_definition_id"])
                        if isinstance(raw.get("target_definition_id"), str)
                        else None
                    ),
                    candidate_artifact_ids=candidate_ids,
                    evidence_ids=(evidence_id,),
                )
            )
    return occurrences


def _components(
    artifact_ids: tuple[str, ...],
    occurrences: tuple[CodeDependencyOccurrence, ...],
) -> tuple[CodeDependencyGroup, ...]:
    adjacency: dict[str, set[str]] = {item: set() for item in artifact_ids}
    reverse: dict[str, set[str]] = {item: set() for item in artifact_ids}
    for occurrence in occurrences:
        target = occurrence.target_artifact_id
        if (
            target is None
            or occurrence.source_artifact_id not in adjacency
            or target not in adjacency
        ):
            continue
        if occurrence.resolution not in {
            CodeDependencyResolutionKind.RESOLVED,
            CodeDependencyResolutionKind.CYCLIC,
            CodeDependencyResolutionKind.RECURSIVE,
        }:
            continue
        adjacency[occurrence.source_artifact_id].add(target)
        reverse[target].add(occurrence.source_artifact_id)

    order: list[str] = []
    visited: set[str] = set()
    for start in sorted(adjacency):
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
            stack.extend((item, False) for item in sorted(adjacency[node], reverse=True))

    components: list[tuple[str, ...]] = []
    assigned: set[str] = set()
    for start in reversed(order):
        if start in assigned:
            continue
        pending = [start]
        assigned.add(start)
        component: set[str] = set()
        while pending:
            node = pending.pop()
            component.add(node)
            for other in sorted(reverse[node], reverse=True):
                if other not in assigned:
                    assigned.add(other)
                    pending.append(other)
        components.append(tuple(sorted(component)))

    component_by_artifact: dict[str, str] = {}
    component_members: dict[str, tuple[str, ...]] = {}
    for members in components:
        group_id = stable_id("CODEGRP", members)
        component_members[group_id] = members
        component_by_artifact.update({item: group_id for item in members})
    prerequisites: dict[str, set[str]] = defaultdict(set)
    self_edges: set[str] = set()
    for source, targets in adjacency.items():
        source_group = component_by_artifact[source]
        for target in targets:
            target_group = component_by_artifact[target]
            if source_group == target_group:
                self_edges.add(source_group)
            else:
                prerequisites[source_group].add(target_group)

    ranks: dict[str, int] = {}

    def rank(group_id: str) -> int:
        if group_id not in ranks:
            ranks[group_id] = (
                0
                if not prerequisites[group_id]
                else 1 + max(rank(item) for item in prerequisites[group_id])
            )
        return ranks[group_id]

    groups = [
        CodeDependencyGroup(
            group_id=group_id,
            artifact_ids=members,
            prerequisite_group_ids=tuple(sorted(prerequisites[group_id])),
            sequence_rank=rank(group_id),
            cyclic=len(members) > 1 or group_id in self_edges,
        )
        for group_id, members in component_members.items()
    ]
    return tuple(sorted(groups, key=lambda item: (item.sequence_rank, item.group_id)))


def derive_code_dependency_analysis(workload: Workload) -> Workload:
    """Derive a complete classification of static include and macro-call observations."""

    inventory = _inventory(workload)
    inventory_ids = {item.artifact_id for item in inventory}
    artifacts = {item.artifact_id: item for item in workload.artifacts}
    macro_strategy_digest = (
        workload.macro_analysis.strategy_digest if workload.macro_analysis is not None else "0" * 64
    )
    policy_digest = _digest(
        {
            "analyzer_id": ANALYZER_ID,
            "analyzer_version": ANALYZER_VERSION,
            "include_policy_digest": INCLUDE_POLICY_DIGEST,
            "macro_strategy_digest": macro_strategy_digest,
        }
    )
    occurrences = tuple(
        sorted(
            [
                *_include_occurrences(workload, artifacts),
                *_call_occurrences(workload, artifacts, macro_strategy_digest),
            ],
            key=lambda item: item.occurrence_id,
        )
    )
    occurrence_ids = [item.occurrence_id for item in occurrences]
    if len(occurrence_ids) != len(set(occurrence_ids)):
        raise ValueError("Duplicate code dependency occurrence identity")
    if workload.macro_analysis is not None:
        macro_observations = {
            item.observation_id: item for item in workload.macro_analysis.observations
        }
        expected_occurrence_ids = {
            item.resolution_id
            for item in workload.macro_analysis.resolutions
            if item.relationship_kind
            in {
                MacroRelationshipKind.SAS_MACRO_CALL,
                MacroRelationshipKind.SAS_INCLUDE_REFERENCE,
            }
            and item.kind is not MacroResolutionKind.INTRINSIC_SYSTEM
            and not (
                not item.candidate_definition_ids
                and item.observation_id in macro_observations
                and is_sas_system_macro_operation(
                    macro_observations[item.observation_id].normalized_identity
                )
            )
        }
        if set(occurrence_ids) != expected_occurrence_ids:
            raise ValueError("Code dependency observations are not classified exactly once")

    eligible_ids = tuple(
        sorted(item.artifact_id for item in inventory if item.kind in _ELIGIBLE_KINDS)
    )
    blockers: list[CodeDependencyBlocker] = []
    if not eligible_ids:
        blockers.append(
            CodeDependencyBlocker(
                blocker_id=stable_id(
                    "CODEBLK", {"workload": workload.workload_id, "reason": "no_eligible_subject"}
                ),
                reason=CodeDependencyBlockerReason.NO_ELIGIBLE_SUBJECT,
                detail="No acquisition-backed SAS subject exists in the source closure",
            )
        )
    for occurrence in occurrences:
        if occurrence.source_artifact_id not in inventory_ids:
            raise ValueError("Code dependency occurrence source is outside the source closure")
        if occurrence.resolution is not CodeDependencyResolutionKind.RESOLVED:
            blockers.append(
                CodeDependencyBlocker(
                    blocker_id=stable_id(
                        "CODEBLK",
                        {
                            "workload": workload.workload_id,
                            "occurrence": occurrence.occurrence_id,
                            "resolution": occurrence.resolution.value,
                        },
                    ),
                    reason=CodeDependencyBlockerReason.UNRESOLVED_DEPENDENCY,
                    occurrence_id=occurrence.occurrence_id,
                    detail=occurrence.resolution.value,
                )
            )

    ordering_ids = set(eligible_ids)
    for occurrence in occurrences:
        ordering_ids.add(occurrence.source_artifact_id)
        if occurrence.target_artifact_id in inventory_ids:
            ordering_ids.add(occurrence.target_artifact_id)
    groups = _components(tuple(sorted(ordering_ids)), occurrences)
    source_closure_digest = _digest(
        [
            (
                item.artifact_id,
                item.kind.value,
                item.logical_path,
                item.checksum,
                item.size_bytes,
                item.acquisition_evidence_ids,
            )
            for item in inventory
        ]
    )
    analysis_complete = bool(eligible_ids) and (
        workload.macro_analysis is None or workload.macro_analysis.complete
    )
    ordering_eligible = (
        analysis_complete
        and not blockers
        and not any(item.cyclic for item in groups)
        and all(
            item.target_artifact_id in inventory_ids
            for item in occurrences
            if item.resolution is CodeDependencyResolutionKind.RESOLVED
        )
    )
    analysis_payload = {
        "workload": workload.workload_id,
        "policy": policy_digest,
        "source_closure": source_closure_digest,
        "occurrences": tuple(item.occurrence_id for item in occurrences),
        "occurrence_resolutions": tuple(
            (item.occurrence_id, item.resolution.value, item.target_artifact_id)
            for item in occurrences
        ),
        "groups": tuple(item.group_id for item in groups),
        "blockers": tuple(item.blocker_id for item in blockers),
    }
    analysis = CodeDependencyAnalysis(
        analysis_id=stable_id("CODEAN", analysis_payload),
        workload_id=workload.workload_id,
        analyzer_id=ANALYZER_ID,
        analyzer_version=ANALYZER_VERSION,
        policy_digest=policy_digest,
        source_closure_digest=source_closure_digest,
        include_policy_digest=INCLUDE_POLICY_DIGEST,
        macro_strategy_digest=macro_strategy_digest,
        inventory=inventory,
        occurrences=occurrences,
        ordering_groups=groups,
        blockers=tuple(sorted(blockers, key=lambda item: item.blocker_id)),
        analysis_complete=analysis_complete,
        ordering_eligible=ordering_eligible,
    )
    return replace(workload, code_dependency_analysis=analysis)
