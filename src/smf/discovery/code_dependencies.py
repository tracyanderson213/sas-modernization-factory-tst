"""Reconcile statically observed SAS macro calls across inventoried artifacts."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from smf.discovery.sas_static import is_sas_system_macro_operation
from smf.workload.identity import stable_id
from smf.workload.models import (
    Artifact,
    Confidence,
    DiscoveryEvidence,
    EvidenceMethod,
    MacroArtifactType,
    MacroObservation,
    MacroObservationKind,
    MacroResolution,
    MacroResolutionKind,
    Relationship,
    RelationshipKind,
    Workload,
)


def _references(artifact: Artifact, key: str) -> tuple[tuple[str, int], ...]:
    static = artifact.metadata.get("sas_static")
    if not isinstance(static, dict):
        return ()
    raw = static.get(key, ())
    if not isinstance(raw, list):
        return ()
    references: list[tuple[str, int]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        line = item.get("line")
        if isinstance(value, str) and isinstance(line, int):
            references.append((value.lower(), line))
    return tuple(references)


def _evidence(artifact: Artifact, value: str, line: int) -> DiscoveryEvidence:
    source = artifact.logical_path or artifact.name
    locator = f"{source}:{line}"
    return DiscoveryEvidence(
        evidence_id=stable_id(
            "EV",
            {
                "method": EvidenceMethod.STATIC_ANALYSIS.value,
                "source": source,
                "locator": locator,
                "observed_value": value,
            },
        ),
        method=EvidenceMethod.STATIC_ANALYSIS,
        source=source,
        confidence=Confidence.HIGH,
        locator=locator,
        observed_value=value,
        metadata={"line": line, "observation": "static_macro_invocation"},
    )


def _merge_evidence(
    *groups: tuple[DiscoveryEvidence, ...],
) -> tuple[DiscoveryEvidence, ...]:
    merged = {item.evidence_id: item for group in groups for item in group}
    return tuple(merged[key] for key in sorted(merged))


def derive_code_dependencies(workload: Workload) -> Workload:
    """Emit ``CALLS`` only for uniquely resolved literal macro invocations."""

    definitions: dict[str, list[str]] = {}
    definition_artifacts: dict[str, str] = {}
    calls_by_artifact: dict[str, list[tuple[str, int, MacroResolution, MacroObservation]]] = {}
    if workload.macro_analysis is not None:
        for definition in workload.macro_analysis.logical_artifacts:
            if definition.artifact_type is not MacroArtifactType.SAS_MACRO_DEFINITION:
                continue
            definitions.setdefault(definition.normalized_identity, []).append(
                definition.logical_artifact_id
            )
            definition_artifacts[definition.logical_artifact_id] = (
                definition.location.source_artifact_id
            )
        observations = {item.observation_id: item for item in workload.macro_analysis.observations}
        for resolution in workload.macro_analysis.resolutions:
            observation = observations.get(resolution.observation_id)
            if observation is None or observation.kind not in {
                MacroObservationKind.LITERAL_INVOCATION,
                MacroObservationKind.INTRINSIC_OPERATION,
                MacroObservationKind.DYNAMIC_INVOCATION,
            }:
                continue
            calls_by_artifact.setdefault(observation.location.source_artifact_id, []).append(
                (
                    observation.normalized_identity,
                    observation.location.line,
                    resolution,
                    observation,
                )
            )
    else:
        for artifact in workload.artifacts:
            for name, _line in _references(artifact, "macro_definition_references"):
                definitions.setdefault(name, []).append(artifact.artifact_id)
                definition_artifacts[artifact.artifact_id] = artifact.artifact_id

    artifacts: dict[str, Artifact] = {item.artifact_id: item for item in workload.artifacts}
    relationships: dict[str, Relationship] = {
        item.relationship_id: item for item in workload.relationships
    }

    for artifact in workload.artifacts:
        findings: list[dict[str, Any]] = []
        calls: list[tuple[str, int, MacroResolution | None, MacroObservation | None]] = []
        if workload.macro_analysis is not None:
            calls.extend(calls_by_artifact.get(artifact.artifact_id, ()))
        else:
            calls.extend(
                (name, line, None, None)
                for name, line in _references(artifact, "macro_invocation_references")
            )
        for name, line, macro_resolution, observation in calls:
            definition_candidates = (
                macro_resolution.candidate_definition_ids
                if macro_resolution is not None
                else tuple(sorted(definitions.get(name, ())))
            )
            candidates = tuple(
                sorted(
                    {
                        definition_artifacts[item]
                        for item in definition_candidates
                        if item in definition_artifacts
                    }
                )
            )
            # Intrinsic/runtime operations remain in macro analysis but are not
            # dependencies on user code unless a visible user definition exists.
            if not definition_candidates and is_sas_system_macro_operation(name):
                continue
            resolution_state = (
                "resolved"
                if len(definition_candidates) == 1
                and len(candidates) == 1
                and (
                    macro_resolution is None
                    or (
                        macro_resolution.kind is MacroResolutionKind.UNIQUE_STATIC_DEFINITION
                        and macro_resolution.target_definition_id == definition_candidates[0]
                    )
                )
                else macro_resolution.kind.value
                if macro_resolution is not None
                else "ambiguous"
                if definition_candidates
                else "missing"
            )
            finding: dict[str, Any] = {
                "reference": name,
                "line": line,
                "resolution": resolution_state,
            }
            evidence = _evidence(artifact, name, line)
            occurrence: dict[str, Any] = {}
            if (
                macro_resolution is not None
                and observation is not None
                and workload.macro_analysis is not None
            ):
                location = observation.location
                occurrence = {
                    "macro_resolution_id": macro_resolution.resolution_id,
                    "macro_observation_id": observation.observation_id,
                    "macro_strategy_digest": workload.macro_analysis.strategy_digest,
                    "target_definition_id": macro_resolution.target_definition_id,
                    "column": location.column,
                    "byte_start": location.byte_start,
                    "byte_end": location.byte_end,
                    "source_checksum": location.source_checksum,
                    "span_digest": location.span_digest,
                }
                finding.update(occurrence)
                evidence = replace(
                    evidence,
                    evidence_id=stable_id(
                        "EV", {"macro_resolution_id": macro_resolution.resolution_id}
                    ),
                    metadata={**evidence.metadata, **occurrence},
                )
            if resolution_state == "resolved":
                target_id = candidates[0]
                finding["target_artifact_id"] = target_id
                relationship_id = stable_id(
                    "REL",
                    {
                        "workload": workload.workload_id,
                        "source": artifact.artifact_id,
                        "kind": RelationshipKind.CALLS.value,
                        "target": target_id,
                        "dependency_domain": "code",
                    },
                )
                existing = relationships.get(relationship_id)
                resolution_metadata: dict[str, Any] = {}
                if occurrence:
                    resolution_ids = tuple(
                        sorted(
                            {
                                occurrence["macro_resolution_id"],
                                *(
                                    existing.metadata.get("macro_resolution_ids", ())
                                    if existing
                                    else ()
                                ),
                            }
                        )
                    )
                    resolution_metadata = {
                        "macro_resolution_id": resolution_ids[0],
                        "macro_resolution_ids": resolution_ids,
                        "macro_strategy_digest": occurrence["macro_strategy_digest"],
                    }
                relationships[relationship_id] = Relationship(
                    relationship_id=relationship_id,
                    source_id=artifact.artifact_id,
                    kind=RelationshipKind.CALLS,
                    target_id=target_id,
                    evidence=_merge_evidence(existing.evidence if existing else (), (evidence,)),
                    metadata={
                        "dependency_domain": "code",
                        "resolution": "unique_macro_definition",
                        **resolution_metadata,
                        "macro_names": tuple(
                            sorted(
                                {
                                    name,
                                    *(existing.metadata.get("macro_names", ()) if existing else ()),
                                }
                            )
                        ),
                    },
                )
            else:
                finding["candidate_artifact_ids"] = candidates
                if macro_resolution is not None:
                    finding["candidate_definition_ids"] = macro_resolution.candidate_definition_ids
            findings.append(finding)

        if workload.macro_analysis is None:
            findings.extend(
                {"reference": reference, "line": line, "resolution": "dynamic"}
                for reference, line in _references(artifact, "dynamic_macro_invocations")
            )

        if findings or "macro_call_findings" in artifact.metadata:
            artifacts[artifact.artifact_id] = replace(
                artifact,
                metadata={
                    **artifact.metadata,
                    "macro_call_findings": sorted(
                        findings,
                        key=lambda item: (
                            int(item["line"]),
                            int(item.get("byte_start", 0)),
                            str(item["reference"]),
                            str(item["resolution"]),
                        ),
                    ),
                },
            )

    return replace(
        workload,
        artifacts=tuple(sorted(artifacts.values(), key=lambda item: item.artifact_id)),
        relationships=tuple(sorted(relationships.values(), key=lambda item: item.relationship_id)),
    )
