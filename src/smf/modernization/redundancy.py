"""Deterministic duplicate and redundant-logic evidence foundation.

MOD-08 identifies exact source duplication and weaker structural SAS similarity
across workload boundaries. Similarity is evidence for governed modernization
assessment; it never proves business-rule equivalence or selects a disposition.
"""

from __future__ import annotations

from dataclasses import replace
from itertools import combinations
from typing import Any

from smf.workload.identity import stable_id
from smf.workload.models import Artifact, ArtifactKind, Confidence, LogicSimilarityFinding, Workload

_SAS_KINDS = {ArtifactKind.SAS_PROGRAM, ArtifactKind.SAS_MACRO, ArtifactKind.SAS_INCLUDE}


def _signature(artifact: Artifact) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    raw = artifact.metadata.get("sas_static")
    if not isinstance(raw, dict):
        return None
    keys = (
        "libraries",
        "by_variables",
        "macro_definitions",
        "macro_invocations",
        "macro_variables",
        "dynamic_dataset_references",
    )
    normalized: list[tuple[str, tuple[str, ...]]] = []
    for key in keys:
        value = raw.get(key, ())
        if isinstance(value, list | tuple):
            normalized.append((key, tuple(sorted(str(item) for item in value))))
    signature = tuple(normalized)
    return signature if any(values for _, values in signature) else None


def _artifact_boundaries(workload: Workload) -> dict[str, str]:
    return {
        artifact_id: boundary.boundary_id
        for boundary in workload.boundaries
        for artifact_id in boundary.artifact_ids
    }


def _finding_metadata(*, exact: bool, structural: bool) -> dict[str, Any]:
    return {
        "basis": "deterministic_logic_similarity_rules",
        "exact_source_match": exact,
        "structural_signature_match": structural,
        "business_rule_equivalence_established": False,
        "requires_confirmation": True,
        "automatic_disposition_selection": False,
    }


def derive_logic_similarity_findings(workload: Workload) -> Workload:
    """Derive cross-boundary logic-similarity findings from canonical artifacts."""

    boundary_by_artifact = _artifact_boundaries(workload)
    artifacts = sorted(
        (
            artifact
            for artifact in workload.artifacts
            if artifact.kind in _SAS_KINDS and artifact.artifact_id in boundary_by_artifact
        ),
        key=lambda item: item.artifact_id,
    )
    findings: list[LogicSimilarityFinding] = []
    for left, right in combinations(artifacts, 2):
        left_boundary = boundary_by_artifact[left.artifact_id]
        right_boundary = boundary_by_artifact[right.artifact_id]
        if left_boundary == right_boundary:
            continue
        exact = bool(left.checksum and right.checksum and left.checksum == right.checksum)
        left_signature = _signature(left)
        right_signature = _signature(right)
        structural = bool(
            left_signature is not None
            and right_signature is not None
            and left_signature == right_signature
        )
        if not exact and not structural:
            continue
        confidence = Confidence.HIGH if exact else Confidence.LOW
        ordered_boundaries = tuple(sorted((left_boundary, right_boundary)))
        ordered_artifacts = tuple(sorted((left.artifact_id, right.artifact_id)))
        findings.append(
            LogicSimilarityFinding(
                finding_id=stable_id(
                    "LSF",
                    {
                        "boundaries": ordered_boundaries,
                        "artifacts": ordered_artifacts,
                        "exact": exact,
                        "structural": structural,
                    },
                ),
                left_boundary_id=ordered_boundaries[0],
                right_boundary_id=ordered_boundaries[1],
                left_artifact_id=ordered_artifacts[0],
                right_artifact_id=ordered_artifacts[1],
                exact_source_match=exact,
                structural_signature_match=structural,
                confidence=confidence,
                evidence=tuple(
                    {item.evidence_id: item for item in (*left.evidence, *right.evidence)}[key]
                    for key in sorted(
                        {item.evidence_id for item in (*left.evidence, *right.evidence)}
                    )
                ),
                metadata=_finding_metadata(exact=exact, structural=structural),
            )
        )
    findings.sort(key=lambda item: item.finding_id)
    exact_count = sum(item.exact_source_match for item in findings)
    structural_count = sum(
        item.structural_signature_match and not item.exact_source_match for item in findings
    )
    metadata = {
        **workload.metadata,
        "logic_similarity": {
            "finding_count": len(findings),
            "exact_source_match_count": exact_count,
            "structural_only_match_count": structural_count,
            "business_rule_equivalence_established": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, logic_similarity_findings=tuple(findings), metadata=metadata)
