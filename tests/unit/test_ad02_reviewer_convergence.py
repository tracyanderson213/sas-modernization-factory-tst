"""Regression tests for AD-02 reviewer findings discovered on 2026-09-09."""

from pathlib import Path

from smf.discovery import discover_source
from smf.workload.models import (
    ArtifactKind,
    DependencyDomain,
    DependencyResolutionReason,
    RelationshipKind,
)


def _discover(root: Path):
    result = discover_source(root, provider="filesystem", namespace="ad02-review")
    assert len(result.workloads) == 1
    workload = result.workloads[0]
    assert workload.dependency_graph is not None
    return workload


def test_scheduler_dependency_reconciles_defined_job_across_jil_files(tmp_path: Path) -> None:
    (tmp_path / "downstream.jil").write_text(
        "insert_job: DOWNSTREAM job_type: c\ncondition: s(UPSTREAM)\n",
        encoding="utf-8",
    )
    (tmp_path / "upstream.jil").write_text(
        "insert_job: UPSTREAM job_type: c\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)

    defined_jobs = [
        artifact
        for artifact in workload.artifacts
        if artifact.kind is ArtifactKind.SCHEDULER_JOB
        and artifact.metadata.get("definition_status") == "defined"
    ]
    upstream = [artifact for artifact in defined_jobs if artifact.name == "UPSTREAM"]
    downstream = [artifact for artifact in defined_jobs if artifact.name == "DOWNSTREAM"]

    assert len(upstream) == 1
    assert len(downstream) == 1

    assert not any(
        artifact.kind is ArtifactKind.SCHEDULER_JOB
        and artifact.name == "UPSTREAM"
        and artifact.metadata.get("definition_status") == "referenced_only"
        for artifact in workload.artifacts
    )

    edges = {
        (relationship.source_id, relationship.kind, relationship.target_id)
        for relationship in workload.relationships
    }
    assert (
        downstream[0].artifact_id,
        RelationshipKind.DEPENDS_ON,
        upstream[0].artifact_id,
    ) in edges
    assert (
        upstream[0].artifact_id,
        RelationshipKind.PRECEDES,
        downstream[0].artifact_id,
    ) in edges

    graph = workload.dependency_graph
    assert not any(
        item.domain is DependencyDomain.SCHEDULER
        and item.source_id == downstream[0].artifact_id
        and item.reference == "UPSTREAM"
        and item.reason is DependencyResolutionReason.EXTERNAL
        for item in graph.unresolved
    )


def test_dynamic_dataset_unresolved_records_preserve_read_write_direction(
    tmp_path: Path,
) -> None:
    (tmp_path / "dynamic.sas").write_text(
        "data &lib..shared;\n  set &lib..shared;\nrun;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    artifact = next(item for item in workload.artifacts if item.name == "dynamic.sas")
    graph = workload.dependency_graph

    dynamic_data = [
        item
        for item in graph.unresolved
        if item.source_id == artifact.artifact_id
        and item.domain is DependencyDomain.DATA
        and item.reason is DependencyResolutionReason.DYNAMIC
    ]

    directions = {
        item.metadata.get("relationship_kind")
        or item.metadata.get("direction")
        or item.metadata.get("access_mode")
        for item in dynamic_data
    }

    assert RelationshipKind.READS.value in directions or RelationshipKind.READS in directions
    assert RelationshipKind.WRITES.value in directions or RelationshipKind.WRITES in directions
    assert len(dynamic_data) >= 2
