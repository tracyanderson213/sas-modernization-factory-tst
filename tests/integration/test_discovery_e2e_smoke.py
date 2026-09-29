from pathlib import Path

from smf.discovery import discover_source
from smf.workload.models import (
    ArtifactKind,
    ConsumerResolution,
    DatasetKind,
    DependencyDomain,
    DependencyResolutionReason,
    EvidenceMethod,
    RelationshipKind,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "e2e" / "sample-sas-estate"


def test_realistic_multi_artifact_estate_builds_connected_graph() -> None:
    result = discover_source(FIXTURE, provider="filesystem", namespace="test-e2e")
    assert len(result.workloads) == 1
    workload = result.workloads[0]

    artifacts = {item.name: item for item in workload.artifacts}
    datasets = {item.name: item for item in workload.datasets}
    edges = {(item.source_id, item.kind, item.target_id) for item in workload.relationships}

    extract = artifacts["extract_claims.sas"]
    transform = artifacts["transform_claims.sas"]
    publish = artifacts["publish_claims.sas"]
    wrapper = artifacts["run_claims.sh"]
    run_job = artifacts["RUN_CLAIMS"]
    load_job = artifacts["LOAD_SOURCE"]

    assert workload.dependency_graph is not None
    load_source_launch = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == load_job.artifact_id
        and item.reference == "/opt/enterprise/load_source.sh"
    )
    assert load_source_launch.domain is DependencyDomain.RUNTIME_LAUNCH
    assert load_source_launch.reason is DependencyResolutionReason.MISSING
    assert load_source_launch.evidence[0].method is EvidenceMethod.SCHEDULER_METADATA

    assert datasets["src.claims"].kind is DatasetKind.DATABASE_TABLE
    assert "DO_NOT_EXPOSE" not in str(datasets["src.claims"].metadata)
    assert datasets["raw.claims_stage"].location == "/data/raw/claims_stage"
    assert datasets["curated.claims"].location == "/data/curated/claims"

    outputs = {
        next(
            item.name for item in workload.datasets if item.dataset_id == output.dataset_id
        ): output
        for output in workload.outputs
    }
    assert outputs["raw.claims_stage"].consumer_ids == (transform.artifact_id,)
    assert outputs["raw.claims_stage"].consumer_resolution is ConsumerResolution.PARTIAL
    assert outputs["curated.claims"].consumer_ids == (publish.artifact_id,)
    report = outputs["claims_report.csv"]
    assert report.consumer_ids == ()
    assert report.consumer_resolution is ConsumerResolution.UNRESOLVED

    assert workload.boundaries
    claims_boundary = next(
        item for item in workload.boundaries if extract.artifact_id in item.artifact_ids
    )
    assert transform.artifact_id in claims_boundary.artifact_ids
    assert publish.artifact_id in claims_boundary.artifact_ids
    assert wrapper.artifact_id in claims_boundary.artifact_ids
    assert run_job.artifact_id in claims_boundary.artifact_ids
    assert claims_boundary.metadata["basis"] == "deterministic_graph_connectivity"
    assert claims_boundary.metadata["requires_confirmation"] is True

    assert workload.topology is not None
    topology_nodes = {item.entity_id: item for item in workload.topology.nodes}
    topology_edges = {
        (item.source_id, item.kind, item.target_id) for item in workload.topology.edges
    }
    assert claims_boundary.boundary_id in topology_nodes
    assert datasets["src.claims"].dataset_id in topology_nodes
    assert workload.topology.metadata["complete_enterprise_topology"] is False
    assert any(
        source == claims_boundary.boundary_id and kind is RelationshipKind.DEPENDS_ON
        for source, kind, _target in topology_edges
    )

    assert (transform.artifact_id, RelationshipKind.DEPENDS_ON, extract.artifact_id) in edges
    assert (publish.artifact_id, RelationshipKind.DEPENDS_ON, transform.artifact_id) in edges
    assert (wrapper.artifact_id, RelationshipKind.TRIGGERS, extract.artifact_id) in edges
    assert (wrapper.artifact_id, RelationshipKind.TRIGGERS, transform.artifact_id) in edges
    assert (wrapper.artifact_id, RelationshipKind.TRIGGERS, publish.artifact_id) in edges
    assert (run_job.artifact_id, RelationshipKind.TRIGGERS, wrapper.artifact_id) in edges
    assert (run_job.artifact_id, RelationshipKind.DEPENDS_ON, load_job.artifact_id) in edges

    common_macro = artifacts["common_macros.sas"]
    assert (extract.artifact_id, RelationshipKind.INCLUDES, common_macro.artifact_id) in edges
    assert not any(
        item.metadata.get("placeholder") and item.logical_path == "macros/common_macros.sas"
        for item in workload.artifacts
    )

    dynamic = artifacts["run_dynamic.sh"]
    assert any(
        finding["resolution"] == "dynamic" for finding in dynamic.metadata["runtime_invocations"]
    )
    assert not any(
        source == dynamic.artifact_id and kind is RelationshipKind.TRIGGERS
        for source, kind, _target in edges
    )

    external = artifacts["EXTERNAL_AUDIT_READY"]
    assert external.metadata["definition_status"] == "referenced_only"
    unresolved_scheduler = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.reference == "EXTERNAL_AUDIT_READY"
    )
    assert unresolved_scheduler.domain is DependencyDomain.SCHEDULER
    assert unresolved_scheduler.reason is DependencyResolutionReason.EXTERNAL
    assert not any(
        external.artifact_id in {item.source_id, item.target_id}
        for item in workload.dependency_graph.edges
    )

    cron_jobs = [
        item
        for item in workload.artifacts
        if item.kind is ArtifactKind.SCHEDULER_JOB
        and item.metadata.get("scheduler_format") == "cron"
    ]
    assert len(cron_jobs) == 1
    assert cron_jobs[0].metadata["schedule"] == "15 4 * * 1-5"
