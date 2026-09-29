from __future__ import annotations

import json
from pathlib import Path

from smf.discovery import discover_source
from smf.workload.models import (
    ConsumerResolution,
    DatasetKind,
    DependencyDomain,
    DependencyResolutionReason,
    ExternalDependencyKind,
    RelationshipKind,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "adversarial" / "discovery-torture"


def _discover():
    result = discover_source(FIXTURE, provider="filesystem", namespace="adversarial")
    assert len(result.workloads) == 1
    return result.workloads[0]


def test_adversarial_discovery_does_not_crash_and_redacts_secret() -> None:
    workload = _discover()
    payload = json.dumps(workload.to_dict())
    assert "SUPER_SECRET_DO_NOT_LEAK" not in payload
    assert any(dataset.name == "src.literal_input" for dataset in workload.datasets)
    assert any(dataset.name == "out.literal_output" for dataset in workload.datasets)


def test_comments_do_not_create_false_sas_dataset_dependencies() -> None:
    workload = _discover()
    names = {dataset.name for dataset in workload.datasets}
    assert "fake.comment_input" not in names
    assert "fake.comment_output" not in names
    assert "fake.statement_comment_input" not in names


def test_quoted_sas_looking_text_does_not_create_false_lineage() -> None:
    workload = _discover()
    names = {dataset.name for dataset in workload.datasets}
    assert "fake.string_input" not in names
    assert "fake.string_output" not in names
    assert "fake.x" not in names


def test_dynamic_dataset_reference_is_preserved_without_fabricated_literal_dataset() -> None:
    workload = _discover()
    artifact = next(item for item in workload.artifacts if item.name == "edge_cases.sas")
    dynamic = set(artifact.metadata["sas_static"]["dynamic_dataset_references"])
    assert "&source_table." in dynamic
    names = {dataset.name for dataset in workload.datasets}
    assert "src.source_table" not in names


def test_work_dataset_is_intermediate_and_literal_db_tables_are_database_tables() -> None:
    workload = _discover()
    datasets = {item.name: item for item in workload.datasets}
    assert datasets["work.stage"].kind is DatasetKind.INTERMEDIATE
    assert datasets["src.member"].kind is DatasetKind.DATABASE_TABLE
    assert datasets["src.claims"].kind is DatasetKind.DATABASE_TABLE


def test_scheduler_external_dependency_is_explicit_and_malformed_metadata_does_not_crash() -> None:
    workload = _discover()
    artifacts = {item.name: item for item in workload.artifacts}
    assert artifacts["MISSING_EXTERNAL_JOB"].metadata["definition_status"] == "referenced_only"
    edges = {(item.source_id, item.kind, item.target_id) for item in workload.relationships}
    child = artifacts["EDGE_CHILD"]
    external = artifacts["MISSING_EXTERNAL_JOB"]
    assert (child.artifact_id, RelationshipKind.DEPENDS_ON, external.artifact_id) in edges
    assert "MALFORMED_BUT_SURVIVABLE" in artifacts


def test_shell_comments_and_strings_do_not_create_fake_trigger_edges() -> None:
    workload = _discover()
    names = {item.name for item in workload.artifacts}
    assert "commented_out.sas" not in names
    assert "string_only.sas" not in names


def test_cron_environment_and_comments_do_not_create_fake_jobs() -> None:
    workload = _discover()
    cron_jobs = [
        item for item in workload.artifacts if item.metadata.get("scheduler_format") == "cron"
    ]
    assert len(cron_jobs) == 1
    assert cron_jobs[0].metadata["schedule"] == "17 2 * * 1-5"


def test_literal_include_reconciles_to_inventoried_artifact_without_duplicate_placeholder() -> None:
    workload = _discover()
    include = next(
        item for item in workload.artifacts if item.logical_path == "includes/real_include.sas"
    )
    source = next(item for item in workload.artifacts if item.name == "edge_cases.sas")
    edges = {(item.source_id, item.kind, item.target_id) for item in workload.relationships}

    assert not include.metadata.get("placeholder")
    assert (source.artifact_id, RelationshipKind.INCLUDES, include.artifact_id) in edges
    assert (
        sum(1 for item in workload.artifacts if item.logical_path == "includes/real_include.sas")
        == 1
    )


def test_external_connection_inventory_is_redacted_and_does_not_invent_quoted_connections() -> None:
    workload = _discover()
    dependencies = {(item.kind, item.name): item for item in workload.external_dependencies}
    connection = dependencies[(ExternalDependencyKind.DATABASE_CONNECTION, "libref:src")]

    assert connection.system == "odbc"
    assert connection.metadata["connection_options"]["password"] == "<redacted>"
    payload = json.dumps(workload.to_dict())
    assert "SUPER_SECRET_DO_NOT_LEAK" not in payload
    assert "libref:fake" not in {item.name for item in workload.external_dependencies}


def test_shell_external_inventory_preserves_dynamic_requirements_safely() -> None:
    workload = _discover()
    keys = {(item.kind, item.name) for item in workload.external_dependencies}

    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "DYNAMIC_PROGRAM") in keys
    assert (ExternalDependencyKind.ENVIRONMENT_VARIABLE, "SAS_BIN") not in keys
    assert (ExternalDependencyKind.EXECUTABLE, "printf") not in keys
    assert (ExternalDependencyKind.EXECUTABLE, "commented_out.sas") not in keys


def test_unresolved_external_connection_has_no_resolved_graph_edge() -> None:
    workload = _discover()
    assert workload.dependency_graph is not None
    script = next(item for item in workload.artifacts if item.name == "run_mixed.sh")
    dependency = next(
        item
        for item in workload.external_dependencies
        if item.kind is ExternalDependencyKind.ENVIRONMENT_VARIABLE
        and item.name == "DYNAMIC_PROGRAM"
    )
    relationship = next(
        item
        for item in workload.relationships
        if item.source_id == script.artifact_id and item.target_id == dependency.dependency_id
    )

    assert any(
        item.source_id == script.artifact_id
        and item.domain is DependencyDomain.EXTERNAL
        and item.reference == "DYNAMIC_PROGRAM"
        and item.reason is DependencyResolutionReason.EXTERNAL
        for item in workload.dependency_graph.unresolved
    )
    assert (
        relationship.relationship_id
        in workload.dependency_graph.metadata["skipped_relationship_ids"]
    )
    assert not any(
        relationship.relationship_id in edge.relationship_ids
        for edge in workload.dependency_graph.edges
    )


def test_downstream_inventory_never_treats_missing_consumer_as_no_consumer() -> None:
    workload = _discover()
    assert workload.outputs
    unresolved = [
        item
        for item in workload.outputs
        if item.consumer_resolution is ConsumerResolution.UNRESOLVED
    ]
    assert unresolved
    assert all(item.consumer_ids == () for item in unresolved)
    assert all(item.metadata["consumer_scope"] == "discovered_estate" for item in workload.outputs)


def test_boundary_detection_is_explainable_and_does_not_absorb_referenced_only_jobs() -> None:
    workload = _discover()
    assert workload.boundaries
    external = next(item for item in workload.artifacts if item.name == "MISSING_EXTERNAL_JOB")
    assert all(external.artifact_id not in item.artifact_ids for item in workload.boundaries)
    assert all(item.metadata["requires_confirmation"] is True for item in workload.boundaries)
    assert workload.metadata["boundary_detection"]["confirmation_required"] is True


def test_current_state_topology_preserves_external_unknowns_without_claiming_completeness() -> None:
    workload = _discover()
    assert workload.topology is not None
    external = next(item for item in workload.artifacts if item.name == "MISSING_EXTERNAL_JOB")
    node = next(item for item in workload.topology.nodes if item.entity_id == external.artifact_id)
    assert node.metadata["definition_status"] == "referenced_only"
    assert workload.topology.metadata["complete_enterprise_topology"] is False
