from dataclasses import replace
from pathlib import Path

from smf.discovery import discover_source
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.workload.models import DependencyDomain, DependencyResolutionReason, RelationshipKind


def test_graph_is_deterministic_idempotent_and_checkout_independent(tmp_path: Path) -> None:
    roots = (tmp_path / "one" / "estate", tmp_path / "two" / "estate")
    for root in roots:
        root.mkdir(parents=True)
        (root / "producer.sas").write_text("data work.shared; run;\n", encoding="utf-8")
        (root / "consumer.sas").write_text(
            "data work.out; set work.shared; run;\n", encoding="utf-8"
        )

    first = discover_source(roots[0], provider="filesystem", namespace="stable").workloads[0]
    second = discover_source(roots[1], provider="filesystem", namespace="stable").workloads[0]
    assert first.dependency_graph == second.dependency_graph
    assert derive_dependency_graph(first).dependency_graph == first.dependency_graph
    assert first.dependency_graph is not None
    assert first.dependency_graph.metadata["complete_enterprise_graph"] is False
    assert first.dependency_graph.metadata["transitive_edges_inferred"] is False
    assert list(first.dependency_graph.nodes) == sorted(
        first.dependency_graph.nodes, key=lambda item: item.node_id
    )
    assert list(first.dependency_graph.edges) == sorted(
        first.dependency_graph.edges, key=lambda item: item.edge_id
    )


def test_graph_preserves_dynamic_and_missing_targets_without_edges(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text(
        "%include 'missing.sas';\ndata &target.; set source.input; run;\n",
        encoding="utf-8",
    )
    workload = discover_source(tmp_path, provider="filesystem", namespace="unresolved").workloads[0]
    assert workload.dependency_graph is not None
    main = next(item for item in workload.artifacts if item.name == "main.sas")
    unresolved = [
        item for item in workload.dependency_graph.unresolved if item.source_id == main.artifact_id
    ]

    assert any(
        item.reference == "missing.sas"
        and item.domain is DependencyDomain.CODE
        and item.reason is DependencyResolutionReason.MISSING
        for item in unresolved
    )
    assert any(
        item.reference == "&target."
        and item.domain is DependencyDomain.DATA
        and item.reason is DependencyResolutionReason.DYNAMIC
        for item in unresolved
    )
    include_relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )
    assert (
        include_relationship.relationship_id
        in workload.dependency_graph.metadata["skipped_relationship_ids"]
    )
    assert not any(
        edge.relationship_ids == (include_relationship.relationship_id,)
        for edge in workload.dependency_graph.edges
    )


def test_dataset_option_macro_variable_is_not_an_unresolved_data_target(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text(
        "data work.output(label=&label); set work.input(obs=&limit); run;\n",
        encoding="utf-8",
    )

    workload = discover_source(
        tmp_path, provider="filesystem", namespace="dataset-options"
    ).workloads[0]
    main = next(item for item in workload.artifacts if item.name == "main.sas")
    assert workload.dependency_graph is not None

    assert {item.name for item in workload.datasets} == {"work.input", "work.output"}
    assert not any(
        item.source_id == main.artifact_id and item.domain is DependencyDomain.DATA
        for item in workload.dependency_graph.unresolved
    )


def test_graph_classifies_macro_variable_include_as_dynamic(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text(
        '%include "&root./common.sas";\n',
        encoding="utf-8",
    )

    result = discover_source(tmp_path, provider="filesystem", namespace="dynamic-include")
    workload = result.workloads[0]
    assert workload.dependency_graph is not None
    main = next(item for item in workload.artifacts if item.name == "main.sas")
    include = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )
    unresolved = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == main.artifact_id and item.reference == "&root./common.sas"
    )

    assert include.metadata["include_resolution"] == "dynamic"
    assert unresolved.reason is DependencyResolutionReason.DYNAMIC
    assert include.relationship_id in workload.dependency_graph.metadata["skipped_relationship_ids"]
    assert not any(
        include.relationship_id in edge.relationship_ids for edge in workload.dependency_graph.edges
    )


def test_graph_preserves_dynamic_proc_dataset_options_as_unresolved(tmp_path: Path) -> None:
    (tmp_path / "sort.sas").write_text(
        "proc sort data=&input. out=&output.; run;\n",
        encoding="utf-8",
    )

    workload = discover_source(tmp_path, provider="filesystem", namespace="dynamic-proc").workloads[
        0
    ]
    artifact = next(item for item in workload.artifacts if item.name == "sort.sas")
    unresolved = {
        (item.reference, item.domain, item.reason)
        for item in workload.dependency_graph.unresolved
        if item.source_id == artifact.artifact_id
    }

    assert unresolved == {
        ("&input.", DependencyDomain.DATA, DependencyResolutionReason.DYNAMIC),
        ("&output.", DependencyDomain.DATA, DependencyResolutionReason.DYNAMIC),
    }
    assert not workload.datasets


def test_graph_preserves_cycles_without_adding_order(tmp_path: Path) -> None:
    (tmp_path / "a.sas").write_text(
        "%include 'b.sas';\n%macro a; %b; %mend;\n%a;\n", encoding="utf-8"
    )
    (tmp_path / "b.sas").write_text("%include 'a.sas';\n%macro b; %a; %mend;\n", encoding="utf-8")
    workload = discover_source(tmp_path, provider="filesystem", namespace="cycle").workloads[0]
    assert workload.dependency_graph is not None
    call_edges = [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.CALLS
    ]
    artifacts = {item.name: item for item in workload.artifacts}

    # The include cycle is not a qualified visibility path, so cross-file calls
    # remain missing while the include observations themselves carry the cycle.
    assert not {
        (artifacts["a.sas"].artifact_id, artifacts["b.sas"].artifact_id),
        (artifacts["b.sas"].artifact_id, artifacts["a.sas"].artifact_id),
    } & {(item.source_id, item.target_id) for item in call_edges}
    assert {
        (artifacts["a.sas"].artifact_id, "b", DependencyResolutionReason.MISSING),
        (artifacts["b.sas"].artifact_id, "a", DependencyResolutionReason.MISSING),
    }.issubset(
        {
            (item.source_id, item.reference, item.reason)
            for item in workload.dependency_graph.unresolved
        }
    )
    assert {
        (artifacts["a.sas"].artifact_id, "b.sas", DependencyResolutionReason.CYCLIC),
        (artifacts["b.sas"].artifact_id, "a.sas", DependencyResolutionReason.CYCLIC),
    }.issubset(
        {
            (item.source_id, item.reference, item.reason)
            for item in workload.dependency_graph.unresolved
        }
    )
    assert not any(
        item.kind is RelationshipKind.PRECEDES
        and {item.source_id, item.target_id}
        == {artifacts["a.sas"].artifact_id, artifacts["b.sas"].artifact_id}
        for item in workload.dependency_graph.edges
    )


def test_graph_rebuild_replaces_stale_projection(tmp_path: Path) -> None:
    (tmp_path / "only.sas").write_text("data work.x; run;\n", encoding="utf-8")
    workload = discover_source(tmp_path, provider="filesystem", namespace="rebuild").workloads[0]
    rebuilt = derive_dependency_graph(replace(workload, dependency_graph=None))
    assert rebuilt.dependency_graph == workload.dependency_graph


def test_graph_identity_changes_when_source_revision_changes(tmp_path: Path) -> None:
    source = tmp_path / "main.sas"
    source.write_text("data work.first; run;\n", encoding="utf-8")
    first = discover_source(tmp_path, provider="filesystem", namespace="revision").workloads[0]
    source.write_text("data work.second; run;\n", encoding="utf-8")
    second = discover_source(tmp_path, provider="filesystem", namespace="revision").workloads[0]

    assert first.workload_id == second.workload_id
    assert first.code_dependency_analysis is not None
    assert second.code_dependency_analysis is not None
    assert (
        first.code_dependency_analysis.source_closure_digest
        != second.code_dependency_analysis.source_closure_digest
    )
    assert first.dependency_graph is not None
    assert second.dependency_graph is not None
    assert first.dependency_graph.graph_id != second.dependency_graph.graph_id
