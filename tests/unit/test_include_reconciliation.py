import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from smf.discovery import discover_source
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.discovery.include_reconciliation import reconcile_include_artifacts
from smf.readiness.engine import _include_relationship_valid
from smf.workload.models import (
    DependencyDomain,
    DependencyResolutionReason,
    EvidenceMethod,
    RelationshipKind,
)


def test_include_resolves_relative_to_including_program(tmp_path: Path) -> None:
    jobs = tmp_path / "jobs"
    shared = jobs / "shared"
    shared.mkdir(parents=True)
    (jobs / "main.sas").write_text('%include "shared/common.sas";\n', encoding="utf-8")
    (shared / "common.sas").write_text("%let ready=1;\n", encoding="utf-8")

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    artifacts = {item.logical_path: item for item in workload.artifacts}
    edges = {(item.source_id, item.kind, item.target_id) for item in workload.relationships}

    main = artifacts["jobs/main.sas"]
    common = artifacts["jobs/shared/common.sas"]
    assert (main.artifact_id, RelationshipKind.INCLUDES, common.artifact_id) in edges
    assert not any(item.metadata.get("placeholder") for item in workload.artifacts)


def test_missing_include_remains_explicit_placeholder(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text('%include "missing/common.sas";\n', encoding="utf-8")

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    placeholder = next(item for item in workload.artifacts if item.metadata.get("placeholder"))

    assert placeholder.logical_path == "missing/common.sas"


@pytest.mark.parametrize(
    "include_path",
    ("/includes/common.sas", "../includes/common.sas", r"C:\includes\common.sas"),
)
def test_include_outside_acquisition_root_does_not_resolve_to_inventory(
    tmp_path: Path, include_path: str
) -> None:
    includes = tmp_path / "includes"
    includes.mkdir()
    (includes / "common.sas").write_text("%let ready=1;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(f'%include "{include_path}";\n', encoding="utf-8")

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    assert workload.dependency_graph is not None
    main = next(item for item in workload.artifacts if item.name == "main.sas")
    common = next(item for item in workload.artifacts if item.logical_path == "includes/common.sas")
    include = next(
        item
        for item in workload.relationships
        if item.source_id == main.artifact_id and item.kind is RelationshipKind.INCLUDES
    )

    assert include.target_id != common.artifact_id
    assert include.metadata["include_resolution"] == "boundary_escape"
    assert any(
        item.source_id == main.artifact_id
        and item.domain is DependencyDomain.CODE
        and item.reference == include_path
        and item.reason is DependencyResolutionReason.UNSUPPORTED
        for item in workload.dependency_graph.unresolved
    )
    assert not any(
        edge.source_id == main.artifact_id
        and edge.kind is RelationshipKind.INCLUDES
        and edge.target_id == common.artifact_id
        for edge in workload.dependency_graph.edges
    )


def test_parent_relative_include_resolves_when_it_stays_inside_acquisition_root(
    tmp_path: Path,
) -> None:
    jobs = tmp_path / "jobs"
    includes = tmp_path / "includes"
    jobs.mkdir()
    includes.mkdir()
    (jobs / "main.sas").write_text('%include "../includes/common.sas";\n', encoding="utf-8")
    (includes / "common.sas").write_text("%let ready=1;\n", encoding="utf-8")

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    artifacts = {item.logical_path: item for item in workload.artifacts}

    assert any(
        item.source_id == artifacts["jobs/main.sas"].artifact_id
        and item.kind is RelationshipKind.INCLUDES
        and item.target_id == artifacts["includes/common.sas"].artifact_id
        for item in workload.relationships
    )

    relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )
    assert relationship.metadata["include_resolution"] == "resolved"
    assert relationship.metadata["include_resolution_id"].startswith("IRES-")
    assert relationship.metadata["include_policy_digest"]
    assert relationship.metadata["source_checksum"] == artifacts["jobs/main.sas"].checksum
    assert relationship.metadata["byte_end"] > relationship.metadata["byte_start"]
    assert relationship.metadata["span_digest"]
    assert relationship.metadata["candidate_artifacts"] == (
        {
            "artifact_id": artifacts["includes/common.sas"].artifact_id,
            "logical_path": "includes/common.sas",
            "checksum": artifacts["includes/common.sas"].checksum,
        },
    )


def test_repeated_literal_includes_have_occurrence_bound_resolution_identities(
    tmp_path: Path,
) -> None:
    source = '%include "inc.sas";\n%include "inc.sas";\n'
    (tmp_path / "inc.sas").write_text("%let ready=1;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")

    workload = discover_source(
        tmp_path, provider="filesystem", namespace="repeated-includes"
    ).workloads[0]
    main = next(item for item in workload.artifacts if item.logical_path == "main.sas")
    relationships = [
        item
        for item in workload.relationships
        if item.source_id == main.artifact_id and item.kind is RelationshipKind.INCLUDES
    ]
    assert len(relationships) == 2
    assert len({item.relationship_id for item in relationships}) == 2
    assert len({item.metadata["include_resolution_id"] for item in relationships}) == 2

    expected_starts = [
        index for index in range(len(source)) if source.startswith("%include", index)
    ]
    assert sorted(item.metadata["byte_start"] for item in relationships) == expected_starts
    raw = source.encode("utf-8")
    for relationship in relationships:
        start = relationship.metadata["byte_start"]
        end = relationship.metadata["byte_end"]
        assert relationship.metadata["span_digest"] == hashlib.sha256(raw[start:end]).hexdigest()

    analysis = workload.macro_analysis
    assert analysis is not None
    include_resolutions = [
        item
        for item in analysis.resolutions
        if item.relationship_kind.value == "sas_include_reference"
    ]
    assert len(include_resolutions) == 2
    assert len({item.resolution_id for item in include_resolutions}) == 2
    assert {item.resolution_id for item in include_resolutions} == {
        item.metadata["include_resolution_id"] for item in relationships
    }
    assert analysis.complete is True

    assert workload.dependency_graph is not None
    graph_edges = [
        item
        for item in workload.dependency_graph.edges
        if item.source_id == main.artifact_id and item.kind is RelationshipKind.INCLUDES
    ]
    assert len(graph_edges) == 1

    payload = workload.to_dict()
    artifact_by_id = {item["artifact_id"]: item for item in payload["artifacts"]}
    include_payloads = [item for item in payload["relationships"] if item["kind"] == "includes"]
    assert all(
        _include_relationship_valid(payload["workload_id"], item, artifact_by_id)
        for item in include_payloads
    )


def test_absolute_and_root_escaping_includes_are_boundary_escape_not_missing(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.sas").write_text(
        '%include "/outside.sas";\n%include "../outside.sas";\n', encoding="utf-8"
    )

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    includes = [item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES]

    assert {item.metadata["include_resolution"] for item in includes} == {"boundary_escape"}
    assert {item.reason for item in workload.dependency_graph.unresolved} == {
        DependencyResolutionReason.UNSUPPORTED
    }
    assert not [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.INCLUDES
    ]


def test_include_cycle_is_preserved_as_blocking_evidence_not_qualified_edges(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.sas").write_text('%include "b.sas";\n', encoding="utf-8")
    (tmp_path / "b.sas").write_text('%include "a.sas";\n', encoding="utf-8")

    workload = discover_source(
        tmp_path, provider="filesystem", namespace="include-cycle"
    ).workloads[0]
    includes = [item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES]

    assert {item.metadata["include_resolution"] for item in includes} == {"cyclic"}
    assert {item.reason for item in workload.dependency_graph.unresolved} == {
        DependencyResolutionReason.CYCLIC
    }
    assert not [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.INCLUDES
    ]
    assert all(len(boundary.artifact_ids) == 1 for boundary in workload.boundaries)


def test_unknown_include_resolution_is_rejected_by_graph_projection(tmp_path: Path) -> None:
    (tmp_path / "inc.sas").write_text("%let ready=1;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text('%include "inc.sas";\n', encoding="utf-8")
    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    relationships = tuple(
        replace(item, metadata={**item.metadata, "include_resolution": "resovled"})
        if item.kind is RelationshipKind.INCLUDES
        else item
        for item in workload.relationships
    )

    with pytest.raises(ValueError, match="Unsupported include resolution"):
        derive_dependency_graph(replace(workload, relationships=relationships))


def test_case_folded_duplicate_candidates_are_ambiguous(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text('%include "shared.sas";\n', encoding="utf-8")
    discovered = discover_source(tmp_path, provider="filesystem").workloads[0]
    placeholder = next(item for item in discovered.artifacts if item.metadata.get("placeholder"))
    inventory_evidence = next(
        evidence
        for artifact in discovered.artifacts
        for evidence in artifact.evidence
        if evidence.method is EvidenceMethod.FILESYSTEM
    )
    first = replace(
        placeholder,
        artifact_id="ART-case-upper",
        logical_path="Shared.sas",
        checksum="a" * 64,
        evidence=(inventory_evidence,),
        metadata={},
    )
    second = replace(
        placeholder,
        artifact_id="ART-case-lower",
        logical_path="shared.sas",
        checksum="b" * 64,
        evidence=(inventory_evidence,),
        metadata={},
    )
    relationships = tuple(
        replace(item, metadata={}) if item.kind is RelationshipKind.INCLUDES else item
        for item in discovered.relationships
    )
    workload = reconcile_include_artifacts(
        replace(
            discovered,
            artifacts=(*discovered.artifacts, first, second),
            relationships=relationships,
        )
    )
    include = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )

    assert include.metadata["include_resolution"] == "ambiguous"
    assert len(include.metadata["candidate_artifacts"]) == 2
    assert not [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.INCLUDES
    ]


def test_resolution_identity_cannot_be_replayed_or_self_asserted(tmp_path: Path) -> None:
    (tmp_path / "inc.sas").write_text("%let ready=1;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text('%include "inc.sas";\n', encoding="utf-8")
    payload = discover_source(tmp_path, provider="filesystem").workloads[0].to_dict()
    relationship = next(item for item in payload["relationships"] if item["kind"] == "includes")
    artifact_by_id = {item["artifact_id"]: item for item in payload["artifacts"]}

    assert _include_relationship_valid(payload["workload_id"], relationship, artifact_by_id)
    asserted = {
        **relationship,
        "metadata": {**relationship["metadata"], "include_resolution_id": "IRES-asserted"},
    }
    assert not _include_relationship_valid(payload["workload_id"], asserted, artifact_by_id)
    assert not _include_relationship_valid("WL-other", relationship, artifact_by_id)


def test_caller_authored_candidate_cannot_authorize_resolution(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text('%include "ghost.sas";\n', encoding="utf-8")
    discovered = discover_source(tmp_path, provider="filesystem").workloads[0]
    placeholder = next(item for item in discovered.artifacts if item.metadata.get("placeholder"))
    asserted_candidate = replace(
        placeholder,
        artifact_id="ART-caller-asserted",
        checksum=None,
        evidence=(),
        metadata={},
    )
    relationships = tuple(
        replace(item, metadata={}) if item.kind is RelationshipKind.INCLUDES else item
        for item in discovered.relationships
    )

    workload = reconcile_include_artifacts(
        replace(
            discovered,
            artifacts=(*discovered.artifacts, asserted_candidate),
            relationships=relationships,
        )
    )
    include = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )

    assert include.metadata["include_resolution"] == "missing"
    assert include.metadata["candidate_artifacts"] == ()
    assert include.target_id != asserted_candidate.artifact_id


def test_percent_encoded_path_is_unsupported_not_normalized(tmp_path: Path) -> None:
    (tmp_path / "outside.sas").write_text("%let unsafe=1;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text('%include "%2e%2e/outside.sas";\n', encoding="utf-8")

    workload = discover_source(tmp_path, provider="filesystem").workloads[0]
    include = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )

    assert include.metadata["include_resolution"] == "unsupported"
    assert not [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.INCLUDES
    ]


def test_symlink_mediated_include_cannot_escape_acquisition_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.sas"
    outside.write_text("%let unsafe=1;\n", encoding="utf-8")
    (root / "linked.sas").symlink_to(outside)
    (root / "main.sas").write_text('%include "linked.sas";\n', encoding="utf-8")

    workload = discover_source(root, provider="filesystem").workloads[0]
    include = next(
        item for item in workload.relationships if item.kind is RelationshipKind.INCLUDES
    )

    assert include.metadata["include_resolution"] == "boundary_escape"
    assert not [
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.INCLUDES
    ]


def test_duplicate_artifact_identity_is_rejected_before_candidate_indexing(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text('%include "missing.sas";\n', encoding="utf-8")
    workload = discover_source(tmp_path, provider="filesystem").workloads[0]

    with pytest.raises(ValueError, match="Duplicate artifact identity"):
        reconcile_include_artifacts(
            replace(workload, artifacts=(*workload.artifacts, workload.artifacts[0]))
        )
