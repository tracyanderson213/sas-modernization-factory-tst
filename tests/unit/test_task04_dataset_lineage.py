from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from smf.discovery import discover_source
from smf.discovery.dependency_graph import derive_dependency_graph
from smf.discovery.downstream import derive_downstream_outputs
from smf.discovery.lineage import derive_data_lineage
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    DataProducerResolution,
    DatasetIdentityResolution,
    DatasetKind,
    RelationshipKind,
)


def _discover(root: Path):
    return discover_source(root, provider="filesystem", namespace="task04").workloads[0]


def _artifact_bytes(workload, root: Path) -> dict[str, bytes]:
    return {
        item.artifact_id: (root / (item.logical_path or item.name)).read_bytes()
        for item in workload.artifacts
    }


def test_accesses_are_occurrence_and_revision_bound(tmp_path: Path) -> None:
    source = "data work.out; set source.claims; set source.claims; run;\n"
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis

    assert analysis is not None
    reads = [item for item in analysis.accesses if item.role is RelationshipKind.READS]
    assert len(reads) == 2
    assert len({item.access_id for item in reads}) == 2
    assert all(item.artifact_checksum == analysis.artifact_revisions[0][1] for item in reads)
    assert all(
        source.encode()[item.byte_start : item.byte_end] == b"source.claims" for item in reads
    )
    assert all(item.source_checksum == item.artifact_checksum for item in reads)
    assert all(item.span_digest for item in reads)
    assert analysis.source_closure_digest
    assert analysis.claim == "static_discovery_only"


def test_same_member_in_different_libraries_never_connects(tmp_path: Path) -> None:
    (tmp_path / "producer.sas").write_text(
        "libname left '/one'; data left.shared; run;\n", encoding="utf-8"
    )
    (tmp_path / "consumer.sas").write_text(
        "libname right '/two'; data work.out; set right.shared; run;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis
    assert analysis is not None
    assert not any(
        edge.kind in {RelationshipKind.PRECEDES, RelationshipKind.DEPENDS_ON}
        and edge.metadata.get("dependency_domain") == "data"
        for edge in workload.relationships
    )
    shared = [item for item in workload.datasets if item.name.endswith(".shared")]
    assert len(shared) == 2
    assert len({item.dataset_id for item in shared}) == 2


def test_conflicting_producers_are_retained_without_selected_dependency(tmp_path: Path) -> None:
    (tmp_path / "one.sas").write_text("data work.shared; run;\n", encoding="utf-8")
    (tmp_path / "two.sas").write_text("data work.shared; run;\n", encoding="utf-8")
    (tmp_path / "read.sas").write_text(
        "data work.report; set work.shared; run;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis
    assert analysis is not None
    shared = next(
        item for item in analysis.dataset_resolutions if item.dataset_name == "work.shared"
    )
    assert shared.producer_resolution is DataProducerResolution.CONFLICTING
    assert len(shared.candidate_producer_access_ids) == 2
    assert len(shared.candidate_producer_artifact_ids) == 2
    assert analysis.complete is False
    assert not any(
        item.kind in {RelationshipKind.PRECEDES, RelationshipKind.DEPENDS_ON}
        and item.metadata.get("via_dataset_name") == "work.shared"
        for item in workload.relationships
    )


def test_missing_and_unresolved_producers_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "read.sas").write_text(
        "data work.report; set unknown.claims; run;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis
    assert analysis is not None
    claims = next(
        item for item in analysis.dataset_resolutions if item.dataset_name == "unknown.claims"
    )
    assert claims.identity_resolution is DatasetIdentityResolution.UNRESOLVED
    assert claims.producer_resolution is DataProducerResolution.UNRESOLVED
    assert analysis.complete is False
    assert any(item.reason.value == "unresolved_identity" for item in analysis.blockers)


def test_empty_or_non_sas_inventory_cannot_claim_complete_lineage(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("not sas", encoding="utf-8")

    workload = _discover(tmp_path)

    assert workload.data_lineage_analysis is not None
    assert workload.data_lineage_analysis.complete is False
    assert workload.data_lineage_analysis.accesses == ()
    assert any(
        item.reason.value == "no_eligible_access"
        for item in workload.data_lineage_analysis.blockers
    )


def test_lineage_rejects_source_checksum_mismatch(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("data work.out; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.WRITES
    )
    relationship.evidence[0].metadata["source_checksum"] = "0" * 64

    with pytest.raises(ValueError, match="source checksum"):
        derive_data_lineage(workload, artifact_bytes=_artifact_bytes(workload, tmp_path))


def test_same_libref_rebound_per_artifact_does_not_connect(tmp_path: Path) -> None:
    (tmp_path / "write.sas").write_text(
        "libname mart '/one'; data mart.shared; run;\n", encoding="utf-8"
    )
    (tmp_path / "read.sas").write_text(
        "libname mart '/two'; data work.out; set mart.shared; run;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)

    shared = [item for item in workload.datasets if item.name == "mart.shared"]
    assert {item.location for item in shared} == {"/one/shared", "/two/shared"}
    assert not any(
        item.kind is RelationshipKind.DEPENDS_ON
        and item.metadata.get("dependency_domain") == "data"
        for item in workload.relationships
    )


def test_repeated_write_in_one_artifact_remains_conflicting_observations(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text(
        "data work.shared; run;\ndata work.shared; run;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis
    assert analysis is not None
    shared = next(
        item for item in analysis.dataset_resolutions if item.dataset_name == "work.shared"
    )
    assert shared.producer_resolution is DataProducerResolution.CONFLICTING
    assert len(shared.candidate_producer_access_ids) == 2
    produced = [
        item
        for item in workload.relationships
        if item.kind is RelationshipKind.PRODUCES and item.target_id == shared.dataset_id
    ]
    assert len(produced) == 2
    assert len({item.relationship_id for item in produced}) == 2


def test_malformed_kind_and_duplicate_identity_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("data work.out; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    dataset = workload.datasets[0]

    with pytest.raises(ValueError, match="Unsupported dataset kind"):
        derive_data_lineage(
            replace(workload, datasets=(replace(dataset, kind=cast(DatasetKind, "typo")),))
        )
    with pytest.raises(ValueError, match="Duplicate canonical dataset identity"):
        derive_data_lineage(replace(workload, datasets=(dataset, dataset)))


def test_secret_bearing_dataset_identity_is_rejected_before_hashing() -> None:
    builder = WorkloadBuilder(name="unsafe", namespace="task04")

    with pytest.raises(ValueError, match="unsafe value"):
        builder.add_dataset(
            kind=DatasetKind.FILE,
            name="claims.csv",
            location="https://user:secret-canary@host/claims.csv",
        )
    with pytest.raises(ValueError, match="unsafe value"):
        builder.add_dataset(
            kind=DatasetKind.SAS_DATASET,
            name="secret_canary_do_not_persist.members",
            system="secret_canary_do_not_persist",
        )


@pytest.mark.parametrize(
    ("source", "references"),
    [
        (
            "data work.out; merge work.left work.right; run;\n",
            {"work.out", "work.left", "work.right"},
        ),
        ("proc print data=work.input; run;\n", {"work.input"}),
        (
            "proc sort data=work.input out=work.output; run;\n",
            {"work.input", "work.output"},
        ),
        (
            "proc sql; create table work.out as select * from work.input; quit;\n",
            {"work.out", "work.input"},
        ),
        (
            'data work.out; infile "/tmp/in.csv"; file "/tmp/out.csv"; run;\n',
            {"work.out", "/tmp/in.csv", "/tmp/out.csv"},
        ),
    ],
)
def test_all_supported_access_scanners_retain_exact_source_spans(
    tmp_path: Path, source: str, references: set[str]
) -> None:
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.data_lineage_analysis
    assert analysis is not None
    observations = {
        item.normalized_reference: source.encode()[item.byte_start : item.byte_end].decode()
        for item in analysis.accesses
    }
    assert set(observations) == references
    assert all(observed.casefold() == reference for reference, observed in observations.items())


def test_caller_supplied_complete_claim_is_recomputed(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text(
        "data work.out; set source.missing; run;\n", encoding="utf-8"
    )
    workload = _discover(tmp_path)
    assert workload.data_lineage_analysis is not None
    asserted = replace(
        workload,
        data_lineage_analysis=replace(workload.data_lineage_analysis, complete=True, blockers=()),
    )

    rederived = derive_data_lineage(asserted, artifact_bytes=_artifact_bytes(asserted, tmp_path))

    assert rederived.data_lineage_analysis is not None
    assert rederived.data_lineage_analysis.complete is False
    assert rederived.data_lineage_analysis.blockers


def test_evidence_free_accesses_never_become_canonical_lineage() -> None:
    builder = WorkloadBuilder(name="unattested", namespace="task04")
    producer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="write.sas")
    consumer = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="read.sas")
    dataset = builder.add_dataset(
        kind=DatasetKind.INTERMEDIATE,
        name="work.shared",
        system="work",
    )
    builder.add_relationship(
        source_id=producer.artifact_id,
        kind=RelationshipKind.WRITES,
        target_id=dataset.dataset_id,
    )
    builder.add_relationship(
        source_id=consumer.artifact_id,
        kind=RelationshipKind.READS,
        target_id=dataset.dataset_id,
    )

    workload = derive_dependency_graph(
        derive_downstream_outputs(derive_data_lineage(builder.build()))
    )

    assert workload.data_lineage_analysis is not None
    assert workload.data_lineage_analysis.complete is False
    assert workload.data_lineage_analysis.accesses == ()
    assert not any(
        item.kind
        in {
            RelationshipKind.PRODUCES,
            RelationshipKind.CONSUMED_BY,
            RelationshipKind.PRECEDES,
            RelationshipKind.DEPENDS_ON,
        }
        for item in workload.relationships
    )
    assert workload.outputs == ()
    assert not workload.dependency_graph.edges


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("byte_start", 999_999),
        ("byte_end", 1_000_000),
        ("span_digest", "0" * 64),
        ("column", 999),
        ("access_id", "DACC-forged"),
    ],
)
def test_mutated_access_occurrence_evidence_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    (tmp_path / "main.sas").write_text("data work.out; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.WRITES
    )
    relationship.evidence[0].metadata[field] = value

    with pytest.raises(ValueError, match="Dataset access"):
        derive_data_lineage(workload, artifact_bytes=_artifact_bytes(workload, tmp_path))


def test_mutated_access_relationship_identity_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("data work.out; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    relationship = next(
        item for item in workload.relationships if item.kind is RelationshipKind.WRITES
    )
    relationships = tuple(
        replace(item, relationship_id="REL-forged") if item is relationship else item
        for item in workload.relationships
    )

    with pytest.raises(ValueError, match="relationship identity"):
        derive_data_lineage(
            replace(workload, relationships=relationships),
            artifact_bytes=_artifact_bytes(workload, tmp_path),
        )


def test_relative_external_files_are_source_scoped_and_unresolved(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "write.sas").write_text(
        'data _null_; file "shared.csv"; run;\n', encoding="utf-8"
    )
    (tmp_path / "b" / "read.sas").write_text(
        'data work.out; infile "shared.csv"; run;\n', encoding="utf-8"
    )

    workload = _discover(tmp_path)
    shared = [item for item in workload.datasets if item.name == "shared.csv"]

    assert len(shared) == 2
    assert len({item.dataset_id for item in shared}) == 2
    assert all(item.metadata["resolution"] == "provisional" for item in shared)
    assert not any(
        item.kind in {RelationshipKind.PRECEDES, RelationshipKind.DEPENDS_ON}
        and item.metadata.get("dependency_domain") == "data"
        for item in workload.relationships
    )
