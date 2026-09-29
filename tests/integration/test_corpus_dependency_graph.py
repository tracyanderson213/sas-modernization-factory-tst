from pathlib import Path

from smf.corpus.loader import load_corpus_manifest
from smf.discovery import discover_source
from smf.workload.models import EvidenceMethod, RelationshipKind

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "dependency-scheduler-foundation.yaml"

RELATIONSHIP_KINDS = {
    "depends-on": RelationshipKind.DEPENDS_ON,
    "includes": RelationshipKind.INCLUDES,
    "invokes": RelationshipKind.TRIGGERS,
    "reads": RelationshipKind.READS,
    "schedules": RelationshipKind.TRIGGERS,
    "writes": RelationshipKind.WRITES,
}


def _logical_path(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def test_corpus_06_expectations_are_observed_in_generated_dependency_graph() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.workload is not None
    root = manifest.workload.root
    workload = discover_source(root, provider="filesystem", namespace="corpus-06").workloads[0]
    assert workload.dependency_graph is not None

    artifacts = {item.logical_path: item for item in workload.artifacts}
    datasets = {item.location: item for item in workload.datasets}
    edges = workload.dependency_graph.edges

    for expectation in manifest.dependency_expectations:
        source_path = _logical_path(expectation.source_path, root)
        method = EvidenceMethod(expectation.evidence_method.replace("-", "_"))
        kind = RELATIONSHIP_KINDS[expectation.relationship]

        if expectation.resolution == "unresolved":
            matches = [
                item
                for item in workload.dependency_graph.unresolved
                if item.reference == expectation.unresolved_reference
                and (
                    item.source_id == artifacts[source_path].artifact_id
                    or any(
                        artifact.artifact_id == item.source_id
                        and artifact.logical_path.startswith(f"{source_path}#")
                        for artifact in workload.artifacts
                    )
                )
            ]
            assert matches, expectation.expectation_id
            assert any(evidence.method is method for item in matches for evidence in item.evidence)
            assert not any(
                edge.source_id in {item.source_id for item in matches}
                and edge.kind is kind
                and any(
                    node.node_id == edge.target_id
                    and node.label == expectation.unresolved_reference
                    for node in workload.dependency_graph.nodes
                )
                for edge in edges
            ), expectation.expectation_id
            continue

        assert expectation.target_path is not None
        target_path = _logical_path(expectation.target_path, root)
        if kind in {RelationshipKind.READS, RelationshipKind.WRITES}:
            target_id = datasets[target_path].dataset_id
        else:
            target_id = artifacts[target_path].artifact_id
        matches = [
            edge
            for edge in edges
            if edge.kind is kind
            and edge.target_id == target_id
            and (
                edge.source_id == artifacts[source_path].artifact_id
                or any(
                    artifact.artifact_id == edge.source_id
                    and artifact.logical_path.startswith(f"{source_path}#")
                    for artifact in workload.artifacts
                )
            )
        ]
        assert matches, expectation.expectation_id
        assert any(evidence.method is method for edge in matches for evidence in edge.evidence)
