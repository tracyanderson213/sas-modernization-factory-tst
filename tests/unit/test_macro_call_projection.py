from dataclasses import replace
from pathlib import Path

import pytest

from smf.discovery import discover_source
from smf.discovery.code_dependencies import derive_code_dependencies
from smf.workload.models import MacroResolutionKind, RelationshipKind


@pytest.mark.parametrize(
    "source",
    [
        "%macro x; %x; %mend; %x;\n",
        "%x; %macro x; %x; %mend;\n",
    ],
)
def test_same_line_calls_keep_recursive_and_resolved_occurrences(
    tmp_path: Path, source: str
) -> None:
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")
    workload = discover_source(tmp_path).workloads[0]
    analysis = workload.macro_analysis
    assert analysis is not None
    observations = {item.observation_id: item for item in analysis.observations}
    calls = {
        item.kind: item
        for item in analysis.resolutions
        if observations[item.observation_id].normalized_identity == "x"
    }
    recursive = calls[MacroResolutionKind.RECURSIVE]
    resolved = calls[MacroResolutionKind.UNIQUE_STATIC_DEFINITION]
    findings = workload.artifacts[0].metadata["macro_call_findings"]
    assert {item["resolution"] for item in findings} == {"recursive", "resolved"}
    assert {item["macro_resolution_id"] for item in findings} == {
        recursive.resolution_id,
        resolved.resolution_id,
    }
    for finding in findings:
        observation = observations[finding["macro_observation_id"]]
        assert finding["byte_start"] == observation.location.byte_start
        assert finding["byte_end"] == observation.location.byte_end

    edge = next(item for item in workload.relationships if item.kind is RelationshipKind.CALLS)
    assert edge.metadata["macro_resolution_ids"] == (resolved.resolution_id,)
    assert len(edge.evidence) == 1
    assert edge.evidence[0].metadata["macro_observation_id"] == resolved.observation_id
    assert workload.dependency_graph is not None
    unresolved = [item for item in workload.dependency_graph.unresolved if item.reference == "x"]
    assert len(unresolved) == 1
    assert unresolved[0].reason.value == "recursive"
    assert unresolved[0].metadata["macro_resolution_id"] == recursive.resolution_id


@pytest.mark.parametrize(
    "source, resolved",
    [
        ("%macro x; %mend; %x; %x;\n", True),
        ("%x; %x;\n", False),
        ("%&x; %&x;\n", False),
    ],
)
def test_repeated_same_line_calls_retain_all_occurrence_evidence(
    tmp_path: Path, source: str, resolved: bool
) -> None:
    (tmp_path / "main.sas").write_text(source, encoding="utf-8")
    workload = discover_source(tmp_path).workloads[0]
    findings = workload.artifacts[0].metadata["macro_call_findings"]
    assert len(findings) == 2
    resolution_ids = {item["macro_resolution_id"] for item in findings}
    assert len(resolution_ids) == 2
    assert len({item["byte_start"] for item in findings}) == 2
    if resolved:
        edge = next(item for item in workload.relationships if item.kind is RelationshipKind.CALLS)
        assert set(edge.metadata["macro_resolution_ids"]) == resolution_ids
        assert len(edge.evidence) == 2
        assert {item.metadata["macro_resolution_id"] for item in edge.evidence} == resolution_ids
    else:
        assert workload.dependency_graph is not None
        unresolved = [
            item for item in workload.dependency_graph.unresolved if item.domain == "code"
        ]
        assert len(unresolved) == 2
        assert {item.metadata["macro_resolution_id"] for item in unresolved} == resolution_ids
        assert len({item.evidence[0].evidence_id for item in unresolved}) == 2


def test_missing_canonical_resolution_does_not_fall_back_to_name_matching(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("%macro x; %mend; %x;\n", encoding="utf-8")
    workload = discover_source(tmp_path).workloads[0]
    assert workload.macro_analysis is not None
    incomplete = replace(
        workload,
        macro_analysis=replace(workload.macro_analysis, resolutions=(), complete=False),
        relationships=(),
    )
    projected = derive_code_dependencies(incomplete)
    assert not any(item.kind is RelationshipKind.CALLS for item in projected.relationships)
    assert not projected.artifacts[0].metadata.get("macro_call_findings")
