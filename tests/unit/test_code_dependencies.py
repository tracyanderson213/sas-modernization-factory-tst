import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from smf.discovery import discover_source
from smf.discovery.code_dependency_analysis import derive_code_dependency_analysis
from smf.discovery.code_dependency_qualification import (
    code_dependency_result_path,
    qualify_code_dependencies,
    write_code_dependency_result,
)
from smf.workload.models import (
    CodeDependencyResolutionKind,
    DependencyResolutionReason,
    RelationshipKind,
)


def _discover(root: Path):
    return discover_source(root, provider="filesystem", namespace="code-deps").workloads[0]


def test_unique_macro_definition_creates_evidence_backed_calls_edge(tmp_path: Path) -> None:
    (tmp_path / "macros").mkdir()
    (tmp_path / "macros" / "common.sas").write_text("%macro common; %mend;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(
        "%include 'macros/common.sas';\n%common;\n%common;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    calls = [item for item in workload.relationships if item.kind is RelationshipKind.CALLS]

    assert len(calls) == 1
    assert calls[0].source_id == artifacts["main.sas"].artifact_id
    assert calls[0].target_id == artifacts["common.sas"].artifact_id
    assert len(calls[0].evidence) == 2
    assert workload.dependency_graph is not None
    edge = next(
        item for item in workload.dependency_graph.edges if item.kind is RelationshipKind.CALLS
    )
    assert edge.relationship_ids == (calls[0].relationship_id,)
    assert {item.evidence_id for item in edge.evidence} == {
        item.evidence_id for item in calls[0].evidence
    }
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.analysis_complete is True
    assert analysis.ordering_eligible is True
    assert analysis.source_closure_digest
    assert analysis.claim == "static_discovery_only"
    assert analysis.generated is False
    assert analysis.executed is False
    assert analysis.validated is False
    assert analysis.parity_passed is False
    assert analysis.human_approved is False
    assert len(analysis.occurrences) == 3
    assert {item.resolution for item in analysis.occurrences} == {
        CodeDependencyResolutionKind.RESOLVED
    }
    assert all(item.byte_end > item.byte_start for item in analysis.occurrences)
    assert all(item.source_checksum and item.span_digest for item in analysis.occurrences)
    assert all(item.target_checksum for item in analysis.occurrences)
    assert analysis.ordering_groups[-1].artifact_ids == (artifacts["main.sas"].artifact_id,)


def test_parameterless_macro_call_without_semicolon_creates_calls_edge(tmp_path: Path) -> None:
    (tmp_path / "helper.sas").write_text("%macro helper; %mend;\n", encoding="utf-8")
    (tmp_path / "caller.sas").write_text("%include 'helper.sas';\n%helper\n", encoding="utf-8")

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    call = next(item for item in workload.relationships if item.kind is RelationshipKind.CALLS)

    assert call.source_id == artifacts["caller.sas"].artifact_id
    assert call.target_id == artifacts["helper.sas"].artifact_id
    caller = artifacts["caller.sas"]
    findings = caller.metadata["macro_call_findings"]
    assert [
        {key: item[key] for key in ("reference", "line", "resolution", "target_artifact_id")}
        for item in findings
    ] == [
        {
            "reference": "helper",
            "line": 2,
            "resolution": "resolved",
            "target_artifact_id": artifacts["helper.sas"].artifact_id,
        }
    ]
    assert findings[0]["macro_resolution_id"] == call.metadata["macro_resolution_id"]
    assert findings[0]["macro_observation_id"] == call.evidence[0].metadata["macro_observation_id"]


def test_macro_call_inside_double_quoted_string_creates_calls_edge(tmp_path: Path) -> None:
    (tmp_path / "helper.sas").write_text("%macro helper; %mend;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(
        "%include 'helper.sas';\ntitle \"%helper();\";\ntitle '%helper();';\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    calls = [item for item in workload.relationships if item.kind is RelationshipKind.CALLS]

    assert len(calls) == 1
    assert calls[0].source_id == artifacts["main.sas"].artifact_id
    assert calls[0].target_id == artifacts["helper.sas"].artifact_id
    assert calls[0].evidence[0].locator == "main.sas:2"


def test_inline_statement_comment_does_not_create_calls_edge(tmp_path: Path) -> None:
    (tmp_path / "helper.sas").write_text("%macro helper; %mend;\n", encoding="utf-8")
    (tmp_path / "caller.sas").write_text(
        "data x; * %helper; run;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    caller = next(item for item in workload.artifacts if item.name == "caller.sas")

    assert not any(
        item.kind is RelationshipKind.CALLS and item.source_id == caller.artifact_id
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    assert not any(
        item.source_id == caller.artifact_id and item.reference == "helper"
        for item in workload.dependency_graph.unresolved
    )


def test_nrstr_literal_does_not_create_calls_edge(tmp_path: Path) -> None:
    (tmp_path / "helper.sas").write_text("%macro helper; %mend;\n", encoding="utf-8")
    (tmp_path / "caller.sas").write_text(
        "%let literal=%nrstr(%helper);\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    caller = next(item for item in workload.artifacts if item.name == "caller.sas")

    assert not any(
        item.kind is RelationshipKind.CALLS and item.source_id == caller.artifact_id
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    assert not any(
        item.source_id == caller.artifact_id and item.reference == "helper"
        for item in workload.dependency_graph.unresolved
    )


def test_dataset_option_macro_variables_do_not_create_unresolved_data_dependencies(
    tmp_path: Path,
) -> None:
    (tmp_path / "caller.sas").write_text(
        'data work.output(label="&label");\n'
        "  set work.input(obs=&limit where=(member_id=&member_id));\n"
        "run;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    caller = next(item for item in workload.artifacts if item.name == "caller.sas")

    assert workload.dependency_graph is not None
    assert not any(
        item.source_id == caller.artifact_id
        and item.reference in {"&label", "&limit", "&member_id"}
        for item in workload.dependency_graph.unresolved
    )


def test_ambiguous_missing_and_dynamic_macro_calls_do_not_invent_targets(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.sas").write_text("%macro duplicate; %mend;\n", encoding="utf-8")
    (tmp_path / "b.sas").write_text("%macro duplicate; %mend;\n", encoding="utf-8")
    (tmp_path / "caller.sas").write_text(
        "%include 'a.sas';\n%include 'b.sas';\n"
        "/* %phantom; */\n%put '%quoted;';\n%duplicate;\n%missing;\n%&selected;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    caller = next(item for item in workload.artifacts if item.name == "caller.sas")
    assert not any(
        item.kind is RelationshipKind.CALLS and item.source_id == caller.artifact_id
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    unresolved = {
        (item.reference, item.reason)
        for item in workload.dependency_graph.unresolved
        if item.source_id == caller.artifact_id
    }
    assert ("duplicate", DependencyResolutionReason.AMBIGUOUS) in unresolved
    assert ("missing", DependencyResolutionReason.MISSING) in unresolved
    assert ("&selected", DependencyResolutionReason.DYNAMIC) in unresolved
    assert all(reference not in {"phantom", "quoted"} for reference, _reason in unresolved)
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.analysis_complete is True
    assert analysis.ordering_eligible is False
    assert {item.resolution for item in analysis.occurrences} >= {
        CodeDependencyResolutionKind.AMBIGUOUS,
        CodeDependencyResolutionKind.MISSING,
        CodeDependencyResolutionKind.DYNAMIC,
    }
    assert analysis.blockers


def test_code_analysis_preserves_include_cycle_as_typed_group(tmp_path: Path) -> None:
    (tmp_path / "a.sas").write_text('%include "b.sas";\n', encoding="utf-8")
    (tmp_path / "b.sas").write_text('%include "a.sas";\n', encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.analysis_complete is True
    assert analysis.ordering_eligible is False
    assert len(analysis.ordering_groups) == 1
    assert analysis.ordering_groups[0].cyclic is True
    assert len(analysis.ordering_groups[0].artifact_ids) == 2
    assert {item.resolution for item in analysis.occurrences} == {
        CodeDependencyResolutionKind.CYCLIC
    }


def test_code_analysis_preserves_recursive_call_as_typed_group(tmp_path: Path) -> None:
    (tmp_path / "recursive.sas").write_text(
        "%macro recurse; %recurse; %mend;\n%recurse;\n", encoding="utf-8"
    )

    workload = _discover(tmp_path)
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.analysis_complete is True
    assert analysis.ordering_eligible is False
    assert len(analysis.ordering_groups) == 1
    assert analysis.ordering_groups[0].cyclic is True
    assert any(
        item.resolution is CodeDependencyResolutionKind.RECURSIVE for item in analysis.occurrences
    )


def test_empty_inventory_fails_closed_without_eligible_subject(tmp_path: Path) -> None:
    (tmp_path / "settings.yaml").write_text("enabled: true\n", encoding="utf-8")

    workload = _discover(tmp_path)
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.analysis_complete is False
    assert analysis.ordering_eligible is False
    assert any(item.reason.value == "no_eligible_subject" for item in analysis.blockers)


def test_code_analysis_rejects_unknown_resolution_enum(tmp_path: Path) -> None:
    (tmp_path / "missing.sas").write_text("%missing;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    artifact = next(item for item in workload.artifacts if item.name == "missing.sas")
    findings = [dict(item) for item in artifact.metadata["macro_call_findings"]]
    findings[0]["resolution"] = "resovled"
    mutated = replace(artifact, metadata={**artifact.metadata, "macro_call_findings": findings})

    with pytest.raises(ValueError, match="Unsupported code dependency resolution"):
        derive_code_dependency_analysis(
            replace(workload, artifacts=(mutated,), code_dependency_analysis=None)
        )


def test_code_analysis_rejects_duplicate_occurrence_identity(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("%missing;\n%other;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    artifact = next(item for item in workload.artifacts if item.name == "main.sas")
    findings = [dict(item) for item in artifact.metadata["macro_call_findings"]]
    findings[1]["macro_resolution_id"] = findings[0]["macro_resolution_id"]
    mutated = replace(artifact, metadata={**artifact.metadata, "macro_call_findings": findings})

    with pytest.raises(ValueError, match="Duplicate code dependency occurrence identity"):
        derive_code_dependency_analysis(
            replace(workload, artifacts=(mutated,), code_dependency_analysis=None)
        )


def test_code_analysis_rejects_dropped_observation(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("%missing;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    artifact = next(item for item in workload.artifacts if item.name == "main.sas")
    mutated = replace(artifact, metadata={**artifact.metadata, "macro_call_findings": []})

    with pytest.raises(ValueError, match="not classified exactly once"):
        derive_code_dependency_analysis(
            replace(workload, artifacts=(mutated,), code_dependency_analysis=None)
        )


def test_code_analysis_rejects_unbound_occurrence_evidence(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("%missing;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    artifact = next(item for item in workload.artifacts if item.name == "main.sas")
    findings = [dict(item) for item in artifact.metadata["macro_call_findings"]]
    findings[0].pop("span_digest")
    mutated = replace(artifact, metadata={**artifact.metadata, "macro_call_findings": findings})

    with pytest.raises(ValueError, match="span_digest"):
        derive_code_dependency_analysis(
            replace(workload, artifacts=(mutated,), code_dependency_analysis=None)
        )


def test_qualified_result_is_bound_isolated_and_recovers_telemetry(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    path = write_code_dependency_result(
        output_root, payload, workload=workload, source_root=source_root
    )
    telemetry = path.with_name("telemetry.json")
    assert path.is_file()
    assert telemetry.is_file()
    assert payload["disposition"] == "qualified"
    assert payload["claims"]["executed"] is False

    canonical_before = path.read_bytes()
    telemetry_before = telemetry.read_bytes()
    assert (
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )
        == path
    )
    assert path.read_bytes() == canonical_before
    assert telemetry.read_bytes() == telemetry_before

    telemetry.unlink()
    assert (
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )
        == path
    )
    assert telemetry.is_file()

    second = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-2",
        execution_id="EXEC-2",
    )
    second_path = write_code_dependency_result(
        output_root, second, workload=workload, source_root=source_root
    )
    assert second_path != path
    assert path.read_bytes()


def test_publication_rejects_result_symlink_escape_without_telemetry(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    result_path = code_dependency_result_path(output_root, payload)
    result_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside-result.json"
    outside.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result_path.symlink_to(outside)

    with pytest.raises(ValueError, match="evidence path is unsafe"):
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )

    assert not result_path.with_name("telemetry.json").exists()


def test_recovery_rejects_telemetry_symlink_escape(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    result_path = write_code_dependency_result(
        output_root, payload, workload=workload, source_root=source_root
    )
    telemetry_path = result_path.with_name("telemetry.json")
    outside = tmp_path / "outside-telemetry.json"
    outside.write_bytes(telemetry_path.read_bytes())
    telemetry_path.unlink()
    telemetry_path.symlink_to(outside)

    with pytest.raises(ValueError, match="evidence path is unsafe"):
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )


@pytest.mark.parametrize("target", ["result", "telemetry"])
def test_publication_rejects_non_regular_targets(tmp_path: Path, target: str) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    result_path = code_dependency_result_path(output_root, payload)
    if target == "result":
        result_path.parent.mkdir(parents=True)
        result_path.mkdir()
    else:
        result_path = write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )
        result_path.with_name("telemetry.json").unlink()
        result_path.with_name("telemetry.json").mkdir()

    with pytest.raises(ValueError, match="evidence path is unsafe"):
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )


def test_publication_rejects_traversal_identity(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )

    with pytest.raises(ValueError, match="Unsafe run_id"):
        write_code_dependency_result(
            tmp_path / "evidence",
            {**payload, "run_id": "../escape"},
            workload=workload,
            source_root=source_root,
        )


def test_qualification_rejects_source_mutation_and_unsafe_identity(tmp_path: Path) -> None:
    source = tmp_path / "main.sas"
    source.write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")

    with pytest.raises(ValueError, match="Unsafe client_id"):
        qualify_code_dependencies(
            workload,
            source_root=tmp_path,
            client_id="../CLIENT",
            subject_id=subject.artifact_id,
            run_id="RUN-1",
            attempt_id="ATTEMPT-1",
            execution_id="EXEC-1",
        )

    source.write_text("data work.changed; run;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source bytes changed"):
        qualify_code_dependencies(
            workload,
            source_root=tmp_path,
            client_id="CLIENT-1",
            subject_id=subject.artifact_id,
            run_id="RUN-1",
            attempt_id="ATTEMPT-1",
            execution_id="EXEC-1",
        )


def test_publication_rejects_caller_supplied_success_claim(tmp_path: Path) -> None:
    source = tmp_path / "main.sas"
    source.write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=tmp_path,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    claims = dict(payload["claims"])
    claims["executed"] = True
    asserted = {**payload, "claims": claims}

    with pytest.raises(ValueError, match="does not replay"):
        write_code_dependency_result(
            tmp_path / "evidence", asserted, workload=workload, source_root=tmp_path
        )


def test_replay_reverifies_canonical_static_only_claims(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    result_path = write_code_dependency_result(
        output_root, payload, workload=workload, source_root=source_root
    )
    forged_claims = {**payload["claims"], "executed": True}
    forged = {**payload, "claims": forged_claims}
    result_path.write_text(json.dumps(forged, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid canonical claims"):
        write_code_dependency_result(
            output_root, forged, workload=workload, source_root=source_root
        )


def test_qualification_rejects_caller_replaced_dependency_analysis(tmp_path: Path) -> None:
    (tmp_path / "main.sas").write_text("%missing;\n", encoding="utf-8")
    workload = _discover(tmp_path)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    assert analysis.blockers

    asserted_analysis = replace(
        analysis,
        occurrences=(),
        blockers=(),
        analysis_complete=True,
        ordering_eligible=True,
    )
    asserted_workload = replace(workload, code_dependency_analysis=asserted_analysis)

    with pytest.raises(ValueError, match="does not replay from discovery evidence"):
        qualify_code_dependencies(
            asserted_workload,
            source_root=tmp_path,
            client_id="CLIENT-1",
            subject_id=subject.artifact_id,
            run_id="RUN-1",
            attempt_id="ATTEMPT-1",
            execution_id="EXEC-1",
        )


@pytest.mark.parametrize("configuration_name", ["autoexec.sas", "config.sas"])
def test_resolved_sas_configuration_dependency_is_in_ordering_closure(
    tmp_path: Path, configuration_name: str
) -> None:
    (tmp_path / configuration_name).write_text("%macro configured; %mend;\n", encoding="utf-8")
    (tmp_path / "main.sas").write_text(
        f'%include "{configuration_name}";\n%configured;\n', encoding="utf-8"
    )

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    analysis = workload.code_dependency_analysis
    assert analysis is not None
    groups_by_artifact = {
        artifact_id: group
        for group in analysis.ordering_groups
        for artifact_id in group.artifact_ids
    }
    prerequisite = groups_by_artifact[artifacts[configuration_name].artifact_id]
    caller = groups_by_artifact[artifacts["main.sas"].artifact_id]

    assert prerequisite.sequence_rank < caller.sequence_rank
    assert prerequisite.group_id in caller.prerequisite_group_ids
    assert analysis.ordering_eligible is True


def test_existing_result_recovers_telemetry_without_mutable_source(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "main.sas"
    source.write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    result_path = write_code_dependency_result(
        output_root, payload, workload=workload, source_root=source_root
    )
    telemetry_path = result_path.with_name("telemetry.json")
    canonical_before = result_path.read_bytes()
    telemetry_before = telemetry_path.read_bytes()

    telemetry_path.unlink()
    source.write_text("data work.changed; run;\n", encoding="utf-8")

    assert (
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )
        == result_path
    )
    assert result_path.read_bytes() == canonical_before
    assert telemetry_path.read_bytes() == telemetry_before

    telemetry_path.unlink()
    source.unlink()
    assert (
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )
        == result_path
    )
    assert result_path.read_bytes() == canonical_before
    assert telemetry_path.read_bytes() == telemetry_before


def test_publication_fails_closed_if_parent_is_swapped_during_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.sas").write_text("data work.ready; run;\n", encoding="utf-8")
    workload = _discover(source_root)
    subject = next(item for item in workload.artifacts if item.name == "main.sas")
    payload = qualify_code_dependencies(
        workload,
        source_root=source_root,
        client_id="CLIENT-1",
        subject_id=subject.artifact_id,
        run_id="RUN-1",
        attempt_id="ATTEMPT-1",
        execution_id="EXEC-1",
    )
    output_root = tmp_path / "evidence"
    expected = code_dependency_result_path(output_root, payload)
    parent = expected.parent
    displaced = tmp_path / "displaced-parent"
    outside = tmp_path / "outside"
    outside.mkdir()
    real_link = os.link
    swapped = False

    def swap_parent_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(displaced)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("smf.immutable_files.os.link", swap_parent_then_link)

    with pytest.raises(ValueError, match="path is unsafe"):
        write_code_dependency_result(
            output_root, payload, workload=workload, source_root=source_root
        )

    assert not (outside / "result.json").exists()
    assert not (outside / "telemetry.json").exists()


def test_two_workloads_publish_to_isolated_paths(tmp_path: Path) -> None:
    output_root = tmp_path / "evidence"
    paths = []
    for name in ("alpha", "beta"):
        source_root = tmp_path / name
        source_root.mkdir()
        (source_root / "main.sas").write_text(f"data work.{name}; run;\n", encoding="utf-8")
        workload = discover_source(source_root, provider="filesystem", namespace=name).workloads[0]
        subject = next(item for item in workload.artifacts if item.name == "main.sas")
        payload = qualify_code_dependencies(
            workload,
            source_root=source_root,
            client_id="CLIENT-1",
            subject_id=subject.artifact_id,
            run_id="RUN-SHARED",
            attempt_id="ATTEMPT-SHARED",
            execution_id=f"EXEC-{name}",
        )
        paths.append(
            write_code_dependency_result(
                output_root, payload, workload=workload, source_root=source_root
            )
        )

    assert paths[0] != paths[1]
    assert all(path.is_file() for path in paths)


def test_sas_intrinsic_macro_functions_are_not_cross_program_dependencies(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.sas").write_text(
        "%let value=%superq(INPUT);\n"
        "%let home=%sysget(HOME);\n"
        "%let cleaned=%trim(&value);\n"
        "%if %symexist(OPTIONAL) %then %put &=OPTIONAL;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    main = next(item for item in workload.artifacts if item.name == "main.sas")
    assert not any(
        item.kind is RelationshipKind.CALLS and item.source_id == main.artifact_id
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    assert not any(
        item.source_id == main.artifact_id
        and item.reference in {"superq", "sysget", "symexist", "trim"}
        for item in workload.dependency_graph.unresolved
    )


def test_inventoried_macro_definition_overrides_intrinsic_suppression(tmp_path: Path) -> None:
    (tmp_path / "trim.sas").write_text("%macro trim; %mend;\n", encoding="utf-8")
    (tmp_path / "caller.sas").write_text(
        "%include 'trim.sas';\n* first\n second;\n%trim;\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    call = next(item for item in workload.relationships if item.kind is RelationshipKind.CALLS)

    assert call.source_id == artifacts["caller.sas"].artifact_id
    assert call.target_id == artifacts["trim.sas"].artifact_id
    assert call.evidence[0].locator == "caller.sas:4"


def test_sas_94_builtin_macro_elements_do_not_create_missing_dependencies(
    tmp_path: Path,
) -> None:
    from smf.discovery import discover_source

    (tmp_path / "main.sas").write_text(
        "%run;\n"
        "%activate window;\n"
        "%syscall catx(delim, msg, s1, s2);\n"
        "%sysmstoreclear;\n"
        "%window status;\n"
        "%let check=%verify(abc,xyz);\n"
        "%let dtype=%datatyp(123);\n"
        "%let left=%qleft(  abc);\n"
        "%let word=%qkscan(&text,1);\n"
        "%let suffix=%qksubstr(&text,2);\n"
        "%let upper=%qupcase(&text);\n"
        "%let licensed=%sysprod(BASE);\n"
        "%let reserved=%sysfutureoperation();\n"
        "%put %sysfunc(trim(&msg));\n",
        encoding="utf-8",
    )
    workload = discover_source(
        tmp_path, provider="filesystem", namespace="ad02-sas-builtins"
    ).workloads[0]
    artifact = next(item for item in workload.artifacts if item.name == "main.sas")
    forbidden = {
        "activate",
        "datatyp",
        "qkscan",
        "qksubstr",
        "qleft",
        "qupcase",
        "run",
        "syscall",
        "sysfunc",
        "sysfutureoperation",
        "sysmstoreclear",
        "sysprod",
        "verify",
        "window",
    }
    findings = artifact.metadata.get("macro_call_findings", ())
    missing = {
        str(item.get("reference", "")).lower()
        for item in findings
        if item.get("resolution") == "missing"
    }
    assert not (forbidden & missing)

    assert workload.dependency_graph is not None
    unresolved_missing = {
        item.reference.lower()
        for item in workload.dependency_graph.unresolved
        if item.reason.value == "missing"
    }
    assert not (forbidden & unresolved_missing)
