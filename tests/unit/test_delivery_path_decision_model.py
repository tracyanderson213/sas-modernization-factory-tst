from dataclasses import replace

from smf.modernization.delivery_path import derive_delivery_path_candidates
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DispositionCandidate,
    ExternalDependencyKind,
    ModernizationDisposition,
    WorkloadBoundary,
)


def _workload(*, shell=False, dynamic=False, external=False, boundary_metadata=None):
    builder = WorkloadBuilder(name="claims")
    sas = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="claims.sas",
        metadata={"sas_static": {"dynamic_dataset_references": ["&&lib..claims"]}}
        if dynamic
        else {},
    )
    artifact_ids = [sas.artifact_id]
    if shell:
        artifact_ids.append(
            builder.add_artifact(kind=ArtifactKind.SHELL_SCRIPT, name="run.sh").artifact_id
        )
    dep_ids = ()
    if external:
        dep = builder.add_external_dependency(
            kind=ExternalDependencyKind.DATABASE_CONNECTION, name="warehouse"
        )
        dep_ids = (dep.dependency_id,)
    workload = builder.build()
    boundary = WorkloadBoundary(
        boundary_id="BND-claims",
        name="claims",
        artifact_ids=tuple(artifact_ids),
        external_dependency_ids=dep_ids,
        confidence=Confidence.HIGH,
        metadata={"requires_confirmation": False, **(boundary_metadata or {})},
    )
    workload = replace(workload, boundaries=(boundary,))
    return derive_modernization_disposition_inputs(workload)


def _paths(workload):
    result = derive_delivery_path_candidates(workload)
    return result, {item.disposition: item for item in result.disposition_inputs[0].candidates}


def test_sas_source_creates_convert_candidate_without_selecting_it():
    result, candidates = _paths(_workload())
    assert ModernizationDisposition.CONVERT in candidates
    assert result.disposition_inputs[0].selected_disposition is None
    assert candidates[ModernizationDisposition.CONVERT].metadata["selected"] is False


def test_convert_is_medium_confidence_when_common_coverage_blockers_are_absent():
    _, candidates = _paths(_workload())
    assert candidates[ModernizationDisposition.CONVERT].confidence is Confidence.MEDIUM


def test_orchestration_adds_reengineer_candidate():
    _, candidates = _paths(_workload(shell=True))
    candidate = candidates[ModernizationDisposition.RE_ENGINEER]
    assert "PATH-REENGINEER-ORCHESTRATION" in candidate.metadata["supporting_signal_ids"]


def test_dynamic_data_reference_adds_reengineer_candidate():
    _, candidates = _paths(_workload(dynamic=True))
    assert (
        "PATH-REENGINEER-DYNAMIC-DATA-REFERENCE"
        in candidates[ModernizationDisposition.RE_ENGINEER].metadata["supporting_signal_ids"]
    )


def test_external_dependency_adds_reengineer_candidate():
    _, candidates = _paths(_workload(external=True))
    assert (
        "PATH-REENGINEER-EXTERNAL-DEPENDENCY"
        in candidates[ModernizationDisposition.RE_ENGINEER].metadata["supporting_signal_ids"]
    )


def test_replace_requires_explicit_replacement_target():
    _, absent = _paths(_workload())
    _, present = _paths(_workload(boundary_metadata={"replacement_target": "approved-service"}))
    assert ModernizationDisposition.REPLACE not in absent
    assert ModernizationDisposition.REPLACE in present


def test_preserve_requires_explicit_constraint():
    _, absent = _paths(_workload())
    _, present = _paths(_workload(boundary_metadata={"preserve_required": True}))
    assert ModernizationDisposition.PRESERVE not in absent
    assert ModernizationDisposition.PRESERVE in present


def test_refactor_is_not_invented_as_parallel_disposition():
    result, _ = _paths(_workload(shell=True))
    assert "refactor" not in {item.value for item in ModernizationDisposition}
    assert (
        result.metadata["delivery_path_candidate_assessment"]["refactor_is_canonical_disposition"]
        is False
    )


def test_existing_retire_and_consolidate_candidates_are_preserved():
    workload = _workload()
    original = workload.disposition_inputs[0]
    retire = DispositionCandidate(
        candidate_id="retire", disposition=ModernizationDisposition.RETIRE, rationale="test"
    )
    consolidate = DispositionCandidate(
        candidate_id="consolidate",
        disposition=ModernizationDisposition.CONSOLIDATE,
        rationale="test",
    )
    workload = replace(
        workload, disposition_inputs=(replace(original, candidates=(retire, consolidate)),)
    )
    _, candidates = _paths(workload)
    assert ModernizationDisposition.RETIRE in candidates
    assert ModernizationDisposition.CONSOLIDATE in candidates


def test_rerun_replaces_path_candidates_instead_of_duplicating_them():
    workload = _workload(shell=True)
    once = derive_delivery_path_candidates(workload)
    twice = derive_delivery_path_candidates(once)
    assert len(once.disposition_inputs[0].candidates) == len(twice.disposition_inputs[0].candidates)
    assert [x.candidate_id for x in once.disposition_inputs[0].candidates] == [
        x.candidate_id for x in twice.disposition_inputs[0].candidates
    ]
