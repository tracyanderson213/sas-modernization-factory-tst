from dataclasses import replace

from smf.modernization.target_state import derive_target_state_pattern_inputs
from smf.modernization.waves import derive_migration_wave_groups
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    EvidenceMethod,
    ExternalDependencyKind,
    Relationship,
    RelationshipKind,
    TargetStatePatternInput,
    WorkloadBoundary,
)


def _workload():
    builder = WorkloadBuilder(name="estate", namespace="test")
    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="estate",
        confidence=Confidence.HIGH,
    )
    first = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="a.sas", evidence=(evidence,))
    second = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="b.sas", evidence=(evidence,))
    third = builder.add_artifact(kind=ArtifactKind.SAS_PROGRAM, name="c.sas", evidence=(evidence,))
    shared = builder.add_external_dependency(
        kind=ExternalDependencyKind.DATABASE_CONNECTION,
        name="warehouse",
        evidence=(evidence,),
    )
    workload = builder.build()
    boundaries = (
        WorkloadBoundary(
            boundary_id="BND-A",
            name="A",
            artifact_ids=(first.artifact_id,),
            external_dependency_ids=(shared.dependency_id,),
            confidence=Confidence.HIGH,
            evidence=(evidence,),
            metadata={"requires_confirmation": False},
        ),
        WorkloadBoundary(
            boundary_id="BND-B",
            name="B",
            artifact_ids=(second.artifact_id,),
            external_dependency_ids=(shared.dependency_id,),
            confidence=Confidence.HIGH,
            evidence=(evidence,),
            metadata={"requires_confirmation": False},
        ),
        WorkloadBoundary(
            boundary_id="BND-C",
            name="C",
            artifact_ids=(third.artifact_id,),
            confidence=Confidence.HIGH,
            evidence=(evidence,),
            metadata={"requires_confirmation": False},
        ),
    )
    workload = replace(workload, boundaries=boundaries)
    workload = derive_target_state_pattern_inputs(workload)
    return workload, first.artifact_id, second.artifact_id, third.artifact_id, evidence


def test_creates_wave_groups_without_assigning_calendar_waves():
    workload, *_ = _workload()
    result = derive_migration_wave_groups(workload)
    assert len(result.migration_wave_groups) == 2
    assert all(
        item.metadata["calendar_wave_assigned"] is False for item in result.migration_wave_groups
    )
    assert result.metadata["migration_wave_grouping"]["governed_planning_required"] is True


def test_shared_external_dependency_creates_affinity_group():
    workload, *_ = _workload()
    result = derive_migration_wave_groups(workload)
    coupled = next(item for item in result.migration_wave_groups if len(item.boundary_ids) == 2)
    assert coupled.boundary_ids == ("BND-A", "BND-B")
    assert "shared_external_dependency" in coupled.coupling_reasons


def test_independent_boundary_remains_independent():
    workload, *_ = _workload()
    result = derive_migration_wave_groups(workload)
    independent = next(
        item for item in result.migration_wave_groups if item.boundary_ids == ("BND-C",)
    )
    assert independent.coupling_reasons == ("independent_boundary",)


def test_group_identity_is_stable():
    workload, *_ = _workload()
    first = derive_migration_wave_groups(workload)
    second = derive_migration_wave_groups(workload)
    assert [item.wave_group_id for item in first.migration_wave_groups] == [
        item.wave_group_id for item in second.migration_wave_groups
    ]


def test_direct_dependency_creates_relative_sequence_order():
    workload, first, _second, third, evidence = _workload()
    boundaries = tuple(replace(item, external_dependency_ids=()) for item in workload.boundaries)
    relationship = Relationship(
        relationship_id="REL-ORDER",
        source_id=first,
        kind=RelationshipKind.PRECEDES,
        target_id=third,
        evidence=(evidence,),
    )
    result = derive_migration_wave_groups(
        replace(workload, boundaries=boundaries, relationships=(relationship,))
    )
    first_group = next(
        item for item in result.migration_wave_groups if "BND-A" in item.boundary_ids
    )
    third_group = next(
        item for item in result.migration_wave_groups if "BND-C" in item.boundary_ids
    )
    assert first_group.sequence_rank == 0
    assert third_group.sequence_rank == 1
    assert third_group.predecessor_group_ids == (first_group.wave_group_id,)


def test_depends_on_direction_is_normalized_before_grouping():
    workload, first, _second, third, evidence = _workload()
    boundaries = tuple(replace(item, external_dependency_ids=()) for item in workload.boundaries)
    relationship = Relationship(
        relationship_id="REL-DEPENDS",
        source_id=third,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=first,
        evidence=(evidence,),
    )
    result = derive_migration_wave_groups(
        replace(workload, boundaries=boundaries, relationships=(relationship,))
    )
    first_group = next(
        item for item in result.migration_wave_groups if "BND-A" in item.boundary_ids
    )
    third_group = next(
        item for item in result.migration_wave_groups if "BND-C" in item.boundary_ids
    )
    assert third_group.predecessor_group_ids == (first_group.wave_group_id,)


def test_unresolved_target_state_evidence_flows_into_wave_group():
    workload, *_ = _workload()
    pattern = workload.target_state_pattern_inputs[0]
    workload = replace(
        workload,
        target_state_pattern_inputs=(
            replace(pattern, unresolved_items=("output_consumer:OUT-1",)),
            *workload.target_state_pattern_inputs[1:],
        ),
    )
    result = derive_migration_wave_groups(workload)
    group = next(
        item for item in result.migration_wave_groups if pattern.boundary_id in item.boundary_ids
    )
    assert "output_consumer:OUT-1" in group.unresolved_items


def test_wave_grouping_does_not_modify_target_pattern_inputs():
    workload, *_ = _workload()
    result = derive_migration_wave_groups(workload)
    assert result.target_state_pattern_inputs == workload.target_state_pattern_inputs
    assert all(
        isinstance(item, TargetStatePatternInput) for item in result.target_state_pattern_inputs
    )


def test_serialization_includes_wave_groups_as_planning_proposals():
    workload, *_ = _workload()
    payload = derive_migration_wave_groups(workload).to_dict()
    assert len(payload["migration_wave_groups"]) == 2
    assert payload["metadata"]["migration_wave_grouping"]["calendar_wave_assigned"] is False


def test_dependency_cycle_stays_in_one_group_for_joint_planning():
    workload, first, _second, third, evidence = _workload()
    boundaries = tuple(replace(item, external_dependency_ids=()) for item in workload.boundaries)
    relationships = (
        Relationship(
            relationship_id="REL-A-C",
            source_id=first,
            kind=RelationshipKind.PRECEDES,
            target_id=third,
            evidence=(evidence,),
        ),
        Relationship(
            relationship_id="REL-C-A",
            source_id=third,
            kind=RelationshipKind.PRECEDES,
            target_id=first,
            evidence=(evidence,),
        ),
    )
    result = derive_migration_wave_groups(
        replace(workload, boundaries=boundaries, relationships=relationships)
    )
    cycle = next(
        item
        for item in result.migration_wave_groups
        if set(item.boundary_ids) == {"BND-A", "BND-C"}
    )
    assert "dependency_cycle" in cycle.coupling_reasons
    assert cycle.predecessor_group_ids == ()
