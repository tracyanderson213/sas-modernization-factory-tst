from smf.modernization.incremental import derive_batch_incremental_opportunities
from smf.workload.models import (
    Artifact,
    ArtifactKind,
    Confidence,
    Dataset,
    DatasetKind,
    Relationship,
    RelationshipKind,
    Workload,
    WorkloadBoundary,
)


def _workload(*, scheduled=True, schedule="0 2 * * *", reads=True, writes=True, unknown=False):
    program = Artifact("ART-P", ArtifactKind.SAS_PROGRAM, "job.sas")
    artifacts = [program]
    ids = [program.artifact_id]
    if scheduled:
        job = Artifact(
            "ART-J",
            ArtifactKind.SCHEDULER_JOB,
            "nightly",
            metadata={"schedule": schedule} if schedule else {},
        )
        artifacts.append(job)
        ids.append(job.artifact_id)
    dataset = Dataset(
        "DS-1", DatasetKind.UNKNOWN if unknown else DatasetKind.DATABASE_TABLE, "source"
    )
    rels = []
    if reads:
        rels.append(Relationship("R1", "ART-P", RelationshipKind.READS, "DS-1"))
    if writes:
        rels.append(Relationship("R2", "ART-P", RelationshipKind.WRITES, "DS-1"))
    boundary = WorkloadBoundary(
        "WB-1",
        "job",
        artifact_ids=tuple(ids),
        dataset_ids=("DS-1",),
        confidence=Confidence.HIGH,
        metadata={"requires_confirmation": False},
    )
    return Workload(
        "WL-1",
        "estate",
        artifacts=tuple(artifacts),
        datasets=(dataset,),
        relationships=tuple(rels),
        boundaries=(boundary,),
    )


def test_scheduled_data_workload_creates_opportunity():
    result = derive_batch_incremental_opportunities(_workload())
    assert len(result.batch_incremental_opportunities) == 1


def test_unscheduled_workload_does_not_create_opportunity():
    assert not derive_batch_incremental_opportunities(
        _workload(scheduled=False)
    ).batch_incremental_opportunities


def test_schedule_without_data_behavior_is_not_enough():
    assert not derive_batch_incremental_opportunities(
        _workload(reads=False, writes=False)
    ).batch_incremental_opportunities


def test_cron_and_read_write_evidence_raise_confidence_to_medium():
    item = derive_batch_incremental_opportunities(_workload()).batch_incremental_opportunities[0]
    assert item.confidence is Confidence.MEDIUM


def test_minimal_schedule_and_data_evidence_remains_low_confidence():
    item = derive_batch_incremental_opportunities(
        _workload(schedule="", writes=False)
    ).batch_incremental_opportunities[0]
    assert item.confidence is Confidence.LOW


def test_change_capture_and_semantics_are_explicit_blockers():
    item = derive_batch_incremental_opportunities(_workload()).batch_incremental_opportunities[0]
    assert "INCREMENTAL-BLOCKER-CHANGE-CAPTURE-NOT-ESTABLISHED" in item.blocker_ids
    assert "INCREMENTAL-BLOCKER-INCREMENTAL-SEMANTICS-NOT-ESTABLISHED" in item.blocker_ids


def test_unknown_dataset_is_a_blocker():
    item = derive_batch_incremental_opportunities(
        _workload(unknown=True)
    ).batch_incremental_opportunities[0]
    assert "INCREMENTAL-BLOCKER-UNKNOWN-DATASET" in item.blocker_ids


def test_analysis_never_selects_target_pattern_or_claims_feasibility():
    item = derive_batch_incremental_opportunities(_workload()).batch_incremental_opportunities[0]
    assert item.metadata["target_pattern_selected"] is False
    assert item.metadata["incremental_feasibility_established"] is False
    assert item.metadata["change_capture_established"] is False


def test_analysis_is_deterministic_and_idempotent():
    first = derive_batch_incremental_opportunities(_workload())
    second = derive_batch_incremental_opportunities(first)
    assert first.batch_incremental_opportunities == second.batch_incremental_opportunities


def test_workload_metadata_records_governance_boundary():
    result = derive_batch_incremental_opportunities(_workload())
    meta = result.metadata["batch_to_incremental_opportunity_analysis"]
    assert meta["opportunity_count"] == 1
    assert meta["automatic_target_selection"] is False
    assert meta["governed_confirmation_required"] is True
