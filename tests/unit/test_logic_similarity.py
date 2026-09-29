from smf.modernization.redundancy import derive_logic_similarity_findings
from smf.workload.models import Artifact, ArtifactKind, Confidence, Workload, WorkloadBoundary


def artifact(name, *, checksum=None, static=None, kind=ArtifactKind.SAS_PROGRAM):
    return Artifact(
        artifact_id=name,
        kind=kind,
        name=f"{name}.sas",
        checksum=checksum,
        metadata={"sas_static": static} if static is not None else {},
    )


def workload(left, right):
    return Workload(
        workload_id="WL",
        name="estate",
        artifacts=(left, right),
        boundaries=(
            WorkloadBoundary("A", "A", artifact_ids=(left.artifact_id,)),
            WorkloadBoundary("B", "B", artifact_ids=(right.artifact_id,)),
        ),
    )


def signature():
    return {
        "libraries": ["dw"],
        "by_variables": ["member_id"],
        "macro_definitions": [],
        "macro_invocations": ["month_end"],
        "macro_variables": ["run_date"],
        "dynamic_dataset_references": [],
    }


def test_exact_checksum_across_boundaries_is_high_confidence_duplicate_evidence():
    result = derive_logic_similarity_findings(
        workload(artifact("a", checksum="same"), artifact("b", checksum="same"))
    )
    finding = result.logic_similarity_findings[0]
    assert finding.exact_source_match is True
    assert finding.confidence is Confidence.HIGH


def test_different_checksums_without_signature_do_not_match():
    result = derive_logic_similarity_findings(
        workload(artifact("a", checksum="1"), artifact("b", checksum="2"))
    )
    assert result.logic_similarity_findings == ()


def test_structural_signature_match_is_only_low_confidence():
    result = derive_logic_similarity_findings(
        workload(
            artifact("a", checksum="1", static=signature()),
            artifact("b", checksum="2", static=signature()),
        )
    )
    finding = result.logic_similarity_findings[0]
    assert finding.structural_signature_match is True
    assert finding.exact_source_match is False
    assert finding.confidence is Confidence.LOW


def test_structural_match_never_claims_business_equivalence():
    result = derive_logic_similarity_findings(
        workload(artifact("a", static=signature()), artifact("b", static=signature()))
    )
    assert (
        result.logic_similarity_findings[0].metadata["business_rule_equivalence_established"]
        is False
    )


def test_same_boundary_is_not_reported_as_estate_duplicate():
    left = artifact("a", checksum="same")
    right = artifact("b", checksum="same")
    source = Workload(
        workload_id="WL",
        name="estate",
        artifacts=(left, right),
        boundaries=(WorkloadBoundary("A", "A", artifact_ids=("a", "b")),),
    )
    assert derive_logic_similarity_findings(source).logic_similarity_findings == ()


def test_non_sas_artifacts_are_not_compared():
    left = artifact("a", checksum="same", kind=ArtifactKind.SHELL_SCRIPT)
    right = artifact("b", checksum="same", kind=ArtifactKind.SHELL_SCRIPT)
    assert derive_logic_similarity_findings(workload(left, right)).logic_similarity_findings == ()


def test_empty_static_signatures_do_not_create_false_similarity():
    empty = {
        "libraries": [],
        "by_variables": [],
        "macro_definitions": [],
        "macro_invocations": [],
        "macro_variables": [],
        "dynamic_dataset_references": [],
    }
    result = derive_logic_similarity_findings(
        workload(
            artifact("a", checksum="1", static=empty), artifact("b", checksum="2", static=empty)
        )
    )
    assert result.logic_similarity_findings == ()


def test_findings_are_stable_across_artifact_order():
    a = artifact("a", checksum="same")
    b = artifact("b", checksum="same")
    first = derive_logic_similarity_findings(workload(a, b)).logic_similarity_findings[0]
    second_source = Workload(
        workload_id="WL",
        name="estate",
        artifacts=(b, a),
        boundaries=(
            WorkloadBoundary("B", "B", artifact_ids=("b",)),
            WorkloadBoundary("A", "A", artifact_ids=("a",)),
        ),
    )
    second = derive_logic_similarity_findings(second_source).logic_similarity_findings[0]
    assert first.finding_id == second.finding_id


def test_rerun_replaces_findings_instead_of_duplicating():
    source = workload(artifact("a", checksum="same"), artifact("b", checksum="same"))
    once = derive_logic_similarity_findings(source)
    twice = derive_logic_similarity_findings(once)
    assert len(twice.logic_similarity_findings) == 1


def test_metadata_reports_exact_and_structural_only_counts():
    result = derive_logic_similarity_findings(
        workload(
            artifact("a", checksum="same", static=signature()),
            artifact("b", checksum="same", static=signature()),
        )
    )
    meta = result.metadata["logic_similarity"]
    assert meta["finding_count"] == 1
    assert meta["exact_source_match_count"] == 1
    assert meta["structural_only_match_count"] == 0
