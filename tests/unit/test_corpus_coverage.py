import hashlib
import json
from pathlib import Path

import pytest

from smf.corpus.coverage import (
    CoverageDimension,
    CoverageEvidence,
    CoverageMaturity,
    build_coverage_report,
    build_repository_coverage_report,
    observed_coverage_from_manifests,
)
from smf.corpus.loader import sha256_file
from smf.corpus.regression import (
    CorpusRegressionRequest,
    CorpusStageRequest,
    RegressionStage,
    StageArtifactInput,
    StageStatus,
    admit_corpus_regression,
    finalize_corpus_regression,
    load_corpus_regression_result,
    record_corpus_stage,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "tests" / "corpus" / "manifests"


def test_repository_report_includes_every_required_dimension() -> None:
    report = build_repository_coverage_report(MANIFESTS)
    assert {item.dimension for item in report.dimensions} == set(CoverageDimension)
    assert report.scenario_count == len(tuple(MANIFESTS.glob("*.yaml")))


def test_manifest_presence_only_creates_observed_maturity() -> None:
    evidence = observed_coverage_from_manifests(MANIFESTS)
    assert evidence
    assert {item.maturity for item in evidence} == {CoverageMaturity.OBSERVED}


def test_report_does_not_collapse_maturity_into_percentage() -> None:
    payload = build_repository_coverage_report(MANIFESTS).to_dict()
    assert "percentage" not in payload
    assert "score" not in payload
    assert "confidence" not in payload
    dimensions = payload["dimensions"]
    assert isinstance(dimensions, list)
    assert all("maturity_counts" in item for item in dimensions)


def test_independent_source_count_is_attributable() -> None:
    report = build_repository_coverage_report(MANIFESTS)
    expected = {
        item.source_id
        for item in observed_coverage_from_manifests(MANIFESTS)
        if item.independent_source
    }
    assert report.independent_source_count == len(expected)
    assert report.independent_source_count >= 3


def test_empty_dimensions_are_reported_as_known_gaps() -> None:
    evidence = (
        CoverageEvidence(
            dimension=CoverageDimension.CONSTRUCT,
            capability="data-step",
            maturity=CoverageMaturity.OBSERVED,
            scenario_id="example",
            evidence_ref="manifest.yaml",
            source_id="smf",
            independent_source=False,
        ),
    )
    report = build_coverage_report(evidence)
    assert CoverageDimension.CONSTRUCT not in report.known_gaps
    assert CoverageDimension.COMPLEXITY in report.known_gaps


def test_higher_maturity_requires_explicit_evidence() -> None:
    tested = CoverageEvidence(
        dimension=CoverageDimension.CONSTRUCT,
        capability="data-step",
        maturity=CoverageMaturity.TESTED,
        scenario_id="semantic-example",
        evidence_ref="tests/unit/test_example.py::test_data_step",
        source_id="smf",
        independent_source=False,
    )
    report = build_coverage_report((tested,))
    construct = next(
        item for item in report.dimensions if item.dimension == CoverageDimension.CONSTRUCT
    )
    assert construct.maturity_counts["tested"] == 1
    assert construct.maturity_counts["observed"] == 0
    assert construct.maturity_counts["converted"] == 0
    assert construct.maturity_counts["executed"] == 0
    assert construct.maturity_counts["validated"] == 0
    assert construct.maturity_counts["certified"] == 0


def test_unresolved_dependency_is_visible_as_gap_evidence() -> None:
    evidence = observed_coverage_from_manifests(MANIFESTS)
    unresolved = [
        item for item in evidence if item.dimension == CoverageDimension.UNRESOLVED_BEHAVIOR
    ]
    assert unresolved
    assert all(item.evidence_ref for item in unresolved)


def _write_proof(path: Path, *, blocked: bool = False, **overrides: object) -> None:
    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=MANIFESTS / "public-sas-official-language-breadth.yaml",
            scenario_id="public-sas-official-language-breadth",
            workload_id="public-sas-official-language-breadth",
            subject_id="public-sas-select-statement",
            run_id="coverage-proof",
            attempt_id="attempt-1",
            output_root=path.parent / "proof-runs",
        )
    )
    if not blocked:
        generated = path.parent / f"{path.stem}-generated.py"
        generated.write_text('result = source_df.select("id")\n', encoding="utf-8")
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="test-converter",
                provider_version="1",
                artifacts=(StageArtifactInput("generated-main", generated),),
            ),
        )
        digest = sha256_file(generated)
        report = path.parent / f"{path.stem}-validation.json"
        report.write_text('{"syntax":"pass"}\n', encoding="utf-8")
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.VALIDATION,
                status=StageStatus.PASSED,
                provider="python-ast",
                provider_version="1",
                artifacts=(StageArtifactInput("validation-report", report),),
                input_artifact_digest=digest,
                validation_kind="static",
                checks=(
                    {
                        "check_id": "python-syntax",
                        "status": "pass",
                        "evidence": {"artifact_digest": digest},
                    },
                ),
            ),
        )
    result_path = finalize_corpus_regression(qualification)
    result = load_corpus_regression_result(result_path)
    payload: dict[str, object] = {
        "schema_version": 1,
        "evidence_id": "proof-001",
        "dimension": "construct",
        "capability": "data-step",
        "maturity": "tested",
        "scenario_id": "public-sas-official-language-breadth",
        "source_id": "sas-code-examples",
        "evidence_ref": result_path.relative_to(path.parent).as_posix(),
        "result_digest": result["content_digest"],
        "independent_source": True,
    }
    payload.update(overrides)
    import yaml

    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_repository_report_merges_explicit_higher_maturity_evidence(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "coverage-evidence"
    evidence_dir.mkdir()
    _write_proof(evidence_dir / "tested.yaml")
    report = build_repository_coverage_report(MANIFESTS, evidence_directory=evidence_dir)
    construct = next(
        item for item in report.dimensions if item.dimension == CoverageDimension.CONSTRUCT
    )
    assert construct.maturity_counts["tested"] == 1
    assert construct.maturity_counts["converted"] == 0


def test_coverage_registry_rejects_observed_claim(tmp_path: Path) -> None:
    from jsonschema import ValidationError

    from smf.corpus.coverage_evidence import load_coverage_evidence

    path = tmp_path / "observed.yaml"
    _write_proof(path, maturity="observed")
    with pytest.raises(ValidationError):
        load_coverage_evidence(path)


def test_coverage_registry_rejects_duplicate_evidence_ids(tmp_path: Path) -> None:
    from smf.corpus.coverage_evidence import load_coverage_evidence_registry

    _write_proof(tmp_path / "one.yaml")
    _write_proof(tmp_path / "two.yaml", capability="proc-sql")
    with pytest.raises(ValueError, match="Duplicate coverage evidence_id"):
        load_coverage_evidence_registry(tmp_path)


def test_coverage_claim_cannot_upgrade_blocked_result_with_boolean_label(
    tmp_path: Path,
) -> None:
    from smf.corpus.coverage_evidence import load_coverage_evidence

    path = tmp_path / "converted.yaml"
    _write_proof(path, blocked=True, maturity="converted")
    with pytest.raises(ValueError, match="does not support converted"):
        load_coverage_evidence(path)


def test_tested_coverage_rejects_blocked_canonical_result(tmp_path: Path) -> None:
    from smf.corpus.coverage_evidence import load_coverage_evidence

    path = tmp_path / "tested.yaml"
    _write_proof(path, blocked=True, maturity="tested")
    with pytest.raises(ValueError, match="does not support tested"):
        load_coverage_evidence(path)


def test_coverage_rejects_digest_consistent_result_without_canonical_chain(
    tmp_path: Path,
) -> None:
    import yaml

    from smf.corpus.coverage_evidence import load_coverage_evidence

    result: dict[str, object] = {
        "schema_version": 1,
        "result_id": "CRR-fake",
        "qualification_id": "CRQ-fake",
        "scenario_id": "public-sas-official-language-breadth",
        "workload_id": "public-sas-official-language-breadth",
        "subject_id": "public-sas-select-statement",
        "source_id": "sas-code-examples",
        "run_id": "forged-run",
        "attempt_id": "attempt-1",
        "manifest_digest": "1" * 64,
        "source_digest": "2" * 64,
        "bundle_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "golden_contract_digest": None,
        "evidence_scope": "shared-regression",
        "environment": "test-only",
        "stage_ids": ["CRS-fake-conversion", "CRS-fake-validation"],
        "missing_stages": [],
        "terminal_disposition": "passed",
        "telemetry": {
            "generated": True,
            "executed": True,
            "validated": True,
            "parity_passed": True,
            "golden_matched": False,
            "human_assisted": False,
            "blocked": False,
        },
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    result["content_digest"] = hashlib.sha256(encoded.encode()).hexdigest()
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    claim = {
        "schema_version": 1,
        "evidence_id": "forged-proof",
        "dimension": "construct",
        "capability": "data-step",
        "maturity": "certified",
        "scenario_id": result["scenario_id"],
        "source_id": result["source_id"],
        "evidence_ref": "result.json",
        "result_digest": result["content_digest"],
        "independent_source": True,
    }
    claim_path = tmp_path / "claim.yaml"
    claim_path.write_text(yaml.safe_dump(claim), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical qualification"):
        load_coverage_evidence(claim_path)


def test_empty_repository_coverage_registry_adds_no_claims() -> None:
    evidence_dir = ROOT / "tests" / "corpus" / "coverage-evidence"
    report = build_repository_coverage_report(MANIFESTS, evidence_directory=evidence_dir)
    for dimension in report.dimensions:
        assert dimension.maturity_counts["tested"] == 0
        assert dimension.maturity_counts["converted"] == 0
        assert dimension.maturity_counts["executed"] == 0
        assert dimension.maturity_counts["validated"] == 0
        assert dimension.maturity_counts["certified"] == 0
