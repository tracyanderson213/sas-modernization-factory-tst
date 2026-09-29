from __future__ import annotations

import hashlib
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from smf.conversion.registry import execute_plan, plan_rules
from smf.corpus import (
    CorpusRegressionRequest,
    CorpusStageRequest,
    RegressionStage,
    StageArtifactInput,
    StageStatus,
    admit_corpus_regression,
    compare_golden_conversion,
    finalize_corpus_regression,
    load_corpus_manifest,
    load_corpus_regression_result,
    load_golden_comparison,
    record_corpus_stage,
    verify_corpus_snapshot,
)
from smf.workload.identity import stable_id

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS / "manifests" / "cv03-golden-conversion.yaml"


def _admit(tmp_path: Path, subject_id: str, *, run_id: str = "cv03-run") -> Path:
    return admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=MANIFEST,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id=subject_id,
            run_id=run_id,
            attempt_id="attempt-1",
            output_root=tmp_path / "out",
        )
    )


def _source(qualification_path: Path) -> tuple[dict[str, object], bytes]:
    qualification = verify_corpus_snapshot(qualification_path)
    subject = next(item for item in qualification["artifacts"] if item["is_subject"])
    return qualification, (qualification_path.parent / subject["snapshot_uri"]).read_bytes()


def _record_positive(qualification_path: Path, tmp_path: Path) -> str:
    qualification, source = _source(qualification_path)
    plan = plan_rules(source, "sparksql")
    subject = next(item for item in qualification["artifacts"] if item["is_subject"])
    source_artifact_id = stable_id(
        "CRART",
        {
            "qualification_id": qualification["qualification_id"],
            "relative_path": subject["relative_path"],
            "sha256": subject["sha256"],
        },
    )
    converted = execute_plan(
        source,
        plan,
        workload_id=str(qualification["workload_id"]),
        source_artifact_id=source_artifact_id,
        run_id=str(qualification["run_id"]),
        attempt_id=str(qualification["attempt_id"]),
    )
    generated = tmp_path / "generated.sql"
    generated.write_text(converted.content, encoding="utf-8")
    record_corpus_stage(
        qualification_path,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=StageStatus.PASSED,
            provider=converted.provider,
            provider_version="smf-0.1.0",
            artifacts=(StageArtifactInput("generated-main", generated),),
            decision_id=plan.plan_id,
            producer_evidence=converted.metadata,
        ),
    )
    return hashlib.sha256(generated.read_bytes()).hexdigest()


def test_positive_golden_is_exact_and_does_not_claim_parity(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive")
    generated_digest = _record_positive(qualification, tmp_path)
    comparison = load_golden_comparison(compare_golden_conversion(qualification))
    assert comparison["outcome"] == "matched"
    assert comparison["expected_sha256"] == generated_digest

    report = tmp_path / "static-validation.json"
    report.write_text(json.dumps({"generated_digest": generated_digest}) + "\n")
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.VALIDATION,
            status=StageStatus.PASSED,
            provider="smf-static-validator",
            provider_version="1.0.0",
            artifacts=(StageArtifactInput("static-validation", report),),
            input_artifact_digest=generated_digest,
            validation_kind="static",
            checks=(
                {
                    "check_id": "sparksql-nonempty",
                    "status": "pass",
                    "evidence": {"artifact_digest": generated_digest},
                },
            ),
        ),
    )
    result = load_corpus_regression_result(finalize_corpus_regression(qualification))
    assert result["terminal_disposition"] == "passed"
    assert result["telemetry"]["golden_matched"] is True
    assert result["telemetry"]["validated"] is True
    assert result["telemetry"]["executed"] is False
    assert result["telemetry"]["parity_passed"] is False


@pytest.mark.parametrize(
    ("subject_id", "status", "terminal"),
    [
        ("cv03-proc-format-negative", StageStatus.UNSUPPORTED, "unsupported"),
        ("cv03-macro-negative", StageStatus.HUMAN_PENDING, "human_pending"),
    ],
)
def test_construct_families_match_expected_non_generation_without_success_claim(
    tmp_path: Path, subject_id: str, status: StageStatus, terminal: str
) -> None:
    qualification = _admit(tmp_path, subject_id, run_id=subject_id)
    _, source = _source(qualification)
    plan = plan_rules(source, "sparksql")
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=status,
            provider="smf-deterministic",
            provider_version="smf-0.1.0",
            decision_id=plan.plan_id,
        ),
    )
    comparison = load_golden_comparison(compare_golden_conversion(qualification))
    result = load_corpus_regression_result(finalize_corpus_regression(qualification))
    assert comparison["outcome"] == "matched"
    assert comparison["actual_sha256"] is None
    assert result["terminal_disposition"] == terminal
    assert result["telemetry"]["golden_matched"] is True
    assert result["telemetry"]["generated"] is False
    assert result["telemetry"]["validated"] is False
    assert result["telemetry"]["parity_passed"] is False


def test_corrupted_expected_output_fails_even_when_manifest_hash_is_updated(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    manifest = corpus / "manifests" / MANIFEST.name
    expected = corpus / "workloads" / "golden" / "cv03" / "expected" / "proc-sql.sql"
    expected.write_text("select name from members;\n", encoding="utf-8")
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][3]["sha256"] = hashlib.sha256(expected.read_bytes()).hexdigest()
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id="cv03-proc-sql-positive",
            run_id="corrupted-golden",
            attempt_id="attempt-1",
            output_root=tmp_path / "out-corrupt",
        )
    )
    _record_positive(qualification, tmp_path)
    comparison = load_golden_comparison(compare_golden_conversion(qualification))
    assert comparison["outcome"] == "mismatched"
    assert comparison["mismatch_category"] == "behavioral-evidence"
    result = load_corpus_regression_result(finalize_corpus_regression(qualification))
    assert result["terminal_disposition"] == "failed"
    assert result["telemetry"]["golden_matched"] is False


def test_caller_selected_provider_label_cannot_manufacture_match(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="wrong-provider")
    qualification_data, _ = _source(qualification)
    expected = qualification.parent / qualification_data["golden_contract"]["snapshot_uri"]
    caller_output = tmp_path / "caller.sql"
    caller_output.write_bytes(expected.read_bytes())
    with pytest.raises(ValueError, match="package-owned deterministic conversion evidence"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="caller-approved",
                provider_version="trust-me",
                artifacts=(StageArtifactInput("generated-main", caller_output),),
            ),
        )


@pytest.mark.parametrize("decision_id", [None, "caller-authored-not-a-plan", "CVPLAN-unrelated"])
def test_caller_authored_conversion_decision_cannot_manufacture_match(
    tmp_path: Path, decision_id: str | None
) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="forged-plan")
    qualification_data, _ = _source(qualification)
    expected = qualification.parent / qualification_data["golden_contract"]["snapshot_uri"]
    caller_output = tmp_path / "caller-copy.sql"
    caller_output.write_bytes(expected.read_bytes())

    with pytest.raises(ValueError, match="package-owned deterministic conversion evidence"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="smf-deterministic",
                provider_version="smf-0.1.0",
                artifacts=(StageArtifactInput("generated-main", caller_output),),
                decision_id=decision_id,
            ),
        )

    assert not qualification.with_name("golden-comparison.json").exists()


def test_caller_authored_plan_metadata_cannot_manufacture_match(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="forged-metadata")
    qualification_data, source = _source(qualification)
    plan = plan_rules(source, "sparksql")
    expected = qualification.parent / qualification_data["golden_contract"]["snapshot_uri"]
    caller_output = tmp_path / "caller-metadata.sql"
    caller_output.write_bytes(expected.read_bytes())
    with pytest.raises(ValueError, match="package-owned deterministic conversion evidence"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="smf-deterministic",
                provider_version="smf-0.1.0",
                artifacts=(StageArtifactInput("generated-main", caller_output),),
                decision_id=plan.plan_id,
                producer_evidence={"plan": plan.to_dict(), "result": "passed"},
            ),
        )


def test_coordinated_source_and_golden_change_cannot_bless_sas_date_semantics(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    manifest = corpus / "manifests" / MANIFEST.name
    source = corpus / "workloads" / "golden" / "cv03" / "source" / "proc-sql.sas"
    expected = corpus / "workloads" / "golden" / "cv03" / "expected" / "proc-sql.sql"
    source.write_text(
        "proc sql; select id from members where event_date = '01JAN2020'd; quit;\n",
        encoding="utf-8",
    )
    expected.write_text(
        "select id from members where event_date = '01JAN2020'd;\n", encoding="utf-8"
    )
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    payload["artifacts"][3]["sha256"] = hashlib.sha256(expected.read_bytes()).hexdigest()
    golden = payload["regression"]["subjects"][0]["golden"]
    golden["golden_version"] = "2.0.0"
    golden["rationale"] = "Caller claims the SAS date literal is source faithful."
    golden["review_reference"] = "caller-authored-review"
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id="cv03-proc-sql-positive",
            run_id="coordinated-drift",
            attempt_id="attempt-1",
            output_root=tmp_path / "out-drift",
        )
    )
    with pytest.raises(ValueError, match="qualified"):
        _record_positive(qualification, tmp_path)
    assert not qualification.with_name("golden-comparison.json").exists()


def test_coordinated_supported_source_and_golden_change_still_needs_behavioral_evidence(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    manifest = corpus / "manifests" / MANIFEST.name
    source = corpus / "workloads" / "golden" / "cv03" / "source" / "proc-sql.sas"
    expected = corpus / "workloads" / "golden" / "cv03" / "expected" / "proc-sql.sql"
    source.write_text("proc sql; select id from members where id=42; quit;\n", encoding="utf-8")
    expected.write_text("select id from members where id=42;\n", encoding="utf-8")
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][0]["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    payload["artifacts"][3]["sha256"] = hashlib.sha256(expected.read_bytes()).hexdigest()
    golden = payload["regression"]["subjects"][0]["golden"]
    golden["golden_version"] = "2.0.0"
    golden["rationale"] = "Caller claims coordinated source and target changes are reviewed."
    golden["review_reference"] = "caller-authored-review"
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id="cv03-proc-sql-positive",
            run_id="coordinated-supported-drift",
            attempt_id="attempt-1",
            output_root=tmp_path / "out-supported-drift",
        )
    )
    _record_positive(qualification, tmp_path)
    comparison = load_golden_comparison(compare_golden_conversion(qualification))
    assert comparison["outcome"] == "mismatched"
    assert comparison["mismatch_category"] == "behavioral-evidence"


def test_fabricated_review_and_unresolved_behavior_digest_cannot_authorize_golden(
    tmp_path: Path,
) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    manifest = corpus / "manifests" / MANIFEST.name
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    golden = payload["regression"]["subjects"][0]["golden"]
    golden["review_reference"] = "caller-says-approved"
    golden["behavioral_evidence_digest"] = "a" * 64
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id="cv03-proc-sql-positive",
            run_id="fabricated-review",
            attempt_id="attempt-1",
            output_root=tmp_path / "out-fabricated-review",
        )
    )
    _record_positive(qualification, tmp_path)
    comparison = load_golden_comparison(compare_golden_conversion(qualification))
    assert comparison["outcome"] == "mismatched"
    assert comparison["mismatch_category"] == "behavioral-evidence"


def test_caller_asserted_golden_stage_cannot_manufacture_match(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="asserted-golden")
    _record_positive(qualification, tmp_path)
    asserted = tmp_path / "asserted.json"
    asserted.write_text('{"passed":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="canonical comparator evidence"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.GOLDEN_COMPARISON,
                status=StageStatus.PASSED,
                provider="caller",
                provider_version="trust-me",
                artifacts=(StageArtifactInput("golden-comparison", asserted),),
                decision_id="approved",
            ),
        )


def test_golden_snapshot_mutation_is_rejected_before_comparison(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="mutated-snapshot")
    _record_positive(qualification, tmp_path)
    data = verify_corpus_snapshot(qualification)
    snapshot = qualification.parent / data["golden_contract"]["snapshot_uri"]
    snapshot.chmod(0o600)
    snapshot.write_text("select changed from members;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="golden snapshot"):
        compare_golden_conversion(qualification)


def test_comparison_retry_and_concurrency_preserve_one_decision(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="concurrent")
    _record_positive(qualification, tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(pool.map(lambda _: compare_golden_conversion(qualification), range(2)))
    assert paths[0] == paths[1]
    assert paths[0].read_bytes() == paths[1].read_bytes()
    assert load_golden_comparison(paths[0])["outcome"] == "matched"


def test_retry_recovers_missing_stage_projection_without_redeciding(tmp_path: Path) -> None:
    qualification = _admit(tmp_path, "cv03-proc-sql-positive", run_id="recover-stage")
    _record_positive(qualification, tmp_path)
    comparison = compare_golden_conversion(qualification)
    before = comparison.read_bytes()
    qualification.with_name("stage-golden-comparison.json").unlink()

    assert compare_golden_conversion(qualification).read_bytes() == before
    assert load_golden_comparison(comparison)["outcome"] == "matched"
    stage = json.loads(qualification.with_name("stage-golden-comparison.json").read_text())
    derived = qualification.parent / stage["artifacts"][0]["artifact_uri"]
    derived.unlink()
    assert compare_golden_conversion(qualification).read_bytes() == before
    assert derived.is_file()


def test_duplicate_golden_id_and_unknown_comparison_mode_fail_closed(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["regression"]["subjects"][1]["golden"]["golden_id"] = payload["regression"]["subjects"][
        0
    ]["golden"]["golden_id"]
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate corpus golden id"):
        load_corpus_manifest(duplicate, verify_files=False)

    payload["regression"]["subjects"][1]["golden"]["golden_id"] = "unique"
    payload["regression"]["subjects"][0]["golden"]["comparison_mode"] = "close-enough"
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(Exception, match="exact-bytes"):
        load_corpus_manifest(malformed, verify_files=False)


def test_secret_canary_cannot_enter_golden_snapshot(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    manifest = corpus / "manifests" / MANIFEST.name
    expected = corpus / "workloads" / "golden" / "cv03" / "expected" / "proc-sql.sql"
    expected.write_text('select "secret-canary-CV03" as leaked;\n', encoding="utf-8")
    payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][3]["sha256"] = hashlib.sha256(expected.read_bytes()).hexdigest()
    manifest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest,
            scenario_id="cv03-golden-conversion",
            workload_id="cv03-golden-conversion",
            subject_id="cv03-proc-sql-positive",
            run_id="secret-golden",
            attempt_id="attempt-1",
            output_root=tmp_path / "out-secret",
        )
    )
    result = json.loads(qualification.read_text(encoding="utf-8"))
    assert result["status"] == "blocked"
    assert "credential material" in result["blockers"][0]["reason"]
    durable = b"".join(
        path.read_bytes() for path in qualification.parent.rglob("*") if path.is_file()
    )
    assert b"secret-canary-CV03" not in durable
