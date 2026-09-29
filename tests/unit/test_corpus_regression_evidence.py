import json
import shutil
from pathlib import Path

import pytest

from smf.corpus import (
    CorpusRegressionRequest,
    CorpusStageRequest,
    RegressionStage,
    StageArtifactInput,
    StageStatus,
    admit_corpus_regression,
    finalize_corpus_regression,
    load_corpus_manifest,
    load_corpus_regression_result,
    record_corpus_stage,
    verify_corpus_snapshot,
)
from smf.corpus.loader import sha256_file

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "representative-multi-artifact-foundation.yaml"


def _request(tmp_path: Path, *, attempt_id: str = "attempt-1") -> CorpusRegressionRequest:
    return CorpusRegressionRequest(
        manifest_path=MANIFEST,
        scenario_id="representative-multi-artifact-foundation",
        workload_id="representative-multi-artifact-foundation",
        subject_id="representative-multi-artifact-main",
        run_id="run-1",
        attempt_id=attempt_id,
        output_root=tmp_path / "out",
    )


def _record_generated(qualification: Path, tmp_path: Path) -> tuple[Path, str]:
    generated = tmp_path / "generated.py"
    generated.write_text('result = source_df.select("id")\n', encoding="utf-8")
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=StageStatus.PASSED,
            provider="sas2databricks",
            provider_version="0.4.0",
            artifacts=(StageArtifactInput("generated-main", generated),),
        ),
    )
    return generated, sha256_file(generated)


def test_representative_subject_is_explicit_and_complete() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.regression is not None
    subject = manifest.regression.subjects[0]
    assert subject.entrypoint.name == "main.sas"
    assert subject.entrypoint in subject.source_closure
    assert subject.validation_policy.validation_kind == "static"
    assert subject.evidence_scope == "shared-regression"


def test_admission_snapshots_exact_closure_and_survives_original_mutation(
    tmp_path: Path,
) -> None:
    qualification_path = admit_corpus_regression(_request(tmp_path))
    qualification = verify_corpus_snapshot(qualification_path)

    assert qualification["status"] == "admitted"
    assert qualification["source_digest"]
    assert len(qualification["artifacts"]) == 6
    assert all(not Path(item["snapshot_uri"]).is_absolute() for item in qualification["artifacts"])

    original = (
        MANIFEST.parent.parent
        / "workloads/representative/multi-artifact-foundation/source/main.sas"
    )
    snapshot = next(item for item in qualification["artifacts"] if item["is_subject"])
    assert (
        qualification_path.parent / snapshot["snapshot_uri"]
    ).read_bytes() == original.read_bytes()


def test_missing_manifest_persists_explicit_unresolved_blocker(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request = CorpusRegressionRequest(
        **{**request.__dict__, "manifest_path": tmp_path / "missing.yaml"}
    )
    path = admit_corpus_regression(request)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["status"] == "blocked"
    assert payload["blockers"][0]["status"] == "unresolved"
    result = load_corpus_regression_result(finalize_corpus_regression(path))
    assert result["terminal_disposition"] == "blocked"
    assert result["telemetry"]["blocked"] is True
    with pytest.raises(ValueError, match="not admitted"):
        verify_corpus_snapshot(path)


def test_snapshot_mutation_blocks_downstream_work(tmp_path: Path) -> None:
    qualification_path = admit_corpus_regression(_request(tmp_path))
    qualification = verify_corpus_snapshot(qualification_path)
    snapshot = qualification_path.parent / qualification["artifacts"][0]["snapshot_uri"]
    snapshot.chmod(0o600)
    snapshot.write_text("mutated", encoding="utf-8")

    with pytest.raises(ValueError, match="snapshot is missing or has changed"):
        verify_corpus_snapshot(qualification_path)


def test_static_validation_is_validated_but_never_parity(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    _, generated_digest = _record_generated(qualification, tmp_path)
    validation_report = tmp_path / "validation.json"
    validation_report.write_text('{"check":"syntax","status":"pass"}\n', encoding="utf-8")
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.VALIDATION,
            status=StageStatus.PASSED,
            provider="smf-static-validator",
            provider_version="1",
            artifacts=(StageArtifactInput("validation-report", validation_report),),
            input_artifact_digest=generated_digest,
            validation_kind="static",
            checks=(
                {
                    "check_id": "python-syntax",
                    "status": "pass",
                    "evidence": {"artifact_digest": generated_digest},
                },
            ),
        ),
    )

    result = load_corpus_regression_result(finalize_corpus_regression(qualification))

    assert result["terminal_disposition"] == "passed"
    assert result["telemetry"] == {
        "generated": True,
        "executed": False,
        "validated": True,
        "parity_passed": False,
        "golden_matched": False,
        "human_assisted": False,
        "blocked": False,
    }


@pytest.mark.parametrize(
    "status",
    [StageStatus.BLOCKED, StageStatus.SKIPPED, StageStatus.UNSUPPORTED],
)
def test_non_success_conversion_cannot_be_counted_as_generated(
    tmp_path: Path, status: StageStatus
) -> None:
    qualification = admit_corpus_regression(_request(tmp_path, attempt_id=status.value))
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=status,
            provider="sas2databricks",
            provider_version="0.4.0",
            reasons=("provider did not produce eligible code",),
        ),
    )
    result = load_corpus_regression_result(finalize_corpus_regression(qualification))

    assert result["telemetry"]["generated"] is False
    assert result["telemetry"]["validated"] is False
    assert result["telemetry"]["parity_passed"] is False
    assert result["terminal_disposition"] != "passed"


def test_self_asserted_human_approval_cannot_authorize_success(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    with pytest.raises(ValueError, match="authenticated, attempt-bound"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.HUMAN_APPROVAL,
                status=StageStatus.PASSED,
                provider="caller",
                provider_version="1",
                decision_id="approve-anything",
            ),
        )


@pytest.mark.parametrize(
    "status", [StageStatus.HUMAN_PENDING, StageStatus.HUMAN_DENIED, StageStatus.CANCELLED]
)
def test_pending_and_denied_remain_distinct(tmp_path: Path, status: StageStatus) -> None:
    qualification = admit_corpus_regression(_request(tmp_path, attempt_id=status.value))
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=RegressionStage.HUMAN_APPROVAL,
            status=status,
            provider="human-review",
            provider_version="1",
            decision_id=f"decision-{status.value}",
        ),
    )
    result = load_corpus_regression_result(finalize_corpus_regression(qualification))
    assert result["terminal_disposition"] == status.value
    assert result["telemetry"]["blocked"] is True


def test_retry_repairs_missing_telemetry_without_changing_result(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    result_path = finalize_corpus_regression(qualification)
    before = result_path.read_bytes()
    telemetry = result_path.with_name("telemetry.json")
    telemetry.unlink()

    assert finalize_corpus_regression(qualification) == result_path
    assert result_path.read_bytes() == before
    assert telemetry.is_file()


def test_retry_recovers_missing_snapshot_only_from_same_manifest_bytes(tmp_path: Path) -> None:
    request = _request(tmp_path)
    qualification_path = admit_corpus_regression(request)
    qualification = verify_corpus_snapshot(qualification_path)
    snapshot = qualification_path.parent / qualification["artifacts"][0]["snapshot_uri"]
    expected = qualification["artifacts"][0]["sha256"]
    snapshot.unlink()

    assert admit_corpus_regression(request) == qualification_path
    assert sha256_file(snapshot) == expected


def test_validation_must_bind_exact_generated_digest(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    _record_generated(qualification, tmp_path)
    report = tmp_path / "validation.json"
    report.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not identify one generated artifact"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.VALIDATION,
                status=StageStatus.PASSED,
                provider="smf-static-validator",
                provider_version="1",
                artifacts=(StageArtifactInput("validation-report", report),),
                input_artifact_digest="0" * 64,
                validation_kind="static",
                checks=(
                    {
                        "check_id": "syntax",
                        "status": "pass",
                        "evidence": {"artifact_digest": "0" * 64},
                    },
                ),
            ),
        )


def test_pass_boolean_cannot_override_nonreproducible_static_evidence(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    generated = tmp_path / "invalid.py"
    generated.write_text("def broken(:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="meaningful converted workload logic"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="converter",
                provider_version="1",
                artifacts=(StageArtifactInput("generated-main", generated),),
            ),
        )


@pytest.mark.parametrize("validation_kind", ["structural-parity", "data-parity", "semantic-parity"])
def test_validation_cannot_override_qualified_static_policy(
    tmp_path: Path, validation_kind: str
) -> None:
    qualification = admit_corpus_regression(_request(tmp_path, attempt_id=validation_kind))
    _, generated_digest = _record_generated(qualification, tmp_path)
    report = tmp_path / f"{validation_kind}.json"
    report.write_text('{"approved":true}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="qualified validation policy"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.VALIDATION,
                status=StageStatus.PASSED,
                provider="caller",
                provider_version="1",
                artifacts=(StageArtifactInput("validation-report", report),),
                input_artifact_digest=generated_digest,
                validation_kind=validation_kind,
                checks=(
                    {
                        "check_id": "claimed-parity",
                        "status": "pass",
                        "evidence": {"approved": True},
                    },
                ),
                evidence_origin="sas-executed-baseline",
                baseline_evidence_id="invented-baseline",
                source_execution_id="invented-execution",
            ),
        )

    assert not (qualification.parent / "stage-validation.json").exists()
    assert not (qualification.parent / "evidence" / "validation").exists()


def test_literal_include_omitted_from_declared_closure_fails_closed(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_ROOT, corpus)
    manifest_path = corpus / "manifests" / MANIFEST.name
    import yaml

    payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    payload["workload"]["relationships"] = []
    payload["regression"]["subjects"][0]["source_closure"] = [
        "../workloads/representative/multi-artifact-foundation/source/main.sas"
    ]
    manifest_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    qualification_path = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest_path,
            scenario_id="representative-multi-artifact-foundation",
            workload_id="representative-multi-artifact-foundation",
            subject_id="representative-multi-artifact-main",
            run_id="incomplete-closure",
            attempt_id="attempt-1",
            output_root=tmp_path / "out",
        )
    )
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))

    assert qualification["status"] == "blocked"
    assert "literal dependency" in qualification["blockers"][0]["reason"]
    assert "configure.sas" in qualification["blockers"][0]["reason"]
    assert "member_rules.sas" in qualification["blockers"][0]["reason"]
    assert qualification["artifacts"] == []


def test_literal_data_dependency_omitted_from_closure_fails_closed(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS_ROOT, corpus)
    manifest_path = corpus / "manifests" / "dependency-scheduler-foundation.yaml"
    import yaml

    payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    consumer = "../workloads/representative/dependency-scheduler-foundation/source/consumer.sas"
    payload["workload"]["entrypoints"] = [consumer]
    payload["workload"]["relationships"] = []
    payload["regression"] = {
        "version": 1,
        "subjects": [
            {
                "subject_id": "consumer",
                "workload_id": "dependency-scheduler-foundation",
                "entrypoint": consumer,
                "target": "pyspark",
                "source_closure": [consumer],
                "stages": ["admission", "conversion", "static-validation"],
                "validation_policy": {
                    "policy_id": "static",
                    "policy_version": "1",
                    "validation_kind": "static",
                },
                "evidence_scope": "test-only",
                "environment": "test-only",
            }
        ],
    }
    manifest_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    qualification = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=manifest_path,
            scenario_id="dependency-scheduler-foundation",
            workload_id="dependency-scheduler-foundation",
            subject_id="consumer",
            run_id="data-closure",
            attempt_id="attempt-1",
            output_root=tmp_path / "out",
        )
    )
    result = json.loads(qualification.read_text(encoding="utf-8"))
    assert result["status"] == "blocked"
    assert "data/shared.csv" in result["blockers"][0]["reason"]


@pytest.mark.parametrize(
    ("stage", "artifact_id", "filename"),
    [
        (RegressionStage.CONVERSION, "generated-main", "generated.py"),
        (RegressionStage.EXECUTION, "execution-output", "execution.log"),
        (RegressionStage.VALIDATION, "validation-report", "validation.json"),
        (RegressionStage.REPAIR, "repair-log", "repair.log"),
    ],
)
def test_stage_artifact_secrets_never_reach_durable_evidence_or_identity(
    tmp_path: Path, stage: RegressionStage, artifact_id: str, filename: str
) -> None:
    canary = f"secret-canary-AD04-{stage.value}"
    qualification = admit_corpus_regression(_request(tmp_path, attempt_id=f"secret-{stage.value}"))
    artifact = tmp_path / filename
    artifact.write_text(f'DB_PASSWORD="{canary}"\n', encoding="utf-8")
    record_corpus_stage(
        qualification,
        CorpusStageRequest(
            stage=stage,
            status=StageStatus.BLOCKED,
            provider="safe-provider",
            provider_version="1",
            artifacts=(StageArtifactInput(artifact_id, artifact),),
            validation_kind="static" if stage == RegressionStage.VALIDATION else None,
        ),
    )

    durable = b"".join(
        path.read_bytes() for path in qualification.parent.rglob("*") if path.is_file()
    )
    assert canary.encode() not in durable
    assert b"<redacted>" in durable


def test_unknown_stage_and_status_values_fail_closed(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    with pytest.raises(ValueError):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage="convertd",  # type: ignore[arg-type]
                status=StageStatus.PASSED,
                provider="provider",
                provider_version="1",
            ),
        )
    with pytest.raises(ValueError):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status="complete",  # type: ignore[arg-type]
                provider="provider",
                provider_version="1",
            ),
        )


@pytest.mark.parametrize("evidence_origin", ["sas-basline", "caller-approved"])
def test_unknown_validation_evidence_origin_fails_closed(
    tmp_path: Path, evidence_origin: str
) -> None:
    qualification = admit_corpus_regression(_request(tmp_path, attempt_id=evidence_origin))
    with pytest.raises(ValueError, match="unsupported evidence_origin"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.VALIDATION,
                status=StageStatus.BLOCKED,
                provider="validator",
                provider_version="1",
                validation_kind="static",
                evidence_origin=evidence_origin,
            ),
        )


def test_static_validation_rejects_caller_supplied_parity_attestations(tmp_path: Path) -> None:
    qualification = admit_corpus_regression(_request(tmp_path))
    with pytest.raises(ValueError, match="cannot accept parity baseline attestations"):
        record_corpus_stage(
            qualification,
            CorpusStageRequest(
                stage=RegressionStage.VALIDATION,
                status=StageStatus.BLOCKED,
                provider="validator",
                provider_version="1",
                validation_kind="static",
                evidence_origin="sas-executed-baseline",
                baseline_evidence_id="invented",
                source_execution_id="invented",
            ),
        )
