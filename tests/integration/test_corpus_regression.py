import ast
import json
from importlib.metadata import version
from pathlib import Path

import pytest

from smf.conversion.providers.sas2databricks import Sas2DatabricksProvider
from smf.corpus import (
    CorpusRegressionRequest,
    CorpusStageRequest,
    RegressionStage,
    StageArtifactInput,
    StageStatus,
    admit_corpus_regression,
    finalize_corpus_regression,
    load_corpus_regression_result,
    record_corpus_stage,
    verify_corpus_snapshot,
)
from smf.corpus.loader import sha256_file

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "public-sas-official-language-breadth.yaml"
REPRESENTATIVE_MANIFEST = (
    CORPUS_ROOT / "manifests" / "representative-multi-artifact-foundation.yaml"
)


def test_untouched_public_subject_passes_pinned_converter_and_static_gate(
    tmp_path: Path,
) -> None:
    qualification_path = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=MANIFEST,
            scenario_id="public-sas-official-language-breadth",
            workload_id="public-sas-official-language-breadth",
            subject_id="public-sas-select-statement",
            run_id="confidence-run",
            attempt_id="attempt-1",
            output_root=tmp_path / "out",
        )
    )
    qualification = verify_corpus_snapshot(qualification_path)
    source_record = next(item for item in qualification["artifacts"] if item["is_subject"])
    immutable_source = qualification_path.parent / source_record["snapshot_uri"]

    provider_version = version("sas2databricks")
    assert provider_version.startswith("0.4.")
    converted = Sas2DatabricksProvider().convert(immutable_source, "pyspark")
    assert converted.provider == "sas2databricks"
    assert converted.content.strip()
    assert converted.metadata["summary"]["review"] == 0
    ast.parse(converted.content)

    generated = tmp_path / "generated.py"
    generated.write_text(converted.content, encoding="utf-8")
    record_corpus_stage(
        qualification_path,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=StageStatus.PASSED,
            provider=converted.provider,
            provider_version=provider_version,
            artifacts=(StageArtifactInput("generated-main", generated),),
        ),
    )
    generated_digest = sha256_file(generated)
    validation_report = tmp_path / "validation.json"
    validation_report.write_text(
        json.dumps(
            {
                "policy_id": "smf-static-validation",
                "policy_version": "1",
                "generated_digest": generated_digest,
                "checks": [{"check_id": "python-syntax", "status": "pass"}],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    record_corpus_stage(
        qualification_path,
        CorpusStageRequest(
            stage=RegressionStage.VALIDATION,
            status=StageStatus.PASSED,
            provider="python-ast",
            provider_version="3.11",
            artifacts=(StageArtifactInput("static-validation-report", validation_report),),
            input_artifact_digest=generated_digest,
            validation_kind="static",
            checks=(
                {
                    "check_id": "python-syntax",
                    "status": "pass",
                    "evidence": {"generated_digest": generated_digest},
                },
            ),
        ),
    )

    result = load_corpus_regression_result(finalize_corpus_regression(qualification_path))
    assert result["terminal_disposition"] == "passed"
    assert result["telemetry"]["generated"] is True
    assert result["telemetry"]["validated"] is True
    assert result["telemetry"]["executed"] is False
    assert result["telemetry"]["parity_passed"] is False
    assert result["evidence_scope"] == "shared-regression"


def test_representative_zero_step_conversion_cannot_be_recorded_as_generated(
    tmp_path: Path,
) -> None:
    qualification_path = admit_corpus_regression(
        CorpusRegressionRequest(
            manifest_path=REPRESENTATIVE_MANIFEST,
            scenario_id="representative-multi-artifact-foundation",
            workload_id="representative-multi-artifact-foundation",
            subject_id="representative-multi-artifact-main",
            run_id="zero-step-run",
            attempt_id="attempt-1",
            output_root=tmp_path / "out",
        )
    )
    qualification = verify_corpus_snapshot(qualification_path)
    source_record = next(item for item in qualification["artifacts"] if item["is_subject"])
    immutable_source = qualification_path.parent / source_record["snapshot_uri"]
    converted = Sas2DatabricksProvider().convert(immutable_source, "pyspark")

    assert converted.metadata["summary"]["steps"] == 0
    generated = tmp_path / "zero-step.py"
    generated.write_text(converted.content, encoding="utf-8")
    with pytest.raises(ValueError, match="meaningful converted workload logic"):
        record_corpus_stage(
            qualification_path,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider=converted.provider,
                provider_version=version("sas2databricks"),
                artifacts=(StageArtifactInput("generated-main", generated),),
            ),
        )

    result = load_corpus_regression_result(finalize_corpus_regression(qualification_path))
    assert result["terminal_disposition"] == "blocked"
    assert result["telemetry"]["generated"] is False
    assert result["telemetry"]["validated"] is False
