import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

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
)
from smf.corpus.loader import _literal_file_dependencies, sha256_file

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS / "manifests/representative-multi-artifact-foundation.yaml"


def _request(root: Path) -> CorpusRegressionRequest:
    return CorpusRegressionRequest(
        manifest_path=MANIFEST,
        scenario_id="representative-multi-artifact-foundation",
        workload_id="representative-multi-artifact-foundation",
        subject_id="representative-multi-artifact-main",
        run_id="human-review",
        attempt_id="attempt-1",
        output_root=root / "out",
    )


@pytest.mark.parametrize(
    "source",
    [
        "from pyspark.sql import SparkSession\nspark = SparkSession.builder.getOrCreate()\n",
        "from pyspark.sql import SparkSession as Session\n"
        's = Session.builder.appName("test").getOrCreate()\n',
        'spark.conf.set("spark.sql.shuffle.partitions", "2")\n',
        "result = 1\n",
        'print("conversion complete")\n',
        'spark.sql("SET spark.sql.shuffle.partitions=2")\n',
        'def unused():\n    return spark.table("source").select("id")\n',
    ],
)
def test_setup_only_conversion_stays_blocked(tmp_path: Path, source: str) -> None:
    q = admit_corpus_regression(_request(tmp_path))
    generated = tmp_path / "generated.py"
    generated.write_text(source)
    with pytest.raises(ValueError, match="meaningful converted workload logic"):
        record_corpus_stage(
            q,
            CorpusStageRequest(
                stage=RegressionStage.CONVERSION,
                status=StageStatus.PASSED,
                provider="test-converter",
                provider_version="1",
                artifacts=(StageArtifactInput("generated-main", generated),),
            ),
        )
    result = load_corpus_regression_result(finalize_corpus_regression(q))
    assert result["terminal_disposition"] == "blocked"
    assert not result["telemetry"]["generated"]
    assert not result["telemetry"]["validated"]
    assert not (q.parent / "evidence/conversion").exists()


@pytest.mark.parametrize(
    "source",
    [
        'result = source_df.select("id").filter("id > 0")\n',
        'result = spark.sql("SELECT id FROM members")\n',
        'result = source_df.withColumnRenamed("member", "member_id")\n',
    ],
)
def test_data_operations_remain_generatable_without_claiming_parity(
    tmp_path: Path, source: str
) -> None:
    q = admit_corpus_regression(_request(tmp_path))
    generated = tmp_path / "generated.py"
    generated.write_text(source)
    record_corpus_stage(
        q,
        CorpusStageRequest(
            stage=RegressionStage.CONVERSION,
            status=StageStatus.PASSED,
            provider="test-converter",
            provider_version="1",
            artifacts=(StageArtifactInput("generated-main", generated),),
        ),
    )
    result = load_corpus_regression_result(finalize_corpus_regression(q))
    assert result["telemetry"]["generated"]
    assert not result["telemetry"]["executed"]
    assert not result["telemetry"]["validated"]
    assert not result["telemetry"]["parity_passed"]


@pytest.mark.parametrize(
    "field",
    [
        "execution_id",
        "decision_id",
        "input_artifact_digest",
        "validation_kind",
        "evidence_origin",
        "baseline_evidence_id",
        "source_execution_id",
    ],
)
def test_identity_metadata_rejects_secrets_before_persistence(tmp_path: Path, field: str) -> None:
    q = admit_corpus_regression(_request(tmp_path))
    canary = "synthetic-ad04-identity-canary"
    request = CorpusStageRequest(
        stage=RegressionStage.EXECUTION,
        status=StageStatus.BLOCKED,
        provider="test-runner",
        provider_version="1",
    )
    request = replace(request, **{field: f"DB_PASSWORD={canary}"})
    with pytest.raises(ValueError, match="credential") as error:
        record_corpus_stage(q, request)
    assert canary not in str(error.value)
    assert not list(q.parent.glob("stage-*.json"))
    assert not (q.parent / "evidence").exists()
    assert not any(
        canary.encode() in path.read_bytes() for path in q.parent.rglob("*") if path.is_file()
    )


@pytest.mark.parametrize(
    "prefix",
    [
        '/* %include "missing.sas"; */\n',
        '* %include "missing.sas";\n',
        '%* %include "missing.sas";\n',
        "title '%include \"missing.sas\";';\n",
        "title \"infile 'missing.csv';\";\n",
    ],
)
def test_comment_and_string_dependencies_do_not_block_admission(
    tmp_path: Path, prefix: str
) -> None:
    corpus = tmp_path / "corpus"
    workload = "workloads/representative/multi-artifact-foundation"
    shutil.copytree(CORPUS / workload, corpus / workload)
    manifest = corpus / "manifests" / MANIFEST.name
    manifest.parent.mkdir()
    payload = yaml.safe_load(MANIFEST.read_text())
    main = corpus / workload / "source/main.sas"
    main.write_text(prefix + main.read_text())
    payload["artifacts"][0]["sha256"] = sha256_file(main)
    manifest.write_text(yaml.safe_dump(payload))
    q = admit_corpus_regression(replace(_request(tmp_path), manifest_path=manifest))
    assert json.loads(q.read_text())["status"] == "admitted"


def test_active_dependency_after_comment_still_must_exist(tmp_path: Path) -> None:
    source = tmp_path / "main.sas"
    source.write_text('/* ignored */ %include "needed.sas";\n')
    with pytest.raises(ValueError, match="missing or ambiguous"):
        _literal_file_dependencies(source, tmp_path)
    dependency = tmp_path / "needed.sas"
    dependency.write_text("data x; value=2*3; run;\n")
    assert _literal_file_dependencies(source, tmp_path) == (dependency,)
