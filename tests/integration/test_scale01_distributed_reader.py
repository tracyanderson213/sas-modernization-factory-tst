from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("pyspark")

import smf.distributed_sas_reader as distributed_reader
from smf.distributed_sas_reader import (
    DistributedReaderConfig,
    DistributedReaderRequest,
    run_distributed_reader,
    verify_distributed_reader,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_SCALE01") == "1":
        raise RuntimeError("SCALE-01 confidence requires the exact qualified local JAR bundle")
    pytest.skip("SCALE-01 qualified local JAR bundle is unavailable", allow_module_level=True)


def _request(**overrides: object) -> DistributedReaderRequest:
    values: dict[str, object] = {
        "client_id": "public-upstream",
        "workload_id": "scale01-public-fixture",
        "source_id": "ag121a-supp-sample",
        "run_id": "scale01-run",
        "attempt_id": "attempt-1",
        "source_relative_path": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "source_byte_count": SOURCE.stat().st_size,
        "oracle_relative_path": ORACLE.name,
        "oracle_sha256": hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        "oracle_byte_count": ORACLE.stat().st_size,
    }
    values.update(overrides)
    return DistributedReaderRequest(**values)  # type: ignore[arg-type]


def test_runtime_design_and_fixture_provenance_are_exact() -> None:
    design = json.loads(
        (ROOT / "config" / "dependencies" / "scale01-runtime.json").read_text(encoding="utf-8")
    )
    assert design["upstream"]["spark_sas7bdat"]["revision"] == (
        "dad0840bd89b7581c35a41ce372c61dc42d15eab"
    )
    assert design["upstream"]["parso"]["revision"] == ("3c514e66264f5f3d5b2970bc2509d749065630c0")
    assert design["fixture"]["sas7bdat_sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert design["fixture"]["csv_sha256"] == hashlib.sha256(ORACLE.read_bytes()).hexdigest()
    assert (
        design["fixture"]["license_sha256"]
        == hashlib.sha256((FIXTURE_ROOT / "LICENSE.spark-sas7bdat").read_bytes()).hexdigest()
    )
    assert design["collection_policy"] == "partition_summaries_only"
    assert not any(design["claims"].values())


def test_real_partitioned_read_streamed_reconciliation_and_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pyspark.sql import DataFrame

    def prohibited(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("whole-table driver collection is prohibited")

    monkeypatch.setattr(DataFrame, "collect", prohibited)
    monkeypatch.setattr(DataFrame, "toPandas", prohibited)
    execution = run_distributed_reader(
        _request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        config=DistributedReaderConfig(),
    )
    result = execution.result
    assert result["distributed_summary"]["row_count"] == 18_638
    assert result["oracle_summary"]["row_count"] == 18_638
    assert [item["row_count"] for item in result["partitions"]] == [8158, 8720, 1760]
    assert len(result["partitions"]) == 3
    assert result["reconciliation"] == {
        "schema_header_match": True,
        "row_count_match": True,
        "null_counts_match": True,
        "row_multiset_match": True,
        "absolute_tolerance": 0.0,
        "relative_tolerance": 0.0,
        "passed": True,
    }
    assert result["runtime"]["driver_row_collection"] is False
    assert result["runtime"]["partition_summary_collection_only"] is True
    assert not any(result["claims"].values())
    replay = verify_distributed_reader(
        execution.result_path,
        request=_request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        config=DistributedReaderConfig(),
    )
    assert replay.result == result


def test_source_symlink_and_artifact_mutation_fail_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / SOURCE.name).symlink_to(SOURCE)
    (source_root / ORACLE.name).write_bytes(ORACLE.read_bytes())
    with pytest.raises(ValueError, match="unsafe"):
        run_distributed_reader(
            _request(),
            source_root=source_root,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path / "out",
            config=DistributedReaderConfig(),
        )

    parso_symlink_root = tmp_path / "parso-symlink"
    parso_symlink_root.mkdir()
    (parso_symlink_root / "spark-sas7bdat-3.0.0-s_2.12.jar").write_bytes(
        (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").read_bytes()
    )
    (parso_symlink_root / "parso-2.0.14.jar").symlink_to(ARTIFACT_ROOT / "parso-2.0.14.jar")
    with pytest.raises(ValueError, match="unsafe"):
        run_distributed_reader(
            _request(),
            source_root=FIXTURE_ROOT,
            artifact_root=parso_symlink_root,
            evidence_root=tmp_path / "out-parso-link",
            config=DistributedReaderConfig(),
        )

    artifact_root_link = tmp_path / "artifact-root-link"
    artifact_root_link.symlink_to(ARTIFACT_ROOT, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe"):
        run_distributed_reader(
            _request(),
            source_root=FIXTURE_ROOT,
            artifact_root=artifact_root_link,
            evidence_root=tmp_path / "out-root-link",
            config=DistributedReaderConfig(),
        )

    artifact_symlink_root = tmp_path / "artifact-symlink"
    artifact_symlink_root.mkdir()
    (artifact_symlink_root / "spark-sas7bdat-3.0.0-s_2.12.jar").symlink_to(
        ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar"
    )
    with pytest.raises(ValueError, match="unsafe"):
        run_distributed_reader(
            _request(),
            source_root=FIXTURE_ROOT,
            artifact_root=artifact_symlink_root,
            evidence_root=tmp_path / "out-artifact-link",
            config=DistributedReaderConfig(),
        )

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    for name in ("spark-sas7bdat-3.0.0-s_2.12.jar", "parso-2.0.14.jar"):
        (artifact_root / name).write_bytes((ARTIFACT_ROOT / name).read_bytes())
    with (artifact_root / "spark-sas7bdat-3.0.0-s_2.12.jar").open("ab") as target:
        target.write(b"mutation")
    with pytest.raises(ValueError, match="snapshot identity mismatch"):
        run_distributed_reader(
            _request(),
            source_root=FIXTURE_ROOT,
            artifact_root=artifact_root,
            evidence_root=tmp_path / "out-2",
            config=DistributedReaderConfig(),
        )


def test_protected_identity_canary_is_rejected_without_echo(tmp_path: Path) -> None:
    canary = "secret-canary-scale01"
    with pytest.raises(ValueError) as captured:
        run_distributed_reader(
            _request(workload_id=canary),
            source_root=FIXTURE_ROOT,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path,
            config=DistributedReaderConfig(),
        )
    assert canary not in str(captured.value)


def test_snapshot_to_consumption_source_replacement_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / SOURCE.name
    source.write_bytes(SOURCE.read_bytes())
    (source_root / ORACLE.name).write_bytes(ORACLE.read_bytes())
    execute_staged = distributed_reader._execute_staged

    def replace_after_staging(*args: object, **kwargs: object) -> dict[str, object]:
        source.write_bytes(b"replacement-after-admission")
        return execute_staged(*args, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(distributed_reader, "_execute_staged", replace_after_staging)
    with pytest.raises(ValueError, match="snapshot identity mismatch"):
        run_distributed_reader(
            _request(),
            source_root=source_root,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path / "out-race",
            config=DistributedReaderConfig(),
        )


def test_immutable_result_mutation_is_rejected(tmp_path: Path) -> None:
    execution = run_distributed_reader(
        _request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        config=DistributedReaderConfig(),
    )
    execution.result_path.chmod(0o600)
    payload = json.loads(execution.result_path.read_text(encoding="utf-8"))
    payload["runtime"]["driver_row_collection"] = True
    execution.result_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_distributed_reader(
            execution.result_path,
            request=_request(),
            source_root=FIXTURE_ROOT,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path,
            config=DistributedReaderConfig(),
        )


def test_two_workloads_are_isolated(tmp_path: Path) -> None:
    first = run_distributed_reader(
        _request(workload_id="workload-a", run_id="run-a"),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        config=DistributedReaderConfig(),
    )
    second = run_distributed_reader(
        _request(workload_id="workload-b", run_id="run-b"),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        config=DistributedReaderConfig(),
    )
    assert first.result_path != second.result_path
    assert first.result["result_id"] != second.result["result_id"]
