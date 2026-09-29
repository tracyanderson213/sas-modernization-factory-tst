from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
from importlib.resources import files
from pathlib import Path
from typing import Any

import jsonschema
import pytest

pytest.importorskip("pyspark")
for dependency in ("pyreadstat", "deltalake", "pyarrow"):
    try:
        importlib.import_module(dependency)
    except ModuleNotFoundError:
        if os.environ.get("SMF_REQUIRE_DBPKG04") == "1":
            raise RuntimeError(f"DBPKG-04 requires pinned {dependency}") from None
        pytest.skip(
            f"DBPKG-04 optional dependency {dependency} is unavailable", allow_module_level=True
        )

from smf.canonical_descriptor import SnapshotPolicy, run_canonical_descriptor  # noqa: E402
from smf.distributed_sas_reader import (  # noqa: E402
    DistributedReaderConfig,
    DistributedReaderRequest,
)
from smf.restartable_ingestion import (  # noqa: E402
    RestartableIngestionRequest,
    run_restartable_ingestion,
    verify_restartable_ingestion,
)
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest  # noqa: E402
from smf.semantic_mapping import (  # noqa: E402
    SemanticMappingRequest,
    load_mapping_policy,
    run_semantic_mapping,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"
POLICY_PATH = ROOT / "examples" / "policies" / "base02-public-fixture-mapping-v1.json"
RESULT_SCHEMA = ROOT / "schemas" / "restartable-ingestion-result.schema.json"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_DBPKG04") == "1":
        raise RuntimeError("DBPKG-04 requires the exact qualified SCALE-01 bundle")
    pytest.skip("DBPKG-04 qualified SCALE-01 bundle is unavailable", allow_module_level=True)


def _local_request(root: Path, **overrides: Any) -> ReaderRequest:
    source = root / SOURCE.name
    values: dict[str, Any] = {
        "client_id": "public-upstream",
        "workload_id": "dbpkg04-public-fixture",
        "source_id": "ag121a-supp-sample",
        "run_id": "dbpkg04-run",
        "attempt_id": "attempt-1",
        "relative_path": source.name,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_byte_count": source.stat().st_size,
    }
    values.update(overrides)
    return ReaderRequest(**values)


def _distributed_request(root: Path, **overrides: Any) -> DistributedReaderRequest:
    local = _local_request(root)
    oracle = root / ORACLE.name
    values: dict[str, Any] = {
        "client_id": local.client_id,
        "workload_id": local.workload_id,
        "source_id": local.source_id,
        "run_id": local.run_id,
        "attempt_id": local.attempt_id,
        "source_relative_path": local.relative_path,
        "source_sha256": local.source_sha256,
        "source_byte_count": local.source_byte_count,
        "oracle_relative_path": oracle.name,
        "oracle_sha256": hashlib.sha256(oracle.read_bytes()).hexdigest(),
        "oracle_byte_count": oracle.stat().st_size,
    }
    values.update(overrides)
    return DistributedReaderRequest(**values)


def _semantic_request(local: ReaderRequest) -> SemanticMappingRequest:
    return SemanticMappingRequest(
        client_id=local.client_id,
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        source_dataset_id="ag121a-supp-sample",
        source_dataset_version="1.0.0",
        evaluation_time="2026-09-20T20:02:00Z",
    )


def _request(local: ReaderRequest, **overrides: Any) -> RestartableIngestionRequest:
    values: dict[str, Any] = {
        "client_id": local.client_id,
        "workload_id": local.workload_id,
        "source_id": local.source_id,
        "run_id": local.run_id,
        "attempt_id": local.attempt_id,
        "source_relative_path": local.relative_path,
        "source_sha256": local.source_sha256,
        "source_byte_count": local.source_byte_count,
        "asset_kind": "sas7bdat",
        "target_id": "local-delta-public-fixture",
    }
    values.update(overrides)
    return RestartableIngestionRequest(**values)


def _local_config() -> ReaderConfig:
    return ReaderConfig(
        PyreadstatProvider().runtime_identity()["distribution_record_sha256"],
        chunk_rows=5_000,
        max_source_bytes=10_000_000,
        max_rows=50_000,
    )


def _snapshot_policy() -> SnapshotPolicy:
    return SnapshotPolicy(
        version="base04-public-fixture-v1",
        acquisition_time="2026-09-20T20:00:00Z",
        evaluation_time="2026-09-20T20:01:00Z",
        valid_until="2027-09-20T20:00:00Z",
    )


@pytest.fixture(scope="module")
def source_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("dbpkg04-source")
    shutil.copy2(SOURCE, root / SOURCE.name)
    shutil.copy2(ORACLE, root / ORACLE.name)
    return root


@pytest.fixture(scope="module")
def admitted(
    tmp_path_factory: pytest.TempPathFactory, source_root: Path
) -> tuple[Path, ReaderRequest, DistributedReaderRequest, SemanticMappingRequest, Path, Path]:
    evidence = tmp_path_factory.mktemp("dbpkg04-evidence")
    local = _local_request(source_root)
    distributed = _distributed_request(source_root)
    semantic_request = _semantic_request(local)
    base04 = run_canonical_descriptor(
        local,
        distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        policy=_snapshot_policy(),
    )
    base02 = run_semantic_mapping(
        semantic_request,
        load_mapping_policy(POLICY_PATH),
        base04_result_path=base04.result_path,
        local_request=local,
        distributed_request=distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
    )
    return evidence, local, distributed, semantic_request, base04.result_path, base02.result_path


def _run(
    admitted: tuple[
        Path, ReaderRequest, DistributedReaderRequest, SemanticMappingRequest, Path, Path
    ],
    source_root: Path,
    **kwargs: Any,
):  # type: ignore[no-untyped-def]
    evidence, local, distributed, semantic_request, base04_path, base02_path = admitted
    return run_restartable_ingestion(
        kwargs.pop("request", _request(local)),
        local_request=local,
        distributed_request=distributed,
        semantic_request=semantic_request,
        mapping_policy=load_mapping_policy(POLICY_PATH),
        base04_result_path=base04_path,
        base02_result_path=base02_path,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
        **kwargs,
    )


def test_actual_partitioned_sas7bdat_to_restartable_delta_and_replay(
    admitted: tuple[
        Path, ReaderRequest, DistributedReaderRequest, SemanticMappingRequest, Path, Path
    ],
    source_root: Path,
) -> None:
    execution = _run(admitted, source_root)
    result = execution.result
    assert result["state"] == "complete_local_delta"
    assert result["reconciliation"]["passed"] is True
    assert result["reconciliation"]["source_summary"]["row_count"] == 18_638
    assert result["reconciliation"]["whole_table_driver_collection"] is False
    assert result["delta"]["table_version"] == 0
    assert result["delta"]["writer"] == "spark-parquet-plus-delta-rs-convert"
    assert [item["phase"] for item in result["checkpoints"]] == ["admission", "delta"]
    assert not any(result["claims"].values())
    public_schema = RESULT_SCHEMA.read_bytes()
    packaged_schema = files("smf.schemas").joinpath(RESULT_SCHEMA.name).read_bytes()
    assert public_schema == packaged_schema
    jsonschema.validate(result, json.loads(public_schema))
    evidence, local, distributed, semantic_request, base04_path, base02_path = admitted
    replay = verify_restartable_ingestion(
        execution.result_path,
        request=_request(local),
        local_request=local,
        distributed_request=distributed,
        semantic_request=semantic_request,
        mapping_policy=load_mapping_policy(POLICY_PATH),
        base04_result_path=base04_path,
        base02_result_path=base02_path,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
    )
    assert replay.result == result


def test_retry_after_delta_checkpoint_is_idempotent(
    admitted: tuple[
        Path, ReaderRequest, DistributedReaderRequest, SemanticMappingRequest, Path, Path
    ],
    source_root: Path,
) -> None:
    # The module-scoped actual run already published both checkpoints and the result. A repeated run
    # takes the replay path and cannot append a second Delta version or overwrite any checkpoint.
    first = _run(admitted, source_root)
    second = _run(admitted, source_root)
    assert second.result == first.result
    assert second.result["delta"]["table_version"] == 0


def test_interrupted_delta_resumes_and_changed_source_invalidates_replay(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    shutil.copy2(SOURCE, source_root / SOURCE.name)
    shutil.copy2(ORACLE, source_root / ORACLE.name)
    original = (source_root / SOURCE.name).read_bytes()
    evidence = tmp_path / "evidence"
    local = _local_request(
        source_root,
        workload_id="dbpkg04-resume-fixture",
        run_id="dbpkg04-resume-run",
    )
    distributed = _distributed_request(
        source_root,
        workload_id=local.workload_id,
        run_id=local.run_id,
    )
    semantic_request = _semantic_request(local)
    base04 = run_canonical_descriptor(
        local,
        distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        policy=_snapshot_policy(),
    )
    base02 = run_semantic_mapping(
        semantic_request,
        load_mapping_policy(POLICY_PATH),
        base04_result_path=base04.result_path,
        local_request=local,
        distributed_request=distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
    )
    request = _request(local)

    def interrupt_after_delta(phase: str) -> None:
        if phase == "delta":
            raise InterruptedError("synthetic interruption after durable Delta checkpoint")

    call = {
        "request": request,
        "local_request": local,
        "distributed_request": distributed,
        "semantic_request": semantic_request,
        "mapping_policy": load_mapping_policy(POLICY_PATH),
        "base04_result_path": base04.result_path,
        "base02_result_path": base02.result_path,
        "source_root": source_root,
        "artifact_root": ARTIFACT_ROOT,
        "evidence_root": evidence,
        "local_config": _local_config(),
        "distributed_config": DistributedReaderConfig(),
        "snapshot_policy": _snapshot_policy(),
    }
    with pytest.raises(InterruptedError, match="durable Delta checkpoint"):
        run_restartable_ingestion(**call, phase_hook=interrupt_after_delta)  # type: ignore[arg-type]

    recovered = run_restartable_ingestion(**call)  # type: ignore[arg-type]
    assert recovered.result["state"] == "complete_local_delta"
    assert recovered.result["delta"]["table_version"] == 0

    (source_root / SOURCE.name).write_bytes(original + b"mutation")
    with pytest.raises(ValueError):
        run_restartable_ingestion(**call)  # type: ignore[arg-type]


def test_mutation_and_cross_workload_identity_fail_closed(
    admitted: tuple[
        Path, ReaderRequest, DistributedReaderRequest, SemanticMappingRequest, Path, Path
    ],
    source_root: Path,
) -> None:
    evidence, local, distributed, semantic_request, base04_path, base02_path = admitted
    result_path = _run(admitted, source_root).result_path
    checkpoint = result_path.parent / "checkpoints" / "01-admission.json"
    checkpoint_bytes = checkpoint.read_bytes()
    checkpoint.chmod(0o600)
    checkpoint_payload = json.loads(checkpoint_bytes)
    checkpoint_payload["evidence"]["source_sha256"] = "0" * 64
    checkpoint.write_text(json.dumps(checkpoint_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="checkpoint"):
        verify_restartable_ingestion(
            result_path,
            request=_request(local),
            local_request=local,
            distributed_request=distributed,
            semantic_request=semantic_request,
            mapping_policy=load_mapping_policy(POLICY_PATH),
            base04_result_path=base04_path,
            base02_result_path=base02_path,
            source_root=source_root,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=evidence,
            local_config=_local_config(),
            distributed_config=DistributedReaderConfig(),
            snapshot_policy=_snapshot_policy(),
        )
    checkpoint.write_bytes(checkpoint_bytes)
    result_path.chmod(0o600)
    mutated = json.loads(result_path.read_text(encoding="utf-8"))
    mutated["claims"]["humana_asset_qualified"] = True
    result_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_restartable_ingestion(
            result_path,
            request=_request(local),
            local_request=local,
            distributed_request=distributed,
            semantic_request=semantic_request,
            mapping_policy=load_mapping_policy(POLICY_PATH),
            base04_result_path=base04_path,
            base02_result_path=base02_path,
            source_root=source_root,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=evidence,
            local_config=_local_config(),
            distributed_config=DistributedReaderConfig(),
            snapshot_policy=_snapshot_policy(),
        )
    with pytest.raises(ValueError, match="identity mismatch"):
        run_restartable_ingestion(
            _request(local, workload_id="other-workload", run_id="other-run"),
            local_request=local,
            distributed_request=distributed,
            semantic_request=semantic_request,
            mapping_policy=load_mapping_policy(POLICY_PATH),
            base04_result_path=base04_path,
            base02_result_path=base02_path,
            source_root=source_root,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=evidence,
            local_config=_local_config(),
            distributed_config=DistributedReaderConfig(),
            snapshot_policy=_snapshot_policy(),
        )


def test_unsupported_assets_publish_actionable_blocked_evidence(tmp_path: Path) -> None:
    request = RestartableIngestionRequest(
        client_id="synthetic",
        workload_id="unsupported-fixture",
        source_id="catalog-fixture",
        run_id="unsupported-run",
        attempt_id="attempt-1",
        source_relative_path="formats.sas7bcat",
        source_sha256="0" * 64,
        source_byte_count=1,
        asset_kind="catalog",
        target_id="no-target",
    )
    execution = run_restartable_ingestion(
        request,
        local_request=object(),  # type: ignore[arg-type]
        distributed_request=object(),  # type: ignore[arg-type]
        semantic_request=object(),  # type: ignore[arg-type]
        mapping_policy=object(),  # type: ignore[arg-type]
        base04_result_path=tmp_path / "absent-base04.json",
        base02_result_path=tmp_path / "absent-base02.json",
        source_root=tmp_path,
        artifact_root=tmp_path,
        evidence_root=tmp_path,
        local_config=object(),  # type: ignore[arg-type]
        distributed_config=object(),  # type: ignore[arg-type]
        snapshot_policy=object(),  # type: ignore[arg-type]
    )
    assert execution.result["state"] == "blocked_unsupported"
    assert execution.result["exceptions"][0]["code"] == "unsupported_asset_requires_disposition"
    assert execution.delta_path is None
    assert not any(execution.result["claims"].values())
    jsonschema.validate(execution.result, json.loads(RESULT_SCHEMA.read_text()))


def test_secret_path_and_unknown_asset_are_rejected_without_echo() -> None:
    canary = "secret-canary-db-pkg-04"
    with pytest.raises(ValueError) as captured:
        RestartableIngestionRequest(
            client_id="synthetic",
            workload_id="fixture",
            source_id="fixture",
            run_id="run",
            attempt_id="attempt-1",
            source_relative_path=f"{canary}.sas7bdat",
            source_sha256="0" * 64,
            source_byte_count=1,
            asset_kind="sas7bdat",
            target_id="target",
        ).validate()
    assert canary not in str(captured.value)
