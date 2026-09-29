from __future__ import annotations

import hashlib
import importlib
import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pyspark")
try:
    importlib.import_module("pyreadstat")
except ModuleNotFoundError:
    if os.environ.get("SMF_REQUIRE_BASE04") == "1":
        raise RuntimeError("BASE-04 confidence requires the pinned conversion runtime") from None
    pytest.skip("BASE-04 optional provider runtime is unavailable", allow_module_level=True)

import smf.canonical_descriptor as canonical_descriptor
from smf.canonical_descriptor import (
    SnapshotPolicy,
    run_canonical_descriptor,
    verify_canonical_descriptor,
)
from smf.distributed_sas_reader import DistributedReaderConfig, DistributedReaderRequest
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_BASE04") == "1":
        raise RuntimeError("BASE-04 confidence requires the exact qualified SCALE-01 bundle")
    pytest.skip("BASE-04 qualified SCALE-01 bundle is unavailable", allow_module_level=True)


def _local_request(**overrides: Any) -> ReaderRequest:
    values: dict[str, Any] = {
        "client_id": "public-upstream",
        "workload_id": "base04-public-fixture",
        "source_id": "ag121a-supp-sample",
        "run_id": "base04-run",
        "attempt_id": "attempt-1",
        "relative_path": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "source_byte_count": SOURCE.stat().st_size,
    }
    values.update(overrides)
    return ReaderRequest(**values)


def _distributed_request(**overrides: Any) -> DistributedReaderRequest:
    local = _local_request()
    values: dict[str, Any] = {
        "client_id": local.client_id,
        "workload_id": local.workload_id,
        "source_id": local.source_id,
        "run_id": local.run_id,
        "attempt_id": local.attempt_id,
        "source_relative_path": local.relative_path,
        "source_sha256": local.source_sha256,
        "source_byte_count": local.source_byte_count,
        "oracle_relative_path": ORACLE.name,
        "oracle_sha256": hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        "oracle_byte_count": ORACLE.stat().st_size,
    }
    values.update(overrides)
    return DistributedReaderRequest(**values)


def _local_config() -> ReaderConfig:
    provider = PyreadstatProvider()
    return ReaderConfig(
        provider.runtime_identity()["distribution_record_sha256"],
        chunk_rows=5_000,
        max_source_bytes=10_000_000,
        max_rows=50_000,
    )


def _policy(**overrides: Any) -> SnapshotPolicy:
    values: dict[str, Any] = {
        "version": "base04-public-fixture-v1",
        "acquisition_time": "2026-09-20T20:00:00Z",
        "evaluation_time": "2026-09-20T20:01:00Z",
        "valid_until": "2027-09-20T20:00:00Z",
    }
    values.update(overrides)
    return SnapshotPolicy(**values)


def _run(tmp_path: Path, **kwargs: Any):  # type: ignore[no-untyped-def]
    return run_canonical_descriptor(
        kwargs.pop("local_request", _local_request()),
        kwargs.pop("distributed_request", _distributed_request()),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        policy=kwargs.pop("policy", _policy()),
        **kwargs,
    )


def test_real_cross_provider_descriptor_replay_and_provenance(tmp_path: Path) -> None:
    execution = _run(tmp_path)
    result = execution.result
    descriptor = result["canonical_descriptor"]
    assert descriptor["row_count"] == 18_638
    assert descriptor["column_count"] == 8
    assert [item["name"] for item in descriptor["columns"]] == [
        "SURVYEAR",
        "LEAID",
        "NAME",
        "PHONE",
        "LATCOD",
        "LONCOD",
        "PKTCH",
        "AMPKM",
    ]
    assert [item["canonical_physical_type"] for item in descriptor["columns"]] == [
        "string",
        "string",
        "string",
        "string",
        "double",
        "double",
        "double",
        "double",
    ]
    assert descriptor["columns"][4]["declared_sas_metadata"]["label"] == "Latitude"
    assert descriptor["semantic_mapping_authority"] == "pending-base02"
    assert result["comparison"]["passed"] is True
    assert result["comparison"]["conflicts"] == []
    assert result["comparison"]["row_multiset_match"] is True
    assert (
        result["provider_snapshots"]["base08"]["physical_summary"]
        == (result["provider_snapshots"]["scale01"]["physical_summary"])
    )
    assert result["target_snapshot"]["descriptor_digest"] == result["descriptor_digest"]
    assert not any(result["claims"].values())
    replay = verify_canonical_descriptor(
        execution.result_path,
        _local_request(),
        _distributed_request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=tmp_path,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        policy=_policy(),
    )
    assert replay.result == result


def test_descriptor_design_and_fixture_provenance_are_exact() -> None:
    design = json.loads(
        (ROOT / "config" / "dependencies" / "base04-descriptor.json").read_text(encoding="utf-8")
    )
    assert design["descriptor_version"] == "base04-canonical-physical-v1"
    assert design["providers"]["local"]["record"] == "BASE-08"
    assert design["providers"]["distributed"]["record"] == "SCALE-01"
    assert design["fixture"]["sas7bdat_sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    assert design["fixture"]["csv_oracle_sha256"] == hashlib.sha256(ORACLE.read_bytes()).hexdigest()
    assert design["semantic_mapping_authority"] == "pending-base02"
    assert not any(design["claims"].values())


def test_expired_future_and_mismatched_snapshots_fail_before_provider_work(tmp_path: Path) -> None:
    for policy in (
        _policy(valid_until="2026-09-20T20:00:59Z"),
        _policy(valid_until="2026-09-20T20:01:00Z"),
        _policy(acquisition_time="2026-09-20T20:01:01Z"),
    ):
        with pytest.raises(ValueError, match="future-dated or expired"):
            _run(tmp_path / policy.acquisition_time.replace(":", "-"), policy=policy)
    with pytest.raises(ValueError, match="same source snapshot"):
        _run(
            tmp_path / "identity",
            distributed_request=_distributed_request(source_sha256="0" * 64),
        )
    canary = "secret-canary-base04"
    with pytest.raises(ValueError) as captured:
        _run(tmp_path / "canary", local_request=_local_request(workload_id=canary))
    assert canary not in str(captured.value)


def test_provider_conflict_is_explicit_and_fail_closed() -> None:
    local = {
        "columns": [
            {
                "position": 0,
                "name": "A",
                "declared": {},
                "observed": {"normalized_type": "float", "null_count": 1},
            }
        ]
    }
    distributed = {
        "schema": [{"name": "B", "type": "string", "nullable": True}],
        "distributed_summary": {"null_counts": [0]},
    }
    _, conflicts = canonical_descriptor._canonical_columns(local, distributed)
    assert conflicts == ["column_identity:0", "null_count:0", "physical_type:0"]
    checks, value_conflicts = canonical_descriptor._compare_physical_summaries(
        {
            "row_count": 2,
            "null_counts": [0],
            "digest_xor": "1" * 64,
            "digest_sum": "2" * 64,
        },
        {
            "row_count": 2,
            "null_counts": [0],
            "digest_xor": "3" * 64,
            "digest_sum": "4" * 64,
        },
    )
    assert checks == {
        "row_count_match": True,
        "null_counts_match": True,
        "row_multiset_match": False,
    }
    assert value_conflicts == ["row_multiset"]


def test_cancellation_does_not_publish_canonical_result(tmp_path: Path) -> None:
    checks = iter((False, True))
    with pytest.raises(InterruptedError, match="cancelled"):
        _run(tmp_path, cancel_check=lambda: next(checks))
    assert list(tmp_path.rglob("sas-reader/result.json"))
    assert not list(tmp_path.rglob("base04/result.json"))
    recovered = _run(tmp_path)
    assert recovered.result["comparison"]["passed"] is True


def test_immutable_mutation_and_cross_workload_isolation(tmp_path: Path) -> None:
    first = _run(tmp_path)
    second = _run(
        tmp_path,
        local_request=_local_request(workload_id="base04-other", run_id="base04-other-run"),
        distributed_request=_distributed_request(
            workload_id="base04-other", run_id="base04-other-run"
        ),
    )
    assert first.result_path != second.result_path
    assert first.result["result_id"] != second.result["result_id"]

    first.result_path.chmod(0o600)
    payload = json.loads(first.result_path.read_text(encoding="utf-8"))
    mutated = deepcopy(payload)
    mutated["canonical_descriptor"]["row_count"] += 1
    first.result_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_canonical_descriptor(
            first.result_path,
            _local_request(),
            _distributed_request(),
            source_root=FIXTURE_ROOT,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path,
            local_config=_local_config(),
            distributed_config=DistributedReaderConfig(),
            policy=_policy(),
        )
