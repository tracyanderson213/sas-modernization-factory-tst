from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path

import pytest

try:
    for dependency in ("pyspark", "deltalake", "pyarrow", "datacompy", "pandas"):
        importlib.import_module(dependency)
except ModuleNotFoundError as exc:
    if os.environ.get("SMF_REQUIRE_VS01") == "1":
        raise RuntimeError(
            "VS-01 confidence requires the pinned vertical-slice extra: "
            "python -m pip install -e '.[dev,vertical-slice]'"
        ) from exc
    pytest.skip(
        "optional VS-01 runtime is unavailable; run make vs01-confidence",
        allow_module_level=True,
    )

from deltalake import DeltaTable

from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest
from smf.vertical_slice import VerticalSliceConfig, run_vertical_slice, verify_vertical_slice

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "sas_reader"
FIXTURE = FIXTURE_ROOT / "sample_bincompressed.sas7bdat"
FIXTURE_SHA = "641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c"


def _request(**overrides: object) -> ReaderRequest:
    values: dict[str, object] = {
        "client_id": "public-upstream",
        "workload_id": "vs01-public-fixture",
        "source_id": "sample-bincompressed",
        "run_id": "vs01-run",
        "attempt_id": "attempt-1",
        "relative_path": FIXTURE.name,
        "source_sha256": FIXTURE_SHA,
        "source_byte_count": FIXTURE.stat().st_size,
    }
    values.update(overrides)
    return ReaderRequest(**values)  # type: ignore[arg-type]


def _config() -> VerticalSliceConfig:
    provider = PyreadstatProvider()
    return VerticalSliceConfig(
        reader=ReaderConfig(
            provider_distribution_digest=provider.runtime_identity()["distribution_record_sha256"],
            chunk_rows=2,
            max_source_bytes=1024 * 1024,
            max_rows=100,
        )
    )


def test_runtime_design_is_exact_and_makes_no_external_claim() -> None:
    design = json.loads(
        (ROOT / "config" / "dependencies" / "vs01-runtime.json").read_text(encoding="utf-8")
    )
    assert design["fixture"]["sha256"] == FIXTURE_SHA
    assert design["fixture"]["revision"] == ("12cc1495d468ae8a170c57cce7557c147b972eac")
    assert design["fixture"]["byte_count"] == FIXTURE.stat().st_size == 196608
    assert (
        design["fixture"]["license_sha256"]
        == hashlib.sha256((FIXTURE_ROOT / "LICENSE.pyreadstat").read_bytes()).hexdigest()
    )
    assert {item["distribution"]: item["version"] for item in design["components"]} == {
        "pyreadstat": "1.3.6",
        "pyspark": "3.5.8",
        "py4j": "0.10.9.7",
        "deltalake": "1.6.4",
        "pyarrow": "25.0.1",
        "datacompy": "1.0.4",
        "pandas": "2.2.3",
        "polars": "1.43.2",
        "polars-runtime-32": "1.43.2",
    }
    assert not any(design["claims"].values())


def test_real_sas7bdat_spark_delta_reconciliation_and_immutable_evidence(
    tmp_path: Path,
) -> None:
    execution = run_vertical_slice(
        _request(), authorized_root=FIXTURE_ROOT, output_root=tmp_path, config=_config()
    )
    result = execution.result

    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA
    assert result["source_reader"]["state"] == "complete"
    assert result["spark"]["version"] == "3.5.8"
    assert result["spark"]["row_count"] == 5
    assert result["delta"]["format"] == "delta"
    assert result["delta"]["writer"] == "delta-rs"
    assert result["delta"]["table_version"] == 0
    assert DeltaTable(execution.delta_path).to_pyarrow_table().num_rows == 5
    assert result["reconciliation"] == {
        **result["reconciliation"],
        "absolute_tolerance": 0.0,
        "relative_tolerance": 0.0,
        "source_row_count": 5,
        "target_row_count": 5,
        "row_count_match": True,
        "columns_match": True,
        "schema_match": True,
        "rows_overlap": True,
        "values_match": True,
        "matching_rows": 5,
        "source_null_counts": {
            "mychar": 0,
            "mynum": 0,
            "mydate": 1,
            "dtime": 1,
            "mylabl": 0,
            "myord": 0,
            "mytime": 1,
        },
        "target_null_counts": {
            "mychar": 0,
            "mynum": 0,
            "mydate": 1,
            "dtime": 1,
            "mylabl": 0,
            "myord": 0,
            "mytime": 1,
        },
        "null_counts_match": True,
        "row_multiset_match": True,
        "temporal_columns_raw_numeric": ["mydate", "dtime", "mytime"],
        "temporal_values_match": True,
        "passed": True,
    }
    assert not any(result["claims"].values())
    mapping = {item["name"]: item for item in result["provisional_mapping"]}
    assert mapping["mychar"]["spark_type"] == "string"
    for name in ("mydate", "dtime", "mytime"):
        assert mapping[name]["spark_type"] == "double"
        assert mapping[name]["semantic_disposition"] == (
            "raw_sas_numeric_temporal_mapping_deferred"
        )

    replay = verify_vertical_slice(
        execution.result_path,
        request=_request(),
        authorized_root=FIXTURE_ROOT,
        output_root=tmp_path,
        config=_config(),
    )
    assert replay.result == result


def test_retry_recovers_existing_delta_and_missing_result(tmp_path: Path) -> None:
    first = run_vertical_slice(
        _request(), authorized_root=FIXTURE_ROOT, output_root=tmp_path, config=_config()
    )
    first.result_path.unlink()
    recovered = run_vertical_slice(
        _request(), authorized_root=FIXTURE_ROOT, output_root=tmp_path, config=_config()
    )
    assert recovered.result == first.result
    assert recovered.result_path.is_file()


def test_output_or_source_mutation_fails_replay(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / FIXTURE.name
    source.write_bytes(FIXTURE.read_bytes())
    request = _request()
    output = tmp_path / "out"
    execution = run_vertical_slice(
        request, authorized_root=source_root, output_root=output, config=_config()
    )

    (execution.delta_path / "mutation-canary.bin").write_bytes(b"not part of reviewed output")
    with pytest.raises(ValueError, match="reconstruct"):
        verify_vertical_slice(
            execution.result_path,
            request=request,
            authorized_root=source_root,
            output_root=output,
            config=_config(),
        )
    (execution.delta_path / "mutation-canary.bin").unlink()
    source.write_bytes(source.read_bytes() + b"mutation")
    with pytest.raises(ValueError, match="snapshot|reconstruct"):
        verify_vertical_slice(
            execution.result_path,
            request=request,
            authorized_root=source_root,
            output_root=output,
            config=_config(),
        )


def test_snapshot_mismatch_and_nonzero_tolerance_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="qualified public fixture"):
        run_vertical_slice(
            _request(source_sha256="0" * 64),
            authorized_root=FIXTURE_ROOT,
            output_root=tmp_path,
            config=_config(),
        )
    with pytest.raises(ValueError, match="zero tolerance"):
        VerticalSliceConfig(reader=_config().reader, absolute_tolerance=0.01).validate()


def test_two_workloads_are_isolated(tmp_path: Path) -> None:
    first = run_vertical_slice(
        _request(workload_id="workload-a", run_id="run-a"),
        authorized_root=FIXTURE_ROOT,
        output_root=tmp_path,
        config=_config(),
    )
    second = run_vertical_slice(
        _request(workload_id="workload-b", run_id="run-b"),
        authorized_root=FIXTURE_ROOT,
        output_root=tmp_path,
        config=_config(),
    )
    assert first.result_path != second.result_path
    assert first.delta_path != second.delta_path
    assert first.result["identity"]["workload_id"] == "workload-a"
    assert second.result["identity"]["workload_id"] == "workload-b"
