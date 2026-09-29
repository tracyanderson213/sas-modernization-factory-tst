"""Bounded real SAS7BDAT-to-local-Delta proof for VS-01.

This is deliberately a fixture-scale qualification path.  It reuses the qualified BASE-08
reader, constructs a real Spark ``StructType`` and DataFrame, writes a local Delta table through
delta-rs, reconciles with DataComPy at zero tolerance, and publishes immutable SMF evidence.
It is not the BASE-02 production semantic mapping or the BASE-04 canonical descriptor.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import importlib.metadata
import json
import os
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from smf.immutable_files import (
    ensure_directory,
    open_lock_file,
    publish_json,
    published_file_exists,
    read_published_json,
)
from smf.sas_reader import (
    PyreadstatProvider,
    ReaderConfig,
    ReaderExecution,
    ReaderRequest,
    publish_reader_result,
    read_sas7bdat,
    verify_reader_result,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_VERSIONS = {
    "pyspark": "3.5.8",
    "py4j": "0.10.9.7",
    "deltalake": "1.6.4",
    "pyarrow": "25.0.1",
    "datacompy": "1.0.4",
    "pandas": "2.2.3",
    "polars": "1.43.2",
    "polars-runtime-32": "1.43.2",
}
_TEMPORAL_FORMAT_PREFIXES = ("DATE", "DATETIME", "DDMMYY", "MMDDYY", "TIME", "YYMMDD")
_FIXTURE_SHA256 = "641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c"
_FIXTURE_BYTES = 196608
_FIXTURE_LICENSE_SHA256 = "07487bc4080297d9c65ffa3f66e3c405f9fd08e4af990cd54212d373eb28debc"


@dataclass(frozen=True)
class VerticalSliceConfig:
    """Exact bounded mapping and runtime policy for the VS-01 public fixture."""

    reader: ReaderConfig
    mapping_version: str = "vs01-fixture-provisional-v1"
    spark_master: str = "local[1]"
    spark_timezone: str = "UTC"
    absolute_tolerance: float = 0.0
    relative_tolerance: float = 0.0
    fixture_upstream: str = "Roche/pyreadstat"
    fixture_revision: str = "12cc1495d468ae8a170c57cce7557c147b972eac"
    fixture_path: str = "test_data/basic/sample_bincompressed.sas7bdat"
    fixture_sha256: str = _FIXTURE_SHA256
    fixture_byte_count: int = _FIXTURE_BYTES
    fixture_license: str = "Apache-2.0; embedded ReadStat MIT notice preserved"
    fixture_license_sha256: str = _FIXTURE_LICENSE_SHA256

    def validate(self) -> None:
        self.reader.validate()
        if self.mapping_version != "vs01-fixture-provisional-v1":
            raise ValueError("VS-01 mapping version is unsupported")
        if self.spark_master != "local[1]" or self.spark_timezone != "UTC":
            raise ValueError("VS-01 Spark execution must remain bounded and deterministic")
        if self.absolute_tolerance != 0 or self.relative_tolerance != 0:
            raise ValueError("VS-01 reconciliation requires zero tolerance")
        if (
            self.fixture_upstream != "Roche/pyreadstat"
            or self.fixture_revision != "12cc1495d468ae8a170c57cce7557c147b972eac"
            or self.fixture_path != "test_data/basic/sample_bincompressed.sas7bdat"
            or self.fixture_sha256 != _FIXTURE_SHA256
            or self.fixture_byte_count != _FIXTURE_BYTES
            or self.fixture_license != "Apache-2.0; embedded ReadStat MIT notice preserved"
            or self.fixture_license_sha256 != _FIXTURE_LICENSE_SHA256
        ):
            raise ValueError("VS-01 fixture provenance or license binding is unsupported")

    def binding(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["reader"] = self.reader.binding()
        return value


@dataclass(frozen=True)
class VerticalSliceExecution:
    result: dict[str, Any]
    result_path: Path
    delta_path: Path


def _runtime_identity() -> dict[str, Any]:
    components = []
    for distribution, required in _VERSIONS.items():
        observed = importlib.metadata.version(distribution)
        if observed != required:
            raise ValueError(f"VS-01 requires {distribution}=={required}; observed {observed}")
        dist = importlib.metadata.distribution(distribution)
        record = dist.read_text("RECORD")
        if not record:
            raise ValueError(f"VS-01 {distribution} distribution RECORD is unavailable")
        components.append(
            {
                "distribution": distribution,
                "version": observed,
                "record_sha256": hashlib.sha256(record.encode()).hexdigest(),
            }
        )
    return {"components": components, "network_at_runtime": False}


def _paths(root: Path, request: ReaderRequest) -> tuple[Path, Path, Path, Path]:
    request.validate()
    attempt = (
        Path(os.path.abspath(os.fspath(root)))
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "vs01"
    )
    return attempt, attempt / "delta", attempt / "result.json", attempt / "execution.lock"


def _provisional_mapping(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    mapping: list[dict[str, Any]] = []
    for column in descriptor["columns"]:
        observed = column["observed"]["normalized_type"]
        if observed == "str":
            spark_type = "string"
        elif observed == "float":
            spark_type = "double"
        else:
            raise ValueError(f"VS-01 fixture mapping does not support observed type {observed}")
        declared_format = column["declared"]["format"]
        upper_format = declared_format.upper() if isinstance(declared_format, str) else ""
        temporal = upper_format.startswith(_TEMPORAL_FORMAT_PREFIXES)
        mapping.append(
            {
                "position": column["position"],
                "name": column["name"],
                "source_observed_type": observed,
                "spark_type": spark_type,
                "nullable": column["observed"]["nullable"],
                "sas_format": declared_format,
                "sas_informat": column["declared"]["informat"],
                "semantic_disposition": (
                    "raw_sas_numeric_temporal_mapping_deferred" if temporal else "provisional"
                ),
            }
        )
    return mapping


def _spark_frame(
    rows: list[tuple[Any, ...]], mapping: list[dict[str, Any]], config: VerticalSliceConfig
) -> tuple[Any, dict[str, Any]]:
    spark_sql = importlib.import_module("pyspark.sql")
    spark_types = importlib.import_module("pyspark.sql.types")
    fields = []
    for item in mapping:
        data_type = (
            spark_types.StringType() if item["spark_type"] == "string" else spark_types.DoubleType()
        )
        fields.append(
            spark_types.StructField(
                item["name"],
                data_type,
                bool(item["nullable"]),
                {
                    "mapping_authority": config.mapping_version,
                    "sas_format": item["sas_format"] or "",
                    "sas_informat": item["sas_informat"] or "",
                    "semantic_disposition": item["semantic_disposition"],
                },
            )
        )
    schema = spark_types.StructType(fields)
    spark = (
        spark_sql.SparkSession.builder.master(config.spark_master)
        .appName("smf-vs01-public-fixture")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.session.timeZone", config.spark_timezone)
        .getOrCreate()
    )
    try:
        frame = spark.createDataFrame(rows, schema=schema)
        observed_count = frame.count()
        pandas_frame = frame.toPandas()
        projection = {
            "version": spark.version,
            "master": config.spark_master,
            "timezone": spark.conf.get("spark.sql.session.timeZone"),
            "schema": schema.jsonValue(),
            "row_count": observed_count,
        }
        return pandas_frame, projection
    finally:
        spark.stop()


def _arrow_schema(mapping: list[dict[str, Any]]) -> Any:
    arrow = importlib.import_module("pyarrow")
    return arrow.schema(
        [
            arrow.field(
                item["name"],
                arrow.string() if item["spark_type"] == "string" else arrow.float64(),
                nullable=bool(item["nullable"]),
            )
            for item in mapping
        ]
    )


def _write_delta(path: Path, pandas_frame: Any, mapping: list[dict[str, Any]]) -> None:
    arrow = importlib.import_module("pyarrow")
    delta = importlib.import_module("deltalake")
    table = arrow.Table.from_pandas(
        pandas_frame, schema=_arrow_schema(mapping), preserve_index=False, safe=True
    )
    delta.write_deltalake(path, table, mode="error")


def _read_delta(path: Path) -> tuple[Any, dict[str, Any]]:
    delta = importlib.import_module("deltalake")
    table_handle = delta.DeltaTable(path)
    table = table_handle.to_pyarrow_table()
    return table, {"table_version": table_handle.version(), "schema": str(table.schema)}


def _canonical_row(row: list[Any] | tuple[Any, ...]) -> str:
    cells = []
    for value in row:
        if value is None:
            cells.append(["null"])
        elif isinstance(value, str):
            cells.append(["string", value])
        elif isinstance(value, int | float):
            cells.append(["number", format(float(value), ".17g")])
        else:
            raise ValueError(f"VS-01 cannot reconcile value type {type(value).__name__}")
    return json.dumps(cells, ensure_ascii=True, separators=(",", ":"))


def _reconcile(
    source_rows: list[tuple[Any, ...]],
    target_table: Any,
    mapping: list[dict[str, Any]],
    config: VerticalSliceConfig,
) -> dict[str, Any]:
    pandas = importlib.import_module("pandas")
    datacompy = importlib.import_module("datacompy")
    names = [item["name"] for item in mapping]
    source_sorted = sorted(source_rows, key=_canonical_row)
    target_rows = [tuple(row.get(name) for name in names) for row in target_table.to_pylist()]
    target_sorted = sorted(target_rows, key=_canonical_row)
    source_frame = pandas.DataFrame(source_sorted, columns=names)
    target_frame = pandas.DataFrame(target_sorted, columns=names)
    comparison = datacompy.PandasCompare(
        source_frame,
        target_frame,
        on_index=True,
        abs_tol=config.absolute_tolerance,
        rel_tol=config.relative_tolerance,
        cast_column_names_lower=False,
        df1_name="qualified_reader",
        df2_name="local_delta",
    )
    source_nulls = {name: int(source_frame[name].isna().sum()) for name in names}
    target_nulls = {name: int(target_frame[name].isna().sum()) for name in names}
    source_digest = digest_value([_canonical_row(row) for row in source_sorted])
    target_digest = digest_value([_canonical_row(row) for row in target_sorted])
    temporal_columns = [
        item["name"]
        for item in mapping
        if item["semantic_disposition"] == "raw_sas_numeric_temporal_mapping_deferred"
    ]
    expected_schema = [
        {
            "name": item["name"],
            "type": "string" if item["spark_type"] == "string" else "double",
            "nullable": bool(item["nullable"]),
        }
        for item in mapping
    ]
    target_schema = [
        {"name": field.name, "type": str(field.type), "nullable": field.nullable}
        for field in target_table.schema
    ]
    temporal_positions = [names.index(name) for name in temporal_columns]
    source_temporal_digest = digest_value(
        [
            _canonical_row([row[position] for position in temporal_positions])
            for row in source_sorted
        ]
    )
    target_temporal_digest = digest_value(
        [
            _canonical_row([row[position] for position in temporal_positions])
            for row in target_sorted
        ]
    )
    result = {
        "engine": "datacompy.PandasCompare",
        "engine_version": importlib.metadata.version("datacompy"),
        "alignment": "canonical_full_row_multiset_not_a_business_key",
        "absolute_tolerance": config.absolute_tolerance,
        "relative_tolerance": config.relative_tolerance,
        "source_row_count": len(source_rows),
        "target_row_count": int(target_table.num_rows),
        "row_count_match": bool(len(source_rows) == target_table.num_rows),
        "columns_match": bool(comparison.all_columns_match()),
        "expected_schema": expected_schema,
        "target_schema": target_schema,
        "schema_match": expected_schema == target_schema,
        "rows_overlap": bool(comparison.all_rows_overlap()),
        "values_match": bool(comparison.intersect_rows_match()),
        "matching_rows": int(comparison.count_matching_rows()),
        "source_null_counts": source_nulls,
        "target_null_counts": target_nulls,
        "null_counts_match": source_nulls == target_nulls,
        "source_row_multiset_digest": source_digest,
        "target_row_multiset_digest": target_digest,
        "row_multiset_match": source_digest == target_digest,
        "temporal_columns_raw_numeric": temporal_columns,
        "source_temporal_digest": source_temporal_digest,
        "target_temporal_digest": target_temporal_digest,
        "temporal_values_match": source_temporal_digest == target_temporal_digest,
    }
    result["passed"] = all(
        (
            result["row_count_match"],
            result["columns_match"],
            result["schema_match"],
            result["rows_overlap"],
            result["values_match"],
            result["null_counts_match"],
            result["row_multiset_match"],
            result["temporal_values_match"],
        )
    )
    return result


def _manifest(delta_path: Path) -> list[dict[str, Any]]:
    lexical_root = Path(os.path.abspath(os.fspath(delta_path)))
    if (
        delta_path.is_symlink()
        or not lexical_root.is_dir()
        or lexical_root.resolve() != lexical_root
    ):
        raise ValueError("VS-01 Delta output is missing, symlinked, or not a directory")
    files = []
    for path in sorted(lexical_root.rglob("*")):
        if path.is_symlink() or any(
            parent.is_symlink() for parent in path.parents if parent != lexical_root.parent
        ):
            raise ValueError("VS-01 Delta output contains a symlink")
        if path.is_dir():
            continue
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("VS-01 Delta output contains a non-regular file")
            chunks = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError("VS-01 Delta output changed while being hashed")
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
        files.append(
            {
                "path": path.relative_to(lexical_root).as_posix(),
                "byte_count": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    if not files or not any(str(item["path"]).startswith("_delta_log/") for item in files):
        raise ValueError("VS-01 output is not a materialized Delta table")
    return files


def _reader_reference(root: Path, request: ReaderRequest) -> str:
    return (
        Path("runs")
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "sas-reader"
        / "result.json"
    ).as_posix()


def _build_result(
    request: ReaderRequest,
    config: VerticalSliceConfig,
    reader: ReaderExecution,
    mapping: list[dict[str, Any]],
    spark: dict[str, Any],
    delta: dict[str, Any],
    reconciliation: dict[str, Any],
    manifest: list[dict[str, Any]],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    identity = {
        "client_id": request.client_id,
        "workload_id": request.workload_id,
        "source_id": request.source_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "source_sha256": request.source_sha256,
        "source_byte_count": request.source_byte_count,
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": "",
        "identity": identity,
        "config": config.binding(),
        "runtime": runtime,
        "source_reader": {
            "evidence_reference": _reader_reference(Path("."), request),
            "content_digest": reader.result["content_digest"],
            "provider_runtime_digest": reader.result["runtime_digest"],
            "state": reader.result["state"],
        },
        "provisional_mapping": mapping,
        "spark": spark,
        "delta": delta,
        "reconciliation": reconciliation,
        "output_manifest": manifest,
        "output_manifest_digest": digest_value(manifest),
        "claims": {
            "canonical_cross_provider_descriptor": False,
            "governed_production_semantic_mapping": False,
            "databricks_or_unity_catalog_validated": False,
            "humana_validated": False,
            "production_ready": False,
            "migration_complete": False,
        },
        "content_digest": "",
    }
    payload["result_id"] = stable_id(
        "VS01", {"identity": identity, "config": payload["config"], "output": manifest}
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    _verify_internal(payload)
    return payload


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "identity",
        "config",
        "runtime",
        "source_reader",
        "provisional_mapping",
        "spark",
        "delta",
        "reconciliation",
        "output_manifest",
        "output_manifest_digest",
        "claims",
        "content_digest",
    }
    if set(result) != required or result["schema_version"] != "1.0":
        raise ValueError("VS-01 result contract is malformed")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("VS-01 result content digest mismatch")
    if result["output_manifest_digest"] != digest_value(result["output_manifest"]):
        raise ValueError("VS-01 output manifest digest mismatch")
    if result["source_reader"]["state"] != "complete":
        raise ValueError("VS-01 cannot claim a non-complete source read")
    if not result["reconciliation"]["passed"]:
        raise ValueError("VS-01 reconciliation did not pass")
    if any(result["claims"].values()):
        raise ValueError("VS-01 result asserts a prohibited claim")


def _execute_current(
    request: ReaderRequest,
    *,
    authorized_root: Path,
    output_root: Path,
    config: VerticalSliceConfig,
    delta_path: Path,
) -> dict[str, Any]:
    runtime = _runtime_identity()
    if (
        request.source_sha256 != config.fixture_sha256
        or request.source_byte_count != config.fixture_byte_count
    ):
        raise ValueError("VS-01 request does not identify the qualified public fixture")
    provider = PyreadstatProvider()
    reader = read_sas7bdat(
        request, authorized_root=authorized_root, config=config.reader, provider=provider
    )
    if reader.result["state"] != "complete":
        raise ValueError(f"VS-01 source reader did not complete: {reader.result['blockers']}")
    publish_reader_result(
        output_root,
        request,
        reader,
        authorized_root=authorized_root,
        config=config.reader,
        provider=provider,
    )
    descriptor = cast(dict[str, Any], reader.result["descriptor"])
    mapping = _provisional_mapping(descriptor)
    rows = [row for chunk in reader.chunks for row in chunk]
    pandas_frame, spark_projection = _spark_frame(rows, mapping, config)
    if spark_projection["row_count"] != len(rows):
        raise ValueError("VS-01 Spark row count differs from the qualified reader")
    if not delta_path.exists():
        ensure_directory(delta_path.parent, root=output_root)
        stage = Path(tempfile.mkdtemp(prefix=".vs01-delta-", dir=delta_path.parent))
        try:
            _write_delta(stage, pandas_frame, mapping)
            _manifest(stage)
            os.rename(stage, delta_path)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    manifest_before = _manifest(delta_path)
    target, delta_projection = _read_delta(delta_path)
    reconciliation = _reconcile(rows, target, mapping, config)
    if not reconciliation["passed"]:
        raise ValueError("VS-01 exact source-to-Delta reconciliation failed")
    manifest = _manifest(delta_path)
    if manifest != manifest_before:
        raise ValueError("VS-01 Delta output changed during reconciliation")
    delta_projection.update(
        {
            "path_reference": "vs01/delta",
            "format": "delta",
            "writer": "delta-rs",
            "output_manifest_digest": digest_value(manifest),
        }
    )
    return _build_result(
        request,
        config,
        reader,
        mapping,
        spark_projection,
        delta_projection,
        reconciliation,
        manifest,
        runtime,
    )


def run_vertical_slice(
    request: ReaderRequest,
    *,
    authorized_root: Path,
    output_root: Path,
    config: VerticalSliceConfig,
) -> VerticalSliceExecution:
    """Execute or reconstruct one exact fixture-scale vertical-slice attempt."""

    config.validate()
    attempt, delta_path, result_path, lock_path = _paths(output_root, request)
    ensure_directory(attempt, root=output_root)
    with open_lock_file(lock_path, root=output_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=output_root, label="VS-01 result"):
            return verify_vertical_slice(
                result_path,
                request=request,
                authorized_root=authorized_root,
                output_root=output_root,
                config=config,
            )
        result = _execute_current(
            request,
            authorized_root=authorized_root,
            output_root=output_root,
            config=config,
            delta_path=delta_path,
        )
        publish_json(result_path, result, "VS-01 result", root=output_root)
        return VerticalSliceExecution(result, result_path, delta_path)


def verify_vertical_slice(
    result_path: Path,
    *,
    request: ReaderRequest,
    authorized_root: Path,
    output_root: Path,
    config: VerticalSliceConfig,
) -> VerticalSliceExecution:
    """Re-read current source and Delta bytes and reconstruct the immutable result exactly."""

    _, delta_path, expected_result_path, _ = _paths(output_root, request)
    if result_path != expected_result_path:
        raise ValueError("VS-01 result path is not bound to the request")
    payload = read_published_json(result_path, root=output_root, label="VS-01 result")
    if not isinstance(payload, dict):
        raise ValueError("VS-01 immutable result is not an object")
    _verify_internal(payload)
    provider = PyreadstatProvider()
    reader_path = output_root / payload["source_reader"]["evidence_reference"]
    reader = verify_reader_result(
        reader_path,
        evidence_root=output_root,
        request=request,
        authorized_root=authorized_root,
        config=config.reader,
        provider=provider,
    )
    if reader.result["content_digest"] != payload["source_reader"]["content_digest"]:
        raise ValueError("VS-01 source-reader evidence binding changed")
    reconstructed = _execute_current(
        request,
        authorized_root=authorized_root,
        output_root=output_root,
        config=config,
        delta_path=delta_path,
    )
    if reconstructed != payload:
        raise ValueError("VS-01 current source/Delta state does not reconstruct immutable evidence")
    return VerticalSliceExecution(payload, result_path, delta_path)


__all__ = [
    "VerticalSliceConfig",
    "VerticalSliceExecution",
    "run_vertical_slice",
    "verify_vertical_slice",
]
