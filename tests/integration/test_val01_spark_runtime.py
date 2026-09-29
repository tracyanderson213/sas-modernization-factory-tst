from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.immutable_files import publish_json, read_published_json
from smf.validation.val01 import (
    ColumnPolicy,
    EvidenceBinding,
    RuntimeManifest,
    SnapshotBinding,
    SparkDataComPyComparator,
    ValidationPolicy,
    ValidationRequest,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("SMF_REQUIRE_VAL01_RUNTIME") != "1",
    reason="VAL-01 qualified runtime lane requires SMF_REQUIRE_VAL01_RUNTIME=1",
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/sas_reader/sample_bincompressed.sas7bdat"
FIXTURE_SHA = "641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c"
STAGE_A = r"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import sys
import pyarrow as pa
import pyarrow.parquet as pq
import setuptools  # activates the Python 3.12 distutils compatibility shim
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest
from smf.sas_reader import read_sas7bdat
from smf.vertical_slice import VerticalSliceConfig, run_vertical_slice
fixture, output = Path(sys.argv[1]), Path(sys.argv[2])
def sha(path): return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
def manifest(root):
    return [{'path': p.relative_to(root).as_posix(), 'byte_count': p.stat().st_size,
             'sha256': sha(p)} for p in sorted(root.rglob('*')) if p.is_file()]
def record(name):
    dist = importlib.metadata.distribution(name)
    item = next(p for p in (dist.files or ()) if str(p).endswith('.dist-info/RECORD'))
    path = Path(dist.locate_file(item))
    return {'name': name, 'version': dist.version, 'record_sha256': sha(path)}
provider = PyreadstatProvider()
request = ReaderRequest('public-upstream', 'vs01-public-fixture', 'sample-bincompressed',
    'vs01-run', 'attempt-1', fixture.name,
    '641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c',
    fixture.stat().st_size)
config = ReaderConfig(provider_distribution_digest=provider.runtime_identity()
    ['distribution_record_sha256'], chunk_rows=2, max_source_bytes=1048576, max_rows=100)
execution = run_vertical_slice(request, authorized_root=fixture.parent, output_root=output,
    config=VerticalSliceConfig(reader=config))
reader = read_sas7bdat(request, authorized_root=fixture.parent, config=config, provider=provider)
names = [item['name'] for item in execution.result['provisional_mapping']]
source_path = output / 'source-baseline'
source_path.mkdir()
writer = None
arrow_schema = None
try:
    for index, chunk in enumerate(reader.chunks):
        values = [dict(zip(names, row, strict=True)) for row in chunk]
        table = pa.Table.from_pylist(values, schema=arrow_schema)
        if writer is None:
            arrow_schema = table.schema
            writer = pq.ParquetWriter(source_path / 'part-00000.parquet', table.schema)
        writer.write_table(table)
finally:
    if writer is not None: writer.close()
receipt = {'schema_version': '1.0',
    'fixture_sha256': 'sha256:641254bdd950e65631701b3182868fe25c46a44e99854881f5c3751b2847848c',
    'python_version': platform.python_version(), 'platform': platform.platform(),
    'source_path': str(source_path), 'source_manifest': manifest(source_path),
    'delta_path': str(execution.delta_path), 'delta_manifest': manifest(execution.delta_path),
    'vs01_result_path': str(execution.result_path),
    'vs01_result_sha256': sha(execution.result_path),
    'records': [record(name) for name in (
        'pyreadstat','numpy','pandas','pyarrow','deltalake','pyspark','py4j')]}
print(json.dumps(receipt, sort_keys=True, separators=(',', ':')))
"""


def _digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _verify_manifest(root: Path, manifest: list[dict[str, Any]]) -> None:
    observed = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        observed.append(
            {
                "path": path.relative_to(root).as_posix(),
                "byte_count": path.stat().st_size,
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    assert observed == manifest


def _seal_stage_a_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    projection = dict(receipt)
    sealed = {"receipt_id": _digest(projection), **projection}
    sealed["content_digest"] = _digest(sealed)
    return sealed


def _verify_stage_a_receipt(receipt: dict[str, Any]) -> None:
    content = dict(receipt)
    observed_content = content.pop("content_digest")
    assert observed_content == _digest(content)
    projection = dict(content)
    observed_id = projection.pop("receipt_id")
    assert observed_id == _digest(projection)
    _verify_manifest(Path(receipt["source_path"]), receipt["source_manifest"])
    _verify_manifest(Path(receipt["delta_path"]), receipt["delta_manifest"])


def _stage_a(tmp_path: Path) -> dict[str, Any]:
    executable = os.environ.get("SMF_VAL01_READER_PYTHON", sys.executable)
    environment = dict(os.environ)
    paths = [str(ROOT / "src")]
    support = os.environ.get("SMF_VAL01_READER_SUPPORT_PATH")
    if support:
        paths.append(support)
    environment["PYTHONPATH"] = os.pathsep.join(paths)
    environment["PYSPARK_PYTHON"] = executable
    environment["PYSPARK_DRIVER_PYTHON"] = executable
    try:
        completed = subprocess.run(
            [executable, "-c", STAGE_A, str(FIXTURE), str(tmp_path / "vs01")],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        pytest.fail(f"stage_a_reader_failed: {exc.stderr}")
    receipt = json.loads(completed.stdout.strip().splitlines()[-1])
    assert isinstance(receipt, dict)
    assert Path(receipt["source_path"]).is_dir()
    assert Path(receipt["delta_path"]).is_dir()
    return _seal_stage_a_receipt(receipt)


def _runtime(tmp_path: Path) -> tuple[RuntimeManifest, Path]:
    private = Ed25519PrivateKey.generate()
    key_path = tmp_path / "runtime.pem"
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    records = []
    for name in (
        "pyspark",
        "py4j",
        "datacompy",
        "numpy",
        "pandas",
        "pyarrow",
        "grpcio",
        "grpcio-status",
        "googleapis-common-protos",
    ):
        distribution = importlib.metadata.distribution(name)
        record = next(
            item for item in distribution.files or () if str(item).endswith(".dist-info/RECORD")
        )
        record_path = Path(str(distribution.locate_file(record)))
        records.append(
            (
                name,
                distribution.version,
                "sha256:" + hashlib.sha256(record_path.read_bytes()).hexdigest(),
            )
        )
    return (
        RuntimeManifest(
            "val01-runtime",
            "1.0.0",
            "spark-datacompy",
            "1.0.0",
            "3.5.8",
            "1.0.4",
            "qualified_runtime",
            True,
            "validation-runtime",
            "sha256:" + "a" * 64,
            "validation-key",
            public,
            b"val01-mismatch-hmac-key-material-0001",
            platform.python_version(),
            f"{sys.platform}-{platform.machine()}",
            tuple(records),
        ),
        key_path,
    )


def _request(
    policy: ValidationPolicy, runtime: RuntimeManifest, stage_a: dict[str, Any]
) -> ValidationRequest:
    bindings = tuple(
        EvidenceBinding(
            kind,
            f"prerequisites/{kind.lower()}.json",
            "sha256:" + f"{index + 1:x}" * 64,
            "sha256:" + f"{index + 7:x}" * 64,
            "sha256:" + f"{index + 8:x}" * 64,
        )
        for index, kind in enumerate(
            ("SCHEMA-INT-01", "DP-02", "DP-03", "DP-04", "DP-05", "DBX-04")
        )
    )
    source = SnapshotBinding("sas-fixture", "reader-snapshot", _digest(stage_a["source_manifest"]))
    target = SnapshotBinding("vs01-delta", "delta-snapshot", _digest(stage_a["delta_manifest"]))
    return ValidationRequest(
        "public-upstream",
        "vs01-public-fixture",
        "val01-run",
        "attempt-1",
        "2026-09-22T12:00:00Z",
        source,
        target,
        bindings,
        _digest(policy.to_dict()),
        "sha256:" + "c" * 64,
        runtime.digest,
    )


def _policy(**changes: Any) -> ValidationPolicy:
    values: dict[str, Any] = {
        "policy_id": "fixture-policy",
        "policy_version": "1.0.0",
        "key_columns": ("mychar",),
        "columns": tuple(
            ColumnPolicy(name, "float", nan_equal=True)
            for name in ("mynum", "mydate", "dtime", "mylabl", "myord", "mytime")
        ),
    }
    values.update(changes)
    return ValidationPolicy(**values)


@pytest.fixture(scope="module")
def stage_a_receipt(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    shared = os.environ.get("SMF_VAL01_STAGE_A_ROOT")
    if not shared:
        return _stage_a(tmp_path_factory.mktemp("val01-stage-a"))
    root = Path(shared)
    root.mkdir(parents=True, exist_ok=True)
    receipt_path = root / "stage-a-receipt.json"
    if receipt_path.exists():
        observed = read_published_json(receipt_path, root=root, label="VAL-01 Stage A receipt")
        assert isinstance(observed, dict)
        _verify_stage_a_receipt(observed)
        return observed
    observed = _stage_a(root)
    publish_json(receipt_path, observed, "VAL-01 Stage A receipt", root=root)
    return observed


def _compare_case(
    stage_a: dict[str, Any], tmp_path: Path, case: str, active: ValidationPolicy | None = None
) -> tuple[dict[str, Any], int, int, str]:
    try:
        spark_sql = importlib.import_module("pyspark.sql")
        functions = importlib.import_module("pyspark.sql.functions")
        window_module = importlib.import_module("pyspark.sql.window")
        importlib.import_module("datacompy.spark")
    except (ImportError, ModuleNotFoundError) as exc:
        if os.environ.get("SMF_REQUIRE_VAL01_RUNTIME") == "1":
            pytest.fail(f"comparator_runtime_unavailable: {exc}")
        pytest.skip(f"comparator_runtime_unavailable: {exc}")

    source_path = Path(stage_a["source_path"])
    delta_path = Path(stage_a["delta_path"])
    _verify_manifest(source_path, stage_a["source_manifest"])
    _verify_manifest(delta_path, stage_a["delta_manifest"])
    spark = (
        spark_sql.SparkSession.builder.master("local[2]")
        .appName("smf-val01-qualified-mechanics")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    try:
        source = spark.read.parquet(str(source_path)).repartition(2)
        target = spark.read.parquet(str(delta_path)).repartition(3)
        source_partitions = int(source.rdd.getNumPartitions())
        target_partitions = int(target.rdd.getNumPartitions())
        plan = str(source._jdf.queryExecution().executedPlan().toString())
        runtime, key_path = _runtime(tmp_path)
        policy = active or _policy()
        request = _request(policy, runtime, stage_a)
        source_binding, target_binding = request.source, request.target
        if active is not None:
            source = source.select("mychar", "mynum")
            target = target.select("mychar", "mynum")
        if case == "cell":
            target = target.withColumn("mynum", functions.col("mynum") + 1)
        elif case == "unmatched":
            target = target.where(functions.lit(False))
        elif case == "duplicate":
            target = target.unionByName(target.limit(1))
        elif case == "null":
            target = target.withColumn("mynum", functions.lit(None).cast("double"))
        elif case == "type":
            target = target.withColumn("mynum", functions.col("mynum").cast("string"))
        elif case == "tolerance_boundary":
            target = target.withColumn("mynum", functions.col("mynum") + functions.lit(0.01))
        elif case == "tolerance_outside":
            target = target.withColumn("mynum", functions.col("mynum") + functions.lit(0.010001))
        elif case == "relative_boundary":
            source = source.withColumn("mynum", functions.lit(0.99))
            target = target.withColumn("mynum", functions.lit(1.0))
        elif case == "relative_outside":
            source = source.withColumn("mynum", functions.lit(0.9899))
            target = target.withColumn("mynum", functions.lit(1.0))
        elif case in {"null_equal", "null_different"}:
            source = source.withColumn("mynum", functions.lit(None).cast("double"))
            target = target.withColumn("mynum", functions.lit(None).cast("double"))
        elif case in {"nan_equal", "nan_different"}:
            source = source.withColumn("mynum", functions.lit(float("nan")))
            target = target.withColumn("mynum", functions.lit(float("nan")))
        elif case in {"infinity_equal", "infinity_different"}:
            source = source.withColumn("mynum", functions.lit(float("inf")))
            target = target.withColumn("mynum", functions.lit(float("inf")))
        elif case == "coercion":
            target = target.withColumn("mynum", functions.col("mynum").cast("string"))
        elif case == "invalid_coercion":
            target = target.withColumn("mynum", functions.lit("not-a-number"))
        elif case == "coercion_source_positive":
            source = source.withColumn("mynum", functions.lit("1.0"))
            target = target.withColumn("mynum", functions.lit(1.0))
        elif case == "coercion_truncation":
            source = source.withColumn("mynum", functions.lit(1).cast("bigint"))
            target = target.withColumn("mynum", functions.lit(1.5))
        elif case == "coercion_overflow":
            source = source.withColumn("mynum", functions.lit(1.0))
            target = target.withColumn("mynum", functions.lit("1e309"))
        elif case == "coercion_decimal_loss":
            source = source.withColumn("mynum", functions.lit("1.23").cast("decimal(5,2)"))
            target = target.withColumn("mynum", functions.lit("1.234").cast("decimal(10,3)"))
        elif case == "coercion_target_noncanonical":
            source = source.withColumn("mynum", functions.lit(1.0))
            target = target.withColumn("mynum", functions.lit("01.0"))
        elif case == "coercion_source_noncanonical":
            source = source.withColumn("mynum", functions.lit("01.0"))
            target = target.withColumn("mynum", functions.lit(1.0))
        elif case == "duplicate_tiebreak":
            source = (
                source.where(functions.col("mynum").isNotNull()).orderBy("mychar", "mynum").limit(1)
            )
            target = (
                target.where(functions.col("mynum").isNotNull()).orderBy("mychar", "mynum").limit(1)
            )
            source = source.unionByName(source.withColumn("mynum", functions.col("mynum") + 100))
            target = target.unionByName(target.withColumn("mynum", functions.col("mynum") + 100))
        elif case == "ambiguous_tiebreak":
            source = source.where(functions.col("mynum").isNotNull()).limit(1)
            target = target.where(functions.col("mynum").isNotNull()).limit(1)
            source = source.unionByName(source)
            target = target.unionByName(target)
        elif case == "order_changed":
            source = (
                source.where(functions.col("mynum").isNotNull())
                .groupBy("mychar")
                .agg(functions.first("mynum").alias("mynum"))
                .orderBy("mychar")
                .limit(2)
            )
            target = (
                target.where(functions.col("mynum").isNotNull())
                .groupBy("mychar")
                .agg(functions.first("mynum").alias("mynum"))
                .orderBy("mychar")
                .limit(2)
            )
            swap_window = window_module.Window.orderBy("mychar").rowsBetween(
                window_module.Window.unboundedPreceding,
                window_module.Window.unboundedFollowing,
            )
            target = target.withColumn(
                "mynum",
                functions.when(
                    functions.row_number().over(window_module.Window.orderBy("mychar")) == 1,
                    functions.last("mynum").over(swap_window),
                ).otherwise(functions.first("mynum").over(swap_window)),
            )
            for governed_column in ("mychar", "mynum"):
                assert (
                    source.select(governed_column)
                    .exceptAll(target.select(governed_column))
                    .limit(1)
                    .count()
                    == 0
                )
                assert (
                    target.select(governed_column)
                    .exceptAll(source.select(governed_column))
                    .limit(1)
                    .count()
                    == 0
                )
        elif case == "stale":
            request = replace(
                request,
                source=replace(request.source, snapshot_digest="sha256:" + "d" * 64),
            )
        receipt = SparkDataComPyComparator(
            source, target, source_binding, target_binding, key_path
        ).compare(request, policy, runtime)
        _verify_manifest(source_path, stage_a["source_manifest"])
        _verify_manifest(delta_path, stage_a["delta_manifest"])
        return receipt, source_partitions, target_partitions, plan
    finally:
        spark.stop()


def test_qualified_spark_datacompy_full_row_comparison(
    stage_a_receipt: dict[str, Any], tmp_path: Path
) -> None:
    _verify_stage_a_receipt(stage_a_receipt)
    forged = json.loads(json.dumps(stage_a_receipt))
    forged["source_manifest"][0]["byte_count"] += 1
    with pytest.raises(AssertionError):
        _verify_stage_a_receipt(forged)
    receipt, source_partitions, target_partitions, plan = _compare_case(
        stage_a_receipt, tmp_path, "exact"
    )
    assert source_partitions == 2
    assert target_partitions == 3
    assert "Exchange" in plan
    assert receipt["primary_match"] is True
    assert receipt["datacompy_match"] is True
    assert receipt["cell_mismatch_count"] == 0


@pytest.mark.parametrize("case", ["cell", "unmatched", "duplicate", "null", "type"])
def test_distributed_adversarial_comparisons(
    stage_a_receipt: dict[str, Any], tmp_path: Path, case: str
) -> None:
    receipt, _, _, _ = _compare_case(stage_a_receipt, tmp_path, case)
    if case == "cell":
        assert receipt["cell_mismatch_count"] > 0
        assert all(
            item["source_value_digest"].startswith("hmac-sha256:")
            for item in receipt["mismatch_references"]
        )
    elif case == "unmatched":
        assert receipt["source_only_count"] > 0
        assert receipt["mismatch_references"]
        assert all(
            item["source_value_digest"].startswith("hmac-sha256:")
            and item["target_value_digest"].startswith("hmac-sha256:")
            for item in receipt["mismatch_references"]
        )
    elif case == "duplicate":
        assert receipt["duplicate_key_count"] > 0
    elif case == "null":
        assert receipt["cell_mismatch_count"] > 0
    else:
        assert receipt["state"] == "unsupported"


@pytest.mark.parametrize(
    "policy",
    [
        _policy(columns=(ColumnPolicy("mynum", "float", sas_missing="collapse_to_null"),)),
        _policy(columns=(ColumnPolicy("mynum", "date", timezone="UTC", yearcutoff=1920),)),
    ],
)
def test_unqualified_semantics_fail_unsupported(
    stage_a_receipt: dict[str, Any], tmp_path: Path, policy: ValidationPolicy
) -> None:
    receipt, _, _, _ = _compare_case(stage_a_receipt, tmp_path, "exact", policy)
    assert receipt["state"] == "unsupported"


@pytest.mark.parametrize(
    ("case", "column", "expected"),
    [
        (
            "tolerance_boundary",
            ColumnPolicy("mynum", "float", absolute_tolerance="0.01"),
            True,
        ),
        (
            "tolerance_outside",
            ColumnPolicy("mynum", "float", absolute_tolerance="0.01"),
            False,
        ),
        (
            "relative_boundary",
            ColumnPolicy("mynum", "float", relative_tolerance="0.01"),
            True,
        ),
        (
            "relative_outside",
            ColumnPolicy("mynum", "float", relative_tolerance="0.01"),
            False,
        ),
        ("null_equal", ColumnPolicy("mynum", "float", null_policy="equal"), True),
        ("null_different", ColumnPolicy("mynum", "float", null_policy="different"), False),
        ("nan_equal", ColumnPolicy("mynum", "float", nan_equal=True), True),
        ("nan_different", ColumnPolicy("mynum", "float", nan_equal=False), False),
        ("infinity_equal", ColumnPolicy("mynum", "float", infinity_equal=True), True),
        (
            "infinity_different",
            ColumnPolicy("mynum", "float", infinity_equal=False),
            False,
        ),
        (
            "coercion",
            ColumnPolicy("mynum", "float", coercion="target_to_source"),
            True,
        ),
        (
            "invalid_coercion",
            ColumnPolicy("mynum", "float", coercion="target_to_source"),
            False,
        ),
        (
            "coercion_source_positive",
            ColumnPolicy("mynum", "float", coercion="source_to_target"),
            True,
        ),
        (
            "coercion_truncation",
            ColumnPolicy("mynum", "integer", coercion="target_to_source"),
            False,
        ),
        (
            "coercion_overflow",
            ColumnPolicy("mynum", "float", coercion="target_to_source"),
            False,
        ),
        (
            "coercion_decimal_loss",
            ColumnPolicy("mynum", "decimal", coercion="target_to_source"),
            False,
        ),
        (
            "coercion_target_noncanonical",
            ColumnPolicy("mynum", "float", coercion="target_to_source"),
            False,
        ),
        (
            "coercion_source_noncanonical",
            ColumnPolicy("mynum", "float", coercion="source_to_target"),
            False,
        ),
        (
            "duplicate_tiebreak",
            ColumnPolicy("mynum", "float"),
            True,
        ),
        ("ambiguous_tiebreak", ColumnPolicy("mynum", "float"), False),
        ("ordered", ColumnPolicy("mynum", "float"), True),
        ("order_changed", ColumnPolicy("mynum", "float"), False),
    ],
)
def test_configured_cell_semantics(
    stage_a_receipt: dict[str, Any],
    tmp_path: Path,
    case: str,
    column: ColumnPolicy,
    expected: bool,
) -> None:
    policy_changes: dict[str, Any] = {"columns": (column,)}
    if case in {"duplicate_tiebreak", "ambiguous_tiebreak"}:
        policy_changes.update(
            duplicate_policy="deterministic_tiebreak", tie_break_columns=("mynum",)
        )
    elif case in {"ordered", "order_changed"}:
        policy_changes.update(order_policy="ordered", order_columns=("mychar",))
        if case == "order_changed":
            policy_changes["order_columns"] = ("mynum",)
            policy_changes["nondeterministic_exclusions"] = ("mynum",)
    receipt, _, _, _ = _compare_case(stage_a_receipt, tmp_path, case, _policy(**policy_changes))
    if case in {
        "invalid_coercion",
        "coercion_truncation",
        "coercion_overflow",
        "coercion_decimal_loss",
        "coercion_target_noncanonical",
        "coercion_source_noncanonical",
        "ambiguous_tiebreak",
    }:
        assert receipt["state"] == "unsupported"
        return
    assert receipt["primary_match"] is expected, receipt
    assert receipt["datacompy_match"] is expected, receipt
    if case == "order_changed":
        assert receipt["source_only_count"] + receipt["target_only_count"] > 0
        assert receipt["cell_mismatch_count"] == 0
        return
    assert (receipt["cell_mismatch_count"] == 0) is expected


def test_stale_snapshot_binding_rejected(stage_a_receipt: dict[str, Any], tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not bound"):
        _compare_case(stage_a_receipt, tmp_path, "stale")
