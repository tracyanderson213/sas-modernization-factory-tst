"""SCALE-01 distributed SAS7BDAT qualification contract.

This module wraps the evaluated ``spark-sas7bdat``/Parso implementation.  It does not parse SAS
bytes itself.  The bounded proof reads one licensed upstream fixture with multiple Spark input
partitions and compares partition-complete aggregates to its independently streamed CSV oracle.
No source or target table is collected into driver memory.
"""

from __future__ import annotations

import csv
import fcntl
import hashlib
import importlib
import json
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from smf.immutable_files import (
    ensure_directory,
    open_lock_file,
    publish_json,
    published_file_exists,
    read_published_json,
)
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

SPARK_SAS7BDAT_REVISION = "dad0840bd89b7581c35a41ce372c61dc42d15eab"
PARSO_REVISION = "3c514e66264f5f3d5b2970bc2509d749065630c0"
SPARK_SAS7BDAT_JAR_SHA256 = "fd0c763c2b92457a583aab8855fd81fb76d30b9d017dcc39d17d952fe2ff3a27"
PARSO_JAR_SHA256 = "3b7e7a32915e04caed5dba31be1430aa57b4f9fa2b3d0ab0ed29067510d16575"
PUBLISHED_SCALA_212_JAR_SHA256 = "a4240d930e37d0bd2b8223e2b0186d26ecaa6dbf65226865227d3a2f71802d0e"
FIXTURE_SHA256 = "bc7867bb33bbf238b7085a370f59e9a91a76ff1f61f6df7c74e3b66d47f5b277"
ORACLE_SHA256 = "a0d0b31f26342a58e5cae435794d4297029d99f6a23acce1eddf4040980c54ec"
LICENSE_SHA256 = "5f3e56904af6912d99cb1a569bed78e39ff6ea25301b7a8fccae5b6e5b62c3cc"
PARSO_LICENSE_SHA256 = "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd"
BUILD_RECEIPT_SHA256 = "e919e2e2efe2f4ff44c8b68e401f29e97b95f9d4b3bd32926723eac954dc92c6"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODULUS = 1 << 256


@dataclass(frozen=True)
class DistributedReaderRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_relative_path: str
    source_sha256: str
    source_byte_count: int
    oracle_relative_path: str
    oracle_sha256: str
    oracle_byte_count: int

    def validate(self) -> None:
        for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
            value = getattr(self, field)
            if (
                not _SAFE_ID.fullmatch(value)
                or value in {".", ".."}
                or contains_protected_data(value)
            ):
                raise ValueError(f"Unsafe SCALE-01 {field}")
        _validate_relative(self.source_relative_path, ".sas7bdat")
        _validate_relative(self.oracle_relative_path, ".csv")
        if not _SHA256.fullmatch(self.source_sha256) or not _SHA256.fullmatch(self.oracle_sha256):
            raise ValueError("SCALE-01 source or oracle digest is invalid")
        if self.source_byte_count <= 0 or self.oracle_byte_count <= 0:
            raise ValueError("SCALE-01 source and oracle byte counts must be positive")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class DistributedReaderConfig:
    spark_sas7bdat_jar: str = "spark-sas7bdat-3.0.0-s_2.12.jar"
    spark_sas7bdat_sha256: str = SPARK_SAS7BDAT_JAR_SHA256
    parso_jar: str = "parso-2.0.14.jar"
    parso_sha256: str = PARSO_JAR_SHA256
    spark_sas7bdat_license: str = "LICENSE.spark-sas7bdat"
    spark_sas7bdat_license_sha256: str = LICENSE_SHA256
    parso_license: str = "LICENSE.parso"
    parso_license_sha256: str = PARSO_LICENSE_SHA256
    build_receipt: str = "scale01-build-receipt.json"
    build_receipt_sha256: str = BUILD_RECEIPT_SHA256
    spark_version: str = "3.5.8"
    scala_version: str = "2.12.18"
    spark_master: str = "local[4]"
    split_bytes: int = 1024 * 1024
    minimum_partitions: int = 2
    fixture_numeric_significant_digits: int = 12

    def validate(self) -> None:
        _validate_relative(self.spark_sas7bdat_jar, ".jar")
        _validate_relative(self.parso_jar, ".jar")
        _validate_relative(self.spark_sas7bdat_license, ".spark-sas7bdat")
        _validate_relative(self.parso_license, ".parso")
        _validate_relative(self.build_receipt, ".json")
        if (
            self.spark_sas7bdat_sha256 != SPARK_SAS7BDAT_JAR_SHA256
            or self.parso_sha256 != PARSO_JAR_SHA256
            or self.spark_sas7bdat_license_sha256 != LICENSE_SHA256
            or self.parso_license_sha256 != PARSO_LICENSE_SHA256
            or self.build_receipt_sha256 != BUILD_RECEIPT_SHA256
            or self.spark_version != "3.5.8"
            or self.scala_version != "2.12.18"
            or self.spark_master != "local[4]"
            or self.split_bytes != 1024 * 1024
            or self.minimum_partitions != 2
            or self.fixture_numeric_significant_digits != 12
        ):
            raise ValueError("Unsupported SCALE-01 runtime configuration")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class DistributedReaderExecution:
    result: dict[str, Any]
    result_path: Path


@dataclass(frozen=True)
class DistributedReaderStagedInputs:
    """Private, descriptor-verified copies of the qualified SCALE-01 inputs."""

    root: Path
    source_path: Path
    oracle_path: Path
    provider_jar: Path
    parso_jar: Path


def _validate_relative(value: str, suffix: str) -> None:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.suffix.lower() != suffix
    ):
        raise ValueError("SCALE-01 relative path is unsafe or unsupported")


def _snapshot(
    root: Path,
    relative: str,
    expected_sha: str,
    expected_bytes: int | None,
    *,
    staged_path: Path | None = None,
) -> dict[str, Any]:
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    path = lexical_root / relative
    if (
        root.is_symlink()
        or not lexical_root.is_dir()
        or path.is_symlink()
        or path.resolve().parent != lexical_root.resolve()
    ):
        raise ValueError("SCALE-01 authorized file root or path is unsafe")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    staged_descriptor: int | None = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("SCALE-01 input is not a regular file")
        if staged_path is not None:
            staged_path.parent.mkdir(parents=True, exist_ok=True)
            staged_descriptor = os.open(
                staged_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            if staged_descriptor is not None:
                view = memoryview(chunk)
                while view:
                    written = os.write(staged_descriptor, view)
                    view = view[written:]
        if staged_descriptor is not None:
            os.fsync(staged_descriptor)
        after = os.fstat(descriptor)
    finally:
        if staged_descriptor is not None:
            os.close(staged_descriptor)
        os.close(descriptor)
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    observed_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    observed = digest.hexdigest()
    if (
        identity != observed_after
        or observed != expected_sha
        or (expected_bytes is not None and before.st_size != expected_bytes)
    ):
        raise ValueError("SCALE-01 input snapshot identity mismatch")
    return {"relative_path": relative, "sha256": observed, "byte_count": before.st_size}


def _artifact_snapshot(root: Path, relative: str, expected_sha: str) -> tuple[Path, dict[str, Any]]:
    path = Path(os.path.abspath(os.fspath(root))) / relative
    projection = _snapshot(root, relative, expected_sha, None)
    return path, projection


def _build_receipt(root: Path, relative: str) -> dict[str, Any]:
    path = Path(os.path.abspath(os.fspath(root))) / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("SCALE-01 build receipt is not a regular file")
        chunks = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise ValueError("SCALE-01 build receipt changed while being read")
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise ValueError("SCALE-01 build receipt is not an object")
    expected = {
        "artifact_sha256": SPARK_SAS7BDAT_JAR_SHA256,
        "build_command": (
            "java -Dspark.version=3.5.8 -jar sbt-launch-1.9.8.jar ++2.12.18! clean package"
        ),
        "build_tool": "sbt",
        "build_tool_launcher_sha256": (
            "75c61f9717043ce4fefb0c85340c1b5cc4404f291358e76a28fc6e330af6dd92"
        ),
        "build_tool_version": "1.9.8",
        "scala_version": "2.12.18",
        "schema_version": "1.0",
        "spark_sas7bdat_revision": SPARK_SAS7BDAT_REVISION,
        "spark_version": "3.5.8",
    }
    if value != expected:
        raise ValueError("SCALE-01 build receipt is malformed or unsupported")
    return value


def _validate_provider_jar(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    required = {
        "com/github/saurfang/sas/spark/DefaultSource.class",
        "com/github/saurfang/sas/mapreduce/SasInputFormat.class",
    }
    if not required.issubset(names):
        raise ValueError("SCALE-01 provider JAR is empty or missing required classes")
    return {"class_file_count": sum(name.endswith(".class") for name in names)}


def _canonical_cell(value: Any, numeric_significant_digits: int) -> list[str]:
    if value is None:
        return ["null"]
    if isinstance(value, str):
        return ["string", value]
    if isinstance(value, int | float):
        # Parso exposes the SAS binary double while the paired upstream CSV serializes the same
        # fixture values in decimal. Remove only that bounded representation noise before an exact
        # byte comparison; this is not a production semantic mapping.
        return ["number", format(float(value), f".{numeric_significant_digits}g")]
    raise ValueError(f"SCALE-01 unsupported value type: {type(value).__name__}")


def _canonical_row(values: list[Any] | tuple[Any, ...], numeric_significant_digits: int) -> bytes:
    return json.dumps(
        [_canonical_cell(value, numeric_significant_digits) for value in values],
        separators=(",", ":"),
    ).encode()


def _empty_summary(index: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "row_count": 0,
        "null_counts": [],
        "digest_xor": "0" * 64,
        "digest_sum": "0" * 64,
    }
    if index is not None:
        value["partition_id"] = index
    return value


def _summarize_rows(
    rows: Any, width: int, numeric_significant_digits: int, index: int | None = None
) -> dict[str, Any]:
    count = 0
    nulls = [0] * width
    digest_xor = 0
    digest_sum = 0
    for row in rows:
        values = tuple(row)
        if len(values) != width:
            raise ValueError("SCALE-01 row width does not match schema")
        count += 1
        for position, value in enumerate(values):
            if value is None:
                nulls[position] += 1
        integer = int.from_bytes(
            hashlib.sha256(_canonical_row(values, numeric_significant_digits)).digest(), "big"
        )
        digest_xor ^= integer
        digest_sum = (digest_sum + integer) % _MODULUS
    return {
        "row_count": count,
        "null_counts": nulls,
        "digest_xor": f"{digest_xor:064x}",
        "digest_sum": f"{digest_sum:064x}",
        **({"partition_id": index} if index is not None else {}),
    }


def summarize_physical_rows(
    rows: Any, width: int, numeric_significant_digits: int
) -> dict[str, Any]:
    """Project rows to the partition-safe SCALE-01 physical multiset summary.

    BASE-04 uses this public projection for a transient local-provider comparison. Source rows
    never enter its durable evidence.
    """

    return _summarize_rows(rows, width, numeric_significant_digits)


def _merge_summaries(summaries: list[dict[str, Any]], width: int) -> dict[str, Any]:
    total = _empty_summary()
    total["null_counts"] = [0] * width
    digest_xor = 0
    digest_sum = 0
    for summary in summaries:
        total["row_count"] += summary["row_count"]
        total["null_counts"] = [
            left + right
            for left, right in zip(total["null_counts"], summary["null_counts"], strict=True)
        ]
        digest_xor ^= int(summary["digest_xor"], 16)
        digest_sum = (digest_sum + int(summary["digest_sum"], 16)) % _MODULUS
    total["digest_xor"] = f"{digest_xor:064x}"
    total["digest_sum"] = f"{digest_sum:064x}"
    return total


def _oracle_summary(
    path: Path, schema: list[dict[str, Any]], numeric_significant_digits: int
) -> dict[str, Any]:
    names = [field["name"] for field in schema]
    types = [field["type"] for field in schema]
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source)
        header = next(reader)
        if header != names:
            raise ValueError("SCALE-01 oracle header does not match provider schema")

        def converted() -> Any:
            for row in reader:
                if len(row) != len(types):
                    raise ValueError("SCALE-01 oracle row width mismatch")
                yield tuple(
                    None if cell == "" else (float(cell) if kind == "double" else cell)
                    for cell, kind in zip(row, types, strict=True)
                )

        return _summarize_rows(converted(), len(names), numeric_significant_digits)


def _result_path(root: Path, request: DistributedReaderRequest) -> tuple[Path, Path]:
    request.validate()
    directory = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "scale01"
    )
    return directory / "result.json", directory / "execution.lock"


def _execute_staged(
    request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    config: DistributedReaderConfig,
) -> dict[str, Any]:
    request.validate()
    config.validate()
    source = _snapshot(
        source_root, request.source_relative_path, request.source_sha256, request.source_byte_count
    )
    oracle = _snapshot(
        source_root, request.oracle_relative_path, request.oracle_sha256, request.oracle_byte_count
    )
    provider_path, provider = _artifact_snapshot(
        artifact_root, config.spark_sas7bdat_jar, config.spark_sas7bdat_sha256
    )
    parso_path, parso = _artifact_snapshot(artifact_root, config.parso_jar, config.parso_sha256)
    _, provider_license = _artifact_snapshot(
        artifact_root,
        config.spark_sas7bdat_license,
        config.spark_sas7bdat_license_sha256,
    )
    _, parso_license = _artifact_snapshot(
        artifact_root, config.parso_license, config.parso_license_sha256
    )
    _, receipt_snapshot = _artifact_snapshot(
        artifact_root, config.build_receipt, config.build_receipt_sha256
    )
    receipt = _build_receipt(artifact_root, config.build_receipt)
    provider.update(_validate_provider_jar(provider_path))
    spark_sql = importlib.import_module("pyspark.sql")
    spark = (
        spark_sql.SparkSession.builder.master(config.spark_master)
        .appName("smf-scale01-public-fixture")
        .config("spark.ui.enabled", "false")
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.jars", f"{provider_path},{parso_path}")
        .getOrCreate()
    )
    try:
        spark.sparkContext.setLogLevel("ERROR")
        spark.sparkContext._jsc.hadoopConfiguration().set(
            "mapreduce.input.fileinputformat.split.minsize", str(config.split_bytes)
        )
        spark.sparkContext._jsc.hadoopConfiguration().set(
            "mapreduce.input.fileinputformat.split.maxsize", str(config.split_bytes)
        )
        scala = str(spark.sparkContext._jvm.scala.util.Properties.versionNumberString())
        if spark.version != config.spark_version or scala != config.scala_version:
            raise ValueError("SCALE-01 Spark or Scala runtime is incompatible")
        frame = spark.read.format("com.github.saurfang.sas.spark").load(
            os.fspath(source_root / request.source_relative_path)
        )
        schema = [
            {"name": field.name, "type": field.dataType.simpleString(), "nullable": field.nullable}
            for field in frame.schema.fields
        ]
        partitions = frame.rdd.mapPartitionsWithIndex(
            lambda index, rows: iter(
                [
                    _summarize_rows(
                        rows, len(schema), config.fixture_numeric_significant_digits, index
                    )
                ]
            )
        ).collect()
        partitions = sorted(partitions, key=lambda item: item["partition_id"])
        if len(partitions) < config.minimum_partitions or any(
            item["row_count"] <= 0 for item in partitions
        ):
            raise ValueError("SCALE-01 did not exercise the required non-empty partitions")
        distributed = _merge_summaries(partitions, len(schema))
        oracle_summary = _oracle_summary(
            source_root / request.oracle_relative_path,
            schema,
            config.fixture_numeric_significant_digits,
        )
        reconciliation = {
            "schema_header_match": True,
            "row_count_match": distributed["row_count"] == oracle_summary["row_count"],
            "null_counts_match": distributed["null_counts"] == oracle_summary["null_counts"],
            "row_multiset_match": distributed["digest_xor"] == oracle_summary["digest_xor"]
            and distributed["digest_sum"] == oracle_summary["digest_sum"],
            "absolute_tolerance": 0.0,
            "relative_tolerance": 0.0,
        }
        reconciliation["passed"] = all(
            value for key, value in reconciliation.items() if key.endswith("_match")
        )
        if not reconciliation["passed"]:
            raise ValueError("SCALE-01 partition-complete reconciliation failed")
        runtime = {
            "spark_version": spark.version,
            "scala_version": scala,
            "spark_master": config.spark_master,
            "network_at_runtime": False,
            "driver_row_collection": False,
            "partition_summary_collection_only": True,
        }
    finally:
        spark.stop()
    # Re-read all governed byte identities after execution.
    _snapshot(
        source_root, request.source_relative_path, request.source_sha256, request.source_byte_count
    )
    _snapshot(
        source_root, request.oracle_relative_path, request.oracle_sha256, request.oracle_byte_count
    )
    _artifact_snapshot(artifact_root, config.spark_sas7bdat_jar, config.spark_sas7bdat_sha256)
    _artifact_snapshot(artifact_root, config.parso_jar, config.parso_sha256)
    _artifact_snapshot(
        artifact_root,
        config.spark_sas7bdat_license,
        config.spark_sas7bdat_license_sha256,
    )
    _artifact_snapshot(artifact_root, config.parso_license, config.parso_license_sha256)
    _artifact_snapshot(artifact_root, config.build_receipt, config.build_receipt_sha256)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": "",
        "request": request.binding(),
        "config": config.binding(),
        "upstream": {
            "spark_sas7bdat_revision": SPARK_SAS7BDAT_REVISION,
            "parso_revision": PARSO_REVISION,
            "build": receipt,
            "published_scala_212_disposition": "rejected_empty_no_class_files",
            "published_scala_212_sha256": PUBLISHED_SCALA_212_JAR_SHA256,
            "license_dispositions": {
                "spark_sas7bdat": "Apache-2.0; retain license and notices",
                "parso": "Apache-2.0; retain license and notices",
            },
        },
        "inputs": {"source": source, "oracle": oracle},
        "artifacts": {
            "spark_sas7bdat": provider,
            "parso": parso,
            "spark_sas7bdat_license": provider_license,
            "parso_license": parso_license,
            "build_receipt": receipt_snapshot,
        },
        "runtime": runtime,
        "schema": schema,
        "partitions": partitions,
        "distributed_summary": distributed,
        "oracle_summary": oracle_summary,
        "reconciliation": reconciliation,
        "claims": {
            "published_jar_qualified": False,
            "databricks_or_unity_catalog_validated": False,
            "humana_validated": False,
            "arbitrary_sas_coverage": False,
            "production_ready": False,
            "semantic_parity": False,
            "migration_complete": False,
        },
        "content_digest": "",
    }
    payload["result_id"] = stable_id(
        "SCALE01", {"request": payload["request"], "config": payload["config"]}
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    _verify_internal(payload)
    return payload


def _execute(
    request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    config: DistributedReaderConfig,
) -> dict[str, Any]:
    """Admit exact no-follow snapshots, then consume only private staged bytes."""

    with stage_distributed_reader_inputs(
        request,
        source_root=source_root,
        artifact_root=artifact_root,
        config=config,
    ) as inputs:
        result = _execute_staged(
            request,
            source_root=inputs.root,
            artifact_root=inputs.root,
            config=config,
        )
    return result


@contextmanager
def stage_distributed_reader_inputs(
    request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    config: DistributedReaderConfig,
) -> Iterator[DistributedReaderStagedInputs]:
    """Yield private copies acquired through SCALE-01's exact no-follow authority checks.

    Consumers must use only the yielded paths while the context is active. The caller-owned
    source and governed provider artifacts are reverified when the context exits.
    """

    request.validate()
    config.validate()
    with tempfile.TemporaryDirectory(prefix="smf-scale01-") as directory:
        staged = Path(directory)
        _snapshot(
            source_root,
            request.source_relative_path,
            request.source_sha256,
            request.source_byte_count,
            staged_path=staged / request.source_relative_path,
        )
        _snapshot(
            source_root,
            request.oracle_relative_path,
            request.oracle_sha256,
            request.oracle_byte_count,
            staged_path=staged / request.oracle_relative_path,
        )
        artifacts = (
            (config.spark_sas7bdat_jar, config.spark_sas7bdat_sha256),
            (config.parso_jar, config.parso_sha256),
            (config.spark_sas7bdat_license, config.spark_sas7bdat_license_sha256),
            (config.parso_license, config.parso_license_sha256),
            (config.build_receipt, config.build_receipt_sha256),
        )
        for relative, expected_sha in artifacts:
            _snapshot(
                artifact_root,
                relative,
                expected_sha,
                None,
                staged_path=staged / relative,
            )
        try:
            yield DistributedReaderStagedInputs(
                root=staged,
                source_path=staged / request.source_relative_path,
                oracle_path=staged / request.oracle_relative_path,
                provider_jar=staged / config.spark_sas7bdat_jar,
                parso_jar=staged / config.parso_jar,
            )
        finally:
            # Mutation of any admitted caller-owned byte invalidates the consumer even though it
            # used only privately staged snapshots.
            _snapshot(
                source_root,
                request.source_relative_path,
                request.source_sha256,
                request.source_byte_count,
            )
            _snapshot(
                source_root,
                request.oracle_relative_path,
                request.oracle_sha256,
                request.oracle_byte_count,
            )
            for relative, expected_sha in artifacts:
                _snapshot(artifact_root, relative, expected_sha, None)


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "request",
        "config",
        "upstream",
        "inputs",
        "artifacts",
        "runtime",
        "schema",
        "partitions",
        "distributed_summary",
        "oracle_summary",
        "reconciliation",
        "claims",
        "content_digest",
    }
    if set(result) != required or result["schema_version"] != "1.0":
        raise ValueError("SCALE-01 result contract is malformed")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("SCALE-01 result content digest mismatch")
    if not result["reconciliation"]["passed"] or any(result["claims"].values()):
        raise ValueError("SCALE-01 result asserts an unsupported outcome")
    if (
        result["runtime"]["driver_row_collection"]
        or not result["runtime"]["partition_summary_collection_only"]
    ):
        raise ValueError("SCALE-01 result permits whole-table driver collection")
    if len(result["partitions"]) < result["config"]["minimum_partitions"]:
        raise ValueError("SCALE-01 partition evidence is incomplete")


def run_distributed_reader(
    request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    config: DistributedReaderConfig,
) -> DistributedReaderExecution:
    config.validate()
    result_path, lock_path = _result_path(evidence_root, request)
    ensure_directory(result_path.parent, root=evidence_root)
    with open_lock_file(lock_path, root=evidence_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=evidence_root, label="SCALE-01 result"):
            return verify_distributed_reader(
                result_path,
                request=request,
                source_root=source_root,
                artifact_root=artifact_root,
                evidence_root=evidence_root,
                config=config,
            )
        result = _execute(
            request, source_root=source_root, artifact_root=artifact_root, config=config
        )
        publish_json(result_path, result, "SCALE-01 result", root=evidence_root)
        return DistributedReaderExecution(result, result_path)


def verify_distributed_reader(
    result_path: Path,
    *,
    request: DistributedReaderRequest,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    config: DistributedReaderConfig,
) -> DistributedReaderExecution:
    expected, _ = _result_path(evidence_root, request)
    if result_path != expected:
        raise ValueError("SCALE-01 evidence path is not request-bound")
    payload = read_published_json(result_path, root=evidence_root, label="SCALE-01 result")
    if not isinstance(payload, dict):
        raise ValueError("SCALE-01 immutable result is not an object")
    _verify_internal(payload)
    reconstructed = _execute(
        request, source_root=source_root, artifact_root=artifact_root, config=config
    )
    if reconstructed != payload:
        raise ValueError("SCALE-01 replay does not reconstruct immutable evidence")
    return DistributedReaderExecution(payload, result_path)


__all__ = [
    "DistributedReaderConfig",
    "DistributedReaderExecution",
    "DistributedReaderRequest",
    "DistributedReaderStagedInputs",
    "run_distributed_reader",
    "stage_distributed_reader_inputs",
    "summarize_physical_rows",
    "verify_distributed_reader",
]
