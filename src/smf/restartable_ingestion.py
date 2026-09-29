"""DBPKG-04 restartable qualified-reader to local-Delta orchestration.

This module composes the existing BASE-04/BASE-02 admission contracts, the qualified SCALE-01
Spark provider, Spark's partitioned Parquet writer, and delta-rs conversion. It implements no SAS
parser or Delta transaction engine. The only executable positive scope is the licensed public
SAS7BDAT qualification fixture; unsupported assets produce immutable blocked exception evidence.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any

from smf.canonical_descriptor import SnapshotPolicy
from smf.distributed_sas_reader import (
    DistributedReaderConfig,
    DistributedReaderRequest,
    stage_distributed_reader_inputs,
    summarize_physical_rows,
)
from smf.immutable_files import (
    ensure_directory,
    open_lock_file,
    publish_json,
    published_file_exists,
    read_published_json,
)
from smf.sas_reader import ReaderConfig, ReaderRequest
from smf.security.ai_admission import contains_protected_data
from smf.semantic_mapping import (
    DatasetMappingPolicy,
    SemanticMappingRequest,
    verify_semantic_mapping,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODULUS = 1 << 256
_SUPPORTED_ASSET = "sas7bdat"
_UNSUPPORTED_ASSETS = {
    "catalog",
    "corrupt_dataset",
    "encrypted_dataset",
    "index",
    "unsupported_encoding",
    "view",
}


def _safe_id(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or contains_protected_data(value)
    ):
        raise ValueError(f"Unsafe DBPKG-04 {label}")
    return value


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or contains_protected_data(value)
    ):
        raise ValueError("DBPKG-04 source path is unsafe")
    return value


@dataclass(frozen=True)
class RestartableIngestionRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_relative_path: str
    source_sha256: str
    source_byte_count: int
    asset_kind: str
    target_id: str

    def validate(self) -> None:
        for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id", "target_id"):
            _safe_id(getattr(self, field), field)
        _relative(self.source_relative_path)
        if not _SHA256.fullmatch(self.source_sha256) or self.source_byte_count <= 0:
            raise ValueError("DBPKG-04 source identity is invalid")
        if self.asset_kind not in {_SUPPORTED_ASSET, *_UNSUPPORTED_ASSETS}:
            raise ValueError("DBPKG-04 asset kind is unknown")
        if self.asset_kind == _SUPPORTED_ASSET and not self.source_relative_path.lower().endswith(
            ".sas7bdat"
        ):
            raise ValueError("DBPKG-04 SAS7BDAT asset path is incompatible")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class RestartableIngestionConfig:
    version: str = "dbpkg04-restartable-ingestion-v1"
    writer: str = "spark-parquet-plus-delta-rs-convert"
    delta_version: str = "1.6.4"
    spark_version: str = "3.5.8"
    spark_master: str = "local[4]"
    numeric_significant_digits: int = 12
    output_mode: str = "create_only"
    network_at_runtime: bool = False

    def validate(self) -> None:
        if self != RestartableIngestionConfig():
            raise ValueError("Unsupported DBPKG-04 ingestion configuration")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class RestartableIngestionExecution:
    result: dict[str, Any]
    result_path: Path
    delta_path: Path | None


def _paths(root: Path, request: RestartableIngestionRequest) -> dict[str, Path]:
    request.validate()
    attempt = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "dbpkg04"
    )
    return {
        "attempt": attempt,
        "lock": attempt / "execution.lock",
        "admission": attempt / "checkpoints" / "01-admission.json",
        "delta_checkpoint": attempt / "checkpoints" / "02-delta.json",
        "delta": attempt / "delta",
        "quarantine": attempt / "quarantine",
        "result": attempt / "result.json",
    }


def _same_identity(request: RestartableIngestionRequest, *bindings: dict[str, Any]) -> None:
    expected = request.binding()
    for binding in bindings:
        for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
            if binding[field] != expected[field]:
                raise ValueError("DBPKG-04 dependency identity mismatch")


def _unsupported_result(
    request: RestartableIngestionRequest, config: RestartableIngestionConfig
) -> dict[str, Any]:
    exception = {
        "code": "unsupported_asset_requires_disposition",
        "asset_kind": request.asset_kind,
        "source_reference": request.source_relative_path,
        "action": "route_to_exception_queue_and_obtain_supported_export_or_approved_disposition",
        "retryable": False,
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": "",
        "request": request.binding(),
        "request_digest": digest_value(request.binding()),
        "config": config.binding(),
        "state": "blocked_unsupported",
        "checkpoints": [],
        "dependencies": {},
        "delta": None,
        "reconciliation": None,
        "exceptions": [exception],
        "claims": _claims(),
        "content_digest": "",
    }
    payload["result_id"] = stable_id(
        "DBPKG04", {"request": payload["request"], "config": payload["config"]}
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    _verify_internal(payload)
    return payload


def _claims() -> dict[str, bool]:
    return {
        "live_databricks_or_unity_catalog": False,
        "humana_asset_qualified": False,
        "production_ready": False,
        "arbitrary_sas_supported": False,
        "semantic_parity": False,
        "migration_complete": False,
    }


def _checkpoint(
    path: Path,
    *,
    root: Path,
    phase: str,
    request: RestartableIngestionRequest,
    config: RestartableIngestionConfig,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "phase": phase,
        "request_digest": digest_value(request.binding()),
        "config_digest": digest_value(config.binding()),
        "evidence": evidence,
        "content_digest": "",
    }
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    publish_json(path, payload, f"DBPKG-04 {phase} checkpoint", root=root)
    observed = read_published_json(path, root=root, label=f"DBPKG-04 {phase} checkpoint")
    if observed != payload:
        raise ValueError(f"DBPKG-04 {phase} checkpoint replay mismatch")
    return payload


def _read_checkpoint(path: Path, *, root: Path, phase: str) -> dict[str, Any]:
    payload = read_published_json(path, root=root, label=f"DBPKG-04 {phase} checkpoint")
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "phase",
        "request_digest",
        "config_digest",
        "evidence",
        "content_digest",
    }:
        raise ValueError(f"DBPKG-04 {phase} checkpoint is malformed")
    if payload["schema_version"] != "1.0" or payload["phase"] != phase:
        raise ValueError(f"DBPKG-04 {phase} checkpoint identity mismatch")
    if payload["content_digest"] != digest_value({**payload, "content_digest": ""}):
        raise ValueError(f"DBPKG-04 {phase} checkpoint digest mismatch")
    return payload


def _manifest(path: Path) -> list[dict[str, Any]]:
    lexical = Path(os.path.abspath(os.fspath(path)))
    if path.is_symlink() or not lexical.is_dir() or lexical.resolve() != lexical:
        raise ValueError("DBPKG-04 Delta output is unsafe or missing")
    files: list[dict[str, Any]] = []
    for candidate in sorted(lexical.rglob("*")):
        if candidate.is_symlink():
            raise ValueError("DBPKG-04 Delta output contains a symlink")
        if candidate.is_dir():
            continue
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("DBPKG-04 Delta output contains a non-regular file")
            digest = hashlib.sha256()
            count = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
                count += len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if before_identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("DBPKG-04 Delta output changed while hashing")
        files.append(
            {
                "path": candidate.relative_to(lexical).as_posix(),
                "byte_count": count,
                "sha256": digest.hexdigest(),
            }
        )
    if not files or not any(item["path"].startswith("_delta_log/") for item in files):
        raise ValueError("DBPKG-04 output is not a Delta table")
    return files


def _merge_summaries(summaries: list[dict[str, Any]], width: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "row_count": 0,
        "null_counts": [0] * width,
        "digest_xor": "0" * 64,
        "digest_sum": "0" * 64,
    }
    xor_value = 0
    sum_value = 0
    for summary in summaries:
        result["row_count"] += summary["row_count"]
        result["null_counts"] = [
            left + right
            for left, right in zip(result["null_counts"], summary["null_counts"], strict=True)
        ]
        xor_value ^= int(summary["digest_xor"], 16)
        sum_value = (sum_value + int(summary["digest_sum"], 16)) % _MODULUS
    result["digest_xor"] = f"{xor_value:064x}"
    result["digest_sum"] = f"{sum_value:064x}"
    return result


def _delta_summary(delta_path: Path, width: int, digits: int) -> tuple[dict[str, Any], int]:
    delta = importlib.import_module("deltalake")
    table = delta.DeltaTable(delta_path)
    summaries = []
    for batch in table.to_pyarrow_dataset().scanner(batch_size=4096).to_batches():
        names = batch.schema.names
        rows = (tuple(item[name] for name in names) for item in batch.to_pylist())
        summaries.append(summarize_physical_rows(rows, width, digits))
    return _merge_summaries(summaries, width), int(table.version())


def _write_delta(
    request: RestartableIngestionRequest,
    distributed: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    output_root: Path,
    delta_path: Path,
    quarantine_root: Path,
    distributed_config: DistributedReaderConfig,
    expected_summary: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    ensure_directory(delta_path.parent, root=output_root)
    if not delta_path.exists():
        stage_parent = Path(tempfile.mkdtemp(prefix=".dbpkg04-stage-", dir=delta_path.parent))
        stage = stage_parent / "delta"
        try:
            with stage_distributed_reader_inputs(
                distributed,
                source_root=source_root,
                artifact_root=artifact_root,
                config=distributed_config,
            ) as inputs:
                spark_sql = importlib.import_module("pyspark.sql")
                spark = (
                    spark_sql.SparkSession.builder.master(distributed_config.spark_master)
                    .appName("smf-db-pkg-04-public-fixture")
                    .config("spark.ui.enabled", "false")
                    .config("spark.driver.bindAddress", "127.0.0.1")
                    .config("spark.driver.host", "127.0.0.1")
                    .config("spark.jars", f"{inputs.provider_jar},{inputs.parso_jar}")
                    .getOrCreate()
                )
                try:
                    spark.sparkContext.setLogLevel("ERROR")
                    scala = str(spark.sparkContext._jvm.scala.util.Properties.versionNumberString())
                    if (
                        spark.version != distributed_config.spark_version
                        or scala != distributed_config.scala_version
                    ):
                        raise ValueError("DBPKG-04 Spark or Scala runtime is incompatible")
                    spark.sparkContext._jsc.hadoopConfiguration().set(
                        "mapreduce.input.fileinputformat.split.minsize",
                        str(distributed_config.split_bytes),
                    )
                    spark.sparkContext._jsc.hadoopConfiguration().set(
                        "mapreduce.input.fileinputformat.split.maxsize",
                        str(distributed_config.split_bytes),
                    )
                    frame = spark.read.format("com.github.saurfang.sas.spark").load(
                        os.fspath(inputs.source_path)
                    )
                    if frame.rdd.getNumPartitions() < distributed_config.minimum_partitions:
                        raise ValueError("DBPKG-04 did not retain partitioned reader execution")
                    frame.write.mode("error").parquet(os.fspath(stage))
                finally:
                    spark.stop()
            delta = importlib.import_module("deltalake")
            if metadata.version("deltalake") != "1.6.4":
                raise ValueError("DBPKG-04 Delta runtime is incompatible")
            delta.convert_to_deltalake(stage, mode="error")
            _manifest(stage)
            os.rename(stage, delta_path)
            stage_parent.rmdir()
        except Exception:
            if stage.exists():
                ensure_directory(quarantine_root, root=output_root)
                quarantine = quarantine_root / (
                    f"staging-{request.source_sha256[:12]}-{stage.name[1:]}"
                )
                os.rename(stage, quarantine)
            if stage_parent.exists():
                shutil.rmtree(stage_parent)
            raise
    manifest_before = _manifest(delta_path)
    summary, version = _delta_summary(
        delta_path,
        len(expected_summary["null_counts"]),
        distributed_config.fixture_numeric_significant_digits,
    )
    if summary != expected_summary:
        ensure_directory(quarantine_root, root=output_root)
        quarantine = quarantine_root / f"delta-mismatch-{request.source_sha256[:12]}"
        os.rename(delta_path, quarantine)
        raise ValueError("DBPKG-04 Delta reconciliation failed; output quarantined")
    if _manifest(delta_path) != manifest_before:
        raise ValueError("DBPKG-04 Delta output changed during reconciliation")
    return manifest_before, summary, version


def _quarantine_stale_delta(paths: dict[str, Path], output_root: Path, source_sha: str) -> None:
    if not paths["delta"].exists():
        return
    ensure_directory(paths["quarantine"], root=output_root)
    destination = paths["quarantine"] / f"invalidated-{source_sha[:12]}"
    if destination.exists():
        raise ValueError("DBPKG-04 invalidated output quarantine collision")
    os.rename(paths["delta"], destination)


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "request",
        "request_digest",
        "config",
        "state",
        "checkpoints",
        "dependencies",
        "delta",
        "reconciliation",
        "exceptions",
        "claims",
        "content_digest",
    }
    if set(result) != required or result["schema_version"] != "1.0":
        raise ValueError("DBPKG-04 result contract is malformed")
    request = RestartableIngestionRequest(**result["request"])
    config = RestartableIngestionConfig(**result["config"])
    if result["request_digest"] != digest_value(request.binding()):
        raise ValueError("DBPKG-04 request digest mismatch")
    config.validate()
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("DBPKG-04 content digest mismatch")
    if result["claims"] != _claims():
        raise ValueError("DBPKG-04 result asserts a prohibited claim")
    if result["state"] == "blocked_unsupported":
        if (
            result["checkpoints"]
            or result["dependencies"]
            or result["delta"] is not None
            or result["reconciliation"] is not None
            or not result["exceptions"]
        ):
            raise ValueError("DBPKG-04 unsupported result is not fail-closed")
    elif result["state"] == "complete_local_delta":
        if (
            [item.get("phase") for item in result["checkpoints"]] != ["admission", "delta"]
            or any(
                set(item) != {"phase", "content_digest"}
                or not _SHA256.fullmatch(item.get("content_digest", ""))
                for item in result["checkpoints"]
            )
            or result["exceptions"]
            or not result["reconciliation"]["passed"]
            or result["delta"] is None
        ):
            raise ValueError("DBPKG-04 completed result is inconsistent")
    else:
        raise ValueError("DBPKG-04 result state is invalid")


def run_restartable_ingestion(
    request: RestartableIngestionRequest,
    *,
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    semantic_request: SemanticMappingRequest,
    mapping_policy: DatasetMappingPolicy,
    base04_result_path: Path,
    base02_result_path: Path,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    snapshot_policy: SnapshotPolicy,
    config: RestartableIngestionConfig | None = None,
    phase_hook: Callable[[str], None] | None = None,
) -> RestartableIngestionExecution:
    """Execute, resume, or replay one immutable local ingestion attempt."""

    config = config or RestartableIngestionConfig()
    request.validate()
    config.validate()
    paths = _paths(evidence_root, request)
    ensure_directory(paths["attempt"], root=evidence_root)
    with open_lock_file(paths["lock"], root=evidence_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(paths["result"], root=evidence_root, label="DBPKG-04 result"):
            return verify_restartable_ingestion(
                paths["result"],
                request=request,
                local_request=local_request,
                distributed_request=distributed_request,
                semantic_request=semantic_request,
                mapping_policy=mapping_policy,
                base04_result_path=base04_result_path,
                base02_result_path=base02_result_path,
                source_root=source_root,
                artifact_root=artifact_root,
                evidence_root=evidence_root,
                local_config=local_config,
                distributed_config=distributed_config,
                snapshot_policy=snapshot_policy,
                config=config,
            )
        if request.asset_kind != _SUPPORTED_ASSET:
            result = _unsupported_result(request, config)
            publish_json(paths["result"], result, "DBPKG-04 result", root=evidence_root)
            return RestartableIngestionExecution(result, paths["result"], None)
        _same_identity(
            request,
            local_request.binding(),
            distributed_request.binding(),
            semantic_request.binding(),
        )
        if (
            request.source_relative_path != distributed_request.source_relative_path
            or request.source_relative_path != local_request.relative_path
            or request.source_sha256 != distributed_request.source_sha256
            or request.source_sha256 != local_request.source_sha256
            or request.source_byte_count != distributed_request.source_byte_count
            or request.source_byte_count != local_request.source_byte_count
        ):
            raise ValueError("DBPKG-04 source identity does not match SCALE-01")
        try:
            semantic = verify_semantic_mapping(
                base02_result_path,
                semantic_request,
                mapping_policy,
                base04_result_path=base04_result_path,
                local_request=local_request,
                distributed_request=distributed_request,
                source_root=source_root,
                artifact_root=artifact_root,
                evidence_root=evidence_root,
                local_config=local_config,
                distributed_config=distributed_config,
                snapshot_policy=snapshot_policy,
            )
        except Exception:
            _quarantine_stale_delta(paths, evidence_root, request.source_sha256)
            raise
        if semantic.result["state"] != "qualified_underlying_mapping":
            raise ValueError("DBPKG-04 semantic mapping is not qualified for underlying values")
        descriptor = semantic.result["canonical_descriptor"]
        base04 = read_published_json(base04_result_path, root=evidence_root, label="BASE-04 result")
        if not isinstance(base04, dict):
            raise ValueError("DBPKG-04 BASE-04 evidence is invalid")
        scale = base04["provider_snapshots"]["scale01"]
        admission = _checkpoint(
            paths["admission"],
            root=evidence_root,
            phase="admission",
            request=request,
            config=config,
            evidence={
                "base02_result_id": semantic.result["result_id"],
                "base02_content_digest": semantic.result["content_digest"],
                "base04_result_id": descriptor["result_id"],
                "base04_content_digest": descriptor["content_digest"],
                "scale01_result_id": scale["result_id"],
                "scale01_content_digest": scale["content_digest"],
                "source_sha256": request.source_sha256,
            },
        )
        if phase_hook is not None:
            phase_hook("admission")
        manifest, target_summary, delta_version = _write_delta(
            request,
            distributed_request,
            source_root=source_root,
            artifact_root=artifact_root,
            output_root=evidence_root,
            delta_path=paths["delta"],
            quarantine_root=paths["quarantine"],
            distributed_config=distributed_config,
            expected_summary=scale["physical_summary"],
        )
        reconciliation = {
            "source_summary": scale["physical_summary"],
            "target_summary": target_summary,
            "partition_complete": True,
            "whole_table_driver_collection": False,
            "passed": target_summary == scale["physical_summary"],
        }
        delta_projection = {
            "path_reference": "dbpkg04/delta",
            "format": "delta",
            "table_version": delta_version,
            "writer": config.writer,
            "manifest": manifest,
            "manifest_digest": digest_value(manifest),
        }
        delta_checkpoint = _checkpoint(
            paths["delta_checkpoint"],
            root=evidence_root,
            phase="delta",
            request=request,
            config=config,
            evidence={
                "delta": delta_projection,
                "reconciliation": reconciliation,
            },
        )
        if phase_hook is not None:
            phase_hook("delta")
        checkpoints = [
            {"phase": "admission", "content_digest": admission["content_digest"]},
            {"phase": "delta", "content_digest": delta_checkpoint["content_digest"]},
        ]
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "result_id": "",
            "request": request.binding(),
            "request_digest": digest_value(request.binding()),
            "config": config.binding(),
            "state": "complete_local_delta",
            "checkpoints": checkpoints,
            "dependencies": admission["evidence"],
            "delta": delta_projection,
            "reconciliation": reconciliation,
            "exceptions": [],
            "claims": _claims(),
            "content_digest": "",
        }
        payload["result_id"] = stable_id(
            "DBPKG04", {"request": payload["request"], "checkpoints": checkpoints}
        )
        payload["content_digest"] = digest_value({**payload, "content_digest": ""})
        _verify_internal(payload)
        publish_json(paths["result"], payload, "DBPKG-04 result", root=evidence_root)
        return RestartableIngestionExecution(payload, paths["result"], paths["delta"])


def verify_restartable_ingestion(
    result_path: Path,
    *,
    request: RestartableIngestionRequest,
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    semantic_request: SemanticMappingRequest,
    mapping_policy: DatasetMappingPolicy,
    base04_result_path: Path,
    base02_result_path: Path,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    snapshot_policy: SnapshotPolicy,
    config: RestartableIngestionConfig | None = None,
) -> RestartableIngestionExecution:
    config = config or RestartableIngestionConfig()
    paths = _paths(evidence_root, request)
    if result_path != paths["result"]:
        raise ValueError("DBPKG-04 result path is not request-bound")
    payload = read_published_json(result_path, root=evidence_root, label="DBPKG-04 result")
    if not isinstance(payload, dict):
        raise ValueError("DBPKG-04 result is not an object")
    _verify_internal(payload)
    if payload["state"] == "blocked_unsupported":
        if payload != _unsupported_result(request, config):
            raise ValueError("DBPKG-04 unsupported evidence does not reconstruct")
        return RestartableIngestionExecution(payload, result_path, None)
    semantic = verify_semantic_mapping(
        base02_result_path,
        semantic_request,
        mapping_policy,
        base04_result_path=base04_result_path,
        local_request=local_request,
        distributed_request=distributed_request,
        source_root=source_root,
        artifact_root=artifact_root,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        snapshot_policy=snapshot_policy,
    )
    admission = _read_checkpoint(paths["admission"], root=evidence_root, phase="admission")
    delta_checkpoint = _read_checkpoint(
        paths["delta_checkpoint"], root=evidence_root, phase="delta"
    )
    manifest = _manifest(paths["delta"])
    target_summary, version = _delta_summary(
        paths["delta"],
        len(payload["reconciliation"]["source_summary"]["null_counts"]),
        distributed_config.fixture_numeric_significant_digits,
    )
    if (
        semantic.result["content_digest"] != payload["dependencies"]["base02_content_digest"]
        or admission["request_digest"] != payload["request_digest"]
        or admission["config_digest"] != digest_value(payload["config"])
        or admission["evidence"] != payload["dependencies"]
        or admission["content_digest"] != payload["checkpoints"][0]["content_digest"]
        or delta_checkpoint["request_digest"] != payload["request_digest"]
        or delta_checkpoint["config_digest"] != digest_value(payload["config"])
        or delta_checkpoint["evidence"]
        != {"delta": payload["delta"], "reconciliation": payload["reconciliation"]}
        or delta_checkpoint["content_digest"] != payload["checkpoints"][1]["content_digest"]
        or digest_value(manifest) != payload["delta"]["manifest_digest"]
        or manifest != payload["delta"]["manifest"]
        or version != payload["delta"]["table_version"]
        or target_summary != payload["reconciliation"]["target_summary"]
        or target_summary != payload["reconciliation"]["source_summary"]
    ):
        raise ValueError("DBPKG-04 current inputs and output do not reconstruct immutable evidence")
    return RestartableIngestionExecution(payload, result_path, paths["delta"])


__all__ = [
    "RestartableIngestionConfig",
    "RestartableIngestionExecution",
    "RestartableIngestionRequest",
    "run_restartable_ingestion",
    "verify_restartable_ingestion",
]
