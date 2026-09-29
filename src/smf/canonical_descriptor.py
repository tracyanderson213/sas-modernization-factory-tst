"""BASE-04 canonical cross-provider descriptor qualification.

The contract reconciles independently produced BASE-08 and SCALE-01 observations for the
same immutable SAS7BDAT snapshot.  It normalizes only provider physical-type vocabulary; it
does not establish BASE-02 semantic mappings, SAS parity, or customer readiness.
"""

from __future__ import annotations

import fcntl
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from smf.distributed_sas_reader import (
    DistributedReaderConfig,
    DistributedReaderRequest,
    run_distributed_reader,
    summarize_physical_rows,
)
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
from smf.sas_reader.evidence import reader_result_path
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_PHYSICAL_TYPES = {"str": "string", "float": "double", "int": "long", "bool": "boolean"}


def _timestamp(value: str, label: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError(f"BASE-04 {label} must use canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"BASE-04 {label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"BASE-04 {label} must use canonical UTC RFC3339")
    return parsed


@dataclass(frozen=True)
class SnapshotPolicy:
    version: str
    acquisition_time: str
    evaluation_time: str
    valid_until: str
    data_scope: str = "licensed-public-fixture"
    retention_class: str = "immutable-qualification-evidence"

    def validate(self) -> None:
        if self.version != "base04-public-fixture-v1":
            raise ValueError("Unsupported BASE-04 snapshot policy")
        acquired = _timestamp(self.acquisition_time, "acquisition_time")
        evaluated = _timestamp(self.evaluation_time, "evaluation_time")
        expires = _timestamp(self.valid_until, "valid_until")
        if acquired > evaluated or expires <= evaluated:
            raise ValueError("BASE-04 fixture is future-dated or expired")
        if self.data_scope != "licensed-public-fixture" or self.retention_class != (
            "immutable-qualification-evidence"
        ):
            raise ValueError("BASE-04 snapshot scope or retention is unsupported")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class CanonicalDescriptorExecution:
    result: dict[str, Any]
    result_path: Path


def _paths(root: Path, request: ReaderRequest) -> tuple[Path, Path, Path]:
    request.validate()
    attempt = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "base04"
    )
    return attempt, attempt / "result.json", attempt / "execution.lock"


def _require_same_identity(local: ReaderRequest, distributed: DistributedReaderRequest) -> None:
    pairs = {
        "client_id": (local.client_id, distributed.client_id),
        "workload_id": (local.workload_id, distributed.workload_id),
        "source_id": (local.source_id, distributed.source_id),
        "run_id": (local.run_id, distributed.run_id),
        "attempt_id": (local.attempt_id, distributed.attempt_id),
        "source_relative_path": (local.relative_path, distributed.source_relative_path),
        "source_sha256": (local.source_sha256, distributed.source_sha256),
        "source_byte_count": (local.source_byte_count, distributed.source_byte_count),
    }
    if any(left != right for left, right in pairs.values()):
        raise ValueError("BASE-04 provider requests do not identify the same source snapshot")


def _canonical_columns(
    local_descriptor: dict[str, Any], distributed_result: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    local_columns = local_descriptor["columns"]
    distributed_columns = distributed_result["schema"]
    conflicts: list[str] = []
    if len(local_columns) != len(distributed_columns):
        conflicts.append("column_count")
    columns: list[dict[str, Any]] = []
    for position, (local, distributed) in enumerate(
        zip(local_columns, distributed_columns, strict=False)
    ):
        observed_type = local["observed"]["normalized_type"]
        canonical_type = _PHYSICAL_TYPES.get(observed_type)
        if canonical_type is None:
            conflicts.append(f"unsupported_physical_type:{position}")
        if local["position"] != position or local["name"] != distributed["name"]:
            conflicts.append(f"column_identity:{position}")
        if canonical_type != distributed["type"]:
            conflicts.append(f"physical_type:{position}")
        local_nulls = local["observed"]["null_count"]
        distributed_nulls = distributed_result["distributed_summary"]["null_counts"][position]
        if local_nulls != distributed_nulls:
            conflicts.append(f"null_count:{position}")
        columns.append(
            {
                "position": position,
                "name": local["name"],
                "canonical_physical_type": canonical_type,
                "nullable_observed": local_nulls > 0,
                "null_count": local_nulls,
                "declared_sas_metadata": local["declared"],
                "provider_observations": {
                    "base08": local["observed"],
                    "scale01": {
                        "spark_type": distributed["type"],
                        "nullable": distributed["nullable"],
                        "null_count": distributed_nulls,
                    },
                },
            }
        )
    return columns, sorted(conflicts)


def _compare_physical_summaries(
    local: dict[str, Any], distributed: dict[str, Any]
) -> tuple[dict[str, bool], list[str]]:
    checks = {
        "row_count_match": local["row_count"] == distributed["row_count"],
        "null_counts_match": local["null_counts"] == distributed["null_counts"],
        "row_multiset_match": local["digest_xor"] == distributed["digest_xor"]
        and local["digest_sum"] == distributed["digest_sum"],
    }
    conflicts = [name.removesuffix("_match") for name, passed in checks.items() if not passed]
    return checks, conflicts


def _build_result(
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    policy: SnapshotPolicy,
    local_execution: ReaderExecution,
    distributed_result: dict[str, Any],
) -> dict[str, Any]:
    local_result = local_execution.result
    descriptor = cast(dict[str, Any], local_result["descriptor"])
    columns, conflicts = _canonical_columns(descriptor, distributed_result)
    local_summary = summarize_physical_rows(
        (row for chunk in local_execution.chunks for row in chunk),
        descriptor["observed_column_count"],
        distributed_result["config"]["fixture_numeric_significant_digits"],
    )
    distributed_summary = distributed_result["distributed_summary"]
    summary_checks, summary_conflicts = _compare_physical_summaries(
        local_summary, distributed_summary
    )
    conflicts.extend(summary_conflicts)
    source_snapshot = {
        "sha256": local_request.source_sha256,
        "byte_count": local_request.source_byte_count,
        "acquisition_time": policy.acquisition_time,
        "data_scope": policy.data_scope,
        "retention_class": policy.retention_class,
    }
    canonical = {
        "descriptor_version": "base04-canonical-physical-v1",
        "file_format": descriptor["file_format"],
        "file_encoding": descriptor["file_encoding"],
        "table_name": descriptor["table_name"],
        "file_label": descriptor["file_label"],
        "row_count": local_summary["row_count"],
        "column_count": len(columns),
        "declared_keys": descriptor["declared_keys"],
        "key_authority": descriptor["key_authority"],
        "columns": columns,
        "semantic_mapping_authority": "pending-base02",
    }
    comparison = {
        "policy_compatible": True,
        "same_source_snapshot": True,
        "column_order_match": not any(item.startswith("column_identity:") for item in conflicts),
        "physical_types_match": not any(
            item.startswith(("physical_type:", "unsupported_physical_type:")) for item in conflicts
        ),
        "row_count_match": summary_checks["row_count_match"],
        "null_counts_match": summary_checks["null_counts_match"]
        and not any(item.startswith("null_count:") for item in conflicts),
        "row_multiset_match": summary_checks["row_multiset_match"],
        "conflicts": sorted(set(conflicts)),
    }
    comparison["passed"] = not comparison["conflicts"]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": "",
        "identity": {
            "client_id": local_request.client_id,
            "workload_id": local_request.workload_id,
            "source_id": local_request.source_id,
            "run_id": local_request.run_id,
            "attempt_id": local_request.attempt_id,
        },
        "snapshot_policy": policy.binding(),
        "source_snapshot": source_snapshot,
        "provider_snapshots": {
            "base08": {
                "result_id": local_result["result_id"],
                "content_digest": local_result["content_digest"],
                "runtime_digest": local_result["runtime_digest"],
                "config_digest": local_result["config_digest"],
                "state": local_result["state"],
                "physical_summary": local_summary,
            },
            "scale01": {
                "result_id": distributed_result["result_id"],
                "content_digest": distributed_result["content_digest"],
                "runtime": distributed_result["runtime"],
                "config": distributed_result["config"],
                "physical_summary": distributed_summary,
            },
        },
        "canonical_descriptor": canonical,
        "descriptor_digest": digest_value(canonical),
        "target_snapshot": {
            "artifact_type": "canonical-cross-provider-descriptor",
            "descriptor_digest": digest_value(canonical),
            "acquisition_time": policy.evaluation_time,
            "data_scope": policy.data_scope,
            "retention_class": policy.retention_class,
        },
        "comparison": comparison,
        "claims": {
            "governed_production_semantic_mapping": False,
            "sas_semantic_parity": False,
            "humana_validated": False,
            "databricks_or_unity_catalog_validated": False,
            "production_ready": False,
            "migration_complete": False,
        },
        "content_digest": "",
    }
    payload["result_id"] = stable_id(
        "BASE04",
        {
            "identity": payload["identity"],
            "source_snapshot": source_snapshot,
            "policy": payload["snapshot_policy"],
            "providers": payload["provider_snapshots"],
        },
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    _verify_internal(payload)
    return payload


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "identity",
        "snapshot_policy",
        "source_snapshot",
        "provider_snapshots",
        "canonical_descriptor",
        "descriptor_digest",
        "target_snapshot",
        "comparison",
        "claims",
        "content_digest",
    }
    if set(result) != required or result["schema_version"] != "1.0":
        raise ValueError("BASE-04 result contract is malformed")
    if set(result["identity"]) != {
        "client_id",
        "workload_id",
        "source_id",
        "run_id",
        "attempt_id",
    }:
        raise ValueError("BASE-04 identity contract is malformed")
    policy = SnapshotPolicy(**result["snapshot_policy"])
    policy.validate()
    if set(result["source_snapshot"]) != {
        "sha256",
        "byte_count",
        "acquisition_time",
        "data_scope",
        "retention_class",
    } or set(result["target_snapshot"]) != {
        "artifact_type",
        "descriptor_digest",
        "acquisition_time",
        "data_scope",
        "retention_class",
    }:
        raise ValueError("BASE-04 source or target snapshot contract is malformed")
    if (
        set(result["provider_snapshots"]) != {"base08", "scale01"}
        or set(result["provider_snapshots"]["base08"])
        != {
            "result_id",
            "content_digest",
            "runtime_digest",
            "config_digest",
            "state",
            "physical_summary",
        }
        or set(result["provider_snapshots"]["scale01"])
        != {"result_id", "content_digest", "runtime", "config", "physical_summary"}
    ):
        raise ValueError("BASE-04 provider snapshot contract is malformed")
    canonical = result["canonical_descriptor"]
    if (
        set(canonical)
        != {
            "descriptor_version",
            "file_format",
            "file_encoding",
            "table_name",
            "file_label",
            "row_count",
            "column_count",
            "declared_keys",
            "key_authority",
            "columns",
            "semantic_mapping_authority",
        }
        or canonical["descriptor_version"] != "base04-canonical-physical-v1"
    ):
        raise ValueError("BASE-04 canonical descriptor contract is malformed")
    if canonical["column_count"] != len(canonical["columns"]):
        raise ValueError("BASE-04 canonical descriptor column count is inconsistent")
    names: set[str] = set()
    for position, column in enumerate(canonical["columns"]):
        if set(column) != {
            "position",
            "name",
            "canonical_physical_type",
            "nullable_observed",
            "null_count",
            "declared_sas_metadata",
            "provider_observations",
        }:
            raise ValueError("BASE-04 canonical column contract is malformed")
        if column["position"] != position or column["name"] in names:
            raise ValueError("BASE-04 canonical column order or identity is invalid")
        names.add(column["name"])
        if column["canonical_physical_type"] not in set(_PHYSICAL_TYPES.values()):
            raise ValueError("BASE-04 canonical physical type is unsupported")
        if set(column["provider_observations"]) != {"base08", "scale01"}:
            raise ValueError("BASE-04 canonical provider observations are malformed")
    if set(result["comparison"]) != {
        "policy_compatible",
        "same_source_snapshot",
        "column_order_match",
        "physical_types_match",
        "row_count_match",
        "null_counts_match",
        "row_multiset_match",
        "conflicts",
        "passed",
    }:
        raise ValueError("BASE-04 comparison contract is malformed")
    expected_claims = {
        "governed_production_semantic_mapping",
        "sas_semantic_parity",
        "humana_validated",
        "databricks_or_unity_catalog_validated",
        "production_ready",
        "migration_complete",
    }
    if set(result["claims"]) != expected_claims:
        raise ValueError("BASE-04 claims contract is malformed")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("BASE-04 result content digest mismatch")
    if result["descriptor_digest"] != digest_value(result["canonical_descriptor"]):
        raise ValueError("BASE-04 canonical descriptor digest mismatch")
    if result["target_snapshot"]["descriptor_digest"] != result["descriptor_digest"]:
        raise ValueError("BASE-04 target snapshot does not bind the canonical descriptor")
    expected_id = stable_id(
        "BASE04",
        {
            "identity": result["identity"],
            "source_snapshot": result["source_snapshot"],
            "policy": result["snapshot_policy"],
            "providers": result["provider_snapshots"],
        },
    )
    if result["result_id"] != expected_id:
        raise ValueError("BASE-04 result identity binding is invalid")
    if not result["comparison"]["passed"] or result["comparison"]["conflicts"]:
        raise ValueError("BASE-04 cross-provider observations conflict")
    if result["canonical_descriptor"]["semantic_mapping_authority"] != "pending-base02":
        raise ValueError("BASE-04 cannot assert production semantic mapping authority")
    if any(result["claims"].values()):
        raise ValueError("BASE-04 result asserts a prohibited claim")


def _execute(
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    policy: SnapshotPolicy,
    cancel_check: Callable[[], bool] | None,
) -> dict[str, Any]:
    local_request.validate()
    distributed_request.validate()
    policy.validate()
    _require_same_identity(local_request, distributed_request)
    if cancel_check is not None and cancel_check():
        raise InterruptedError("BASE-04 execution cancelled before provider work")
    provider = PyreadstatProvider()
    local = read_sas7bdat(
        local_request, authorized_root=source_root, config=local_config, provider=provider
    )
    if local.result["state"] != "complete":
        raise ValueError("BASE-04 local provider did not complete")
    local_path = reader_result_path(evidence_root, local_request)
    if published_file_exists(local_path, root=evidence_root, label="SAS reader result"):
        local = verify_reader_result(
            local_path,
            evidence_root=evidence_root,
            request=local_request,
            authorized_root=source_root,
            config=local_config,
            provider=provider,
        )
    else:
        publish_reader_result(
            evidence_root,
            local_request,
            local,
            authorized_root=source_root,
            config=local_config,
            provider=provider,
        )
    if cancel_check is not None and cancel_check():
        raise InterruptedError("BASE-04 execution cancelled after local provider")
    distributed = run_distributed_reader(
        distributed_request,
        source_root=source_root,
        artifact_root=artifact_root,
        evidence_root=evidence_root,
        config=distributed_config,
    )
    if cancel_check is not None and cancel_check():
        raise InterruptedError("BASE-04 execution cancelled before publication")
    return _build_result(
        local_request,
        distributed_request,
        policy,
        local,
        distributed.result,
    )


def run_canonical_descriptor(
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    policy: SnapshotPolicy,
    cancel_check: Callable[[], bool] | None = None,
) -> CanonicalDescriptorExecution:
    """Execute both qualified providers and atomically publish their canonical descriptor."""

    _, result_path, lock_path = _paths(evidence_root, local_request)
    ensure_directory(result_path.parent, root=evidence_root)
    with open_lock_file(lock_path, root=evidence_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=evidence_root, label="BASE-04 result"):
            return verify_canonical_descriptor(
                result_path,
                local_request,
                distributed_request,
                source_root=source_root,
                artifact_root=artifact_root,
                evidence_root=evidence_root,
                local_config=local_config,
                distributed_config=distributed_config,
                policy=policy,
            )
        result = _execute(
            local_request,
            distributed_request,
            source_root=source_root,
            artifact_root=artifact_root,
            evidence_root=evidence_root,
            local_config=local_config,
            distributed_config=distributed_config,
            policy=policy,
            cancel_check=cancel_check,
        )
        publish_json(result_path, result, "BASE-04 result", root=evidence_root)
        return CanonicalDescriptorExecution(result, result_path)


def verify_canonical_descriptor(
    result_path: Path,
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    *,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    policy: SnapshotPolicy,
) -> CanonicalDescriptorExecution:
    """Re-evaluate current provider inputs and require exact immutable reconstruction."""

    _, expected, _ = _paths(evidence_root, local_request)
    if result_path != expected:
        raise ValueError("BASE-04 result path is not request-bound")
    payload = read_published_json(result_path, root=evidence_root, label="BASE-04 result")
    if not isinstance(payload, dict):
        raise ValueError("BASE-04 immutable result is not an object")
    _verify_internal(payload)
    reconstructed = _execute(
        local_request,
        distributed_request,
        source_root=source_root,
        artifact_root=artifact_root,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        policy=policy,
        cancel_check=None,
    )
    if reconstructed != payload:
        raise ValueError("BASE-04 current inputs do not reconstruct immutable evidence")
    return CanonicalDescriptorExecution(payload, result_path)


__all__ = [
    "CanonicalDescriptorExecution",
    "SnapshotPolicy",
    "run_canonical_descriptor",
    "verify_canonical_descriptor",
]
