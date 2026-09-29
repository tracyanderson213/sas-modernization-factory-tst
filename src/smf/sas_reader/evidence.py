"""Immutable publication and replay for bounded SAS reader results."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from smf.immutable_files import publish_json, read_published_json
from smf.sas_reader.provider import (
    PyreadstatProvider,
    ReaderConfig,
    ReaderExecution,
    ReaderRequest,
    read_sas7bdat,
)
from smf.upstream.crypto import digest_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe SAS reader evidence identity")
    return value


def reader_result_path(root: Path, request: ReaderRequest) -> Path:
    return (
        root
        / "runs"
        / _component(request.run_id)
        / "workloads"
        / _component(request.workload_id)
        / "attempts"
        / _component(request.attempt_id)
        / "sas-reader"
        / "result.json"
    )


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "request",
        "request_digest",
        "config",
        "config_digest",
        "runtime",
        "runtime_digest",
        "source",
        "state",
        "blockers",
        "diagnostic",
        "descriptor",
        "chunks",
        "claims",
        "content_digest",
    }
    if set(result) != required or result.get("schema_version") != "1.0":
        raise ValueError("SAS reader result contract is malformed")
    if result["state"] not in {"complete", "blocked", "unsupported", "failed"}:
        raise ValueError("SAS reader result state is invalid")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("SAS reader result content digest mismatch")
    if result["config_digest"] != digest_value(result["config"]):
        raise ValueError("SAS reader config digest mismatch")
    if result["runtime_digest"] != digest_value(result["runtime"]):
        raise ValueError("SAS reader runtime digest mismatch")
    if set(result["runtime"]) != {
        "provider",
        "provider_version",
        "provider_release_revision",
        "evaluated_upstream_revision",
        "provider_authority",
        "transitive_parser",
        "transitive_revision",
        "distribution_record_sha256",
        "runtime_dependencies",
        "python",
        "python_implementation",
        "platform",
        "byte_order",
    }:
        raise ValueError("SAS reader runtime projection is malformed")
    if set(result["request"]) != {
        "client_id",
        "workload_id",
        "source_id",
        "run_id",
        "attempt_id",
        "relative_path",
        "source_sha256",
        "source_byte_count",
    }:
        raise ValueError("SAS reader request projection is malformed")
    if set(result["config"]) != {
        "provider_distribution_digest",
        "chunk_rows",
        "max_source_bytes",
        "max_rows",
        "encoding",
    }:
        raise ValueError("SAS reader config projection is malformed")
    if set(result["source"]) != {"sha256", "byte_count", "snapshot_verified"}:
        raise ValueError("SAS reader source projection is malformed")
    if set(result["claims"]) != {
        "migration_complete",
        "semantic_parity",
        "humana_validated",
        "databricks_validated",
        "production_ready",
    }:
        raise ValueError("SAS reader claims projection is malformed")
    if any(result["claims"].values()):
        raise ValueError("SAS reader result asserts a prohibited lifecycle claim")
    offset = 0
    for index, chunk in enumerate(result["chunks"]):
        if set(chunk) != {"index", "row_offset", "row_count", "content_sha256"}:
            raise ValueError("SAS reader chunk evidence is malformed")
        if chunk["index"] != index or chunk["row_offset"] != offset or chunk["row_count"] <= 0:
            raise ValueError("SAS reader chunk ordering is invalid")
        if not isinstance(chunk["content_sha256"], str) or len(chunk["content_sha256"]) != 64:
            raise ValueError("SAS reader chunk digest is invalid")
        offset += chunk["row_count"]
    if result["state"] == "complete":
        if result["blockers"] or result["descriptor"] is None:
            raise ValueError("Complete SAS reader result is internally inconsistent")
        descriptor = result["descriptor"]
        if set(descriptor) != {
            "file_format",
            "file_encoding",
            "table_name",
            "file_label",
            "declared_row_count",
            "observed_row_count",
            "declared_column_count",
            "observed_column_count",
            "declared_keys",
            "key_authority",
            "creation_time",
            "modification_time",
            "columns",
        }:
            raise ValueError("SAS reader descriptor is malformed")
        if descriptor["observed_row_count"] != offset:
            raise ValueError("SAS reader descriptor and chunk row counts conflict")
        names: set[str] = set()
        for position, column in enumerate(descriptor["columns"]):
            if set(column) != {"position", "name", "declared", "observed"}:
                raise ValueError("SAS reader column descriptor is malformed")
            if column["position"] != position or column["name"] in names:
                raise ValueError("SAS reader column order or identity is invalid")
            names.add(column["name"])
            if set(column["declared"]) != {
                "label",
                "format",
                "informat",
                "value_label_set",
                "storage_width",
                "nullable",
                "unit",
                "key",
            } or set(column["observed"]) != {
                "readstat_type",
                "normalized_type",
                "null_count",
                "nullable",
            }:
                raise ValueError("SAS reader declared/observed column contract is malformed")
        if descriptor["observed_column_count"] != len(names):
            raise ValueError("SAS reader observed column count is inconsistent")
    elif not result["blockers"] or result["descriptor"] is not None or result["chunks"]:
        raise ValueError("Non-complete SAS reader result is internally inconsistent")


def publish_reader_result(
    evidence_root: Path,
    request: ReaderRequest,
    execution: ReaderExecution,
    *,
    authorized_root: Path,
    config: ReaderConfig,
    provider: PyreadstatProvider | None = None,
) -> Path:
    """Reconstruct and atomically publish one result without persisting source rows."""

    _verify_internal(execution.result)
    if execution.result["runtime"]["provider_authority"] != "qualified_installed_module":
        raise ValueError("Synthetic SAS reader evidence cannot be published")
    if execution.result["request_digest"] != digest_value(request.binding()):
        raise ValueError("SAS reader result is not bound to the publication request")
    reconstructed = read_sas7bdat(
        request,
        authorized_root=authorized_root,
        config=config,
        provider=provider,
    )
    if reconstructed != execution:
        raise ValueError(
            "SAS reader publication candidate does not reconstruct from current inputs"
        )
    path = reader_result_path(evidence_root, request)
    publish_json(path, execution.result, "SAS reader result", root=evidence_root)
    return path


def verify_reader_result(
    path: Path,
    *,
    evidence_root: Path,
    request: ReaderRequest,
    authorized_root: Path,
    config: ReaderConfig,
    provider: PyreadstatProvider | None = None,
) -> ReaderExecution:
    """Re-read source/provider/config and require exact reconstruction of immutable evidence."""

    if path != reader_result_path(evidence_root, request):
        raise ValueError("SAS reader evidence path is not bound to the request")
    payload = read_published_json(path, root=evidence_root, label="SAS reader result")
    if not isinstance(payload, dict):
        raise ValueError("SAS reader evidence is not an object")
    _verify_internal(payload)
    if payload["runtime"]["provider_authority"] != "qualified_installed_module":
        raise ValueError("Synthetic SAS reader evidence cannot be verified as operational")
    if payload["request_digest"] != digest_value(request.binding()):
        raise ValueError("SAS reader replay request binding mismatch")
    replay = read_sas7bdat(
        request,
        authorized_root=authorized_root,
        config=config,
        provider=provider,
    )
    if replay.result != payload:
        raise ValueError("SAS reader replay does not reconstruct the immutable result")
    return replay
