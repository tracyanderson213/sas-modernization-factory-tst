"""SCHEMA-INT-01 integration of governed descriptors with the DP-01 comparator.

This module proves only that the existing structural comparator consumes the current
BASE-04 source descriptor and BASE-02 published target descriptor in a chain that is
bound to the current DBPKG-01/DBPKG-04 evidence.  It does not claim live Unity Catalog
read-back, row parity, SAS semantic parity, or migration completion.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from smf.canonical_descriptor import verify_canonical_descriptor
from smf.immutable_files import (
    ensure_directory,
    open_lock_file,
    publish_json,
    published_file_exists,
    read_published_json,
)
from smf.restartable_ingestion import verify_restartable_ingestion
from smf.security.ai_admission import contains_protected_data
from smf.semantic_mapping import verify_semantic_mapping
from smf.unity_catalog_validation import (
    CurrentIngestionEvidence,
    CurrentTargetMappingEvidence,
    UnityCatalogValidationPolicy,
    UnityCatalogValidationRequest,
    verify_unity_catalog_validation_against_inputs,
)
from smf.upstream.crypto import digest_value
from smf.validation.structural import (
    DatasetSchemaSnapshot,
    EvidenceProvenance,
    SchemaColumn,
    StructuralParityPolicy,
    calculate_snapshot_digest,
    compare_snapshots,
    validate_snapshot_payload,
    validate_structural_result_payload,
)
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_PHYSICAL_TYPES: dict[str, tuple[str, str]] = {
    "string": ("string", "string"),
    "double": ("float", "double"),
    "long": ("bigint", "bigint"),
    "boolean": ("boolean", "boolean"),
}


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe SCHEMA-INT-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"SCHEMA-INT-01 {label} is not a SHA-256 digest")
    return value


@dataclass(frozen=True)
class SchemaIntegrationRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    logical_dataset_id: str
    source_dataset_id: str
    target_dataset_id: str
    base04_result_id: str
    base04_content_digest: str
    base02_result_id: str
    base02_content_digest: str
    dbpkg01_result_id: str
    dbpkg01_content_digest: str

    def binding(self) -> dict[str, str]:
        for name in (
            "client_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "logical_dataset_id",
            "source_dataset_id",
            "target_dataset_id",
            "base04_result_id",
            "base02_result_id",
            "dbpkg01_result_id",
        ):
            _safe(getattr(self, name), name)
        for name in (
            "base04_content_digest",
            "base02_content_digest",
            "dbpkg01_content_digest",
        ):
            _sha(getattr(self, name), name)
        return cast(dict[str, str], asdict(self))


@dataclass(frozen=True)
class CurrentSchemaIntegrationEvidence:
    dbpkg01_result_path: Path
    dbpkg01_output_root: Path
    dbpkg01_request: UnityCatalogValidationRequest
    dbpkg01_policy: UnityCatalogValidationPolicy
    target_mapping: CurrentTargetMappingEvidence
    ingestion: CurrentIngestionEvidence


@dataclass(frozen=True)
class SchemaIntegrationExecution:
    result: dict[str, Any]
    result_path: Path


def _schema() -> dict[str, Any]:
    payload = json.loads(
        files("smf.schemas").joinpath("schema-integration-result.schema.json").read_text()
    )
    if not isinstance(payload, dict):
        raise TypeError("SCHEMA-INT-01 result schema must be an object")
    return cast(dict[str, Any], payload)


def _paths(root: Path, request: SchemaIntegrationRequest) -> tuple[Path, Path]:
    request.binding()
    parent = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "schema-int-01"
    )
    return parent / "result.json", parent / ".lock"


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/schema_integration.py", files("smf").joinpath("schema_integration.py")),
        (
            "smf/validation/structural.py",
            files("smf.validation").joinpath("structural.py"),
        ),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/schema-integration-result.schema.json",
            files("smf.schemas").joinpath("schema-integration-result.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _column(
    *, ordinal: int, name: str, physical_type: str, nullable: bool, width: int | None
) -> SchemaColumn:
    try:
        logical, native = _PHYSICAL_TYPES[physical_type]
    except KeyError as exc:
        raise ValueError(
            f"SCHEMA-INT-01 unsupported canonical physical type: {physical_type}"
        ) from exc
    return SchemaColumn(
        ordinal=ordinal,
        name=name,
        logical_type=logical,
        native_type=native,
        nullable=nullable,
        length=width if physical_type == "string" else None,
    )


def _snapshot(
    *,
    logical_dataset_id: str,
    engine: str,
    producer: str,
    reference: str,
    columns: tuple[SchemaColumn, ...],
    metadata: dict[str, str | int | float | bool | None],
) -> DatasetSchemaSnapshot:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "logical_dataset_id": logical_dataset_id,
        "engine": engine,
        "columns": [asdict(column) for column in columns],
        "provenance": asdict(
            EvidenceProvenance(
                producer=producer,
                origin="immutable-governed-evidence",
                reference=reference,
                authoritative=True,
            )
        ),
        "metadata": metadata,
    }
    payload["digest"] = calculate_snapshot_digest(payload)
    return DatasetSchemaSnapshot.from_dict(payload)


def _evaluate(
    request: SchemaIntegrationRequest,
    *,
    base04: dict[str, Any],
    base02: dict[str, Any],
    ingestion: dict[str, Any],
    dbpkg01: dict[str, Any],
) -> dict[str, Any]:
    binding = request.binding()
    identities = (base04["identity"], base02["request"], ingestion["request"], dbpkg01["request"])
    for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
        if any(identity[field] != binding[field] for identity in identities):
            raise ValueError(f"SCHEMA-INT-01 upstream {field} mismatch")
    expected = {
        "base04_result_id": base04["result_id"],
        "base04_content_digest": base04["content_digest"],
        "base02_result_id": base02["result_id"],
        "base02_content_digest": base02["content_digest"],
        "dbpkg01_result_id": dbpkg01["result_id"],
        "dbpkg01_content_digest": dbpkg01["content_digest"],
    }
    if any(binding[name] != value for name, value in expected.items()):
        raise ValueError("SCHEMA-INT-01 upstream evidence identity or content drift")
    if base02["request"]["source_dataset_id"] != request.source_dataset_id:
        raise ValueError("SCHEMA-INT-01 source dataset identity mismatch")
    targets = [
        item for item in base02["targets"] if item["target_dataset_id"] == request.target_dataset_id
    ]
    if base02["state"] != "qualified_underlying_mapping" or len(targets) != 1:
        raise ValueError("SCHEMA-INT-01 published target descriptor is absent or ambiguous")
    if (
        ingestion["state"] != "complete_local_delta"
        or not ingestion["reconciliation"]["passed"]
        or ingestion["request"]["target_id"] != request.target_dataset_id
    ):
        raise ValueError("SCHEMA-INT-01 target ingestion evidence is incomplete or incompatible")
    if dbpkg01["request"]["target_dataset_id"] != request.target_dataset_id:
        raise ValueError("SCHEMA-INT-01 DBPKG-01 target identity mismatch")

    source_descriptor = base04["canonical_descriptor"]
    source_columns = tuple(
        _column(
            ordinal=item["position"] + 1,
            name=item["name"],
            physical_type=item["canonical_physical_type"],
            nullable=item["nullable_observed"],
            width=item["declared_sas_metadata"]["storage_width"],
        )
        for item in source_descriptor["columns"]
    )
    source_by_identity = {
        (item["position"], item["name"]): item for item in source_descriptor["columns"]
    }
    target = targets[0]
    ordered_target = sorted(target["columns"], key=lambda item: item["source_position"])
    target_columns: list[SchemaColumn] = []
    for item in ordered_target:
        source = source_by_identity.get((item["source_position"], item["source_name"]))
        if source is None or not item["underlying_value_authority"]:
            raise ValueError("SCHEMA-INT-01 target column lacks authoritative source binding")
        target_columns.append(
            _column(
                ordinal=item["source_position"] + 1,
                name=item["target_name"],
                physical_type=item["target_physical_type"],
                nullable=source["nullable_observed"],
                width=item["expected_storage_width"],
            )
        )

    source_snapshot = _snapshot(
        logical_dataset_id=request.logical_dataset_id,
        engine="base04-cross-provider",
        producer="BASE-04",
        reference=f"smf://BASE-04/{base04['result_id']}",
        columns=source_columns,
        metadata={
            "source_dataset_id": request.source_dataset_id,
            "descriptor_digest": base04["descriptor_digest"],
            "content_digest": base04["content_digest"],
        },
    )
    target_snapshot = _snapshot(
        logical_dataset_id=request.logical_dataset_id,
        engine="base02-governed-target-plan",
        producer="BASE-02+DBPKG-01",
        reference=f"smf://DBPKG-01/{dbpkg01['result_id']}/governed-plan",
        columns=tuple(target_columns),
        metadata={
            "target_dataset_id": request.target_dataset_id,
            "target_descriptor_digest": target["target_descriptor_digest"],
            "dbpkg04_result_id": ingestion["result_id"],
            "dbpkg01_content_digest": dbpkg01["content_digest"],
            "evidence_class": "governed_plan_bound_to_reconciled_local_delta",
            "physical_target_schema_observed": False,
        },
    )
    comparison = compare_snapshots(source_snapshot, target_snapshot, StructuralParityPolicy())
    nonpassing = [check.code for check in comparison.checks if check.status != "pass"]
    state = {
        "passed": "passed_governed_descriptor_integration",
        "failed": "failed_descriptor_comparison",
        "blocked": "blocked_descriptor_comparison",
    }[comparison.status]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "schema-int-01.1.0",
        "result_id": "",
        "content_digest": "",
        "request": binding,
        "request_digest": digest_value(binding),
        "upstream": {
            **expected,
            "base04_descriptor_digest": base04["descriptor_digest"],
            "base02_target_descriptor_digest": target["target_descriptor_digest"],
            "dbpkg04_result_id": ingestion["result_id"],
            "dbpkg04_content_digest": ingestion["content_digest"],
        },
        "source_snapshot": source_snapshot.to_dict(),
        "target_snapshot": target_snapshot.to_dict(),
        "comparison": comparison.to_dict(),
        "evidence_boundary": {
            "source_descriptor_class": "observed_cross_provider_physical",
            "target_descriptor_class": "governed_plan_bound_to_reconciled_local_delta",
            "target_physical_schema_observed": False,
        },
        "state": state,
        "blockers": sorted(set(nonpassing)),
        "implementation_manifest": _implementation_manifest(),
        "claims": {
            "live_databricks_contacted": False,
            "unity_catalog_readback_validated": False,
            "row_or_cell_parity": False,
            "sas_semantic_parity": False,
            "humana_validated": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    payload["result_id"] = stable_id(
        "SCHEMAINT01",
        {
            key: value
            for key, value in payload.items()
            if key not in {"result_id", "content_digest"}
        },
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    verify_schema_integration_result(payload)
    return payload


def _replay_current(
    request: SchemaIntegrationRequest, evidence: CurrentSchemaIntegrationEvidence
) -> dict[str, Any]:
    ingestion_evidence = evidence.ingestion
    dbpkg01 = verify_unity_catalog_validation_against_inputs(
        evidence.dbpkg01_result_path,
        evidence.dbpkg01_request,
        evidence.dbpkg01_policy,
        target_mapping_evidence=evidence.target_mapping,
        ingestion_evidence=ingestion_evidence,
        output_root=evidence.dbpkg01_output_root,
    )
    ingestion = verify_restartable_ingestion(
        ingestion_evidence.result_path,
        request=ingestion_evidence.request,
        local_request=ingestion_evidence.local_request,
        distributed_request=ingestion_evidence.distributed_request,
        semantic_request=ingestion_evidence.semantic_request,
        mapping_policy=ingestion_evidence.mapping_policy,
        base04_result_path=ingestion_evidence.base04_result_path,
        base02_result_path=ingestion_evidence.base02_result_path,
        source_root=ingestion_evidence.source_root,
        artifact_root=ingestion_evidence.artifact_root,
        evidence_root=ingestion_evidence.evidence_root,
        local_config=ingestion_evidence.local_config,
        distributed_config=ingestion_evidence.distributed_config,
        snapshot_policy=ingestion_evidence.snapshot_policy,
    ).result
    base02 = verify_semantic_mapping(
        ingestion_evidence.base02_result_path,
        ingestion_evidence.semantic_request,
        ingestion_evidence.mapping_policy,
        base04_result_path=ingestion_evidence.base04_result_path,
        local_request=ingestion_evidence.local_request,
        distributed_request=ingestion_evidence.distributed_request,
        source_root=ingestion_evidence.source_root,
        artifact_root=ingestion_evidence.artifact_root,
        evidence_root=ingestion_evidence.evidence_root,
        local_config=ingestion_evidence.local_config,
        distributed_config=ingestion_evidence.distributed_config,
        snapshot_policy=ingestion_evidence.snapshot_policy,
    ).result
    base04 = verify_canonical_descriptor(
        ingestion_evidence.base04_result_path,
        ingestion_evidence.local_request,
        ingestion_evidence.distributed_request,
        source_root=ingestion_evidence.source_root,
        artifact_root=ingestion_evidence.artifact_root,
        evidence_root=ingestion_evidence.evidence_root,
        local_config=ingestion_evidence.local_config,
        distributed_config=ingestion_evidence.distributed_config,
        policy=ingestion_evidence.snapshot_policy,
    ).result
    return _evaluate(request, base04=base04, base02=base02, ingestion=ingestion, dbpkg01=dbpkg01)


def verify_schema_integration_result(result: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(result), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError(
            "SCHEMA-INT-01 schema validation failed: "
            + "; ".join(error.message for error in errors)
        )
    validate_snapshot_payload(result["source_snapshot"])
    validate_snapshot_payload(result["target_snapshot"])
    validate_structural_result_payload(result["comparison"])
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("SCHEMA-INT-01 request digest mismatch")
    decision = {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }
    if result["result_id"] != stable_id("SCHEMAINT01", decision):
        raise ValueError("SCHEMA-INT-01 result identity mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("SCHEMA-INT-01 content digest mismatch")
    expected_state = {
        "passed": "passed_governed_descriptor_integration",
        "failed": "failed_descriptor_comparison",
        "blocked": "blocked_descriptor_comparison",
    }[result["comparison"]["status"]]
    expected_blockers = sorted(
        {item["code"] for item in result["comparison"]["checks"] if item["status"] != "pass"}
    )
    if result["state"] != expected_state or result["blockers"] != expected_blockers:
        raise ValueError("SCHEMA-INT-01 comparison disposition mismatch")
    if result["evidence_boundary"] != {
        "source_descriptor_class": "observed_cross_provider_physical",
        "target_descriptor_class": "governed_plan_bound_to_reconciled_local_delta",
        "target_physical_schema_observed": False,
    }:
        raise ValueError("SCHEMA-INT-01 evidence boundary mismatch")
    source_snapshot = result["source_snapshot"]
    target_snapshot = result["target_snapshot"]
    if (
        source_snapshot["engine"] != "base04-cross-provider"
        or source_snapshot["provenance"]
        != {
            "producer": "BASE-04",
            "origin": "immutable-governed-evidence",
            "reference": source_snapshot["provenance"]["reference"],
            "authoritative": True,
        }
        or not source_snapshot["provenance"]["reference"].startswith("smf://BASE-04/")
    ):
        raise ValueError("SCHEMA-INT-01 source evidence class mismatch")
    if (
        target_snapshot["engine"] != "base02-governed-target-plan"
        or target_snapshot["provenance"]
        != {
            "producer": "BASE-02+DBPKG-01",
            "origin": "immutable-governed-evidence",
            "reference": target_snapshot["provenance"]["reference"],
            "authoritative": True,
        }
        or not target_snapshot["provenance"]["reference"].endswith("/governed-plan")
        or target_snapshot["metadata"].get("evidence_class")
        != "governed_plan_bound_to_reconciled_local_delta"
        or target_snapshot["metadata"].get("physical_target_schema_observed") is not False
    ):
        raise ValueError("SCHEMA-INT-01 target evidence class mismatch")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("SCHEMA-INT-01 implementation manifest mismatch")
    if any(result["claims"].values()):
        raise ValueError("SCHEMA-INT-01 asserts a prohibited claim")


def run_schema_integration(
    request: SchemaIntegrationRequest,
    evidence: CurrentSchemaIntegrationEvidence,
    *,
    output_root: Path,
) -> SchemaIntegrationExecution:
    result_path, lock_path = _paths(output_root, request)
    ensure_directory(result_path.parent, root=output_root)
    with open_lock_file(lock_path, root=output_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=output_root, label="SCHEMA-INT-01 result"):
            return verify_schema_integration(
                result_path, request, evidence, output_root=output_root
            )
        result = _replay_current(request, evidence)
        publish_json(result_path, result, "SCHEMA-INT-01 result", root=output_root)
        return SchemaIntegrationExecution(result, result_path)


def verify_schema_integration(
    result_path: Path,
    request: SchemaIntegrationRequest,
    evidence: CurrentSchemaIntegrationEvidence,
    *,
    output_root: Path,
) -> SchemaIntegrationExecution:
    expected, _ = _paths(output_root, request)
    if result_path != expected:
        raise ValueError("SCHEMA-INT-01 result path is not request-bound")
    observed = read_published_json(result_path, root=output_root, label="SCHEMA-INT-01 result")
    if not isinstance(observed, dict):
        raise ValueError("SCHEMA-INT-01 immutable result is not an object")
    verify_schema_integration_result(observed)
    replayed = _replay_current(request, evidence)
    if observed != replayed:
        raise ValueError("SCHEMA-INT-01 evidence differs from current governed inputs")
    return SchemaIntegrationExecution(observed, result_path)


__all__ = [
    "CurrentSchemaIntegrationEvidence",
    "SchemaIntegrationExecution",
    "SchemaIntegrationRequest",
    "run_schema_integration",
    "verify_schema_integration",
    "verify_schema_integration_result",
]
