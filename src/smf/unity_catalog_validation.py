"""Offline, default-deny Unity Catalog validation planning for DBPKG-01.

This module composes DBPKG-04 local Delta evidence with BASE-10 target mapping. It
does not implement a Delta writer or contact Databricks. Live validation remains
blocked until separately governed authentication, compute, and external-action
authority are supplied to a future online adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from smf.canonical_descriptor import SnapshotPolicy
from smf.distributed_sas_reader import DistributedReaderConfig, DistributedReaderRequest
from smf.immutable_files import publish_json, read_published_json
from smf.restartable_ingestion import (
    RestartableIngestionConfig,
    RestartableIngestionRequest,
    verify_restartable_ingestion,
)
from smf.sas_reader import ReaderConfig, ReaderRequest
from smf.security.ai_admission import contains_protected_data
from smf.semantic_mapping import DatasetMappingPolicy, SemanticMappingRequest
from smf.target_mapping import (
    ResolutionEvidence,
    SemanticEvidence,
    TargetMappingRequest,
    TargetPackagingPolicy,
    verify_target_mapping,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_REQUIRED_GRANTS = ("USE_CATALOG", "USE_SCHEMA", "SELECT", "MODIFY")


def _safe(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value) or contains_protected_data(value):
        raise ValueError(f"Unsafe DBPKG-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"DBPKG-01 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"DBPKG-01 {label} is not canonical RFC3339 UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"DBPKG-01 {label} is not canonical RFC3339 UTC")
    return parsed


@dataclass(frozen=True)
class UnityCatalogValidationRequest:
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    target_dataset_id: str
    evaluation_time: str
    target_mapping_content_digest: str
    ingestion_content_digest: str
    authentication_result_id: str
    authentication_content_digest: str
    compute_result_id: str
    compute_content_digest: str

    def binding(self) -> dict[str, Any]:
        for name in (
            "client_id",
            "deployment_id",
            "environment_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "target_dataset_id",
            "authentication_result_id",
            "compute_result_id",
        ):
            _safe(getattr(self, name), name)
        for name in (
            "target_mapping_content_digest",
            "ingestion_content_digest",
            "authentication_content_digest",
            "compute_content_digest",
        ):
            _sha(getattr(self, name), name)
        _time(self.evaluation_time, "evaluation_time")
        return asdict(self)


@dataclass(frozen=True)
class CurrentTargetMappingEvidence:
    result_path: Path
    request: TargetMappingRequest
    policy: TargetPackagingPolicy
    semantic: SemanticEvidence
    resolutions: tuple[ResolutionEvidence, ...]
    evidence_root: Path


@dataclass(frozen=True)
class CurrentIngestionEvidence:
    result_path: Path
    request: RestartableIngestionRequest
    local_request: ReaderRequest
    distributed_request: DistributedReaderRequest
    semantic_request: SemanticMappingRequest
    mapping_policy: DatasetMappingPolicy
    base04_result_path: Path
    base02_result_path: Path
    source_root: Path
    artifact_root: Path
    evidence_root: Path
    local_config: ReaderConfig
    distributed_config: DistributedReaderConfig
    snapshot_policy: SnapshotPolicy
    config: RestartableIngestionConfig = RestartableIngestionConfig()


@dataclass(frozen=True)
class UnityCatalogValidationPolicy:
    policy_id: str
    version: str
    issued_at: str
    valid_until: str
    catalog: str
    schema: str
    table: str
    credential_reference: str
    required_grants: tuple[str, ...] = _REQUIRED_GRANTS
    environment_class: str = "evaluation"
    live_validation_enabled: bool = False
    mutation_enabled: bool = False

    def binding(self) -> dict[str, Any]:
        _safe(self.policy_id, "policy_id")
        if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", self.version):
            raise ValueError("DBPKG-01 policy version is invalid")
        issued = _time(self.issued_at, "policy issued_at")
        expires = _time(self.valid_until, "policy valid_until")
        if issued >= expires:
            raise ValueError("DBPKG-01 policy interval is invalid")
        for name in ("catalog", "schema", "table"):
            if not _NAME.fullmatch(getattr(self, name)):
                raise ValueError(f"DBPKG-01 {name} is invalid")
        _safe(self.credential_reference, "credential_reference")
        if (
            self.required_grants != _REQUIRED_GRANTS
            or self.environment_class != "evaluation"
            or self.live_validation_enabled
            or self.mutation_enabled
        ):
            raise ValueError("DBPKG-01 policy widens the offline validation boundary")
        value = asdict(self)
        value["required_grants"] = list(self.required_grants)
        return value


def _schema() -> dict[str, Any]:
    value = json.loads(
        files("smf.schemas").joinpath("unity-catalog-validation-result.schema.json").read_text()
    )
    if not isinstance(value, dict):
        raise ValueError("DBPKG-01 packaged schema is invalid")
    return value


def _manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/unity_catalog_validation.py", files("smf").joinpath("unity_catalog_validation.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        ("smf/target_mapping.py", files("smf").joinpath("target_mapping.py")),
        ("smf/restartable_ingestion.py", files("smf").joinpath("restartable_ingestion.py")),
        (
            "smf/schemas/unity-catalog-validation-result.schema.json",
            files("smf.schemas").joinpath("unity-catalog-validation-result.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _load(path: Path, root: Path, label: str) -> dict[str, Any]:
    value = read_published_json(path, root=root, label=label)
    if not isinstance(value, dict):
        raise ValueError(f"DBPKG-01 {label} is not an object")
    return value


def evaluate_unity_catalog_validation(
    request: UnityCatalogValidationRequest,
    policy: UnityCatalogValidationPolicy,
    *,
    target_mapping_evidence: CurrentTargetMappingEvidence,
    ingestion_evidence: CurrentIngestionEvidence,
) -> dict[str, Any]:
    binding = request.binding()
    policy_binding = policy.binding()
    evaluated = _time(request.evaluation_time, "evaluation_time")
    if not (
        _time(policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(policy.valid_until, "policy valid_until")
    ):
        raise ValueError("DBPKG-01 policy is not current")
    if (
        target_mapping_evidence.request.evaluation_time != request.evaluation_time
        or ingestion_evidence.semantic_request.evaluation_time != request.evaluation_time
        or ingestion_evidence.snapshot_policy.evaluation_time != request.evaluation_time
    ):
        raise ValueError("DBPKG-01 upstream authority was not evaluated at the current time")
    if (
        _time(target_mapping_evidence.policy.valid_until, "target policy valid_until") <= evaluated
        or _time(ingestion_evidence.snapshot_policy.valid_until, "snapshot policy valid_until")
        <= evaluated
    ):
        raise ValueError("DBPKG-01 upstream authority is expired")
    target_mapping = verify_target_mapping(
        target_mapping_evidence.result_path,
        target_mapping_evidence.request,
        target_mapping_evidence.policy,
        target_mapping_evidence.semantic,
        target_mapping_evidence.resolutions,
        evidence_root=target_mapping_evidence.evidence_root,
    ).result
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
        config=ingestion_evidence.config,
    ).result
    if (
        target_mapping["content_digest"] != request.target_mapping_content_digest
        or ingestion["content_digest"] != request.ingestion_content_digest
    ):
        raise ValueError("DBPKG-01 upstream content drift")
    for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
        if (
            target_mapping["request"][field] != binding[field]
            or ingestion["request"][field] != binding[field]
        ):
            raise ValueError(f"DBPKG-01 upstream {field} mismatch")
    for field in ("deployment_id", "environment_id"):
        if target_mapping["request"][field] != binding[field]:
            raise ValueError(f"DBPKG-01 upstream {field} mismatch")
    targets = [
        item
        for item in target_mapping["targets"]
        if item["target_dataset_id"] == request.target_dataset_id
    ]
    if target_mapping["state"] != "qualified_offline_mapping" or len(targets) != 1:
        raise ValueError("DBPKG-01 target mapping is absent, ambiguous, or blocked")
    if (
        ingestion["state"] != "complete_local_delta"
        or ingestion["request"]["target_id"] != request.target_dataset_id
    ):
        raise ValueError("DBPKG-01 local Delta input is absent or incompatible")
    target = targets[0]
    resolved = target["resolved_namespace"]
    expected = (policy.catalog, policy.schema, policy.table)
    observed = (resolved["catalog"], resolved["schema"], resolved["table"])
    if observed != expected or resolved["environment_id"] != request.environment_id:
        raise ValueError("DBPKG-01 governed target differs from policy")
    qualified_name = ".".join(expected)
    if (
        resolved["qualified_name"] != qualified_name
        or resolved["environment_class"] != "evaluation"
    ):
        raise ValueError("DBPKG-01 target namespace is unauthorized")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "dbpkg-01.1.0",
        "result_id": "pending",
        "content_digest": "",
        "request": binding,
        "request_digest": digest_value(binding),
        "policy": policy_binding,
        "policy_digest": digest_value(policy_binding),
        "upstream": {
            "target_mapping_result_id": target_mapping["result_id"],
            "target_mapping_content_digest": target_mapping["content_digest"],
            "ingestion_result_id": ingestion["result_id"],
            "ingestion_content_digest": ingestion["content_digest"],
            "delta_manifest_digest": digest_value(ingestion["delta"]["manifest"]),
        },
        "provider": {
            "name": "databricks-sdk-online-adapter",
            "status": "not_invoked_not_qualified",
            "network_contacted": False,
        },
        "validation_plan": {
            "qualified_name": qualified_name,
            "credential_reference": policy.credential_reference,
            "required_grants": list(policy.required_grants),
            "read_operations": ["catalog_get", "schema_get", "table_get", "grants_get"],
            "write_operations": [],
            "rollback_operations": [],
            "external_requirements": [
                {
                    "kind": "dbx02_authentication_receipt",
                    "expected_id": request.authentication_result_id,
                    "expected_digest": request.authentication_content_digest,
                    "authority": "untrusted_expectation_only",
                },
                {
                    "kind": "dbx03_compute_admission",
                    "expected_id": request.compute_result_id,
                    "expected_digest": request.compute_content_digest,
                    "authority": "untrusted_expectation_only",
                },
                {
                    "kind": "unity_catalog_readback",
                    "expected_id": None,
                    "expected_digest": None,
                    "authority": "pending_external_authority",
                },
            ],
        },
        "state": "blocked_external_validation",
        "blockers": ["live_unity_catalog_authority_and_readback_required"],
        "implementation_manifest": _manifest(),
        "claims": {
            "live_databricks_contacted": False,
            "unity_catalog_validated": False,
            "grants_verified": False,
            "write_performed": False,
            "rollback_performed": False,
            "humana_ready": False,
            "production_ready": False,
            "semantic_parity": False,
            "migration_complete": False,
        },
    }
    payload["result_id"] = stable_id(
        "DBPKG01", {k: v for k, v in payload.items() if k not in {"result_id", "content_digest"}}
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    verify_unity_catalog_validation(payload)
    return payload


def verify_unity_catalog_validation(result: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(result), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError(
            "DBPKG-01 schema validation failed: " + "; ".join(item.message for item in errors)
        )
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("DBPKG-01 request digest mismatch")
    if result["policy_digest"] != digest_value(result["policy"]):
        raise ValueError("DBPKG-01 policy digest mismatch")
    decision = {k: v for k, v in result.items() if k not in {"result_id", "content_digest"}}
    if result["result_id"] != stable_id("DBPKG01", decision):
        raise ValueError("DBPKG-01 result identity mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("DBPKG-01 content digest mismatch")
    if result["implementation_manifest"] != _manifest() or any(result["claims"].values()):
        raise ValueError("DBPKG-01 implementation or claim boundary mismatch")


def publish_unity_catalog_validation(
    result: dict[str, Any],
    request: UnityCatalogValidationRequest,
    policy: UnityCatalogValidationPolicy,
    *,
    target_mapping_evidence: CurrentTargetMappingEvidence,
    ingestion_evidence: CurrentIngestionEvidence,
    output_root: Path,
) -> Path:
    replayed = evaluate_unity_catalog_validation(
        request,
        policy,
        target_mapping_evidence=target_mapping_evidence,
        ingestion_evidence=ingestion_evidence,
    )
    if replayed != result:
        raise ValueError("DBPKG-01 candidate differs from current governed inputs")
    verify_unity_catalog_validation(result)
    result_request = result["request"]
    run_id = _safe(result_request["run_id"], "run_id")
    workload_id = _safe(result_request["workload_id"], "workload_id")
    attempt_id = _safe(result_request["attempt_id"], "attempt_id")
    path = (
        output_root
        / "runs"
        / run_id
        / "workloads"
        / workload_id
        / "attempts"
        / attempt_id
        / "dbpkg01"
        / "result.json"
    )
    publish_json(path, result, "DBPKG-01 result", root=output_root)
    observed = _load(path, output_root, "DBPKG-01 result")
    verify_unity_catalog_validation(observed)
    if observed != result:
        raise ValueError("DBPKG-01 publication replay mismatch")
    return path


def verify_unity_catalog_validation_against_inputs(
    result_path: Path,
    request: UnityCatalogValidationRequest,
    policy: UnityCatalogValidationPolicy,
    *,
    target_mapping_evidence: CurrentTargetMappingEvidence,
    ingestion_evidence: CurrentIngestionEvidence,
    output_root: Path,
) -> dict[str, Any]:
    observed = _load(result_path, output_root, "DBPKG-01 result")
    verify_unity_catalog_validation(observed)
    expected = evaluate_unity_catalog_validation(
        request,
        policy,
        target_mapping_evidence=target_mapping_evidence,
        ingestion_evidence=ingestion_evidence,
    )
    if observed != expected:
        raise ValueError("DBPKG-01 evidence differs from current governed inputs")
    return observed
