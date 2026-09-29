"""Governed, offline mapping of qualified logical outputs to Delta target metadata.

BASE-10 composes the current BASE-02 semantic decision with current BASE-03 namespace
resolution.  It never contacts or mutates Databricks or Unity Catalog.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from smf.canonical_descriptor import SnapshotPolicy
from smf.distributed_sas_reader import DistributedReaderConfig, DistributedReaderRequest
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
from smf.target_resolution import (
    TargetResolutionRequest,
    evaluate_target_resolution,
    verify_target_resolution,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_RESULT_NAME = "target-mapping.result.json"


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError(f"BASE-10 {label} must use canonical UTC RFC3339")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"BASE-10 {label} must use canonical UTC RFC3339")
    return parsed


def _safe_id(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
    ):
        raise ValueError(f"Unsafe BASE-10 {label}")
    return value


@dataclass(frozen=True)
class TargetMappingRequest:
    client_id: str
    deployment_id: str
    environment_id: str
    environment_class: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    artifact_id: str
    evaluation_time: str

    def binding(self) -> dict[str, Any]:
        for field in (
            "client_id",
            "deployment_id",
            "environment_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "artifact_id",
        ):
            _safe_id(getattr(self, field), field)
        if self.environment_class not in {"evaluation", "production"}:
            raise ValueError("BASE-10 environment_class is invalid")
        _time(self.evaluation_time, "evaluation_time")
        return asdict(self)


@dataclass(frozen=True)
class TargetPolicyBinding:
    target_dataset_id: str
    logical_dataset: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetPolicyBinding:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("BASE-10 target policy binding has unknown or missing fields")
        result = cls(**value)
        result.validate()
        return result

    def validate(self) -> None:
        _safe_id(self.target_dataset_id, "target_dataset_id")
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,127}",
            self.logical_dataset,
        ):
            raise ValueError("BASE-10 logical dataset binding is invalid")

    def to_dict(self) -> dict[str, str]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class TargetPackagingPolicy:
    policy_id: str
    version: str
    authority_scope: str
    issued_at: str
    valid_until: str
    table_format: str
    storage_mode: str
    storage_disposition: str
    schema_evolution_policy: str
    overwrite_policy: str
    collision_policy: str
    production_namespace_policy: str
    target_bindings: tuple[TargetPolicyBinding, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetPackagingPolicy:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("BASE-10 packaging policy has unknown or missing fields")
        if not isinstance(value["target_bindings"], list):
            raise ValueError("BASE-10 target policy bindings are malformed")
        normalized = dict(value)
        normalized["target_bindings"] = tuple(
            TargetPolicyBinding.from_dict(item) for item in value["target_bindings"]
        )
        result = cls(**normalized)
        result.validate()
        return result

    def validate(self) -> None:
        _safe_id(self.policy_id, "policy_id")
        if not _VERSION.fullmatch(self.version):
            raise ValueError("BASE-10 policy version is invalid")
        issued = _time(self.issued_at, "policy issued_at")
        expires = _time(self.valid_until, "policy valid_until")
        if expires <= issued:
            raise ValueError("BASE-10 policy validity interval is invalid")
        expected = {
            "authority_scope": "offline-evaluation-contract",
            "table_format": "delta",
            "storage_mode": "managed",
            "storage_disposition": "environment_resolved_location_not_accessed",
            "schema_evolution_policy": "deny_implicit_evolution",
            "overwrite_policy": "deny",
            "collision_policy": "reject_casefold_qualified_name",
            "production_namespace_policy": "deny_without_external_authority",
        }
        if any(getattr(self, key) != expected_value for key, expected_value in expected.items()):
            raise ValueError("BASE-10 policy widens the bounded offline contract")
        if not self.target_bindings:
            raise ValueError("BASE-10 policy has no explicit target binding")
        target_ids = [item.target_dataset_id.casefold() for item in self.target_bindings]
        logical = [item.logical_dataset.casefold() for item in self.target_bindings]
        if len(set(target_ids)) != len(target_ids) or len(set(logical)) != len(logical):
            raise ValueError("BASE-10 policy target binding is ambiguous")
        for item in self.target_bindings:
            item.validate()

    @property
    def digest(self) -> str:
        return digest_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["target_bindings"] = [item.to_dict() for item in self.target_bindings]
        return value


@dataclass(frozen=True)
class SemanticEvidence:
    result_path: Path
    request: SemanticMappingRequest
    policy: DatasetMappingPolicy
    base04_result_path: Path
    local_request: ReaderRequest
    distributed_request: DistributedReaderRequest
    source_root: Path
    artifact_root: Path
    evidence_root: Path
    local_config: ReaderConfig
    distributed_config: DistributedReaderConfig
    snapshot_policy: SnapshotPolicy


@dataclass(frozen=True)
class ResolutionEvidence:
    target_dataset_id: str
    result_path: Path
    request: TargetResolutionRequest


@dataclass(frozen=True)
class TargetMappingExecution:
    result: dict[str, Any]
    result_path: Path


def _schema() -> dict[str, Any]:
    payload = json.loads(
        files("smf.schemas").joinpath("target-mapping-result.schema.json").read_text()
    )
    if not isinstance(payload, dict):
        raise ValueError("Packaged BASE-10 result schema is invalid")
    return payload


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/target_mapping.py", files("smf").joinpath("target_mapping.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        (
            "smf/schemas/target-mapping-result.schema.json",
            files("smf.schemas").joinpath("target-mapping-result.schema.json"),
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def _paths(root: Path, request: TargetMappingRequest) -> tuple[Path, Path]:
    request.binding()
    directory = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "base10"
    )
    return directory / _RESULT_NAME, directory / "execution.lock"


def _current_resolution(
    evidence: ResolutionEvidence, evaluation_time: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    _safe_id(evidence.target_dataset_id, "target_dataset_id")
    replayed = evaluate_target_resolution(evidence.request).result
    expected = evidence.request.output_root / replayed["canonical_evidence_reference"]
    if evidence.result_path != expected:
        raise ValueError("BASE-10 target-resolution path is not request-bound")
    payload = read_published_json(
        evidence.result_path,
        root=evidence.request.output_root,
        label="BASE-03 result",
    )
    if not isinstance(payload, dict):
        raise ValueError("BASE-10 target-resolution evidence is not an object")
    verify_target_resolution(payload)
    if payload != replayed:
        raise ValueError("BASE-10 target resolution does not match current governed inputs")
    current = evaluate_target_resolution(
        replace(evidence.request, evaluation_time=evaluation_time)
    ).result
    return current, payload


def _current_semantic(
    evidence: SemanticEvidence, evaluation_time: str
) -> tuple[dict[str, Any], bool]:
    result = verify_semantic_mapping(
        evidence.result_path,
        evidence.request,
        evidence.policy,
        base04_result_path=evidence.base04_result_path,
        local_request=evidence.local_request,
        distributed_request=evidence.distributed_request,
        source_root=evidence.source_root,
        artifact_root=evidence.artifact_root,
        evidence_root=evidence.evidence_root,
        local_config=evidence.local_config,
        distributed_config=evidence.distributed_config,
        snapshot_policy=evidence.snapshot_policy,
    ).result
    evaluated = _time(evaluation_time, "evaluation_time")
    snapshot_current = (
        _time(evidence.snapshot_policy.acquisition_time, "snapshot acquisition_time")
        <= evaluated
        < _time(evidence.snapshot_policy.valid_until, "snapshot valid_until")
    )
    return result, snapshot_current


def _evaluate_target_mapping(
    request: TargetMappingRequest,
    policy: TargetPackagingPolicy,
    semantic_result: dict[str, Any],
    resolution_results: dict[str, dict[str, Any]],
    *,
    published_resolution_results: dict[str, dict[str, Any]] | None = None,
    semantic_snapshot_current: bool = True,
) -> dict[str, Any]:
    """Compose already verified upstream results into a bounded BASE-10 decision."""

    binding = request.binding()
    policy.validate()
    evaluated = _time(request.evaluation_time, "evaluation_time")
    blockers: list[str] = []
    if not (
        _time(policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(policy.valid_until, "policy valid_until")
    ):
        blockers.append("target_packaging_policy_not_current")
    semantic_policy = semantic_result["policy"]
    if not (
        _time(semantic_policy["issued_at"], "semantic policy issued_at")
        <= evaluated
        < _time(semantic_policy["valid_until"], "semantic policy valid_until")
    ):
        blockers.append("semantic_mapping_authority_not_current")
    if not semantic_snapshot_current:
        blockers.append("semantic_snapshot_not_current")
    for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id"):
        if semantic_result["request"][field] != binding[field]:
            raise ValueError(f"BASE-10 semantic {field} identity mismatch")
    if semantic_result["state"] != "qualified_underlying_mapping":
        blockers.append("semantic_mapping_not_qualified")

    semantic_targets = {item["target_dataset_id"]: item for item in semantic_result["targets"]}
    if len(semantic_targets) != len(semantic_result["targets"]):
        raise ValueError("BASE-10 semantic targets are ambiguous")
    if set(resolution_results) != set(semantic_targets):
        raise ValueError("BASE-10 resolution inventory does not exactly match semantic targets")
    policy_bindings = {item.target_dataset_id: item for item in policy.target_bindings}
    if set(policy_bindings) != set(semantic_targets):
        raise ValueError("BASE-10 policy binding inventory does not exactly match semantic targets")
    published = published_resolution_results or resolution_results
    if set(published) != set(semantic_targets):
        raise ValueError("BASE-10 published resolution inventory is incomplete")

    targets: list[dict[str, Any]] = []
    resolution_authorities: list[dict[str, Any]] = []
    qualified_names: set[str] = set()
    for target_id in sorted(semantic_targets):
        semantic_target = semantic_targets[target_id]
        resolution_result = resolution_results[target_id]
        identity = resolution_result["identity"]
        for field in (
            "client_id",
            "deployment_id",
            "environment_id",
            "environment_class",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "artifact_id",
            "evaluation_time",
        ):
            if identity[field] != binding[field]:
                raise ValueError(f"BASE-10 target-resolution {field} identity mismatch")
        resolution_authorities.append(
            {
                "target_dataset_id": target_id,
                "current_result_id": resolution_result["result_id"],
                "current_content_digest": resolution_result["content_digest"],
                "current_status": resolution_result["status"],
                "published_result_id": published[target_id]["result_id"],
                "published_content_digest": published[target_id]["content_digest"],
                "evidence_reference": published[target_id]["canonical_evidence_reference"],
            }
        )
        if semantic_result["state"] != "qualified_underlying_mapping":
            continue
        resolution = resolution_result["resolution"]
        if resolution_result["status"] != "resolved" or resolution is None:
            blockers.append(f"target_resolution_blocked:{target_id}")
            continue
        if resolution["logical_dataset"] != policy_bindings[target_id].logical_dataset:
            blockers.append(f"logical_dataset_binding_mismatch:{target_id}")
        if identity["access_mode"] != "write":
            blockers.append(f"target_write_access_not_resolved:{target_id}")
        if resolution["environment_class"] == "production":
            blockers.append(f"production_namespace_requires_external_authority:{target_id}")
        folded = resolution["qualified_name"].casefold()
        if folded in qualified_names:
            blockers.append(f"qualified_target_collision:{target_id}")
            continue
        qualified_names.add(folded)
        targets.append(
            {
                "target_dataset_id": target_id,
                "target_dataset_version": semantic_target["target_dataset_version"],
                "logical_namespace": semantic_target["target_namespace"],
                "resolved_namespace": resolution,
                "table_format": policy.table_format,
                "storage_mode": policy.storage_mode,
                "storage_disposition": policy.storage_disposition,
                "schema_evolution_policy": policy.schema_evolution_policy,
                "overwrite_policy": policy.overwrite_policy,
                "columns": semantic_target["columns"],
                "schema_digest": semantic_target["target_descriptor_digest"],
                "transformation_id": semantic_target["transformation_id"],
                "transformation_version": semantic_target["transformation_version"],
                "semantic_result_id": semantic_result["result_id"],
                "semantic_content_digest": semantic_result["content_digest"],
                "resolution_result_id": resolution_result["result_id"],
                "resolution_content_digest": resolution_result["content_digest"],
                "published_resolution_result_id": published[target_id]["result_id"],
                "published_resolution_content_digest": published[target_id]["content_digest"],
                "resolution_evidence_reference": published[target_id][
                    "canonical_evidence_reference"
                ],
                "target_state": "planned_not_executed",
            }
        )

    state = "qualified_offline_mapping" if not blockers else "blocked"
    manifest = _implementation_manifest()
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "base-10.1.0",
        "result_id": "pending",
        "content_digest": "",
        "request": binding,
        "request_digest": digest_value(binding),
        "policy": policy.to_dict(),
        "policy_digest": policy.digest,
        "semantic_authority": {
            "result_id": semantic_result["result_id"],
            "content_digest": semantic_result["content_digest"],
            "policy_digest": semantic_result["policy_digest"],
            "state": semantic_result["state"],
        },
        "resolution_authorities": resolution_authorities,
        "state": state,
        "blockers": sorted(set(blockers)),
        "targets": targets,
        "implementation_manifest": manifest,
        "claims": {
            "live_catalog_contacted": False,
            "target_exists": False,
            "access_authorized": False,
            "write_performed": False,
            "schema_applied": False,
            "databricks_validated": False,
            "humana_ready": False,
            "production_ready": False,
            "migration_complete": False,
            "semantic_parity": False,
        },
    }
    payload["result_id"] = stable_id("BASE10", _decision(payload))
    payload["content_digest"] = digest_value(_without_digest(payload))
    _verify_internal(payload)
    return payload


def _decision(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }


def _without_digest(result: dict[str, Any]) -> dict[str, Any]:
    return {**result, "content_digest": ""}


def _verify_internal(result: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(result), key=lambda error: list(error.path)
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"BASE-10 result schema validation failed: {detail}")
    if result["request_digest"] != digest_value(result["request"]):
        raise ValueError("BASE-10 request digest mismatch")
    policy = TargetPackagingPolicy.from_dict(result["policy"])
    if result["policy_digest"] != policy.digest:
        raise ValueError("BASE-10 policy digest mismatch")
    if result["result_id"] != stable_id("BASE10", _decision(result)):
        raise ValueError("BASE-10 governed decision identity mismatch")
    if result["content_digest"] != digest_value(_without_digest(result)):
        raise ValueError("BASE-10 content digest mismatch")
    if result["implementation_manifest"] != _implementation_manifest():
        raise ValueError("BASE-10 implementation manifest mismatch")
    if any(result["claims"].values()):
        raise ValueError("BASE-10 contains an operational claim")
    if (result["state"] == "blocked") != bool(result["blockers"]):
        raise ValueError("BASE-10 state and blockers disagree")
    target_ids: set[str] = set()
    authority_ids = [
        item["target_dataset_id"].casefold() for item in result["resolution_authorities"]
    ]
    if len(authority_ids) != len(set(authority_ids)) or set(authority_ids) != {
        item.target_dataset_id.casefold() for item in policy.target_bindings
    }:
        raise ValueError("BASE-10 resolution authority inventory mismatch")
    qualified_names: set[str] = set()
    for target in result["targets"]:
        if target["schema_digest"] != digest_value(target["columns"]):
            raise ValueError("BASE-10 target schema digest mismatch")
        if (
            target["semantic_result_id"] != result["semantic_authority"]["result_id"]
            or target["semantic_content_digest"] != result["semantic_authority"]["content_digest"]
        ):
            raise ValueError("BASE-10 target semantic authority mismatch")
        target_id = target["target_dataset_id"].casefold()
        qualified_name = target["resolved_namespace"]["qualified_name"].casefold()
        if target_id in target_ids or qualified_name in qualified_names:
            raise ValueError("BASE-10 target result contains a collision")
        target_ids.add(target_id)
        qualified_names.add(qualified_name)
    if result["state"] == "qualified_offline_mapping" and len(target_ids) != len(
        policy.target_bindings
    ):
        raise ValueError("BASE-10 qualified result omits a governed target")


def _reconstruct(
    request: TargetMappingRequest,
    policy: TargetPackagingPolicy,
    semantic: SemanticEvidence,
    resolutions: tuple[ResolutionEvidence, ...],
) -> dict[str, Any]:
    semantic_result, snapshot_current = _current_semantic(semantic, request.evaluation_time)
    resolved: dict[str, dict[str, Any]] = {}
    published: dict[str, dict[str, Any]] = {}
    for evidence in resolutions:
        if evidence.target_dataset_id in resolved:
            raise ValueError("BASE-10 resolution evidence contains a target collision")
        current, immutable = _current_resolution(evidence, request.evaluation_time)
        resolved[evidence.target_dataset_id] = current
        published[evidence.target_dataset_id] = immutable
    return _evaluate_target_mapping(
        request,
        policy,
        semantic_result,
        resolved,
        published_resolution_results=published,
        semantic_snapshot_current=snapshot_current,
    )


def run_target_mapping(
    request: TargetMappingRequest,
    policy: TargetPackagingPolicy,
    semantic: SemanticEvidence,
    resolutions: tuple[ResolutionEvidence, ...],
    *,
    evidence_root: Path,
    cancel_check: Callable[[], bool] | None = None,
) -> TargetMappingExecution:
    result_path, lock_path = _paths(evidence_root, request)
    ensure_directory(result_path.parent, root=evidence_root)
    with open_lock_file(lock_path, root=evidence_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=evidence_root, label="BASE-10 result"):
            return verify_target_mapping(
                result_path,
                request,
                policy,
                semantic,
                resolutions,
                evidence_root=evidence_root,
            )
        result = _reconstruct(request, policy, semantic, resolutions)
        if cancel_check is not None and cancel_check():
            raise InterruptedError("BASE-10 target mapping cancelled")
        publish_json(result_path, result, "BASE-10 result", root=evidence_root)
        return TargetMappingExecution(result, result_path)


def verify_target_mapping(
    result_path: Path,
    request: TargetMappingRequest,
    policy: TargetPackagingPolicy,
    semantic: SemanticEvidence,
    resolutions: tuple[ResolutionEvidence, ...],
    *,
    evidence_root: Path,
) -> TargetMappingExecution:
    expected, _ = _paths(evidence_root, request)
    if result_path != expected:
        raise ValueError("BASE-10 result path is not request-bound")
    payload = read_published_json(result_path, root=evidence_root, label="BASE-10 result")
    if not isinstance(payload, dict):
        raise ValueError("BASE-10 immutable result is not an object")
    _verify_internal(payload)
    if payload != _reconstruct(request, policy, semantic, resolutions):
        raise ValueError("BASE-10 evidence does not match current governed inputs")
    return TargetMappingExecution(payload, result_path)


__all__ = [
    "ResolutionEvidence",
    "SemanticEvidence",
    "TargetMappingExecution",
    "TargetMappingRequest",
    "TargetPackagingPolicy",
    "TargetPolicyBinding",
    "run_target_mapping",
    "verify_target_mapping",
]
