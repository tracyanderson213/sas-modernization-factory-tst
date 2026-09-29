"""BASE-02 governed dataset, physical-type, and semantic mapping contract.

The module consumes a verified BASE-04 canonical descriptor and qualifies only explicit mappings
of underlying values. Formats/informats, special missing values, customer business semantics, and
runtime parity remain visible and fail closed until their named authorities exist.
"""

from __future__ import annotations

import fcntl
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from smf.canonical_descriptor import SnapshotPolicy, verify_canonical_descriptor
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
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_TYPES = {"string", "double", "long", "boolean"}
_CONTRACT_DIGESTS = {
    "temporal_policy_digest": "5316c7e5b91d84fb0f373a4478671657457d3ef0355f98eab1c08d3edfaef4dd",
    "value_policy_digest": "2b44972f3bdbbccc5cd6edda3dbba78e9bd1891b49959a323194be1b973064ea",
    "format_function_policy_digest": (
        "4dd077f344d97424f132fdc0a827a8f201bbc9073c32968264e61f43c63ba7fc"
    ),
}


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"BASE-02 {label} must use canonical UTC RFC3339")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"BASE-02 {label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"BASE-02 {label} must use canonical UTC RFC3339")
    return parsed


def _id(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_ID.fullmatch(value)
        or contains_protected_data(value)
    ):
        raise ValueError(f"Unsafe BASE-02 {label}")
    return value


@dataclass(frozen=True)
class SemanticMappingRequest:
    client_id: str
    workload_id: str
    source_id: str
    run_id: str
    attempt_id: str
    source_dataset_id: str
    source_dataset_version: str
    evaluation_time: str

    def validate(self) -> None:
        for field in (
            "client_id",
            "workload_id",
            "source_id",
            "run_id",
            "attempt_id",
            "source_dataset_id",
        ):
            _id(getattr(self, field), field)
        if not _VERSION.fullmatch(self.source_dataset_version):
            raise ValueError("BASE-02 source dataset version is invalid")
        _time(self.evaluation_time, "evaluation_time")

    def binding(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class ColumnMapping:
    source_name: str
    source_position: int
    source_physical_type: str
    target_name: str
    target_physical_type: str
    mapping_kind: str
    rename_rationale: str | None
    expected_format: str | None
    expected_informat: str | None
    expected_storage_width: int
    format_disposition: str
    informat_disposition: str
    encoding_disposition: str
    precision_disposition: str
    length_disposition: str
    temporal_disposition: str
    missing_disposition: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ColumnMapping:
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("BASE-02 column mapping has unknown or missing fields")
        try:
            result = cls(**value)
        except TypeError as exc:
            raise ValueError("BASE-02 column mapping is malformed") from exc
        result.validate()
        return result

    def validate(self) -> None:
        _id(self.source_name, "source column")
        _id(self.target_name, "target column")
        if type(self.source_position) is not int or self.source_position < 0:
            raise ValueError("BASE-02 source column position is invalid")
        if self.source_physical_type not in _TARGET_TYPES or self.target_physical_type not in (
            _TARGET_TYPES
        ):
            raise ValueError("BASE-02 physical type mapping is unsupported")
        if self.mapping_kind != "identity_underlying_value":
            raise ValueError("BASE-02 mapping cannot transform source meaning")
        if self.source_name != self.target_name and (
            not isinstance(self.rename_rationale, str)
            or not self.rename_rationale
            or contains_protected_data(self.rename_rationale)
        ):
            raise ValueError("BASE-02 renamed column requires attributable rationale")
        if self.source_name == self.target_name and self.rename_rationale is not None:
            raise ValueError("BASE-02 identity column cannot carry rename rationale")
        for value in (self.expected_format, self.expected_informat):
            if value is not None and not isinstance(value, str):
                raise ValueError("BASE-02 declared SAS metadata must be text or null")
        if type(self.expected_storage_width) is not int or self.expected_storage_width < 1:
            raise ValueError("BASE-02 declared storage width is invalid")
        if self.format_disposition != "metadata_only_projection_blocked":
            raise ValueError("BASE-02 format projection must remain blocked")
        if self.informat_disposition != "metadata_only_application_blocked":
            raise ValueError("BASE-02 informat application must remain blocked")
        if self.missing_disposition != "ordinary_null_only_special_missing_blocked":
            raise ValueError("BASE-02 missing-value disposition is unsupported")
        if self.length_disposition != "preserve_storage_width_no_truncation":
            raise ValueError("BASE-02 length disposition is unsupported")
        if self.temporal_disposition not in {
            "not_temporal_observation",
            "blocked_pending_explicit_temporal_policy",
        }:
            raise ValueError("BASE-02 temporal disposition is unsupported")
        if self.source_physical_type == "string":
            if (
                self.target_physical_type != "string"
                or self.encoding_disposition != ("provider_decoded_unicode_to_utf8")
                or self.precision_disposition != "not_applicable"
            ):
                raise ValueError("BASE-02 string mapping policy is incompatible")
        elif self.source_physical_type == "double":
            if (
                self.target_physical_type != "double"
                or self.encoding_disposition != ("not_applicable")
                or self.precision_disposition != "binary64_no_narrowing_tolerance_pending"
            ):
                raise ValueError("BASE-02 double mapping policy is incompatible")
        else:
            raise ValueError("BASE-02 selected mapping supports only string and double")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class TargetMapping:
    target_dataset_id: str
    target_dataset_version: str
    target_namespace: str
    transformation_id: str
    transformation_version: str
    rationale: str
    columns: tuple[ColumnMapping, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TargetMapping:
        fields = set(cls.__dataclass_fields__)
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or not isinstance(value["columns"], list)
        ):
            raise ValueError("BASE-02 target mapping has unknown or malformed fields")
        normalized = dict(value)
        normalized["columns"] = tuple(ColumnMapping.from_dict(item) for item in value["columns"])
        try:
            result = cls(**normalized)
        except TypeError as exc:
            raise ValueError("BASE-02 target mapping is malformed") from exc
        result.validate()
        return result

    def validate(self) -> None:
        for field in ("target_dataset_id", "target_namespace", "transformation_id"):
            _id(getattr(self, field), field)
        if not _VERSION.fullmatch(self.target_dataset_version) or not _VERSION.fullmatch(
            self.transformation_version
        ):
            raise ValueError("BASE-02 target or transformation version is invalid")
        if (
            not isinstance(self.rationale, str)
            or not self.rationale
            or contains_protected_data(self.rationale)
        ):
            raise ValueError("BASE-02 target mapping rationale is missing or unsafe")
        if not self.columns:
            raise ValueError("BASE-02 target mapping has no columns")
        names = [item.target_name for item in self.columns]
        sources = [(item.source_position, item.source_name) for item in self.columns]
        if len(set(names)) != len(names) or len(set(sources)) != len(sources):
            raise ValueError("BASE-02 target mapping contains ambiguous column resolution")
        for item in self.columns:
            item.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["columns"] = [item.to_dict() for item in self.columns]
        return value


@dataclass(frozen=True)
class DatasetMappingPolicy:
    policy_id: str
    version: str
    authority_scope: str
    issued_at: str
    valid_until: str
    source_dataset_id: str
    source_dataset_version: str
    source_snapshot_sha256: str
    canonical_descriptor_digest: str
    canonical_descriptor_version: str
    source_encoding: str
    target_encoding: str
    ordinary_missing_policy: str
    special_missing_policy: str
    numeric_precision_policy: str
    temporal_timezone_policy: str
    yearcutoff_policy: str
    format_informat_policy: str
    source_key_policy: str
    target_key_policy: str
    executable_format_allowlist: tuple[str, ...]
    semantic_contract_digests: dict[str, str]
    targets: tuple[TargetMapping, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> DatasetMappingPolicy:
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("BASE-02 policy has unknown or missing fields")
        normalized = dict(value)
        if not isinstance(value["targets"], list) or not isinstance(
            value["executable_format_allowlist"], list
        ):
            raise ValueError("BASE-02 policy target or allowlist is malformed")
        normalized["targets"] = tuple(TargetMapping.from_dict(item) for item in value["targets"])
        normalized["executable_format_allowlist"] = tuple(value["executable_format_allowlist"])
        try:
            result = cls(**normalized)
        except TypeError as exc:
            raise ValueError("BASE-02 policy is malformed") from exc
        result.validate()
        return result

    @property
    def policy_digest(self) -> str:
        return digest_value(self.to_dict())

    def validate(self) -> None:
        _id(self.policy_id, "policy_id")
        _id(self.source_dataset_id, "source_dataset_id")
        if not _VERSION.fullmatch(self.version) or not _VERSION.fullmatch(
            self.source_dataset_version
        ):
            raise ValueError("BASE-02 policy or source dataset version is invalid")
        issued = _time(self.issued_at, "policy issued_at")
        expires = _time(self.valid_until, "policy valid_until")
        if expires <= issued:
            raise ValueError("BASE-02 mapping policy validity window is empty")
        if self.authority_scope != "licensed-public-fixture-qualification":
            raise ValueError("BASE-02 policy cannot assert customer authority")
        if not _SHA256.fullmatch(self.source_snapshot_sha256) or not _SHA256.fullmatch(
            self.canonical_descriptor_digest
        ):
            raise ValueError("BASE-02 policy source or descriptor digest is invalid")
        if self.canonical_descriptor_version != "base04-canonical-physical-v1":
            raise ValueError("BASE-02 canonical descriptor version is unsupported")
        expected = {
            "source_encoding": "WINDOWS-1252",
            "target_encoding": "UTF-8",
            "ordinary_missing_policy": "provider_null_to_target_null",
            "special_missing_policy": "blocked_unless_qualified",
            "numeric_precision_policy": "binary64_no_narrowing_tolerance_pending",
            "temporal_timezone_policy": "blocked_without_explicit_utc_policy",
            "yearcutoff_policy": "blocked_for_two_digit_year_semantics",
            "format_informat_policy": "metadata_only_no_executable_projection",
            "source_key_policy": "descriptor_declared_keys_only",
            "target_key_policy": "pending_business_owner",
        }
        if any(getattr(self, key) != expected_value for key, expected_value in expected.items()):
            raise ValueError("BASE-02 semantic policy cannot widen unresolved behavior")
        if self.executable_format_allowlist:
            raise ValueError("BASE-02 executable format allowlist must remain empty")
        if self.semantic_contract_digests != _CONTRACT_DIGESTS:
            raise ValueError("BASE-02 SASSEM contract digests are unsupported")
        if not self.targets:
            raise ValueError("BASE-02 policy has no target mapping")
        target_ids = [item.target_dataset_id for item in self.targets]
        if len(set(target_ids)) != len(target_ids):
            raise ValueError("BASE-02 target dataset resolution is ambiguous")
        for item in self.targets:
            item.validate()

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        value["executable_format_allowlist"] = list(self.executable_format_allowlist)
        value["targets"] = [item.to_dict() for item in self.targets]
        return value


@dataclass(frozen=True)
class SemanticMappingExecution:
    result: dict[str, Any]
    result_path: Path


def _paths(root: Path, request: SemanticMappingRequest) -> tuple[Path, Path]:
    request.validate()
    directory = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "base02"
    )
    return directory / "result.json", directory / "execution.lock"


def _blocked(reason: str) -> tuple[str, list[str]]:
    return "blocked", [reason]


def _evaluate(
    request: SemanticMappingRequest,
    policy: DatasetMappingPolicy,
    descriptor_result: dict[str, Any],
) -> dict[str, Any]:
    request.validate()
    policy.validate()
    evaluated = _time(request.evaluation_time, "evaluation_time")
    if not (
        _time(policy.issued_at, "policy issued_at")
        <= evaluated
        < _time(policy.valid_until, "policy valid_until")
    ):
        state, blockers = _blocked("mapping_policy_not_current")
    elif any(
        request.binding()[field] != descriptor_result["identity"][field]
        for field in ("client_id", "workload_id", "source_id", "run_id", "attempt_id")
    ):
        state, blockers = _blocked("canonical_descriptor_identity_mismatch")
    elif request.source_dataset_id != policy.source_dataset_id or (
        request.source_dataset_version != policy.source_dataset_version
    ):
        state, blockers = _blocked("source_dataset_identity_mismatch")
    elif descriptor_result["source_snapshot"]["sha256"] != policy.source_snapshot_sha256:
        state, blockers = _blocked("source_snapshot_mismatch")
    elif descriptor_result["descriptor_digest"] != policy.canonical_descriptor_digest:
        state, blockers = _blocked("canonical_descriptor_digest_mismatch")
    elif descriptor_result["canonical_descriptor"]["descriptor_version"] != (
        policy.canonical_descriptor_version
    ):
        state, blockers = _blocked("canonical_descriptor_version_mismatch")
    elif descriptor_result["canonical_descriptor"]["file_encoding"] != policy.source_encoding:
        state, blockers = _blocked("source_encoding_policy_mismatch")
    else:
        state, blockers = "qualified_underlying_mapping", []

    source_columns = descriptor_result["canonical_descriptor"]["columns"]
    expected = {
        (item["position"], item["name"], item["canonical_physical_type"]): item
        for item in source_columns
    }
    targets: list[dict[str, Any]] = []
    for target in policy.targets:
        mapped = {
            (item.source_position, item.source_name, item.source_physical_type): item
            for item in target.columns
        }
        if set(mapped) != set(expected):
            state, blockers = _blocked("column_mapping_is_incomplete_or_ambiguous")
        projected: list[dict[str, Any]] = []
        for key, mapping in mapped.items():
            observed = expected.get(key)
            if observed is None:
                continue
            if mapping.expected_format != observed["declared_sas_metadata"]["format"] or (
                mapping.expected_informat != observed["declared_sas_metadata"]["informat"]
            ):
                state, blockers = _blocked("declared_format_or_informat_mismatch")
            if mapping.expected_storage_width != observed["declared_sas_metadata"]["storage_width"]:
                state, blockers = _blocked("declared_storage_width_mismatch")
            projected.append(
                {
                    **mapping.to_dict(),
                    "source_column_descriptor_digest": digest_value(observed),
                    "underlying_value_authority": state == "qualified_underlying_mapping",
                    "formatted_projection_authority": False,
                }
            )
        targets.append(
            {
                "target_dataset_id": target.target_dataset_id,
                "target_dataset_version": target.target_dataset_version,
                "target_namespace": target.target_namespace,
                "transformation_id": target.transformation_id,
                "transformation_version": target.transformation_version,
                "rationale": target.rationale,
                "columns": projected,
                "target_snapshot_state": "planned_not_executed",
                "target_descriptor_digest": digest_value(projected),
            }
        )

    if state != "qualified_underlying_mapping":
        for result_target in targets:
            for column in result_target["columns"]:
                column["underlying_value_authority"] = False
            result_target["target_descriptor_digest"] = digest_value(result_target["columns"])

    unresolved = [
        "customer_mapping_authority",
        "executable_format_and_informat_projection",
        "special_missing_value_equivalence",
        "numeric_business_tolerance",
        "temporal_timezone_locale_and_yearcutoff_for_applicable_columns",
        "business_key_and_one_to_many_business_disposition",
        "sas_runtime_output_and_target_runtime_parity",
    ]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": "",
        "request": request.binding(),
        "request_digest": digest_value(request.binding()),
        "policy": policy.to_dict(),
        "policy_digest": policy.policy_digest,
        "canonical_descriptor": {
            "result_id": descriptor_result["result_id"],
            "content_digest": descriptor_result["content_digest"],
            "descriptor_digest": descriptor_result["descriptor_digest"],
            "source_snapshot": descriptor_result["source_snapshot"],
        },
        "key_policy": {
            "source_declared_keys": descriptor_result["canonical_descriptor"]["declared_keys"],
            "source_key_authority": descriptor_result["canonical_descriptor"]["key_authority"],
            "source_policy": policy.source_key_policy,
            "target_policy": policy.target_key_policy,
            "target_keys": [],
            "target_key_authority": False,
        },
        "state": state,
        "blockers": blockers,
        "targets": targets,
        "unresolved_external_decisions": unresolved,
        "execution_authorized": False,
        "claims": {
            "target_generated": False,
            "target_executed": False,
            "validated": False,
            "semantic_parity": False,
            "humana_approved": False,
            "databricks_or_unity_catalog_validated": False,
            "production_ready": False,
            "migration_complete": False,
        },
        "content_digest": "",
    }
    payload["result_id"] = stable_id(
        "BASE02",
        {
            "request": payload["request"],
            "policy_digest": payload["policy_digest"],
            "descriptor_digest": descriptor_result["descriptor_digest"],
        },
    )
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    _verify_internal(payload)
    return payload


def _verify_internal(result: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "result_id",
        "request",
        "request_digest",
        "policy",
        "policy_digest",
        "canonical_descriptor",
        "key_policy",
        "state",
        "blockers",
        "targets",
        "unresolved_external_decisions",
        "execution_authorized",
        "claims",
        "content_digest",
    }
    if set(result) != required or result["schema_version"] != "1.0":
        raise ValueError("BASE-02 result contract is malformed")
    request = SemanticMappingRequest(**result["request"])
    policy = DatasetMappingPolicy.from_dict(result["policy"])
    if (
        result["request_digest"] != digest_value(request.binding())
        or result["policy_digest"] != policy.policy_digest
    ):
        raise ValueError("BASE-02 request or policy digest mismatch")
    if result["content_digest"] != digest_value({**result, "content_digest": ""}):
        raise ValueError("BASE-02 result content digest mismatch")
    if result["state"] not in {"qualified_underlying_mapping", "blocked"}:
        raise ValueError("BASE-02 result state is invalid")
    if (result["state"] == "blocked") != bool(result["blockers"]):
        raise ValueError("BASE-02 result blocker state is inconsistent")
    expected_claims = {
        "target_generated",
        "target_executed",
        "validated",
        "semantic_parity",
        "humana_approved",
        "databricks_or_unity_catalog_validated",
        "production_ready",
        "migration_complete",
    }
    if (
        set(result["claims"]) != expected_claims
        or result["execution_authorized"]
        or any(result["claims"].values())
    ):
        raise ValueError("BASE-02 result asserts an unauthorized outcome")
    if not result["unresolved_external_decisions"]:
        raise ValueError("BASE-02 unresolved authorities cannot be omitted")
    if set(result["key_policy"]) != {
        "source_declared_keys",
        "source_key_authority",
        "source_policy",
        "target_policy",
        "target_keys",
        "target_key_authority",
    } or result["key_policy"] != {
        "source_declared_keys": result["key_policy"]["source_declared_keys"],
        "source_key_authority": result["key_policy"]["source_key_authority"],
        "source_policy": "descriptor_declared_keys_only",
        "target_policy": "pending_business_owner",
        "target_keys": [],
        "target_key_authority": False,
    }:
        raise ValueError("BASE-02 key policy is malformed or asserts target authority")
    if not isinstance(result["targets"], list) or len(result["targets"]) != len(policy.targets):
        raise ValueError("BASE-02 target result contract is malformed")
    for target, governed in zip(result["targets"], policy.targets, strict=True):
        if set(target) != {
            "target_dataset_id",
            "target_dataset_version",
            "target_namespace",
            "transformation_id",
            "transformation_version",
            "rationale",
            "columns",
            "target_snapshot_state",
            "target_descriptor_digest",
        }:
            raise ValueError("BASE-02 target result contract is malformed")
        if target["target_snapshot_state"] != "planned_not_executed":
            raise ValueError("BASE-02 target result asserts execution")
        if target["target_dataset_id"] != governed.target_dataset_id:
            raise ValueError("BASE-02 target result identity is inconsistent")
        if target["target_descriptor_digest"] != digest_value(target["columns"]):
            raise ValueError("BASE-02 target descriptor digest mismatch")
        if not isinstance(target["columns"], list):
            raise ValueError("BASE-02 target columns are malformed")
        for column in target["columns"]:
            expected_keys = set(ColumnMapping.__dataclass_fields__) | {
                "source_column_descriptor_digest",
                "underlying_value_authority",
                "formatted_projection_authority",
            }
            if set(column) != expected_keys:
                raise ValueError("BASE-02 projected column contract is malformed")
            expected_authority = result["state"] == "qualified_underlying_mapping"
            if (
                column["underlying_value_authority"] is not expected_authority
                or column["formatted_projection_authority"] is not False
            ):
                raise ValueError("BASE-02 projected column authority is invalid")


def run_semantic_mapping(
    request: SemanticMappingRequest,
    policy: DatasetMappingPolicy,
    *,
    base04_result_path: Path,
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    snapshot_policy: SnapshotPolicy,
    cancel_check: Callable[[], bool] | None = None,
) -> SemanticMappingExecution:
    result_path, lock_path = _paths(evidence_root, request)
    ensure_directory(result_path.parent, root=evidence_root)
    with open_lock_file(lock_path, root=evidence_root) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if published_file_exists(result_path, root=evidence_root, label="BASE-02 result"):
            return verify_semantic_mapping(
                result_path,
                request,
                policy,
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
        descriptor = verify_canonical_descriptor(
            base04_result_path,
            local_request,
            distributed_request,
            source_root=source_root,
            artifact_root=artifact_root,
            evidence_root=evidence_root,
            local_config=local_config,
            distributed_config=distributed_config,
            policy=snapshot_policy,
        )
        if cancel_check is not None and cancel_check():
            raise InterruptedError("BASE-02 mapping cancelled")
        result = _evaluate(request, policy, descriptor.result)
        if cancel_check is not None and cancel_check():
            raise InterruptedError("BASE-02 mapping cancelled")
        publish_json(result_path, result, "BASE-02 result", root=evidence_root)
        return SemanticMappingExecution(result, result_path)


def verify_semantic_mapping(
    result_path: Path,
    request: SemanticMappingRequest,
    policy: DatasetMappingPolicy,
    *,
    base04_result_path: Path,
    local_request: ReaderRequest,
    distributed_request: DistributedReaderRequest,
    source_root: Path,
    artifact_root: Path,
    evidence_root: Path,
    local_config: ReaderConfig,
    distributed_config: DistributedReaderConfig,
    snapshot_policy: SnapshotPolicy,
) -> SemanticMappingExecution:
    expected, _ = _paths(evidence_root, request)
    if result_path != expected:
        raise ValueError("BASE-02 result path is not request-bound")
    payload = read_published_json(result_path, root=evidence_root, label="BASE-02 result")
    if not isinstance(payload, dict):
        raise ValueError("BASE-02 immutable result is not an object")
    _verify_internal(payload)
    descriptor = verify_canonical_descriptor(
        base04_result_path,
        local_request,
        distributed_request,
        source_root=source_root,
        artifact_root=artifact_root,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        policy=snapshot_policy,
    )
    reconstructed = _evaluate(request, policy, descriptor.result)
    if reconstructed != payload:
        raise ValueError("BASE-02 current inputs do not reconstruct immutable evidence")
    return SemanticMappingExecution(payload, result_path)


def load_mapping_policy(path: Path) -> DatasetMappingPolicy:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("BASE-02 policy file is missing or invalid JSON") from exc
    return DatasetMappingPolicy.from_dict(payload)


__all__ = [
    "ColumnMapping",
    "DatasetMappingPolicy",
    "SemanticMappingExecution",
    "SemanticMappingRequest",
    "TargetMapping",
    "load_mapping_policy",
    "run_semantic_mapping",
    "verify_semantic_mapping",
]
