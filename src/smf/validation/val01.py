"""VAL-01 distributed, full-row/cell reconciliation composition contract."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import importlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from functools import reduce
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.execution.runtime_evidence import (
    CurrentExecutionPlanEvidence,
    RuntimeEvidenceRequest,
    SyntheticRuntimeObservation,
    verify_runtime_evidence,
)
from smf.immutable_files import publish_json, read_published_bytes, read_published_json
from smf.schema_integration import (
    CurrentSchemaIntegrationEvidence,
    SchemaIntegrationRequest,
    verify_schema_integration,
)
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import sign_payload, verify_proof
from smf.validation.dp02 import (
    DP02Request,
    SparkDataFrameCountAdapter,
    verify_current_dp02_result,
)
from smf.validation.dp03 import DP03TrustPolicy, verify_dp03_result
from smf.validation.dp04 import ProfilingPolicy
from smf.validation.dp04 import verify_result as verify_dp04_result
from smf.validation.dp05 import DP05TrustPolicy, verify_dp05_result
from smf.validation.row_count import RowCountPolicy
from smf.workload.sanitization import sanitize_discovery_value

Status = Literal["passed", "failed", "blocked", "cancelled", "unsupported"]
DuplicatePolicy = Literal["reject", "deterministic_tiebreak"]
NullKeyPolicy = Literal["reject", "match"]
NullPolicy = Literal["equal", "different"]
CoercionPolicy = Literal["none", "source_to_target", "target_to_source"]
StringPolicy = Literal["exact", "trim", "trim_casefold"]
SasMissingPolicy = Literal["distinct", "collapse_to_null"]
OrderPolicy = Literal["keyed_unordered", "ordered"]
EvidenceClass = Literal["synthetic_contract", "qualified_runtime"]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_KINDS = ("SCHEMA-INT-01", "DP-02", "DP-03", "DP-04", "DP-05", "DBX-04")
_MAX_COLUMNS = 256
_MAX_KEYS = 16
_MAX_MISMATCH_REFS = 1000
_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe_id(value: str, label: str) -> str:
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"Unsafe VAL-01 {label}")
    return value


def _require_digest(value: str, label: str) -> str:
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"Invalid VAL-01 {label}")
    return value


def _assert_safe(value: Any) -> None:
    if isinstance(value, str):
        if contains_protected_data(value) or sanitize_discovery_value(value) != value:
            raise ValueError("VAL-01 evidence contains protected data")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _assert_safe(key)
            _assert_safe(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _assert_safe(item)


def _spark_type_matches(logical_type: str, spark_type: str) -> bool:
    """Return whether a Spark SQL type is an exact member of a governed logical family."""

    normalized = spark_type.casefold()
    families = {
        "string": ("string",),
        "integer": ("tinyint", "smallint", "int", "bigint"),
        "decimal": ("decimal(",),
        "float": ("float", "double"),
        "date": ("date",),
        "timestamp": ("timestamp", "timestamp_ntz"),
        "boolean": ("boolean",),
    }
    expected = families.get(logical_type, ())
    return any(normalized == item or normalized.startswith(item) for item in expected)


def _coercion_pair_allowed(
    logical_type: str, source_type: str, target_type: str, direction: CoercionPolicy
) -> bool:
    """Close directed coercion to explicit scalar families before round-trip proof."""

    if direction == "none":
        return source_type == target_type and _spark_type_matches(logical_type, source_type)
    authoritative = target_type if direction == "source_to_target" else source_type
    other = source_type if direction == "source_to_target" else target_type
    if not _spark_type_matches(logical_type, authoritative):
        return False
    if logical_type in {"integer", "decimal", "float"}:
        return other == "string" or any(
            _spark_type_matches(kind, other) for kind in ("integer", "decimal", "float")
        )
    if logical_type == "boolean":
        return other in {"boolean", "string"}
    return logical_type == "string" and other == "string"


def _datacompy_float_tolerance(value: Decimal) -> float:
    """Encode a decimal threshold for DataComPy without narrowing its boundary."""

    if value == 0:
        return 0.0
    binary = float(value)
    # Spark double arithmetic can accumulate more than one representational ULP
    # before DataComPy applies its float-only threshold. This narrow, quantified
    # envelope is used only by the independent cross-check; the exact-decimal
    # primary comparison remains a mandatory conjunct.
    envelope = max(math.ulp(binary) * 8, abs(binary) * 1e-12)
    return binary + envelope


def _contains_scalar(value: Any, expected: str) -> bool:
    if value == expected:
        return True
    if isinstance(value, Mapping):
        return any(_contains_scalar(item, expected) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_scalar(item, expected) for item in value)
    return False


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text("utf-8"))
    if not isinstance(value, dict):
        raise TypeError("VAL-01 schema must be an object")
    return cast(dict[str, Any], value)


def _validate(name: str, payload: dict[str, Any]) -> None:
    if len(_canonical(payload)) > _MAX_EVIDENCE_BYTES:
        raise ValueError("VAL-01 evidence exceeds governed byte bound")
    schemas = {
        filename: _schema(filename)
        for filename in ("val01-comparator-receipt.schema.json", "val01-result.schema.json")
    }
    registry = Registry()
    for value in schemas.values():
        registry = registry.with_resource(cast(str, value["$id"]), Resource.from_contents(value))
    errors = sorted(
        Draft202012Validator(schemas[name], registry=registry).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"VAL-01 schema validation failed: {detail}")


@dataclass(frozen=True)
class SnapshotBinding:
    dataset_id: str
    snapshot_id: str
    snapshot_digest: str

    def to_dict(self) -> dict[str, str]:
        return {
            "dataset_id": _safe_id(self.dataset_id, "dataset_id"),
            "snapshot_id": _safe_id(self.snapshot_id, "snapshot_id"),
            "snapshot_digest": _require_digest(self.snapshot_digest, "snapshot_digest"),
        }


@dataclass(frozen=True)
class EvidenceBinding:
    kind: str
    relative_path: str
    result_id: str
    content_digest: str
    artifact_digest: str

    def to_dict(self) -> dict[str, str]:
        if self.kind not in _KINDS:
            raise ValueError("VAL-01 prerequisite kind is unsupported")
        path = Path(self.relative_path)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("VAL-01 prerequisite path is unsafe")
        return {
            "kind": self.kind,
            "relative_path": self.relative_path,
            "result_id": _require_digest(self.result_id, "prerequisite result_id"),
            "content_digest": _require_digest(self.content_digest, "prerequisite content_digest"),
            "artifact_digest": _require_digest(
                self.artifact_digest, "prerequisite artifact_digest"
            ),
        }


@dataclass(frozen=True)
class SchemaCurrentEvidence:
    binding: EvidenceBinding
    request: SchemaIntegrationRequest
    evidence: CurrentSchemaIntegrationEvidence


@dataclass(frozen=True)
class DP02CurrentEvidence:
    binding: EvidenceBinding
    request: DP02Request
    source_receipt_root: Path
    source_receipt_path: Path
    target_adapter: SparkDataFrameCountAdapter
    policy: RowCountPolicy


@dataclass(frozen=True)
class DP03CurrentEvidence:
    binding: EvidenceBinding
    trust_policy: DP03TrustPolicy


@dataclass(frozen=True)
class DP04CurrentEvidence:
    binding: EvidenceBinding
    source_partitions: tuple[dict[str, Any], ...]
    target_partitions: tuple[dict[str, Any], ...]
    policy: ProfilingPolicy


@dataclass(frozen=True)
class DP05CurrentEvidence:
    binding: EvidenceBinding
    trust_policy: DP05TrustPolicy


@dataclass(frozen=True)
class DBX04CurrentEvidence:
    binding: EvidenceBinding
    request: RuntimeEvidenceRequest
    observation: SyntheticRuntimeObservation
    current_plan: CurrentExecutionPlanEvidence


@dataclass(frozen=True)
class CurrentEvidence:
    schema: SchemaCurrentEvidence
    row_count: DP02CurrentEvidence
    aggregates: DP03CurrentEvidence
    distributions: DP04CurrentEvidence
    samples: DP05CurrentEvidence
    runtime: DBX04CurrentEvidence

    def bindings(self) -> tuple[EvidenceBinding, ...]:
        return (
            self.schema.binding,
            self.row_count.binding,
            self.aggregates.binding,
            self.distributions.binding,
            self.samples.binding,
            self.runtime.binding,
        )


@dataclass(frozen=True)
class ColumnPolicy:
    name: str
    logical_type: Literal["string", "integer", "decimal", "float", "date", "timestamp", "boolean"]
    coercion: CoercionPolicy = "none"
    null_policy: NullPolicy = "equal"
    absolute_tolerance: str = "0"
    relative_tolerance: str = "0"
    relative_denominator: Literal["target_absolute"] = "target_absolute"
    tolerance_combination: Literal["absolute_plus_relative"] = "absolute_plus_relative"
    nan_equal: bool = False
    infinity_equal: bool = False
    sas_missing: SasMissingPolicy = "distinct"
    string_policy: StringPolicy = "exact"
    timezone: str | None = None
    yearcutoff: int | None = None
    encoding: str = "utf-8"
    format_normalization: Literal["underlying_value_only"] = "underlying_value_only"

    def to_dict(self) -> dict[str, Any]:
        _safe_id(self.name, "column name")
        try:
            absolute = Decimal(self.absolute_tolerance)
            relative = Decimal(self.relative_tolerance)
        except InvalidOperation as exc:
            raise ValueError("VAL-01 tolerance is invalid") from exc
        if not absolute.is_finite() or not relative.is_finite() or absolute < 0 or relative < 0:
            raise ValueError("VAL-01 tolerance must be finite and non-negative")
        if relative > 1:
            raise ValueError("VAL-01 relative tolerance must not exceed one")
        if (
            self.relative_denominator != "target_absolute"
            or self.tolerance_combination != "absolute_plus_relative"
        ):
            raise ValueError("VAL-01 numeric tolerance formula is unsupported")
        if self.logical_type in {"date", "timestamp"}:
            if not self.timezone or self.yearcutoff is None:
                raise ValueError("VAL-01 temporal policy requires timezone and YEARCUTOFF")
            _safe_id(self.timezone.replace("/", "-"), "timezone")
            if not 1582 <= self.yearcutoff <= 9999:
                raise ValueError("VAL-01 YEARCUTOFF is outside the governed range")
        elif self.timezone is not None or self.yearcutoff is not None:
            raise ValueError("VAL-01 temporal settings require a temporal column")
        if self.encoding.casefold() != "utf-8":
            raise ValueError("VAL-01 only accepts the qualified UTF-8 comparison encoding")
        return asdict(self)


@dataclass(frozen=True)
class ValidationPolicy:
    policy_id: str
    policy_version: str
    key_columns: tuple[str, ...]
    columns: tuple[ColumnPolicy, ...]
    duplicate_policy: DuplicatePolicy = "reject"
    tie_break_columns: tuple[str, ...] = ()
    null_key_policy: NullKeyPolicy = "reject"
    order_policy: OrderPolicy = "keyed_unordered"
    order_columns: tuple[str, ...] = ()
    nondeterministic_exclusions: tuple[str, ...] = ()
    maximum_mismatch_references: int = 100

    def to_dict(self) -> dict[str, Any]:
        _safe_id(self.policy_id, "policy_id")
        _safe_id(self.policy_version, "policy_version")
        if not 1 <= len(self.key_columns) <= _MAX_KEYS or len(set(self.key_columns)) != len(
            self.key_columns
        ):
            raise ValueError("VAL-01 join keys must be non-empty, unique and bounded")
        if not 1 <= len(self.columns) <= _MAX_COLUMNS:
            raise ValueError("VAL-01 compared columns must be non-empty and bounded")
        names = [column.name for column in self.columns]
        if len(set(names)) != len(names) or set(names) & set(self.key_columns):
            raise ValueError("VAL-01 key and compared columns must be distinct and unique")
        governed = set(self.key_columns) | set(names)
        for value in (*self.key_columns, *self.tie_break_columns, *self.order_columns):
            _safe_id(value, "governed column")
        if not set(self.tie_break_columns).issubset(governed):
            raise ValueError("VAL-01 tie-break columns must be governed")
        if self.duplicate_policy == "reject" and self.tie_break_columns:
            raise ValueError("VAL-01 reject-duplicate policy cannot carry tie-break columns")
        if self.duplicate_policy == "deterministic_tiebreak" and not self.tie_break_columns:
            raise ValueError("VAL-01 duplicate alignment requires deterministic tie-break columns")
        if self.order_policy == "ordered" and not self.order_columns:
            raise ValueError("VAL-01 ordered comparison requires explicit order columns")
        if self.order_policy == "keyed_unordered" and self.order_columns:
            raise ValueError("VAL-01 unordered comparison cannot carry order columns")
        if not set(self.nondeterministic_exclusions).issubset(set(names)):
            raise ValueError("VAL-01 nondeterministic exclusions must be compared columns")
        if not 1 <= self.maximum_mismatch_references <= _MAX_MISMATCH_REFS:
            raise ValueError("VAL-01 mismatch-reference bound is invalid")
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "key_columns": list(self.key_columns),
            "columns": [column.to_dict() for column in self.columns],
            "duplicate_policy": self.duplicate_policy,
            "tie_break_columns": list(self.tie_break_columns),
            "null_key_policy": self.null_key_policy,
            "order_policy": self.order_policy,
            "order_columns": list(self.order_columns),
            "nondeterministic_exclusions": list(self.nondeterministic_exclusions),
            "maximum_mismatch_references": self.maximum_mismatch_references,
        }


@dataclass(frozen=True)
class RuntimeManifest:
    manifest_id: str
    manifest_version: str
    provider_id: str
    provider_version: str
    spark_version: str
    datacompy_version: str
    evidence_class: EvidenceClass
    qualified: bool
    authority_id: str
    authority_digest: str
    verification_key_id: str
    verification_key: str
    mismatch_hmac_key: bytes
    python_version: str = ""
    platform_id: str = ""
    distribution_records: tuple[tuple[str, str, str], ...] = ()

    def public_payload(self) -> dict[str, Any]:
        for value in (
            self.manifest_id,
            self.manifest_version,
            self.provider_id,
            self.provider_version,
            self.spark_version,
            self.datacompy_version,
            self.authority_id,
            self.verification_key_id,
        ):
            _safe_id(value, "runtime identity")
        _require_digest(self.authority_digest, "runtime authority_digest")
        try:
            decoded = base64.b64decode(self.verification_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("VAL-01 verification key is not canonical base64") from exc
        if len(decoded) != 32 or len(self.mismatch_hmac_key) < 32:
            raise ValueError("VAL-01 runtime cryptographic material is invalid")
        if self.evidence_class == "qualified_runtime" and not self.qualified:
            raise ValueError("VAL-01 qualified runtime must be explicitly qualified")
        if self.evidence_class == "synthetic_contract" and self.qualified:
            raise ValueError("VAL-01 synthetic runtime cannot be qualified")
        python_version = self.python_version or "unqualified"
        platform_id = self.platform_id or "unqualified"
        _safe_id(python_version, "runtime Python version")
        _safe_id(platform_id, "runtime platform")
        records = []
        seen: set[str] = set()
        for name, version, record_digest in self.distribution_records:
            _safe_id(name, "runtime distribution")
            _safe_id(version, "runtime distribution version")
            _require_digest(record_digest, "runtime distribution RECORD digest")
            if name in seen:
                raise ValueError("VAL-01 runtime distribution RECORD is duplicated")
            seen.add(name)
            records.append({"name": name, "version": version, "record_digest": record_digest})
        required = {
            "pyspark",
            "py4j",
            "datacompy",
            "numpy",
            "pandas",
            "pyarrow",
            "grpcio",
            "grpcio-status",
            "googleapis-common-protos",
        }
        if self.evidence_class == "qualified_runtime" and seen != required:
            raise ValueError("VAL-01 qualified runtime RECORD closure is incomplete")
        return {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "spark_version": self.spark_version,
            "datacompy_version": self.datacompy_version,
            "evidence_class": self.evidence_class,
            "qualified": self.qualified,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
            "verification_key_id": self.verification_key_id,
            "verification_key": self.verification_key,
            "mismatch_hmac_key_digest": _byte_digest(self.mismatch_hmac_key),
            "python_version": python_version,
            "platform_id": platform_id,
            "distribution_records": sorted(records, key=lambda item: item["name"]),
        }

    @property
    def digest(self) -> str:
        return _digest(self.public_payload())


@dataclass(frozen=True)
class RuntimeTrustPolicy:
    policy_id: str
    policy_version: str
    qualified_manifest_digests: tuple[str, ...]
    allowed_authorities: tuple[tuple[str, str, str, str], ...]

    def public_payload(self) -> dict[str, Any]:
        _safe_id(self.policy_id, "runtime trust policy_id")
        _safe_id(self.policy_version, "runtime trust policy_version")
        if not self.qualified_manifest_digests or len(set(self.qualified_manifest_digests)) != len(
            self.qualified_manifest_digests
        ):
            raise ValueError("VAL-01 runtime trust allowlist must be non-empty and unique")
        for digest in self.qualified_manifest_digests:
            _require_digest(digest, "qualified runtime manifest digest")
        identities: set[tuple[str, str]] = set()
        authorities: list[dict[str, str]] = []
        for authority_id, authority_digest, key_id, public_key in self.allowed_authorities:
            _safe_id(authority_id, "trusted authority_id")
            _safe_id(key_id, "trusted key_id")
            _require_digest(authority_digest, "trusted authority_digest")
            if (authority_id, key_id) in identities:
                raise ValueError("VAL-01 runtime trust authority is duplicated")
            identities.add((authority_id, key_id))
            try:
                decoded = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("VAL-01 trusted key is not canonical base64") from exc
            if len(decoded) != 32:
                raise ValueError("VAL-01 trusted key must be Ed25519")
            authorities.append(
                {
                    "authority_id": authority_id,
                    "authority_digest": authority_digest,
                    "verification_key_id": key_id,
                    "verification_key": public_key,
                }
            )
        if not authorities:
            raise ValueError("VAL-01 runtime trust authority allowlist is empty")
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "qualified_manifest_digests": sorted(self.qualified_manifest_digests),
            "allowed_authorities": sorted(
                authorities, key=lambda item: (item["authority_id"], item["verification_key_id"])
            ),
        }

    @property
    def digest(self) -> str:
        return _digest(self.public_payload())

    def authorizes(self, runtime: RuntimeManifest) -> bool:
        authorized = {(item[0], item[1], item[2], item[3]) for item in self.allowed_authorities}
        identity = (
            runtime.authority_id,
            runtime.authority_digest,
            runtime.verification_key_id,
            runtime.verification_key,
        )
        return runtime.digest in self.qualified_manifest_digests and identity in authorized


@dataclass(frozen=True)
class ValidationRequest:
    client_id: str
    workload_id: str
    run_id: str
    attempt_id: str
    evaluated_at: str
    source: SnapshotBinding
    target: SnapshotBinding
    prerequisites: tuple[EvidenceBinding, ...]
    policy_digest: str
    trust_policy_digest: str
    runtime_manifest_digest: str
    maximum_evidence_age_seconds: int = 86_400

    def to_dict(self) -> dict[str, Any]:
        for value, label in (
            (self.client_id, "client_id"),
            (self.workload_id, "workload_id"),
            (self.run_id, "run_id"),
            (self.attempt_id, "attempt_id"),
        ):
            _safe_id(value, label)
        if not _RFC3339.fullmatch(self.evaluated_at):
            raise ValueError("VAL-01 evaluated_at must be canonical UTC RFC3339")
        datetime.fromisoformat(self.evaluated_at.removesuffix("Z") + "+00:00")
        if not 1 <= self.maximum_evidence_age_seconds <= 604_800:
            raise ValueError("VAL-01 prerequisite freshness bound is invalid")
        bindings = [binding.to_dict() for binding in self.prerequisites]
        if sorted(binding["kind"] for binding in bindings) != sorted(_KINDS):
            raise ValueError("VAL-01 requires exactly one current binding for every prerequisite")
        return {
            "client_id": self.client_id,
            "workload_id": self.workload_id,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "evaluated_at": self.evaluated_at,
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "prerequisites": sorted(bindings, key=lambda item: item["kind"]),
            "policy_digest": _require_digest(self.policy_digest, "policy_digest"),
            "trust_policy_digest": _require_digest(self.trust_policy_digest, "trust_policy_digest"),
            "runtime_manifest_digest": _require_digest(
                self.runtime_manifest_digest, "runtime_manifest_digest"
            ),
            "maximum_evidence_age_seconds": self.maximum_evidence_age_seconds,
        }


class CancellationToken(Protocol):
    def __call__(self) -> bool: ...


def _evidence_time(payload: Any) -> datetime | None:
    observed: list[datetime] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            if (
                key in {"evaluated_at", "observed_at", "created_at", "captured_at"}
                and isinstance(value, str)
                and _RFC3339.fullmatch(value)
            ):
                observed.append(datetime.fromisoformat(value.removesuffix("Z") + "+00:00"))
            else:
                nested = _evidence_time(value)
                if nested is not None:
                    observed.append(nested)
    elif isinstance(payload, list | tuple):
        for value in payload:
            nested = _evidence_time(value)
            if nested is not None:
                observed.append(nested)
    return max(observed) if observed else None


def _verify_current_prerequisite(
    root: Path,
    kind: str,
    path: Path,
    payload: dict[str, Any],
    current: CurrentEvidence,
) -> None:
    if kind == "SCHEMA-INT-01":
        schema_context = current.schema
        verify_schema_integration(
            path, schema_context.request, schema_context.evidence, output_root=root
        )
    elif kind == "DP-02":
        row_context = current.row_count
        verify_current_dp02_result(
            path,
            row_context.request,
            evidence_root=root,
            source_receipt_root=row_context.source_receipt_root,
            source_receipt_path=row_context.source_receipt_path,
            target_adapter=row_context.target_adapter,
            policy=row_context.policy,
        )
    elif kind == "DP-03":
        verify_dp03_result(payload, trust_policy=current.aggregates.trust_policy)
    elif kind == "DP-04":
        distribution_context = current.distributions
        verify_dp04_result(
            payload,
            source_partitions=distribution_context.source_partitions,
            target_partitions=distribution_context.target_partitions,
            policy=distribution_context.policy,
        )
    elif kind == "DP-05":
        verify_dp05_result(payload, trust_policy=current.samples.trust_policy)
    elif kind == "DBX-04":
        runtime_context = current.runtime
        verify_runtime_evidence(
            payload,
            runtime_context.request,
            runtime_context.observation,
            runtime_context.current_plan,
        )
    else:  # pragma: no cover - guarded by request validation
        raise ValueError("VAL-01 prerequisite kind is unsupported")


def _load_prerequisites(
    root: Path, request: ValidationRequest, current: CurrentEvidence
) -> list[dict[str, str]]:
    if sorted(
        (binding.to_dict() for binding in current.bindings()), key=lambda item: item["kind"]
    ) != sorted(
        (binding.to_dict() for binding in request.prerequisites), key=lambda item: item["kind"]
    ):
        raise ValueError("VAL-01 current evidence contexts differ from request bindings")
    contexts = {binding.kind: binding for binding in current.bindings()}
    loaded: list[dict[str, str]] = []
    for binding in request.prerequisites:
        expected = binding.to_dict()
        path = root / binding.relative_path
        raw = read_published_bytes(path, root=root, label=f"VAL-01 {binding.kind} prerequisite")
        if len(raw) > _MAX_EVIDENCE_BYTES or _byte_digest(raw) != binding.artifact_digest:
            raise ValueError("VAL-01 prerequisite bytes differ from the current binding")
        payload = read_published_json(path, root=root, label=f"VAL-01 {binding.kind} prerequisite")
        if not isinstance(payload, dict):
            raise ValueError("VAL-01 prerequisite must be a JSON object")
        _verify_current_prerequisite(root, binding.kind, path, payload, current)
        identity = payload.get(
            "result_id", payload.get("receipt_id", payload.get("content_digest"))
        )
        if identity != binding.result_id:
            raise ValueError("VAL-01 prerequisite result identity mismatch")
        if payload.get("content_digest") != binding.content_digest:
            raise ValueError("VAL-01 prerequisite content identity mismatch")
        if payload.get("status") in {"blocked", "failed", "cancelled", "unsupported"}:
            raise ValueError("VAL-01 prerequisite has a non-qualifying terminal status")
        claims = payload.get("claims")
        if isinstance(claims, dict) and claims.get("blocked") is True:
            raise ValueError("VAL-01 prerequisite carries a blocking claim")
        for expected_identity in (
            request.client_id,
            request.workload_id,
            request.run_id,
            request.source.snapshot_digest,
            request.target.snapshot_digest,
        ):
            if not _contains_scalar(payload, expected_identity):
                raise ValueError(
                    "VAL-01 prerequisite scope/snapshot binding disagrees with request"
                )
        observed_at = _evidence_time(payload)
        evaluated_at = datetime.fromisoformat(request.evaluated_at.removesuffix("Z") + "+00:00")
        if observed_at is None or observed_at > datetime.now(UTC):
            raise ValueError("VAL-01 prerequisite freshness evidence is missing or future-dated")
        age = (evaluated_at - observed_at).total_seconds()
        if age < 0 or age > request.maximum_evidence_age_seconds:
            raise ValueError("VAL-01 prerequisite evidence is stale or newer than request")
        _assert_safe(payload)
        loaded.append(expected)
        if contexts[binding.kind] != binding:
            raise ValueError("VAL-01 prerequisite context binding mismatch")
    return sorted(loaded, key=lambda item: item["kind"])


def _verify_receipt(
    receipt: dict[str, Any], request_digest: str, policy_digest: str, runtime: RuntimeManifest
) -> None:
    _validate("val01-comparator-receipt.schema.json", receipt)
    if receipt["request_digest"] != request_digest or receipt["policy_digest"] != policy_digest:
        raise ValueError("VAL-01 comparator receipt is not request/policy bound")
    if receipt["runtime_manifest_digest"] != runtime.digest:
        raise ValueError("VAL-01 comparator receipt is not runtime bound")
    if (
        receipt["provider_id"] != runtime.provider_id
        or receipt["provider_version"] != runtime.provider_version
    ):
        raise ValueError("VAL-01 comparator provider differs from runtime manifest")
    if (
        receipt["authority_id"] != runtime.authority_id
        or receipt["authority_digest"] != runtime.authority_digest
    ):
        raise ValueError("VAL-01 comparator authority is untrusted")
    if receipt["proof"] is None:
        if (
            receipt["state"] != "unavailable"
            or receipt["reason"] != "comparator_runtime_unavailable"
        ):
            raise ValueError("VAL-01 unsigned comparator receipt is not an unavailable blocker")
        _assert_safe(receipt)
        return
    verify_proof(
        receipt,
        trusted_keys={runtime.verification_key_id: runtime.verification_key},
        allowed_key_ids={runtime.verification_key_id},
    )
    _assert_safe(receipt)


def _blocked_receipt(
    request_digest: str, policy_digest: str, runtime: RuntimeManifest
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_digest": request_digest,
        "policy_digest": policy_digest,
        "runtime_manifest_digest": runtime.digest,
        "provider_id": runtime.provider_id,
        "provider_version": runtime.provider_version,
        "authority_id": runtime.authority_id,
        "authority_digest": runtime.authority_digest,
        "state": "unavailable",
        "reason": "comparator_runtime_unavailable",
        "source_count": None,
        "target_count": None,
        "matched_count": None,
        "source_only_count": None,
        "target_only_count": None,
        "cell_mismatch_count": None,
        "duplicate_key_count": None,
        "null_key_count": None,
        "primary_match": None,
        "datacompy_match": None,
        "mismatch_references": [],
        "proof": None,
    }


def _counts_match_policy(receipt: Mapping[str, Any], policy: ValidationPolicy) -> bool:
    required_zero = ["source_only_count", "target_only_count", "cell_mismatch_count"]
    if policy.duplicate_policy == "reject":
        required_zero.append("duplicate_key_count")
    if policy.null_key_policy == "reject":
        required_zero.append("null_key_count")
    return all(receipt[name] == 0 for name in required_zero)


def evaluate_val01(
    root: Path,
    request: ValidationRequest,
    policy: ValidationPolicy,
    trust_policy: RuntimeTrustPolicy,
    runtime: RuntimeManifest,
    comparator: SparkDataComPyComparator | SyntheticComparator | None,
    current_evidence: CurrentEvidence,
    *,
    cancelled: CancellationToken = lambda: False,
) -> dict[str, Any]:
    request_payload, policy_payload = request.to_dict(), policy.to_dict()
    runtime_payload = runtime.public_payload()
    if request.policy_digest != _digest(policy_payload):
        raise ValueError("VAL-01 request does not bind the active policy")
    if request.runtime_manifest_digest != runtime.digest:
        raise ValueError("VAL-01 request does not bind the active runtime manifest")
    if request.trust_policy_digest != trust_policy.digest:
        raise ValueError("VAL-01 request does not bind the active runtime trust policy")
    if runtime.evidence_class == "qualified_runtime" and not trust_policy.authorizes(runtime):
        raise ValueError("VAL-01 runtime is not independently allowlisted")
    prerequisite_bindings = _load_prerequisites(root, request, current_evidence)
    request_digest, policy_digest = _digest(request_payload), _digest(policy_payload)
    if cancelled():
        status: Status = "cancelled"
        receipt: dict[str, Any] | None = None
        blockers = ["cancelled_before_comparison"]
    elif comparator is None:
        status = "blocked"
        receipt = _blocked_receipt(request_digest, policy_digest, runtime)
        blockers = ["comparator_runtime_unavailable"]
    else:
        if type(comparator) not in {SparkDataComPyComparator, SyntheticComparator}:
            raise TypeError("VAL-01 comparator must be an exact built-in adapter")
        if (
            runtime.evidence_class == "qualified_runtime"
            and type(comparator) is not SparkDataComPyComparator
        ):
            raise TypeError("VAL-01 qualified claims require the built-in Spark/DataComPy adapter")
        receipt = comparator.compare(request, policy, runtime)
        if cancelled():
            status = "cancelled"
            receipt = None
            blockers = ["cancelled_after_comparison"]
        else:
            _verify_receipt(receipt, request_digest, policy_digest, runtime)
            reason = receipt["reason"]
            blockers = [reason] if receipt["state"] == "unavailable" else []
            if receipt["state"] == "unsupported":
                status = "unsupported"
            elif blockers:
                status = "blocked"
            else:
                counts_match = _counts_match_policy(receipt, policy)
                comparator_agrees = receipt["primary_match"] == receipt["datacompy_match"]
                status = (
                    "passed"
                    if counts_match and comparator_agrees and receipt["primary_match"]
                    else "failed"
                )
                if not comparator_agrees:
                    blockers.append("independent_comparator_disagreement")
                if status == "passed":
                    status = "blocked"
                    blockers.extend(
                        ["runtime_authority_unavailable", "snapshot_authority_unavailable"]
                    )
    # This bounded increment intentionally has no authority-producing path.
    # Comparator mechanics can be exercised, but only independently acquired
    # governed runtime and snapshot provider records may unlock these claims.
    qualified_pass = False
    projection = {
        "schema_version": "1.0",
        "request": request_payload,
        "request_digest": request_digest,
        "policy": policy_payload,
        "policy_digest": policy_digest,
        "runtime_manifest": runtime_payload,
        "runtime_manifest_digest": runtime.digest,
        "trust_policy": trust_policy.public_payload(),
        "trust_policy_digest": trust_policy.digest,
        "prerequisite_bindings": prerequisite_bindings,
        "receipt": receipt,
        "status": status,
        "blockers": sorted(set(blockers)),
        "claims": {
            "generated": False,
            "executed": False,
            "validated": qualified_pass,
            "full_row_comparison_passed": qualified_pass,
            "cell_parity_passed": qualified_pass,
            "data_parity_passed": qualified_pass,
            "certified": False,
            "human_approved": False,
            "humana_validated": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_val01_result(
        root,
        result,
        policy=policy,
        trust_policy=trust_policy,
        runtime=runtime,
        current_evidence=current_evidence,
    )
    return result


def verify_val01_result(
    root: Path,
    result: dict[str, Any],
    *,
    policy: ValidationPolicy,
    trust_policy: RuntimeTrustPolicy,
    runtime: RuntimeManifest,
    current_evidence: CurrentEvidence,
) -> None:
    _validate("val01-result.schema.json", result)
    _assert_safe(result)
    content = dict(result)
    observed_digest = content.pop("content_digest")
    if observed_digest != _digest(content):
        raise ValueError("VAL-01 result content digest mismatch")
    projection = dict(content)
    observed_id = projection.pop("result_id")
    if observed_id != _digest(projection):
        raise ValueError("VAL-01 result identity mismatch")
    raw_request = cast(dict[str, Any], result["request"])
    request = ValidationRequest(
        client_id=raw_request["client_id"],
        workload_id=raw_request["workload_id"],
        run_id=raw_request["run_id"],
        attempt_id=raw_request["attempt_id"],
        evaluated_at=raw_request["evaluated_at"],
        source=SnapshotBinding(**raw_request["source"]),
        target=SnapshotBinding(**raw_request["target"]),
        prerequisites=tuple(EvidenceBinding(**item) for item in raw_request["prerequisites"]),
        policy_digest=raw_request["policy_digest"],
        trust_policy_digest=raw_request["trust_policy_digest"],
        runtime_manifest_digest=raw_request["runtime_manifest_digest"],
        maximum_evidence_age_seconds=raw_request["maximum_evidence_age_seconds"],
    )
    if result["request_digest"] != _digest(request.to_dict()):
        raise ValueError("VAL-01 request digest mismatch")
    if result["policy"] != policy.to_dict() or result["policy_digest"] != _digest(policy.to_dict()):
        raise ValueError("VAL-01 active policy differs from result")
    if (
        result["runtime_manifest"] != runtime.public_payload()
        or result["runtime_manifest_digest"] != runtime.digest
    ):
        raise ValueError("VAL-01 active runtime differs from result")
    if (
        result["trust_policy"] != trust_policy.public_payload()
        or result["trust_policy_digest"] != trust_policy.digest
    ):
        raise ValueError("VAL-01 active runtime trust policy differs from result")
    if result["prerequisite_bindings"] != _load_prerequisites(root, request, current_evidence):
        raise ValueError("VAL-01 current prerequisite evidence differs from result")
    receipt = result["receipt"]
    if receipt is None:
        if result["status"] != "cancelled" or result["blockers"] not in (
            ["cancelled_before_comparison"],
            ["cancelled_after_comparison"],
        ):
            raise ValueError("VAL-01 cancelled result is inconsistent")
    elif receipt.get("proof") is None:
        expected = _blocked_receipt(result["request_digest"], result["policy_digest"], runtime)
        if (
            receipt != expected
            or result["status"] != "blocked"
            or result["blockers"] != ["comparator_runtime_unavailable"]
        ):
            raise ValueError("VAL-01 unsigned runtime blocker is inconsistent")
    else:
        _verify_receipt(receipt, result["request_digest"], result["policy_digest"], runtime)
        reason = receipt["reason"]
        if receipt["state"] == "unavailable":
            expected_status, expected_blockers = "blocked", [reason]
        elif receipt["state"] == "unsupported":
            expected_status, expected_blockers = "unsupported", []
        else:
            counts_match = _counts_match_policy(receipt, policy)
            agreement = receipt["primary_match"] == receipt["datacompy_match"]
            expected_status = (
                "passed" if counts_match and agreement and receipt["primary_match"] else "failed"
            )
            expected_blockers = [] if agreement else ["independent_comparator_disagreement"]
            if expected_status == "passed":
                expected_status = "blocked"
                expected_blockers = [
                    "runtime_authority_unavailable",
                    "snapshot_authority_unavailable",
                ]
        if result["status"] != expected_status or result["blockers"] != expected_blockers:
            raise ValueError("VAL-01 terminal disposition differs from the comparator receipt")
        if len(receipt["mismatch_references"]) > policy.maximum_mismatch_references:
            raise ValueError("VAL-01 mismatch evidence exceeds the active policy bound")
    claims = result["claims"]
    qualified_pass = False
    for name in (
        "validated",
        "full_row_comparison_passed",
        "cell_parity_passed",
        "data_parity_passed",
    ):
        if claims[name] is not qualified_pass:
            raise ValueError("VAL-01 scoped validation claim is inconsistent")
    if any(
        claims[name]
        for name in (
            "generated",
            "executed",
            "certified",
            "human_approved",
            "humana_validated",
            "production_ready",
            "migration_complete",
        )
    ):
        raise ValueError("VAL-01 result contains a prohibited claim")


def result_path(root: Path, request: ValidationRequest) -> Path:
    request.to_dict()
    return (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.attempt_id
        / "val01"
        / "result.json"
    )


def publish_val01_result(
    root: Path,
    request: ValidationRequest,
    policy: ValidationPolicy,
    trust_policy: RuntimeTrustPolicy,
    runtime: RuntimeManifest,
    comparator: SparkDataComPyComparator | SyntheticComparator | None,
    current_evidence: CurrentEvidence,
    *,
    cancelled: CancellationToken = lambda: False,
) -> Path:
    result = evaluate_val01(
        root,
        request,
        policy,
        trust_policy,
        runtime,
        comparator,
        current_evidence,
        cancelled=cancelled,
    )
    if result["status"] == "cancelled" or cancelled():
        raise RuntimeError("VAL-01 publication cancelled")
    path = result_path(root, request)
    publish_json(path, result, "VAL-01 result", root=root)
    loaded = read_published_json(path, root=root, label="VAL-01 result")
    if not isinstance(loaded, dict):
        raise ValueError("Published VAL-01 result must be an object")
    verify_val01_result(
        root,
        loaded,
        policy=policy,
        trust_policy=trust_policy,
        runtime=runtime,
        current_evidence=current_evidence,
    )
    if loaded != result:
        raise ValueError("Published VAL-01 result differs from candidate")
    return path


class SparkDataComPyComparator:
    """Qualified runtime adapter; imports Spark/DataComPy only at the governed boundary."""

    def __init__(
        self,
        source_frame: Any,
        target_frame: Any,
        source_binding: SnapshotBinding,
        target_binding: SnapshotBinding,
        signing_key_path: Path,
    ) -> None:
        self._source = source_frame
        self._target = target_frame
        self._source_binding = source_binding
        self._target_binding = target_binding
        self._signing_key_path = signing_key_path

    @staticmethod
    def runtime_available(runtime: RuntimeManifest) -> bool:
        try:
            pyspark = importlib.import_module("pyspark")
            datacompy = importlib.import_module("datacompy")
            importlib.import_module("datacompy.spark")
        except (ImportError, ModuleNotFoundError):
            return False
        return (
            getattr(pyspark, "__version__", None) == runtime.spark_version
            and getattr(datacompy, "__version__", None) == runtime.datacompy_version
        )

    def compare(
        self,
        request: ValidationRequest,
        policy: ValidationPolicy,
        runtime: RuntimeManifest,
    ) -> dict[str, Any]:
        if not self.runtime_available(runtime):
            receipt = _blocked_receipt(
                _digest(request.to_dict()), _digest(policy.to_dict()), runtime
            )
            _verify_receipt(receipt, _digest(request.to_dict()), _digest(policy.to_dict()), runtime)
            return receipt
        if self._source_binding != request.source or self._target_binding != request.target:
            raise ValueError("VAL-01 runtime frames are not bound to the requested snapshots")
        receipt = self._compare_distributed(request, policy, runtime)
        sign_payload(
            receipt,
            private_key_path=self._signing_key_path,
            key_id=runtime.verification_key_id,
        )
        _verify_receipt(receipt, _digest(request.to_dict()), _digest(policy.to_dict()), runtime)
        return receipt

    def _receipt(
        self,
        request: ValidationRequest,
        policy: ValidationPolicy,
        runtime: RuntimeManifest,
        *,
        state: Literal["observed", "unavailable", "unsupported"],
        reason: str,
        counts: Mapping[str, int] | None = None,
        primary_match: bool | None = None,
        datacompy_match: bool | None = None,
        mismatch_references: Sequence[dict[str, str]] = (),
    ) -> dict[str, Any]:
        values = counts or {}
        return {
            "schema_version": "1.0",
            "request_digest": _digest(request.to_dict()),
            "policy_digest": _digest(policy.to_dict()),
            "runtime_manifest_digest": runtime.digest,
            "provider_id": runtime.provider_id,
            "provider_version": runtime.provider_version,
            "authority_id": runtime.authority_id,
            "authority_digest": runtime.authority_digest,
            "state": state,
            "reason": reason,
            "source_count": values.get("source_count"),
            "target_count": values.get("target_count"),
            "matched_count": values.get("matched_count"),
            "source_only_count": values.get("source_only_count"),
            "target_only_count": values.get("target_only_count"),
            "cell_mismatch_count": values.get("cell_mismatch_count"),
            "duplicate_key_count": values.get("duplicate_key_count"),
            "null_key_count": values.get("null_key_count"),
            "primary_match": primary_match,
            "datacompy_match": datacompy_match,
            "mismatch_references": list(mismatch_references),
            "proof": None,
        }

    @staticmethod
    def _one(frame: Any) -> Any:
        return next(iter(frame.limit(1).toLocalIterator()), None)

    @classmethod
    def _count(cls, frame: Any) -> int:
        row = cls._one(frame.selectExpr("count(*) AS value"))
        if row is None:
            raise ValueError("VAL-01 distributed scalar aggregate is unavailable")
        return int(row["value"])

    def _compare_distributed(
        self, request: ValidationRequest, policy: ValidationPolicy, runtime: RuntimeManifest
    ) -> dict[str, Any]:
        functions = importlib.import_module("pyspark.sql.functions")
        window_module = importlib.import_module("pyspark.sql.window")
        spark_compare = importlib.import_module("datacompy.spark")
        source, target = self._source, self._target
        governed = set(policy.key_columns) | {column.name for column in policy.columns}
        if set(source.columns) != governed or set(target.columns) != governed:
            return self._receipt(
                request, policy, runtime, state="unsupported", reason="policy_unsupported"
            )
        null_source = source.where(
            reduce(
                lambda left, right: left | right,
                (functions.col(name).isNull() for name in policy.key_columns),
            )
        )
        null_target = target.where(
            reduce(
                lambda left, right: left | right,
                (functions.col(name).isNull() for name in policy.key_columns),
            )
        )
        null_count = self._count(null_source) + self._count(null_target)
        source_dupes = source.groupBy(*policy.key_columns).count().where(functions.col("count") > 1)
        target_dupes = target.groupBy(*policy.key_columns).count().where(functions.col("count") > 1)
        duplicate_count = self._count(source_dupes) + self._count(target_dupes)
        base_counts = {
            "source_count": self._count(source),
            "target_count": self._count(target),
            "duplicate_key_count": duplicate_count,
            "null_key_count": null_count,
        }
        if null_count and policy.null_key_policy == "reject":
            return self._receipt(
                request,
                policy,
                runtime,
                state="observed",
                reason="null_keys",
                counts=base_counts,
                primary_match=False,
                datacompy_match=False,
            )
        join_keys = list(policy.key_columns)
        if policy.order_policy == "ordered":
            source_order_dupes = (
                source.groupBy(*policy.order_columns).count().where(functions.col("count") > 1)
            )
            target_order_dupes = (
                target.groupBy(*policy.order_columns).count().where(functions.col("count") > 1)
            )
            if self._count(source_order_dupes) or self._count(target_order_dupes):
                return self._receipt(
                    request,
                    policy,
                    runtime,
                    state="unsupported",
                    reason="policy_unsupported",
                    counts=base_counts,
                    primary_match=False,
                    datacompy_match=False,
                )
            ordered_window = window_module.Window.orderBy(
                *(functions.col(name).asc_nulls_first() for name in policy.order_columns)
            )
            source = source.withColumn("_val01_order", functions.row_number().over(ordered_window))
            target = target.withColumn("_val01_order", functions.row_number().over(ordered_window))
            join_keys.append("_val01_order")
        if duplicate_count:
            if policy.duplicate_policy == "reject":
                return self._receipt(
                    request,
                    policy,
                    runtime,
                    state="observed",
                    reason="duplicate_keys",
                    counts=base_counts,
                    primary_match=False,
                    datacompy_match=False,
                )
            order = [functions.col(name).asc_nulls_first() for name in policy.tie_break_columns]
            tie_source = (
                source.groupBy(*policy.key_columns, *policy.tie_break_columns)
                .count()
                .where(functions.col("count") > 1)
            )
            tie_target = (
                target.groupBy(*policy.key_columns, *policy.tie_break_columns)
                .count()
                .where(functions.col("count") > 1)
            )
            if self._count(tie_source) or self._count(tie_target):
                return self._receipt(
                    request,
                    policy,
                    runtime,
                    state="unsupported",
                    reason="policy_unsupported",
                    counts=base_counts,
                    primary_match=False,
                    datacompy_match=False,
                )
            window = window_module.Window.partitionBy(*policy.key_columns).orderBy(*order)
            source = source.withColumn("_val01_ordinal", functions.row_number().over(window))
            target = target.withColumn("_val01_ordinal", functions.row_number().over(window))
            join_keys.append("_val01_ordinal")
        compare_columns = [
            column
            for column in policy.columns
            if column.name not in policy.nondeterministic_exclusions
        ]
        source_types, target_types = dict(source.dtypes), dict(target.dtypes)
        for column in compare_columns:
            if column.logical_type in {"date", "timestamp"} or column.sas_missing != "distinct":
                # These rules require an authoritative provider normalization receipt;
                # raw Spark column shape alone cannot establish SAS semantics.
                return self._receipt(
                    request, policy, runtime, state="unsupported", reason="policy_unsupported"
                )
            source_value = functions.col(column.name)
            target_value = functions.col(column.name)
            source_type = source_types[column.name]
            target_type = target_types[column.name]
            if not _coercion_pair_allowed(
                column.logical_type, source_type, target_type, column.coercion
            ):
                return self._receipt(
                    request,
                    policy,
                    runtime,
                    state="unsupported",
                    reason="policy_unsupported",
                    counts=base_counts,
                    primary_match=False,
                    datacompy_match=False,
                )
            if column.coercion == "source_to_target":
                original = source_value
                source_value = source_value.cast(target_type)
                round_trip = source_value.cast(source_type)
                coercion_loss = original.isNotNull() & (
                    source_value.isNull() | ~original.eqNullSafe(round_trip)
                )
                if self._count(source.where(coercion_loss)):
                    return self._receipt(
                        request,
                        policy,
                        runtime,
                        state="unsupported",
                        reason="policy_unsupported",
                        counts=base_counts,
                        primary_match=False,
                        datacompy_match=False,
                    )
            elif column.coercion == "target_to_source":
                original = target_value
                target_value = target_value.cast(source_type)
                round_trip = target_value.cast(target_type)
                coercion_loss = original.isNotNull() & (
                    target_value.isNull() | ~original.eqNullSafe(round_trip)
                )
                if self._count(target.where(coercion_loss)):
                    return self._receipt(
                        request,
                        policy,
                        runtime,
                        state="unsupported",
                        reason="policy_unsupported",
                        counts=base_counts,
                        primary_match=False,
                        datacompy_match=False,
                    )
            if column.string_policy in {"trim", "trim_casefold"}:
                source_value, target_value = (
                    functions.trim(source_value),
                    functions.trim(target_value),
                )
            if column.string_policy == "trim_casefold":
                source_value, target_value = (
                    functions.lower(source_value),
                    functions.lower(target_value),
                )
            if column.logical_type in {"date", "timestamp"}:
                session_timezone = str(source.sparkSession.conf.get("spark.sql.session.timeZone"))
                if session_timezone != column.timezone:
                    return self._receipt(
                        request,
                        policy,
                        runtime,
                        state="unsupported",
                        reason="policy_unsupported",
                        counts=base_counts,
                        primary_match=False,
                        datacompy_match=False,
                    )
            source = source.withColumn(column.name, source_value)
            target = target.withColumn(column.name, target_value)
        source = source.select(*join_keys, *(column.name for column in compare_columns)).withColumn(
            "_val01_source", functions.lit(True)
        )
        target = target.select(*join_keys, *(column.name for column in compare_columns)).withColumn(
            "_val01_target", functions.lit(True)
        )
        left, right = source.alias("source"), target.alias("target")
        conditions = []
        for name in join_keys:
            left_key, right_key = functions.col(f"source.{name}"), functions.col(f"target.{name}")
            conditions.append(
                left_key.eqNullSafe(right_key)
                if policy.null_key_policy == "match"
                else left_key == right_key
            )
        condition = reduce(lambda lhs, rhs: lhs & rhs, conditions)
        joined_raw = left.join(right, condition, "full_outer")
        projections = [
            functions.col(f"source.{name}").alias(f"_key_source_{index}")
            for index, name in enumerate(policy.key_columns)
        ] + [
            functions.col(f"target.{name}").alias(f"_key_target_{index}")
            for index, name in enumerate(policy.key_columns)
        ]
        for index, column in enumerate(compare_columns):
            projections.extend(
                (
                    functions.col(f"source.{column.name}").alias(f"_source_value_{index}"),
                    functions.col(f"target.{column.name}").alias(f"_target_value_{index}"),
                )
            )
        projections.extend(
            (
                functions.col("source._val01_source").alias("_source_present"),
                functions.col("target._val01_target").alias("_target_present"),
            )
        )
        joined = joined_raw.select(*projections)
        source_present = functions.col("_source_present").isNotNull()
        target_present = functions.col("_target_present").isNotNull()
        both = source_present & target_present
        mismatch_expressions: list[tuple[str, Any]] = []
        abs_tolerance: dict[str, float] = {}
        rel_tolerance: dict[str, float] = {}
        for index, column in enumerate(compare_columns):
            source_value = functions.col(f"_source_value_{index}")
            target_value = functions.col(f"_target_value_{index}")
            if column.logical_type in {"integer", "decimal", "float"}:
                absolute_decimal = Decimal(column.absolute_tolerance)
                relative_decimal = Decimal(column.relative_tolerance)
                # Decimal arithmetic makes the policy boundary deterministic instead of
                # allowing binary-float rounding to move a value across it. Relative
                # tolerance is explicitly measured against the target absolute value,
                # matching the established VAL-01/DataComPy policy contract.
                source_decimal = source_value.cast("decimal(38,18)")
                target_decimal = target_value.cast("decimal(38,18)")
                tolerance = functions.lit(absolute_decimal) + functions.lit(
                    relative_decimal
                ) * functions.abs(target_decimal)
                finite_equal = functions.abs(source_decimal - target_decimal) <= tolerance
                if column.logical_type == "float":
                    source_nan = functions.isnan(source_value)
                    target_nan = functions.isnan(target_value)
                    source_infinite = (source_value == functions.lit(float("inf"))) | (
                        source_value == functions.lit(float("-inf"))
                    )
                    target_infinite = (target_value == functions.lit(float("inf"))) | (
                        target_value == functions.lit(float("-inf"))
                    )
                    finite_equal = finite_equal & ~(
                        source_nan | target_nan | source_infinite | target_infinite
                    )
                    equal = finite_equal
                    if column.nan_equal:
                        equal = equal | (source_nan & target_nan)
                    if column.infinity_equal:
                        equal = equal | (
                            source_infinite & target_infinite & (source_value == target_value)
                        )
                else:
                    equal = finite_equal
                # DataComPy's public API accepts only binary floats. Encode its
                # independent threshold with the bounded representation envelope
                # above so an exact decimal boundary is not rejected for rounding. The
                # primary exact-decimal comparator remains authoritative and both
                # comparators still must pass, so this cannot admit an out-of-policy
                # value.
                abs_tolerance[column.name] = _datacompy_float_tolerance(absolute_decimal)
                rel_tolerance[column.name] = _datacompy_float_tolerance(relative_decimal)
            else:
                equal = source_value == target_value
            if column.null_policy == "equal":
                equal = equal | (source_value.isNull() & target_value.isNull())
            mismatch_expressions.append(
                (column.name, both & ~functions.coalesce(equal, functions.lit(False)))
            )
        source_only = source_present & ~target_present
        target_only = target_present & ~source_present
        any_mismatch = reduce(
            lambda lhs, rhs: lhs | rhs,
            (expression for _, expression in mismatch_expressions),
            functions.lit(False),
        )
        counts = {
            **base_counts,
            "matched_count": self._count(joined.where(both)),
            "source_only_count": self._count(joined.where(source_only)),
            "target_only_count": self._count(joined.where(target_only)),
            "cell_mismatch_count": sum(
                self._count(joined.where(expression)) for _, expression in mismatch_expressions
            ),
        }
        references: list[dict[str, str]] = []
        diagnostic_columns = [
            functions.col(f"_key_source_{index}") for index, _ in enumerate(policy.key_columns)
        ] + [functions.col(f"_key_target_{index}") for index, _ in enumerate(policy.key_columns)]
        for index, (_, expression) in enumerate(mismatch_expressions):
            diagnostic_columns.extend(
                (
                    functions.col(f"_source_value_{index}"),
                    functions.col(f"_target_value_{index}"),
                    expression.alias(f"_mismatch_{index}"),
                )
            )
        mismatch_rows = (
            joined.where(any_mismatch)
            .select(*diagnostic_columns)
            .limit(policy.maximum_mismatch_references)
        )
        for row in mismatch_rows.toLocalIterator():
            key_values = [
                row[f"_key_source_{index}"]
                if row[f"_key_source_{index}"] is not None
                else row[f"_key_target_{index}"]
                for index, _ in enumerate(policy.key_columns)
            ]
            for index, (name, _) in enumerate(mismatch_expressions):
                if not row[f"_mismatch_{index}"]:
                    continue
                source_value = row[f"_source_value_{index}"]
                target_value = row[f"_target_value_{index}"]
                references.append(
                    {
                        "key_hmac": hmac_mismatch_key(key_values, runtime.mismatch_hmac_key),
                        "column": name,
                        "source_value_digest": hmac_mismatch_value(
                            "source", name, source_value, runtime.mismatch_hmac_key
                        ),
                        "target_value_digest": hmac_mismatch_value(
                            "target", name, target_value, runtime.mismatch_hmac_key
                        ),
                    }
                )
                if len(references) >= policy.maximum_mismatch_references:
                    break
            if len(references) >= policy.maximum_mismatch_references:
                break
        if len(references) < policy.maximum_mismatch_references:
            unmatched_rows = (
                joined.where(source_only | target_only)
                .select(
                    *(
                        functions.col(f"_key_source_{index}")
                        for index, _ in enumerate(policy.key_columns)
                    ),
                    *(
                        functions.col(f"_key_target_{index}")
                        for index, _ in enumerate(policy.key_columns)
                    ),
                    functions.col("_source_present"),
                    functions.col("_target_present"),
                )
                .limit(policy.maximum_mismatch_references - len(references))
            )
            for row in unmatched_rows.toLocalIterator():
                key_values = [
                    row[f"_key_source_{index}"]
                    if row[f"_key_source_{index}"] is not None
                    else row[f"_key_target_{index}"]
                    for index, _ in enumerate(policy.key_columns)
                ]
                references.append(
                    {
                        "key_hmac": hmac_mismatch_key(key_values, runtime.mismatch_hmac_key),
                        "column": "row-presence",
                        "source_value_digest": hmac_mismatch_value(
                            "source",
                            "row-presence",
                            row["_source_present"] is not None,
                            runtime.mismatch_hmac_key,
                        ),
                        "target_value_digest": hmac_mismatch_value(
                            "target",
                            "row-presence",
                            row["_target_present"] is not None,
                            runtime.mismatch_hmac_key,
                        ),
                    }
                )
        normalized_source = source.select(*join_keys, *(column.name for column in compare_columns))
        normalized_target = target.select(*join_keys, *(column.name for column in compare_columns))
        # DataComPy's built-in null/NaN/infinity equivalence is not permitted to
        # override a stricter configured VAL-01 policy. Side-bound marker columns
        # make those explicit differences independently visible to the cross-check.
        for index, column in enumerate(compare_columns):
            if column.null_policy == "different":
                marker = f"_val01_null_policy_{index}"
                normalized_source = normalized_source.withColumn(
                    marker, functions.col(column.name).isNull()
                )
                normalized_target = normalized_target.withColumn(marker, functions.lit(False))
            if column.logical_type == "float" and not column.nan_equal:
                marker = f"_val01_nan_policy_{index}"
                normalized_source = normalized_source.withColumn(
                    marker,
                    functions.coalesce(
                        functions.isnan(functions.col(column.name)), functions.lit(False)
                    ),
                )
                normalized_target = normalized_target.withColumn(marker, functions.lit(False))
            if column.logical_type == "float" and not column.infinity_equal:
                marker = f"_val01_infinity_policy_{index}"
                value = functions.col(column.name)
                normalized_source = normalized_source.withColumn(
                    marker,
                    functions.coalesce(
                        (value == functions.lit(float("inf")))
                        | (value == functions.lit(float("-inf"))),
                        functions.lit(False),
                    ),
                )
                normalized_target = normalized_target.withColumn(marker, functions.lit(False))
        datacompy = spark_compare.SparkSQLCompare(
            source.sparkSession,
            normalized_source,
            normalized_target,
            join_columns=join_keys,
            abs_tol=abs_tolerance,
            rel_tol=rel_tolerance,
            df1_name="source",
            df2_name="target",
            ignore_spaces=False,
            ignore_case=False,
            cast_column_names_lower=False,
            cache_intermediates=False,
        )
        required_zero = ["source_only_count", "target_only_count", "cell_mismatch_count"]
        if policy.duplicate_policy == "reject":
            required_zero.append("duplicate_key_count")
        if policy.null_key_policy == "reject":
            required_zero.append("null_key_count")
        primary_match = all(counts[name] == 0 for name in required_zero)
        return self._receipt(
            request,
            policy,
            runtime,
            state="observed",
            reason="observed",
            counts=counts,
            primary_match=primary_match,
            datacompy_match=bool(datacompy.matches(ignore_extra_columns=False)),
            mismatch_references=references,
        )


class SyntheticComparator:
    """Exact test-only adapter; its receipts can never authorize validation claims."""

    def __init__(
        self,
        receipt_factory: Callable[
            [ValidationRequest, ValidationPolicy, RuntimeManifest], dict[str, Any]
        ],
    ) -> None:
        self._receipt_factory = receipt_factory

    def compare(
        self, request: ValidationRequest, policy: ValidationPolicy, runtime: RuntimeManifest
    ) -> dict[str, Any]:
        if runtime.evidence_class != "synthetic_contract" or runtime.qualified:
            raise ValueError("VAL-01 synthetic comparator cannot use a qualified runtime")
        return self._receipt_factory(request, policy, runtime)


def hmac_mismatch_key(values: Sequence[object], key: bytes) -> str:
    """Tokenize bounded mismatch join keys before they enter evidence."""

    if len(key) < 32 or len(values) > _MAX_KEYS:
        raise ValueError("VAL-01 mismatch token input is invalid")
    encoded: list[dict[str, str]] = []
    for value in values:
        if value is None:
            item = {"type": "null", "value": ""}
        elif isinstance(value, bool):
            item = {"type": "boolean", "value": "true" if value else "false"}
        elif isinstance(value, int):
            item = {"type": "integer", "value": str(value)}
        elif isinstance(value, float) and math.isfinite(value):
            item = {"type": "float", "value": repr(value)}
        elif isinstance(value, Decimal) and value.is_finite():
            item = {"type": "decimal", "value": format(value.normalize(), "f")}
        elif isinstance(value, str):
            item = {"type": "string", "value": value}
        else:
            raise ValueError("VAL-01 mismatch key type is unsupported")
        encoded.append(item)
    return "hmac-sha256:" + hmac.new(key, _canonical(encoded), hashlib.sha256).hexdigest()


def hmac_mismatch_value(side: str, column: str, value: object, key: bytes) -> str:
    """Create a domain-separated, non-dictionary value locator for diagnostics."""

    if side not in {"source", "target"} or len(key) < 32:
        raise ValueError("VAL-01 mismatch value token input is invalid")
    _safe_id(column, "mismatch column")
    if value is None:
        item: dict[str, str] = {"type": "null", "value": ""}
    elif isinstance(value, bool):
        item = {"type": "boolean", "value": "true" if value else "false"}
    elif isinstance(value, int):
        item = {"type": "integer", "value": str(value)}
    elif isinstance(value, float):
        if math.isnan(value):
            item = {"type": "float", "value": "nan"}
        elif math.isinf(value):
            item = {"type": "float", "value": "+infinity" if value > 0 else "-infinity"}
        else:
            item = {"type": "float", "value": repr(value)}
    elif isinstance(value, Decimal) and value.is_finite():
        item = {"type": "decimal", "value": format(value.normalize(), "f")}
    elif isinstance(value, str):
        item = {"type": "string", "value": value}
    else:
        raise ValueError("VAL-01 mismatch value type is unsupported")
    payload = {
        "domain": "SMF-VAL-01-MISMATCH-VALUE-V1",
        "side": side,
        "column": column,
        "value": item,
    }
    return "hmac-sha256:" + hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
