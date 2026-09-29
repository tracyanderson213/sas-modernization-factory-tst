from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from jsonschema import Draft202012Validator

StructuralStatus = Literal["passed", "failed", "blocked"]
StructuralCheckStatus = Literal["pass", "fail", "blocked"]

_SUPPORTED_LOGICAL_TYPES = {
    "string",
    "integer",
    "bigint",
    "decimal",
    "float",
    "boolean",
    "date",
    "time",
    "datetime",
    "timestamp",
    "binary",
}
_KNOWN_NATIVE_TYPES = {
    "bigint",
    "binary",
    "boolean",
    "byte",
    "char",
    "character",
    "date",
    "datetime",
    "decimal",
    "double",
    "double precision",
    "float",
    "int",
    "integer",
    "long",
    "numeric",
    "real",
    "short",
    "smallint",
    "string",
    "time",
    "timestamp",
    "tinyint",
    "varbinary",
    "varchar",
}
_LENGTH_REQUIRED_NATIVE_TYPES = {"char", "character", "varchar", "varbinary"}
_UNBOUNDED_LENGTH_NATIVE_TYPES = {"string"}


def _load_schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"{name} must contain a JSON object")
    return cast(dict[str, Any], payload)


def _validate(payload: dict[str, Any], schema_name: str, label: str) -> None:
    errors = sorted(
        Draft202012Validator(_load_schema(schema_name)).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"{label} schema validation failed: {details}")


def _canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def calculate_snapshot_digest(payload: dict[str, Any]) -> str:
    """Calculate the digest for a snapshot payload, excluding its digest field."""
    content = dict(payload)
    content.pop("digest", None)
    return _canonical_digest(content)


def calculate_policy_digest(policy: StructuralParityPolicy) -> str:
    """Calculate the canonical digest of every policy field that affects comparison."""
    return _canonical_digest(policy.to_dict())


@dataclass(frozen=True)
class SchemaColumn:
    ordinal: int
    name: str
    logical_type: str
    native_type: str
    nullable: bool
    length: int | None = None
    precision: int | None = None
    scale: int | None = None


@dataclass(frozen=True)
class EvidenceProvenance:
    producer: str
    origin: str
    reference: str
    authoritative: bool


@dataclass(frozen=True)
class DatasetSchemaSnapshot:
    schema_version: str
    logical_dataset_id: str
    engine: str
    columns: tuple[SchemaColumn, ...]
    provenance: EvidenceProvenance
    digest: str
    metadata: dict[str, str | int | float | bool | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["columns"] = [asdict(column) for column in self.columns]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> DatasetSchemaSnapshot:
        validate_snapshot_payload(payload)
        provenance = cast(dict[str, Any], payload["provenance"])
        columns = cast(list[dict[str, Any]], payload["columns"])
        return cls(
            schema_version=cast(str, payload["schema_version"]),
            logical_dataset_id=cast(str, payload["logical_dataset_id"]),
            engine=cast(str, payload["engine"]),
            columns=tuple(SchemaColumn(**column) for column in columns),
            provenance=EvidenceProvenance(**provenance),
            digest=cast(str, payload["digest"]),
            metadata=cast(dict[str, str | int | float | bool | None], payload["metadata"]),
        )


@dataclass(frozen=True)
class TypeCompatibilityRule:
    rule_id: str
    source_logical_type: str
    source_native_type: str
    target_logical_type: str
    target_native_type: str


@dataclass(frozen=True)
class StructuralParityPolicy:
    schema_version: str = "1.0"
    policy_id: str = "smf.strict"
    policy_version: str = "1.0"
    case_sensitive_names: bool = False
    order_significant: bool = True
    allow_empty_schemas: bool = False
    nullability_rule: str = "exact"
    length_rule: str = "exact"
    precision_rule: str = "exact"
    scale_rule: str = "exact"
    type_mappings: tuple[TypeCompatibilityRule, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["type_mappings"] = [asdict(rule) for rule in self.type_mappings]
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> StructuralParityPolicy:
        validate_policy_payload(payload)
        rules = cast(list[dict[str, str]], payload["type_mappings"])
        return cls(
            schema_version=cast(str, payload["schema_version"]),
            policy_id=cast(str, payload["policy_id"]),
            policy_version=cast(str, payload["policy_version"]),
            case_sensitive_names=cast(bool, payload["case_sensitive_names"]),
            order_significant=cast(bool, payload["order_significant"]),
            allow_empty_schemas=cast(bool, payload["allow_empty_schemas"]),
            nullability_rule=cast(str, payload["nullability_rule"]),
            length_rule=cast(str, payload["length_rule"]),
            precision_rule=cast(str, payload["precision_rule"]),
            scale_rule=cast(str, payload["scale_rule"]),
            type_mappings=tuple(TypeCompatibilityRule(**rule) for rule in rules),
        )


@dataclass(frozen=True)
class StructuralParityRequest:
    source: DatasetSchemaSnapshot
    target: DatasetSchemaSnapshot
    policy: StructuralParityPolicy = field(default_factory=StructuralParityPolicy)
    output_dir: Path = Path("out")


@dataclass(frozen=True)
class StructuralCheck:
    code: str
    path: str
    expected: Any
    actual: Any
    applied_rule: str
    status: StructuralCheckStatus
    blocking: bool
    diagnostic: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StructuralParityResult:
    comparison_id: str
    policy: dict[str, str]
    source_evidence: dict[str, Any]
    target_evidence: dict[str, Any]
    status: StructuralStatus
    checks: list[StructuralCheck]
    schema_version: str = "1.0"
    warnings: list[str] = field(default_factory=list)
    output_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["checks"] = [check.to_dict() for check in self.checks]
        return payload


def validate_snapshot_payload(payload: dict[str, Any]) -> None:
    _validate(payload, "dataset-schema-snapshot.schema.json", "Dataset snapshot")
    columns = cast(list[dict[str, Any]], payload["columns"])
    ordinals = [column["ordinal"] for column in columns]
    if ordinals != list(range(1, len(columns) + 1)):
        raise ValueError("Dataset snapshot columns must have contiguous ordinals starting at 1")
    for column in columns:
        precision = cast(int | None, column["precision"])
        scale = cast(int | None, column["scale"])
        if precision is not None and scale is not None and scale > precision:
            raise ValueError(
                f"Dataset snapshot column {column['name']!r} has scale above precision"
            )


def validate_policy_payload(payload: dict[str, Any]) -> None:
    _validate(payload, "structural-parity-policy.schema.json", "Structural policy")
    rules = cast(list[dict[str, str]], payload["type_mappings"])
    identities: set[tuple[str, str, str, str]] = set()
    rule_ids: set[str] = set()
    for rule in rules:
        identity = (
            rule["source_logical_type"].casefold(),
            rule["source_native_type"].casefold(),
            rule["target_logical_type"].casefold(),
            rule["target_native_type"].casefold(),
        )
        if identity in identities or rule["rule_id"] in rule_ids:
            raise ValueError("Structural policy contains duplicate or ambiguous type mappings")
        identities.add(identity)
        rule_ids.add(rule["rule_id"])


def validate_structural_result_payload(payload: dict[str, Any]) -> None:
    _validate(payload, "structural-parity-result.schema.json", "Structural result")


def load_snapshot(path: Path) -> DatasetSchemaSnapshot:
    payload = _load_mapping(path)
    return DatasetSchemaSnapshot.from_dict(payload)


def load_policy(path: Path) -> StructuralParityPolicy:
    payload = _load_mapping(path)
    return StructuralParityPolicy.from_dict(payload)


def _load_mapping(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        if path.suffix.casefold() in {".yaml", ".yml"}:
            payload = yaml.safe_load(handle)
        else:
            payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain an object")
    return cast(dict[str, Any], payload)


def _evidence_reference(snapshot: DatasetSchemaSnapshot) -> dict[str, Any]:
    return {
        "logical_dataset_id": snapshot.logical_dataset_id,
        "engine": snapshot.engine,
        "digest": snapshot.digest,
        **asdict(snapshot.provenance),
    }


def _check(
    code: str,
    path: str,
    expected: Any,
    actual: Any,
    rule: str,
    matches: bool,
    diagnostic: str,
    *,
    blocked: bool = False,
) -> StructuralCheck:
    status: StructuralCheckStatus = "blocked" if blocked else ("pass" if matches else "fail")
    return StructuralCheck(code, path, expected, actual, rule, status, not matches, diagnostic)


def _normalized_name(name: str, policy: StructuralParityPolicy) -> str:
    return name if policy.case_sensitive_names else name.casefold()


def _duplicate_names(snapshot: DatasetSchemaSnapshot, policy: StructuralParityPolicy) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for column in snapshot.columns:
        identity = _normalized_name(column.name, policy)
        if identity in seen and identity not in duplicates:
            duplicates.append(identity)
        seen.add(identity)
    return duplicates


def _type_rule(
    source: SchemaColumn, target: SchemaColumn, policy: StructuralParityPolicy
) -> str | None:
    source_pair = (source.logical_type.casefold(), source.native_type.casefold())
    target_pair = (target.logical_type.casefold(), target.native_type.casefold())
    for rule in policy.type_mappings:
        if source_pair == (
            rule.source_logical_type.casefold(),
            rule.source_native_type.casefold(),
        ) and target_pair == (
            rule.target_logical_type.casefold(),
            rule.target_native_type.casefold(),
        ):
            return rule.rule_id
    if source_pair == target_pair:
        return "exact-logical-and-native-type"
    return None


def _attribute_matches(
    expected: int | None,
    actual: int | None,
    rule: str,
    *,
    actual_is_unbounded: bool = False,
) -> bool:
    if rule == "exact":
        return expected == actual
    if actual_is_unbounded:
        return True
    if expected is None or actual is None:
        return expected == actual
    return actual >= expected


def _missing_required_attributes(column: SchemaColumn) -> list[str]:
    """Return absent attributes needed to interpret a bounded native/logical type."""
    missing: list[str] = []
    native_type = column.native_type.casefold()
    logical_type = column.logical_type.casefold()
    if native_type in _LENGTH_REQUIRED_NATIVE_TYPES and column.length is None:
        missing.append("length")
    if logical_type == "decimal" or native_type in {"decimal", "numeric"}:
        if column.precision is None:
            missing.append("precision")
        if column.scale is None:
            missing.append("scale")
    return missing


def _compare_column(
    source: SchemaColumn, target: SchemaColumn, policy: StructuralParityPolicy
) -> list[StructuralCheck]:
    path = f"columns[{source.ordinal - 1}]({source.name})"
    source_supported = source.logical_type.casefold() in _SUPPORTED_LOGICAL_TYPES
    target_supported = target.logical_type.casefold() in _SUPPORTED_LOGICAL_TYPES
    explicit_rule = next(
        (
            rule
            for rule in policy.type_mappings
            if (
                source.logical_type.casefold(),
                source.native_type.casefold(),
                target.logical_type.casefold(),
                target.native_type.casefold(),
            )
            == (
                rule.source_logical_type.casefold(),
                rule.source_native_type.casefold(),
                rule.target_logical_type.casefold(),
                rule.target_native_type.casefold(),
            )
        ),
        None,
    )
    native_supported = (
        source.native_type.casefold() in _KNOWN_NATIVE_TYPES
        and target.native_type.casefold() in _KNOWN_NATIVE_TYPES
    ) or explicit_rule is not None
    supported = source_supported and target_supported and native_supported
    missing_attributes = {
        "source": _missing_required_attributes(source),
        "target": _missing_required_attributes(target),
    }
    sufficiently_described = not any(missing_attributes.values())
    checks = [
        _check(
            "SCHEMA-TYPE-UNSUPPORTED",
            f"{path}.logical_type",
            "supported logical type",
            {
                "source": {"logical": source.logical_type, "native": source.native_type},
                "target": {"logical": target.logical_type, "native": target.native_type},
            },
            "supported-logical-and-native-types-v1-or-explicit-mapping",
            supported,
            "Both logical types are supported"
            if supported
            else "Unsupported logical or native type blocks comparison",
            blocked=not supported,
        ),
        _check(
            "SCHEMA-TYPE-UNSUPPORTED",
            f"{path}.attributes",
            {"source": [], "target": []},
            missing_attributes,
            "required-type-attributes-v1",
            sufficiently_described,
            "Applicable type attributes are present"
            if sufficiently_described
            else "Missing length, precision, or scale prevents a safe type comparison",
            blocked=not sufficiently_described,
        ),
    ]
    type_rule = _type_rule(source, target, policy) if supported else None
    checks.append(
        _check(
            "SCHEMA-TYPE-INCOMPATIBLE",
            f"{path}.type",
            {"logical": source.logical_type, "native": source.native_type},
            {"logical": target.logical_type, "native": target.native_type},
            type_rule or "no-approved-type-mapping",
            type_rule is not None,
            "Types match an approved rule"
            if type_rule
            else "Declare an exact type mapping in a versioned policy",
        )
    )
    nullable_matches = source.nullable == target.nullable or (
        policy.nullability_rule == "target_may_be_nullable"
        and not source.nullable
        and target.nullable
    )
    checks.append(
        _check(
            "SCHEMA-NULLABILITY-MISMATCH",
            f"{path}.nullable",
            source.nullable,
            target.nullable,
            policy.nullability_rule,
            nullable_matches,
            "Nullability satisfies policy"
            if nullable_matches
            else "Target nullability violates policy",
        )
    )
    decimal_capacity_matches = True
    if (
        source.logical_type.casefold() == "decimal"
        and target.logical_type.casefold() == "decimal"
        and source.precision is not None
        and source.scale is not None
        and target.precision is not None
        and target.scale is not None
    ):
        decimal_capacity_matches = (
            target.precision - target.scale >= source.precision - source.scale
        )
    for attribute, code, rule in (
        ("length", "SCHEMA-LENGTH-MISMATCH", policy.length_rule),
        ("precision", "SCHEMA-PRECISION-MISMATCH", policy.precision_rule),
        ("scale", "SCHEMA-SCALE-MISMATCH", policy.scale_rule),
    ):
        expected = getattr(source, attribute)
        actual = getattr(target, attribute)
        target_is_unbounded = (
            attribute == "length"
            and target.length is None
            and target.native_type.casefold() in _UNBOUNDED_LENGTH_NATIVE_TYPES
        )
        matches = _attribute_matches(
            expected,
            actual,
            rule,
            actual_is_unbounded=target_is_unbounded,
        )
        if rule == "target_may_widen" and attribute in {"precision", "scale"}:
            matches = matches and decimal_capacity_matches
        checks.append(
            _check(
                code,
                f"{path}.{attribute}",
                expected,
                actual,
                rule,
                matches,
                f"{attribute.capitalize()} and decimal integral capacity satisfy policy"
                if matches and attribute in {"precision", "scale"} and rule == "target_may_widen"
                else f"{attribute.capitalize()} satisfies policy"
                if matches
                else f"Target {attribute} or decimal integral capacity violates policy"
                if attribute in {"precision", "scale"} and rule == "target_may_widen"
                else f"Target {attribute} violates policy",
            )
        )
    order_matches = not policy.order_significant or source.ordinal == target.ordinal
    checks.append(
        _check(
            "SCHEMA-ORDER-MISMATCH",
            f"{path}.ordinal",
            source.ordinal,
            target.ordinal,
            "significant" if policy.order_significant else "ignored",
            order_matches,
            "Column order satisfies policy" if order_matches else "Target column ordinal differs",
        )
    )
    return checks


def compare_snapshots(
    source: DatasetSchemaSnapshot,
    target: DatasetSchemaSnapshot,
    policy: StructuralParityPolicy,
) -> StructuralParityResult:
    validate_snapshot_payload(source.to_dict())
    validate_snapshot_payload(target.to_dict())
    validate_policy_payload(policy.to_dict())
    policy_digest = calculate_policy_digest(policy)
    identity_payload = {
        "source_digest": source.digest,
        "target_digest": target.digest,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy_digest,
    }
    checks: list[StructuralCheck] = []

    for role, snapshot in (("source", source), ("target", target)):
        authoritative = snapshot.provenance.authoritative
        checks.append(
            _check(
                "SCHEMA-EVIDENCE-MISSING",
                f"{role}.provenance.authoritative",
                True,
                authoritative,
                "authoritative-evidence-required",
                authoritative,
                "Evidence is authoritative"
                if authoritative
                else f"{role.capitalize()} evidence is not authoritative",
                blocked=not authoritative,
            )
        )
        calculated = calculate_snapshot_digest(snapshot.to_dict())
        digest_matches = calculated == snapshot.digest
        checks.append(
            _check(
                "SCHEMA-EVIDENCE-DIGEST",
                f"{role}.digest",
                calculated,
                snapshot.digest,
                "sha256-canonical-json-v1",
                digest_matches,
                "Evidence digest verified"
                if digest_matches
                else f"{role.capitalize()} evidence digest does not match content",
                blocked=not digest_matches,
            )
        )

    mapped = source.logical_dataset_id == target.logical_dataset_id
    checks.append(
        _check(
            "SCHEMA-DATASET-UNMAPPED",
            "logical_dataset_id",
            source.logical_dataset_id,
            target.logical_dataset_id,
            "exact-logical-dataset-id",
            mapped,
            "Datasets are explicitly mapped" if mapped else "Logical dataset identifiers differ",
            blocked=not mapped,
        )
    )
    if not policy.allow_empty_schemas and (not source.columns or not target.columns):
        checks.append(
            _check(
                "SCHEMA-EVIDENCE-MISSING",
                "columns",
                "at least one source and target column",
                {"source": len(source.columns), "target": len(target.columns)},
                "non-empty-schema-required",
                False,
                "Empty schema evidence is disallowed by policy",
                blocked=True,
            )
        )

    duplicates_found = False
    for role, snapshot in (("source", source), ("target", target)):
        duplicates = _duplicate_names(snapshot, policy)
        duplicates_found = duplicates_found or bool(duplicates)
        checks.append(
            _check(
                "SCHEMA-DUPLICATE-COLUMN",
                f"{role}.columns",
                [],
                duplicates,
                "case-sensitive" if policy.case_sensitive_names else "unicode-casefold",
                not duplicates,
                "Column identities are unique"
                if not duplicates
                else f"Duplicate {role} column identities are ambiguous",
                blocked=bool(duplicates),
            )
        )

    if not duplicates_found:
        targets = {_normalized_name(column.name, policy): column for column in target.columns}
        source_names = {_normalized_name(column.name, policy) for column in source.columns}
        for source_column in source.columns:
            identity = _normalized_name(source_column.name, policy)
            target_column = targets.get(identity)
            checks.append(
                _check(
                    "SCHEMA-COLUMN-MISSING",
                    f"columns[{source_column.ordinal - 1}]({source_column.name})",
                    source_column.name,
                    target_column.name if target_column else None,
                    "case-sensitive" if policy.case_sensitive_names else "unicode-casefold",
                    target_column is not None,
                    "Column is present"
                    if target_column
                    else "Expected source column is missing from target",
                )
            )
            if target_column is not None:
                checks.extend(_compare_column(source_column, target_column, policy))
        for target_column in target.columns:
            identity = _normalized_name(target_column.name, policy)
            if identity not in source_names:
                checks.append(
                    _check(
                        "SCHEMA-COLUMN-UNEXPECTED",
                        f"target.columns[{target_column.ordinal - 1}]({target_column.name})",
                        None,
                        target_column.name,
                        "one-to-one-column-match",
                        False,
                        "Target column has no source counterpart",
                    )
                )

    if any(check.status == "blocked" for check in checks):
        status: StructuralStatus = "blocked"
    elif any(check.status == "fail" for check in checks):
        status = "failed"
    else:
        status = "passed"
    result = StructuralParityResult(
        comparison_id=_canonical_digest(identity_payload),
        policy={
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "digest": policy_digest,
        },
        source_evidence=_evidence_reference(source),
        target_evidence=_evidence_reference(target),
        status=status,
        checks=checks,
    )
    validate_structural_result_payload(result.to_dict())
    return result


def compare_structural_schema(request: StructuralParityRequest) -> StructuralParityResult:
    result = compare_snapshots(request.source, request.target, request.policy)
    safe_dataset = re.sub(r"[^A-Za-z0-9._-]+", "-", request.source.logical_dataset_id).strip(".-")
    if not safe_dataset:
        safe_dataset = "dataset"
    manifest = request.output_dir / safe_dataset / "validation" / "structural-parity.manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    result.output_files.append(str(manifest))
    payload = result.to_dict()
    validate_structural_result_payload(payload)
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return result
