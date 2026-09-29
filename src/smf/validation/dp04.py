"""DP-04 distributed null, SAS special-missing, and distribution reconciliation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from smf.immutable_files import publish_json, read_published_json
from smf.security.ai_admission import contains_protected_data

ProfileSide = Literal["source", "target"]
ColumnKind = Literal["numeric", "categorical"]
SamplingMethod = Literal["exact", "deterministic_hash"]
EvidenceClass = Literal["synthetic_contract"]

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_SAS_MISSING_CODES = (".", "._", *(f".{letter}" for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
_MAX_POLICY_COLUMNS = 128
_MAX_BINS_PER_COLUMN = 256
_MAX_CATEGORIES_PER_COLUMN = 512
_MAX_SAMPLING_KEYS = 16
_MAX_PARTITIONS_PER_SIDE = 4096
_MAX_RESULT_CHECKS = _MAX_POLICY_COLUMNS * 10 + 2
_EVIDENCE_LIMITS = {
    "dp04-policy.schema.json": 1_048_576,
    "dp04-partition-profile.schema.json": 2_097_152,
    "dp04-result.schema.json": 16_777_216,
}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate DP-04 configuration key")
        result[key] = value
    return result


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("DP-04 schema must be an object")
    return cast(dict[str, Any], value)


def _validate(name: str, payload: dict[str, Any]) -> None:
    if len(_canonical_bytes(payload)) > _EVIDENCE_LIMITS[name]:
        raise ValueError("DP-04 evidence exceeds the governed byte bound")
    errors = sorted(
        Draft202012Validator(_schema(name), format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(map(str, error.absolute_path)) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"DP-04 schema validation failed: {details}")


def _safe_id(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."} or contains_protected_data(value):
        raise ValueError(f"Unsafe DP-04 {label}")
    return value


def _safe_text(value: str, label: str) -> str:
    if not value or len(value) > 256 or contains_protected_data(value):
        raise ValueError(f"Unsafe DP-04 {label}")
    return value


def _assert_persistable(value: Any) -> None:
    """Reject protected data before it can be hashed or persisted."""

    if isinstance(value, str):
        if contains_protected_data(value):
            raise ValueError("DP-04 evidence contains protected data")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _assert_persistable(key)
            _assert_persistable(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            _assert_persistable(item)


def _read_json(path: Path, schema_name: str) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            os.close(descriptor)
            raise ValueError("DP-04 governed input is not a regular file")
        if before.st_size > _EVIDENCE_LIMITS[schema_name]:
            os.close(descriptor)
            raise ValueError("DP-04 governed input exceeds the governed byte bound")
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(_EVIDENCE_LIMITS[schema_name] + 1)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError("DP-04 governed input is missing or unsafe") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise ValueError("DP-04 governed input changed while being read")
    if len(raw) > _EVIDENCE_LIMITS[schema_name]:
        raise ValueError("DP-04 governed input exceeds the governed byte bound")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DP-04 governed input is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError("DP-04 governed input must be an object")
    _validate(schema_name, value)
    return value


@dataclass(frozen=True)
class SasMissing:
    """Explicit SAS missing category; strings such as '.A' remain ordinary strings."""

    code: str

    def __post_init__(self) -> None:
        if self.code not in _SAS_MISSING_CODES:
            raise ValueError("Unsupported SAS missing-value category")


@dataclass(frozen=True)
class ColumnPolicy:
    name: str
    kind: ColumnKind
    numeric_bins: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    absolute_tolerance: str = "0"
    relative_tolerance: str = "0"


@dataclass(frozen=True)
class SamplingPolicy:
    method: SamplingMethod
    fraction: str
    seed: str
    key_columns: tuple[str, ...]


@dataclass(frozen=True)
class ReceiptAuthority:
    side: ProfileSide
    authority_id: str
    key_id: str
    provider_id: str
    provider_version: str
    evidence_class: EvidenceClass
    public_key: str


@dataclass(frozen=True)
class ProfilingPolicy:
    policy_id: str
    policy_version: str
    columns: tuple[ColumnPolicy, ...]
    sampling: SamplingPolicy
    receipt_authorities: tuple[ReceiptAuthority, ...]
    canonical: bytes
    digest: str


@dataclass(frozen=True)
class ProfileIdentity:
    client_id: str
    workload_id: str
    source_digest: str
    run_id: str
    attempt_id: str
    artifact_id: str
    snapshot_digest: str
    provider_id: str
    provider_version: str

    def payload(self) -> dict[str, str]:
        value = asdict(self)
        for field in ("client_id", "workload_id", "run_id", "attempt_id", "artifact_id"):
            _safe_id(value[field], field)
        for field in ("source_digest", "snapshot_digest"):
            if not _SHA.fullmatch(value[field]):
                raise ValueError(f"DP-04 {field} must be a SHA-256 digest")
        _safe_text(value["provider_id"], "provider_id")
        _safe_text(value["provider_version"], "provider_version")
        return cast(dict[str, str], value)


def load_policy(path: Path) -> ProfilingPolicy:
    payload = _read_json(path, "dp04-policy.schema.json")
    _safe_id(payload["policy_id"], "policy_id")
    _safe_id(payload["policy_version"], "policy_version")
    if len(payload["columns"]) > _MAX_POLICY_COLUMNS:
        raise ValueError("DP-04 policy column count exceeds the governed bound")
    names = [item["name"].casefold() for item in payload["columns"]]
    if len(names) != len(set(names)):
        raise ValueError("DP-04 policy contains duplicate or ambiguous columns")
    columns: list[ColumnPolicy] = []
    for item in payload["columns"]:
        bins = tuple(item["numeric_bins"])
        if len(bins) > _MAX_BINS_PER_COLUMN:
            raise ValueError("DP-04 numeric bin count exceeds the governed bound")
        if len(item["categories"]) > _MAX_CATEGORIES_PER_COLUMN:
            raise ValueError("DP-04 category count exceeds the governed bound")
        try:
            decimal_bins = tuple(Decimal(value) for value in bins)
            absolute = Decimal(item["absolute_tolerance"])
            relative = Decimal(item["relative_tolerance"])
        except InvalidOperation as exc:
            raise ValueError("DP-04 policy contains an invalid decimal") from exc
        if any(not value.is_finite() for value in (*decimal_bins, absolute, relative)):
            raise ValueError("DP-04 policy decimals must be finite")
        if list(decimal_bins) != sorted(set(decimal_bins)):
            raise ValueError("DP-04 numeric bins must be strictly increasing")
        if absolute < 0 or relative < 0:
            raise ValueError("DP-04 tolerances cannot be negative")
        if item["kind"] == "numeric" and not bins:
            raise ValueError("DP-04 numeric columns require declared bins")
        if item["kind"] == "categorical" and not item["categories"]:
            raise ValueError("DP-04 categorical columns require declared categories")
        if len(item["categories"]) != len(set(item["categories"])):
            raise ValueError("DP-04 categorical values must be unique")
        for category in item["categories"]:
            _safe_text(category, "declared category")
        columns.append(
            ColumnPolicy(
                name=item["name"],
                kind=item["kind"],
                numeric_bins=bins,
                categories=tuple(item["categories"]),
                absolute_tolerance=item["absolute_tolerance"],
                relative_tolerance=item["relative_tolerance"],
            )
        )
    sampling_value = payload["sampling"]
    fraction = Decimal(sampling_value["fraction"])
    if not fraction.is_finite() or fraction <= 0 or fraction > 1:
        raise ValueError("DP-04 sampling fraction must be within (0, 1]")
    if sampling_value["method"] == "exact" and fraction != 1:
        raise ValueError("DP-04 exact profiling requires fraction 1")
    if sampling_value["method"] == "deterministic_hash" and not sampling_value["key_columns"]:
        raise ValueError("DP-04 deterministic sampling requires key columns")
    if len(sampling_value["key_columns"]) > _MAX_SAMPLING_KEYS:
        raise ValueError("DP-04 sampling key count exceeds the governed bound")
    _safe_id(sampling_value["seed"], "sampling seed")
    authorities = _load_authorities(payload["receipt_authorities"])
    _assert_persistable(payload)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return ProfilingPolicy(
        policy_id=payload["policy_id"],
        policy_version=payload["policy_version"],
        columns=tuple(columns),
        sampling=SamplingPolicy(
            method=sampling_value["method"],
            fraction=sampling_value["fraction"],
            seed=sampling_value["seed"],
            key_columns=tuple(sampling_value["key_columns"]),
        ),
        receipt_authorities=authorities,
        canonical=canonical,
        digest=_digest(payload),
    )


def _policy_payload(policy: ProfilingPolicy) -> dict[str, Any]:
    try:
        payload = json.loads(policy.canonical, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DP-04 admitted policy is malformed") from exc
    if not isinstance(payload, dict) or _digest(payload) != policy.digest:
        raise ValueError("DP-04 policy changed after admission")
    _validate("dp04-policy.schema.json", payload)
    reconstructed = load_policy_from_payload(payload)
    if reconstructed != policy:
        raise ValueError("DP-04 policy object diverges from canonical policy")
    return payload


def load_policy_from_payload(payload: dict[str, Any]) -> ProfilingPolicy:
    """Reconstruct a policy without accepting a caller-authored dataclass projection."""

    # Validate through a temporary-free mirror of load_policy semantics.
    _validate("dp04-policy.schema.json", payload)
    if len(payload["columns"]) > _MAX_POLICY_COLUMNS:
        raise ValueError("DP-04 policy column count exceeds the governed bound")
    columns: list[ColumnPolicy] = []
    names: set[str] = set()
    for item in payload["columns"]:
        folded = item["name"].casefold()
        if folded in names:
            raise ValueError("DP-04 policy contains duplicate or ambiguous columns")
        names.add(folded)
        bins = tuple(item["numeric_bins"])
        if len(bins) > _MAX_BINS_PER_COLUMN:
            raise ValueError("DP-04 numeric bin count exceeds the governed bound")
        if len(item["categories"]) > _MAX_CATEGORIES_PER_COLUMN:
            raise ValueError("DP-04 category count exceeds the governed bound")
        decimals = tuple(Decimal(value) for value in bins)
        absolute = Decimal(item["absolute_tolerance"])
        relative = Decimal(item["relative_tolerance"])
        if any(not value.is_finite() for value in (*decimals, absolute, relative)):
            raise ValueError("DP-04 policy decimals must be finite")
        if list(decimals) != sorted(set(decimals)):
            raise ValueError("DP-04 numeric bins must be strictly increasing")
        if absolute < 0 or relative < 0:
            raise ValueError("DP-04 tolerances cannot be negative")
        if item["kind"] == "numeric" and not bins:
            raise ValueError("DP-04 numeric columns require declared bins")
        if item["kind"] == "categorical" and not item["categories"]:
            raise ValueError("DP-04 categorical columns require declared categories")
        if len(item["categories"]) != len(set(item["categories"])):
            raise ValueError("DP-04 categorical values must be unique")
        for category in item["categories"]:
            _safe_text(category, "declared category")
        columns.append(
            ColumnPolicy(
                name=item["name"],
                kind=item["kind"],
                numeric_bins=bins,
                categories=tuple(item["categories"]),
                absolute_tolerance=item["absolute_tolerance"],
                relative_tolerance=item["relative_tolerance"],
            )
        )
    sampling = payload["sampling"]
    fraction = Decimal(sampling["fraction"])
    if not fraction.is_finite() or fraction <= 0 or fraction > 1:
        raise ValueError("DP-04 sampling fraction must be within (0, 1]")
    if sampling["method"] == "exact" and fraction != 1:
        raise ValueError("DP-04 exact profiling requires fraction 1")
    if sampling["method"] == "deterministic_hash" and not sampling["key_columns"]:
        raise ValueError("DP-04 deterministic sampling requires key columns")
    if len(sampling["key_columns"]) > _MAX_SAMPLING_KEYS:
        raise ValueError("DP-04 sampling key count exceeds the governed bound")
    _safe_id(sampling["seed"], "sampling seed")
    authorities = _load_authorities(payload["receipt_authorities"])
    _safe_id(payload["policy_id"], "policy_id")
    _safe_id(payload["policy_version"], "policy_version")
    for column in columns:
        _safe_id(column.name, "column name")
    for key_column in sampling["key_columns"]:
        _safe_id(key_column, "sampling key column")
    _assert_persistable(payload)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return ProfilingPolicy(
        policy_id=payload["policy_id"],
        policy_version=payload["policy_version"],
        columns=tuple(columns),
        sampling=SamplingPolicy(
            method=sampling["method"],
            fraction=sampling["fraction"],
            seed=sampling["seed"],
            key_columns=tuple(sampling["key_columns"]),
        ),
        receipt_authorities=authorities,
        canonical=canonical,
        digest=_digest(payload),
    )


def _load_authorities(values: Sequence[dict[str, Any]]) -> tuple[ReceiptAuthority, ...]:
    authorities: list[ReceiptAuthority] = []
    identities: set[tuple[str, str]] = set()
    side_authorities: dict[str, set[str]] = {"source": set(), "target": set()}
    side_keys: dict[str, set[str]] = {"source": set(), "target": set()}
    side_material: dict[str, set[bytes]] = {"source": set(), "target": set()}
    for value in values:
        side = cast(ProfileSide, value["side"])
        authority_id = _safe_id(value["authority_id"], "receipt authority")
        key_id = _safe_id(value["key_id"], "receipt key")
        provider_id = _safe_text(value["provider_id"], "receipt provider")
        provider_version = _safe_text(value["provider_version"], "receipt provider version")
        identity = (authority_id, key_id)
        if identity in identities:
            raise ValueError("DP-04 receipt authority identities must be unique")
        identities.add(identity)
        try:
            public_key = base64.b64decode(value["public_key"], validate=True)
        except ValueError as exc:
            raise ValueError("DP-04 receipt authority key is malformed") from exc
        if len(public_key) != 32:
            raise ValueError("DP-04 receipt authority key is malformed")
        side_authorities[side].add(authority_id)
        side_keys[side].add(key_id)
        side_material[side].add(public_key)
        authorities.append(
            ReceiptAuthority(
                side,
                authority_id,
                key_id,
                provider_id,
                provider_version,
                value["evidence_class"],
                value["public_key"],
            )
        )
    if not authorities:
        raise ValueError("DP-04 requires at least one receipt authority")
    if not all(side_authorities.values()):
        raise ValueError("DP-04 source and target receipt authorities are required")
    if side_authorities["source"] & side_authorities["target"]:
        raise ValueError("DP-04 source and target authority domains must be distinct")
    if side_keys["source"] & side_keys["target"]:
        raise ValueError("DP-04 source and target key domains must be distinct")
    if side_material["source"] & side_material["target"]:
        raise ValueError("DP-04 source and target key material must be distinct")
    return tuple(authorities)


def _canonical_sampling_value(value: Any) -> dict[str, Any]:
    """Produce a closed, typed sampling key without caller-defined coercion."""

    if value is None:
        return {"type": "null", "value": None}
    if type(value) is bool:
        return {"type": "boolean", "value": value}
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            raise ValueError("DP-04 sampling integer exceeds the governed bound")
        return {"type": "integer", "value": str(value)}
    if type(value) is str:
        if len(value) > 512:
            raise ValueError("DP-04 sampling string exceeds the governed bound")
        _assert_persistable(value)
        return {"type": "string", "value": value}
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("DP-04 sampling decimal must be finite")
        canonical = "0" if value == 0 else format(value.normalize(), "f")
        if len(canonical) > 128:
            raise ValueError("DP-04 sampling decimal exceeds the governed bound")
        return {"type": "decimal", "value": canonical}
    if isinstance(value, SasMissing):
        return {"type": "sas_missing", "value": value.code}
    raise ValueError("DP-04 sampling key has an unsupported type")


def _selected(row: Mapping[str, Any], policy: ProfilingPolicy) -> tuple[bool, str]:
    if policy.sampling.method == "exact":
        return True, "0" * 64
    try:
        key = [_canonical_sampling_value(row[name]) for name in policy.sampling.key_columns]
    except KeyError as exc:
        raise ValueError("DP-04 sampling key is missing") from exc
    encoded = json.dumps(
        {"seed": policy.sampling.seed, "key": key},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    value = int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big")
    threshold = int(Decimal(policy.sampling.fraction) * Decimal(2**64))
    return value < threshold, hashlib.sha256(encoded).hexdigest()


def _sampling_payload(policy: ProfilingPolicy) -> dict[str, Any]:
    return {
        "method": policy.sampling.method,
        "fraction": policy.sampling.fraction,
        "seed": policy.sampling.seed,
        "key_columns": list(policy.sampling.key_columns),
    }


def _empty_column(column: ColumnPolicy) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": column.name,
        "kind": column.kind,
        "ordinary_null_count": 0,
        "sas_missing_counts": {code: 0 for code in _SAS_MISSING_CODES},
        "non_missing_count": 0,
        "all_missing": False,
    }
    if column.kind == "numeric":
        value.update(
            {
                "numeric_count": 0,
                "sum": "0",
                "sum_squares": "0",
                "minimum": None,
                "maximum": None,
                "bin_counts": [0] * (len(column.numeric_bins) + 1),
                "category_counts": {},
                "other_count": 0,
            }
        )
    else:
        value.update(
            {
                "numeric_count": 0,
                "sum": "0",
                "sum_squares": "0",
                "minimum": None,
                "maximum": None,
                "bin_counts": [],
                "category_counts": {category: 0 for category in column.categories},
                "other_count": 0,
            }
        )
    return value


def _receipt_unsigned_payload(profile: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in profile.items() if key not in {"content_digest", "signature"}
    }


def _receipt_signing_payload(profile: Mapping[str, Any]) -> bytes:
    payload = _receipt_unsigned_payload(profile)
    payload["content_digest"] = profile["content_digest"]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _authority_for(
    policy: ProfilingPolicy,
    *,
    side: ProfileSide,
    authority_id: str,
    key_id: str,
    provider_id: str,
    provider_version: str,
    evidence_class: str,
) -> ReceiptAuthority:
    matches = [
        authority
        for authority in policy.receipt_authorities
        if authority.side == side
        and authority.authority_id == authority_id
        and authority.key_id == key_id
        and authority.provider_id == provider_id
        and authority.provider_version == provider_version
        and authority.evidence_class == evidence_class
    ]
    if len(matches) != 1:
        raise ValueError("DP-04 receipt authority is not trusted for the exact provider scope")
    return matches[0]


def profile_partition(
    rows: Iterable[Mapping[str, Any]],
    *,
    partition_id: str,
    side: ProfileSide,
    identity: ProfileIdentity,
    policy: ProfilingPolicy,
    authority_id: str,
    key_id: str,
    evidence_class: EvidenceClass,
    signer: Callable[[bytes], bytes],
) -> dict[str, Any]:
    """Scan one partition once; retain bounded sufficient statistics, never rows."""

    _policy_payload(policy)
    _safe_id(partition_id, "partition_id")
    identity_payload = identity.payload()
    _safe_id(authority_id, "authority_id")
    _safe_id(key_id, "key_id")
    _authority_for(
        policy,
        side=side,
        authority_id=authority_id,
        key_id=key_id,
        provider_id=identity.provider_id,
        provider_version=identity.provider_version,
        evidence_class=evidence_class,
    )
    profiles = {column.name: _empty_column(column) for column in policy.columns}
    input_count = 0
    selected_count = 0
    sample_key_sum = 0
    sample_key_xor = 0
    blockers: set[str] = set()
    for row in rows:
        input_count += 1
        selected, sample_key = _selected(row, policy)
        if not selected:
            continue
        selected_count += 1
        sample_integer = int(sample_key, 16)
        sample_key_sum = (sample_key_sum + sample_integer) % (2**256)
        sample_key_xor ^= sample_integer
        for column in policy.columns:
            profile = profiles[column.name]
            if column.name not in row:
                blockers.add(f"missing_column:{column.name}")
                continue
            value = row[column.name]
            if value is None:
                profile["ordinary_null_count"] += 1
                continue
            if isinstance(value, SasMissing):
                profile["sas_missing_counts"][value.code] += 1
                continue
            profile["non_missing_count"] += 1
            if column.kind == "numeric":
                try:
                    number = Decimal(str(value))
                except InvalidOperation:
                    blockers.add(f"incompatible_numeric:{column.name}")
                    continue
                if not number.is_finite():
                    blockers.add(f"non_finite_numeric:{column.name}")
                    continue
                profile["numeric_count"] += 1
                profile["sum"] = str(Decimal(profile["sum"]) + number)
                profile["sum_squares"] = str(Decimal(profile["sum_squares"]) + number * number)
                if profile["minimum"] is None or number < Decimal(profile["minimum"]):
                    profile["minimum"] = str(number)
                if profile["maximum"] is None or number > Decimal(profile["maximum"]):
                    profile["maximum"] = str(number)
                index = sum(number > Decimal(boundary) for boundary in column.numeric_bins)
                profile["bin_counts"][index] += 1
            else:
                category = str(value)
                if category in profile["category_counts"]:
                    profile["category_counts"][category] += 1
                else:
                    profile["other_count"] += 1
    for profile in profiles.values():
        missing = profile["ordinary_null_count"] + sum(profile["sas_missing_counts"].values())
        profile["all_missing"] = selected_count > 0 and missing == selected_count
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "smf-dp04-v1",
        "partition_id": partition_id,
        "side": side,
        "identity": identity_payload,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy.digest,
        "evidence_class": evidence_class,
        "authority_id": authority_id,
        "key_id": key_id,
        "sampling": _sampling_payload(policy),
        "input_row_count": input_count,
        "profiled_row_count": selected_count,
        "sample_key_sum": f"{sample_key_sum:064x}",
        "sample_key_xor": f"{sample_key_xor:064x}",
        "columns": [profiles[column.name] for column in policy.columns],
        "status": "blocked" if blockers else "complete",
        "blockers": sorted(blockers),
        "claims": {
            "distributed_profile_complete": not blockers,
            "reconciled": False,
            "parity_passed": False,
            "human_approved": False,
        },
        "content_digest": "",
        "signature": "",
    }
    _assert_persistable(payload)
    payload["content_digest"] = _digest(_receipt_unsigned_payload(payload))
    payload["signature"] = base64.b64encode(signer(_receipt_signing_payload(payload))).decode()
    _validate("dp04-partition-profile.schema.json", payload)
    verify_partition(payload, policy=policy)
    return payload


def verify_partition(profile: dict[str, Any], *, policy: ProfilingPolicy) -> None:
    _validate("dp04-partition-profile.schema.json", profile)
    _assert_persistable(profile)
    if profile["content_digest"] != _digest(_receipt_unsigned_payload(profile)):
        raise ValueError("DP-04 partition profile mutation detected")
    identity = profile["identity"]
    ProfileIdentity(**identity).payload()
    authority = _authority_for(
        policy,
        side=profile["side"],
        authority_id=profile["authority_id"],
        key_id=profile["key_id"],
        provider_id=identity["provider_id"],
        provider_version=identity["provider_version"],
        evidence_class=profile["evidence_class"],
    )
    try:
        signature = base64.b64decode(profile["signature"], validate=True)
        public_key = base64.b64decode(authority.public_key, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _receipt_signing_payload(profile)
        )
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("DP-04 partition receipt signature is invalid") from exc
    if profile["claims"]["reconciled"] or profile["claims"]["parity_passed"]:
        raise ValueError("DP-04 partition profile asserts an unauthorized claim")
    if profile["claims"]["distributed_profile_complete"] != (profile["status"] == "complete"):
        raise ValueError("DP-04 partition completion claim is inconsistent")
    if (profile["status"] == "complete") != (not profile["blockers"]):
        raise ValueError("DP-04 partition status and blockers are inconsistent")
    names = [column["name"].casefold() for column in profile["columns"]]
    if len(names) != len(set(names)):
        raise ValueError("DP-04 partition contains duplicate columns")
    if profile["status"] == "complete":
        for column in profile["columns"]:
            missing = column["ordinary_null_count"] + sum(column["sas_missing_counts"].values())
            if missing + column["non_missing_count"] != profile["profiled_row_count"]:
                raise ValueError("DP-04 partition column counts do not reconcile")
            if column["all_missing"] != (
                profile["profiled_row_count"] > 0 and missing == profile["profiled_row_count"]
            ):
                raise ValueError("DP-04 partition all-missing state is inconsistent")
            if column["kind"] == "numeric" and (
                column["numeric_count"] != column["non_missing_count"]
                or sum(column["bin_counts"]) != column["numeric_count"]
            ):
                raise ValueError("DP-04 numeric partition counts do not reconcile")
            if column["kind"] == "categorical" and (
                sum(column["category_counts"].values()) + column["other_count"]
                != column["non_missing_count"]
            ):
                raise ValueError("DP-04 categorical partition counts do not reconcile")


def _merge(profiles: Sequence[dict[str, Any]], policy: ProfilingPolicy) -> dict[str, Any]:
    if not profiles:
        raise ValueError("DP-04 requires at least one partition profile")
    if len(profiles) > _MAX_PARTITIONS_PER_SIDE:
        raise ValueError("DP-04 partition count exceeds the governed bound")
    _policy_payload(policy)
    for profile in profiles:
        verify_partition(profile, policy=policy)
        observed_columns = profile["columns"]
        if [item["name"] for item in observed_columns] != [
            column.name for column in policy.columns
        ]:
            raise ValueError("DP-04 partition columns do not match policy")
        for observed, configured in zip(observed_columns, policy.columns, strict=True):
            if observed["kind"] != configured.kind:
                raise ValueError("DP-04 partition column kind does not match policy")
            if len(observed["bin_counts"]) != (
                len(configured.numeric_bins) + 1 if configured.kind == "numeric" else 0
            ):
                raise ValueError("DP-04 partition bins do not match policy")
            if set(observed["category_counts"]) != set(configured.categories):
                raise ValueError("DP-04 partition categories do not match policy")
    partition_ids = [profile["partition_id"] for profile in profiles]
    if len(partition_ids) != len(set(partition_ids)):
        raise ValueError("DP-04 partition identities must be unique")
    expected_sampling = _sampling_payload(policy)
    configuration_blockers = {
        "partition_policy_mismatch"
        for profile in profiles
        if profile["policy_id"] != policy.policy_id
        or profile["policy_version"] != policy.policy_version
        or profile["policy_digest"] != policy.digest
    }
    configuration_blockers.update(
        "partition_sampling_mismatch"
        for profile in profiles
        if profile["sampling"] != expected_sampling
    )
    first = profiles[0]
    binding_fields = (
        "side",
        "identity",
        "policy_id",
        "policy_version",
        "policy_digest",
        "sampling",
        "evidence_class",
    )
    if any(
        any(profile[field] != first[field] for field in binding_fields) for profile in profiles[1:]
    ):
        raise ValueError("DP-04 partition profiles have incompatible scope")
    merged = {column.name: _empty_column(column) for column in policy.columns}
    for profile in profiles:
        for observed in profile["columns"]:
            target = merged[observed["name"]]
            for key in ("ordinary_null_count", "non_missing_count", "numeric_count", "other_count"):
                target[key] += observed[key]
            for code, count in observed["sas_missing_counts"].items():
                target["sas_missing_counts"][code] += count
            target["sum"] = str(Decimal(target["sum"]) + Decimal(observed["sum"]))
            target["sum_squares"] = str(
                Decimal(target["sum_squares"]) + Decimal(observed["sum_squares"])
            )
            for index, count in enumerate(observed["bin_counts"]):
                target["bin_counts"][index] += count
            for category, count in observed["category_counts"].items():
                target["category_counts"][category] += count
            if observed["minimum"] is not None and (
                target["minimum"] is None
                or Decimal(observed["minimum"]) < Decimal(target["minimum"])
            ):
                target["minimum"] = observed["minimum"]
            if observed["maximum"] is not None and (
                target["maximum"] is None
                or Decimal(observed["maximum"]) > Decimal(target["maximum"])
            ):
                target["maximum"] = observed["maximum"]
    row_count = sum(profile["profiled_row_count"] for profile in profiles)
    sample_key_sum = sum(int(profile["sample_key_sum"], 16) for profile in profiles) % (2**256)
    sample_key_xor = 0
    for profile in profiles:
        sample_key_xor ^= int(profile["sample_key_xor"], 16)
    for value in merged.values():
        missing = value["ordinary_null_count"] + sum(value["sas_missing_counts"].values())
        value["all_missing"] = row_count > 0 and missing == row_count
    return {
        "side": first["side"],
        "identity": first["identity"],
        "policy_digest": policy.digest,
        "evidence_class": first["evidence_class"],
        "sampling": first["sampling"],
        "input_row_count": sum(profile["input_row_count"] for profile in profiles),
        "profiled_row_count": row_count,
        "sample_scope_digest": _digest(
            {
                "profiled_row_count": row_count,
                "sample_key_sum": f"{sample_key_sum:064x}",
                "sample_key_xor": f"{sample_key_xor:064x}",
            }
        ),
        "partition_count": len(profiles),
        "partition_digests": sorted(profile["content_digest"] for profile in profiles),
        "columns": [merged[column.name] for column in policy.columns],
        "status": (
            "blocked"
            if configuration_blockers or any(profile["status"] == "blocked" for profile in profiles)
            else "complete"
        ),
        "blockers": sorted(
            configuration_blockers | {item for profile in profiles for item in profile["blockers"]}
        ),
    }


def _within(expected: Decimal, actual: Decimal, absolute: Decimal, relative: Decimal) -> bool:
    return abs(actual - expected) <= max(absolute, relative * abs(expected))


def reconcile_profiles(
    source_partitions: Sequence[dict[str, Any]],
    target_partitions: Sequence[dict[str, Any]],
    *,
    policy: ProfilingPolicy,
) -> dict[str, Any]:
    """Merge distributed receipts and reconcile comparable source/target scopes."""

    source = _merge(source_partitions, policy)
    target = _merge(target_partitions, policy)
    source_identity = source["identity"]
    target_identity = target["identity"]
    common_identity = ("client_id", "workload_id", "run_id", "attempt_id", "artifact_id")
    incompatible: list[str] = []
    if source["side"] != "source" or target["side"] != "target":
        incompatible.append("profile_side_assignment_mismatch")
    if any(source_identity[field] != target_identity[field] for field in common_identity):
        incompatible.append("identity_scope_mismatch")
    if source["sampling"] != target["sampling"]:
        incompatible.append("sampling_method_or_scope_mismatch")
    elif (
        source["sampling"]["method"] == "deterministic_hash"
        and source["sample_scope_digest"] != target["sample_scope_digest"]
    ):
        incompatible.append("sample_scope_mismatch")
    if source["status"] != "complete" or target["status"] != "complete":
        incompatible.append("partition_profile_blocked")
    if source["evidence_class"] != target["evidence_class"]:
        incompatible.append("evidence_class_mismatch")
    checks: list[dict[str, Any]] = []
    source_columns = {item["name"]: item for item in source["columns"]}
    target_columns = {item["name"]: item for item in target["columns"]}
    for column in policy.columns:
        left = source_columns[column.name]
        right = target_columns[column.name]
        for metric in ("ordinary_null_count", "sas_missing_counts", "all_missing"):
            checks.append(
                {
                    "column": column.name,
                    "metric": metric,
                    "expected": left[metric],
                    "actual": right[metric],
                    "status": "pass" if left[metric] == right[metric] else "fail",
                    "diagnostic": "exact missing-category comparison",
                }
            )
        distribution_metrics = (
            ("bin_counts", left["bin_counts"], right["bin_counts"]),
            ("category_counts", left["category_counts"], right["category_counts"]),
            ("other_count", left["other_count"], right["other_count"]),
        )
        for metric, expected, actual in distribution_metrics:
            checks.append(
                {
                    "column": column.name,
                    "metric": metric,
                    "expected": expected,
                    "actual": actual,
                    "status": "pass" if expected == actual else "fail",
                    "diagnostic": "declared bounded distribution comparison",
                }
            )
        if column.kind == "numeric" and left["numeric_count"] and right["numeric_count"]:
            absolute = Decimal(column.absolute_tolerance)
            relative = Decimal(column.relative_tolerance)
            for metric in ("minimum", "maximum", "sum", "sum_squares"):
                expected_decimal = Decimal(left[metric])
                actual_decimal = Decimal(right[metric])
                checks.append(
                    {
                        "column": column.name,
                        "metric": metric,
                        "expected": left[metric],
                        "actual": right[metric],
                        "status": (
                            "pass"
                            if _within(expected_decimal, actual_decimal, absolute, relative)
                            else "fail"
                        ),
                        "diagnostic": "policy-bounded numeric comparison",
                    }
                )
    if source["profiled_row_count"] != target["profiled_row_count"]:
        checks.append(
            {
                "column": "*",
                "metric": "profiled_row_count",
                "expected": source["profiled_row_count"],
                "actual": target["profiled_row_count"],
                "status": "fail",
                "diagnostic": "comparable profiled scope requires equal row counts",
            }
        )
    if source["input_row_count"] != target["input_row_count"]:
        checks.append(
            {
                "column": "*",
                "metric": "input_row_count",
                "expected": source["input_row_count"],
                "actual": target["input_row_count"],
                "status": "fail",
                "diagnostic": "declared input scopes require equal row counts",
            }
        )
    if len(checks) > _MAX_RESULT_CHECKS:
        raise ValueError("DP-04 reconciliation check count exceeds the governed bound")
    if incompatible:
        outcome = "incompatible"
    elif any(check["status"] == "fail" for check in checks):
        outcome = "failed"
    else:
        outcome = "passed"
    binding = {
        "client_id": source_identity["client_id"],
        "workload_id": source_identity["workload_id"],
        "run_id": source_identity["run_id"],
        "attempt_id": source_identity["attempt_id"],
        "artifact_id": source_identity["artifact_id"],
        "policy_digest": policy.digest,
        "source_profile_digest": _digest(source),
        "target_profile_digest": _digest(target),
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "smf-dp04-v1",
        "reconciliation_id": f"DP04-{_digest(binding)[:32]}",
        **binding,
        "source_profile": source,
        "target_profile": target,
        "outcome": outcome,
        "blockers": sorted(incompatible),
        "checks": checks,
        "evidence_class": "synthetic_contract",
        "claims": {
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "human_assisted": False,
            "human_approved": False,
            "production_ready": False,
        },
        "content_digest": "",
    }
    _assert_persistable(result)
    result["content_digest"] = _digest({**result, "content_digest": ""})
    _validate("dp04-result.schema.json", result)
    return result


def verify_result(
    result: dict[str, Any],
    *,
    source_partitions: Sequence[dict[str, Any]],
    target_partitions: Sequence[dict[str, Any]],
    policy: ProfilingPolicy,
) -> None:
    _validate("dp04-result.schema.json", result)
    _assert_persistable(result)
    if result["content_digest"] != _digest({**result, "content_digest": ""}):
        raise ValueError("DP-04 result mutation detected")
    reconstructed = reconcile_profiles(source_partitions, target_partitions, policy=policy)
    if reconstructed != result:
        raise ValueError("DP-04 result does not match deterministic replay")
    if result["claims"]["production_ready"] or result["claims"]["human_approved"]:
        raise ValueError("DP-04 result asserts an unauthorized claim")


def publish_result(
    output_root: Path,
    result: dict[str, Any],
    *,
    source_partitions: Sequence[dict[str, Any]],
    target_partitions: Sequence[dict[str, Any]],
    policy: ProfilingPolicy,
    cancelled: Callable[[], bool] | None = None,
) -> Path:
    if cancelled is not None and cancelled():
        raise InterruptedError("DP-04 publication cancelled before replay")
    verify_result(
        result,
        source_partitions=source_partitions,
        target_partitions=target_partitions,
        policy=policy,
    )
    if cancelled is not None and cancelled():
        raise InterruptedError("DP-04 publication cancelled before immutable write")
    path = (
        output_root
        / "runs"
        / _safe_id(result["run_id"], "run_id")
        / "workloads"
        / _safe_id(result["workload_id"], "workload_id")
        / "attempts"
        / _safe_id(result["attempt_id"], "attempt_id")
        / "dp04-null-distribution.result.json"
    )
    publish_json(path, result, "DP-04 result", root=output_root)
    loaded = read_published_json(path, root=output_root, label="DP-04 result")
    if not isinstance(loaded, dict):
        raise ValueError("Published DP-04 result is invalid")
    verify_result(
        loaded,
        source_partitions=source_partitions,
        target_partitions=target_partitions,
        policy=policy,
    )
    return path
