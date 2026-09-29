"""Offline, non-authorizing CORPUS-11 binary-fixture qualification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from smf.immutable_files import publish_json, read_published_json
from smf.upstream.crypto import digest_value, sign_payload, verify_proof
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate fixture qualification key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate fixture qualification key")
        result[key] = value
    return result


def _validate(schema_name: str, payload: dict[str, Any]) -> None:
    schema = json.loads(files("smf.schemas").joinpath(schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Fixture qualification schema validation failed: {detail}")


def _load(path: Path, schema_name: str) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            os.close(descriptor)
            raise ValueError("Fixture qualification input is not a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read()
            final = os.fstat(handle.fileno())
        if (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
        ):
            raise ValueError("Fixture qualification input changed while being read")
        text = raw.decode("utf-8")
        if path.suffix.lower() == ".json":
            value = json.loads(text, object_pairs_hook=_unique_pairs)
        else:
            value = yaml.load(text, Loader=_UniqueLoader)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Fixture qualification input is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError("Fixture qualification input must be an object")
    _validate(schema_name, value)
    return value


def _identity(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe fixture qualification {label}")
    return value


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Fixture qualification time requires a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class FixturePolicy:
    canonical_bytes: bytes
    digest: str
    trusted_policy_keys: tuple[tuple[str, str], ...]
    allowed_policy_key_ids: tuple[str, ...]
    allowed_policy_authorities: tuple[str, ...]
    trust_digest: str


def _trust_digest(
    keys: tuple[tuple[str, str], ...], key_ids: tuple[str, ...], authorities: tuple[str, ...]
) -> str:
    return digest_value(
        {
            "trusted_policy_keys": [list(item) for item in keys],
            "allowed_policy_key_ids": list(key_ids),
            "allowed_policy_authorities": list(authorities),
        }
    )


def _key_fingerprint(encoded: str) -> str:
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Fixture policy contains malformed public-key material") from exc
    if len(decoded) != 32:
        raise ValueError("Fixture policy public key must be an Ed25519 key")
    return hashlib.sha256(decoded).hexdigest()


def _validate_policy_semantics(
    payload: dict[str, Any],
    *,
    policy_key_id: str,
    trusted_policy_keys: Mapping[str, str],
) -> None:
    for field in ("policy_id", "policy_version", "client_id", "authority"):
        _identity(payload[field], field)
    key_names = ("manifest_key_ids", "prerequisite_key_ids", "evaluator_key_ids")
    configured_keys = set(payload["verification_keys"])
    key_domains = [set(payload[name]) for name in key_names]
    if policy_key_id in configured_keys or policy_key_id in set().union(*key_domains):
        raise ValueError("Fixture policy signing key must be independent of operational domains")
    if any(not domain.issubset(configured_keys) for domain in key_domains):
        raise ValueError("Fixture policy references an unknown verification key")
    if any(
        left & right for index, left in enumerate(key_domains) for right in key_domains[index + 1 :]
    ):
        raise ValueError("Fixture qualification trust-domain keys must be distinct")
    try:
        policy_fingerprint = _key_fingerprint(trusted_policy_keys[policy_key_id])
    except KeyError as exc:
        raise ValueError("Fixture policy signer is absent from the external trust root") from exc
    operational_fingerprints = [
        _key_fingerprint(payload["verification_keys"][key_id])
        for domain in key_domains
        for key_id in sorted(domain)
    ]
    if policy_fingerprint in operational_fingerprints:
        raise ValueError("Policy and operational public-key material must be distinct")
    if len(operational_fingerprints) != len(set(operational_fingerprints)):
        raise ValueError("Operational trust domains contain aliased public-key material")

    authority_names = (
        "manifest_authorities",
        "prerequisite_authorities",
        "evaluator_authorities",
    )
    authority_domains = [set(payload[name]) for name in authority_names]
    if any(not domain for domain in authority_domains):
        raise ValueError("Fixture policy authority allowlists cannot be empty")
    if any(
        left & right
        for index, left in enumerate(authority_domains)
        for right in authority_domains[index + 1 :]
    ):
        raise ValueError("Fixture qualification trust-domain authorities must be distinct")
    customer_authorities = set(payload["customer_authorities"])
    operational_authorities = set().union(*authority_domains)
    if customer_authorities & operational_authorities:
        raise ValueError("Customer and operational fixture authorities must be distinct")
    if payload["authority"] in operational_authorities | customer_authorities:
        raise ValueError("Fixture policy authority must be independent of governed domains")
    for name in (*authority_names, "customer_authorities"):
        for authority in payload[name]:
            _identity(authority, name)

    prerequisite_ids = [item["prerequisite_id"] for item in payload["prerequisites"]]
    if sorted(prerequisite_ids) != ["LIC-01", "UPQ-01"]:
        raise ValueError("Fixture policy must bind exactly LIC-01 and UPQ-01")


def _policy_payload(policy: FixturePolicy) -> dict[str, Any]:
    if hashlib.sha256(policy.canonical_bytes).hexdigest() != policy.digest:
        raise ValueError("Fixture policy changed after admission")
    value = json.loads(policy.canonical_bytes, object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("Fixture policy canonical payload is invalid")
    _validate("fixture-qualification-policy.schema.json", value)
    if (
        _trust_digest(
            policy.trusted_policy_keys,
            policy.allowed_policy_key_ids,
            policy.allowed_policy_authorities,
        )
        != policy.trust_digest
    ):
        raise ValueError("Fixture policy trust roots changed after admission")
    policy_key_id = verify_proof(
        value,
        trusted_keys=dict(policy.trusted_policy_keys),
        allowed_key_ids=set(policy.allowed_policy_key_ids),
    )
    if value["authority"] not in policy.allowed_policy_authorities:
        raise ValueError("Fixture policy authority changed after admission")
    _validate_policy_semantics(
        value,
        policy_key_id=policy_key_id,
        trusted_policy_keys=dict(policy.trusted_policy_keys),
    )
    return value


def _canonical_policy_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def load_fixture_policy(
    path: Path,
    *,
    trusted_policy_keys: Mapping[str, str],
    allowed_policy_key_ids: set[str],
    allowed_policy_authorities: set[str],
) -> FixturePolicy:
    payload = _load(path, "fixture-qualification-policy.schema.json")
    policy_key_id = verify_proof(
        payload,
        trusted_keys=dict(trusted_policy_keys),
        allowed_key_ids=allowed_policy_key_ids,
    )
    if payload["authority"] not in allowed_policy_authorities:
        raise ValueError("Fixture policy authority is not trusted")
    _validate_policy_semantics(
        payload,
        policy_key_id=policy_key_id,
        trusted_policy_keys=trusted_policy_keys,
    )
    canonical = _canonical_policy_bytes(payload)
    frozen_keys = tuple(sorted(trusted_policy_keys.items()))
    frozen_key_ids = tuple(sorted(allowed_policy_key_ids))
    frozen_authorities = tuple(sorted(allowed_policy_authorities))
    return FixturePolicy(
        canonical_bytes=canonical,
        digest=hashlib.sha256(canonical).hexdigest(),
        trusted_policy_keys=frozen_keys,
        allowed_policy_key_ids=frozen_key_ids,
        allowed_policy_authorities=frozen_authorities,
        trust_digest=_trust_digest(frozen_keys, frozen_key_ids, frozen_authorities),
    )


def load_fixture_manifest(path: Path) -> dict[str, Any]:
    return _load(path, "fixture-qualification-manifest.schema.json")


def _read_fixture(root: Path, relative_name: str) -> bytes:
    relative = PurePosixPath(relative_name)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("Fixture path contains traversal")
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    if root.is_symlink() or not lexical_root.is_dir() or lexical_root.resolve() != lexical_root:
        raise ValueError("Fixture root is missing or unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lexical_root, flags)
    try:
        for part in relative.parts[:-1]:
            replacement = os.open(part, flags, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(replacement).st_mode):
                os.close(replacement)
                raise ValueError("Fixture path contains a non-directory component")
            os.close(descriptor)
            descriptor = replacement
        file_flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        file_descriptor = os.open(relative.name, file_flags, dir_fd=descriptor)
        with os.fdopen(file_descriptor, "rb") as handle:
            observed = os.fstat(handle.fileno())
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError("Fixture is not a regular file")
            data = handle.read()
            final = os.fstat(handle.fileno())
        observed_identity = (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
            observed.st_ctime_ns,
        )
        final_identity = (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        )
        if observed_identity != final_identity or len(data) != final.st_size:
            raise ValueError("Fixture changed while being read")
        return data
    finally:
        os.close(descriptor)


def _verify_manifest(manifest: dict[str, Any], policy: FixturePolicy) -> None:
    policy_payload = _policy_payload(policy)
    _validate("fixture-qualification-manifest.schema.json", manifest)
    verify_proof(
        manifest,
        trusted_keys=policy_payload["verification_keys"],
        allowed_key_ids=set(policy_payload["manifest_key_ids"]),
    )
    if manifest["authority"] not in policy_payload["manifest_authorities"]:
        raise ValueError("Fixture manifest authority is not trusted")
    for field in ("client_id", "workload_id", "run_id", "attempt_id", "manifest_id"):
        _identity(manifest[field], field)
    if manifest["client_id"] != policy_payload["client_id"]:
        raise ValueError("Fixture manifest crosses the configured client boundary")
    fixtures = manifest["fixtures"]
    ids = [item["fixture_id"].casefold() for item in fixtures]
    paths = [item["logical_path"].casefold() for item in fixtures]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        raise ValueError("Duplicate or ambiguous fixture identity")


def _verify_prerequisites(manifest: dict[str, Any], policy: FixturePolicy) -> list[str]:
    policy_payload = _policy_payload(policy)
    blockers: list[str] = []
    expected = {item["prerequisite_id"]: item for item in policy_payload["prerequisites"]}
    receipts = {item["prerequisite_id"]: item for item in manifest["prerequisites"]}
    if set(receipts) != set(expected) or len(receipts) != len(manifest["prerequisites"]):
        return ["prerequisite_coverage_mismatch"]
    bindings = ("client_id", "workload_id", "source_digest", "run_id", "attempt_id")
    for prerequisite_id, configured in expected.items():
        receipt = receipts[prerequisite_id]
        verify_proof(
            receipt,
            trusted_keys=policy_payload["verification_keys"],
            allowed_key_ids=set(policy_payload["prerequisite_key_ids"]),
        )
        if receipt["authority"] not in policy_payload["prerequisite_authorities"]:
            blockers.append(f"{prerequisite_id.lower()}_authority_untrusted")
        if any(receipt[field] != manifest[field] for field in bindings):
            blockers.append(f"{prerequisite_id.lower()}_subject_mismatch")
        if receipt["result_digest"] != configured["result_digest"]:
            blockers.append(f"{prerequisite_id.lower()}_result_mismatch")
        if receipt["status"] != "complete":
            blockers.append(f"{prerequisite_id.lower()}_not_complete")
    return blockers


def _fixture_blockers(
    fixture: dict[str, Any], manifest: dict[str, Any], policy: FixturePolicy, root: Path | None
) -> tuple[str, list[str]]:
    policy_payload = _policy_payload(policy)
    blockers: list[str] = []
    asset_class = fixture["asset_class"]
    purpose = manifest["purpose"]
    if (
        purpose not in policy_payload["allowed_purposes"]
        or purpose not in fixture["permitted_purposes"]
    ):
        blockers.append("purpose_not_permitted")
    if fixture["media_type"] not in policy_payload["allowed_media_types"]:
        blockers.append("media_type_not_permitted")
    if asset_class == "prohibited":
        blockers.append("asset_prohibited")
    elif asset_class == "evaluation_only":
        if purpose != "reader_evaluation" or fixture["redistribution"] != "evaluation_only":
            blockers.append("evaluation_boundary_violation")
    elif asset_class == "customer_controlled":
        if (
            manifest["evidence_class"] != "real"
            or fixture["redistribution"] != "customer_controlled"
        ):
            blockers.append("customer_authority_required")
        if fixture["authority"] not in policy_payload["customer_authorities"]:
            blockers.append("customer_authority_untrusted")
    elif asset_class == "licensed":
        license_record = fixture["license"]
        if (
            fixture["redistribution"] != "license_permitted"
            or license_record["status"] != "verified"
            or license_record["license_id"] not in policy_payload["allowed_license_ids"]
        ):
            blockers.append("license_not_qualified")
    if root is None:
        blockers.append("fixture_bytes_missing")
    else:
        try:
            data = _read_fixture(root, fixture["logical_path"])
        except (OSError, ValueError):
            blockers.append("fixture_bytes_missing_or_unsafe")
        else:
            if (
                len(data) != fixture["byte_count"]
                or hashlib.sha256(data).hexdigest() != fixture["sha256"]
            ):
                blockers.append("fixture_byte_identity_mismatch")
    if not blockers:
        return "qualified_contract", []
    if "asset_prohibited" in blockers or any("boundary_violation" in item for item in blockers):
        return "denied", sorted(set(blockers))
    if any("mismatch" in item or "untrusted" in item for item in blockers):
        return "incompatible", sorted(set(blockers))
    return "blocked", sorted(set(blockers))


def _unsigned_fixture_result(
    manifest: dict[str, Any],
    *,
    policy: FixturePolicy,
    evaluated_at: str,
    fixture_root: Path | None,
    evaluator_authority: str,
) -> dict[str, Any]:
    policy_payload = _policy_payload(policy)
    _verify_manifest(manifest, policy)
    evaluated = _time(evaluated_at)
    collected = _time(manifest["collected_at"])
    blockers = _verify_prerequisites(manifest, policy)
    if evaluated < collected:
        blockers.append("evaluation_precedes_collection")
    elif (evaluated - collected).total_seconds() > policy_payload["max_evidence_age_seconds"]:
        blockers.append("manifest_stale")
    decisions = []
    for fixture in sorted(manifest["fixtures"], key=lambda item: item["fixture_id"].casefold()):
        outcome, fixture_blockers = _fixture_blockers(fixture, manifest, policy, fixture_root)
        decisions.append(
            {
                "fixture_id": fixture["fixture_id"],
                "asset_class": fixture["asset_class"],
                "outcome": outcome,
                "blockers": fixture_blockers,
                "fixture_digest": fixture["sha256"],
            }
        )
    outcomes = {item["outcome"] for item in decisions}
    if blockers:
        outcome = "stale" if blockers == ["manifest_stale"] else "blocked"
    elif "denied" in outcomes:
        outcome = "denied"
    elif "incompatible" in outcomes:
        outcome = "incompatible"
    elif "blocked" in outcomes:
        outcome = "blocked"
    else:
        outcome = "qualified_contract"
    binding = {
        "client_id": manifest["client_id"],
        "workload_id": manifest["workload_id"],
        "source_digest": manifest["source_digest"],
        "run_id": manifest["run_id"],
        "attempt_id": manifest["attempt_id"],
        "policy_digest": policy.digest,
        "manifest_digest": digest_value(manifest),
        "evaluated_at": evaluated_at,
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "smf-corpus-fixture-qualification-v1",
        "result_id": stable_id("CFQ", binding),
        **binding,
        "evidence_class": manifest["evidence_class"],
        "purpose": manifest["purpose"],
        "outcome": outcome,
        "blockers": sorted(set(blockers)),
        "decisions": decisions,
        "claims": {
            "customer_access_authorized": False,
            "redistribution_authorized": False,
            "migration_executed": False,
            "reader_validated": False,
            "parity_established": False,
            "production_ready": False,
        },
        "evaluator_authority": _identity(evaluator_authority, "evaluator authority"),
    }
    return result


def evaluate_fixture_manifest(
    manifest: dict[str, Any],
    *,
    policy: FixturePolicy,
    evaluated_at: str,
    fixture_root: Path | None,
    evaluator_private_key: Path,
    evaluator_key_id: str,
    evaluator_authority: str,
) -> dict[str, Any]:
    """Evaluate exact local bytes without acquiring or authorizing any artifact."""

    policy_payload = _policy_payload(policy)
    if evaluator_key_id not in policy_payload["evaluator_key_ids"]:
        raise ValueError("Fixture evaluator key is not trusted")
    if evaluator_authority not in policy_payload["evaluator_authorities"]:
        raise ValueError("Fixture evaluator authority is not trusted")
    result = _unsigned_fixture_result(
        manifest,
        policy=policy,
        evaluated_at=evaluated_at,
        fixture_root=fixture_root,
        evaluator_authority=evaluator_authority,
    )
    sign_payload(result, private_key_path=evaluator_private_key, key_id=evaluator_key_id)
    _validate("fixture-qualification-result.schema.json", result)
    return result


def verify_fixture_result(
    result: dict[str, Any],
    *,
    manifest: dict[str, Any],
    policy: FixturePolicy,
    fixture_root: Path | None,
) -> None:
    policy_payload = _policy_payload(policy)
    _validate("fixture-qualification-result.schema.json", result)
    _verify_manifest(manifest, policy)
    verify_proof(
        result,
        trusted_keys=policy_payload["verification_keys"],
        allowed_key_ids=set(policy_payload["evaluator_key_ids"]),
    )
    if result["evaluator_authority"] not in policy_payload["evaluator_authorities"]:
        raise ValueError("Fixture result evaluator authority is not trusted")
    if result["policy_digest"] != policy.digest or result["manifest_digest"] != digest_value(
        manifest
    ):
        raise ValueError("Fixture result input binding mismatch")
    for field in ("client_id", "workload_id", "source_digest", "run_id", "attempt_id"):
        if result[field] != manifest[field]:
            raise ValueError("Fixture result subject binding mismatch")
    if any(result["claims"].values()):
        raise ValueError("Fixture result contains an unauthorized claim")
    reconstructed = _unsigned_fixture_result(
        manifest,
        policy=policy,
        evaluated_at=result["evaluated_at"],
        fixture_root=fixture_root,
        evaluator_authority=result["evaluator_authority"],
    )
    if {key: value for key, value in result.items() if key != "proof"} != reconstructed:
        raise ValueError("Fixture result does not match deterministic replay")


def publish_fixture_result(
    output_root: Path,
    result: dict[str, Any],
    *,
    manifest: dict[str, Any],
    policy: FixturePolicy,
    fixture_root: Path | None,
) -> Path:
    verify_fixture_result(result, manifest=manifest, policy=policy, fixture_root=fixture_root)
    path = (
        output_root
        / "runs"
        / _identity(result["run_id"], "run_id")
        / "workloads"
        / _identity(result["workload_id"], "workload_id")
        / "attempts"
        / _identity(result["attempt_id"], "attempt_id")
        / "fixture-qualification.result.json"
    )
    publish_json(path, result, "fixture qualification result", root=output_root)
    loaded = read_published_json(path, root=output_root, label="fixture qualification result")
    if not isinstance(loaded, dict):
        raise ValueError("Published fixture qualification result is invalid")
    verify_fixture_result(loaded, manifest=manifest, policy=policy, fixture_root=fixture_root)
    return path
