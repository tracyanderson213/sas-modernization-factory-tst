"""Offline, signed source-to-validation certification bundle verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_bytes, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value, verify_proof
from smf.workload.identity import stable_id

ROLES = (
    "source",
    "conversion",
    "execution",
    "baseline",
    "validation",
    "reconciliation",
    "provenance",
    "completion_approval",
)
POSITIVE_STATE = {
    "source": "admitted",
    "conversion": "converted",
    "execution": "succeeded",
    "baseline": "acquired",
    "validation": "validated",
    "reconciliation": "reconciled",
    "provenance": "validated",
    "completion_approval": "approved",
}
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass(frozen=True)
class CertificationBundleRequest:
    evidence_root: Path
    output_root: Path
    policy_relative_path: str
    evidence_relative_paths: tuple[str, ...]
    trust_roots: dict[str, str]
    evaluated_at: str


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Packaged {name} is not an object")
    return value


def _validate(name: str, value: dict[str, Any]) -> None:
    names = (
        "certification-policy.schema.json",
        "certification-evidence.schema.json",
        "certification-bundle-result.schema.json",
    )
    registry = Registry().with_resources(
        [(_schema(item)["$id"], Resource.from_contents(_schema(item))) for item in names]
    )
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(value),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"TASK-25 schema validation failed: {detail}")


def _safe(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
    ):
        raise ValueError(f"TASK-25 {label} is unsafe")
    return value


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"TASK-25 {label} must be canonical UTC RFC3339")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"TASK-25 {label} must be canonical UTC RFC3339")
    return parsed


def _relative(value: str, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"TASK-25 {label} must be a safe relative path")
    return path


def _read(root: Path, relative: str, label: str) -> bytes:
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    path = lexical_root.joinpath(*_relative(relative, label).parts)
    return read_published_bytes(path, root=lexical_root, label=label)


def _load(raw: bytes, label: str) -> dict[str, Any]:
    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"TASK-25 {label} contains duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"TASK-25 {label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"TASK-25 {label} must be an object")
    return value


def _reject_protected(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_protected(key)
            _reject_protected(item)
    elif isinstance(value, list):
        for item in value:
            _reject_protected(item)
    elif isinstance(value, str) and contains_protected_data(value):
        raise ValueError("TASK-25 evidence metadata contains protected material")


def _policy_digest(policy: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in policy.items() if key not in {"proof", "policy_digest"}
    }
    return digest_value(unsigned)


def _evidence_digest(evidence: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in evidence.items() if key not in {"proof", "evidence_digest"}
    }
    return digest_value(unsigned)


def _implementation_manifest() -> list[dict[str, str]]:
    resources = (
        ("smf/certification_bundle.py", files("smf").joinpath("certification_bundle.py")),
        ("smf/immutable_files.py", files("smf").joinpath("immutable_files.py")),
        ("smf/security/ai_admission.py", files("smf").joinpath("security/ai_admission.py")),
        ("smf/upstream/crypto.py", files("smf").joinpath("upstream/crypto.py")),
        ("smf/workload/identity.py", files("smf").joinpath("workload/identity.py")),
        *(
            (f"smf/schemas/{name}", files("smf.schemas").joinpath(name))
            for name in (
                "certification-policy.schema.json",
                "certification-evidence.schema.json",
                "certification-bundle-result.schema.json",
            )
        ),
    )
    return [
        {"path": name, "sha256": hashlib.sha256(resource.read_bytes()).hexdigest()}
        for name, resource in resources
    ]


def evaluate_certification_bundle(request: CertificationBundleRequest) -> dict[str, Any]:
    """Verify a signed exact chain; synthetic evidence can never certify a real run."""

    evaluated = _time(request.evaluated_at, "evaluated_at")
    if not request.trust_roots:
        raise ValueError("TASK-25 requires out-of-band policy trust roots")
    for key_id, public_key in request.trust_roots.items():
        _safe(key_id, "trust-root key_id")
        if not isinstance(public_key, str) or len(public_key) < 40:
            raise ValueError("TASK-25 trust-root public key is invalid")

    policy_raw = _read(request.evidence_root, request.policy_relative_path, "policy")
    policy = _load(policy_raw, "policy")
    _reject_protected(policy)
    _validate("certification-policy.schema.json", policy)
    if policy["required_roles"] != list(ROLES):
        raise ValueError("TASK-25 policy must require the complete canonical evidence chain")
    if policy["policy_digest"] != _policy_digest(policy):
        raise ValueError("TASK-25 policy digest is invalid")
    policy_key = verify_proof(
        policy, trusted_keys=request.trust_roots, allowed_key_ids=set(request.trust_roots)
    )
    if policy_key != policy["authority_key_id"]:
        raise ValueError("TASK-25 policy proof is not from its declared authority")
    if not (
        _time(policy["valid_from"], "policy valid_from")
        <= evaluated
        < _time(policy["valid_until"], "policy valid_until")
    ):
        raise ValueError("TASK-25 certification policy is not current")

    role_keys = {item["role"]: set(item["key_ids"]) for item in policy["role_authorities"]}
    if set(role_keys) != set(ROLES):
        raise ValueError("TASK-25 policy role authorities are incomplete or ambiguous")
    trusted_keys = cast(dict[str, str], policy["verification_keys"])
    expected_versions = cast(dict[str, str], policy["contract_versions"])
    if set(expected_versions) != set(ROLES):
        raise ValueError("TASK-25 policy contract versions are incomplete")

    evidence_by_role: dict[str, dict[str, Any]] = {}
    evidence_paths: dict[str, str] = {}
    for relative in request.evidence_relative_paths:
        raw = _read(request.evidence_root, relative, "evidence")
        evidence = _load(raw, "evidence")
        _reject_protected(evidence)
        _validate("certification-evidence.schema.json", evidence)
        role = cast(str, evidence["role"])
        if role in evidence_by_role:
            raise ValueError("TASK-25 evidence roles must be unique")
        if evidence["evidence_digest"] != _evidence_digest(evidence):
            raise ValueError("TASK-25 evidence digest is invalid")
        verify_proof(evidence, trusted_keys=trusted_keys, allowed_key_ids=role_keys[role])
        if evidence["policy_digest"] != policy["policy_digest"]:
            raise ValueError("TASK-25 evidence crosses the certification policy boundary")
        if evidence["contract_version"] != expected_versions[role]:
            raise ValueError("TASK-25 evidence contract version is incompatible")
        if any(evidence[name] != policy["identity"][name] for name in policy["identity"]):
            raise ValueError("TASK-25 evidence crosses the certified run identity")
        issued = _time(evidence["issued_at"], "evidence issued_at")
        expires = _time(evidence["expires_at"], "evidence expires_at")
        if issued > evaluated or expires <= evaluated:
            raise ValueError("TASK-25 evidence is not current")
        payload = _read(request.evidence_root, evidence["payload_ref"], "payload")
        if contains_protected_data(payload.decode("utf-8", errors="ignore")):
            raise ValueError("TASK-25 payload contains protected material")
        if hashlib.sha256(payload).hexdigest() != evidence["payload_sha256"]:
            raise ValueError("TASK-25 payload bytes changed")
        evidence_by_role[role] = evidence
        evidence_paths[role] = relative

    missing = [role for role in ROLES if role not in evidence_by_role]
    blockers = [f"missing:{role}" for role in missing]
    ordered: list[dict[str, Any]] = []
    prior_digests: dict[str, str] = {}
    for role_index, role in enumerate(ROLES):
        role_evidence = evidence_by_role.get(role)
        if role_evidence is None:
            continue
        predecessors = role_evidence["predecessor_digests"]
        known_positions_match = all(
            predecessors[prior_index] == prior_digests[prior_role]
            for prior_index, prior_role in enumerate(ROLES[:role_index])
            if prior_role in prior_digests
        )
        if len(predecessors) != role_index or not known_positions_match:
            raise ValueError("TASK-25 evidence chain is disconnected or reordered")
        if role_evidence["state"] != POSITIVE_STATE[role]:
            blockers.append(f"{role}:{role_evidence['state']}")
        ordered.append(
            {
                "role": role,
                "evidence_id": role_evidence["evidence_id"],
                "evidence_digest": role_evidence["evidence_digest"],
                "relative_path": evidence_paths[role],
                "payload_ref": role_evidence["payload_ref"],
                "payload_sha256": role_evidence["payload_sha256"],
                "contract_version": role_evidence["contract_version"],
                "state": role_evidence["state"],
                "issued_at": role_evidence["issued_at"],
                "expires_at": role_evidence["expires_at"],
            }
        )
        prior_digests[role] = role_evidence["evidence_digest"]

    # This bounded TASK-25 increment proves the bundle mechanics only.  Its
    # caller-supplied local trust roots cannot establish customer authority.
    certified = False
    blockers.append("external_certification_authority_required")
    identity = dict(policy["identity"])
    identity.update(
        {
            "policy_id": policy["policy_id"],
            "policy_version": policy["policy_version"],
            "policy_digest": policy["policy_digest"],
            "evaluated_at": request.evaluated_at,
        }
    )
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "contract_version": "task-25.1.0",
        "result_id": stable_id("CERTRES", identity),
        "content_digest": "0" * 64,
        "canonical_evidence_reference": (
            f"runs/{identity['run_id']}/workloads/{identity['workload_id']}/attempts/"
            f"{identity['attempt_id']}/certification/certification-bundle.result.json"
        ),
        "identity": identity,
        "status": "certified" if certified else "blocked",
        "terminal_disposition": "certified" if certified else "requirements_unmet",
        "evidence_class": policy["evidence_class"],
        "chain": ordered,
        "blockers": blockers,
        "implementation_manifest": _implementation_manifest(),
        "claims": {
            "source_bound": "source" in evidence_by_role,
            "baseline_verified": evidence_by_role.get("baseline", {}).get("state") == "acquired",
            "converted": evidence_by_role.get("conversion", {}).get("state") == "converted",
            "executed": evidence_by_role.get("execution", {}).get("state") == "succeeded",
            "validated": evidence_by_role.get("validation", {}).get("state") == "validated",
            "reconciled": evidence_by_role.get("reconciliation", {}).get("state") == "reconciled",
            "approval_verified": False,
            "certified": certified,
            "promoted": False,
            "production_ready": False,
            "migration_complete": False,
        },
    }
    result["content_digest"] = digest_value(
        {key: value for key, value in result.items() if key != "content_digest"}
    )
    _validate("certification-bundle-result.schema.json", result)
    return result


def verify_certification_bundle(
    result: dict[str, Any], request: CertificationBundleRequest
) -> None:
    _validate("certification-bundle-result.schema.json", result)
    if result != evaluate_certification_bundle(request):
        raise ValueError("TASK-25 certification bundle differs from current governed inputs")


def publish_certification_bundle(
    request: CertificationBundleRequest,
) -> tuple[dict[str, Any], Path]:
    result = evaluate_certification_bundle(request)
    path = request.output_root.joinpath(
        *_relative(result["canonical_evidence_reference"], "result path").parts
    )
    publish_json(path, result, "TASK-25 certification bundle", root=request.output_root)
    observed = read_published_json(path, root=request.output_root, label="TASK-25 bundle")
    if not isinstance(observed, dict):
        raise ValueError("TASK-25 published bundle is not an object")
    verify_certification_bundle(observed, request)
    return observed, path
