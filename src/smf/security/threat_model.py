"""Strict loader for the offline SMF security threat-model contract."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast
from urllib.parse import unquote

import yaml

from smf.security.schema import validate_security_schema
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SECRET_CANARY = re.compile(
    r"secret-canary-|(?:password|token|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]+",
    re.IGNORECASE,
)
_PROTECTED_DATA = re.compile(
    r"(?:\b\d{3}-\d{2}-\d{4}\b|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"\b(?:ssn|social[ _-]?security(?:[ _-]?number)?|dob|date[ _-]?of[ _-]?birth|"
    r"mrn|medical[ _-]?record(?:[ _-]?number)?|patient[ _-]?id|member[ _-]?id)"
    r"\s*[:=]\s*[A-Z0-9][A-Z0-9./_-]{3,}\b)",
    re.IGNORECASE,
)
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{12,}={0,2}(?![A-Za-z0-9_-])")
_REQUIRED_BOUNDARY_KINDS = {
    "source_ingestion",
    "canonical_evidence",
    "advisory_recall",
    "ai_transport",
    "durable_storage",
    "identity_secrets",
    "runtime",
    "validation",
    "human_approval",
    "engineering_worktree",
}
_REQUIRED_EVIDENCE_BINDINGS = {
    "client_id",
    "deployment_id",
    "environment_id",
    "workload_id",
    "subject_id",
    "source_digest",
    "policy_id",
    "policy_version",
    "provider_id",
    "strategy_version",
    "run_id",
    "attempt_id",
    "decision_id",
    "artifact_id",
}
_CLAIM_STATES = {
    "generated",
    "executed",
    "validated",
    "parity_passed",
    "certified",
    "human_approved",
    "blocked",
    "skipped",
    "failed",
    "pending",
    "denied",
}
_BLOCKED_OPERATIONS = {
    "ai_repair",
    "ai_submission",
    "baseline_execution",
    "certification",
    "competition_acceptance",
    "databricks_execution",
    "end_to_end_certification",
    "estate_recall_authority",
    "humana_parity_qualification",
    "live_authentication",
    "parity_qualification",
    "production_promotion",
    "protected_data_execution",
    "protected_data_ingestion",
}


class _UniqueLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueLoader, node: yaml.Node, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate threat-model key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class SecurityThreatModel:
    """Validated, immutable view of the architecture threat-model document."""

    model_id: str
    model_version: str
    content_digest: str
    payload: Mapping[str, Any]
    snapshot_bytes: bytes


def threat_model_digest(payload: Mapping[str, Any]) -> str:
    """Return the canonical digest, excluding the field which carries that digest."""

    digest_payload = dict(payload)
    digest_payload.pop("content_digest", None)
    encoded = json.dumps(
        _json_value(digest_payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    return value


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _decoded_text_variants(value: str) -> set[str]:
    """Return bounded text decodings used only for fail-closed content inspection."""

    variants = {value}
    pending = [(value, 0)]
    while pending:
        candidate, depth = pending.pop()
        if depth >= 4:
            continue
        expanded = unquote(candidate)
        if expanded not in variants:
            variants.add(expanded)
            pending.append((expanded, depth + 1))
        for match in _BASE64_TOKEN.finditer(candidate):
            token = match.group(0)
            padded = token + "=" * (-len(token) % 4)
            try:
                raw = base64.b64decode(padded, altchars=b"-_", validate=True)
                decoded = raw.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if decoded not in variants:
                variants.add(decoded)
                pending.append((decoded, depth + 1))
    return variants


def _validate_no_sensitive_content(value: object) -> None:
    """Reject sensitive leaf text before it can be hashed or retained in a snapshot."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            _validate_no_sensitive_content(key)
            _validate_no_sensitive_content(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            _validate_no_sensitive_content(item)
        return
    if not isinstance(value, str):
        return
    for candidate in _decoded_text_variants(value):
        sanitized = sanitize_discovery_value(candidate)
        if (
            sanitized != candidate
            or _SECRET_CANARY.search(candidate)
            or _PROTECTED_DATA.search(candidate)
        ):
            raise ValueError("Threat model contains sensitive durable content")


def _safe_repo_path(value: object, root: Path) -> Path:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        raise ValueError("Threat-model reference must be repository-relative")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    else:
        raise ValueError("Threat-model reference has unsafe encoding")
    if "\\" in decoded:
        raise ValueError("Threat-model reference has an unsafe separator")
    parts = Path(decoded).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Threat-model reference escapes repository scope")
    target = (root / decoded).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Threat-model reference escapes repository scope") from exc
    return target


def _indexed(items: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    folded: set[str] = set()
    for item in items:
        identity = item["id"]
        if not _SAFE_ID.fullmatch(identity):
            raise ValueError(f"Unsafe {label} identity")
        if identity.casefold() in folded:
            raise ValueError(f"Duplicate or case-ambiguous {label} identity")
        folded.add(identity.casefold())
        result[identity] = item
    return result


def _require_refs(values: list[str], known: Mapping[str, object], label: str) -> None:
    missing = sorted(set(values) - set(known))
    if missing:
        raise ValueError(f"Unknown {label} reference: {', '.join(missing)}")


def _require_operations(values: list[str]) -> None:
    unknown = sorted(set(values) - _BLOCKED_OPERATIONS)
    if unknown:
        raise ValueError(f"Unknown blocked operation: {', '.join(unknown)}")


def _validate_semantics(payload: dict[str, Any], root: Path) -> None:
    collections = {
        name: _indexed(payload[name], name)
        for name in ("owners", "boundaries", "flows", "controls", "threats")
    }
    binding_ids = _indexed(payload["referenced_bindings"], "referenced binding")
    unresolved_ids = _indexed(payload["unresolved_inputs"], "unresolved input")
    all_ids = [identity for collection in collections.values() for identity in collection]
    all_ids.extend(binding_ids)
    all_ids.extend(unresolved_ids)
    if len({identity.casefold() for identity in all_ids}) != len(all_ids):
        raise ValueError("Threat-model identities must be globally case-unambiguous")

    boundary_kinds = {item["kind"] for item in payload["boundaries"]}
    if boundary_kinds != _REQUIRED_BOUNDARY_KINDS:
        raise ValueError("Threat model does not cover the required trust boundaries exactly")

    boundaries = collections["boundaries"]
    flows = collections["flows"]
    owners = collections["owners"]
    controls = collections["controls"]
    for boundary in payload["boundaries"]:
        _require_operations(boundary["blocked_operations"])
        if not set(boundary["accepted_data_classes"]).issubset(payload["data_classes"]):
            raise ValueError("Boundary uses an undeclared data class")
    for flow in payload["flows"]:
        _require_operations(flow["blocked_operations"])
        _require_refs(
            [flow["origin_boundary_id"], flow["destination_boundary_id"]],
            boundaries,
            "boundary",
        )
        if flow["trust"] in {"untrusted", "advisory"} and flow["grants_authority"]:
            raise ValueError("Untrusted or advisory data cannot grant authority")
        if set(flow["required_identity_fields"]) != _REQUIRED_EVIDENCE_BINDINGS:
            raise ValueError("Flow evidence is not bound to the exact decision identity")
        if not set(flow["payload_classes"]).issubset(payload["data_classes"]):
            raise ValueError("Flow uses an undeclared data class")
        if flow["implementation_state"] != "implemented" and not flow["blocked_operations"]:
            raise ValueError("Incomplete flows must identify blocked operations")
    for control in payload["controls"]:
        _require_refs([control["owner_id"]], owners, "owner")
        if control["authorizes_success"]:
            raise ValueError("Architecture assertions cannot authorize workload success")
        for reference in control["implementation_refs"] + control["evidence_refs"]:
            target = _safe_repo_path(reference, root)
            if not target.is_file():
                raise ValueError(f"Threat-model reference does not resolve: {reference}")

    mandatory_threats = {"prompt-injection", "cross-client-retrieval"}
    if not mandatory_threats.issubset(collections["threats"]):
        raise ValueError("Prompt-injection and cross-client retrieval threats are mandatory")
    for threat in payload["threats"]:
        _require_operations(threat["blocked_operations"])
        _require_refs(threat["flow_ids"], flows, "flow")
        _require_refs(threat["control_ids"], controls, "control")
        _require_refs([threat["owner_id"]], owners, "owner")
        if (
            threat["residual_status"] in {"unresolved", "partially_mitigated"}
            and threat["severity"] in {"high", "critical"}
            and (
                threat["review_disposition"] != "review_blocker" or not threat["blocked_operations"]
            )
        ):
            raise ValueError("Residual high-impact threats must fail closed")
        if threat["severity"] in {"high", "critical"}:
            if threat["residual_status"] == "accepted":
                raise ValueError(
                    "High-impact risk acceptance requires governed risk-acceptance evidence"
                )
            if threat["residual_status"] == "mitigated" and any(
                controls[control_id]["implementation_state"] != "implemented"
                for control_id in threat["control_ids"]
            ):
                raise ValueError(
                    "High-impact mitigation requires implemented evidence-backed controls"
                )

    bindings = payload["evidence_contract"]["required_identity_bindings"]
    if set(bindings) != _REQUIRED_EVIDENCE_BINDINGS or len(bindings) != len(set(bindings)):
        raise ValueError("Evidence contract is missing exact authority bindings")
    claims = payload["evidence_contract"]["claim_states"]
    if set(claims) != _CLAIM_STATES or len(claims) != len(set(claims)):
        raise ValueError("Lifecycle claims must remain separate, including pending and denied")
    contract = payload["evidence_contract"]
    if not all(
        (
            contract["meaningful_eligible_subject_required"],
            contract["source_snapshot_or_reverification_required"],
            contract["immutable_canonical_evidence"],
            contract["idempotent_derived_recovery"],
            contract["cross_workload_isolation"],
        )
    ):
        raise ValueError("Threat model weakens a mandatory evidence invariant")

    recall = payload["advisory_recall"]
    if recall["authority"] != "advisory_only" or recall["required_provenance_fields"] != [
        "origin",
        "client_scope",
        "applicability",
        "version",
        "selection_reason",
        "conflicts",
        "supersession",
        "rejection_state",
    ]:
        raise ValueError("Advisory recall provenance or authority is incomplete")

    for binding in payload["referenced_bindings"]:
        target = _safe_repo_path(binding["path"], root)
        if not target.is_file():
            raise ValueError(f"Referenced binding does not resolve: {binding['path']}")
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != binding["sha256"]:
            raise ValueError(f"Referenced binding digest changed: {binding['id']}")

    for item in payload["unresolved_inputs"]:
        _require_operations(item["blocks"])
        _require_refs([item["owner_id"]], owners, "owner")


def load_security_threat_model(
    path: Path, *, repository_root: Path | None = None
) -> SecurityThreatModel:
    """Load and validate a threat model without executing any referenced content."""

    raw = path.read_bytes()
    try:
        payload = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Invalid security threat model") from exc
    if not isinstance(payload, dict):
        raise ValueError("Security threat model must be an object")
    _validate_no_sensitive_content(payload)
    validate_security_schema("security-threat-model.schema.json", payload)
    expected = threat_model_digest(payload)
    if payload["content_digest"] != expected:
        raise ValueError("Security threat-model content digest mismatch")
    root = (repository_root or Path.cwd()).resolve()
    _validate_semantics(payload, root)
    return SecurityThreatModel(
        model_id=payload["model_id"],
        model_version=payload["model_version"],
        content_digest=expected,
        payload=cast(Mapping[str, Any], _freeze(payload)),
        snapshot_bytes=raw,
    )
