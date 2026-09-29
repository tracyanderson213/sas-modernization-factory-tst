"""Deterministic, offline license and dependency-compliance evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from smf.compliance.schema import validate_evidence, validate_policy, validate_result
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value, sign_payload, verify_proof
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate license compliance configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate license compliance configuration key")
        result[key] = value
    return result


@dataclass(frozen=True)
class CompliancePolicy:
    payload: dict[str, Any]
    policy_digest: str


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("License compliance policy is missing or unsafe")
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            value = json.loads(text, object_pairs_hook=_unique_pairs)
        else:
            value = yaml.load(text, Loader=_UniqueLoader)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError("License compliance policy is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError("License compliance policy must be an object")
    return value


def _safe_identity(value: str, label: str) -> None:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe license compliance {label}")


def _safe_strings(value: Any) -> None:
    if isinstance(value, dict):
        for nested in value.values():
            _safe_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            _safe_strings(nested)
    elif isinstance(value, str) and (
        contains_protected_data(value) or sanitize_discovery_value(value) != value
    ):
        raise ValueError("Protected or unsafe data is not allowed in compliance evidence")


def load_compliance_policy(path: Path) -> CompliancePolicy:
    raw = _load(path)
    validate_policy(raw)
    for field in ("policy_id", "policy_version", "client_id"):
        _safe_identity(raw[field], field)
    keys = set(raw["verification_keys"])
    domains = (
        "collector_provenance",
        "license_provenance",
        "security_provenance",
        "scanner_provenance",
        "prerequisite_provenance",
        "evaluator_provenance",
    )
    if any(not set(raw[name]["key_ids"]).issubset(keys) for name in domains):
        raise ValueError("License compliance policy references an unknown verification key")
    trust_sets = [set(raw[name]["key_ids"]) for name in domains]
    if any(
        left & right for index, left in enumerate(trust_sets) for right in trust_sets[index + 1 :]
    ):
        raise ValueError("License compliance trust-domain signing keys must be distinct")
    if len(raw["sec03_acceptance_contract_digests"]) != len(
        set(raw["sec03_acceptance_contract_digests"])
    ):
        raise ValueError("Duplicate SEC-03 acceptance contract identity")
    exception_ids = [item["exception_id"] for item in raw["vulnerability_exception_allowlist"]]
    if len(exception_ids) != len(set(exception_ids)):
        raise ValueError("Duplicate vulnerability exception identity")
    _safe_strings(raw)
    return CompliancePolicy(raw, digest_value(raw))


def load_compliance_evidence(path: Path) -> dict[str, Any]:
    """Load evidence with duplicate-key and closed-schema rejection before evaluation."""

    raw = _load(path)
    validate_evidence(raw)
    _safe_strings(raw)
    return raw


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Compliance time must include a timezone")
    return parsed.astimezone(UTC)


def _verify_domain(record: dict[str, Any], policy: CompliancePolicy, domain: str) -> None:
    provenance = policy.payload[domain]
    verify_proof(
        record,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(provenance["key_ids"]),
    )
    if record["authority"] not in provenance["authorities"]:
        raise ValueError(f"Compliance evidence authority is not trusted for {domain}")


def _binding_digest(kind: str, identity: str, components: list[dict[str, Any]]) -> str:
    return digest_value({f"{kind}_id": identity, "components": components})


def _add(blockers: dict[str, set[str]], outcome: str, code: str) -> None:
    blockers.setdefault(outcome, set()).add(code)


_PRECEDENCE = (
    "denied",
    "failed",
    "ambiguous",
    "incompatible",
    "stale",
    "unavailable_scanner",
    "pending",
    "blocked",
)


def _evaluate_compliance_payload(
    evidence: dict[str, Any], *, policy: CompliancePolicy
) -> dict[str, Any]:
    """Reconstruct the unsigned deterministic decision for evaluation or replay."""

    validate_evidence(evidence)
    _safe_strings(evidence)
    for field in ("bundle_id", "client_id", "workload_id", "run_id", "attempt_id"):
        _safe_identity(evidence[field], field)
    if evidence["client_id"] != policy.payload["client_id"]:
        raise ValueError("Compliance evidence crosses the configured client boundary")
    _verify_domain(evidence, policy, "collector_provenance")
    binding = {
        "client_id": evidence["client_id"],
        "workload_id": evidence["workload_id"],
        "source_digest": evidence["source_digest"],
        "run_id": evidence["run_id"],
        "attempt_id": evidence["attempt_id"],
        "observed_at": evidence["observed_at"],
        "policy_digest": policy.policy_digest,
    }
    if evidence["bundle_id"] != stable_id("LICB", binding):
        raise ValueError("Compliance bundle identity is not bound to its exact subject")

    blockers: dict[str, set[str]] = {}
    if evidence["evidence_class"] == "real":
        _add(blockers, "blocked", "real_component_approval_not_authorized")
    profile = evidence["deployment_profile"]
    allowed_profiles = {
        (item["profile_id"], item["profile_digest"])
        for item in policy.payload["allowed_deployment_profiles"]
    }
    if (profile["profile_id"], profile["profile_digest"]) not in allowed_profiles:
        _add(blockers, "incompatible", "deployment_profile_not_allowed")

    resolution = evidence["resolution"]
    installed = evidence["installed_environment"]
    sbom = evidence["sbom"]
    component_lists = (resolution["components"], installed["components"], sbom["components"])
    for components in component_lists:
        canonical_ids = [item["component_id"].casefold() for item in components]
        if len(canonical_ids) != len(set(canonical_ids)):
            raise ValueError("Duplicate or ambiguous compliance component identity")
    if not resolution["components"]:
        _add(blockers, "blocked", "empty_resolution")
    expected_resolution = _binding_digest(
        "resolution", resolution["resolution_id"], resolution["components"]
    )
    expected_environment = _binding_digest(
        "environment", installed["environment_id"], installed["components"]
    )
    expected_sbom = digest_value(
        {
            "sbom_id": sbom["sbom_id"],
            "format": sbom["format"],
            "resolution_digest": sbom["resolution_digest"],
            "environment_digest": sbom["environment_digest"],
            "components": sbom["components"],
        }
    )
    if resolution["resolution_digest"] != expected_resolution:
        _add(blockers, "incompatible", "resolution_digest_mismatch")
    if installed["environment_digest"] != expected_environment:
        _add(blockers, "incompatible", "installed_environment_digest_mismatch")
    if (
        sbom["sbom_digest"] != expected_sbom
        or sbom["resolution_digest"] != resolution["resolution_digest"]
        or sbom["environment_digest"] != installed["environment_digest"]
        or component_lists[0] != component_lists[1]
        or component_lists[0] != component_lists[2]
    ):
        _add(blockers, "incompatible", "resolution_environment_sbom_mismatch")

    component_ids = [item["component_id"] for item in resolution["components"]]
    licenses = evidence["licenses"]
    if sorted(item["component_id"] for item in licenses) != sorted(component_ids):
        _add(blockers, "ambiguous", "license_component_coverage_mismatch")
    for item in licenses:
        _verify_domain(item, policy, "license_provenance")
        state = item["state"]
        if state != "verified":
            _add(blockers, state if state in _PRECEDENCE else "blocked", f"license_{state}")
        if item["license_id"] not in policy.payload["approved_license_ids"]:
            _add(blockers, "denied", "license_default_deny")

    notices = evidence["notice_files"]
    notice_components = [item["component_id"] for item in notices]
    canonical_notice_components = [component_id.casefold() for component_id in notice_components]
    if len(canonical_notice_components) != len(set(canonical_notice_components)):
        raise ValueError("Duplicate NOTICE component identity")
    if any(component_id not in component_ids for component_id in notice_components):
        _add(blockers, "incompatible", "notice_component_scope_mismatch")
    for item in licenses:
        if item["notice_required"] and item["component_id"] not in notice_components:
            _add(blockers, "blocked", "required_notice_missing")

    provenance = evidence["provenance"]
    if sorted(item["component_id"] for item in provenance) != sorted(component_ids):
        _add(blockers, "ambiguous", "provenance_component_coverage_mismatch")
    expected_artifacts = {
        item["component_id"]: item["artifact_digest"] for item in resolution["components"]
    }
    if any(
        expected_artifacts.get(item["component_id"]) != item["artifact_digest"]
        for item in provenance
    ):
        _add(blockers, "incompatible", "component_provenance_mismatch")
    components_by_id = {item["component_id"]: item for item in resolution["components"]}
    provenance_by_id = {item["component_id"]: item for item in provenance}
    for item in licenses:
        component = components_by_id.get(item["component_id"])
        component_provenance = provenance_by_id.get(item["component_id"])
        if (
            component is None
            or component_provenance is None
            or any(
                item[field] != component[field]
                for field in ("version", "artifact_type", "artifact_digest")
            )
            or item["source_revision"] != component_provenance["source_revision"]
        ):
            _add(blockers, "incompatible", "license_component_binding_mismatch")

    for prerequisite_name in ("upq", "sec03"):
        prerequisite = evidence[prerequisite_name]
        _verify_domain(prerequisite, policy, "prerequisite_provenance")
        if (
            prerequisite["client_id"] != evidence["client_id"]
            or prerequisite["workload_id"] != evidence["workload_id"]
            or prerequisite["source_digest"] != evidence["source_digest"]
            or prerequisite["run_id"] != evidence["run_id"]
            or prerequisite["attempt_id"] != evidence["attempt_id"]
        ):
            _add(blockers, "incompatible", f"{prerequisite_name}_subject_binding_mismatch")
        status = prerequisite["status"]
        if status != "complete":
            outcome = status if status in _PRECEDENCE else "blocked"
            _add(blockers, outcome, f"{prerequisite_name}_{status}")
    if any(item["upq_result_digest"] != evidence["upq"]["result_digest"] for item in licenses):
        _add(blockers, "incompatible", "license_upq_binding_mismatch")
    if any(item["upq_result_digest"] != evidence["upq"]["result_digest"] for item in provenance):
        _add(blockers, "incompatible", "provenance_upq_binding_mismatch")

    sec03_digests = policy.payload["sec03_acceptance_contract_digests"]
    if len(sec03_digests) != 1:
        _add(blockers, "ambiguous", "sec03_acceptance_contract_inconsistent")
    elif evidence["sec03"]["acceptance_contract_digest"] != sec03_digests[0]:
        _add(blockers, "incompatible", "sec03_acceptance_contract_mismatch")

    vulnerability = evidence["vulnerability"]
    _verify_domain(vulnerability, policy, "scanner_provenance")
    scanner_status = vulnerability["status"]
    if scanner_status != "complete":
        outcome = scanner_status if scanner_status in _PRECEDENCE else "failed"
        _add(blockers, outcome, f"scanner_{scanner_status}")
    if (
        vulnerability["resolution_digest"] != resolution["resolution_digest"]
        or vulnerability["environment_digest"] != installed["environment_digest"]
        or vulnerability["sbom_digest"] != sbom["sbom_digest"]
    ):
        _add(blockers, "incompatible", "vulnerability_scan_binding_mismatch")
    if vulnerability["advisories_digest"] != digest_value(vulnerability["advisories"]):
        _add(blockers, "incompatible", "advisories_digest_mismatch")
    advisory_ids = [item["advisory_id"] for item in vulnerability["advisories"]]
    if len(advisory_ids) != len(set(advisory_ids)):
        raise ValueError("Duplicate vulnerability advisory identity")

    evaluated = _parse_time(evidence["evaluated_at"])
    exception_policy = {
        item["exception_id"]: item for item in policy.payload["vulnerability_exception_allowlist"]
    }
    supplied_exceptions: dict[str, dict[str, Any]] = {}
    for item in vulnerability["exceptions"]:
        if item["exception_id"] in supplied_exceptions:
            raise ValueError("Duplicate vulnerability exception identity")
        supplied_exceptions[item["exception_id"]] = item
        _verify_domain(item, policy, "security_provenance")
        allowed = exception_policy.get(item["exception_id"])
        if allowed is None or any(
            item[field] != allowed[field]
            for field in ("advisory_id", "component_id", "expires_at", "authority")
        ):
            _add(blockers, "denied", "vulnerability_exception_not_allowlisted")
        if _parse_time(item["expires_at"]) <= evaluated:
            _add(blockers, "stale", "vulnerability_exception_expired")

    finding_ids: set[str] = set()
    for finding in vulnerability["findings"]:
        if finding["finding_id"] in finding_ids:
            raise ValueError("Duplicate vulnerability finding identity")
        finding_ids.add(finding["finding_id"])
        if (
            finding["advisory_id"] not in advisory_ids
            or finding["component_id"] not in component_ids
        ):
            _add(blockers, "incompatible", "vulnerability_finding_binding_mismatch")
        if finding["status"] == "affected":
            exception = supplied_exceptions.get(finding.get("exception_id", ""))
            if exception is None:
                _add(blockers, "failed", "unresolved_vulnerability")
            elif (
                exception["advisory_id"] != finding["advisory_id"]
                or exception["component_id"] != finding["component_id"]
            ):
                _add(blockers, "incompatible", "vulnerability_exception_binding_mismatch")

    observed = _parse_time(evidence["observed_at"])
    scanned = _parse_time(vulnerability["scanned_at"])
    scan_age = (evaluated - scanned).total_seconds()
    if scanned > observed or scan_age < 0:
        _add(blockers, "ambiguous", "future_dated_vulnerability_scan")
    elif scan_age > policy.payload["max_evidence_age_seconds"]:
        _add(blockers, "stale", "vulnerability_scan_stale")
    age = (evaluated - observed).total_seconds()
    if age < 0:
        _add(blockers, "ambiguous", "future_dated_evidence")
    elif age > policy.payload["max_evidence_age_seconds"]:
        _add(blockers, "stale", "compliance_evidence_stale")

    outcome = next((name for name in _PRECEDENCE if blockers.get(name)), "contract_pass")
    all_blockers = sorted({code for values in blockers.values() for code in values})
    result_identity = {**binding, "evidence_digest": digest_value(evidence)}
    result = {
        "schema_version": "1.0",
        "result_id": stable_id("LIC", result_identity),
        "decision_id": stable_id("LICD", {**result_identity, "outcome": outcome}),
        **binding,
        "evidence_class": evidence["evidence_class"],
        "evidence_digest": digest_value(evidence),
        "deployment_profile_digest": profile["profile_digest"],
        "resolution_digest": resolution["resolution_digest"],
        "environment_digest": installed["environment_digest"],
        "sbom_digest": sbom["sbom_digest"],
        "upq_result_digest": evidence["upq"]["result_digest"],
        "sec03_result_digest": evidence["sec03"]["result_digest"],
        "outcome": outcome,
        "blockers": all_blockers,
        "component_count": len(component_ids),
        "finding_count": len(vulnerability["findings"]),
        "exception_count": len(vulnerability["exceptions"]),
        "claims": {
            "real_components_approved": False,
            "humana_distribution_approved": False,
            "vulnerability_free": False,
            "production_ready": False,
            "lifecycle_complete": False,
        },
        "authority": policy.payload["evaluator_provenance"]["authorities"][0],
        "proof": {},
    }
    return result


def evaluate_compliance(
    evidence: dict[str, Any],
    *,
    policy: CompliancePolicy,
    evaluator_private_key: Path,
    evaluator_key_id: str,
) -> dict[str, Any]:
    """Evaluate supplied immutable evidence without fetching, inference, or real approval."""

    result = _evaluate_compliance_payload(evidence, policy=policy)
    sign_payload(result, private_key_path=evaluator_private_key, key_id=evaluator_key_id)
    validate_result(result)
    _verify_domain(result, policy, "evaluator_provenance")
    return result
