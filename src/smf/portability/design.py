"""PKG-DES-01 offline portability design and source-only preflight."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from smf.immutable_files import publish_json, read_published_bytes
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

_SCHEMAS = ("portability-design.schema.json", "portability-result.schema.json")
_PRECEDENCE = ("denied", "failed", "ambiguous", "incompatible", "stale", "pending", "blocked")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate portability contract key")
        result[key] = value
    return result


def _validate(name: str, payload: dict[str, Any]) -> None:
    if name not in _SCHEMAS:
        raise ValueError("Unknown portability schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Portability schema validation failed: {detail}")


def _safe_path(path: Path, root: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} is outside the authorized root") from exc


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
        raise ValueError("Protected or unsafe data is not allowed in portability evidence")


def load_portability_design(path: Path, *, authorized_root: Path) -> dict[str, Any]:
    """Load a root-confined, duplicate-key-free portability design."""

    _safe_path(path, authorized_root, "Portability design")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Portability design is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("Portability design must be an object")
    _validate("portability-design.schema.json", payload)
    _safe_strings(payload)
    _validate_contract(payload)
    return payload


def _unique(items: list[dict[str, Any]], field: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        key = item[field].casefold()
        if key in result:
            raise ValueError(f"Duplicate or ambiguous {label} identity")
        result[key] = item
    return result


def _validate_contract(contract: dict[str, Any]) -> None:
    matrix = _unique(contract["runtime_matrix"], "matrix_id", "runtime matrix")
    requirements = _unique(contract["requirements"], "component_id", "dependency")
    observations = _unique(contract["observations"], "component_id", "runtime observation")
    artifacts = _unique(contract["offline_artifacts"], "component_id", "offline artifact")
    if any(item["platform_id"].casefold() not in matrix for item in requirements.values()):
        raise ValueError("Dependency references an unknown runtime matrix entry")
    for observation in observations.values():
        platform = matrix.get(observation["platform_id"].casefold())
        if platform is None:
            raise ValueError("Runtime observation references an unknown runtime matrix entry")
        if observation["runtime_matrix_digest"] != digest_value(platform):
            raise ValueError("Runtime observation matrix digest mismatch")
    if set(observations) - set(requirements) or set(artifacts) - set(requirements):
        raise ValueError("Observation or offline artifact is outside the dependency lock")
    expected = {
        "runtime_matrix": digest_value(contract["runtime_matrix"]),
        "dependency_lock": digest_value(contract["requirements"]),
        "offline_artifact_plan": digest_value(contract["offline_artifacts"]),
    }
    if contract["digests"] != expected:
        raise ValueError("Portability design digest mismatch")


def _add(blockers: dict[str, set[str]], outcome: str, code: str) -> None:
    blockers.setdefault(outcome, set()).add(code)


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Portability evidence time is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError("Portability evidence time must include a timezone")
    return parsed.astimezone(UTC)


def _offline_requirement(
    requirement: dict[str, Any],
    artifact: dict[str, Any],
    matrix: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "component_id": requirement["component_id"],
        "filename": artifact["filename"],
        "kind": requirement["kind"],
        "version": requirement["version"],
        "platform_id": requirement["platform_id"],
        "runtime_matrix": matrix[requirement["platform_id"].casefold()],
        "expected_sha256": requirement["artifact_sha256"],
        "source_revision": artifact["source_revision"],
        "license_digest": artifact["license_digest"],
        "notice_digest": artifact["notice_digest"],
        "sbom_digest": artifact["sbom_digest"],
        "provenance_digest": artifact["provenance_digest"],
        "vulnerability_digest": artifact["vulnerability_digest"],
        "intake_state": artifact["intake_state"],
    }


def evaluate_portability_design(contract: dict[str, Any]) -> dict[str, Any]:
    """Evaluate design evidence without fetching, installing, compiling or authorizing."""

    _validate("portability-design.schema.json", contract)
    _safe_strings(contract)
    _validate_contract(contract)
    observations = _unique(contract["observations"], "component_id", "runtime observation")
    artifacts = _unique(contract["offline_artifacts"], "component_id", "offline artifact")
    matrix = _unique(contract["runtime_matrix"], "matrix_id", "runtime matrix")
    blockers: dict[str, set[str]] = {}
    required_offline: set[str] = set()
    complete_offline_plans: set[str] = set()
    evaluated_at = _time(contract["evaluated_at"])
    evidence_observed_at = _time(contract["observed_at"])
    maximum_age = contract["freshness_max_age_seconds"]

    if evidence_observed_at > evaluated_at:
        _add(blockers, "ambiguous", "evidence_observed_in_future")
    elif (evaluated_at - evidence_observed_at).total_seconds() > maximum_age:
        _add(blockers, "stale", "evidence_stale")

    if contract["evidence_class"] == "real":
        _add(blockers, "blocked", "real_runtime_approval_not_authorized")

    for requirement in contract["requirements"]:
        component_id = requirement["component_id"]
        key = component_id.casefold()
        observation = observations.get(key)
        artifact = artifacts.get(key)
        if contract["profile"] == "source-only":
            if observation is None or observation["state"] == "missing":
                _add(blockers, "blocked", f"missing:{component_id}")
                required_offline.add(component_id)
            elif observation["state"] != "present":
                mapped = "pending" if observation["state"] == "unapproved" else observation["state"]
                _add(blockers, mapped, f"{observation['state']}:{component_id}")
                required_offline.add(component_id)
            elif (
                observation["platform_id"] != requirement["platform_id"]
                or observation["runtime_matrix_digest"]
                != digest_value(matrix[requirement["platform_id"].casefold()])
                or observation["version"] != requirement["version"]
                or observation["artifact_sha256"] != requirement["artifact_sha256"]
            ):
                _add(blockers, "incompatible", f"runtime_lock_mismatch:{component_id}")
                required_offline.add(component_id)
            elif observation["authority_digest"] is None:
                _add(blockers, "ambiguous", f"missing_runtime_authority:{component_id}")
                required_offline.add(component_id)
            else:
                observed_at = _time(observation["observed_at"])
                if observed_at > evaluated_at:
                    _add(blockers, "ambiguous", f"runtime_observation_in_future:{component_id}")
                    required_offline.add(component_id)
                elif (evaluated_at - observed_at).total_seconds() > maximum_age:
                    _add(blockers, "stale", f"runtime_observation_stale:{component_id}")
                    required_offline.add(component_id)
        else:
            required_offline.add(component_id)

        if component_id in required_offline:
            if artifact is None:
                _add(blockers, "blocked", f"missing_offline_artifact_plan:{component_id}")
            else:
                expected = (
                    requirement["kind"],
                    requirement["version"],
                    requirement["platform_id"],
                    requirement["artifact_sha256"],
                )
                actual = (
                    artifact["kind"],
                    artifact["version"],
                    artifact["platform_id"],
                    artifact["sha256"],
                )
                if actual != expected:
                    _add(blockers, "incompatible", f"offline_artifact_lock_mismatch:{component_id}")
                else:
                    complete_offline_plans.add(key)
                state = artifact["intake_state"]
                if state != "approved":
                    mapped = state if state in _PRECEDENCE else "blocked"
                    _add(blockers, mapped, f"offline_intake_{state}:{component_id}")

    outcome = "contract_pass"
    for candidate in _PRECEDENCE:
        if blockers.get(candidate):
            outcome = candidate
            break
    flat_blockers = sorted(code for codes in blockers.values() for code in codes)
    binding = {
        "design_id": contract["design_id"],
        "client_id": contract["client_id"],
        "workload_id": contract["workload_id"],
        "source_digest": contract["source_digest"],
        "upstream_revision": contract["upstream_revision"],
        "run_id": contract["run_id"],
        "attempt_id": contract["attempt_id"],
        "profile": contract["profile"],
        "contract_digest": digest_value(contract),
    }
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "result_id": stable_id(
            "PKGDES", {**binding, "outcome": outcome, "blockers": flat_blockers}
        ),
        **binding,
        "outcome": outcome,
        "blockers": flat_blockers,
        "required_offline_artifacts": [
            _offline_requirement(
                requirement,
                artifacts[requirement["component_id"].casefold()],
                matrix,
            )
            for requirement in contract["requirements"]
            if requirement["component_id"] in required_offline
            and requirement["component_id"].casefold() in complete_offline_plans
        ],
        "claims": {
            "authorizes_installation": False,
            "authorizes_distribution": False,
            "authorizes_runtime": False,
            "qualifies_final_bundle": False,
            "establishes_humana_readiness": False,
        },
        "content_digest": "",
    }
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    _validate("portability-result.schema.json", result)
    return result


def _result_path(output_root: Path, result: dict[str, Any]) -> Path:
    return (
        output_root
        / "runs"
        / str(result["run_id"])
        / "workloads"
        / str(result["workload_id"])
        / "attempts"
        / str(result["attempt_id"])
        / "portability-design.result.json"
    )


def publish_portability_result(
    output_root: Path, result: dict[str, Any], *, contract: dict[str, Any]
) -> Path:
    """Publish an immutable canonical result after deterministic replay."""

    verify_portability_result(result, contract=contract)
    path = _result_path(output_root, result)
    publish_json(path, result, "portability design result", root=output_root)
    return path


def verify_portability_result(result: dict[str, Any], *, contract: dict[str, Any]) -> None:
    _validate("portability-result.schema.json", result)
    if result != evaluate_portability_design(contract):
        raise ValueError("Portability result does not match deterministic replay")
    if any(blocker.startswith("missing_offline_artifact_plan:") for blocker in result["blockers"]):
        raise ValueError("Portability result is diagnostic-only until its offline plan is complete")


def load_published_portability_result(
    path: Path, *, output_root: Path, contract: dict[str, Any]
) -> dict[str, Any]:
    """Load and replay a canonical root-confined result."""

    try:
        payload = json.loads(
            read_published_bytes(path, root=output_root, label="portability design result"),
            object_pairs_hook=_unique_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Portability result is malformed") from exc
    if (
        not isinstance(payload, dict)
        or path.absolute() != _result_path(output_root, payload).absolute()
    ):
        raise ValueError("Portability result is outside its canonical path")
    verify_portability_result(payload, contract=contract)
    return payload
