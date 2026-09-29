"""Immutable LIC-01 publication, deterministic replay, and derivative recovery."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from smf.compliance.engine import CompliancePolicy, _evaluate_compliance_payload
from smf.compliance.schema import validate_evidence, validate_projection, validate_result
from smf.immutable_files import publish_json, read_published_bytes
from smf.upstream.crypto import digest_value, verify_proof

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate license compliance result key")
        result[key] = value
    return result


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe compliance publication identity")
    return value


def _path(root: Path, payload: dict[str, Any]) -> Path:
    return (
        root
        / "runs"
        / _component(payload["run_id"])
        / "workloads"
        / _component(payload["workload_id"])
        / "attempts"
        / _component(payload["attempt_id"])
        / "license-compliance.result.json"
    )


def _projection(result: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "schema_version": "1.0",
        "projection_type": "license_compliance_non_authorizing",
        "result_id": result["result_id"],
        "decision_id": result["decision_id"],
        "client_id": result["client_id"],
        "workload_id": result["workload_id"],
        "source_digest": result["source_digest"],
        "run_id": result["run_id"],
        "attempt_id": result["attempt_id"],
        "policy_digest": result["policy_digest"],
        "evidence_digest": result["evidence_digest"],
        "outcome": result["outcome"],
        "blockers": result["blockers"],
        "synthetic_contract_pass": result["outcome"] == "contract_pass"
        and result["evidence_class"] == "synthetic_contract",
        "authorizes_real_components": False,
        "authorizes_distribution": False,
        "content_digest": "",
    }
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    validate_projection(payload)
    return payload


def _verify_result(
    result: dict[str, Any], evidence: dict[str, Any], policy: CompliancePolicy
) -> None:
    validate_result(result)
    validate_evidence(evidence)
    provenance = policy.payload["evaluator_provenance"]
    verify_proof(
        result,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(provenance["key_ids"]),
    )
    if result["authority"] not in provenance["authorities"]:
        raise ValueError("Compliance result evaluator authority is not trusted")
    if result["evidence_digest"] != digest_value(evidence):
        raise ValueError("Compliance result evidence changed after evaluation")
    bindings = (
        "client_id",
        "workload_id",
        "source_digest",
        "run_id",
        "attempt_id",
    )
    if any(result[field] != evidence[field] for field in bindings):
        raise ValueError("Compliance result subject binding mismatch")
    if result["policy_digest"] != policy.policy_digest:
        raise ValueError("Compliance result policy binding mismatch")
    if any(result["claims"].values()):
        raise ValueError("Compliance result asserts an unauthorized success claim")
    reconstructed = _evaluate_compliance_payload(evidence, policy=policy)
    if {key: value for key, value in result.items() if key != "proof"} != {
        key: value for key, value in reconstructed.items() if key != "proof"
    }:
        raise ValueError("Compliance result does not match deterministic replay")


def publish_compliance_result(
    output_root: Path,
    result: dict[str, Any],
    *,
    evidence: dict[str, Any],
    policy: CompliancePolicy,
) -> Path:
    """Publish canonical result first; recover missing projection on identical retry."""

    _verify_result(result, evidence, policy)
    path = _path(output_root, result)
    publish_json(path, result, "license compliance result", root=output_root)
    canonical = load_compliance_result(
        path, output_root=output_root, evidence=evidence, policy=policy
    )
    publish_json(
        path.with_name("license-compliance.projection.json"),
        _projection(canonical),
        "license compliance projection",
        root=output_root,
    )
    return path


def load_compliance_result(
    path: Path,
    *,
    output_root: Path,
    evidence: dict[str, Any],
    policy: CompliancePolicy,
) -> dict[str, Any]:
    try:
        payload = json.loads(
            read_published_bytes(path, root=output_root, label="license compliance result"),
            object_pairs_hook=_unique_pairs,
        )
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("License compliance result is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("License compliance result must be an object")
    expected = _path(output_root, payload)
    if (
        path.absolute() != expected.absolute()
        or path.is_symlink()
        or path.resolve() != expected.resolve()
    ):
        raise ValueError("License compliance result is outside its canonical path")
    _verify_result(payload, evidence, policy)
    return payload


def verify_compliance_projection(projection: dict[str, Any], result: dict[str, Any]) -> None:
    validate_projection(projection)
    if projection != _projection(result):
        raise ValueError("Compliance projection does not reconstruct canonical evidence")
