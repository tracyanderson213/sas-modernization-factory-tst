"""Append-only publication, replay verification, and derived recovery."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from smf.immutable_files import publish_json, read_published_json
from smf.upstream.crypto import digest_value, verify_proof
from smf.upstream.policy import UpstreamInventory, UpstreamPolicy
from smf.upstream.schema import validate_projection, validate_result
from smf.workload.identity import stable_id

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe upstream qualification identity")
    return value


def qualification_result_path(root: Path, payload: dict[str, Any]) -> Path:
    return (
        root
        / "runs"
        / _component(payload["run_id"])
        / "upstream"
        / _component(payload["scope_id"])
        / "attempts"
        / _component(payload["attempt_id"])
        / "qualification.result.json"
    )


def _publish(path: Path, payload: dict[str, Any], label: str, *, root: Path) -> None:
    try:
        publish_json(path, payload, f"upstream {label}", root=root)
    except ValueError as exc:
        raise ValueError(f"Unsafe immutable upstream {label} path") from exc


def _projection(payload: dict[str, Any]) -> dict[str, Any]:
    result = {
        "schema_version": "1.0",
        "projection_type": "bounded_upstream_permitted_use",
        "result_id": payload["result_id"],
        "result_digest": payload["content_digest"],
        "scope_id": payload["scope_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "policy_digest": payload["policy_digest"],
        "inventory_digest": payload["inventory_digest"],
        "outcome": payload["outcome"],
        "entries": [
            {
                "upstream_id": item["upstream_id"],
                "revision": item["revision"],
                "outcome": item["outcome"],
                "disposition": item["disposition"],
                "permitted_use": (
                    item["permitted_use"]
                    if item["outcome"] == "qualified" and item["receipt_present"]
                    else []
                ),
                "receipt_digest": item["receipt_digest"],
                "selection_reason_required": True,
                "authorizes_execution": False,
                "authorizes_copying": item["disposition"] == "reuse_selected_licensed_components"
                and item["outcome"] == "qualified"
                and "licensed_component" in item["permitted_use"],
            }
            for item in payload["decisions"]
        ],
        "content_digest": "",
    }
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    validate_projection(result)
    return result


def _telemetry(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event": "upstream_qualification_evaluated",
        "result_id": payload["result_id"],
        "decision_id": payload["decision_id"],
        "scope_id": payload["scope_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "outcome": payload["outcome"],
        "qualified_count": sum(item["outcome"] == "qualified" for item in payload["decisions"]),
        "blocked_count": sum(item["outcome"] != "qualified" for item in payload["decisions"]),
        "authorizes_execution": False,
        "human_approved": False,
    }


def _verify(
    payload: dict[str, Any],
    *,
    evidence_root: Path,
    trusted_policy: UpstreamPolicy,
    trusted_inventory: UpstreamInventory,
) -> None:
    validate_result(payload)
    if payload["content_digest"] != digest_value({**payload, "content_digest": "", "proof": {}}):
        raise ValueError("Upstream result content digest mismatch")
    verify_proof(
        payload,
        trusted_keys=trusted_policy.payload["verification_keys"],
        allowed_key_ids=set(trusted_policy.payload["qualification_provenance"]["key_ids"]),
    )
    if payload["policy_digest"] != trusted_policy.policy_digest:
        raise ValueError("Upstream result trusted policy binding mismatch")
    if (
        payload["qualification_authority"]
        not in trusted_policy.payload["qualification_provenance"]["authorities"]
    ):
        raise ValueError("Upstream result qualification authority is not trusted")
    if payload["inventory_digest"] != trusted_inventory.inventory_digest:
        raise ValueError("Upstream result trusted inventory binding mismatch")
    prerequisite = payload["prerequisite"]
    requirement = trusted_policy.payload["prerequisite"]
    verify_proof(
        prerequisite,
        trusted_keys=trusted_policy.payload["verification_keys"],
        allowed_key_ids=set(trusted_policy.payload["prerequisite_provenance"]["key_ids"]),
    )
    expected_prerequisite_id = stable_id(
        "PREREQ",
        {
            "prerequisite_id": prerequisite["prerequisite_id"],
            "acceptance_digest": prerequisite["acceptance_digest"],
            "scope_id": prerequisite["scope_id"],
            "run_id": prerequisite["run_id"],
            "attempt_id": prerequisite["attempt_id"],
            "authority": prerequisite["authority"],
        },
    )
    if (
        prerequisite["prerequisite_id"] != requirement["prerequisite_id"]
        or prerequisite["acceptance_digest"] != requirement["acceptance_digest"]
        or prerequisite["decision_id"] != expected_prerequisite_id
        or prerequisite["decision_state"] != "current"
        or prerequisite["authority"]
        not in trusted_policy.payload["prerequisite_provenance"]["authorities"]
        or prerequisite["scope_id"] != payload["scope_id"]
        or prerequisite["run_id"] != payload["run_id"]
        or prerequisite["attempt_id"] != payload["attempt_id"]
    ):
        raise ValueError("Upstream result prerequisite binding mismatch")
    prerequisite_complete = (prerequisite["status"], prerequisite["implementation_state"]) == (
        "Done",
        "Foundation Complete",
    )
    if not prerequisite_complete and any(
        decision["outcome"] == "qualified" for decision in payload["decisions"]
    ):
        raise ValueError("Qualified upstream has no canonical prerequisite completion")
    expected_ids = [item["upstream_id"] for item in trusted_inventory.payload["upstreams"]]
    if [item["upstream_id"] for item in payload["decisions"]] != expected_ids:
        raise ValueError("Upstream result inventory identity binding mismatch")
    for expected, decision in zip(
        trusted_inventory.payload["upstreams"], payload["decisions"], strict=True
    ):
        if (
            decision["revision"] != expected["revision"]
            or decision["disposition"] != expected["disposition"]
        ):
            raise ValueError("Upstream result broadens or substitutes governed inventory")
        permitted = expected["permitted_use"] if decision["outcome"] == "qualified" else []
        if decision["permitted_use"] != permitted:
            raise ValueError("Upstream permitted-use projection is not fail closed")
    identity = {
        "scope_id": payload["scope_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "evaluation_time": payload["evaluation_time"],
        "policy_digest": payload["policy_digest"],
        "inventory_digest": payload["inventory_digest"],
    }
    if payload["result_id"] != stable_id("UPQ", identity) or payload["decision_id"] != stable_id(
        "UPQD", identity
    ):
        raise ValueError("Upstream result identity mismatch")
    if any(payload["claims"].values()):
        raise ValueError("Upstream qualification asserts an unauthorized lifecycle claim")
    root = evidence_root.resolve()
    referenced_files = [payload["prerequisite_file"]]
    referenced_files.extend(
        record for decision in payload["decisions"] for record in decision["files"]
    )
    for record in referenced_files:
        lexical = root / record["relative_path"]
        try:
            relative_parts = lexical.absolute().relative_to(root.absolute()).parts
        except ValueError as exc:
            raise ValueError("Upstream evidence reference escapes root") from exc
        if any(
            root.joinpath(*relative_parts[:index]).is_symlink()
            for index in range(1, len(relative_parts) + 1)
        ):
            raise ValueError("Upstream evidence reference is a symlink")
        path = lexical.resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Upstream evidence reference is missing or outside root")
        data = path.read_bytes()
        if (
            len(data) != record["byte_count"]
            or hashlib.sha256(data).hexdigest() != record["sha256"]
        ):
            raise ValueError("Upstream evidence bytes changed after qualification")
    prerequisite_path = root / payload["prerequisite_file"]["relative_path"]
    try:
        current_prerequisite = json.loads(prerequisite_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Upstream prerequisite evidence is malformed") from exc
    if current_prerequisite != prerequisite:
        raise ValueError("Upstream prerequisite evidence changed after qualification")
    for decision in payload["decisions"]:
        if decision["outcome"] == "qualified" and (
            not decision["receipt_present"]
            or decision["receipt_digest"] is None
            or decision["blockers"]
        ):
            raise ValueError("Qualified upstream lacks reconstructable evidence")
    precedence = [
        "denied",
        "failed",
        "ambiguous",
        "incompatible",
        "stale",
        "unsupported",
        "blocked_missing",
        "blocked_pending",
    ]
    outcomes = {item["outcome"] for item in payload["decisions"]}
    expected_outcome = next((item for item in precedence if item in outcomes), "qualified")
    expected_blockers = sorted(
        {blocker for decision in payload["decisions"] for blocker in decision["blockers"]}
    )
    if payload["outcome"] != expected_outcome or payload["blockers"] != expected_blockers:
        raise ValueError("Upstream terminal outcome does not reconcile decision evidence")


def write_qualification_result(
    output_root: Path,
    payload: dict[str, Any],
    *,
    evidence_root: Path,
    trusted_policy: UpstreamPolicy,
    trusted_inventory: UpstreamInventory,
) -> Path:
    """Publish canonical evidence first, then recoverable projection and telemetry."""

    _verify(
        payload,
        evidence_root=evidence_root,
        trusted_policy=trusted_policy,
        trusted_inventory=trusted_inventory,
    )
    path = qualification_result_path(output_root, payload)
    _publish(path, payload, "qualification result", root=output_root)
    canonical = load_qualification_result(
        path,
        output_root=output_root,
        evidence_root=evidence_root,
        trusted_policy=trusted_policy,
        trusted_inventory=trusted_inventory,
    )
    _publish(
        path.with_name("consumer.projection.json"),
        _projection(canonical),
        "projection",
        root=output_root,
    )
    _publish(
        path.with_name("telemetry.json"),
        _telemetry(canonical),
        "telemetry",
        root=output_root,
    )
    return path


def load_qualification_result(
    path: Path,
    *,
    output_root: Path,
    evidence_root: Path,
    trusted_policy: UpstreamPolicy,
    trusted_inventory: UpstreamInventory,
) -> dict[str, Any]:
    try:
        payload = read_published_json(path, root=output_root, label="upstream result")
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Upstream result is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("Upstream result must be an object")
    expected = qualification_result_path(output_root, payload)
    if (
        path.absolute() != expected.absolute()
        or path.is_symlink()
        or path.resolve() != expected.resolve()
    ):
        raise ValueError("Upstream result is outside its canonical evidence path")
    _verify(
        payload,
        evidence_root=evidence_root,
        trusted_policy=trusted_policy,
        trusted_inventory=trusted_inventory,
    )
    return payload


def verify_consumer_projection(projection: dict[str, Any], result: dict[str, Any]) -> None:
    validate_projection(projection)
    if projection != _projection(result):
        raise ValueError("Upstream consumer projection does not reconstruct canonical evidence")
