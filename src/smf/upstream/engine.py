"""Fail-closed evaluation of immutable upstream evidence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import digest_value, sign_payload, verify_proof
from smf.upstream.models import QualificationOutcome, UpstreamQualificationRequest
from smf.upstream.policy import (
    UpstreamInventory,
    UpstreamPolicy,
    load_upstream_inventory,
    load_upstream_policy,
)
from smf.upstream.schema import validate_receipt
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$")


def _identity(value: str, label: str) -> str:
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or contains_protected_data(value)
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"Unsafe upstream {label}")
    return value


def _load_object(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate key in upstream evidence")
        result[key] = value
    return result


def _safe_file(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative or not relative.isascii():
        raise ValueError(f"{label} path is unsafe")
    decoded = relative
    for _ in range(4):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    else:
        raise ValueError(f"{label} path is unsafe")
    lexical = Path(decoded)
    if lexical.is_absolute() or any(
        part in {"", ".", ".."} or not _SAFE_PART.fullmatch(part) for part in lexical.parts
    ):
        raise ValueError(f"{label} path escapes evidence root")
    root = root.resolve()
    path = root / lexical
    if any(
        root.joinpath(*lexical.parts[:index]).is_symlink()
        for index in range(1, len(lexical.parts) + 1)
    ):
        raise ValueError(f"{label} path is a symlink")
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError(f"{label} path escapes evidence root")
    return resolved


def _file_record(root: Path, record: dict[str, Any], label: str) -> dict[str, Any]:
    path = _safe_file(root, record["relative_path"], label)
    data = path.read_bytes()
    observed = hashlib.sha256(data).hexdigest()
    if not data or len(data) != record["byte_count"] or observed != record["sha256"]:
        raise ValueError(f"{label} bytes do not match attributable evidence")
    return {
        "relative_path": record["relative_path"],
        "artifact_type": record.get("artifact_type", "license"),
        "byte_count": len(data),
        "sha256": observed,
    }


def _verify_supporting_evidence(
    root: Path,
    file_reference: dict[str, Any],
    *,
    expected_class: str,
    receipt: dict[str, Any],
    policy: UpstreamPolicy,
) -> dict[str, Any]:
    path = _safe_file(root, file_reference["relative_path"], "Supporting evidence")
    evidence = _load_object(path, "Supporting evidence")
    required = {
        "schema_version",
        "record_id",
        "evidence_id",
        "evidence_class",
        "upstream_id",
        "revision",
        "scope_id",
        "run_id",
        "attempt_id",
        "authority",
        "payload",
        "proof",
    }
    if set(evidence) != required or not isinstance(evidence["payload"], dict):
        raise ValueError("Supporting evidence has unknown or missing fields")
    if contains_protected_data(json.dumps({**evidence, "proof": {}}, sort_keys=True)):
        raise ValueError("Supporting evidence contains protected data or a secret")
    verify_proof(
        evidence,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(policy.payload["supporting_evidence_provenance"]["key_ids"]),
    )
    if evidence["authority"] not in policy.payload["supporting_evidence_provenance"]["authorities"]:
        raise ValueError("Supporting evidence authority is not trusted")
    bindings = {
        "upstream_id": receipt["upstream_id"],
        "revision": receipt["revision"],
        "scope_id": receipt["scope_id"],
        "run_id": receipt["run_id"],
        "attempt_id": receipt["attempt_id"],
    }
    if (
        evidence["schema_version"] != "1.0"
        or evidence["evidence_class"] != expected_class
        or any(evidence.get(key) != value for key, value in bindings.items())
    ):
        raise ValueError("Supporting evidence identity binding mismatch")
    expected_id = stable_id(
        "UPQE",
        {
            **bindings,
            "evidence_id": evidence["evidence_id"],
            "evidence_class": evidence["evidence_class"],
            "authority": evidence["authority"],
            "payload": evidence["payload"],
        },
    )
    if evidence["record_id"] != expected_id:
        raise ValueError("Supporting evidence identity is not reconstructable")
    return evidence


def _verify_acquisition(
    receipt: dict[str, Any], policy: UpstreamPolicy, artifact: dict[str, Any]
) -> None:
    acquisition = receipt["acquisition"]
    verify_proof(
        acquisition,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(policy.payload["acquisition_provenance"]["key_ids"]),
    )
    if acquisition["authority"] not in policy.payload["acquisition_provenance"]["authorities"]:
        raise ValueError("Artifact acquisition authority is not trusted")
    expected = {
        "upstream_id": receipt["upstream_id"],
        "canonical_origin": receipt["canonical_origin"],
        "revision": receipt["revision"],
        "revision_type": receipt["revision_type"],
        "artifact": artifact,
    }
    if any(acquisition.get(key) != value for key, value in expected.items()):
        raise ValueError("Artifact acquisition evidence is not bound to qualified bytes")
    expected_id = stable_id(
        "UPQA",
        {
            "upstream_id": receipt["upstream_id"],
            "revision": receipt["revision"],
            "artifact_sha256": artifact["sha256"],
            "authority": acquisition["authority"],
        },
    )
    if acquisition["acquisition_id"] != expected_id:
        raise ValueError("Artifact acquisition identity is not reconstructable")


def _verify_prerequisite(
    root: Path, policy: UpstreamPolicy, *, scope_id: str, run_id: str, attempt_id: str
) -> tuple[QualificationOutcome | None, str | None, dict[str, Any]]:
    requirement = policy.payload["prerequisite"]
    path = _safe_file(root, requirement["evidence_path"], "Prerequisite evidence")
    evidence = _load_object(path, "Prerequisite evidence")
    required = {
        "schema_version",
        "prerequisite_id",
        "scope_id",
        "run_id",
        "attempt_id",
        "status",
        "implementation_state",
        "acceptance_digest",
        "authority",
        "decision_id",
        "decision_state",
        "proof",
    }
    if set(evidence) != required:
        raise ValueError("Prerequisite evidence has unknown or missing fields")
    verify_proof(
        evidence,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(policy.payload["prerequisite_provenance"]["key_ids"]),
    )
    if evidence["authority"] not in policy.payload["prerequisite_provenance"]["authorities"]:
        raise ValueError("Prerequisite authority is not trusted")
    if (
        evidence["schema_version"] != "1.0"
        or evidence["prerequisite_id"] != requirement["prerequisite_id"]
        or evidence["scope_id"] != scope_id
        or evidence["run_id"] != run_id
        or evidence["attempt_id"] != attempt_id
    ):
        raise ValueError("Prerequisite evidence identity binding mismatch")
    if evidence["acceptance_digest"] != requirement["acceptance_digest"]:
        raise ValueError("Prerequisite evidence does not match the approved acceptance source")
    expected_decision_id = stable_id(
        "PREREQ",
        {
            "prerequisite_id": evidence["prerequisite_id"],
            "acceptance_digest": evidence["acceptance_digest"],
            "scope_id": evidence["scope_id"],
            "run_id": evidence["run_id"],
            "attempt_id": evidence["attempt_id"],
            "authority": evidence["authority"],
        },
    )
    if evidence["decision_id"] != expected_decision_id:
        raise ValueError("Prerequisite decision identity is not reconstructable")
    if evidence["decision_state"] != "current":
        raise ValueError("Prerequisite decision is superseded")
    state = (evidence["status"], evidence["implementation_state"])
    if state == ("Done", "Foundation Complete"):
        return None, None, evidence
    if evidence["status"] == "Denied":
        return QualificationOutcome.DENIED, "prerequisite_denied", evidence
    if evidence["status"] in {"Todo", "In Progress", "Pending"}:
        return QualificationOutcome.BLOCKED_PENDING, "prerequisite_pending", evidence
    return QualificationOutcome.FAILED, "prerequisite_failed", evidence


def _evaluate_receipt(
    root: Path,
    expected: dict[str, Any],
    policy: UpstreamPolicy,
    inventory: UpstreamInventory,
    *,
    scope_id: str,
    run_id: str,
    attempt_id: str,
    evaluation_time: datetime,
) -> dict[str, Any]:
    relative_receipt = f"receipts/{expected['upstream_id']}.json"
    receipt_path = root / relative_receipt
    if not receipt_path.exists():
        return {
            "upstream_id": expected["upstream_id"],
            "revision": expected["revision"],
            "outcome": QualificationOutcome.BLOCKED_MISSING.value,
            "disposition": expected["disposition"],
            "permitted_use": [],
            "blockers": ["observation_receipt_missing"],
            "receipt_present": False,
            "receipt_digest": None,
            "files": [],
        }
    receipt_path = _safe_file(root, relative_receipt, "Observation receipt")
    receipt = _load_object(receipt_path, "Observation receipt")
    protected_view = {
        **receipt,
        "proof": {},
        "acquisition": {**receipt.get("acquisition", {}), "proof": {}},
    }
    if contains_protected_data(json.dumps(protected_view, sort_keys=True)):
        raise ValueError("Observation receipt contains protected data or a secret")
    validate_receipt(receipt)
    verify_proof(
        receipt,
        trusted_keys=policy.payload["verification_keys"],
        allowed_key_ids=set(policy.payload["observer_provenance"]["key_ids"]),
    )
    if receipt["observer_authority"] not in policy.payload["observer_provenance"]["authorities"]:
        raise ValueError("Observation authority is not trusted")
    bindings = {
        "upstream_id": expected["upstream_id"],
        "canonical_origin": expected["canonical_origin"],
        "revision": expected["revision"],
        "revision_type": expected["revision_type"],
        "artifact_class": expected["artifact_class"],
        "scope_id": scope_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "policy_digest": policy.policy_digest,
        "inventory_digest": inventory.inventory_digest,
        "disposition": expected["disposition"],
        "permitted_use": expected["permitted_use"],
    }
    if any(receipt.get(key) != value for key, value in bindings.items()):
        raise ValueError("Observation receipt identity or authority binding mismatch")
    artifact = _file_record(root, receipt["artifact"], "Upstream artifact")
    expected_receipt_id = stable_id(
        "UPQR",
        {
            **bindings,
            "artifact_sha256": artifact["sha256"],
            "observer_authority": receipt["observer_authority"],
        },
    )
    if receipt["receipt_id"] != expected_receipt_id:
        raise ValueError("Observation receipt identity is not reconstructable")
    _verify_acquisition(receipt, policy, artifact)
    expected_licenses = sorted(
        (item["evidence_id"], item["license_id"]) for item in expected["license_evidence"]
    )
    supplied_licenses = sorted(
        (item["evidence_id"], item["license_id"]) for item in receipt["license_evidence"]
    )
    if expected_licenses != supplied_licenses:
        raise ValueError("License evidence inventory does not match governed expectation")
    license_files = [
        _file_record(root, item, "License evidence") for item in receipt["license_evidence"]
    ]
    evidence_paths = [artifact["relative_path"], *(item["relative_path"] for item in license_files)]
    if len(evidence_paths) != len(set(evidence_paths)):
        raise ValueError("Artifact and license evidence paths must be distinct")
    expected_capabilities = {item["capability_id"] for item in expected["capabilities"]}
    supplied_capabilities = {item["capability_id"] for item in receipt["capability_evidence"]}
    if len(supplied_capabilities) != len(receipt["capability_evidence"]):
        raise ValueError("Capability evidence identity is duplicated")
    if expected_capabilities != supplied_capabilities:
        raise ValueError("Capability evidence inventory does not match governed expectation")
    expected_limitations = {item["limitation_id"] for item in expected["limitations"]}
    if expected_limitations != set(receipt["observed_limitation_ids"]):
        raise ValueError("Observed limitation inventory does not match governed expectation")
    activity = receipt["activity"]
    if (
        activity["source"] != expected["activity_source"]
        or activity["revision"] != expected["revision"]
    ):
        raise ValueError("Activity observation is not bound to the expected revision")
    try:
        observed_at = datetime.fromisoformat(activity["observed_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Activity observation timestamp is malformed") from exc
    if observed_at.tzinfo is None:
        raise ValueError("Activity observation timestamp must have a timezone")
    freshness = policy.payload["activity_freshness"]
    age_seconds = (evaluation_time - observed_at).total_seconds()
    expired = age_seconds > freshness["max_age_seconds"]
    from_future = age_seconds < -freshness["max_future_skew_seconds"]
    blockers: list[str] = []
    outcome = QualificationOutcome.QUALIFIED
    for capability in receipt["capability_evidence"]:
        supporting = [
            _file_record(root, capability["execution_evidence"], "Capability execution evidence"),
            _file_record(
                root, capability["environment_evidence"], "Capability environment evidence"
            ),
            _file_record(root, capability["output_evidence"], "Capability output evidence"),
            _file_record(
                root, capability["negative_case_evidence"], "Capability negative-case evidence"
            ),
        ]
        expected_types = [
            "execution_record",
            "environment_manifest",
            "command_output",
            "negative_case_record",
        ]
        if [item["artifact_type"] for item in supporting] != expected_types:
            raise ValueError("Capability references the wrong immutable evidence classes")
        records = [
            _verify_supporting_evidence(
                root,
                capability[field],
                expected_class=evidence_class,
                receipt=receipt,
                policy=policy,
            )
            for field, evidence_class in zip(
                (
                    "execution_evidence",
                    "environment_evidence",
                    "output_evidence",
                    "negative_case_evidence",
                ),
                expected_types,
                strict=True,
            )
        ]
        if (
            supporting[1]["sha256"] != capability["environment_digest"]
            or supporting[2]["sha256"] != capability["output_digest"]
        ):
            raise ValueError("Capability digests do not match immutable supporting evidence")
        execution_payload = records[0]["payload"]
        expected_execution = {
            "command": capability["command"],
            "expected_outcome": capability["expected_outcome"],
            "actual_outcome": capability["actual_outcome"],
            "exit_status": capability["exit_status"],
            "execution_state": capability["execution_state"],
        }
        if (
            records[0]["evidence_id"] != capability["evidence_id"]
            or execution_payload != expected_execution
        ):
            raise ValueError("Capability assertion does not match attributable execution evidence")
        if records[3]["payload"].get("outcome") != "rejected":
            raise ValueError("Capability negative-case evidence does not prove rejection")
        evidence_paths.extend(item["relative_path"] for item in supporting)
        if capability["execution_state"] in {"skipped", "not_executed"}:
            outcome = QualificationOutcome.UNSUPPORTED
            blockers.append(f"capability_not_executed:{capability['capability_id']}")
        elif capability["execution_state"] == "failed" or capability["actual_outcome"] != "pass":
            outcome = QualificationOutcome.FAILED
            blockers.append(f"capability_failed:{capability['capability_id']}")
        elif capability["expected_outcome"] != "pass" or capability["exit_status"] != 0:
            outcome = QualificationOutcome.FAILED
            blockers.append(f"capability_outcome_inconsistent:{capability['capability_id']}")
        if capability["mocked"] or capability["generated_only"]:
            outcome = QualificationOutcome.UNSUPPORTED
            blockers.append(f"capability_not_external_evidence:{capability['capability_id']}")
    compatibility = receipt["compatibility"]
    compatibility_evidence = _file_record(root, compatibility["evidence"], "Compatibility evidence")
    if compatibility_evidence["artifact_type"] != "compatibility_record":
        raise ValueError("Compatibility references the wrong immutable evidence class")
    compatibility_record = _verify_supporting_evidence(
        root,
        compatibility["evidence"],
        expected_class="compatibility_record",
        receipt=receipt,
        policy=policy,
    )
    if compatibility_record["evidence_id"] != compatibility["evidence_id"] or compatibility_record[
        "payload"
    ] != {
        "state": compatibility["state"],
        "environment_digest": compatibility["environment_digest"],
    }:
        raise ValueError("Compatibility assertion does not match attributable review evidence")
    evidence_paths.append(compatibility_evidence["relative_path"])
    if len(evidence_paths) != len(set(evidence_paths)):
        raise ValueError("Immutable capability or compatibility evidence is duplicated")
    if compatibility["state"] == "pending":
        outcome = QualificationOutcome.BLOCKED_PENDING
        blockers.append("compatibility_pending")
    elif compatibility["state"] == "incompatible":
        outcome = QualificationOutcome.INCOMPATIBLE
        blockers.append("compatibility_incompatible")
    elif compatibility["state"] == "unsupported":
        outcome = QualificationOutcome.UNSUPPORTED
        blockers.append("compatibility_unsupported")
    if expired and outcome is QualificationOutcome.QUALIFIED:
        outcome = QualificationOutcome.STALE
        blockers.append("activity_observation_expired")
    elif from_future and outcome is QualificationOutcome.QUALIFIED:
        outcome = QualificationOutcome.STALE
        blockers.append("activity_observation_from_future")
    files = [artifact, *license_files]
    for capability in receipt["capability_evidence"]:
        files.extend(
            _file_record(root, capability[field], f"Capability {field}")
            for field in (
                "execution_evidence",
                "environment_evidence",
                "output_evidence",
                "negative_case_evidence",
            )
        )
    files.append(compatibility_evidence)
    files.append(
        {
            "relative_path": relative_receipt,
            "artifact_type": "observation_receipt",
            "byte_count": receipt_path.stat().st_size,
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        }
    )
    return {
        "upstream_id": expected["upstream_id"],
        "revision": expected["revision"],
        "outcome": outcome.value,
        "disposition": expected["disposition"],
        "permitted_use": (
            receipt["permitted_use"] if outcome is QualificationOutcome.QUALIFIED else []
        ),
        "blockers": sorted(blockers),
        "receipt_present": True,
        "receipt_digest": digest_value(receipt),
        "files": files,
    }


def qualify_upstreams(request: UpstreamQualificationRequest) -> dict[str, Any]:
    """Evaluate once per decision identity and sign the complete deterministic result."""

    for label in (
        "scope_id",
        "run_id",
        "attempt_id",
        "signing_key_id",
        "signing_authority",
    ):
        _identity(str(getattr(request, label)), label)
    policy = load_upstream_policy(request.policy_path)
    inventory = load_upstream_inventory(request.inventory_path)
    try:
        evaluation_time = datetime.fromisoformat(request.evaluation_time.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Qualification evaluation time is malformed") from exc
    if evaluation_time.tzinfo is None:
        raise ValueError("Qualification evaluation time must have a timezone")
    if request.signing_key_id not in policy.payload["qualification_provenance"]["key_ids"]:
        raise ValueError("Qualification signing key is not trusted by policy")
    if request.signing_authority not in policy.payload["qualification_provenance"]["authorities"]:
        raise ValueError("Qualification signing authority is not trusted by policy")
    root = request.evidence_root
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Upstream evidence root is missing or unsafe")
    root = root.resolve()
    prerequisite_outcome, prerequisite_blocker, prerequisite = _verify_prerequisite(
        root,
        policy,
        scope_id=request.scope_id,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
    )
    prerequisite_path = _safe_file(
        root, policy.payload["prerequisite"]["evidence_path"], "Prerequisite evidence"
    )
    prerequisite_bytes = prerequisite_path.read_bytes()
    prerequisite_file = {
        "relative_path": policy.payload["prerequisite"]["evidence_path"],
        "artifact_type": "prerequisite_record",
        "byte_count": len(prerequisite_bytes),
        "sha256": hashlib.sha256(prerequisite_bytes).hexdigest(),
    }
    decisions = [
        _evaluate_receipt(
            root,
            item,
            policy,
            inventory,
            scope_id=request.scope_id,
            run_id=request.run_id,
            attempt_id=request.attempt_id,
            evaluation_time=evaluation_time,
        )
        for item in inventory.payload["upstreams"]
    ]
    if prerequisite_outcome is not None:
        for item in decisions:
            if item["outcome"] == QualificationOutcome.QUALIFIED.value:
                item["outcome"] = prerequisite_outcome.value
                item["blockers"] = [str(prerequisite_blocker)]
    outcomes = [QualificationOutcome(item["outcome"]) for item in decisions]
    precedence = [
        QualificationOutcome.DENIED,
        QualificationOutcome.FAILED,
        QualificationOutcome.AMBIGUOUS,
        QualificationOutcome.INCOMPATIBLE,
        QualificationOutcome.STALE,
        QualificationOutcome.UNSUPPORTED,
        QualificationOutcome.BLOCKED_MISSING,
        QualificationOutcome.BLOCKED_PENDING,
    ]
    terminal = QualificationOutcome.QUALIFIED
    for candidate in precedence:
        if candidate in outcomes:
            terminal = candidate
            break
    identity = {
        "scope_id": request.scope_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "evaluation_time": request.evaluation_time,
        "policy_digest": policy.policy_digest,
        "inventory_digest": inventory.inventory_digest,
    }
    result = {
        "schema_version": "1.0",
        "contract_version": "smf-upstream-qualification-v1",
        "result_id": stable_id("UPQ", identity),
        "decision_id": stable_id("UPQD", identity),
        **identity,
        "scope_kind": policy.payload["scope_kind"],
        "policy_id": policy.payload["policy_id"],
        "policy_version": policy.payload["policy_version"],
        "inventory_id": inventory.payload["inventory_id"],
        "inventory_version": inventory.payload["inventory_version"],
        "qualification_authority": request.signing_authority,
        "prerequisite": prerequisite,
        "prerequisite_file": prerequisite_file,
        "decisions": decisions,
        "outcome": terminal.value,
        "blockers": sorted({blocker for item in decisions for blocker in item["blockers"]}),
        "claims": {
            "installed": False,
            "security_cleared": False,
            "legally_approved": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "promoted": False,
            "human_approved": False,
        },
        "content_digest": "",
        "proof": {},
    }
    result["content_digest"] = digest_value({**result, "content_digest": "", "proof": {}})
    sign_payload(result, private_key_path=request.signing_key_path, key_id=request.signing_key_id)
    return result
