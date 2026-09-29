"""Verification and byte acquisition for an approved SAS export package."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.baseline.policy import BaselineAcquisitionPolicy
from smf.baseline.schema import validate_receipt
from smf.readiness.policy import canonical_json, digest_value
from smf.security.ai_admission import contains_protected_data
from smf.workload.sanitization import sanitize_discovery_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def receipt_subject(receipt: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(receipt)
    unsigned.pop("proof", None)
    return unsigned


def receipt_digest(receipt: dict[str, Any]) -> str:
    return digest_value(receipt_subject(receipt))


def approval_subject_digest(receipt: dict[str, Any], policy_digest: str) -> str:
    """Bind approval to the complete technical acquisition subject."""

    subject = receipt_subject(receipt)
    return digest_value({"receipt": subject, "acquisition_policy_digest": policy_digest})


def _verify_signature(
    payload: dict[str, Any], *, key_ids: list[str], keys: dict[str, str], label: str
) -> str:
    proof = payload.get("proof")
    if not isinstance(proof, dict) or set(proof) != {"algorithm", "key_id", "value"}:
        raise ValueError(f"{label} proof is invalid")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or key_id not in key_ids or key_id not in keys:
        raise ValueError(f"{label} proof is not trusted")
    unsigned = dict(payload)
    unsigned.pop("proof", None)
    try:
        public = base64.b64decode(keys[str(key_id)], validate=True)
        signature = base64.b64decode(proof["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, canonical_json(unsigned).encode("utf-8")
        )
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError(f"{label} proof is invalid") from exc
    return str(key_id)


def _safe_package_file(root: Path, reference: str) -> Path:
    if not reference or contains_protected_data(reference):
        raise ValueError("Export artifact reference is unsafe")
    decoded = reference
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    relative = Path(decoded)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Export artifact reference escapes package root")
    root = root.resolve()
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Export artifact reference is symlinked")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("Export artifact is missing or outside package root")
    return resolved


def verify_receipt(
    receipt: dict[str, Any], policy: BaselineAcquisitionPolicy, *, now: datetime | None = None
) -> str:
    validate_receipt(receipt)
    safe = sanitize_discovery_value(receipt)
    if safe != receipt or contains_protected_data(json.dumps(receipt, sort_keys=True)):
        raise ValueError("Baseline export receipt contains sensitive durable content")
    producer = policy.payload["producer_provenance"]
    if receipt["producer_authority"] not in producer["authorities"]:
        raise ValueError("Baseline export producer authority is not permitted")
    if receipt["provider"] != policy.payload["provider"]:
        raise ValueError("Baseline export provider binding mismatch")
    if receipt["provider_version"] != policy.payload["provider_version"]:
        raise ValueError("Baseline export provider version binding mismatch")
    if receipt["format"] not in policy.payload["allowed_output_formats"]:
        raise ValueError("Baseline export output format is not permitted")
    observed = now or datetime.now(UTC)
    try:
        executed = datetime.fromisoformat(receipt["executed_at"].replace("Z", "+00:00"))
        exported = datetime.fromisoformat(receipt["exported_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Baseline export timestamps are invalid") from exc
    if (
        executed.tzinfo is None
        or exported.tzinfo is None
        or executed > exported
        or exported > observed
        or (observed - exported).total_seconds() > policy.payload["max_export_age_seconds"]
    ):
        raise ValueError("Baseline export receipt is stale or future-dated")
    return _verify_signature(
        receipt,
        key_ids=producer["key_ids"],
        keys=policy.payload["verification_keys"],
        label="Baseline export receipt",
    )


def verify_approval(
    approval: dict[str, Any],
    receipt: dict[str, Any],
    policy: BaselineAcquisitionPolicy,
    *,
    producer_key_id: str,
    now: datetime | None = None,
) -> tuple[str, str]:
    required = {
        "schema_version",
        "decision_id",
        "state",
        "authority",
        "owner_assignment_ref",
        "subject_digest",
        "issued_at",
        "expires_at",
        "proof",
    }
    if set(approval) != required or approval.get("schema_version") != "1.0":
        raise ValueError("Baseline acquisition decision is malformed")
    if (
        sanitize_discovery_value(approval) != approval
        or contains_protected_data(json.dumps(approval, sort_keys=True))
        or any(
            not isinstance(approval.get(field), str) or not _SAFE_ID.fullmatch(str(approval[field]))
            for field in ("decision_id", "authority", "owner_assignment_ref")
        )
    ):
        raise ValueError("Baseline acquisition decision contains unsafe durable identity")
    if approval.get("state") not in {"approved", "pending", "denied"}:
        raise ValueError("Baseline acquisition decision state is invalid")
    if approval.get("subject_digest") != approval_subject_digest(receipt, policy.policy_digest):
        raise ValueError("Baseline acquisition decision subject binding mismatch")
    provenance = policy.payload["approval_provenance"]
    if approval.get("authority") not in provenance["authorities"]:
        raise ValueError("Baseline acquisition decision authority is not permitted")
    try:
        issued = datetime.fromisoformat(str(approval["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(approval["expires_at"]).replace("Z", "+00:00"))
        current = now or datetime.now(UTC)
    except ValueError as exc:
        raise ValueError("Baseline acquisition decision validity is invalid") from exc
    if issued.tzinfo is None or expires.tzinfo is None or current < issued or current >= expires:
        raise ValueError("Baseline acquisition decision is not currently valid")
    key_id = _verify_signature(
        approval,
        key_ids=provenance["key_ids"],
        keys=policy.payload["verification_keys"],
        label="Baseline acquisition decision",
    )
    if key_id == producer_key_id:
        raise ValueError("Baseline producer and approval must be separately attributable")
    return str(approval["state"]), key_id


def acquire_output_bytes(
    receipt: dict[str, Any], package_root: Path, policy: BaselineAcquisitionPolicy
) -> tuple[dict[str, Any], ...]:
    acquired: list[dict[str, Any]] = []
    seen_outputs: set[str] = set()
    seen_datasets: set[str] = set()
    for output in receipt["outputs"]:
        if output["output_id"] in seen_outputs or output["dataset_id"] in seen_datasets:
            raise ValueError("Baseline export contains duplicate output or dataset identity")
        seen_outputs.add(output["output_id"])
        seen_datasets.add(output["dataset_id"])
        if output["status"] != "completed" or output["origin"] != "sas_execution":
            raise ValueError("Baseline output was not completed by SAS execution")
        if output["format"] not in policy.payload["allowed_output_formats"]:
            raise ValueError("Baseline output format is not permitted")
        path = _safe_package_file(package_root, output["artifact_path"])
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        digest = hashlib.sha256(data).hexdigest()
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or not data
            or len(data) != output["byte_count"]
            or digest != output["content_digest"]
            or len(data) > policy.payload["max_output_bytes"]
        ):
            raise ValueError("Baseline output bytes changed or do not match the signed receipt")
        acquired.append({**output, "data": data})
    if not acquired:
        raise ValueError("Baseline export contains no meaningful output")
    return tuple(acquired)
