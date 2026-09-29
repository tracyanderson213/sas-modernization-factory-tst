"""Append-only AI-context decision persistence with telemetry recovery."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from smf.security.ai_models import AIContextAdmissionResult, AIContextRequest
from smf.security.ai_policy import ai_digest, canonical_ai_json
from smf.security.ai_telemetry import ai_context_event
from smf.security.schema import validate_security_schema

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_QUALIFIED_CHECKS = [
    {"check_id": "readiness_replayed", "status": "pass"},
    {"check_id": "classification_verified", "status": "pass"},
    {"check_id": "source_bytes_reverified", "status": "pass"},
    {"check_id": "protected_data_scan", "status": "pass"},
    {"check_id": "allowlist_intersection", "status": "pass"},
]


def _component(value: str, label: str) -> str:
    if not _SAFE.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"Unsafe {label}")
    return value


def ai_context_result_path(root: Path, result: AIContextAdmissionResult) -> Path:
    request = result.request
    return (
        root
        / "runs"
        / _component(request["run_id"], "run_id")
        / "workloads"
        / _component(request["workload_id"], "workload_id")
        / "attempts"
        / _component(request["attempt_id"], "attempt_id")
        / "security"
        / "ai-context"
        / _component(result.decision_id, "decision_id")
        / "ai-context-admission.result.json"
    )


def _validate(payload: dict[str, Any]) -> None:
    validate_security_schema("ai-context-admission-result.schema.json", payload)
    try:
        AIContextRequest(**payload["request"])
    except (TypeError, ValueError) as exc:
        raise ValueError("AI context result request binding is invalid") from exc
    expected_id = "ai-" + ai_digest(
        {"contract": "smf-ai-context-admission-v1", "request": payload["request"]}
    )
    if payload["decision_id"] != expected_id:
        raise ValueError("AI context decision identity mismatch")
    qualified = payload["state"] == "qualified_offline"
    if payload["context_qualified"] is not qualified:
        raise ValueError("AI context qualification claim mismatch")
    if qualified:
        if (
            payload["blocker_codes"]
            or payload["context_digest"] is None
            or payload["context_byte_count"] is None
            or payload["context_byte_count"] < 1
            or payload["checks"] != _QUALIFIED_CHECKS
            or not payload["permitted_artifact_ids"]
            or not payload["permitted_fields"]
            or payload["terminal_disposition"] != "context_qualified_offline"
        ):
            raise ValueError("Qualified AI context result is not reconstructable")
    elif (
        not payload["blocker_codes"]
        or payload["context_digest"] is not None
        or payload["context_byte_count"] is not None
        or payload["terminal_disposition"] != "context_not_qualified"
    ):
        raise ValueError("Blocked AI context result claim mismatch")
    if payload["evidence_refs"][:2] != [
        payload["request"]["readiness_result_id"],
        payload["request"]["classification_evidence_id"],
    ]:
        raise ValueError("AI context evidence references are not request-bound")
    for flag in (
        "transport_attempted",
        "submission_authorized",
        "generated",
        "executed",
        "validated",
        "parity_passed",
        "certified",
        "human_approved",
        "human_assisted",
    ):
        if payload[flag] is not False:
            raise ValueError("AI context result cannot assert downstream authority or success")
    unsigned = dict(payload)
    unsigned.pop("proof")
    unsigned["content_digest"] = ""
    if payload["content_digest"] != ai_digest(unsigned):
        raise ValueError("AI context result content digest mismatch")


def _verify_proof(
    payload: dict[str, Any], verification_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("AI context result lacks a trusted evidence proof")
    key_id = proof.get("key_id")
    if (
        proof.get("algorithm") != "ed25519"
        or not isinstance(key_id, str)
        or key_id not in verification_keys
    ):
        raise ValueError("AI context result lacks a trusted evidence proof")
    unsigned = dict(payload)
    unsigned.pop("proof", None)
    try:
        import base64
        import binascii

        signature = base64.b64decode(proof.get("value", ""), validate=True)
        verification_keys[key_id].verify(signature, canonical_ai_json(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("AI context result trusted evidence proof is invalid") from exc


def load_ai_context_result(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("AI context result must be an object")
    _verify_proof(payload, verification_keys)
    _validate(payload)
    return payload


def _publish(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return
        raise FileExistsError(f"Conflicting immutable AI context evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ai-context-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if json.loads(path.read_text(encoding="utf-8")) != payload:
                raise FileExistsError(
                    f"Conflicting immutable AI context evidence: {path}"
                ) from None
    finally:
        temporary.unlink(missing_ok=True)


def write_ai_context_result(
    root: Path,
    result: AIContextAdmissionResult,
    *,
    signing_key: Ed25519PrivateKey | None = None,
    key_id: str | None = None,
) -> Path:
    if signing_key is None or key_id is None:
        raise ValueError("An attributable evidence signing key is required")
    _component(key_id, "evidence key_id")
    path = ai_context_result_path(root, result)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("AI context evidence path escapes output root")
    payload = result.to_dict()
    import base64

    payload["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signing_key.sign(canonical_ai_json(payload))).decode("ascii"),
    }
    _validate(payload)
    _publish(path, payload)
    canonical = load_ai_context_result(path, verification_keys={key_id: signing_key.public_key()})
    _publish(path.with_name("ai-context-admission.telemetry.json"), ai_context_event(canonical))
    return path
