"""Append-only, signed AI transport evidence and restart recovery."""

from __future__ import annotations

import base64
import binascii
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

from smf.security.ai_policy import ai_digest, canonical_ai_json
from smf.security.ai_transport_models import AITransportRequest, AITransportResult
from smf.security.ai_transport_telemetry import ai_transport_event
from smf.security.schema import validate_security_schema

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def transport_decision_id(request: AITransportRequest) -> str:
    return "ait-" + ai_digest({"contract": "smf-ai-transport-v1", "request": request.bindings()})


def transport_evidence_dir(root: Path, request: AITransportRequest) -> Path:
    for value in (
        request.run_id,
        request.workload_id,
        request.workflow_attempt_id,
        request.provider_request_id,
        request.transport_attempt_id,
    ):
        if not _SAFE.fullmatch(value) or value in {".", ".."}:
            raise ValueError("Unsafe AI transport evidence identity")
    path = (
        root
        / "runs"
        / request.run_id
        / "workloads"
        / request.workload_id
        / "attempts"
        / request.workflow_attempt_id
        / "security"
        / "ai-transport"
        / request.provider_request_id
        / request.transport_attempt_id
    )
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("AI transport evidence path escapes output root")
    return path


def _sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if not _SAFE.fullmatch(key_id):
        raise ValueError("Unsafe evidence signing key identity")
    signed = dict(payload)
    signed["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical_ai_json(payload))).decode("ascii"),
    }
    return signed


def _verify(payload: dict[str, Any], keys: Mapping[str, Ed25519PublicKey]) -> None:
    proof = payload.get("proof")
    if not isinstance(proof, dict):
        raise ValueError("AI transport evidence lacks trusted proof")
    key_id = proof.get("key_id")
    if proof.get("algorithm") != "ed25519" or not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("AI transport evidence proof is untrusted")
    unsigned = dict(payload)
    unsigned.pop("proof")
    try:
        signature = base64.b64decode(proof.get("value", ""), validate=True)
        keys[key_id].verify(signature, canonical_ai_json(unsigned))
    except (TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("AI transport evidence proof is invalid") from exc


def _publish(path: Path, payload: dict[str, Any]) -> bool:
    """Atomically publish immutable evidence and report whether this call won."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return False
        raise FileExistsError(f"Conflicting immutable AI transport evidence: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".ai-transport-", dir=path.parent)
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
                    f"Conflicting immutable AI transport evidence: {path}"
                ) from None
            return False
        return True
    finally:
        temporary.unlink(missing_ok=True)


def write_transport_preparation(
    root: Path,
    request: AITransportRequest,
    evidence_refs: tuple[str, ...],
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    payload = {
        "schema_version": "1.0",
        "decision_id": transport_decision_id(request),
        "request_digest": request.request_digest,
        "request": request.bindings(),
        "state": "prepared",
        "evidence_refs": list(evidence_refs),
    }
    signed = _sign(payload, signing_key, key_id)
    validate_security_schema("ai-transport-preparation.schema.json", signed)
    path = transport_evidence_dir(root, request) / "preparation.json"
    _publish(path, signed)
    return path


def _load_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid AI transport evidence") from exc
    if not isinstance(payload, dict):
        raise ValueError("AI transport evidence must be an object")
    return payload


def load_transport_preparation(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    validate_security_schema("ai-transport-preparation.schema.json", payload)
    try:
        request = AITransportRequest(**payload["request"])
    except (TypeError, ValueError) as exc:
        raise ValueError("AI transport preparation request is invalid") from exc
    if (
        payload["decision_id"] != transport_decision_id(request)
        or payload["request_digest"] != request.request_digest
    ):
        raise ValueError("AI transport preparation binding mismatch")
    return payload


def write_dispatch_marker(
    root: Path,
    request: AITransportRequest,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> tuple[Path, bool]:
    payload = {
        "schema_version": "1.0",
        "decision_id": transport_decision_id(request),
        "request_digest": request.request_digest,
        "state": "dispatch_started",
    }
    path = transport_evidence_dir(root, request) / "dispatch.json"
    claimed = _publish(path, _sign(payload, signing_key, key_id))
    return path, claimed


def load_dispatch_marker(
    path: Path,
    request: AITransportRequest,
    *,
    verification_keys: Mapping[str, Ed25519PublicKey],
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    if set(payload) != {
        "schema_version",
        "decision_id",
        "request_digest",
        "state",
        "proof",
    } or (
        payload["schema_version"] != "1.0"
        or payload["state"] != "dispatch_started"
        or payload["decision_id"] != transport_decision_id(request)
        or payload["request_digest"] != request.request_digest
    ):
        raise ValueError("AI transport dispatch marker binding mismatch")
    return payload


def _validate_result(payload: dict[str, Any]) -> None:
    validate_security_schema("ai-transport-result.schema.json", payload)
    try:
        request = AITransportRequest(**payload["request"])
    except (TypeError, ValueError) as exc:
        raise ValueError("AI transport result request is invalid") from exc
    if payload["decision_id"] != transport_decision_id(request):
        raise ValueError("AI transport decision identity mismatch")
    received = payload["state"] == "response_received"
    if payload["response_received"] is not received:
        raise ValueError("AI transport response claim mismatch")
    if received and (
        payload["response_status"] is None or not 200 <= payload["response_status"] < 300
    ):
        raise ValueError("AI transport response status is not successful")
    if received:
        if (
            not payload["transport_attempted"]
            or not payload["submission_authorized"]
            or payload["blocker_codes"]
            or payload["response_status"] is None
            or payload["response_digest"] is None
            or payload["response_byte_count"] is None
        ):
            raise ValueError("AI transport success is not reconstructable")
    elif payload["response_digest"] is not None or payload["response_byte_count"] is not None:
        raise ValueError("Blocked transport result cannot retain response evidence")
    elif not payload["blocker_codes"]:
        raise ValueError("Non-success transport result requires an explicit blocker")
    attempted_states = {
        "redirect_rejected",
        "transport_failed",
        "timed_out",
        "cancelled",
        "outcome_unknown",
        "response_received",
    }
    if payload["state"] in attempted_states and not payload["transport_attempted"]:
        raise ValueError("Terminal transport state lacks a dispatch attempt")
    if payload["transport_attempted"] and payload["state"] not in attempted_states:
        raise ValueError("Pre-dispatch transport state cannot claim an attempt")
    if payload["response_received"] and not payload["submission_authorized"]:
        raise ValueError("Response receipt lacks submission authority")
    if payload["state"] in attempted_states and not payload["submission_authorized"]:
        raise ValueError("Dispatched transport state lacks submission authority")
    if payload["state"] in attempted_states and not payload["context_qualified"]:
        raise ValueError("Dispatched transport state lacks qualified context")
    if payload["state"] == "redirect_rejected" and (
        payload["response_status"] is None or not 300 <= payload["response_status"] < 400
    ):
        raise ValueError("Redirect rejection lacks a redirect response")
    if (
        payload["state"] in {"timed_out", "cancelled", "outcome_unknown"}
        and payload["response_status"] is not None
    ):
        raise ValueError("Response-free transport state cannot assert an HTTP status")
    if received and len(payload["evidence_refs"]) < 5:
        raise ValueError("AI transport success lacks reconstructable evidence references")
    downstream_flags = (
        "generated",
        "executed",
        "validated",
        "parity_passed",
        "certified",
        "human_approved",
    )
    for flag in downstream_flags:
        if payload[flag] is not False:
            raise ValueError("AI transport result cannot assert downstream success")


def write_transport_result(
    root: Path,
    result: AITransportResult,
    *,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> Path:
    payload = _sign(result.to_dict(), signing_key, key_id)
    _validate_result(payload)
    request = AITransportRequest(**result.request)
    path = transport_evidence_dir(root, request) / "result.json"
    _publish(path, payload)
    _publish(path.with_name("telemetry.json"), ai_transport_event(payload))
    return path


def load_transport_result(
    path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    payload = _load_object(path)
    _verify(payload, verification_keys)
    _validate_result(payload)
    return payload


def recover_transport_telemetry(
    result_path: Path, *, verification_keys: Mapping[str, Ed25519PublicKey]
) -> Path:
    result = load_transport_result(result_path, verification_keys=verification_keys)
    telemetry = result_path.with_name("telemetry.json")
    _publish(telemetry, ai_transport_event(result))
    return telemetry
