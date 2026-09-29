"""Append-only packet publication and idempotent derived-artifact recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from smf.architecture_review.projection import internal_projection, shared_projection
from smf.architecture_review.schema import validate
from smf.architecture_review.telemetry import packet_event
from smf.readiness.policy import digest_value

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe architecture review identity")
    return value


def packet_path(root: Path, packet: dict[str, Any]) -> Path:
    identity = packet["identity"]
    return (
        root
        / "runs"
        / _component(identity["run_id"])
        / "workloads"
        / _component(identity["workload_id"])
        / "attempts"
        / _component(identity["attempt_id"])
        / "architecture-review"
        / _component(packet["packet_id"])
        / "packet.manifest.json"
    )


def _validate_packet(payload: dict[str, Any]) -> None:
    validate("architecture-review-packet.schema.json", payload)
    if payload["content_digest"] != digest_value({**payload, "content_digest": ""}):
        raise ValueError("Architecture review packet digest mismatch")
    identity = payload["identity"]
    expected_packet_id = digest_value(
        {
            "contract": "smf-architecture-review-v1",
            "workload_id": identity["workload_id"],
            "subject_id": identity["subject_id"],
            "boundary_id": identity["boundary_id"],
            "run_id": identity["run_id"],
            "attempt_id": identity["attempt_id"],
            "assessed_revision": payload["assessed_revision"],
            "discovery_namespace": payload["source"]["discovery_namespace"],
            "client_id": identity["client_id"],
            "deployment_id": identity["deployment_id"],
            "environment_id": identity["environment_id"],
            "source": payload["source"],
            "configuration_digest": payload["configuration"]["configuration_digest"],
            "threat_model_digest": payload["configuration"]["threat_model_digest"],
            "requirements_digest": payload["configuration"]["requirements_digest"],
        }
    )
    if payload["packet_id"] != expected_packet_id:
        raise ValueError("Architecture review packet identity mismatch")
    for artifact in payload["source"]["source_closure"]:
        locator = Path(artifact["locator"])
        if any(component.is_symlink() for component in (locator, *locator.parents)) or not (
            locator.is_absolute() and locator.is_file()
        ):
            raise ValueError("Architecture review source snapshot locator is unavailable or unsafe")
        if hashlib.sha256(locator.read_bytes()).hexdigest() != artifact["sha256"]:
            raise ValueError("Architecture review source snapshot changed after qualification")


def load_packet(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Architecture review packet must be an object")
    _validate_packet(payload)
    return payload


def _publish(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) == payload:
            return
        raise FileExistsError(f"Conflicting immutable architecture review evidence: {path}")
    descriptor, name = tempfile.mkstemp(prefix=".architecture-review-", dir=path.parent)
    temporary = Path(name)
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
                    f"Conflicting immutable architecture review evidence: {path}"
                ) from None
    finally:
        temporary.unlink(missing_ok=True)


def write_packet(root: Path, packet: dict[str, Any]) -> Path:
    _validate_packet(packet)
    path = packet_path(root, packet)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Architecture review output escapes root")
    _publish(path, packet)
    canonical = load_packet(path)
    _publish(path.with_name("packet.internal.json"), internal_projection(canonical))
    shared = shared_projection(canonical)
    if shared is not None:
        _publish(path.with_name("packet.shared.json"), shared)
    _publish(path.with_name("packet.telemetry.json"), packet_event(canonical))
    return path
