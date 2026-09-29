"""Versioned, deterministic workload and run-lineage identities.

This module defines identity only.  A verified lineage envelope is evidence of
what was qualified; it never authorizes execution, validation, approval, or
promotion by itself.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator

from smf.workload.models import ArtifactKind
from smf.workload.sanitization import sanitize_discovery_value

CONTRACT_VERSION = "1.0"
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}$")
_IDENTITY = re.compile(r"^(?:WL|SRC|RUN|ATT|LIN)-v1-[a-f0-9]{64}$")
_SECRET_CANARY = re.compile(r"(?i)(?<![A-Za-z0-9])secret[-_. ]*canary(?:[-_. ]|$)")
_PROTECTED = re.compile(
    r"(?i)(?:\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)|"
    r"\b(?:dob|date[_ -]?of[_ -]?birth)\s*[:=]\s*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b|"
    r"\b(?:mrn|member(?:[_ -]?(?:id|number))?|patient[_ -]?id)"
    r"\s*(?::|=|\s)\s*[A-Za-z0-9-]{4,}\b|"
    r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}(?!\d))"
)


class LineageOperation(StrEnum):
    """Supported offline factory operations."""

    INTAKE = "intake"
    DISCOVERY = "discovery"
    ASSESSMENT = "assessment"
    READINESS = "readiness"
    CONVERSION = "conversion"
    VALIDATION = "validation"
    EXECUTION = "execution"


@dataclass(frozen=True)
class LineageArtifact:
    """One immutable member of a source revision closure."""

    subject_id: str
    kind: str
    logical_path: str
    sha256: str
    size_bytes: int
    entrypoint: bool
    source_locators: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunLineage:
    """Complete, non-authorizing lineage envelope for one qualified attempt."""

    schema_version: str
    workload_id: str
    source_revision_id: str
    run_id: str
    attempt_id: str
    lineage_id: str
    client_id: str
    workload_key: str
    artifacts: tuple[LineageArtifact, ...]
    operation: LineageOperation
    target: str
    policy_digest: str
    strategy_digest: str
    configuration_digest: str
    idempotency_key: str
    attempt_key: str
    provider: str
    provider_version: str
    qualified_input_digests: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["operation"] = self.operation.value
        payload["artifacts"] = [
            {**asdict(item), "source_locators": list(item.source_locators)}
            for item in self.artifacts
        ]
        payload["qualified_input_digests"] = list(self.qualified_input_digests)
        return payload


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _derive(domain: str, material: object) -> str:
    digest = hashlib.sha256(
        _canonical(
            {
                "contract": "smf.run-lineage",
                "contract_version": CONTRACT_VERSION,
                "domain": domain,
                "material": material,
            }
        )
    ).hexdigest()
    prefixes = {
        "workload": "WL",
        "source_revision": "SRC",
        "run": "RUN",
        "attempt": "ATT",
        "lineage": "LIN",
    }
    return f"{prefixes[domain]}-v1-{digest}"


def _contains_protected_identity(value: str) -> bool:
    views = [value]
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        views.append(expanded)
        decoded = expanded
    for candidate in tuple(views):
        tokens = re.findall(r"[A-Za-z0-9_-]{16,}", candidate)
        tokens.extend(re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", candidate))
        for token in tokens:
            try:
                padded = token.replace("-", "+").replace("_", "/") + "=" * (-len(token) % 4)
                views.append(base64.b64decode(padded, validate=True).decode("utf-8"))
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
    return any(
        _SECRET_CANARY.search(candidate)
        or _PROTECTED.search(candidate)
        or sanitize_discovery_value(candidate) != candidate
        for candidate in views
    )


def contains_protected_identity(value: str) -> bool:
    """Return whether an identity would persist secret or protected-data content."""

    return _contains_protected_identity(value)


def _safe_value(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SAFE_VALUE.fullmatch(value)
        or value in {".", ".."}
        or _contains_protected_identity(value)
    ):
        raise ValueError(f"Unsafe {label}")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"Invalid {label}")
    return value


def _logical_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(ord(character) < 32 for character in value)
        or _contains_protected_identity(value)
    ):
        raise ValueError("Unsafe logical path")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    parsed = urlsplit(decoded)
    path = PurePosixPath(decoded)
    if parsed.scheme or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Unsafe logical path")
    return path.as_posix()


def _safe_locator(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(ord(character) < 32 for character in value)
        or _contains_protected_identity(value)
    ):
        raise ValueError("Unsafe source locator")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Unsafe source locator")
    return value


def _normalize_artifacts(
    artifacts: Sequence[LineageArtifact | Mapping[str, Any]],
) -> tuple[LineageArtifact, ...]:
    if not artifacts:
        raise ValueError("Source closure must not be empty")
    normalized: list[LineageArtifact] = []
    subjects: set[str] = set()
    paths: set[str] = set()
    locators: dict[str, str] = {}
    entrypoints = 0
    kinds = {item.value for item in ArtifactKind}
    for raw in artifacts:
        item = raw if isinstance(raw, LineageArtifact) else LineageArtifact(**raw)
        subject_id = _safe_value(item.subject_id, "source subject")
        if subject_id.casefold() in subjects:
            raise ValueError("Duplicate source subject identity")
        subjects.add(subject_id.casefold())
        logical_path = _logical_path(item.logical_path)
        if logical_path.casefold() in paths:
            raise ValueError("Duplicate canonical logical path")
        paths.add(logical_path.casefold())
        if item.kind not in kinds:
            raise ValueError("Unsupported artifact kind")
        if (
            not isinstance(item.size_bytes, int)
            or isinstance(item.size_bytes, bool)
            or item.size_bytes <= 0
        ):
            raise ValueError("Source artifact must contain non-empty immutable bytes")
        if not isinstance(item.entrypoint, bool):
            raise ValueError("Invalid entrypoint role")
        if item.entrypoint:
            entrypoints += 1
            if item.kind != ArtifactKind.SAS_PROGRAM.value:
                raise ValueError("Entrypoint must be a SAS program")
        safe_locators: list[str] = []
        for locator in item.source_locators:
            safe = _safe_locator(locator)
            folded = safe.casefold()
            owner = locators.get(folded)
            if owner is not None and owner != subject_id.casefold():
                raise ValueError("Ambiguous source locator alias")
            locators[folded] = subject_id.casefold()
            if folded not in {value.casefold() for value in safe_locators}:
                safe_locators.append(safe)
        normalized.append(
            LineageArtifact(
                subject_id=subject_id,
                kind=item.kind,
                logical_path=logical_path,
                sha256=_digest(item.sha256, "source digest"),
                size_bytes=item.size_bytes,
                entrypoint=item.entrypoint,
                source_locators=tuple(sorted(safe_locators, key=str.casefold)),
            )
        )
    if entrypoints == 0:
        raise ValueError("Source closure requires a meaningful entrypoint")
    return tuple(sorted(normalized, key=lambda item: item.subject_id.casefold()))


def _operation(value: LineageOperation | str) -> LineageOperation:
    try:
        return LineageOperation(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Unsupported lineage operation") from exc


def build_run_lineage(
    *,
    client_id: str,
    workload_key: str,
    artifacts: Sequence[LineageArtifact | Mapping[str, Any]],
    operation: LineageOperation | str,
    target: str,
    policy_digest: str,
    strategy_digest: str,
    configuration_digest: str,
    idempotency_key: str,
    attempt_key: str,
    provider: str,
    provider_version: str,
    qualified_input_digests: Sequence[str],
) -> RunLineage:
    """Derive all identities from safe, canonical, immutable material."""

    safe_client = _safe_value(client_id, "client identity")
    safe_workload_key = _safe_value(workload_key, "workload key")
    safe_artifacts = _normalize_artifacts(artifacts)
    safe_operation = _operation(operation)
    safe_target = _safe_value(target, "target")
    safe_idempotency_key = _safe_value(idempotency_key, "idempotency key")
    safe_attempt_key = _safe_value(attempt_key, "attempt key")
    safe_provider = _safe_value(provider, "provider")
    safe_provider_version = _safe_value(provider_version, "provider version")
    safe_policy = _digest(policy_digest, "policy digest")
    safe_strategy = _digest(strategy_digest, "strategy digest")
    safe_configuration = _digest(configuration_digest, "configuration digest")
    qualified = tuple(
        sorted({_digest(value, "qualified input digest") for value in qualified_input_digests})
    )
    if not qualified:
        raise ValueError("Qualified input digests must be non-empty")
    source_digests = {item.sha256 for item in safe_artifacts}
    if not source_digests.issubset(qualified):
        raise ValueError("Qualified inputs do not bind the complete source closure")

    workload_material = {"client_id": safe_client, "workload_key": safe_workload_key}
    workload_id = _derive("workload", workload_material)
    source_material = {
        "workload_id": workload_id,
        "artifacts": [
            {
                "subject_id": item.subject_id,
                "kind": item.kind,
                "logical_path": item.logical_path,
                "sha256": item.sha256,
                "size_bytes": item.size_bytes,
                "entrypoint": item.entrypoint,
            }
            for item in safe_artifacts
        ],
    }
    source_revision_id = _derive("source_revision", source_material)
    run_material = {
        "workload_id": workload_id,
        "source_revision_id": source_revision_id,
        "operation": safe_operation.value,
        "target": safe_target,
        "policy_digest": safe_policy,
        "strategy_digest": safe_strategy,
        "configuration_digest": safe_configuration,
        "idempotency_key": safe_idempotency_key,
    }
    run_id = _derive("run", run_material)
    attempt_material = {
        "run_id": run_id,
        "attempt_key": safe_attempt_key,
        "provider": safe_provider,
        "provider_version": safe_provider_version,
        "qualified_input_digests": qualified,
    }
    attempt_id = _derive("attempt", attempt_material)
    without_lineage_id = {
        "schema_version": CONTRACT_VERSION,
        "workload_id": workload_id,
        "source_revision_id": source_revision_id,
        "run_id": run_id,
        "attempt_id": attempt_id,
        **workload_material,
        "artifacts": [asdict(item) for item in safe_artifacts],
        **{
            key: value
            for key, value in run_material.items()
            if key not in {"workload_id", "source_revision_id"}
        },
        "attempt_key": safe_attempt_key,
        "provider": safe_provider,
        "provider_version": safe_provider_version,
        "qualified_input_digests": qualified,
    }
    lineage_id = _derive("lineage", without_lineage_id)
    return RunLineage(
        schema_version=CONTRACT_VERSION,
        workload_id=workload_id,
        source_revision_id=source_revision_id,
        run_id=run_id,
        attempt_id=attempt_id,
        lineage_id=lineage_id,
        client_id=safe_client,
        workload_key=safe_workload_key,
        artifacts=safe_artifacts,
        operation=safe_operation,
        target=safe_target,
        policy_digest=safe_policy,
        strategy_digest=safe_strategy,
        configuration_digest=safe_configuration,
        idempotency_key=safe_idempotency_key,
        attempt_key=safe_attempt_key,
        provider=safe_provider,
        provider_version=safe_provider_version,
        qualified_input_digests=qualified,
    )


_FIELDS = {field.name for field in __import__("dataclasses").fields(RunLineage)}


def verify_run_lineage(raw: RunLineage | Mapping[str, Any]) -> RunLineage:
    """Semantically verify a lineage envelope and rederive every identity."""

    payload = raw.to_dict() if isinstance(raw, RunLineage) else dict(raw)
    schema = json.loads(
        files("smf.schemas").joinpath("run-lineage.schema.json").read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload), key=lambda error: list(error.path)
    )
    if errors:
        locations = ", ".join(
            ".".join(str(part) for part in error.path) or "fields" for error in errors
        )
        raise ValueError(f"Lineage envelope schema fields are invalid: {locations}")
    unknown = set(payload) - _FIELDS
    missing = _FIELDS - set(payload)
    if unknown or missing:
        raise ValueError("Lineage envelope has unsupported or missing fields")
    if payload["schema_version"] != CONTRACT_VERSION:
        raise ValueError("Unsupported lineage schema version")
    for field in ("workload_id", "source_revision_id", "run_id", "attempt_id", "lineage_id"):
        if not isinstance(payload[field], str) or not _IDENTITY.fullmatch(payload[field]):
            raise ValueError(f"Invalid {field.replace('_', ' ')}")
    expected = build_run_lineage(
        client_id=payload["client_id"],
        workload_key=payload["workload_key"],
        artifacts=payload["artifacts"],
        operation=payload["operation"],
        target=payload["target"],
        policy_digest=payload["policy_digest"],
        strategy_digest=payload["strategy_digest"],
        configuration_digest=payload["configuration_digest"],
        idempotency_key=payload["idempotency_key"],
        attempt_key=payload["attempt_key"],
        provider=payload["provider"],
        provider_version=payload["provider_version"],
        qualified_input_digests=payload["qualified_input_digests"],
    )
    for label in ("workload", "source revision", "run", "attempt", "lineage"):
        field = label.replace(" ", "_") + "_id"
        if payload[field] != getattr(expected, field):
            raise ValueError(f"Lineage {label} identity verification failed")
    return expected


def _key_digest(domain: str, value: str) -> str:
    return hashlib.sha256(_canonical({"domain": domain, "value": value})).hexdigest()


def lineage_path(output_root: Path, lineage: RunLineage) -> Path:
    """Return a stable key path that detects changed-material key reuse."""

    return (
        output_root
        / "workload-lineage"
        / lineage.workload_id
        / "run-keys"
        / _key_digest("run-key", lineage.idempotency_key)
        / "attempt-keys"
        / _key_digest("attempt-key", lineage.attempt_key)
        / "lineage.json"
    )


def _publish_immutable(path: Path, encoded: bytes, conflict_message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != encoded:
            raise FileExistsError(conflict_message)
        path.chmod(0o444)
        return
    descriptor, name = tempfile.mkstemp(prefix=".run-lineage-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != encoded:
                raise FileExistsError(conflict_message) from None
        path.chmod(0o444)
    finally:
        temporary.unlink(missing_ok=True)


def publish_run_lineage(output_root: Path, raw: RunLineage | Mapping[str, Any]) -> Path:
    """Create immutable evidence, or verify an identical retry without overwrite."""

    lineage = verify_run_lineage(raw)
    path = lineage_path(output_root, lineage)
    encoded = (json.dumps(lineage.to_dict(), indent=2, sort_keys=True) + "\n").encode()
    run_binding_path = path.parents[2] / "run-binding.json"
    run_binding = {
        "schema_version": CONTRACT_VERSION,
        "workload_id": lineage.workload_id,
        "source_revision_id": lineage.source_revision_id,
        "run_id": lineage.run_id,
        "idempotency_key_digest": _key_digest("run-key", lineage.idempotency_key),
    }
    run_binding_bytes = (json.dumps(run_binding, indent=2, sort_keys=True) + "\n").encode()
    _publish_immutable(
        run_binding_path,
        run_binding_bytes,
        "Conflicting immutable run idempotency key reuse",
    )
    if path.exists():
        existing = verify_run_lineage(json.loads(path.read_text(encoding="utf-8")))
        if existing != lineage or path.read_bytes() != encoded:
            raise FileExistsError("Conflicting immutable lineage key reuse")
        path.chmod(0o444)
        return path
    _publish_immutable(path, encoded, "Conflicting immutable lineage key reuse")
    return path
