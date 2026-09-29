"""Offline, fail-closed SAS LIBNAME binding resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.library_binding.models import (
    BindingBlocker,
    BindingRequest,
    BindingState,
    RuntimeBindingEvidence,
)
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

STRATEGY_ID = "smf-sas-library-binding"
STRATEGY_VERSION = "1.0"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LIBNAME = re.compile(r"\blibname\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)
_MACRO = re.compile(r"(?<!&)&([A-Za-z_][A-Za-z0-9_]*)\.?")
_QUOTED = r"(?P<q>['\"])(?P<value>(?:(?P=q){2}|(?! (?P=q)).)*)?(?P=q)"
_ONE_PATH = re.compile(rf"^\s*(?:base\s+)?{_QUOTED}\s*$", re.IGNORECASE | re.VERBOSE)
_PATH_TOKEN = re.compile(r"(['\"])((?:\1\1|(?!\1).)*)\1", re.DOTALL)


@dataclass(frozen=True)
class PreparedLibraryBindings:
    result: dict[str, Any]
    projection: dict[str, Any]


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _safe_id(value: str, label: str) -> str:
    if not _SAFE_ID.fullmatch(value) or sanitize_discovery_value(value) != value:
        raise ValueError(f"Unsafe library binding {label}")
    return value


def assert_persistable(value: Any) -> None:
    """Reject protected values anywhere in evidence destined for persistence."""

    if isinstance(value, str):
        if contains_protected_data(value) or sanitize_discovery_value(value) != value:
            raise ValueError("Library binding evidence contains protected data")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            assert_persistable(key)
            assert_persistable(item)
        return
    if isinstance(value, list | tuple):
        for item in value:
            assert_persistable(item)


def _mask_comments(source: str) -> str:
    """Replace SAS comments with spaces while preserving newlines and offsets."""

    chars = list(source)
    index = 0
    quote: str | None = None
    while index < len(chars):
        char = chars[index]
        if quote is not None:
            if char == quote:
                if index + 1 < len(chars) and chars[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        comment_end: int | None = None
        if char == "/" and index + 1 < len(chars) and chars[index + 1] == "*":
            found = source.find("*/", index + 2)
            comment_end = len(chars) if found < 0 else found + 2
        boundary = max(source.rfind(";", 0, index), source.rfind("\n", 0, index)) + 1
        statement_prefix_is_space = not source[boundary:index].strip()
        if comment_end is None and (
            (char == "%" and index + 1 < len(chars) and chars[index + 1] == "*")
            or (char == "*" and statement_prefix_is_space)
        ):
            found = source.find(";", index + 1)
            comment_end = len(chars) if found < 0 else found + 1
        if comment_end is None:
            index += 1
            continue
        for position in range(index, comment_end):
            if chars[position] not in "\r\n":
                chars[position] = " "
        index = comment_end
    return "".join(chars)


def _quoted_spans(source: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(source):
        if source[index] not in {"'", '"'}:
            index += 1
            continue
        quote = source[index]
        start = index
        index += 1
        while index < len(source):
            if source[index] == quote:
                if index + 1 < len(source) and source[index + 1] == quote:
                    index += 2
                    continue
                index += 1
                break
            index += 1
        spans.append((start, index))
    return tuple(spans)


def _inside(offset: int, spans: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= offset < end for start, end in spans)


def _statement_end(source: str, start: int) -> int | None:
    quote: str | None = None
    index = start
    while index < len(source):
        char = source[index]
        if quote is not None:
            if char == quote:
                if index + 1 < len(source) and source[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == ";":
            return index + 1
        index += 1
    return None


def _literal_paths(body: str) -> tuple[str, ...] | None:
    one = _ONE_PATH.fullmatch(body)
    if one:
        return (one.group("value").replace(one.group("q") * 2, one.group("q")),)
    stripped = body.strip()
    if not (stripped.startswith("(") and stripped.endswith(")")):
        return None
    inner = stripped[1:-1]
    matches = tuple(_PATH_TOKEN.finditer(inner))
    if not matches:
        return None
    residue = list(inner)
    values: list[str] = []
    for match in matches:
        values.append(match.group(2).replace(match.group(1) * 2, match.group(1)))
        residue[match.start() : match.end()] = " " * (match.end() - match.start())
    if "".join(residue).strip():
        return None
    return tuple(values)


def runtime_evidence_payload(evidence: RuntimeBindingEvidence) -> dict[str, Any]:
    payload = asdict(evidence)
    payload.pop("evidence_digest")
    payload.pop("signature")
    payload["observed_paths"] = list(evidence.observed_paths)
    return payload


def runtime_evidence_digest(evidence: RuntimeBindingEvidence) -> str:
    return _digest(runtime_evidence_payload(evidence))


def runtime_evidence_signing_payload(evidence: RuntimeBindingEvidence) -> bytes:
    payload = runtime_evidence_payload(evidence)
    payload["evidence_digest"] = evidence.evidence_digest
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _policy_payload(request: BindingRequest) -> dict[str, Any]:
    policy = request.policy
    providers = sorted(
        [
            [_safe_id(provider, "runtime provider"), _safe_id(version, "provider version")]
            for provider, version in policy.allowed_runtime_providers
        ]
    )
    if len(providers) != len({tuple(item) for item in providers}):
        raise ValueError("Duplicate runtime provider")
    authorities = sorted(
        _safe_id(value, "runtime authority") for value in policy.trusted_runtime_authorities
    )
    keys = sorted(
        [
            [_safe_id(key_id, "verification key id"), encoded]
            for key_id, encoded in policy.verification_keys
        ]
    )
    if len(authorities) != len(set(authorities)) or len(keys) != len({item[0] for item in keys}):
        raise ValueError("Duplicate runtime trust identity")
    for _, encoded in keys:
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError("Runtime verification key is malformed") from exc
        if len(decoded) != 32:
            raise ValueError("Runtime verification key is malformed")
    if policy.max_evidence_age_seconds <= 0 or policy.future_skew_seconds < 0:
        raise ValueError("Runtime evidence time policy is invalid")
    return {
        "policy_id": _safe_id(policy.policy_id, "policy id"),
        "policy_version": _safe_id(policy.policy_version, "policy version"),
        "client_id": _safe_id(policy.client_id, "client id"),
        "allowed_runtime_providers": providers,
        "trusted_runtime_authorities": authorities,
        "verification_keys": keys,
        "max_evidence_age_seconds": policy.max_evidence_age_seconds,
        "future_skew_seconds": policy.future_skew_seconds,
        "strategy_id": STRATEGY_ID,
        "strategy_version": STRATEGY_VERSION,
    }


def _occurrences(request: BindingRequest) -> list[dict[str, Any]]:
    occurrences: list[dict[str, Any]] = []
    if len({document.artifact_id for document in request.documents}) != len(request.documents):
        raise ValueError("Duplicate source document identity")
    for document in sorted(request.documents, key=lambda value: value.artifact_id):
        _safe_id(document.artifact_id, "artifact id")
        if sanitize_discovery_value(document.logical_path) != document.logical_path:
            raise ValueError("Source document path is unsafe")
        if hashlib.sha256(document.content).hexdigest() != document.sha256:
            raise ValueError("Source document checksum mismatch")
        source = document.content.decode("utf-8", errors="strict")
        masked = _mask_comments(source)
        spans = _quoted_spans(masked)
        for match in _LIBNAME.finditer(masked):
            if _inside(match.start(), spans):
                continue
            end = _statement_end(masked, match.end())
            if end is None:
                end = len(masked)
            body = masked[match.end() : end - (1 if masked[end - 1 : end] == ";" else 0)]
            raw = source[match.start() : end]
            libref = match.group(1).lower()
            paths = _literal_paths(body)
            lowered = body.strip().lower()
            macros = sorted(set(_MACRO.findall(body)))
            if lowered == "clear":
                state = BindingState.CLEARED
                blockers = [BindingBlocker.CLEARED.value]
                paths = ()
            elif macros:
                state = BindingState.DYNAMIC
                blockers = [
                    BindingBlocker.MISSING_MACRO.value,
                    BindingBlocker.RUNTIME_EVIDENCE_REQUIRED.value,
                ]
                paths = ()
            elif paths is not None:
                if any(contains_protected_data(path) for path in paths):
                    raise ValueError("LIBNAME literal contains protected data")
                state = BindingState.LITERAL
                blockers = []
            else:
                state = BindingState.UNRESOLVED
                blockers = [
                    BindingBlocker.UNSUPPORTED_FORM.value,
                    BindingBlocker.RUNTIME_EVIDENCE_REQUIRED.value,
                ]
                paths = ()
            byte_start = len(source[: match.start()].encode())
            byte_end = len(source[:end].encode())
            occurrence_id = stable_id(
                "LBO",
                {
                    "workload_id": request.workload_id,
                    "artifact_id": document.artifact_id,
                    "artifact_sha256": document.sha256,
                    "byte_start": byte_start,
                    "byte_end": byte_end,
                    "statement_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                },
            )
            occurrences.append(
                {
                    "occurrence_id": occurrence_id,
                    "artifact_id": document.artifact_id,
                    "source_path": document.logical_path,
                    "source_sha256": document.sha256,
                    "libref": libref,
                    "line": source.count("\n", 0, match.start()) + 1,
                    "column": match.start() - source.rfind("\n", 0, match.start()),
                    "byte_start": byte_start,
                    "byte_end": byte_end,
                    "statement_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                    "state": state.value,
                    "paths": list(paths),
                    "macro_references": macros,
                    "blockers": blockers,
                }
            )
    return occurrences


def _runtime_by_libref(
    request: BindingRequest,
    *,
    policy_digest: str,
    occurrence_bindings: dict[str, tuple[str, str]],
    current_occurrences: dict[str, str],
    evaluated_at: datetime,
) -> dict[str, RuntimeBindingEvidence]:
    values: dict[str, RuntimeBindingEvidence] = {}
    allowed = set(request.policy.allowed_runtime_providers)
    trusted_authorities = set(request.policy.trusted_runtime_authorities)
    key_values = dict(request.policy.verification_keys)
    for evidence in request.runtime_evidence:
        libref = evidence.libref.lower()
        for label, value in (
            ("runtime evidence id", evidence.evidence_id),
            ("runtime provider id", evidence.provider_id),
            ("runtime provider version", evidence.provider_version),
        ):
            _safe_id(value, label)
        if libref in values:
            raise ValueError("Duplicate runtime evidence for libref")
        if runtime_evidence_digest(evidence) != evidence.evidence_digest:
            raise ValueError("Runtime binding evidence digest mismatch")
        if any(contains_protected_data(path) for path in evidence.observed_paths):
            raise ValueError("Runtime binding evidence contains protected data")
        selected = occurrence_bindings.get(evidence.selected_occurrence_id)
        if evidence.authority not in trusted_authorities:
            raise ValueError("Runtime binding evidence authority is not trusted")
        encoded_key = key_values.get(evidence.key_id)
        if encoded_key is None:
            raise ValueError("Runtime binding evidence key is not trusted")
        try:
            observed_at = datetime.fromisoformat(evidence.observed_at)
            if observed_at.tzinfo is None:
                raise ValueError
            observed_at = observed_at.astimezone(UTC)
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(encoded_key, validate=True)
            )
            public_key.verify(
                base64.b64decode(evidence.signature, validate=True),
                runtime_evidence_signing_payload(evidence),
            )
        except (ValueError, InvalidSignature) as exc:
            raise ValueError("Runtime binding evidence proof is invalid") from exc
        age_seconds = (evaluated_at - observed_at).total_seconds()
        if age_seconds < -request.policy.future_skew_seconds:
            raise ValueError("Runtime binding evidence is from the future")
        if age_seconds > request.policy.max_evidence_age_seconds:
            raise ValueError("Runtime binding evidence is stale")
        expected = (
            evidence.client_id == request.policy.client_id
            and evidence.workload_id == request.workload_id
            and evidence.source_closure_digest == request.source_closure_digest
            and evidence.policy_digest == policy_digest
            and evidence.run_id == request.run_id
            and evidence.attempt_id == request.attempt_id
            and (evidence.provider_id, evidence.provider_version) in allowed
            and selected is not None
            and selected[0] == libref
            and selected[1] != BindingState.CLEARED.value
            and current_occurrences.get(libref) == evidence.selected_occurrence_id
            and bool(evidence.observed_paths)
        )
        if not expected:
            raise ValueError("Runtime binding evidence is outside the governed request")
        values[libref] = evidence
    return values


def evaluate_library_bindings(request: BindingRequest) -> PreparedLibraryBindings:
    """Resolve supported logical bindings without granting path or runtime authority."""

    for label, value in (
        ("workload id", request.workload_id),
        ("run id", request.run_id),
        ("attempt id", request.attempt_id),
    ):
        _safe_id(value, label)
    for value in (request.source_closure_digest, request.evaluated_at):
        if contains_protected_data(value) or sanitize_discovery_value(value) != value:
            raise ValueError("Library binding request contains protected data")
    if not _SHA256.fullmatch(request.source_closure_digest):
        raise ValueError("Source closure digest is invalid")
    try:
        evaluated_at = datetime.fromisoformat(request.evaluated_at)
    except ValueError as exc:
        raise ValueError("Library binding evaluation timestamp is invalid") from exc
    if evaluated_at.tzinfo is None:
        raise ValueError("Library binding evaluation timestamp must include a timezone")
    evaluated_at = evaluated_at.astimezone(UTC)
    policy = _policy_payload(request)
    policy_digest = _digest(policy)
    occurrences = _occurrences(request)
    by_libref: dict[str, list[dict[str, Any]]] = {}
    for occurrence in occurrences:
        by_libref.setdefault(str(occurrence["libref"]), []).append(occurrence)
    runtime = _runtime_by_libref(
        request,
        policy_digest=policy_digest,
        occurrence_bindings={
            str(value["occurrence_id"]): (str(value["libref"]), str(value["state"]))
            for value in occurrences
        },
        current_occurrences={
            libref: str(history[-1]["occurrence_id"]) for libref, history in by_libref.items()
        },
        evaluated_at=evaluated_at,
    )
    unknown = set(runtime) - set(by_libref)
    if unknown:
        raise ValueError("Runtime evidence references an unobserved libref")

    bindings: list[dict[str, Any]] = []
    for libref, history in sorted(by_libref.items()):
        governed = runtime.get(libref)
        last = history[-1]
        if governed is not None:
            state = BindingState.RUNTIME_OBSERVED
            paths = list(governed.observed_paths)
            blockers: list[str] = []
            authoritative = True
            runtime_id: str | None = governed.evidence_id
        elif last["state"] == BindingState.CLEARED.value:
            state = BindingState.CLEARED
            paths = []
            blockers = [BindingBlocker.CLEARED.value]
            authoritative = False
            runtime_id = None
        elif len(history) > 1:
            state = BindingState.AMBIGUOUS
            paths = []
            blockers = [
                BindingBlocker.REASSIGNED.value,
                BindingBlocker.RUNTIME_EVIDENCE_REQUIRED.value,
            ]
            authoritative = False
            runtime_id = None
        else:
            state = BindingState(str(last["state"]))
            paths = list(last["paths"])
            blockers = list(last["blockers"])
            authoritative = state is BindingState.LITERAL
            runtime_id = None
        bindings.append(
            {
                "binding_id": stable_id(
                    "LBR",
                    {
                        "workload_id": request.workload_id,
                        "libref": libref,
                        "occurrences": [item["occurrence_id"] for item in history],
                        "policy_digest": policy_digest,
                        "runtime_evidence_id": runtime_id,
                    },
                ),
                "libref": libref,
                "state": state.value,
                "logical_paths": paths,
                "occurrence_ids": [item["occurrence_id"] for item in history],
                "selected_occurrence_id": governed.selected_occurrence_id if governed else None,
                "runtime_evidence_id": runtime_id,
                "runtime_evidence_digest": governed.evidence_digest if governed else None,
                "runtime_provider": (
                    [governed.provider_id, governed.provider_version] if governed else None
                ),
                "runtime_observed_at": governed.observed_at if governed else None,
                "runtime_authority": governed.authority if governed else None,
                "runtime_key_id": governed.key_id if governed else None,
                "blockers": blockers,
                "claims": {
                    "authoritative_logical_binding": authoritative,
                    "path_exists": False,
                    "path_authorized": False,
                    "credentials_resolved": False,
                    "connectivity_validated": False,
                },
            }
        )

    result: dict[str, Any] = {
        "schema_version": "1.0",
        "strategy_id": STRATEGY_ID,
        "strategy_version": STRATEGY_VERSION,
        "client_id": request.policy.client_id,
        "workload_id": request.workload_id,
        "source_closure_digest": request.source_closure_digest,
        "policy": policy,
        "policy_digest": policy_digest,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "evaluated_at": request.evaluated_at,
        "occurrences": occurrences,
        "bindings": bindings,
        "claims": {
            "offline_analysis_generated": bool(occurrences),
            "sas_executed": False,
            "customer_paths_accessed": False,
            "credentials_inferred": False,
            "migration_ready": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_approved": False,
        },
    }
    result["result_id"] = stable_id("LBRES", result)
    projection = library_binding_projection(result)
    assert_persistable(result)
    assert_persistable(projection)
    return PreparedLibraryBindings(result=result, projection=projection)


def library_binding_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": result["schema_version"],
        "result_id": result["result_id"],
        "client_id": result["client_id"],
        "workload_id": result["workload_id"],
        "source_closure_digest": result["source_closure_digest"],
        "policy_digest": result["policy_digest"],
        "run_id": result["run_id"],
        "attempt_id": result["attempt_id"],
        "binding_states": {item["libref"]: item["state"] for item in result["bindings"]},
        "claims": result["claims"],
    }
