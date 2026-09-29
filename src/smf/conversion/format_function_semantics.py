"""Classification-only SAS FORMAT, INFORMAT, and function semantics.

SASSEM-04 deliberately does not emit target code.  It records exact source
locations and fails closed until independently qualified mappings and governed
runtime inputs exist.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from smf.conversion.manifest import publish_json, read_published_json


class SemanticDisposition(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"


class InputStatus(StrEnum):
    PENDING = "pending"
    DENIED = "denied"


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET = re.compile(
    rb"(?i)(secret-canary|password\s*=|passwd\s*=|client[_-]?secret|"
    rb"access[_-]?token|dapi[a-z0-9]{8,})"
)
_EXTERNAL_INPUTS = (
    "sas_runtime",
    "sas_version",
    "session_options",
    "locale",
    "timezone",
    "yearcutoff",
    "oracle_authority",
    "business_tolerances",
    "humana_owner_decisions",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class ExternalInput:
    name: str
    status: InputStatus
    evidence_ref: str | None = None

    def validate(self) -> ExternalInput:
        if self.name not in _EXTERNAL_INPUTS:
            raise ValueError("Unknown external input")
        if self.status is InputStatus.PENDING and self.evidence_ref is not None:
            raise ValueError("Pending external input cannot carry authority evidence")
        if self.status is InputStatus.DENIED and not self.evidence_ref:
            raise ValueError("Denied external input requires attributable evidence")
        if self.evidence_ref is not None and not _SAFE_ID.fullmatch(self.evidence_ref):
            raise ValueError("External input evidence reference is unsafe")
        return self


@dataclass(frozen=True)
class FormatFunctionPolicy:
    policy_id: str
    version: str
    strategy_id: str
    strategy_version: str
    executable_mapping_allowlist: tuple[str, ...]
    source_encoding: str
    unknown_label_handling: str
    ambiguous_context_handling: str
    custom_semantics_handling: str
    external_inputs: tuple[ExternalInput, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["executable_mapping_allowlist"] = list(self.executable_mapping_allowlist)
        payload["external_inputs"] = [
            {**asdict(item), "status": item.status.value} for item in self.external_inputs
        ]
        return payload

    @property
    def policy_digest(self) -> str:
        return _digest(self.to_dict())

    def validate(self) -> FormatFunctionPolicy:
        for value in (self.policy_id, self.strategy_id):
            if not _SAFE_ID.fullmatch(value):
                raise ValueError("Policy or strategy identity is invalid")
        if not _VERSION.fullmatch(self.version) or not _VERSION.fullmatch(self.strategy_version):
            raise ValueError("Policy or strategy version is invalid")
        if self.executable_mapping_allowlist:
            raise ValueError("Executable mapping allowlist must remain empty")
        if self.source_encoding != "utf-8-strict":
            raise ValueError("Source encoding is unsupported")
        if self.unknown_label_handling != "blocked":
            raise ValueError("Unknown labels must remain blocked")
        if self.ambiguous_context_handling != "blocked":
            raise ValueError("Ambiguous contexts must remain blocked")
        if self.custom_semantics_handling != "unsupported":
            raise ValueError("Custom semantics must remain unsupported")
        if tuple(item.name for item in self.external_inputs) != _EXTERNAL_INPUTS:
            raise ValueError("External inputs are missing, duplicated, or out of order")
        for item in self.external_inputs:
            item.validate()
        return self

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FormatFunctionPolicy:
        fields = {
            "policy_id",
            "version",
            "strategy_id",
            "strategy_version",
            "executable_mapping_allowlist",
            "source_encoding",
            "unknown_label_handling",
            "ambiguous_context_handling",
            "custom_semantics_handling",
            "external_inputs",
        }
        if not isinstance(payload, dict) or set(payload) != fields:
            raise ValueError("Policy has unknown or missing fields")
        values = dict(payload)
        allowlist = values["executable_mapping_allowlist"]
        inputs = values["external_inputs"]
        if not isinstance(allowlist, list) or not all(isinstance(v, str) for v in allowlist):
            raise ValueError("Executable mapping allowlist is malformed")
        if not isinstance(inputs, list):
            raise ValueError("External inputs are malformed")
        parsed: list[ExternalInput] = []
        try:
            for item in inputs:
                if not isinstance(item, dict) or set(item) != {"name", "status", "evidence_ref"}:
                    raise ValueError("External input has unknown or missing fields")
                parsed.append(
                    ExternalInput(
                        name=item["name"],
                        status=InputStatus(item["status"]),
                        evidence_ref=item["evidence_ref"],
                    )
                )
            values["executable_mapping_allowlist"] = tuple(allowlist)
            values["external_inputs"] = tuple(parsed)
            return cls(**values).validate()
        except ValueError:
            raise
        except TypeError as exc:
            raise ValueError("Policy contains malformed enum or field values") from exc


def classification_policy() -> FormatFunctionPolicy:
    return FormatFunctionPolicy(
        policy_id="smf.sassem04.classification",
        version="1.0.0",
        strategy_id="smf.sas-format-function-classifier",
        strategy_version="1.0.0",
        executable_mapping_allowlist=(),
        source_encoding="utf-8-strict",
        unknown_label_handling="blocked",
        ambiguous_context_handling="blocked",
        custom_semantics_handling="unsupported",
        external_inputs=tuple(
            ExternalInput(name, InputStatus.PENDING) for name in _EXTERNAL_INPUTS
        ),
    ).validate()


@dataclass(frozen=True)
class SemanticOccurrence:
    occurrence_id: str
    kind: str
    name: str
    byte_start: int
    byte_end: int
    line: int
    column: int
    source_token_sha256: str
    disposition: SemanticDisposition
    reason_code: str
    underlying_value_separate: bool = True
    formatted_projection_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["disposition"] = self.disposition.value
        return payload


@dataclass(frozen=True)
class ClassificationRequest:
    client_id: str
    workload_id: str
    subject_id: str
    source_artifact_id: str
    run_id: str
    attempt_id: str
    source_snapshot_ref: str


_PROC_FORMAT = re.compile(r"\bproc\s+format\b", re.IGNORECASE)
_PROC_FCMP = re.compile(r"\bproc\s+fcmp\b", re.IGNORECASE)
_STATEMENT = re.compile(r"\b(?P<kind>format|informat)\b(?P<body>[^;]*);", re.IGNORECASE)
_SYSFUNC = re.compile(r"%sysfunc\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_FUNCTION = re.compile(r"(?<![%&.])\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FORMAT_LABEL_TEXT = (
    r"(?:\$?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\d*\.\d*)"
    r"|(?:[0-9]+\.[0-9]*)"
)
_FORMAT_LABEL = re.compile(rf"(?<![A-Za-z0-9_])(?P<label>{_FORMAT_LABEL_TEXT})(?![A-Za-z0-9_])")
_FORMAT_LABEL_FULL = re.compile(_FORMAT_LABEL_TEXT)
_END_BLOCK = re.compile(r"\b(?:run|quit)\s*;", re.IGNORECASE)
_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STATEMENT_COMMENT = re.compile(r"(?m)(?:^|(?<=;))[ \t]*\*[^;]*;")
_TARGET_TEMPLATE = re.compile(r"{{.*?}}|{%.*?%}", re.DOTALL)
_MACRO_TOKEN = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*|&[A-Za-z_][A-Za-z0-9_]*\.?")
_SKIP_FUNCTIONS = {"if", "do", "select", "where", "while", "until", "macro"}
_FORMAT_FUNCTIONS = {"put", "putc", "putn"}
_INFORMAT_FUNCTIONS = {"input", "inputc", "inputn"}


def _mask_strings_and_comments(text: str) -> tuple[str, bool]:
    chars = list(text)
    ambiguous = False
    for match in _COMMENT.finditer(text):
        chars[match.start() : match.end()] = " " * (match.end() - match.start())
    for match in _STATEMENT_COMMENT.finditer(text):
        chars[match.start() : match.end()] = " " * (match.end() - match.start())
    if text.count("/*") != text.count("*/"):
        ambiguous = True
    index = 0
    while index < len(text):
        if chars[index] not in {"'", '"'}:
            index += 1
            continue
        quote = chars[index]
        index += 1
        while index < len(text):
            if chars[index] == quote:
                if index + 1 < len(text) and chars[index + 1] == quote:
                    chars[index : index + 2] = "  "
                    index += 2
                    continue
                chars[index] = " "
                index += 1
                break
            chars[index] = " "
            index += 1
        else:
            ambiguous = True
    return "".join(chars), ambiguous


def _occurrence(
    source: bytes,
    text: str,
    *,
    kind: str,
    name: str,
    start: int,
    end: int,
    disposition: SemanticDisposition,
    reason: str,
) -> SemanticOccurrence:
    # ASCII SAS tokens have identical character and UTF-8 byte offsets.  Convert
    # from character offsets anyway so non-ASCII source before a token stays exact.
    byte_start = len(text[:start].encode("utf-8"))
    byte_end = len(text[:end].encode("utf-8"))
    token = source[byte_start:byte_end]
    token_sha256 = hashlib.sha256(token).hexdigest()
    identity = {
        "kind": kind,
        "name": name.lower(),
        "byte_start": byte_start,
        "byte_end": byte_end,
        "token_sha256": token_sha256,
    }
    return SemanticOccurrence(
        occurrence_id=f"occ-{_digest(identity)[:24]}",
        kind=kind,
        name=name.lower(),
        byte_start=byte_start,
        byte_end=byte_end,
        line=text.count("\n", 0, start) + 1,
        column=start - text.rfind("\n", 0, start),
        source_token_sha256=token_sha256,
        disposition=disposition,
        reason_code=reason,
    )


def _block_occurrence(
    source: bytes, text: str, match: re.Match[str], kind: str
) -> SemanticOccurrence:
    end_match = _END_BLOCK.search(text, match.end())
    end = end_match.end() if end_match else len(text)
    block = text[match.start() : end]
    if kind == "proc_format":
        if re.search(r"\bdefault\s*=", block, re.IGNORECASE):
            reason = "unsupported_default"
        elif re.search(r"(?:^|\s)[^;=]+\s*-\s*[^;=]+\s*=", block, re.IGNORECASE):
            reason = "overlapping_or_ranged_definition"
        else:
            reason = "custom_format_or_informat"
    else:
        reason = "fcmp_function"
    return _occurrence(
        source,
        text,
        kind=kind,
        name=kind,
        start=match.start(),
        end=end,
        disposition=SemanticDisposition.UNSUPPORTED,
        reason=reason,
    )


def _function_arguments(
    masked: str, match: re.Match[str]
) -> tuple[list[tuple[int, int]], int | None]:
    """Return top-level argument spans and the closing parenthesis, if present."""

    opening = match.end() - 1
    depth = 1
    argument_start = opening + 1
    arguments: list[tuple[int, int]] = []
    index = argument_start
    while index < len(masked):
        character = masked[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                arguments.append((argument_start, index))
                return arguments, index
        elif character == "," and depth == 1:
            arguments.append((argument_start, index))
            argument_start = index + 1
        elif character == ";" and depth == 1:
            break
        index += 1
    arguments.append((argument_start, index))
    return arguments, None


def _trimmed_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _format_argument_occurrence(
    source: bytes,
    text: str,
    masked: str,
    match: re.Match[str],
) -> SemanticOccurrence | None:
    function_name = match.group("name").lower()
    if function_name in _FORMAT_FUNCTIONS:
        kind = "format_argument"
    elif function_name in _INFORMAT_FUNCTIONS:
        kind = "informat_argument"
    else:
        return None

    arguments, closing = _function_arguments(masked, match)
    if len(arguments) > 1:
        start, end = _trimmed_span(text, *arguments[1])
    else:
        start, end = match.start(), (closing + 1 if closing is not None else arguments[-1][1])
    argument = text[start:end]
    label_match = _FORMAT_LABEL_FULL.fullmatch(argument)
    if closing is not None and label_match is not None:
        reason = "custom_catalog_reference" if argument.count(".") > 1 else "unqualified_mapping"
        name = argument
    else:
        # Empty, dynamic, missing, or syntactically incomplete arguments are
        # evidence of ambiguity.  Bind the occurrence to a non-empty call span
        # when there is no concrete second-argument token.
        if start == end:
            start, end = match.start(), (closing + 1 if closing is not None else match.end())
        name = function_name
        reason = "ambiguous_format_or_informat_argument"
    return _occurrence(
        source,
        text,
        kind=kind,
        name=name,
        start=start,
        end=end,
        disposition=SemanticDisposition.BLOCKED,
        reason=reason,
    )


def _classify_occurrences(source: bytes, text: str) -> tuple[SemanticOccurrence, ...]:
    masked, lexically_ambiguous = _mask_strings_and_comments(text)
    found: list[SemanticOccurrence] = []
    occupied: list[tuple[int, int]] = []
    template_mask = list(masked)
    for match in _TARGET_TEMPLATE.finditer(masked):
        found.append(
            _occurrence(
                source,
                text,
                kind="target_template",
                name="target_template",
                start=match.start(),
                end=match.end(),
                disposition=SemanticDisposition.BLOCKED,
                reason="target_template_not_sas",
            )
        )
        template_mask[match.start() : match.end()] = " " * (match.end() - match.start())
    masked = "".join(template_mask)
    for pattern, kind in ((_PROC_FORMAT, "proc_format"), (_PROC_FCMP, "proc_fcmp")):
        for match in pattern.finditer(masked):
            item = _block_occurrence(source, text, match, kind)
            found.append(item)
            end_match = _END_BLOCK.search(text, match.end())
            occupied.append((match.start(), end_match.end() if end_match else len(text)))
    for match in _STATEMENT.finditer(masked):
        if masked[max(0, match.start() - 6) : match.start()].lower().strip() == "proc":
            continue
        statement_kind = match.group("kind").lower()
        labels = list(_FORMAT_LABEL.finditer(match.group("body")))
        macro_ambiguous = bool(_MACRO_TOKEN.search(match.group("body")))
        if not labels or macro_ambiguous:
            found.append(
                _occurrence(
                    source,
                    text,
                    kind=f"{statement_kind}_statement",
                    name=statement_kind,
                    start=match.start(),
                    end=match.end(),
                    disposition=SemanticDisposition.BLOCKED,
                    reason="ambiguous_format_or_informat_statement",
                )
            )
        for label in labels:
            start = match.start("body") + label.start("label")
            end = match.start("body") + label.end("label")
            name = label.group("label")
            reason = "custom_catalog_reference" if name.count(".") > 1 else "unqualified_mapping"
            found.append(
                _occurrence(
                    source,
                    text,
                    kind=f"{statement_kind}_label",
                    name=name,
                    start=start,
                    end=end,
                    disposition=SemanticDisposition.BLOCKED,
                    reason=reason,
                )
            )
    sysfunc_spans: list[tuple[int, int]] = []
    for match in _SYSFUNC.finditer(masked):
        sysfunc_spans.append((match.start(), match.end()))
        found.append(
            _occurrence(
                source,
                text,
                kind="macro_sysfunc",
                name=match.group("name"),
                start=match.start(),
                end=match.end(),
                disposition=SemanticDisposition.BLOCKED,
                reason="macro_function_context_unqualified",
            )
        )
    for match in _MACRO_TOKEN.finditer(masked):
        if any(start <= match.start() < end for start, end in sysfunc_spans):
            continue
        found.append(
            _occurrence(
                source,
                text,
                kind="macro_processing",
                name=match.group(),
                start=match.start(),
                end=match.end(),
                disposition=SemanticDisposition.BLOCKED,
                reason="macro_processing_separate",
            )
        )
    for match in _FUNCTION.finditer(masked):
        name = match.group("name")
        if name.lower() in _SKIP_FUNCTIONS:
            continue
        if any(start <= match.start() < end for start, end in occupied):
            continue
        argument_occurrence = _format_argument_occurrence(source, text, masked, match)
        if argument_occurrence is not None:
            found.append(argument_occurrence)
        if any(start <= match.start() < end for start, end in sysfunc_spans):
            continue
        found.append(
            _occurrence(
                source,
                text,
                kind="sas_function",
                name=name,
                start=match.start(),
                end=match.end(),
                disposition=SemanticDisposition.BLOCKED,
                reason="unqualified_function",
            )
        )
    if lexically_ambiguous:
        found.append(
            _occurrence(
                source,
                text,
                kind="ambiguous_context",
                name="macro_or_lexical_ambiguity",
                start=0,
                end=len(text),
                disposition=SemanticDisposition.BLOCKED,
                reason="ambiguous_context",
            )
        )
    occurrence_ids = [item.occurrence_id for item in found]
    if len(set(occurrence_ids)) != len(occurrence_ids):
        raise ValueError("Duplicate semantic occurrence identity")
    return tuple(sorted(found, key=lambda item: (item.byte_start, item.byte_end, item.kind)))


def classify_format_function_semantics(
    source: bytes,
    request: ClassificationRequest,
    policy: FormatFunctionPolicy | None,
) -> dict[str, Any]:
    """Return non-authorizing, immutable-ready classification evidence."""

    for field, value in asdict(request).items():
        if (
            not isinstance(value, str)
            or not _SAFE_ID.fullmatch(value)
            or _SECRET.search(value.encode())
        ):
            raise ValueError(f"Unsafe or malformed {field}")
    if not source:
        raise ValueError("A non-empty source snapshot is required")
    if _SECRET.search(source):
        raise ValueError("Source contains protected data and cannot be persisted or hashed")
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Source is not strict UTF-8") from exc
    if policy is None:
        raise ValueError("A package-validated mapping policy is required")
    policy.validate()
    occurrences = _classify_occurrences(source, text)
    source_digest = hashlib.sha256(source).hexdigest()
    identity = {
        **asdict(request),
        "source_sha256": source_digest,
        "policy_digest": policy.policy_digest,
        "strategy_id": policy.strategy_id,
        "strategy_version": policy.strategy_version,
    }
    decision_id = f"decision-{_digest(identity)[:32]}"
    disposition = (
        SemanticDisposition.NOT_APPLICABLE
        if not occurrences
        else (
            SemanticDisposition.UNSUPPORTED
            if any(item.disposition is SemanticDisposition.UNSUPPORTED for item in occurrences)
            else SemanticDisposition.BLOCKED
        )
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "evidence_id": f"evidence-{_digest({**identity, 'decision_id': decision_id})[:32]}",
        "decision_id": decision_id,
        **asdict(request),
        "source_sha256": source_digest,
        "source_size": len(source),
        "policy": policy.to_dict(),
        "policy_digest": policy.policy_digest,
        "strategy_id": policy.strategy_id,
        "strategy_version": policy.strategy_version,
        "disposition": disposition.value,
        "occurrences": [item.to_dict() for item in occurrences],
        "claims": {
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "certified": False,
            "human_assisted": False,
            "human_approved": False,
            "blocked": disposition
            in {SemanticDisposition.BLOCKED, SemanticDisposition.UNSUPPORTED},
        },
        "terminal_disposition": "unresolved" if occurrences else "not_applicable",
    }
    payload["evidence_sha256"] = _digest(payload)
    return payload


def verify_classification_evidence(
    payload: dict[str, Any], source: bytes, policy: FormatFunctionPolicy
) -> dict[str, Any]:
    """Recompute the decision from qualified bytes; caller assertions have no authority."""

    supplied = dict(payload)
    evidence_digest = supplied.pop("evidence_sha256", None)
    if not isinstance(evidence_digest, str) or not _SHA256.fullmatch(evidence_digest):
        raise ValueError("Evidence digest is missing or malformed")
    if _digest(supplied) != evidence_digest:
        raise ValueError("Evidence digest does not match canonical content")
    request = ClassificationRequest(
        **{field: payload[field] for field in ClassificationRequest.__dataclass_fields__}
    )
    expected = classify_format_function_semantics(source, request, policy)
    if expected != payload:
        raise ValueError("Evidence does not match the exact source, policy, and decision identity")
    return expected


def classification_telemetry(payload: dict[str, Any]) -> dict[str, Any]:
    claims = payload["claims"]
    return {
        "schema_version": "1.0.0",
        "event": "sas_semantics_classified",
        "client_id": payload["client_id"],
        "workload_id": payload["workload_id"],
        "run_id": payload["run_id"],
        "attempt_id": payload["attempt_id"],
        "decision_id": payload["decision_id"],
        "evidence_sha256": payload["evidence_sha256"],
        **claims,
        "disposition": payload["disposition"],
    }


def _validate_evidence_payload(payload: dict[str, Any]) -> None:
    supplied = dict(payload)
    evidence_digest = supplied.pop("evidence_sha256", None)
    if not isinstance(evidence_digest, str) or _digest(supplied) != evidence_digest:
        raise ValueError("Evidence digest does not match canonical content")
    try:
        request = ClassificationRequest(
            **{field: payload[field] for field in ClassificationRequest.__dataclass_fields__}
        )
        policy = FormatFunctionPolicy.from_dict(payload["policy"])
    except (KeyError, TypeError) as exc:
        raise ValueError("Evidence identity or policy is malformed") from exc
    for field, value in asdict(request).items():
        if (
            not isinstance(value, str)
            or not _SAFE_ID.fullmatch(value)
            or _SECRET.search(value.encode())
        ):
            raise ValueError(f"Unsafe or malformed {field}")
    source_sha256 = payload.get("source_sha256")
    if not isinstance(source_sha256, str) or not _SHA256.fullmatch(source_sha256):
        raise ValueError("Evidence source digest is malformed")
    if payload.get("policy_digest") != policy.policy_digest:
        raise ValueError("Evidence policy digest is inconsistent")
    identity = {
        **asdict(request),
        "source_sha256": source_sha256,
        "policy_digest": policy.policy_digest,
        "strategy_id": policy.strategy_id,
        "strategy_version": policy.strategy_version,
    }
    decision_id = f"decision-{_digest(identity)[:32]}"
    evidence_id = f"evidence-{_digest({**identity, 'decision_id': decision_id})[:32]}"
    if payload.get("decision_id") != decision_id or payload.get("evidence_id") != evidence_id:
        raise ValueError("Evidence decision identity is inconsistent")
    disposition = payload.get("disposition")
    occurrences = payload.get("occurrences")
    if disposition not in {item.value for item in SemanticDisposition} or not isinstance(
        occurrences, list
    ):
        raise ValueError("Evidence disposition or occurrences are malformed")
    blocked = disposition in {"blocked", "unsupported"}
    if blocked != bool(occurrences):
        raise ValueError("Evidence disposition does not match its eligible occurrences")
    occurrence_ids = [item.get("occurrence_id") for item in occurrences if isinstance(item, dict)]
    if len(occurrence_ids) != len(occurrences) or len(set(occurrence_ids)) != len(occurrence_ids):
        raise ValueError("Evidence contains duplicate or malformed occurrence identity")
    expected_claims = {
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "human_approved": False,
        "blocked": blocked,
    }
    if payload.get("claims") != expected_claims:
        raise ValueError("Classification evidence contains an unauthorized success claim")
    expected_terminal = "unresolved" if blocked else "not_applicable"
    if payload.get("terminal_disposition") != expected_terminal:
        raise ValueError("Classification terminal disposition is inconsistent")


def publish_classification_evidence(
    root: Path,
    payload: dict[str, Any],
    *,
    source: bytes,
    policy: FormatFunctionPolicy,
) -> tuple[Path, Path]:
    """Publish canonical evidence first and recover the derived event idempotently."""

    verify_classification_evidence(payload, source, policy)
    _validate_evidence_payload(payload)
    parts = [payload[key] for key in ("client_id", "workload_id", "run_id", "attempt_id")]
    if not all(isinstance(part, str) and _SAFE_ID.fullmatch(part) for part in parts):
        raise ValueError("Evidence contains an unsafe publication identity")
    relative = Path(*parts)
    directory = root / relative
    evidence_path = directory / "sas-semantics.evidence.json"
    telemetry_path = directory / "sas-semantics.telemetry.json"
    publish_json(evidence_path, payload, "SAS semantics evidence", root=root)
    canonical = read_published_json(evidence_path, root=root, label="SAS semantics evidence")
    if not isinstance(canonical, dict):
        raise ValueError("Canonical SAS semantics evidence is malformed")
    verify_classification_evidence(canonical, source, policy)
    _validate_evidence_payload(canonical)
    publish_json(
        telemetry_path,
        classification_telemetry(canonical),
        "SAS semantics telemetry",
        root=root,
    )
    return evidence_path, telemetry_path


def recover_classification_telemetry(evidence_path: Path) -> Path:
    if evidence_path.name != "sas-semantics.evidence.json" or len(evidence_path.parents) < 5:
        raise ValueError("Canonical SAS semantics evidence path is malformed")
    root = evidence_path.parents[4]
    payload = read_published_json(evidence_path, root=root, label="SAS semantics evidence")
    if not isinstance(payload, dict):
        raise ValueError("Canonical SAS semantics evidence is malformed")
    _validate_evidence_payload(payload)
    parts = [payload[key] for key in ("client_id", "workload_id", "run_id", "attempt_id")]
    if not all(isinstance(part, str) and _SAFE_ID.fullmatch(part) for part in parts):
        raise ValueError("Evidence contains an unsafe publication identity")
    expected = root.joinpath(*parts, "sas-semantics.evidence.json")
    if os.path.abspath(evidence_path) != os.path.abspath(expected):
        raise ValueError("Canonical SAS semantics evidence path does not match its identity")
    telemetry_path = evidence_path.with_name("sas-semantics.telemetry.json")
    publish_json(
        telemetry_path,
        classification_telemetry(payload),
        "SAS semantics telemetry",
        root=root,
    )
    return telemetry_path
