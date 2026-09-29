"""Bounded SAS missing-value and implicit literal-coercion compatibility.

Only exact character-to-numeric coercion between syntactically self-typed
literals is normalizable. Missing-sensitive, malformed, lossy, and
schema-dependent behavior remains explicit and cannot generate target code.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any


class ValueDisposition(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    QUALIFIED = "qualified"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"


_FIELDS = {
    "policy_id",
    "version",
    "sas_semantic_family",
    "supported_targets",
    "ordinary_missing_mode",
    "special_missing_mode",
    "missing_comparison_mode",
    "missing_ordering_mode",
    "missing_arithmetic_mode",
    "missing_summary_mode",
    "missing_output_mode",
    "character_to_numeric_mode",
    "numeric_to_character_mode",
    "schema_dependent_mode",
    "malformed_input_mode",
    "lossy_coercion_mode",
    "maximum_integer_digits",
    "maximum_fractional_digits",
    "unsupported_cases",
}
_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?")
_SECRET_TEXT = re.compile(
    r"(?i)(secret-canary|password\s*=|passwd\s*=|client[_-]?secret|access[_-]?token|dapi[a-z0-9]{8,})"
)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True)
class ValueCompatibilityPolicy:
    policy_id: str
    version: str
    sas_semantic_family: str
    supported_targets: tuple[str, ...]
    ordinary_missing_mode: str
    special_missing_mode: str
    missing_comparison_mode: str
    missing_ordering_mode: str
    missing_arithmetic_mode: str
    missing_summary_mode: str
    missing_output_mode: str
    character_to_numeric_mode: str
    numeric_to_character_mode: str
    schema_dependent_mode: str
    malformed_input_mode: str
    lossy_coercion_mode: str
    maximum_integer_digits: int
    maximum_fractional_digits: int
    unsupported_cases: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["supported_targets"] = list(self.supported_targets)
        value["unsupported_cases"] = list(self.unsupported_cases)
        return value

    @property
    def policy_digest(self) -> str:
        return _digest(self.to_dict())

    def validate(self) -> ValueCompatibilityPolicy:
        if not _SAFE_ID.fullmatch(self.policy_id) or not _VERSION.fullmatch(self.version):
            raise ValueError("Value compatibility policy identity or version is invalid")
        if self.sas_semantic_family != "sas-9.4-compatible":
            raise ValueError("Value compatibility policy semantic family is unsupported")
        if not self.supported_targets or set(self.supported_targets) - {"sparksql", "pyspark"}:
            raise ValueError("Value compatibility policy contains an unsupported target")
        if len(set(self.supported_targets)) != len(self.supported_targets):
            raise ValueError("Value compatibility policy contains a duplicate target")
        modes = {
            self.ordinary_missing_mode,
            self.special_missing_mode,
            self.missing_comparison_mode,
            self.missing_ordering_mode,
            self.missing_arithmetic_mode,
            self.missing_summary_mode,
            self.missing_output_mode,
            self.numeric_to_character_mode,
            self.schema_dependent_mode,
            self.malformed_input_mode,
            self.lossy_coercion_mode,
        }
        if modes != {"unresolved"}:
            raise ValueError("Value compatibility policy unresolved modes cannot be widened")
        if self.character_to_numeric_mode != "exact-bounded-decimal-literals":
            raise ValueError("Value compatibility policy character coercion mode is unsupported")
        if not 1 <= self.maximum_integer_digits <= 18:
            raise ValueError("Value compatibility policy integer bound is unsupported")
        if not 0 <= self.maximum_fractional_digits <= 9:
            raise ValueError("Value compatibility policy fractional bound is unsupported")
        if not self.unsupported_cases or len(set(self.unsupported_cases)) != len(
            self.unsupported_cases
        ):
            raise ValueError("Value compatibility policy unsupported cases are malformed")
        if _SECRET_TEXT.search(json.dumps(self.to_dict(), sort_keys=True)):
            raise ValueError("Value compatibility policy contains protected data")
        return self

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ValueCompatibilityPolicy:
        if not isinstance(payload, dict) or set(payload) != _FIELDS:
            raise ValueError("Value compatibility policy has unknown or missing fields")
        normalized = dict(payload)
        for field in ("supported_targets", "unsupported_cases"):
            value = normalized[field]
            if (
                not isinstance(value, list)
                or not value
                or not all(isinstance(item, str) and item for item in value)
            ):
                raise ValueError(f"Value compatibility policy {field} is malformed")
            normalized[field] = tuple(value)
        if (
            type(normalized["maximum_integer_digits"]) is not int
            or type(normalized["maximum_fractional_digits"]) is not int
        ):
            raise ValueError("Value compatibility policy precision bounds are malformed")
        try:
            return cls(**normalized).validate()
        except TypeError as exc:
            raise ValueError("Value compatibility policy is malformed") from exc


@dataclass(frozen=True)
class ValueOccurrence:
    occurrence_kind: str
    conversion_direction: str | None
    byte_start: int
    byte_end: int
    source_token_sha256: str
    missing_category: str | None
    operand_types: tuple[str, ...]
    normalized_value: str | None
    target_expression: str | None
    target_expression_sha256: str | None
    policy_id: str | None
    policy_version: str | None
    policy_digest: str | None
    strategy_id: str = "smf.sas-value-semantics"
    strategy_version: str = "1.0.0"
    reason_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ValueClassification:
    disposition: ValueDisposition
    rewritten: bytes | None
    occurrences: tuple[ValueOccurrence, ...]
    blockers: tuple[str, ...]


_QUOTED = rb"(?:'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\")"
_PLAIN_QUOTED = _QUOTED + rb"(?![A-Za-z])"
_NUMERIC = rb"[+-]?[0-9]+(?:\.[0-9]+)?"
_BOUNDED_NUMERIC = rb"(?<![A-Za-z0-9_.])" + _NUMERIC + rb"(?![A-Za-z0-9_.])"
_COERCION = re.compile(
    rb"(?:(?P<char>"
    + _PLAIN_QUOTED
    + rb")\s*(?P<op><=|>=|<>|=|<|>|\+|-|\*|/)\s*(?P<num>"
    + _BOUNDED_NUMERIC
    + rb")"
    rb"|(?P<num2>"
    + _BOUNDED_NUMERIC
    + rb")\s*(?P<op2><=|>=|<>|=|<|>|\+|-|\*|/)\s*(?P<char2>"
    + _PLAIN_QUOTED
    + rb"))"
)
_IDENTIFIER = rb"[A-Za-z_][A-Za-z0-9_.]*"
_SIMPLE_OPERAND = rb"(?:" + _PLAIN_QUOTED + rb"|" + _BOUNDED_NUMERIC + rb"|" + _IDENTIFIER + rb")"
_BETWEEN_COERCION = re.compile(
    rb"(?P<subject>"
    + _SIMPLE_OPERAND
    + rb")\s+(?:not\s+)?between\s+(?P<lower>"
    + _SIMPLE_OPERAND
    + rb")\s+and\s+(?P<upper>"
    + _SIMPLE_OPERAND
    + rb")",
    re.IGNORECASE,
)
_CONCAT_COERCION = re.compile(
    rb"(?P<left>" + _SIMPLE_OPERAND + rb")\s*\|\|\s*(?P<right>" + _SIMPLE_OPERAND + rb")"
)
_MISSING = re.compile(rb"(?<![A-Za-z0-9_.])\.(?P<category>[A-Za-z_]+)?(?![A-Za-z0-9_.])")
_BLANK = re.compile(rb"(['\"])[ \t]*\1")
_QUOTED_TOKEN = re.compile(_QUOTED)
_SCHEMA_DEPENDENT = re.compile(
    rb"(?:"
    + rb"(?P<identifier>"
    + _IDENTIFIER
    + rb")\s*(?:<=|>=|<>|=|<|>|\+|-|\*|/)\s*(?P<char>"
    + _PLAIN_QUOTED
    + rb")"
    + rb"|(?P<char2>"
    + _PLAIN_QUOTED
    + rb")\s*(?:<=|>=|<>|=|<|>|\+|-|\*|/)\s*(?P<identifier2>"
    + _IDENTIFIER
    + rb"))"
)


def _occurrence(
    *,
    kind: str,
    token: bytes,
    start: int,
    end: int,
    policy: ValueCompatibilityPolicy | None,
    direction: str | None = None,
    category: str | None = None,
    operand_types: tuple[str, ...] = (),
    normalized: str | None = None,
    expression: str | None = None,
    reason: str | None = None,
) -> ValueOccurrence:
    return ValueOccurrence(
        occurrence_kind=kind,
        conversion_direction=direction,
        byte_start=start,
        byte_end=end,
        source_token_sha256=hashlib.sha256(token).hexdigest(),
        missing_category=category,
        operand_types=operand_types,
        normalized_value=normalized,
        target_expression=expression,
        target_expression_sha256=(
            hashlib.sha256(expression.encode()).hexdigest() if expression is not None else None
        ),
        policy_id=policy.policy_id if policy else None,
        policy_version=policy.version if policy else None,
        policy_digest=policy.policy_digest if policy else None,
        reason_code=reason,
    )


def _canonical_number(value: bytes, policy: ValueCompatibilityPolicy) -> str | None:
    try:
        text = value.decode("ascii").strip(" \t")
    except UnicodeDecodeError:
        return None
    if not _NUMBER.fullmatch(text):
        return None
    unsigned = text.lstrip("+-")
    integer, _, fraction = unsigned.partition(".")
    if (
        len(integer) > policy.maximum_integer_digits
        or len(fraction) > policy.maximum_fractional_digits
    ):
        return None
    try:
        parsed = Decimal(text)
    except InvalidOperation:
        return None
    binary_value = float(parsed)
    if not math.isfinite(binary_value) or Decimal.from_float(binary_value) != parsed:
        return None
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    if normalized in {"-0", "+0", ""}:
        normalized = "0"
    return normalized


def classify_value_semantics(
    statement: bytes,
    policy: ValueCompatibilityPolicy | None,
    *,
    target: str,
) -> ValueClassification:
    """Classify exact statement bytes without inferring column or variable types."""

    if target not in {"sparksql", "pyspark"}:
        raise ValueError("Unknown value compatibility target")
    if policy is not None and target not in policy.supported_targets:
        return ValueClassification(
            ValueDisposition.BLOCKED,
            None,
            (),
            ("value compatibility policy does not authorize the target",),
        )

    quoted_spans = tuple((item.start(), item.end()) for item in _QUOTED_TOKEN.finditer(statement))
    unresolved: list[ValueOccurrence] = []
    for match in _MISSING.finditer(statement):
        if any(start <= match.start() < end for start, end in quoted_spans):
            continue
        marker = match.group(0)
        suffix = match.group("category")
        valid_suffix = suffix is None or suffix == b"_" or (len(suffix) == 1 and suffix.isalpha())
        category = (
            "ordinary"
            if suffix is None
            else ("special-low" if suffix == b"_" else f"special-{suffix.decode().upper()}")
        )
        unresolved.append(
            _occurrence(
                kind="numeric_missing",
                token=marker,
                start=match.start(),
                end=match.end(),
                policy=policy,
                category=category,
                operand_types=("numeric-missing",),
                reason=(
                    "missing_semantics_unresolved" if valid_suffix else "unsupported_missing_marker"
                ),
            )
        )
    for match in _BLANK.finditer(statement):
        unresolved.append(
            _occurrence(
                kind="character_missing",
                token=match.group(0),
                start=match.start(),
                end=match.end(),
                policy=policy,
                category="character-blank",
                operand_types=("character-missing",),
                reason="missing_semantics_unresolved",
            )
        )
    if unresolved:
        disposition = ValueDisposition.BLOCKED if policy is None else ValueDisposition.UNSUPPORTED
        reason = (
            "value compatibility policy is required for detected missing semantics"
            if policy is None
            else "missing-value comparison, ordering, arithmetic, summary, or output is unresolved"
        )
        return ValueClassification(disposition, None, tuple(unresolved), (reason,))

    contextual_occurrences: list[ValueOccurrence] = []
    for match in _BETWEEN_COERCION.finditer(statement):
        groups = ("subject", "lower", "upper")
        character_groups = tuple(
            group for group in groups if match.group(group).startswith((b"'", b'"'))
        )
        identifier_groups = tuple(
            group
            for group in groups
            if re.fullmatch(_IDENTIFIER, match.group(group), re.IGNORECASE)
        )
        if character_groups and identifier_groups:
            for group in character_groups:
                token = match.group(group)
                contextual_occurrences.append(
                    _occurrence(
                        kind="type_ambiguous_coercion",
                        token=token,
                        start=match.start(group),
                        end=match.end(group),
                        policy=policy,
                        operand_types=("unbound-identifier", "character-literal"),
                        reason=(
                            "policy_missing"
                            if policy is None
                            else "authoritative_type_binding_missing"
                        ),
                    )
                )
            continue
        if identifier_groups or not character_groups or len(character_groups) == len(groups):
            continue
        for group in character_groups:
            token = match.group(group)
            numeric_value = _canonical_number(token[1:-1], policy) if policy is not None else None
            reason = "policy_missing"
            if policy is not None:
                reason = (
                    "between_coercion_context_unresolved"
                    if numeric_value is not None
                    else "malformed_or_lossy_numeric_literal"
                )
            contextual_occurrences.append(
                _occurrence(
                    kind="implicit_coercion",
                    token=token,
                    start=match.start(group),
                    end=match.end(group),
                    policy=policy,
                    direction="character-to-numeric",
                    operand_types=("numeric-literal", "character-literal"),
                    reason=reason,
                )
            )
    for match in _CONCAT_COERCION.finditer(statement):
        concat_groups = ("left", "right")
        numeric_groups = tuple(
            group for group in concat_groups if re.fullmatch(_BOUNDED_NUMERIC, match.group(group))
        )
        identifier_groups = tuple(
            group
            for group in concat_groups
            if re.fullmatch(_IDENTIFIER, match.group(group), re.IGNORECASE)
        )
        if not numeric_groups and not identifier_groups:
            continue
        evidence_groups = numeric_groups or identifier_groups
        for group in evidence_groups:
            token = match.group(group)
            contextual_occurrences.append(
                _occurrence(
                    kind=("implicit_coercion" if numeric_groups else "type_ambiguous_coercion"),
                    token=token,
                    start=match.start(group),
                    end=match.end(group),
                    policy=policy,
                    direction="numeric-to-character" if numeric_groups else None,
                    operand_types=(
                        ("numeric-literal", "concatenation-operand")
                        if numeric_groups
                        else ("unbound-identifier", "concatenation-operand")
                    ),
                    reason=(
                        "policy_missing"
                        if policy is None
                        else (
                            "numeric_to_character_unresolved"
                            if numeric_groups
                            else "authoritative_type_binding_missing"
                        )
                    ),
                )
            )
    if contextual_occurrences:
        disposition = ValueDisposition.BLOCKED if policy is None else ValueDisposition.UNSUPPORTED
        reason = (
            "value compatibility policy is required for implicit coercion"
            if policy is None
            else "implicit coercion context is unsupported by the compatibility policy"
        )
        return ValueClassification(disposition, None, tuple(contextual_occurrences), (reason,))

    schema_dependent = list(_SCHEMA_DEPENDENT.finditer(statement))
    if schema_dependent:
        ambiguous_occurrences: list[ValueOccurrence] = []
        for match in schema_dependent:
            char_group = "char" if match.group("char") is not None else "char2"
            token = match.group(char_group)
            ambiguous_occurrences.append(
                _occurrence(
                    kind="type_ambiguous_coercion",
                    token=token,
                    start=match.start(char_group),
                    end=match.end(char_group),
                    policy=policy,
                    operand_types=("unbound-identifier", "character-literal"),
                    reason="authoritative_type_binding_missing",
                )
            )
        disposition = ValueDisposition.BLOCKED if policy is None else ValueDisposition.UNSUPPORTED
        return ValueClassification(
            disposition,
            None,
            tuple(ambiguous_occurrences),
            ("schema-dependent coercion requires an authoritative type binding",),
        )

    matches = list(_COERCION.finditer(statement))
    if not matches:
        return ValueClassification(ValueDisposition.NOT_APPLICABLE, statement, (), ())
    if policy is None:
        blocked_occurrences = tuple(
            _occurrence(
                kind="implicit_coercion",
                token=match.group(0),
                start=match.start(),
                end=match.end(),
                policy=None,
                direction="character-to-numeric",
                operand_types=("character-literal", "numeric-literal"),
                reason="policy_missing",
            )
            for match in matches
        )
        return ValueClassification(
            ValueDisposition.BLOCKED,
            None,
            blocked_occurrences,
            ("value compatibility policy is required for implicit coercion",),
        )

    occurrences: list[ValueOccurrence] = []
    replacements: list[tuple[int, int, bytes]] = []
    for match in matches:
        char_group = "char" if match.group("char") is not None else "char2"
        token = match.group(char_group)
        operator = match.group("op") or match.group("op2")
        if operator in {b"+", b"-", b"*", b"/"}:
            occurrences.append(
                _occurrence(
                    kind="implicit_coercion",
                    token=token,
                    start=match.start(char_group),
                    end=match.end(char_group),
                    policy=policy,
                    direction="character-to-numeric",
                    operand_types=("character-literal", "numeric-literal"),
                    reason="arithmetic_equivalence_unproven",
                )
            )
            continue
        raw_value = token[1:-1]
        normalized = _canonical_number(raw_value, policy)
        if normalized is None:
            occurrences.append(
                _occurrence(
                    kind="implicit_coercion",
                    token=token,
                    start=match.start(char_group),
                    end=match.end(char_group),
                    policy=policy,
                    direction="character-to-numeric",
                    operand_types=("character-literal", "numeric-literal"),
                    reason="malformed_or_lossy_numeric_literal",
                )
            )
            continue
        occurrences.append(
            _occurrence(
                kind="implicit_coercion",
                token=token,
                start=match.start(char_group),
                end=match.end(char_group),
                policy=policy,
                direction="character-to-numeric",
                operand_types=("character-literal", "numeric-literal"),
                normalized=normalized,
                expression=normalized,
            )
        )
        replacements.append((match.start(char_group), match.end(char_group), normalized.encode()))
    if any(item.reason_code for item in occurrences):
        return ValueClassification(
            ValueDisposition.UNSUPPORTED,
            None,
            tuple(occurrences),
            ("malformed, out-of-policy, or lossy implicit numeric coercion is unresolved",),
        )
    rewritten = statement
    for start, end, replacement in reversed(replacements):
        rewritten = rewritten[:start] + replacement + rewritten[end:]
    return ValueClassification(ValueDisposition.QUALIFIED, rewritten, tuple(occurrences), ())
