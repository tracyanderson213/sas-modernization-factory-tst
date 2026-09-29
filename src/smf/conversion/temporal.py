"""Bounded, locale-independent SAS date and datetime literal normalization.

This module implements only the explicitly qualified SASSEM-01 literal slice.
It does not claim general SAS FORMAT, INFORMAT, function, macro, or timezone
compatibility.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any


class TemporalLiteralKind(StrEnum):
    DATE = "date"
    DATETIME = "datetime"


class TemporalDisposition(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    NORMALIZED = "normalized"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"


_POLICY_FIELDS = {
    "policy_id",
    "version",
    "date_epoch",
    "date_unit",
    "datetime_epoch",
    "datetime_unit",
    "calendar",
    "minimum_date",
    "maximum_date",
    "maximum_fractional_digits",
    "precision_mode",
    "source_timezone",
    "target_timezone",
    "date_format_projection",
    "datetime_format_projection",
    "supported_targets",
    "unsupported_cases",
}
_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TemporalPolicy:
    policy_id: str
    version: str
    date_epoch: str
    date_unit: str
    datetime_epoch: str
    datetime_unit: str
    calendar: str
    minimum_date: str
    maximum_date: str
    maximum_fractional_digits: int
    precision_mode: str
    source_timezone: str
    target_timezone: str
    date_format_projection: str
    datetime_format_projection: str
    supported_targets: tuple[str, ...]
    unsupported_cases: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["supported_targets"] = list(self.supported_targets)
        payload["unsupported_cases"] = list(self.unsupported_cases)
        return payload

    @property
    def policy_digest(self) -> str:
        return _digest(self.to_dict())

    def validate(self) -> TemporalPolicy:
        if not _SAFE_ID.fullmatch(self.policy_id) or not _VERSION.fullmatch(self.version):
            raise ValueError("Temporal policy identity or version is invalid")
        if self.date_epoch != "1960-01-01" or self.date_unit != "days":
            raise ValueError("Temporal policy requires the supported SAS date epoch and unit")
        if self.datetime_epoch != "1960-01-01T00:00:00" or self.datetime_unit != "seconds":
            raise ValueError("Temporal policy requires the supported SAS datetime epoch and unit")
        if self.calendar != "proleptic-gregorian":
            raise ValueError("Temporal policy calendar is unsupported")
        try:
            minimum = date.fromisoformat(self.minimum_date)
            maximum = date.fromisoformat(self.maximum_date)
        except ValueError as exc:
            raise ValueError("Temporal policy date range is invalid") from exc
        if minimum > maximum:
            raise ValueError("Temporal policy date range is reversed")
        if self.maximum_fractional_digits != 6 or self.precision_mode != "preserve-exact":
            raise ValueError("Temporal policy precision mode is unsupported")
        if self.source_timezone != "UTC" or self.target_timezone != "UTC":
            raise ValueError("Temporal policy timezone modes must both be explicit UTC")
        if self.date_format_projection != "DATE9.":
            raise ValueError("Temporal policy date formatting projection is unsupported")
        if self.datetime_format_projection != "ISO8601-6":
            raise ValueError("Temporal policy datetime formatting projection is unsupported")
        if not self.supported_targets or set(self.supported_targets) - {"sparksql", "pyspark"}:
            raise ValueError("Temporal policy contains an unsupported target")
        if len(set(self.supported_targets)) != len(self.supported_targets):
            raise ValueError("Temporal policy contains a duplicate target")
        if not self.unsupported_cases:
            raise ValueError("Temporal policy must enumerate unsupported cases")
        return self

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TemporalPolicy:
        if not isinstance(payload, dict) or set(payload) != _POLICY_FIELDS:
            raise ValueError("Temporal policy has unknown or missing fields")
        normalized = dict(payload)
        for field in ("supported_targets", "unsupported_cases"):
            value = normalized[field]
            if not isinstance(value, list | tuple) or not all(
                isinstance(item, str) for item in value
            ):
                raise ValueError(f"Temporal policy {field} is malformed")
            normalized[field] = tuple(value)
        try:
            policy = cls(**normalized)
        except TypeError as exc:
            raise ValueError("Temporal policy is malformed") from exc
        return policy.validate()


def utc_temporal_policy() -> TemporalPolicy:
    """Return the package-owned policy for the bounded UTC literal slice."""

    return TemporalPolicy(
        policy_id="smf.sas-temporal.utc-literals",
        version="1.0.0",
        date_epoch="1960-01-01",
        date_unit="days",
        datetime_epoch="1960-01-01T00:00:00",
        datetime_unit="seconds",
        calendar="proleptic-gregorian",
        minimum_date="0001-01-01",
        maximum_date="9999-12-31",
        maximum_fractional_digits=6,
        precision_mode="preserve-exact",
        source_timezone="UTC",
        target_timezone="UTC",
        date_format_projection="DATE9.",
        datetime_format_projection="ISO8601-6",
        supported_targets=("sparksql", "pyspark"),
        unsupported_cases=(
            "time-only literals",
            "two-digit years and YEARCUTOFF",
            "named zones, numeric offsets, and local wall-clock interpretation",
            "more than six fractional digits",
            "locale-dependent month forms",
            "macro-generated literals",
            "FORMAT, INFORMAT, INPUT, INTCK, and INTNX",
        ),
    ).validate()


@dataclass(frozen=True)
class TemporalMapping:
    literal_kind: TemporalLiteralKind
    byte_start: int
    byte_end: int
    literal_sha256: str
    canonical_source: str
    normalized_value: str
    target_expression: str
    target_expression_sha256: str
    policy_id: str
    policy_version: str
    policy_digest: str
    strategy_id: str = "smf.sas-temporal-literal"
    strategy_version: str = "1.0.0"

    @property
    def kind(self) -> TemporalLiteralKind:
        return self.literal_kind

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TemporalNormalizationResult:
    disposition: TemporalDisposition
    rewritten: bytes | None
    mappings: tuple[TemporalMapping, ...]
    blockers: tuple[str, ...]


_TOKEN = re.compile(
    rb"""(?<![A-Za-z0-9_])(?:'(?:[^']|'')*'|"(?:[^"]|"")*")"""
    rb"(?P<suffix>[A-Za-z]+)\b"
)
_DATE = re.compile(r"(?P<day>[0-9]{2})(?P<month>[A-Za-z]{3})(?P<year>[0-9]{4})")
_DATETIME = re.compile(
    r"(?P<day>[0-9]{2})(?P<month>[A-Za-z]{3})(?P<year>[0-9]{4}):"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?"
)
_MONTHS = {
    "JAN": 1,
    "FEB": 2,
    "MAR": 3,
    "APR": 4,
    "MAY": 5,
    "JUN": 6,
    "JUL": 7,
    "AUG": 8,
    "SEP": 9,
    "OCT": 10,
    "NOV": 11,
    "DEC": 12,
}


def _blocked(reason: str) -> TemporalNormalizationResult:
    return TemporalNormalizationResult(TemporalDisposition.BLOCKED, None, (), (reason,))


def _parse_date(value: str, policy: TemporalPolicy) -> tuple[date, str] | str:
    matched = _DATE.fullmatch(value)
    if matched is None:
        return "date literal grammar is unsupported"
    month = _MONTHS.get(matched.group("month").upper())
    if month is None:
        return "date literal uses a locale-dependent or unknown month"
    try:
        parsed = date(int(matched.group("year")), month, int(matched.group("day")))
    except ValueError:
        return "date literal is not a valid Gregorian calendar date"
    if (
        not date.fromisoformat(policy.minimum_date)
        <= parsed
        <= date.fromisoformat(policy.maximum_date)
    ):
        return "date literal is outside the policy-supported range"
    canonical = f"{parsed.day:02d}{matched.group('month').upper()}{parsed.year:04d}"
    return parsed, canonical


def _mapping(
    token: bytes,
    match: re.Match[bytes],
    kind: TemporalLiteralKind,
    canonical: str,
    normalized: str,
    expression: str,
    policy: TemporalPolicy,
) -> TemporalMapping:
    return TemporalMapping(
        literal_kind=kind,
        byte_start=match.start(),
        byte_end=match.end(),
        literal_sha256=hashlib.sha256(token).hexdigest(),
        canonical_source=canonical,
        normalized_value=normalized,
        target_expression=expression,
        target_expression_sha256=hashlib.sha256(expression.encode("utf-8")).hexdigest(),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_digest=policy.policy_digest,
    )


def normalize_temporal_literals(
    source: bytes, policy: TemporalPolicy | None, *, target: str = "sparksql"
) -> TemporalNormalizationResult:
    """Normalize exact SAS literal tokens while retaining byte-bound evidence."""

    matches = tuple(_TOKEN.finditer(source))
    if not matches:
        return TemporalNormalizationResult(TemporalDisposition.NOT_APPLICABLE, source, (), ())
    suffixes = tuple(match.group("suffix").decode("ascii").lower() for match in matches)
    if any(suffix == "t" for suffix in suffixes):
        return TemporalNormalizationResult(
            TemporalDisposition.UNSUPPORTED,
            None,
            (),
            ("time-only literals are outside the supported temporal policy",),
        )
    if any(suffix not in {"d", "dt"} for suffix in suffixes):
        return TemporalNormalizationResult(
            TemporalDisposition.UNSUPPORTED,
            None,
            (),
            ("quoted literal suffix is outside the supported temporal grammar",),
        )
    if policy is None:
        return _blocked("temporal policy binding is required")
    policy.validate()
    if target not in policy.supported_targets:
        return _blocked("conversion target is absent from the temporal policy")
    mappings: list[TemporalMapping] = []
    for match in matches:
        token = match.group(0)
        suffix = match.group("suffix").decode("ascii").lower()
        quote = token[:1]
        try:
            value = token[1 : token.rfind(quote)].decode("ascii")
        except UnicodeDecodeError:
            return _blocked("temporal literal is not locale-independent ASCII")
        if suffix == "d":
            parsed = _parse_date(value, policy)
            if isinstance(parsed, str):
                return _blocked(parsed)
            parsed_date, canonical = parsed
            normalized = str((parsed_date - date.fromisoformat(policy.date_epoch)).days)
            expression = f"DATE '{parsed_date.isoformat()}'"
            mappings.append(
                _mapping(
                    token,
                    match,
                    TemporalLiteralKind.DATE,
                    canonical,
                    normalized,
                    expression,
                    policy,
                )
            )
            continue
        parsed_match = _DATETIME.fullmatch(value)
        if parsed_match is None:
            return _blocked("datetime literal grammar is unsupported")
        fraction = parsed_match.group("fraction") or ""
        if len(fraction) > policy.maximum_fractional_digits:
            return _blocked("datetime literal precision exceeds the supported maximum")
        date_part = (
            f"{parsed_match.group('day')}{parsed_match.group('month')}{parsed_match.group('year')}"
        )
        parsed_date_value = _parse_date(date_part, policy)
        if isinstance(parsed_date_value, str):
            return _blocked(parsed_date_value.replace("date literal", "datetime literal"))
        parsed_date, canonical_date = parsed_date_value
        hour = int(parsed_match.group("hour"))
        minute = int(parsed_match.group("minute"))
        second = int(parsed_match.group("second"))
        if hour > 23 or minute > 59 or second > 59:
            return _blocked("datetime literal clock value is invalid")
        parsed_datetime = datetime(
            parsed_date.year, parsed_date.month, parsed_date.day, hour, minute, second
        )
        epoch = datetime.fromisoformat(policy.datetime_epoch)
        whole_seconds = int((parsed_datetime - epoch).total_seconds())
        normalized_decimal = Decimal(whole_seconds)
        if fraction:
            normalized_decimal += Decimal(f"0.{fraction}")
        normalized = format(normalized_decimal, "f")
        time_text = f"{hour:02d}:{minute:02d}:{second:02d}"
        if fraction:
            time_text += f".{fraction}"
        canonical = f"{canonical_date}:{time_text}"
        expression = f"TIMESTAMP '{parsed_date.isoformat()} {time_text}'"
        mappings.append(
            _mapping(
                token,
                match,
                TemporalLiteralKind.DATETIME,
                canonical,
                normalized,
                expression,
                policy,
            )
        )
    rewritten = source
    for mapping in reversed(mappings):
        rewritten = (
            rewritten[: mapping.byte_start]
            + mapping.target_expression.encode("utf-8")
            + rewritten[mapping.byte_end :]
        )
    return TemporalNormalizationResult(
        TemporalDisposition.NORMALIZED, rewritten, tuple(mappings), ()
    )
