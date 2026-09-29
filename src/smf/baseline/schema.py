"""Packaged schema validation for baseline acquisition contracts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

_NAMES = {
    "baseline-acquisition-request.schema.json",
    "baseline-acquisition-policy.schema.json",
    "baseline-provider-receipt.schema.json",
    "baseline-acquisition-result.schema.json",
    "baseline-acquisition-telemetry.schema.json",
}


def validate(name: str, payload: dict[str, Any]) -> None:
    if name not in _NAMES:
        raise ValueError("Unknown baseline acquisition schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Baseline acquisition schema validation failed: {detail}")


def validate_policy(payload: dict[str, Any]) -> None:
    validate("baseline-acquisition-policy.schema.json", payload)


def validate_request(payload: dict[str, Any]) -> None:
    validate("baseline-acquisition-request.schema.json", payload)


def validate_receipt(payload: dict[str, Any]) -> None:
    validate("baseline-provider-receipt.schema.json", payload)


def validate_result(payload: dict[str, Any]) -> None:
    validate("baseline-acquisition-result.schema.json", payload)


def validate_telemetry(payload: dict[str, Any]) -> None:
    validate("baseline-acquisition-telemetry.schema.json", payload)
