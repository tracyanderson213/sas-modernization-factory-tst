"""Packaged strict JSON Schema validation for LIC-01."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

_NAMES = {
    "license-compliance-policy.schema.json",
    "license-compliance-evidence.schema.json",
    "license-compliance-result.schema.json",
    "license-compliance-projection.schema.json",
}


def validate(name: str, payload: dict[str, Any]) -> None:
    if name not in _NAMES:
        raise ValueError("Unknown license compliance schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"License compliance schema validation failed: {detail}")


def validate_policy(payload: dict[str, Any]) -> None:
    validate("license-compliance-policy.schema.json", payload)


def validate_evidence(payload: dict[str, Any]) -> None:
    validate("license-compliance-evidence.schema.json", payload)


def validate_result(payload: dict[str, Any]) -> None:
    validate("license-compliance-result.schema.json", payload)


def validate_projection(payload: dict[str, Any]) -> None:
    validate("license-compliance-projection.schema.json", payload)
