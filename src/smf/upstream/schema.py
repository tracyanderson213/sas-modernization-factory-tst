"""Packaged JSON Schema validation for upstream qualification contracts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

_NAMES = {
    "upstream-policy.schema.json",
    "upstream-inventory.schema.json",
    "upstream-observation-receipt.schema.json",
    "upstream-qualification-result.schema.json",
    "upstream-consumer-projection.schema.json",
}


def validate(name: str, payload: dict[str, Any]) -> None:
    if name not in _NAMES:
        raise ValueError("Unknown upstream qualification schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Upstream schema validation failed: {details}")


def validate_policy(payload: dict[str, Any]) -> None:
    validate("upstream-policy.schema.json", payload)


def validate_inventory(payload: dict[str, Any]) -> None:
    validate("upstream-inventory.schema.json", payload)


def validate_receipt(payload: dict[str, Any]) -> None:
    validate("upstream-observation-receipt.schema.json", payload)


def validate_result(payload: dict[str, Any]) -> None:
    validate("upstream-qualification-result.schema.json", payload)


def validate_projection(payload: dict[str, Any]) -> None:
    validate("upstream-consumer-projection.schema.json", payload)
