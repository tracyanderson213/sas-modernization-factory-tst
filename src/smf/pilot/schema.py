"""Packaged JSON-schema validation for pilot-selection artifacts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator


def _validate(name: str, payload: dict[str, Any]) -> None:
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Pilot selection schema validation failed: {detail}")


def validate_policy(payload: dict[str, Any]) -> None:
    _validate("pilot-selection-policy.schema.json", payload)


def validate_inventory(payload: dict[str, Any]) -> None:
    _validate("pilot-inventory.schema.json", payload)


def validate_result(payload: dict[str, Any]) -> None:
    _validate("pilot-selection-result.schema.json", payload)
