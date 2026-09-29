"""JSON schema access for readiness inputs, policies, and results."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator


def _load(name: str) -> dict[str, Any]:
    resource = files("smf.schemas").joinpath(name)
    raw = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"{name} must contain a JSON object")
    return raw


def _validate(name: str, payload: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_load(name)).iter_errors(payload), key=lambda e: list(e.path)
    )
    if errors:
        message = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Readiness schema validation failed: {message}")


def validate_input_schema(payload: dict[str, Any]) -> None:
    _validate("readiness-input.schema.json", payload)


def validate_policy_schema(payload: dict[str, Any]) -> None:
    _validate("readiness-policy.schema.json", payload)


def validate_result_schema(payload: dict[str, Any]) -> None:
    _validate("readiness-result.schema.json", payload)
