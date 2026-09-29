"""Packaged JSON-schema validation for batch-intake contracts."""

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
        raise ValueError(f"Batch intake schema validation failed: {detail}")


def validate_manifest(payload: dict[str, Any]) -> None:
    _validate("batch-intake-manifest.schema.json", payload)


def validate_policy(payload: dict[str, Any]) -> None:
    _validate("batch-intake-policy.schema.json", payload)


def validate_result(payload: dict[str, Any]) -> None:
    _validate("batch-intake-result.schema.json", payload)
