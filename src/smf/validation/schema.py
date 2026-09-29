from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def validation_schema_path() -> Path:
    return _repo_root() / "schemas" / "validation-result.schema.json"


def load_validation_schema() -> dict[str, Any]:
    with validation_schema_path().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise TypeError("Validation schema must be a JSON object")

    return payload


def validate_result_schema(payload: dict[str, Any]) -> None:
    validator = Draft202012Validator(load_validation_schema())
    errors = sorted(
        validator.iter_errors(payload),
        key=lambda error: list(error.path),
    )

    if errors:
        formatted = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"Validation schema validation failed: {formatted}")
