from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def execution_schema_path() -> Path:
    return _repo_root() / "schemas" / "execution-result.schema.json"


def load_execution_schema() -> dict[str, Any]:
    with execution_schema_path().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise TypeError("Execution schema must be a JSON object")

    return payload


def validate_execution_schema(payload: dict[str, Any]) -> None:
    validator = Draft202012Validator(load_execution_schema())
    errors = sorted(
        validator.iter_errors(payload),
        key=lambda error: list(error.path),
    )

    if errors:
        formatted = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"Execution schema validation failed: {formatted}")
