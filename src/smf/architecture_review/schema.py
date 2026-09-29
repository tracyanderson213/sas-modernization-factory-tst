"""Packaged schema validation for architecture review artifacts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator


def validate(name: str, payload: dict[str, Any]) -> None:
    if name not in {
        "architecture-review-packet.schema.json",
        "architecture-review-projection.schema.json",
    }:
        raise ValueError("Unknown architecture review schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda e: list(e.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Architecture review schema validation failed: {detail}")
