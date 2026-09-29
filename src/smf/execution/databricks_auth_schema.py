"""JSON Schema validation for DBX-02 authentication evidence."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("Databricks authentication schema must be an object")
    return payload


def validate_databricks_authentication_schema(name: str, payload: dict[str, Any]) -> None:
    if name not in {
        "databricks-authentication-request.schema.json",
        "databricks-authentication-result.schema.json",
    }:
        raise ValueError("Unsupported Databricks authentication schema")
    request = _schema("databricks-authentication-request.schema.json")
    registry = Registry().with_resource(
        "databricks-authentication-request.schema.json",
        Resource.from_contents(request),
    )
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(payload),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Databricks authentication schema validation failed: {detail}")
