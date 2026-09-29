"""JSON Schema validation for DBX-03 compute-policy evidence."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def _schema(name: str) -> dict[str, Any]:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("Databricks compute schema must be an object")
    return payload


def validate_databricks_compute_schema(name: str, payload: dict[str, Any]) -> None:
    supported = {
        "databricks-compute-availability.schema.json",
        "databricks-compute-policy.schema.json",
        "databricks-compute-request.schema.json",
        "databricks-compute-result.schema.json",
    }
    if name not in supported:
        raise ValueError("Unsupported Databricks compute schema")
    request = _schema("databricks-compute-request.schema.json")
    registry = Registry().with_resource(request["$id"], Resource.from_contents(request))
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(payload),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Databricks compute schema validation failed: {detail}")
