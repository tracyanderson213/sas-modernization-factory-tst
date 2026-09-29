"""Packaged schema loading for migration contract artifacts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


def validate_schema(name: str, payload: dict[str, Any]) -> None:
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    related = (
        "migration-cli-request.schema.json",
        "migration-cli-result.schema.json",
        "migration-cli-telemetry.schema.json",
        "migration-source-snapshot.schema.json",
        "migration-configuration-manifest.schema.json",
    )
    resources = []
    for related_name in related:
        related_schema = json.loads(
            files("smf.schemas").joinpath(related_name).read_text(encoding="utf-8")
        )
        resources.append((related_schema["$id"], Resource.from_contents(related_schema)))
    registry = Registry().with_resources(resources)
    errors = sorted(
        Draft202012Validator(schema, registry=registry).iter_errors(payload),
        key=lambda e: list(e.path),
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        )
        raise ValueError(f"Migration contract schema validation failed: {detail}")
