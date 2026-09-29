"""Packaged JSON Schema validation for security contracts."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator


def validate_security_schema(name: str, payload: dict[str, Any]) -> None:
    if name not in {
        "workload-identity-config.schema.json",
        "secret-provider-config.schema.json",
        "secret-resolution-result.schema.json",
        "security-threat-model.schema.json",
        "ai-context-policy.schema.json",
        "ai-classification-evidence.schema.json",
        "ai-context-admission-result.schema.json",
        "ai-transport-policy.schema.json",
        "ai-endpoint-binding.schema.json",
        "ai-submission-evidence.schema.json",
        "ai-transport-preparation.schema.json",
        "ai-transport-result.schema.json",
        "ai-provider-preparation.schema.json",
        "ai-provider-prerequisite.schema.json",
        "ai-provider-result.schema.json",
    }:
        raise ValueError("Unknown security schema")
    schema = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path)
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(map(str, item.path)) or '<root>'}: {item.message}" for item in errors
        )
        raise ValueError(f"Security schema validation failed: {detail}")
