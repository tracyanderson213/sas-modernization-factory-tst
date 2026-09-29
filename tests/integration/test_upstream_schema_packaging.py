from __future__ import annotations

import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

SCHEMAS = (
    "upstream-policy.schema.json",
    "upstream-inventory.schema.json",
    "upstream-observation-receipt.schema.json",
    "upstream-qualification-result.schema.json",
    "upstream-consumer-projection.schema.json",
)


@pytest.mark.parametrize("name", SCHEMAS)
def test_upstream_schema_is_packaged_and_valid(name: str) -> None:
    payload = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(payload)
