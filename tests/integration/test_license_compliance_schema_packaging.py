"""Installed-package coverage for LIC-01 schemas."""

from __future__ import annotations

import json
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator


@pytest.mark.parametrize(
    "name",
    [
        "license-compliance-policy.schema.json",
        "license-compliance-evidence.schema.json",
        "license-compliance-result.schema.json",
        "license-compliance-projection.schema.json",
    ],
)
def test_license_compliance_schema_is_packaged(name: str) -> None:
    payload = files("smf.schemas").joinpath(name).read_text(encoding="utf-8")
    assert '"additionalProperties": false' in payload
    Draft202012Validator.check_schema(json.loads(payload))
