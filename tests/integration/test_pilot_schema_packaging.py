import json
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


@pytest.mark.parametrize(
    "name",
    [
        "pilot-inventory.schema.json",
        "pilot-selection-policy.schema.json",
        "pilot-selection-result.schema.json",
    ],
)
def test_pilot_schema_is_packaged_and_byte_identical(name: str) -> None:
    repository = Path("schemas") / name
    packaged = files("smf.schemas").joinpath(name)
    assert repository.read_bytes() == packaged.read_bytes()
    Draft202012Validator.check_schema(json.loads(repository.read_text(encoding="utf-8")))
