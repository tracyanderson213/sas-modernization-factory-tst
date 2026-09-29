import json
from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


@pytest.mark.parametrize(
    "name",
    [
        "batch-intake-manifest.schema.json",
        "batch-intake-policy.schema.json",
        "batch-intake-result.schema.json",
    ],
)
def test_batch_intake_schema_is_packaged_and_byte_identical(name: str) -> None:
    repository = Path("schemas") / name
    packaged = files("smf.schemas").joinpath(name)
    assert repository.read_bytes() == packaged.read_bytes()
    Draft202012Validator.check_schema(json.loads(repository.read_text(encoding="utf-8")))
