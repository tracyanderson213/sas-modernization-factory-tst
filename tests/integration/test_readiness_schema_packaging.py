from importlib.resources import files
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "name",
    [
        "readiness-input.schema.json",
        "readiness-policy.schema.json",
        "readiness-result.schema.json",
    ],
)
def test_repository_and_packaged_readiness_schemas_match(name: str) -> None:
    repository = Path("schemas") / name
    packaged = files("smf.schemas").joinpath(name)
    assert repository.read_bytes() == packaged.read_bytes()
