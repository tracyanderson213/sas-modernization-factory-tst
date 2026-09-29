from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "name",
    [
        "fixture-qualification-policy.schema.json",
        "fixture-qualification-manifest.schema.json",
        "fixture-qualification-result.schema.json",
    ],
)
def test_fixture_qualification_schema_is_packaged_and_matches_source(name: str) -> None:
    repository_schema = Path("schemas") / name
    packaged = files("smf.schemas").joinpath(name)
    assert repository_schema.read_bytes() == packaged.read_bytes()
