from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import pytest

SCHEMAS = (
    "baseline-acquisition-policy.schema.json",
    "baseline-acquisition-request.schema.json",
    "baseline-acquisition-result.schema.json",
    "baseline-acquisition-telemetry.schema.json",
    "baseline-provider-receipt.schema.json",
)


@pytest.mark.parametrize("name", SCHEMAS)
def test_repository_and_packaged_baseline_schemas_match(name: str) -> None:
    assert (Path("schemas") / name).read_bytes() == files("smf.schemas").joinpath(name).read_bytes()
