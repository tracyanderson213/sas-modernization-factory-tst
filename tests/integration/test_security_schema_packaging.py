from importlib.resources import files
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


@pytest.mark.parametrize(
    "name",
    [
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
    ],
)
def test_security_schema_is_packaged_and_byte_identical(name: str) -> None:
    repository = Path("schemas") / name
    packaged = files("smf.schemas").joinpath(name)
    assert repository.read_bytes() == packaged.read_bytes()
    Draft202012Validator.check_schema(__import__("json").loads(repository.read_text()))
