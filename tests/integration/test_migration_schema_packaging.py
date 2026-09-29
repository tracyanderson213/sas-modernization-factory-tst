import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMAS = (
    "migration-cli-request.schema.json",
    "migration-cli-result.schema.json",
    "migration-cli-telemetry.schema.json",
    "migration-source-snapshot.schema.json",
    "migration-configuration-manifest.schema.json",
)


def test_migration_schema_mirrors_are_identical_and_strict() -> None:
    for name in SCHEMAS:
        public = Path("schemas", name).read_bytes()
        packaged = files("smf.schemas").joinpath(name).read_bytes()
        assert public == packaged
        schema = json.loads(public)
        Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
