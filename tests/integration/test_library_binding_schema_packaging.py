import json
from importlib.resources import files

from jsonschema import Draft202012Validator


def test_library_binding_schema_is_packaged_and_valid() -> None:
    payload = json.loads(
        files("smf.schemas")
        .joinpath("sas-library-binding-evidence.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(payload)
