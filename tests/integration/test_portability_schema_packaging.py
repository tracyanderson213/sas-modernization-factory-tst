from importlib.resources import files


def test_portability_schemas_are_packaged() -> None:
    schemas = files("smf.schemas")
    for name in ("portability-design.schema.json", "portability-result.schema.json"):
        assert schemas.joinpath(name).is_file()
        assert '"additionalProperties": false' in schemas.joinpath(name).read_text(encoding="utf-8")
