from pathlib import Path

from jsonschema import Draft202012Validator

from smf.validation.engine import validate_conversion
from smf.validation.models import ValidationRequest
from smf.validation.schema import load_validation_schema


def test_validation_result_is_schema_valid(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "simple.py"
    generated.write_text("value = 1\n", encoding="utf-8")

    result = validate_conversion(
        ValidationRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            output_dir=tmp_path / "out",
            minimum_confidence=0.0,
        )
    )

    validator = Draft202012Validator(load_validation_schema())
    errors = list(validator.iter_errors(result.to_dict()))

    assert errors == []
