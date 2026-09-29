from jsonschema import Draft202012Validator

from smf.assessment.analyzer import assess_sas_file
from smf.assessment.schema import load_assessment_schema


def test_example_assessment_is_schema_valid() -> None:
    payload = assess_sas_file("examples/simple/example.sas")
    validator = Draft202012Validator(load_assessment_schema())

    errors = list(validator.iter_errors(payload))

    assert errors == []
