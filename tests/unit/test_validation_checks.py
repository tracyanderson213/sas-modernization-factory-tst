from pathlib import Path

from smf.validation.checks import (
    check_generated_nonempty,
    check_python_syntax,
    check_sas_remainders,
)


def test_valid_python_passes_static_checks(tmp_path: Path) -> None:
    generated = tmp_path / "generated.py"
    generated.write_text(
        'df = spark.table("work_transactions")\nresult = df.groupBy("customer_id").sum("amount")\n',
        encoding="utf-8",
    )

    assert check_generated_nonempty(generated).status == "pass"
    assert check_python_syntax(generated, "pyspark").status == "pass"
    assert check_sas_remainders(generated).status == "pass"


def test_invalid_python_fails_syntax(tmp_path: Path) -> None:
    generated = tmp_path / "broken.py"
    generated.write_text("def broken(:\n", encoding="utf-8")

    result = check_python_syntax(generated, "pyspark")

    assert result.status == "fail"


def test_sas_remainder_fails(tmp_path: Path) -> None:
    generated = tmp_path / "generated.py"
    generated.write_text("proc sql;\nquit;\n", encoding="utf-8")

    result = check_sas_remainders(generated)

    assert result.status == "fail"
    assert result.evidence["matches"]
