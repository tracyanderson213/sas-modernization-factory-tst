from pathlib import Path

from smf.validation.engine import validate_conversion
from smf.validation.models import ValidationRequest


def test_simple_valid_conversion_passes_or_warns(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text(
        """
        proc sql;
            create table work.summary as
            select customer_id, sum(amount) as total_amount
            from work.transactions
            group by customer_id;
        quit;
        """,
        encoding="utf-8",
    )

    generated = tmp_path / "simple.py"
    generated.write_text(
        'transactions = spark.table("work_transactions")\n'
        'summary = transactions.groupBy("customer_id").sum("amount")\n',
        encoding="utf-8",
    )

    result = validate_conversion(
        ValidationRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            output_dir=tmp_path / "out",
            minimum_confidence=0.70,
        )
    )

    assert result.status in {"passed", "warning"}
    assert result.requires_human_review is False
    assert result.confidence >= 0.70
    assert any(path.endswith("validation.manifest.json") for path in result.output_files)


def test_invalid_generated_code_fails(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "broken.py"
    generated.write_text("def broken(:\n", encoding="utf-8")

    result = validate_conversion(
        ValidationRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            output_dir=tmp_path / "out",
        )
    )

    assert result.status == "failed"
    assert result.requires_human_review is True


def test_advanced_sas_requires_human_review(tmp_path: Path) -> None:
    source = tmp_path / "advanced.sas"
    source.write_text(
        "proc logistic data=work.training; model outcome = age score; run;\n",
        encoding="utf-8",
    )

    generated = tmp_path / "advanced.py"
    generated.write_text("result = 1\n", encoding="utf-8")

    result = validate_conversion(
        ValidationRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            output_dir=tmp_path / "out",
            minimum_confidence=0.0,
        )
    )

    assert result.status == "human_review"
    assert result.requires_human_review is True


def test_missing_generated_file_raises(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    request = ValidationRequest(
        source_file=source,
        generated_file=tmp_path / "missing.py",
        target="pyspark",
    )

    try:
        validate_conversion(request)
    except FileNotFoundError:
        return

    raise AssertionError("Expected FileNotFoundError")
