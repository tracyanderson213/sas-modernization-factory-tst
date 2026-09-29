from pathlib import Path

from smf.assessment.analyzer import assess_sas_file


def test_simple_workload_produces_complete_assessment(tmp_path: Path) -> None:
    sas_file = tmp_path / "simple.sas"
    sas_file.write_text(
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

    result = assess_sas_file(str(sas_file))

    assert result["workload_id"].startswith("SMF-")
    assert result["complexity"] == "simple"
    assert result["automation_route"] == "deterministic"
    assert result["complexity_score"] > 0
    assert result["recommended_validation_level"] == 3
    assert result["dependencies"]["inputs"] == ["work.transactions"]
    assert result["dependencies"]["outputs"] == ["work.summary"]
    assert result["score_breakdown"]


def test_advanced_workload_routes_to_human(tmp_path: Path) -> None:
    sas_file = tmp_path / "advanced.sas"
    sas_file.write_text(
        """
        proc logistic data=work.training;
            model outcome = age score;
        run;
        """,
        encoding="utf-8",
    )

    result = assess_sas_file(str(sas_file))

    assert result["complexity"] == "highly_complex"
    assert result["automation_route"] == "human_supervised"
    assert result["recommended_validation_level"] == 5
    assert "PROC LOGISTIC" in result["unsupported_constructs"]


def test_missing_file_raises_file_not_found() -> None:
    missing = "tests/workloads/does-not-exist.sas"

    try:
        assess_sas_file(missing)
    except FileNotFoundError as exc:
        assert missing in str(exc)
    else:
        raise AssertionError("Expected FileNotFoundError")
