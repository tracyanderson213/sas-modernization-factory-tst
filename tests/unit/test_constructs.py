from smf.assessment.constructs import detect_constructs


def test_detects_sql_constructs() -> None:
    source = """
    proc sql;
        create table work.summary as
        select region, sum(amount)
        from work.claims
        where paid = 1
        group by region;
    quit;
    """

    constructs = detect_constructs(source)

    assert "PROC SQL" in constructs
    assert "CREATE TABLE" in constructs
    assert "SELECT" in constructs
    assert "WHERE" in constructs
    assert "GROUP BY" in constructs
    assert "SUM" in constructs


def test_detects_advanced_proc() -> None:
    constructs = detect_constructs("proc logistic data=work.training; run;")
    assert "PROC LOGISTIC" in constructs
