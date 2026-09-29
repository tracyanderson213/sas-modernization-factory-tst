from smf.assessment.dependencies import extract_dependencies


def test_extracts_sql_input_and_output() -> None:
    source = """
    proc sql;
        create table work.output as
        select *
        from work.source s
        left join work.lookup l on s.id = l.id;
    quit;
    """

    dependencies = extract_dependencies(source)

    assert dependencies.outputs == ["work.output"]
    assert dependencies.inputs == ["work.lookup", "work.source"]


def test_extracts_includes_and_macros() -> None:
    source = """
    %include "shared/common.sas";

    %macro build_report();
    %mend;

    %other_macro();
    """

    dependencies = extract_dependencies(source)

    assert dependencies.includes == ["shared/common.sas"]
    assert dependencies.macros_defined == ["build_report"]
    assert dependencies.macros_invoked == ["other_macro"]
