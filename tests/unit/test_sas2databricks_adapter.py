from smf.conversion.providers.sas2databricks import _parse_cli_output


def test_cli_summary_is_removed_from_generated_code() -> None:
    stdout = (
        "# Databricks notebook source\n"
        "value = 1\n"
        "model=opus-4.8 target=pyspark steps=1 review=1 llm_escalations=1\n"
    )

    content, metadata, warnings = _parse_cli_output(stdout)

    assert "model=opus-4.8" not in content
    assert content.endswith("value = 1\n")
    assert metadata["model"] == "opus-4.8"
    assert metadata["review"] == 1
    assert metadata["llm_escalations"] == 1
    assert warnings
