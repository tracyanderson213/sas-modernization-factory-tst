from pathlib import Path

from smf.execution.models import ExecutionRequest
from smf.execution.providers.databricks import DatabricksExecutionProvider


def test_databricks_provider_blocks_without_governed_authentication(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.delenv("DATABRICKS_TOKEN", raising=False)

    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    generated = tmp_path / "generated.py"
    generated.write_text("value = 1\n", encoding="utf-8")

    result = DatabricksExecutionProvider().execute(
        ExecutionRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            provider="databricks",
        )
    )

    assert result.status == "blocked"
    assert "Governed Databricks authentication" in result.stderr
    assert result.evidence["reason_code"] == "remote_submission_disabled"


def test_environment_credentials_cannot_manufacture_submission(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("DATABRICKS_HOST", "https://example.cloud.databricks.com")
    monkeypatch.setenv("DATABRICKS_TOKEN", "test-token")

    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    generated = tmp_path / "generated.py"
    generated.write_text("value = 1\n", encoding="utf-8")

    result = DatabricksExecutionProvider().execute(
        ExecutionRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            provider="databricks",
        )
    )

    assert result.status == "blocked"
    assert result.run_id is None
    assert result.evidence["remote_submission_enabled"] is False
    assert "test-token" not in str(result.to_dict())
