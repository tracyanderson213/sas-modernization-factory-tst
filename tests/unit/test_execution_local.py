from pathlib import Path

from smf.execution.models import ExecutionRequest
from smf.execution.providers.local import LocalExecutionProvider


def test_local_provider_executes_valid_python(tmp_path: Path) -> None:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "generated.py"
    generated.write_text('print("ok")\n', encoding="utf-8")

    result = LocalExecutionProvider().execute(
        ExecutionRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
        )
    )

    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"


def test_local_provider_reports_python_failure(tmp_path: Path) -> None:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "generated.py"
    generated.write_text('raise RuntimeError("boom")\n', encoding="utf-8")

    result = LocalExecutionProvider().execute(
        ExecutionRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
        )
    )

    assert result.status == "failed"
    assert result.exit_code != 0
    assert "RuntimeError" in result.stderr
