from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from smf.execution.engine import execute_validation
from smf.execution.models import ExecutionRequest
from smf.execution.schema import load_execution_schema
from smf.validation.models import ValidationCheck, ValidationResult


def test_execution_result_is_schema_valid(tmp_path: Path) -> None:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    generated = tmp_path / "generated.py"
    generated.write_text('print("ok")\n', encoding="utf-8")

    static_result = ValidationResult(
        source_file=str(source),
        generated_file=str(generated),
        target="pyspark",
        status="passed",
        confidence=1.0,
        requires_human_review=False,
        checks=[
            ValidationCheck(
                "TEST",
                "test",
                "pass",
                "ok",
            )
        ],
    )

    with patch(
        "smf.execution.engine.validate_conversion",
        return_value=static_result,
    ):
        result = execute_validation(
            ExecutionRequest(
                source_file=source,
                generated_file=generated,
                target="pyspark",
                provider="local",
                output_dir=tmp_path / "out",
            )
        )

    validator = Draft202012Validator(load_execution_schema())
    errors = list(validator.iter_errors(result.to_dict()))

    assert errors == []
    assert result.status == "succeeded"
    assert any(path.endswith("execution.manifest.json") for path in result.output_files)


def test_failed_state_changing_execution_cannot_repeat_or_overwrite_attempt(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    counter = tmp_path / "counter.txt"
    generated = tmp_path / "generated.py"
    generated.write_text(
        "from pathlib import Path\n"
        f"counter = Path({str(counter)!r})\n"
        "value = int(counter.read_text()) if counter.exists() else 0\n"
        "counter.write_text(str(value + 1))\n"
        "raise RuntimeError('failed after side effect')\n",
        encoding="utf-8",
    )
    static_result = ValidationResult(
        source_file=str(source),
        generated_file=str(generated),
        target="pyspark",
        status="passed",
        confidence=1.0,
        requires_human_review=False,
        checks=[ValidationCheck("TEST", "test", "pass", "ok")],
    )

    def request(attempt_id: str) -> ExecutionRequest:
        return ExecutionRequest(
            source_file=source,
            generated_file=generated,
            target="pyspark",
            provider="local",
            output_dir=tmp_path / "out",
            run_id="run-ops03",
            attempt_id=attempt_id,
        )

    with patch("smf.execution.engine.validate_conversion", return_value=static_result):
        first = execute_validation(request("attempt-1"))
        first_manifest = Path(first.output_files[-1])
        first_bytes = first_manifest.read_bytes()

        with pytest.raises(RuntimeError, match="already has canonical execution evidence"):
            execute_validation(request("attempt-1"))

        assert counter.read_text(encoding="utf-8") == "1"
        assert first_manifest.read_bytes() == first_bytes

        second = execute_validation(request("attempt-2"))

    second_manifest = Path(second.output_files[-1])
    assert counter.read_text(encoding="utf-8") == "2"
    assert second_manifest != first_manifest
    assert first_manifest.read_bytes() == first_bytes


def test_interrupted_execution_claim_blocks_unknown_outcome_retry(tmp_path: Path) -> None:
    source = tmp_path / "source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    generated = tmp_path / "generated.py"
    generated.write_text('print("side effect")\n', encoding="utf-8")
    request = ExecutionRequest(
        source_file=source,
        generated_file=generated,
        target="pyspark",
        provider="local",
        output_dir=tmp_path / "out",
        run_id="run-ops03",
        attempt_id="interrupted-1",
    )
    static_result = ValidationResult(
        source_file=str(source),
        generated_file=str(generated),
        target="pyspark",
        status="passed",
        confidence=1.0,
        requires_human_review=False,
        checks=[ValidationCheck("TEST", "test", "pass", "ok")],
    )
    calls = 0

    class InterruptedProvider:
        def execute(self, request: ExecutionRequest) -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("provider disconnected after possible side effect")

    with (
        patch("smf.execution.engine.validate_conversion", return_value=static_result),
        patch("smf.execution.engine._provider", return_value=InterruptedProvider()),
    ):
        with pytest.raises(RuntimeError, match="provider disconnected"):
            execute_validation(request)
        with pytest.raises(RuntimeError, match="outcome is unknown and retry is prohibited"):
            execute_validation(request)

    assert calls == 1
    claim = (
        tmp_path
        / "out/runs/run-ops03/workloads/source/attempts/interrupted-1/execution"
        / "execution.claim.json"
    )
    assert claim.exists()
    assert not claim.with_name("execution.manifest.json").exists()
