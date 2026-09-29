import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from smf.cli.main import _conversion_exit_status, build_parser, run_convert


def test_parser_includes_convert_and_validate_commands() -> None:
    parser = build_parser()

    convert_args = parser.parse_args(["convert", "example.sas", "--target", "pyspark"])
    validate_args = parser.parse_args(
        ["validate", "example.sas", "example.py", "--target", "pyspark"]
    )

    assert convert_args.command == "convert"
    assert validate_args.command == "validate"


def test_convert_cli_handler_fails_closed_without_readiness(
    tmp_path: Path,
) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(
        [
            "convert",
            str(source),
            "--target",
            "pyspark",
            "--out",
            str(tmp_path / "out"),
        ]
    )

    with patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider:
        exit_code = run_convert(args)

    assert exit_code == 1
    provider.assert_not_called()
    assert not (tmp_path / "out").exists()


def test_conversion_exit_status_does_not_report_blockers_as_command_success() -> None:
    assert _conversion_exit_status("converted") == 0
    assert _conversion_exit_status("review_required") == 0
    assert _conversion_exit_status("unsupported") == 2
    assert _conversion_exit_status("blocked") == 2
    assert _conversion_exit_status("human_pending") == 2
    assert _conversion_exit_status("human_denied") == 2
    assert _conversion_exit_status("failed") == 1


def test_validate_cli_json(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "simple.py"
    generated.write_text("value = 1\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "validate",
            str(source),
            str(generated),
            "--target",
            "pyspark",
            "--out",
            str(tmp_path / "out"),
            "--minimum-confidence",
            "0.0",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0

    payload = json.loads(result.stdout)

    assert payload["target"] == "pyspark"
    assert payload["source_file"] == str(source)
    assert payload["generated_file"] == str(generated)
    assert "confidence" in payload
    assert "checks" in payload


def test_validate_cli_returns_error_for_bad_python(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    generated = tmp_path / "broken.py"
    generated.write_text("def broken(:\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "validate",
            str(source),
            str(generated),
            "--target",
            "pyspark",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Status:" in result.stdout
    assert "failed" in result.stdout
