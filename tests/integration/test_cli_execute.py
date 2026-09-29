from argparse import Namespace
from unittest.mock import patch

from smf.cli.main import build_parser, run_execute
from smf.execution.models import ExecutionResult


def test_cli_parser_includes_execute() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "execute",
            "example.sas",
            "example.py",
            "--provider",
            "local",
        ]
    )

    assert args.command == "execute"
    assert args.provider == "local"


def test_json_execute_returns_nonzero_for_blocked_result(capsys) -> None:
    args = Namespace(
        source="example.sas",
        generated="example.py",
        target="pyspark",
        provider="databricks",
        out="out",
        timeout=120,
        allow_writes=False,
        json=True,
    )
    result = ExecutionResult(
        source_file="example.sas",
        generated_file="example.py",
        target="pyspark",
        provider="databricks",
        status="blocked",
        duration_seconds=0,
    )
    with patch("smf.cli.main.execute_validation", return_value=result):
        assert run_execute(args) == 1
    assert '"status": "blocked"' in capsys.readouterr().out
