from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from smf.cli.main import build_parser

ROOT = Path(__file__).resolve().parents[2]
GATEWAY_CONFIG = (ROOT / "examples/ai-gateway-preflight.yaml").read_text(encoding="utf-8")


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "smf.cli.main", *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_exact_migration_parser_inventory() -> None:
    parser = build_parser()
    top = next(action for action in parser._actions if action.dest == "command")
    migrate = next(
        action for action in top.choices["migrate"]._actions if action.dest == "migrate_command"
    )
    exceptions = next(
        action
        for action in migrate.choices["exceptions"]._actions
        if action.dest == "exceptions_command"
    )
    gateway = next(
        action
        for action in top.choices["ai-gateway"]._actions
        if action.dest == "ai_gateway_command"
    )

    assert set(migrate.choices) == {
        "convert",
        "modernize",
        "status",
        "resume",
        "exceptions",
        "approve",
        "promote",
    }
    assert set(exceptions.choices) == {"list", "submit", "decide"}
    assert set(gateway.choices) == {"preflight"}


def test_every_run_level_handler_emits_json_blocked_evidence_and_exit_2(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.yaml"
    evidence.write_text("schema_version: '1.0'\nevidence_id: request-1\n", encoding="utf-8")
    commands = (
        ("status",),
        (
            "resume",
            "--from-checkpoint",
            "latest-safe",
            "--factory-config",
            "deployments/humana/factory.yaml",
        ),
        ("exceptions", "list"),
        ("exceptions", "submit", "--exception-file", str(evidence)),
        ("exceptions", "decide", "--decision-file", str(evidence)),
        ("approve", "--stage", "migration-completion", "--approval-file", str(evidence)),
        (
            "promote",
            "--target",
            "test-target",
            "--promotion-approval",
            str(evidence),
        ),
    )
    for index, command in enumerate(commands):
        completed = _run(
            "migrate", *command, "--run-id", f"run-{index}", "--out", str(tmp_path), "--json"
        )
        assert completed.returncode == 2, completed.stderr
        summary = json.loads(completed.stdout)
        assert summary["status"] == "blocked"
        assert summary["terminal_disposition"] == "not_implemented"
        assert not any(summary["lifecycle"].values())
        assert Path(summary["result_path"]).is_file()


def test_malformed_contract_enum_exits_1_and_publishes_nothing(tmp_path: Path) -> None:
    completed = _run(
        "migrate",
        "resume",
        "--run-id",
        "run-1",
        "--from-checkpoint",
        "last_sfae",
        "--factory-config",
        "deployments/humana/factory.yaml",
        "--out",
        str(tmp_path),
    )
    assert completed.returncode == 1
    assert not list(tmp_path.rglob("*.json"))


def test_published_convert_and_gateway_preflight_arguments(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.sas").write_text("data work.out; run;\n", encoding="utf-8")
    workload = tmp_path / "workload.yaml"
    workload.write_text(
        "workloads:\n  - workload_id: HUM-WL-001\n    entry_points:\n      - path: main.sas\n",
        encoding="utf-8",
    )
    policies = {}
    for name in ("gateway", "asset", "type", "validation"):
        path = tmp_path / f"{name}.yaml"
        if name == "gateway":
            path.write_text(GATEWAY_CONFIG, encoding="utf-8")
        else:
            path.write_text(f"schema_version: '1.0'\npolicy_id: {name}\n", encoding="utf-8")
        policies[name] = path
    migration_gateway = tmp_path / "migration-gateway.yaml"
    migration_gateway.write_text(
        "schema_version: '1.0'\nprovider: humana-ai-gateway\nmode: preflight\n",
        encoding="utf-8",
    )

    converted = _run(
        "migrate",
        "convert",
        "--source",
        str(source),
        "--factory-config",
        "deployments/humana/factory.yaml",
        "--gateway-config",
        str(migration_gateway),
        "--workload-config",
        str(workload),
        "--asset-policy",
        str(policies["asset"]),
        "--type-policy",
        str(policies["type"]),
        "--validation-policy",
        str(policies["validation"]),
        "--workload-id",
        "HUM-WL-001",
        "--run-id",
        "HUM-CONV-20260918-001",
        "--attempt-id",
        "1",
        "--out",
        str(tmp_path / "conversion-out"),
    )
    assert converted.returncode == 2, converted.stderr
    assert json.loads(converted.stdout)["lifecycle"]["executed"] is False

    gateway = _run(
        "ai-gateway",
        "preflight",
        "--config",
        str(policies["gateway"]),
        "--workload-id",
        "HUM-WL-001",
        "--evaluation-time",
        "2026-09-20T12:00:00Z",
        "--out",
        str(tmp_path / "gateway-out"),
        "--json",
    )
    assert gateway.returncode == 2, gateway.stderr
    assert json.loads(gateway.stdout)["claims"]["provider_invoked"] is False


def test_gateway_preflight_rejects_incompatible_or_ambiguous_configuration(
    tmp_path: Path,
) -> None:
    invalid_payloads = (
        "schema_version: '999'\nprovider: humana-ai-gateway\nmode: preflight\n",
        "schema_version: '1.0'\nprovider: definitely-not-supported\nmode: preflight\n",
        "schema_version: '1.0'\nprovider: humana-ai-gateway\nmode: allow_everything\n",
        "schema_version: '1.0'\nprovider: humana-ai-gateway\n",
        "schema_version: '1.0'\nprovider: humana-ai-gateway\nmode: preflight\nextra: true\n",
    )
    for index, payload in enumerate(invalid_payloads):
        config = tmp_path / f"invalid-gateway-{index}.yaml"
        output = tmp_path / f"out-{index}"
        config.write_text(payload, encoding="utf-8")
        completed = _run(
            "ai-gateway",
            "preflight",
            "--config",
            str(config),
            "--workload-id",
            "HUM-WL-001",
            "--evaluation-time",
            "2026-09-20T12:00:00Z",
            "--out",
            str(output),
            "--json",
        )
        assert completed.returncode == 1, completed.stdout
        assert not list(output.rglob("migration-cli.result.json"))


def test_gateway_retry_recovers_missing_telemetry_without_inputs(tmp_path: Path) -> None:
    config = tmp_path / "gateway.yaml"
    config.write_text(GATEWAY_CONFIG, encoding="utf-8")
    output = tmp_path / "out"
    arguments = (
        "ai-gateway",
        "preflight",
        "--config",
        str(config),
        "--workload-id",
        "HUM-WL-001",
        "--evaluation-time",
        "2026-09-20T12:00:00Z",
        "--out",
        str(output),
        "--json",
    )
    initial = _run(*arguments)
    assert initial.returncode == 2, initial.stderr
    telemetry_path = next(output.rglob("ai-gateway-preflight.telemetry.json"))
    expected_telemetry = telemetry_path.read_bytes()
    telemetry_path.unlink()
    retried = _run(*arguments)
    assert retried.returncode == 2, retried.stderr
    assert telemetry_path.read_bytes() == expected_telemetry

    telemetry_path.unlink()
    config.unlink()
    missing_input = _run(*arguments)
    assert missing_input.returncode == 1
    assert not telemetry_path.exists()


def test_gateway_retry_with_no_canonical_match_and_no_input_fails_closed(
    tmp_path: Path,
) -> None:
    output = tmp_path / "out"
    completed = _run(
        "ai-gateway",
        "preflight",
        "--config",
        str(tmp_path / "missing.yaml"),
        "--workload-id",
        "HUM-WL-001",
        "--evaluation-time",
        "2026-09-20T12:00:00Z",
        "--out",
        str(output),
        "--json",
    )
    assert completed.returncode == 1
    assert not list(output.rglob("migration-cli.result.json"))


def test_legacy_parser_error_semantics_are_unchanged() -> None:
    completed = _run("convert", "--not-a-real-option")
    assert completed.returncode == 2
