from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest
import yaml

from smf.cli.main import build_parser
from smf.deployment import initialize_deployment_template


def _config(root: Path, *, complete: bool) -> tuple[Path, Path]:
    root.mkdir()
    factory = initialize_deployment_template("humana", root)[0]
    state = "active" if complete else "pending"
    reference = "approved-ref" if complete else None
    probe = {
        "required": True,
        "timeout_seconds": 30,
        "max_retries": 1,
        "max_evidence_age_seconds": 3600,
        "write_scope": "none",
    }
    payload = {
        "schema_version": "1.0",
        "mode": "customer_validate",
        "deployment_identity": {
            "client_id": "humana",
            "deployment_id": "humana-competition-pilot",
            "environment_id": "humana-databricks-pilot",
        },
        "workspace": {
            "state": state,
            "host_reference": reference,
            "workspace_reference": reference,
            "auth_context_reference": reference,
            "auth_method": "entra_workload_identity" if complete else "pending",
            "principal_reference": reference,
        },
        "unity_catalog": {
            "state": state,
            "catalog_reference": reference,
            "logical_schemas": {
                name: reference
                for name in (
                    "source",
                    "discovery",
                    "conversion",
                    "validation",
                    "evidence",
                    "operations",
                )
            },
        },
        "volumes": {
            "state": state,
            **{name: reference for name in ("landing", "artifact", "validation", "checkpoint")},
        },
        "compute": {
            "state": state,
            "selection": "existing" if complete else "pending",
            "existing_compute_reference": reference,
            "governed_request": None,
        },
        "git": {"state": "not_configured", "repository_reference": None},
        "vault": {
            "state": state,
            "provider": "hashicorp_vault",
            "origin_reference": reference,
            "vault_reference": reference,
            "namespace_reference": reference,
            "mount_reference": reference,
            "auth_method": "entra_workload_identity" if complete else "pending",
            "audience_reference": reference,
            "role_reference": reference,
            "secret_binding_references": ["binding-ref"] if complete else [],
        },
        "ai_gateway": {
            "state": state,
            "origin_reference": reference,
            "gateway_reference": reference,
            "configuration_reference": reference,
            "provider": "anthropic",
            "anthropic_route_reference": reference,
            "anthropic_model_reference": reference,
            "direct_provider_fallback": False,
        },
        "packages": {
            "state": state,
            "repository_reference": reference,
            "offline_bundle_reference": reference,
            "offline_wheel_reference": reference,
            "offline_jar_reference": reference,
            "offline_native_reference": reference,
        },
        "sources": {
            "sas_program_state": state,
            "sas_program_reference": reference,
            "sas7bdat_state": state,
            "sas7bdat_reference": reference,
            "source_system_state": state,
            "source_system_reference": reference,
        },
        "probe_policy": {
            "policy_id": "offline-policy",
            "policy_version": "1.0",
            **{
                name: ({**probe, "required": False} if name == "git" else dict(probe))
                for name in (
                    "workspace",
                    "catalog",
                    "volumes",
                    "compute",
                    "git",
                    "vault",
                    "ai_gateway",
                    "packages",
                    "sas_programs",
                    "sas7bdat",
                    "source_system",
                )
            },
        },
    }
    path = root / "environment-plan.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return factory, path


def _args(factory: Path, environment: Path, output: Path) -> list[str]:
    return [
        "deployment-config",
        "plan",
        "--config",
        str(factory),
        "--environment-config",
        str(environment),
        "--out",
        str(output),
        "--run-id",
        "run-1",
        "--attempt-id",
        "attempt-1",
        "--json",
    ]


def _run(arguments: list[str]) -> int:
    parsed = build_parser().parse_args(arguments)
    return parsed.func(parsed)


def test_plan_cli_exits_zero_only_for_complete_plan(tmp_path: Path, capsys: object) -> None:
    factory, config = _config(tmp_path / "complete", complete=True)
    assert _run(_args(factory, config, tmp_path / "out")) == 0
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["status"] == "complete"
    assert all(value is False for value in payload["claims"].values())


def test_plan_cli_exits_two_for_valid_blocked_plan(tmp_path: Path, capsys: object) -> None:
    factory, config = _config(tmp_path / "blocked", complete=False)
    assert _run(_args(factory, config, tmp_path / "out")) == 2
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert payload["status"] == "blocked"
    assert payload["blockers"]


def test_plan_cli_exits_one_for_malformed_input(tmp_path: Path, capsys: object) -> None:
    root = tmp_path / "malformed"
    root.mkdir()
    factory = initialize_deployment_template("humana", root)[0]
    config = root / "malformed.yaml"
    config.write_text("schema_version: [", encoding="utf-8")
    assert _run(_args(factory, config, tmp_path / "out")) == 1
    assert "ERROR:" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_plan_cli_usage_errors_exit_one() -> None:
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(["deployment-config", "plan"])
    assert caught.value.code == 1


def test_plan_cli_accepts_explicit_json_flag(tmp_path: Path) -> None:
    factory, config = _config(tmp_path / "json-flag", complete=False)
    parsed = build_parser().parse_args(_args(factory, config, tmp_path / "out"))
    assert parsed.json is True


def test_environment_plan_schemas_are_packaged_byte_for_byte() -> None:
    for name in (
        "environment-plan-config.schema.json",
        "environment-plan-result.schema.json",
        "environment-plan-telemetry.schema.json",
    ):
        assert (Path("schemas") / name).read_bytes() == files("smf.schemas").joinpath(
            name
        ).read_bytes()
