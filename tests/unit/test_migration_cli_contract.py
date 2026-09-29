from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from smf.migration_contract import (
    MigrationCommand,
    MigrationContractRequest,
    evaluate_migration_contract,
    publish_result,
    recover_missing_telemetry,
    verify_result,
)
from smf.migration_contract.schema import validate_schema

ROOT = Path(__file__).resolve().parents[2]


def _source_request(tmp_path: Path, *, command: MigrationCommand = MigrationCommand.CONVERT):
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.sas").write_text("data work.out; set work.in; run;\n", encoding="utf-8")
    workload = tmp_path / "workload.yaml"
    workload.write_text(
        "workloads:\n  - workload_id: claims\n    entry_points:\n"
        "      - entry_point_id: main\n        path: main.sas\n        type: sas_program\n",
        encoding="utf-8",
    )
    deployment = tmp_path / "deployment"
    shutil.copytree(ROOT / "deployments/humana", deployment)
    roles = []
    for role in ("gateway_configuration", "asset_policy", "type_policy", "validation_policy"):
        policy = tmp_path / f"{role}.yaml"
        if role == "gateway_configuration":
            policy.write_text(
                "schema_version: '1.0'\nprovider: humana-ai-gateway\nmode: preflight\n",
                encoding="utf-8",
            )
        else:
            policy.write_text(f"schema_version: '1.0'\npolicy_id: {role}\n", encoding="utf-8")
        roles.append((role, policy))
    if command is MigrationCommand.MODERNIZE:
        modern = tmp_path / "modernization.yaml"
        modern.write_text("schema_version: '1.0'\npolicy_id: modernization\n", encoding="utf-8")
        roles.append(("modernization_policy", modern))
    return MigrationContractRequest(
        command=command,
        run_id="run-1",
        attempt_id="attempt-1",
        output_root=tmp_path / "out",
        workload_id="claims",
        source_root=source,
        workload_config=workload,
        factory_config=deployment / "factory.yaml",
        role_paths=tuple(roles),
    )


def test_convert_is_bound_and_always_non_authorizing(tmp_path: Path) -> None:
    prepared = evaluate_migration_contract(_source_request(tmp_path))
    result = prepared.result

    assert result["status"] == "blocked"
    assert result["backend_state"] == "not_implemented"
    assert not any(result["lifecycle"].values())
    assert result["identity"]["source_closure_digest"]
    assert result["identity"]["configuration_bundle_digest"]
    assert {item["code"] for item in result["blockers"]} == {
        "upstream_qualification_not_bound",
        "backend_not_implemented",
    }
    verify_result(result)


def test_identity_changes_across_source_environment_run_and_attempt(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    first = evaluate_migration_contract(request).result
    (request.source_root / "main.sas").write_text("data work.changed; run;\n", encoding="utf-8")
    changed_source = evaluate_migration_contract(request).result
    changed_run = evaluate_migration_contract(
        MigrationContractRequest(**{**request.__dict__, "run_id": "run-2"})
    ).result
    changed_attempt = evaluate_migration_contract(
        MigrationContractRequest(**{**request.__dict__, "attempt_id": "attempt-2"})
    ).result

    assert (
        len({item["decision_id"] for item in (first, changed_source, changed_run, changed_attempt)})
        == 4
    )


def test_literal_includes_are_bound_transitively_and_change_identity(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    (request.source_root / "main.sas").write_text(
        '%include "helper.sas";\ndata work.out; run;\n', encoding="utf-8"
    )
    (request.source_root / "helper.sas").write_text(
        "%include 'constants.sas';\n%let value=helper;\n", encoding="utf-8"
    )
    (request.source_root / "constants.sas").write_text("%let value=one;\n", encoding="utf-8")

    first = evaluate_migration_contract(request).result
    assert [item["path"] for item in first["source_snapshot"]["source_inventory"]] == [
        "constants.sas",
        "helper.sas",
        "main.sas",
    ]

    (request.source_root / "constants.sas").write_text("%let value=two;\n", encoding="utf-8")
    second = evaluate_migration_contract(request).result
    assert first["identity"]["source_closure_digest"] != second["identity"]["source_closure_digest"]
    assert first["decision_id"] != second["decision_id"]

    request.workload_config.write_text(
        "workloads:\n  - workload_id: claims\n    entry_points:\n"
        "      - entry_point_id: main\n        path: main.sas\n        type: sas_program\n"
        "    source_closure:\n      - main.sas\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="omits literal include dependency"):
        evaluate_migration_contract(request)


@pytest.mark.parametrize(
    "workload_text",
    [
        "workloads:\n  - workload_id: claims\n    entry_points: []\n",
        "workloads:\n  - workload_id: claims\n    entry_points:\n      - path: empty.sas\n",
        "workloads:\n  - workload_id: claims\n    entry_points:\n      - path: ../escape.sas\n",
        "workloads:\n"
        "  - workload_id: claims\n"
        "    entry_points:\n"
        "      - path: main.sas\n"
        "  - workload_id: CLAIMS\n"
        "    entry_points:\n"
        "      - path: main.sas\n",
    ],
)
def test_empty_escaping_and_duplicate_subjects_fail_closed(
    tmp_path: Path, workload_text: str
) -> None:
    request = _source_request(tmp_path)
    (request.source_root / "empty.sas").write_bytes(b"")
    request.workload_config.write_text(workload_text, encoding="utf-8")

    with pytest.raises(ValueError):
        evaluate_migration_contract(request)


def test_symlink_entry_point_fails_closed(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    (request.source_root / "linked.sas").symlink_to(request.source_root / "main.sas")
    request.workload_config.write_text(
        "workloads:\n  - workload_id: claims\n    entry_points:\n      - path: linked.sas\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="symlink"):
        evaluate_migration_contract(request)


def test_duplicate_yaml_key_and_caller_success_assertion_are_rejected(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    request.workload_config.write_text(
        "workloads:\n  - workload_id: claims\n    workload_id: claims\n"
        "    entry_points:\n      - path: main.sas\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate"):
        evaluate_migration_contract(request)

    with pytest.raises(ValueError, match="schema validation"):
        validate_schema(
            "migration-cli-request.schema.json",
            {
                "schema_version": "1.0",
                "command": "convert",
                "run_id": "run-1",
                "attempt_id": "attempt-1",
                "workload_id": "claims",
                "approved": True,
            },
        )


def test_publication_is_idempotent_and_recovers_only_missing_telemetry(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    prepared = evaluate_migration_contract(request)
    result_path, telemetry_path = publish_result(
        request.output_root, prepared.result, prepared.telemetry
    )
    first_result = result_path.read_bytes()
    first_telemetry = telemetry_path.read_bytes()
    telemetry_path.unlink()
    shutil.rmtree(request.source_root)
    request.workload_config.unlink()
    request.factory_config.parent.rename(tmp_path / "deployment-removed")

    recovered = recover_missing_telemetry(request)
    assert recovered is not None
    recovered_result, recovered_telemetry = publish_result(
        request.output_root, recovered.result, recovered.telemetry
    )

    assert recovered_result.read_bytes() == first_result
    assert recovered_telemetry.read_bytes() == first_telemetry
    result_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Conflicting immutable artifact"):
        publish_result(request.output_root, prepared.result, prepared.telemetry)


def test_invocation_recovery_uses_one_canonical_result_without_producer_inputs(
    tmp_path: Path,
) -> None:
    source_request = _source_request(tmp_path)
    gateway_path = dict(source_request.role_paths)["gateway_configuration"]
    request = MigrationContractRequest(
        command=MigrationCommand.AI_GATEWAY_PREFLIGHT,
        run_id="gateway-preflight",
        attempt_id=None,
        output_root=source_request.output_root,
        workload_id="claims",
        factory_config=source_request.factory_config,
        role_paths=(("gateway_configuration", gateway_path),),
    )
    prepared = evaluate_migration_contract(request)
    result_path, telemetry_path = publish_result(
        request.output_root, prepared.result, prepared.telemetry
    )
    expected_result = result_path.read_bytes()
    expected_telemetry = telemetry_path.read_bytes()
    telemetry_path.unlink()
    gateway_path.unlink()
    request.factory_config.parent.rename(tmp_path / "deployment-removed")

    recovered = recover_missing_telemetry(request)
    assert recovered is not None
    recovered_result, recovered_telemetry = publish_result(
        request.output_root, recovered.result, recovered.telemetry
    )
    assert recovered_result.read_bytes() == expected_result
    assert recovered_telemetry.read_bytes() == expected_telemetry


def test_invocation_recovery_rejects_ambiguous_canonical_results(tmp_path: Path) -> None:
    source_request = _source_request(tmp_path)
    gateway_path = dict(source_request.role_paths)["gateway_configuration"]
    request = MigrationContractRequest(
        command=MigrationCommand.AI_GATEWAY_PREFLIGHT,
        run_id="gateway-preflight",
        attempt_id=None,
        output_root=source_request.output_root,
        workload_id="claims",
        factory_config=source_request.factory_config,
        role_paths=(("gateway_configuration", gateway_path),),
    )
    first = evaluate_migration_contract(request)
    _, first_telemetry = publish_result(request.output_root, first.result, first.telemetry)
    gateway_path.write_text(
        "schema_version: '1.0'\nprovider: humana-ai-gateway\nmode: preflight\n# changed\n",
        encoding="utf-8",
    )
    second = evaluate_migration_contract(request)
    _, second_telemetry = publish_result(request.output_root, second.result, second.telemetry)
    first_telemetry.unlink()
    second_telemetry.unlink()

    with pytest.raises(ValueError, match="Multiple canonical results match"):
        recover_missing_telemetry(request)


def test_publication_rejects_symlinked_output_component(tmp_path: Path) -> None:
    request = _source_request(tmp_path)
    prepared = evaluate_migration_contract(request)
    outside = tmp_path / "outside"
    outside.mkdir()
    request.output_root.mkdir()
    (request.output_root / "runs").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        publish_result(request.output_root, prepared.result, prepared.telemetry)


def test_publication_fails_closed_on_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _source_request(tmp_path)
    prepared = evaluate_migration_contract(request)
    result_path = request.output_root / prepared.result["canonical_evidence_reference"]
    parent = result_path.parent
    displaced = tmp_path / "displaced-cli"
    outside = tmp_path / "outside-cli"
    outside.mkdir()
    real_link = os.link
    swapped = False

    def swap_parent_then_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal swapped
        if not swapped:
            parent.rename(displaced)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr("smf.immutable_files.os.link", swap_parent_then_link)

    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_result(request.output_root, prepared.result, prepared.telemetry)

    assert not (outside / "migration-cli.result.json").exists()
    assert not (outside / "migration-cli.telemetry.json").exists()


def test_run_ledger_state_is_missing_not_approved_or_denied(tmp_path: Path) -> None:
    prepared = evaluate_migration_contract(
        MigrationContractRequest(
            command=MigrationCommand.STATUS,
            run_id="run-1",
            attempt_id=None,
            output_root=tmp_path,
        )
    )
    assert prepared.result["identity"]["attempt_id"] is None
    assert prepared.telemetry["blocker_states"] == ["missing", "not_implemented"]
    assert prepared.result["lifecycle"]["human_approved"] is False
