from __future__ import annotations

import hashlib
import json
import os
import socket
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

import smf.deployment.environment_plan as environment_plan_module
from smf.deployment import (
    EnvironmentPlanRequest,
    evaluate_environment_plan,
    initialize_deployment_template,
    load_environment_plan_config,
    publish_environment_plan,
    recover_environment_plan,
    verify_environment_plan,
)


def _config(*, mode: str = "customer_validate", complete: bool = False) -> dict[str, Any]:
    state = "active" if complete else "pending"
    reference = "approved-ref" if complete else None
    probe = {
        "required": True,
        "timeout_seconds": 30,
        "max_retries": 1,
        "max_evidence_age_seconds": 3600,
        "write_scope": "none",
    }
    return {
        "schema_version": "1.0",
        "mode": mode,
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
            "secret_binding_references": ["opaque-binding-ref"] if complete else [],
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
            "policy_id": "offline-plan-policy",
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


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _request(tmp_path: Path, config: dict[str, Any]) -> EnvironmentPlanRequest:
    deployment = tmp_path / "deployment"
    initialize_deployment_template("humana", deployment)
    return EnvironmentPlanRequest(
        factory_config_path=deployment / "factory.yaml",
        environment_config_path=_write(deployment / "environment-plan.yaml", config),
        output_root=tmp_path / "out",
        run_id="run-1",
        attempt_id="attempt-1",
    )


def test_complete_customer_plan_is_deterministic_offline_and_claims_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_network(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"network access attempted: {args!r} {kwargs!r}")

    monkeypatch.setattr(socket, "socket", reject_network)
    request = _request(tmp_path, _config(complete=True))
    first = evaluate_environment_plan(request)
    second = evaluate_environment_plan(request)

    assert first == second
    assert first.result["status"] == "complete"
    assert first.result["blockers"] == []
    assert all(value is False for value in first.result["claims"].values())
    assert all(item["provider_operation"] is False for item in first.result["planned_probes"])
    identity = first.result["identity"]
    assert identity["factory_configuration_digest"]
    assert identity["factory_bundle_digest"]
    assert identity["environment_configuration_digest"]
    assert identity["implementation_manifest_digest"]
    assert {item["path"] for item in first.result["implementation_manifest"]} == {
        "smf/deployment/environment_plan.py",
        "smf/deployment/configuration.py",
        "smf/immutable_files.py",
        "smf/cli/main.py",
        "environment-plan-config.schema.json",
        "environment-plan-result.schema.json",
        "environment-plan-telemetry.schema.json",
    }
    assert first.result["canonical_evidence_reference"].startswith(
        "runs/run-1/environments/humana-databricks-pilot/plan-attempts/attempt-1/"
    )
    assert {item["disposition"] for item in first.result["planned_probes"]} == {
        "planned",
        "omitted",
    }
    verify_environment_plan(request, first.result)


def test_valid_pending_plan_is_blocked_and_has_deterministic_remediation(tmp_path: Path) -> None:
    prepared = evaluate_environment_plan(_request(tmp_path, _config()))

    assert prepared.result["status"] == "blocked"
    assert len(prepared.result["blockers"]) == 10
    assert {item["code"] for item in prepared.result["blockers"]} == {"required_reference_pending"}
    blocked = [
        item for item in prepared.result["planned_probes"] if item["disposition"] == "blocked"
    ]
    assert {item["remediation"] for item in blocked} == {"supply_reference"}


def test_contract_uses_exact_approved_schema_and_volume_names(tmp_path: Path) -> None:
    payload, _ = load_environment_plan_config(_request(tmp_path, _config()).environment_config_path)
    assert set(payload["unity_catalog"]["logical_schemas"]) == {
        "source",
        "discovery",
        "conversion",
        "validation",
        "evidence",
        "operations",
    }
    assert set(payload["volumes"]) == {
        "state",
        "landing",
        "artifact",
        "validation",
        "checkpoint",
    }
    assert set(payload["workspace"]) == {
        "state",
        "host_reference",
        "workspace_reference",
        "auth_context_reference",
        "auth_method",
        "principal_reference",
    }


@pytest.mark.parametrize(
    ("section", "alternative"),
    [
        ("logical_schemas", "control"),
        ("volumes", "staging"),
        ("workspace", "host"),
    ],
)
def test_alternative_topology_names_are_rejected(
    tmp_path: Path, section: str, alternative: str
) -> None:
    payload = _config()
    target = (
        payload["unity_catalog"]["logical_schemas"]
        if section == "logical_schemas"
        else payload[section]
    )
    target[alternative] = None
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_environment_plan(_request(tmp_path, payload))


def test_customer_mode_never_accepts_a_write_scope(tmp_path: Path) -> None:
    payload = _config(complete=True)
    payload["probe_policy"]["workspace"]["write_scope"] = "scoped_internal"
    result = evaluate_environment_plan(_request(tmp_path, payload)).result
    assert result["status"] == "blocked"
    assert result["blockers"] == [
        {"code": "customer_mode_write_scope_forbidden", "reference_id": "workspace"}
    ]
    assert result["claims"]["infrastructure_mutated"] is False


def test_customer_mode_can_plan_read_only_probes_without_contacting_provider(
    tmp_path: Path,
) -> None:
    payload = _config(complete=True)
    payload["probe_policy"]["workspace"]["write_scope"] = "read_only"
    result = evaluate_environment_plan(_request(tmp_path, payload)).result
    assert result["status"] == "complete"
    assert result["claims"]["provider_contacted"] is False


def test_internal_mode_can_describe_but_never_perform_scoped_internal_work(tmp_path: Path) -> None:
    payload = _config(mode="internal_provision", complete=True)
    payload["probe_policy"]["workspace"]["write_scope"] = "scoped_internal"
    result = evaluate_environment_plan(_request(tmp_path, payload)).result
    assert result["status"] == "complete"
    assert result["claims"]["provider_contacted"] is False
    assert result["claims"]["infrastructure_mutated"] is False


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda value: value.update({"unknown": True}), "schema validation"),
        (lambda value: value.update({"mode": "provision_customer"}), "schema validation"),
        (
            lambda value: value["ai_gateway"].update({"direct_provider_fallback": True}),
            "schema validation",
        ),
        (
            lambda value: value["workspace"].update({"workspace_reference": "client-secret-value"}),
            "credential marker",
        ),
        (
            lambda value: value["workspace"].update({"workspace_reference": "../escape"}),
            "schema validation",
        ),
        (
            lambda value: value["unity_catalog"]["logical_schemas"].pop("operations"),
            "schema validation",
        ),
        (
            lambda value: value["compute"].update(
                {
                    "selection": "existing",
                    "existing_compute_reference": "compute-ref",
                    "governed_request": {
                        "compute_policy_reference": "policy-ref",
                        "runtime_reference": "runtime-ref",
                        "node_type_reference": "node-ref",
                    },
                }
            ),
            "schema validation",
        ),
        (
            lambda value: value["workspace"].update(
                {"state": "active", "workspace_reference": None}
            ),
            "unresolved references",
        ),
    ],
)
def test_malformed_or_unsafe_configuration_fails_closed(
    tmp_path: Path, mutator: Any, message: str
) -> None:
    payload = _config()
    mutator(payload)
    with pytest.raises(ValueError, match=message):
        evaluate_environment_plan(_request(tmp_path, payload))


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: '1.0'\nschema_version: '1.0'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate environment-plan"):
        load_environment_plan_config(path)


def test_symlinked_configuration_is_rejected(tmp_path: Path) -> None:
    real = _write(tmp_path / "real.yaml", _config())
    link = tmp_path / "linked.yaml"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        load_environment_plan_config(link)


def test_immutable_publication_replays_and_detects_changed_input(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    result_path, telemetry_path = publish_environment_plan(request, prepared)
    assert result_path.is_file()
    assert telemetry_path.is_file()

    assert recover_environment_plan(request) is None
    publish_environment_plan(request, prepared)

    changed = _config()
    changed["probe_policy"]["policy_version"] = "1.1"
    _write(request.environment_config_path, changed)
    with pytest.raises(ValueError, match="does not match current governed inputs"):
        recover_environment_plan(request)


def test_missing_telemetry_is_recovered_from_canonical_result(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    result_path, telemetry_path = publish_environment_plan(request, prepared)
    telemetry_path.unlink()

    recovered = recover_environment_plan(request)
    assert recovered is not None
    assert recovered.result == json.loads(result_path.read_text(encoding="utf-8"))
    _, repaired = publish_environment_plan(request, recovered)
    assert repaired.is_file()


def test_result_and_telemetry_mutation_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    result_path, telemetry_path = publish_environment_plan(request, prepared)

    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["claims"]["environment_ready"] = True
    result_path.chmod(0o600)
    result_path.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation|digest mismatch"):
        recover_environment_plan(request)

    # Use an independent attempt to prove derived telemetry cannot be caller-mutated.
    request_two = EnvironmentPlanRequest(
        factory_config_path=request.factory_config_path,
        environment_config_path=request.environment_config_path,
        output_root=request.output_root,
        run_id="run-2",
        attempt_id="attempt-2",
    )
    _, telemetry_two = publish_environment_plan(request_two, evaluate_environment_plan(request_two))
    telemetry_two.chmod(0o600)
    telemetry_two.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="telemetry mutation"):
        recover_environment_plan(request_two)


def _recompute_content_digest(payload: dict[str, Any]) -> None:
    candidate = {**payload, "content_digest": ""}
    encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["content_digest"] = hashlib.sha256(encoded).hexdigest()


def test_self_consistent_blocked_to_complete_rewrite_cannot_replay(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    result_path, _ = publish_environment_plan(request, prepared)
    rewritten = json.loads(result_path.read_text(encoding="utf-8"))
    rewritten["blockers"] = []
    rewritten["status"] = "complete"
    rewritten["terminal_disposition"] = "complete"
    rewritten["retry"] = {
        "retryable": False,
        "recovery_count": 0,
        "recovery_source": None,
    }
    for probe in rewritten["planned_probes"]:
        probe["disposition"] = "planned"
        probe["remediation"] = "none"
    _recompute_content_digest(rewritten)
    with pytest.raises(ValueError, match="does not match current governed inputs"):
        verify_environment_plan(request, rewritten)
    result_path.chmod(0o600)
    result_path.write_text(json.dumps(rewritten), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match current governed inputs"):
        recover_environment_plan(request)


def test_changed_inputs_between_evaluation_and_publication_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    changed = _config()
    changed["probe_policy"]["policy_version"] = "1.1"
    _write(request.environment_config_path, changed)
    with pytest.raises(ValueError, match="inputs changed after evaluation"):
        publish_environment_plan(request, prepared)


def test_public_evaluator_post_return_mutation_cannot_reach_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, _config())
    original = environment_plan_module.evaluate_environment_plan

    def evaluate_then_mutate(
        supplied: EnvironmentPlanRequest,
    ) -> environment_plan_module.PreparedEnvironmentPlan:
        prepared = original(supplied)
        changed = _config()
        changed["probe_policy"]["policy_version"] = "1.1"
        _write(supplied.environment_config_path, changed)
        return prepared

    monkeypatch.setattr(environment_plan_module, "evaluate_environment_plan", evaluate_then_mutate)
    stale = environment_plan_module.evaluate_environment_plan(request)
    with pytest.raises(ValueError, match="inputs changed after evaluation"):
        publish_environment_plan(request, stale)
    assert not request.output_root.exists()


def test_post_promotion_input_mutation_quarantines_canonical_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    canonical_result = request.output_root / prepared.result["canonical_evidence_reference"]
    canonical_directory = canonical_result.parent
    original = environment_plan_module._evaluate_environment_plan_current
    mutated = False

    def evaluate_and_mutate_after_promotion(
        supplied: EnvironmentPlanRequest,
    ) -> environment_plan_module.PreparedEnvironmentPlan:
        nonlocal mutated
        result = original(supplied)
        if canonical_directory.exists() and not mutated:
            changed = _config()
            changed["probe_policy"]["policy_version"] = "1.1"
            _write(supplied.environment_config_path, changed)
            mutated = True
        return result

    monkeypatch.setattr(
        environment_plan_module,
        "_evaluate_environment_plan_current",
        evaluate_and_mutate_after_promotion,
    )
    with pytest.raises(ValueError, match="inputs changed after attempt promotion"):
        publish_environment_plan(request, prepared)
    assert mutated is True
    assert not canonical_result.exists()
    assert not canonical_result.with_name("environment-plan.telemetry.json").exists()
    assert not canonical_directory.exists()
    rejected = list(canonical_directory.parent.glob(".rejected-attempt-1-*"))
    assert len(rejected) == 1
    assert (rejected[0] / "environment-plan.result.json").is_file()
    assert (rejected[0] / "environment-plan.telemetry.json").is_file()


def test_post_promotion_extra_artifact_quarantines_entire_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    canonical_result = request.output_root / prepared.result["canonical_evidence_reference"]
    canonical_directory = canonical_result.parent
    original = environment_plan_module._evaluate_environment_plan_current
    injected = False

    def evaluate_and_inject_after_promotion(
        supplied: EnvironmentPlanRequest,
    ) -> environment_plan_module.PreparedEnvironmentPlan:
        nonlocal injected
        result = original(supplied)
        if canonical_directory.exists() and not injected:
            (canonical_directory / "unexpected.json").write_text("{}\n", encoding="utf-8")
            injected = True
        return result

    monkeypatch.setattr(
        environment_plan_module,
        "_evaluate_environment_plan_current",
        evaluate_and_inject_after_promotion,
    )
    with pytest.raises(ValueError, match="extra artifacts"):
        publish_environment_plan(request, prepared)
    assert injected is True
    assert not canonical_directory.exists()
    assert not canonical_result.exists()
    assert not canonical_result.with_name("environment-plan.telemetry.json").exists()
    rejected = list(canonical_directory.parent.glob(".rejected-attempt-1-*"))
    assert len(rejected) == 1
    assert (rejected[0] / "environment-plan.result.json").is_file()
    assert (rejected[0] / "environment-plan.telemetry.json").is_file()
    assert (rejected[0] / "unexpected.json").is_file()


def test_atomic_promotion_never_replaces_concurrent_empty_canonical_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    canonical_result = request.output_root / prepared.result["canonical_evidence_reference"]
    canonical_directory = canonical_result.parent
    original = environment_plan_module._rename_directory_noreplace
    injected = False

    def inject_concurrent_directory(
        parent_descriptor: int, source_name: str, destination_name: str
    ) -> None:
        nonlocal injected
        canonical_directory.mkdir()
        injected = True
        original(parent_descriptor, source_name, destination_name)

    monkeypatch.setattr(
        environment_plan_module,
        "_rename_directory_noreplace",
        inject_concurrent_directory,
    )
    with pytest.raises(FileExistsError, match="Conflicting canonical"):
        publish_environment_plan(request, prepared)
    assert injected is True
    assert canonical_directory.is_dir()
    assert list(canonical_directory.iterdir()) == []
    assert not canonical_result.exists()
    assert not canonical_result.with_name("environment-plan.telemetry.json").exists()
    rejected = list(canonical_directory.parent.glob(".rejected-attempt-1-*"))
    assert len(rejected) == 1
    assert (rejected[0] / "environment-plan.result.json").is_file()
    assert (rejected[0] / "environment-plan.telemetry.json").is_file()


def test_post_rename_fsync_failure_quarantines_owned_canonical_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    canonical_result = request.output_root / prepared.result["canonical_evidence_reference"]
    canonical_directory = canonical_result.parent
    original_fsync = environment_plan_module.os.fsync
    raised = False

    def fail_first_fsync_after_rename(descriptor: int) -> None:
        nonlocal raised
        if canonical_directory.exists() and not raised:
            raised = True
            raise OSError("synthetic post-rename fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(environment_plan_module.os, "fsync", fail_first_fsync_after_rename)
    with pytest.raises(OSError, match="synthetic post-rename fsync failure"):
        publish_environment_plan(request, prepared)
    assert raised is True
    assert not canonical_directory.exists()
    assert not canonical_result.exists()
    assert not canonical_result.with_name("environment-plan.telemetry.json").exists()
    rejected = list(canonical_directory.parent.glob(".rejected-attempt-1-*"))
    assert len(rejected) == 1
    assert (rejected[0] / "environment-plan.result.json").is_file()
    assert (rejected[0] / "environment-plan.telemetry.json").is_file()


def test_atomic_promotion_fails_closed_on_unsupported_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "attempts"
    parent.mkdir()
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    monkeypatch.setattr(environment_plan_module.sys, "platform", "unsupported-os")
    try:
        with pytest.raises(RuntimeError, match="unsupported"):
            environment_plan_module._rename_directory_noreplace(
                descriptor, ".staging-attempt-1-test", "attempt-1"
            )
    finally:
        os.close(descriptor)


def test_partial_staging_is_quarantined_before_restart(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    prepared = evaluate_environment_plan(request)
    canonical_result = request.output_root / prepared.result["canonical_evidence_reference"]
    attempts_root = canonical_result.parent.parent
    stale = attempts_root / ".staging-attempt-1-interrupted"
    stale.mkdir(parents=True)
    (stale / "environment-plan.result.json").write_text("{}\n", encoding="utf-8")

    result_path, telemetry_path = publish_environment_plan(request, prepared)
    assert result_path.is_file()
    assert telemetry_path.is_file()
    assert not stale.exists()
    rejected = list(attempts_root.glob(".rejected-attempt-1-*"))
    assert len(rejected) == 1
    assert (rejected[0] / "environment-plan.result.json").is_file()


def test_static_probe_dependency_closure_mutation_is_rejected(tmp_path: Path) -> None:
    result = deepcopy(evaluate_environment_plan(_request(tmp_path, _config(complete=True))).result)
    catalog = next(item for item in result["planned_probes"] if item["reference_id"] == "catalog")
    catalog["dependencies"] = []
    _recompute_content_digest(result)
    with pytest.raises(ValueError, match="does not replay from governed policy"):
        verify_environment_plan(_request(tmp_path, _config(complete=True)), result)


def test_attempts_are_isolated_across_environments(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    publish_environment_plan(request, evaluate_environment_plan(request))
    changed = deepcopy(_config())
    changed["deployment_identity"]["environment_id"] = "other-environment"
    _write(request.environment_config_path, changed)
    with pytest.raises(ValueError, match="does not match the factory snapshot"):
        recover_environment_plan(request)


def test_factory_and_environment_configuration_must_share_a_directory(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    other = tmp_path / "other"
    other.mkdir()
    moved = _write(other / "environment-plan.yaml", _config())
    mismatched = EnvironmentPlanRequest(
        factory_config_path=request.factory_config_path,
        environment_config_path=moved,
        output_root=request.output_root,
        run_id=request.run_id,
        attempt_id=request.attempt_id,
    )
    with pytest.raises(ValueError, match="share an authorized directory"):
        evaluate_environment_plan(mismatched)


def test_factory_bundle_mutation_invalidates_existing_attempt(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    publish_environment_plan(request, evaluate_environment_plan(request))
    provider = request.factory_config_path.parent / "databricks.yaml"
    provider.write_text(
        provider.read_text(encoding="utf-8") + "\n# changed bytes\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="digest mismatch|mode or policy binding changed"):
        recover_environment_plan(request)


def test_output_root_symlink_boundary_is_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path, _config())
    outside = tmp_path / "outside"
    outside.mkdir()
    request.output_root.mkdir()
    (request.output_root / "runs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        publish_environment_plan(request, evaluate_environment_plan(request))
