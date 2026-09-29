from __future__ import annotations

import hashlib
import json
import os
import socket
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path

import jsonschema
import pytest

import smf.ai_repair as repair_module
from smf.ai_gateway import GatewayPreflightRequest, MockGatewayScenario
from smf.ai_repair import (
    PreparedRepairResult,
    RepairControllerRequest,
    prepare_repair_result,
    publish_repair_result,
    recover_repair_result,
    telemetry_from_result,
    verify_repair_result,
)
from smf.conversion import ProviderPackageRequest, build_provider_package
from smf.conversion.providers.sas2databricks import QUALIFIED_VERSION
from smf.immutable_files import publish_json

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "tests" / "corpus" / "workloads" / "public" / "sas-code-examples"
GATEWAY_CONFIG = ROOT / "examples" / "ai-gateway-preflight.yaml"
RESULT_SCHEMA = ROOT / "schemas" / "ai-repair-result.schema.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_provider() -> None:
    installed = version("sas2databricks")
    if installed != QUALIFIED_VERSION:
        if os.environ.get("SMF_REQUIRE_AIREP01") == "1":
            pytest.fail(f"AIREP-01 requires sas2databricks {QUALIFIED_VERSION}, found {installed}")
        pytest.skip("AIREP-01 qualified deterministic provider is unavailable")


def _request(
    tmp_path: Path,
    source: Path,
    *,
    workload_id: str = "claims",
    run_id: str = "airep-run",
    attempt_id: str = "attempt-1",
    source_root: Path = ROOT,
    scenarios: tuple[MockGatewayScenario, ...] = (),
    max_attempts: int = 2,
) -> RepairControllerRequest:
    output = tmp_path / "out"
    provenance_root = tmp_path / "provenance"
    provenance_root.mkdir(parents=True, exist_ok=True)
    provenance_file = provenance_root / "source.json"
    provenance_file.write_text(
        json.dumps(
            {
                "evidence_id": "sas-code-examples-579e057f",
                "artifact_id": f"{source.stem}-sas",
                "artifact_sha256": _sha256(source),
                "origin": "https://github.com/sassoftware/sas-code-examples",
                "revision": "579e057f90cd699f744fd6a1c8acaf9243f7ff67",
                "license": "Apache-2.0",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    deterministic = ProviderPackageRequest(
        source_file=source,
        source_root=source_root,
        output_root=output,
        client_id="humana",
        deployment_id="humana-competition-pilot",
        environment_id="humana-databricks-pilot",
        workload_id=workload_id,
        source_artifact_id=f"{source.stem}-sas",
        run_id=run_id,
        attempt_id=attempt_id,
        expected_source_sha256=_sha256(source),
        source_provenance_file=provenance_file,
        source_provenance_root=provenance_root,
        expected_source_provenance_sha256=_sha256(provenance_file),
    )
    manifest = build_provider_package(deterministic)
    gateway = GatewayPreflightRequest(
        factory_config_path=ROOT / "deployments" / "humana" / "factory.yaml",
        gateway_config_path=GATEWAY_CONFIG,
        output_root=output,
        run_id=run_id,
        attempt_id=attempt_id,
        workload_id=workload_id,
        evaluation_time="2026-09-20T12:00:00Z",
    )
    return RepairControllerRequest(
        deterministic_manifest_path=manifest,
        deterministic_request=deterministic,
        gateway_request=gateway,
        output_root=output,
        controller_attempt_id=attempt_id,
        max_gateway_attempts=max_attempts,
        synthetic_scenarios=scenarios,
    )


def test_deterministic_success_never_crosses_gateway_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_provider()
    request = _request(tmp_path, PUBLIC / "create-column-select.sas")

    def forbidden(_request: object) -> object:
        raise AssertionError("gateway preflight must not run after deterministic success")

    monkeypatch.setattr(repair_module, "evaluate_gateway_preflight", forbidden)
    prepared = prepare_repair_result(request)
    assert prepared.result["status"] == "deterministic_complete"
    assert prepared.result["gateway"] is None
    assert prepared.result["synthetic_exercises"] == []
    manifest_paths = {item["path"] for item in prepared.result["implementation_manifest"]}
    assert "smf/immutable_files.py" in manifest_paths
    assert prepared.result["claims"]["deterministic_conversion_selected"] is True
    assert not any(
        value
        for key, value in prepared.result["claims"].items()
        if key != "deterministic_conversion_selected"
    )


def test_explicit_deterministic_rejection_routes_only_to_bounded_synthetic_contract(
    tmp_path: Path,
) -> None:
    _require_provider()
    request = _request(
        tmp_path,
        PUBLIC / "by-groupformat.sas",
        scenarios=(MockGatewayScenario.THROTTLED, MockGatewayScenario.SUCCESS),
    )
    prepared = prepare_repair_result(request)
    result = prepared.result
    assert result["status"] == "blocked"
    assert result["deterministic"]["status"] == "review_required"
    assert result["terminal_disposition"] == "external_gateway_authority_required"
    assert [item["scenario"] for item in result["synthetic_exercises"]] == [
        "throttled",
        "success",
    ]
    assert all(item["provider_invoked"] is False for item in result["synthetic_exercises"])
    assert result["synthetic_exercises"][0]["previous_attempt_digest"] is None
    assert (
        result["synthetic_exercises"][1]["previous_attempt_digest"]
        == result["synthetic_exercises"][0]["attempt_digest"]
    )
    assert all(
        item["repair_artifact_state"] == "not_generated" and item["revalidation_state"] == "not_run"
        for item in result["synthetic_exercises"]
    )
    assert not any(result["claims"].values())
    assert {item["code"] for item in result["blockers"]} >= {
        "deterministic_conversion_incomplete",
        "live_gateway_authority_missing",
    }

    result_path, telemetry_path = publish_repair_result(request, prepared)
    assert result_path.is_file() and telemetry_path.is_file()
    verify_repair_result(json.loads(result_path.read_text(encoding="utf-8")), request)
    assert publish_repair_result(request, prepared) == (result_path, telemetry_path)


def test_bounded_attempts_identity_roots_and_protected_values_fail_closed(tmp_path: Path) -> None:
    _require_provider()
    source = PUBLIC / "by-groupformat.sas"
    with pytest.raises(ValueError, match="between 1 and 3"):
        prepare_repair_result(_request(tmp_path / "zero", source, max_attempts=0))
    too_many = _request(
        tmp_path / "many",
        source,
        max_attempts=1,
        scenarios=(MockGatewayScenario.THROTTLED, MockGatewayScenario.SUCCESS),
    )
    with pytest.raises(ValueError, match="exceed"):
        prepare_repair_result(too_many)

    mismatch = _request(tmp_path / "mismatch", source)
    mismatch = replace(
        mismatch,
        gateway_request=replace(mismatch.gateway_request, workload_id="other-workload"),
    )
    with pytest.raises(ValueError, match="identities differ"):
        prepare_repair_result(mismatch)

    different_root = _request(tmp_path / "root", source)
    different_root = replace(different_root, output_root=tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="evidence root differs"):
        prepare_repair_result(different_root)

    canary = "api-key-secret-canary"
    with pytest.raises(ValueError) as caught:
        _request(tmp_path / "protected", source, workload_id=canary)
    assert canary not in str(caught.value)


def test_nonretryable_or_uncertain_synthetic_outcome_stops_attempt_chain(tmp_path: Path) -> None:
    _require_provider()
    source = PUBLIC / "by-groupformat.sas"
    for scenario in (
        MockGatewayScenario.SUCCESS,
        MockGatewayScenario.AUTHENTICATION_DENIED,
        MockGatewayScenario.CONTENT_FILTERED,
        MockGatewayScenario.UNCERTAIN_TIMEOUT,
    ):
        request = _request(
            tmp_path / scenario.value,
            source,
            scenarios=(scenario, MockGatewayScenario.THROTTLED),
        )
        prepared = prepare_repair_result(request)
        assert len(prepared.result["synthetic_exercises"]) == 1
        assert prepared.result["claims"]["repair_generated"] is False
        assert prepared.result["claims"]["validated"] is False


def test_replay_mutation_isolation_and_schema_strictness(tmp_path: Path) -> None:
    _require_provider()
    copied_root = tmp_path / "source"
    copied_root.mkdir()
    copied = copied_root / "program.sas"
    copied.write_bytes((PUBLIC / "by-groupformat.sas").read_bytes())
    request = _request(
        tmp_path,
        copied,
        source_root=copied_root,
        scenarios=(MockGatewayScenario.CONTENT_FILTERED,),
    )
    prepared = prepare_repair_result(request)
    forged = json.loads(json.dumps(prepared.result))
    forged["claims"]["repair_generated"] = True
    with pytest.raises(ValueError, match="schema|digest"):
        verify_repair_result(forged, request)

    monkeypatch_manifest = list(prepared.result["implementation_manifest"])
    monkeypatch_manifest[3] = {**monkeypatch_manifest[3], "sha256": "f" * 64}
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(repair_module, "_implementation_manifest", lambda: monkeypatch_manifest)
        with pytest.raises(ValueError, match="implementation manifest"):
            verify_repair_result(prepared.result, request)

    copied.write_text("data changed; run;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        verify_repair_result(prepared.result, request)

    first = _request(tmp_path / "first", PUBLIC / "by-groupformat.sas", workload_id="first")
    second = _request(tmp_path / "second", PUBLIC / "by-groupformat.sas", workload_id="second")
    assert (
        prepare_repair_result(first).result["result_id"]
        != prepare_repair_result(second).result["result_id"]
    )

    schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
    unknown = json.loads(json.dumps(prepare_repair_result(first).result))
    unknown["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(unknown)

    nested = json.loads(json.dumps(prepare_repair_result(first).result))
    nested["deterministic"]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(nested)

    telemetry_schema = json.loads(
        (ROOT / "schemas" / "ai-repair-telemetry.schema.json").read_text(encoding="utf-8")
    )
    invalid_telemetry = telemetry_from_result(prepare_repair_result(first).result)
    invalid_telemetry["claims"]["repair_generated"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(telemetry_schema).validate(invalid_telemetry)


def test_missing_telemetry_can_be_recovered_after_current_input_replay(tmp_path: Path) -> None:
    _require_provider()
    request = _request(tmp_path, PUBLIC / "by-groupformat.sas")
    prepared = prepare_repair_result(request)
    root = request.output_root
    result_path = root / prepared.result["canonical_evidence_reference"]
    publish_json(result_path, prepared.result, "AIREP-01 result", root=root)
    assert recover_repair_result(request) == PreparedRepairResult(
        prepared.result, telemetry_from_result(prepared.result)
    )


def test_offline_controller_never_opens_network_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_provider()
    request = _request(tmp_path, PUBLIC / "by-groupformat.sas")

    def forbidden_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("AIREP-01 must remain offline")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    assert prepare_repair_result(request).result["status"] == "blocked"


def test_public_and_packaged_schemas_are_identical() -> None:
    for name in ("ai-repair-result.schema.json", "ai-repair-telemetry.schema.json"):
        assert (ROOT / "schemas" / name).read_bytes() == (
            ROOT / "src" / "smf" / "schemas" / name
        ).read_bytes()
