from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from smf.ai_gateway import (
    DeterministicMockGatewayTransport,
    GatewayPreflightRequest,
    MockGatewayScenario,
    evaluate_gateway_preflight,
    evaluate_synthetic_probe,
    load_gateway_config,
    publish_gateway_preflight,
    verify_gateway_result,
)

ROOT = Path(__file__).resolve().parents[2]
GATEWAY_CONFIG = (ROOT / "examples/ai-gateway-preflight.yaml").read_text(encoding="utf-8")


def _request(tmp_path: Path, text: str = GATEWAY_CONFIG) -> GatewayPreflightRequest:
    deployment = tmp_path / "deployment"
    shutil.copytree(ROOT / "deployments/humana", deployment)
    config = tmp_path / "gateway.yaml"
    config.write_text(text, encoding="utf-8")
    return GatewayPreflightRequest(
        factory_config_path=deployment / "factory.yaml",
        gateway_config_path=config,
        output_root=tmp_path / "out",
        run_id="run-1",
        attempt_id="attempt-1",
        workload_id="claims",
        evaluation_time="2026-09-20T12:00:00Z",
    )


def test_offline_preflight_binds_configuration_and_makes_no_operational_claim(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    prepared = evaluate_gateway_preflight(request)
    assert prepared.result["status"] == "blocked"
    assert prepared.result["terminal_disposition"] == "external_authority_required"
    assert not any(prepared.result["claims"].values())
    assert {item["code"] for item in prepared.result["blockers"]} == {
        "live_gateway_authority_missing",
        "gateway_configuration_pending",
        "configuration_authority_pending",
    }
    result_path, telemetry_path = publish_gateway_preflight(request, prepared)
    assert result_path.is_file() and telemetry_path.is_file()
    verify_gateway_result(json.loads(result_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("scenario", list(MockGatewayScenario))
def test_mock_scenarios_are_synthetic_and_never_claim_provider_invocation(
    scenario: MockGatewayScenario,
) -> None:
    outcome = evaluate_synthetic_probe(DeterministicMockGatewayTransport(scenario))
    assert outcome.evidence_class == "synthetic_contract"
    assert outcome.provider_invoked is False
    if scenario is MockGatewayScenario.UNCERTAIN_TIMEOUT:
        assert outcome.outcome_certain is False
        assert outcome.retryable is False


def test_arbitrary_transport_cannot_cross_offline_boundary() -> None:
    class HostileTransport:
        evidence_class = "operational_verified"

        def probe(self):
            raise AssertionError("must not be called")

    with pytest.raises(ValueError, match="Operational"):
        evaluate_synthetic_probe(HostileTransport())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changed,match",
    [
        (GATEWAY_CONFIG.replace("gateway.example.invalid", "api.anthropic.com"), "Direct"),
        (GATEWAY_CONFIG.replace("gateway.example.invalid", "api.anthropic.com."), "Direct"),
        (GATEWAY_CONFIG.replace("gateway.example.invalid", "api.openai.com."), "Direct"),
        (
            GATEWAY_CONFIG.replace("gateway.example.invalid", "customer.openai.azure.com."),
            "Direct",
        ),
        (GATEWAY_CONFIG + "api_key: sk-secret-canary\n", "credential field|schema"),
        (
            GATEWAY_CONFIG.replace("mode: preflight", "mode: preflight\nmode: preflight"),
            "Duplicate",
        ),
        (
            GATEWAY_CONFIG.replace(
                "https://gateway.example.invalid", "http://gateway.example.invalid"
            ),
            "HTTPS",
        ),
        (GATEWAY_CONFIG.replace("persist_prompt: false", "persist_prompt: true"), "schema"),
        (
            GATEWAY_CONFIG.replace(
                'valid_until: "2026-09-27T23:59:59Z"',
                'valid_until: "2026-09-19T23:59:59Z"',
            ),
            "stale",
        ),
    ],
)
def test_unsafe_ambiguous_or_direct_provider_configuration_fails_closed(
    tmp_path: Path, changed: str, match: str
) -> None:
    request = _request(tmp_path, changed)
    with pytest.raises(ValueError, match=match):
        load_gateway_config(request.gateway_config_path)


def test_symlink_and_mutated_result_are_rejected(tmp_path: Path) -> None:
    request = _request(tmp_path)
    link = tmp_path / "linked.yaml"
    link.symlink_to(request.gateway_config_path)
    with pytest.raises(ValueError, match="symlink"):
        load_gateway_config(link)

    prepared = evaluate_gateway_preflight(request)
    prepared.result["identity"]["workload_id"] = "other"
    with pytest.raises(ValueError, match="identity|digest"):
        verify_gateway_result(prepared.result)


def test_publication_replays_current_inputs_and_rejects_forged_or_missing_input(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    prepared = evaluate_gateway_preflight(request)
    forged = json.loads(json.dumps(prepared.result))
    forged["configuration"]["gateway"]["route"] = "/forged"
    forged["content_digest"] = "0" * 64
    forged["content_digest"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in forged.items() if key != "content_digest"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    forged_prepared = type(prepared)(forged, prepared.telemetry)
    with pytest.raises(ValueError, match="current qualified inputs"):
        publish_gateway_preflight(request, forged_prepared)

    request.gateway_config_path.unlink()
    with pytest.raises(ValueError, match="missing or unsafe"):
        publish_gateway_preflight(request, prepared)


def test_evaluation_time_is_bound_and_expired_or_mutated_time_fails_closed(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    prepared = evaluate_gateway_preflight(request)
    assert prepared.result["identity"]["evaluation_time"] == "2026-09-20T12:00:00+00:00"

    expired = GatewayPreflightRequest(
        **{**request.__dict__, "evaluation_time": "2026-09-28T00:00:00Z"}
    )
    with pytest.raises(ValueError, match="stale at evaluation_time"):
        evaluate_gateway_preflight(expired)

    changed_time = GatewayPreflightRequest(
        **{**request.__dict__, "evaluation_time": "2026-09-21T12:00:00Z"}
    )
    with pytest.raises(ValueError, match="current qualified inputs"):
        publish_gateway_preflight(changed_time, prepared)


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-20 12:00:00+00:00",
        "2026-09-20",
        "2026-W38-7T12:00:00Z",
        "20260920T120000Z",
        "2026-09-20t12:00:00z",
        "2026-09-20T12:00Z",
        "2026-09-20T12:00:00",
    ],
)
def test_evaluation_time_rejects_noncanonical_or_non_rfc3339_forms(
    tmp_path: Path, value: str
) -> None:
    request = _request(tmp_path)
    invalid = GatewayPreflightRequest(**{**request.__dict__, "evaluation_time": value})
    with pytest.raises(ValueError, match="canonical RFC 3339"):
        evaluate_gateway_preflight(invalid)


@pytest.mark.parametrize(
    "name",
    [
        "ai-gateway-config.schema.json",
        "ai-gateway-preflight-result.schema.json",
        "ai-gateway-preflight-telemetry.schema.json",
    ],
)
def test_public_and_packaged_gateway_schemas_are_byte_identical(name: str) -> None:
    assert (ROOT / "schemas" / name).read_bytes() == (
        ROOT / "src" / "smf" / "schemas" / name
    ).read_bytes()
