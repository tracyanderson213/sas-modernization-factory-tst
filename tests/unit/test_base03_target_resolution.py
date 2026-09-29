from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from smf.immutable_files import publish_json
from smf.target_resolution import (
    PreparedTargetResolution,
    TargetResolutionRequest,
    evaluate_target_resolution,
    load_target_resolution_config,
    publish_target_resolution,
    recover_target_resolution,
    telemetry_from_result,
    verify_target_resolution,
)

ROOT = Path(__file__).resolve().parents[2]

CONFIG = """\
schema_version: "1.0"
policy_id: namespace-policy-eval
policy_version: "1.0.0"
deployment_identity:
  client_id: synthetic-client
  deployment_id: synthetic-deployment
  environment_id: synthetic-evaluation
environment_class: evaluation
implicit_default_behavior: deny
authority:
  state: active
  qualified_at: "2026-09-20T00:00:00Z"
  valid_until: "2026-09-28T00:00:00Z"
  authority_reference: synthetic-owner-decision
bindings:
  - binding_id: claims-target
    binding_version: "1.2.0"
    logical_dataset: CLAIMS.CLAIM_LINE
    environment_id: synthetic-evaluation
    environment_class: evaluation
    access_modes: [read, write]
    catalog: smf_eval
    schema: claims_validation
    table: claim_line
    namespace_source: explicit_governed_binding
    authority_reference: synthetic-binding-decision
"""


def _request(tmp_path: Path, config: str = CONFIG, **changes: Any) -> TargetResolutionRequest:
    tmp_path.mkdir(parents=True, exist_ok=True)
    config_path = tmp_path / "target-resolution.yaml"
    config_path.write_text(config, encoding="utf-8")
    values: dict[str, object] = {
        "config_root": tmp_path,
        "config_path": config_path,
        "output_root": tmp_path / "evidence",
        "client_id": "synthetic-client",
        "deployment_id": "synthetic-deployment",
        "environment_id": "synthetic-evaluation",
        "environment_class": "evaluation",
        "workload_id": "claims-workload",
        "source_id": "source-snapshot-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "artifact_id": "artifact-1",
        "logical_dataset": "CLAIMS.CLAIM_LINE",
        "access_mode": "write",
        "evaluation_time": "2026-09-21T00:00:00Z",
    }
    values.update(changes)
    return TargetResolutionRequest(**values)  # type: ignore[arg-type]


def test_explicit_environment_binding_resolves_and_publishes_immutable_evidence(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    prepared = evaluate_target_resolution(request)

    assert prepared.result["status"] == "resolved"
    assert prepared.result["resolution"] == {
        "binding_id": "claims-target",
        "binding_version": "1.2.0",
        "logical_dataset": "CLAIMS.CLAIM_LINE",
        "catalog": "smf_eval",
        "schema": "claims_validation",
        "table": "claim_line",
        "qualified_name": "smf_eval.claims_validation.claim_line",
        "environment_id": "synthetic-evaluation",
        "environment_class": "evaluation",
        "namespace_source": "explicit_governed_binding",
        "authority_reference": "synthetic-binding-decision",
        "access_mode": "write",
    }
    assert prepared.result["blockers"] == []
    assert not any(prepared.result["claims"].values())

    result_path, telemetry_path = publish_target_resolution(request, prepared)
    assert result_path.is_file() and telemetry_path.is_file()
    verify_target_resolution(json.loads(result_path.read_text(encoding="utf-8")))
    assert publish_target_resolution(request, prepared) == (result_path, telemetry_path)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"logical_dataset": "CLAIMS.MISSING"}, "logical_dataset_binding_missing"),
        ({"access_mode": "read"}, None),
    ],
)
def test_resolution_is_explicit_and_never_uses_an_implicit_default(
    tmp_path: Path, changes: dict[str, Any], expected: str | None
) -> None:
    request = _request(tmp_path, **changes)
    prepared = evaluate_target_resolution(request)
    if expected is None:
        assert prepared.result["status"] == "resolved"
    else:
        assert prepared.result["resolution"] is None
        assert expected in {item["code"] for item in prepared.result["blockers"]}


def test_pending_stale_and_denied_authority_remain_visible(tmp_path: Path) -> None:
    pending = _request(tmp_path, CONFIG.replace("state: active", "state: pending"))
    prepared = evaluate_target_resolution(pending)
    assert prepared.result["status"] == "blocked"
    assert {item["code"] for item in prepared.result["blockers"]} == {"namespace_authority_pending"}

    stale = _request(
        tmp_path,
        CONFIG,
        evaluation_time="2026-09-28T00:00:00Z",
        access_mode="read",
    )
    assert "namespace_authority_stale" in {
        item["code"] for item in evaluate_target_resolution(stale).result["blockers"]
    }

    denied = _request(tmp_path, CONFIG.replace("[read, write]", "[read]"))
    assert "target_access_mode_denied" in {
        item["code"] for item in evaluate_target_resolution(denied).result["blockers"]
    }


@pytest.mark.parametrize(
    ("changed", "match"),
    [
        (
            CONFIG + CONFIG.split("bindings:\n", 1)[1].replace("claims-target", "claims-two"),
            "schema|configuration",
        ),
        (
            CONFIG.replace("CLAIMS.CLAIM_LINE", "claims.claim_line") + "\n",
            "",
        ),
        (
            CONFIG.replace(
                "table: claim_line",
                "table: claim_line\n    unexpected: value",
            ),
            "schema",
        ),
        (
            CONFIG.replace("policy_id: namespace-policy-eval", "policy_id: secret-canary"),
            "Unsafe|protected",
        ),
        (
            CONFIG.replace(
                "implicit_default_behavior: deny",
                "implicit_default_behavior: deny\nimplicit_default_behavior: deny",
            ),
            "malformed",
        ),
        (
            CONFIG.replace("implicit_default_behavior: deny", "implicit_default_behavior: allow"),
            "schema",
        ),
    ],
)
def test_ambiguous_unknown_secret_or_duplicate_configuration_fails_closed(
    tmp_path: Path, changed: str, match: str
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(changed, encoding="utf-8")
    if not match:
        load_target_resolution_config(path)
    else:
        with pytest.raises(ValueError, match=match):
            load_target_resolution_config(path)


def test_case_collision_and_cross_environment_binding_are_rejected(tmp_path: Path) -> None:
    second = """
  - binding_id: claims-target-2
    binding_version: "1.0.0"
    logical_dataset: claims.claim_line
    environment_id: synthetic-evaluation
    environment_class: evaluation
    access_modes: [read]
    catalog: SMF_EVAL
    schema: CLAIMS_VALIDATION
    table: CLAIM_LINE
    namespace_source: explicit_governed_binding
    authority_reference: synthetic-binding-decision
"""
    path = tmp_path / "collision.yaml"
    path.write_text(CONFIG + second, encoding="utf-8")
    with pytest.raises(ValueError, match="case collision"):
        load_target_resolution_config(path)

    path.write_text(
        CONFIG.replace(
            "    environment_id: synthetic-evaluation",
            "    environment_id: another-environment",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="crosses environment identity"):
        load_target_resolution_config(path)


def test_request_identity_and_environment_isolation_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="client_id"):
        evaluate_target_resolution(_request(tmp_path, client_id="other-client"))
    with pytest.raises(ValueError, match="environment class"):
        evaluate_target_resolution(_request(tmp_path, environment_class="production"))
    with pytest.raises(ValueError, match="case_mismatch|current governed inputs"):
        prepared = evaluate_target_resolution(_request(tmp_path))
        changed = _request(tmp_path, logical_dataset="claims.claim_line")
        publish_target_resolution(changed, prepared)


def test_symlink_input_mutation_result_mutation_and_cross_workload_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _request(tmp_path)
    link = tmp_path / "linked.yaml"
    link.symlink_to(request.config_path)
    with pytest.raises(ValueError, match="symlink"):
        load_target_resolution_config(link)

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    real_config = real_root / "config.yaml"
    real_config.write_text(CONFIG, encoding="utf-8")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink|non-directory"):
        load_target_resolution_config(linked_root / "config.yaml", root=linked_root)

    original_read = os.read
    swapped = False

    def swap_after_read(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, count)
        if chunk and not swapped:
            swapped = True
            replacement = tmp_path / "replacement.yaml"
            replacement.write_text(CONFIG.replace("claims-target", "replacement"), encoding="utf-8")
            replacement.replace(request.config_path)
        return chunk

    monkeypatch.setattr(os, "read", swap_after_read)
    with pytest.raises(ValueError, match="changed while being acquired"):
        load_target_resolution_config(request.config_path, root=request.config_root)
    monkeypatch.setattr(os, "read", original_read)
    request.config_path.write_text(CONFIG, encoding="utf-8")

    prepared = evaluate_target_resolution(request)
    forged = json.loads(json.dumps(prepared.result))
    forged["resolution"]["table"] = "forged"
    with pytest.raises(ValueError, match="digest"):
        verify_target_resolution(forged)

    forged["content_digest"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in forged.items() if key != "content_digest"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="governed decision identity"):
        verify_target_resolution(forged)

    request.config_path.write_text(CONFIG.replace("claim_line", "claim_line_v2"), encoding="utf-8")
    with pytest.raises(ValueError, match="current governed inputs"):
        publish_target_resolution(request, prepared)

    other = _request(tmp_path / "other", workload_id="other-workload")
    assert (
        evaluate_target_resolution(other).result["canonical_evidence_reference"]
        != prepared.result["canonical_evidence_reference"]
    )


def test_concurrent_idempotence_and_telemetry_recovery(tmp_path: Path) -> None:
    request = _request(tmp_path)
    prepared = evaluate_target_resolution(request)
    with ThreadPoolExecutor(max_workers=2) as executor:
        paths = list(executor.map(lambda _: publish_target_resolution(request, prepared), range(2)))
    assert paths[0] == paths[1]

    recovery_request = _request(tmp_path / "recovery")
    recovery = evaluate_target_resolution(recovery_request)
    result_path = recovery_request.output_root / recovery.result["canonical_evidence_reference"]
    publish_json(
        result_path,
        recovery.result,
        "target-resolution result",
        root=recovery_request.output_root,
    )
    recovered = recover_target_resolution(recovery_request)
    assert recovered == PreparedTargetResolution(
        recovery.result, telemetry_from_result(recovery.result)
    )


@pytest.mark.parametrize(
    "name",
    [
        "target-resolution-config.schema.json",
        "target-resolution-result.schema.json",
        "target-resolution-telemetry.schema.json",
    ],
)
def test_public_and_packaged_target_resolution_schemas_are_identical(name: str) -> None:
    assert (ROOT / "schemas" / name).read_bytes() == (
        ROOT / "src" / "smf" / "schemas" / name
    ).read_bytes()
