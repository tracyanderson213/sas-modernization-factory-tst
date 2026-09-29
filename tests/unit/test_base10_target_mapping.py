from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import smf.target_mapping as target_mapping
from smf.target_mapping import (
    ResolutionEvidence,
    SemanticEvidence,
    TargetMappingRequest,
    TargetPackagingPolicy,
    TargetPolicyBinding,
    run_target_mapping,
)
from smf.upstream.crypto import digest_value

ROOT = Path(__file__).resolve().parents[2]
SHA_A = "a" * 64
SHA_B = "b" * 64


def _column() -> dict[str, Any]:
    return {
        "source_name": "value",
        "source_position": 0,
        "source_physical_type": "string",
        "target_name": "value",
        "target_physical_type": "string",
        "mapping_kind": "identity_underlying_value",
        "rename_rationale": None,
        "expected_format": None,
        "expected_informat": None,
        "expected_storage_width": 32,
        "format_disposition": "metadata_only_projection_blocked",
        "informat_disposition": "metadata_only_application_blocked",
        "encoding_disposition": "provider_decoded_unicode_to_utf8",
        "precision_disposition": "not_applicable",
        "length_disposition": "preserve_storage_width_no_truncation",
        "temporal_disposition": "not_temporal_observation",
        "missing_disposition": "ordinary_null_only_special_missing_blocked",
        "source_column_descriptor_digest": SHA_A,
        "underlying_value_authority": True,
        "formatted_projection_authority": False,
    }


def _request(**changes: Any) -> TargetMappingRequest:
    values: dict[str, Any] = {
        "client_id": "synthetic-client",
        "deployment_id": "synthetic-deployment",
        "environment_id": "synthetic-evaluation",
        "environment_class": "evaluation",
        "workload_id": "workload-1",
        "source_id": "source-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "artifact_id": "artifact-1",
        "evaluation_time": "2026-09-21T12:00:00Z",
    }
    values.update(changes)
    return TargetMappingRequest(**values)


def _policy(**changes: Any) -> TargetPackagingPolicy:
    values: dict[str, Any] = {
        "policy_id": "base10-synthetic-policy",
        "version": "1.0.0",
        "authority_scope": "offline-evaluation-contract",
        "issued_at": "2026-09-20T00:00:00Z",
        "valid_until": "2026-09-28T00:00:00Z",
        "table_format": "delta",
        "storage_mode": "managed",
        "storage_disposition": "environment_resolved_location_not_accessed",
        "schema_evolution_policy": "deny_implicit_evolution",
        "overwrite_policy": "deny",
        "collision_policy": "reject_casefold_qualified_name",
        "production_namespace_policy": "deny_without_external_authority",
        "target_bindings": (TargetPolicyBinding("target-1", "SOURCE.TABLE_ONE"),),
    }
    values.update(changes)
    return TargetPackagingPolicy(**values)


def _semantic(
    *, targets: list[dict[str, Any]] | None = None, state: str = "qualified_underlying_mapping"
) -> dict[str, Any]:
    default_target = {
        "target_dataset_id": "target-1",
        "target_dataset_version": "1.0.0",
        "target_namespace": "logical-evaluation",
        "transformation_id": "identity-underlying",
        "transformation_version": "1.0.0",
        "columns": [_column()],
        "target_descriptor_digest": digest_value([_column()]),
    }
    return {
        "request": {
            "client_id": "synthetic-client",
            "workload_id": "workload-1",
            "source_id": "source-1",
            "run_id": "run-1",
            "attempt_id": "attempt-1",
        },
        "state": state,
        "policy": {
            "issued_at": "2026-09-20T00:00:00Z",
            "valid_until": "2027-09-28T00:00:00Z",
        },
        "targets": targets or [default_target],
        "result_id": "BASE02-result",
        "content_digest": SHA_A,
        "policy_digest": SHA_B,
    }


def _resolution(
    *,
    target: str = "table_one",
    deployment_id: str = "synthetic-deployment",
    environment_id: str = "synthetic-evaluation",
    environment_class: str = "evaluation",
    access_mode: str = "write",
    evaluation_time: str = "2026-09-21T12:00:00Z",
) -> dict[str, Any]:
    return {
        "identity": {
            "client_id": "synthetic-client",
            "deployment_id": deployment_id,
            "environment_id": environment_id,
            "environment_class": environment_class,
            "workload_id": "workload-1",
            "source_id": "source-1",
            "run_id": "run-1",
            "attempt_id": "attempt-1",
            "artifact_id": "artifact-1",
            "access_mode": access_mode,
            "evaluation_time": evaluation_time,
        },
        "status": "resolved",
        "resolution": {
            "binding_id": f"binding-{target}",
            "binding_version": "1.0.0",
            "logical_dataset": "SOURCE.TABLE_ONE",
            "catalog": "smf_eval",
            "schema": "conversion",
            "table": target,
            "qualified_name": f"smf_eval.conversion.{target}",
            "environment_id": "synthetic-evaluation",
            "environment_class": environment_class,
            "namespace_source": "explicit_governed_binding",
            "authority_reference": "synthetic-owner-decision",
            "access_mode": access_mode,
        },
        "result_id": f"B03RES-{target}",
        "content_digest": SHA_B,
        "canonical_evidence_reference": (
            "runs/run-1/workloads/workload-1/target-resolution-attempts/"
            "attempt-1/target-resolution.result.json"
        ),
    }


def test_qualified_mapping_preserves_semantic_schema_and_resolved_namespace() -> None:
    result = target_mapping._evaluate_target_mapping(
        _request(), _policy(), _semantic(), {"target-1": _resolution()}
    )

    assert result["state"] == "qualified_offline_mapping"
    assert result["blockers"] == []
    assert result["targets"][0]["resolved_namespace"]["qualified_name"] == (
        "smf_eval.conversion.table_one"
    )
    assert result["targets"][0]["columns"] == _semantic()["targets"][0]["columns"]
    assert result["targets"][0]["target_state"] == "planned_not_executed"
    assert not any(result["claims"].values())


def test_policy_authority_and_unsupported_namespace_fail_closed() -> None:
    with pytest.raises(ValueError, match="widens"):
        replace(_policy(), overwrite_policy="allow").validate()
    stale = target_mapping._evaluate_target_mapping(
        _request(evaluation_time="2026-09-28T00:00:00Z"),
        _policy(),
        _semantic(),
        {"target-1": _resolution(evaluation_time="2026-09-28T00:00:00Z")},
    )
    assert stale["state"] == "blocked"
    assert stale["blockers"] == ["target_packaging_policy_not_current"]

    production = target_mapping._evaluate_target_mapping(
        _request(environment_id="synthetic-production", environment_class="production"),
        _policy(),
        _semantic(),
        {
            "target-1": _resolution(
                environment_id="synthetic-production", environment_class="production"
            )
        },
    )
    assert "production_namespace_requires_external_authority:target-1" in production["blockers"]

    upstream_blocked = target_mapping._evaluate_target_mapping(
        _request(),
        _policy(),
        _semantic(state="blocked"),
        {"target-1": _resolution()},
    )
    assert upstream_blocked["state"] == "blocked"
    assert upstream_blocked["targets"] == []
    assert upstream_blocked["blockers"] == ["semantic_mapping_not_qualified"]

    semantic_stale = _semantic()
    semantic_stale["policy"]["valid_until"] = _request().evaluation_time
    stale_authority = target_mapping._evaluate_target_mapping(
        _request(), _policy(), semantic_stale, {"target-1": _resolution()}
    )
    assert "semantic_mapping_authority_not_current" in stale_authority["blockers"]

    stale_snapshot = target_mapping._evaluate_target_mapping(
        _request(),
        _policy(),
        _semantic(),
        {"target-1": _resolution()},
        semantic_snapshot_current=False,
    )
    assert "semantic_snapshot_not_current" in stale_snapshot["blockers"]


def test_exact_inventory_identity_and_collision_guards() -> None:
    with pytest.raises(ValueError, match="inventory"):
        target_mapping._evaluate_target_mapping(_request(), _policy(), _semantic(), {})
    wrong = _resolution()
    wrong["identity"]["client_id"] = "other-client"
    with pytest.raises(ValueError, match="client_id"):
        target_mapping._evaluate_target_mapping(
            _request(), _policy(), _semantic(), {"target-1": wrong}
        )

    targets = [
        _semantic()["targets"][0],
        {**_semantic()["targets"][0], "target_dataset_id": "target-2"},
    ]
    collision = target_mapping._evaluate_target_mapping(
        _request(),
        _policy(
            target_bindings=(
                TargetPolicyBinding("target-1", "SOURCE.TABLE_ONE"),
                TargetPolicyBinding("target-2", "SOURCE.TABLE_TWO"),
            )
        ),
        _semantic(targets=targets),
        {"target-1": _resolution(), "target-2": _resolution()},
    )
    assert "qualified_target_collision:target-2" in collision["blockers"]

    with pytest.raises(ValueError, match="deployment_id"):
        target_mapping._evaluate_target_mapping(
            _request(),
            _policy(
                target_bindings=(
                    TargetPolicyBinding("target-1", "SOURCE.TABLE_ONE"),
                    TargetPolicyBinding("target-2", "SOURCE.TABLE_TWO"),
                )
            ),
            _semantic(targets=targets),
            {
                "target-1": _resolution(target="one"),
                "target-2": _resolution(target="two", deployment_id="other-deployment"),
            },
        )
    with pytest.raises(ValueError, match="environment_id"):
        target_mapping._evaluate_target_mapping(
            _request(),
            _policy(
                target_bindings=(
                    TargetPolicyBinding("target-1", "SOURCE.TABLE_ONE"),
                    TargetPolicyBinding("target-2", "SOURCE.TABLE_TWO"),
                )
            ),
            _semantic(targets=targets),
            {
                "target-1": _resolution(target="one"),
                "target-2": _resolution(target="two", environment_id="other-environment"),
            },
        )
    with pytest.raises(ValueError, match="environment_class"):
        target_mapping._evaluate_target_mapping(
            _request(),
            _policy(
                target_bindings=(
                    TargetPolicyBinding("target-1", "SOURCE.TABLE_ONE"),
                    TargetPolicyBinding("target-2", "SOURCE.TABLE_TWO"),
                )
            ),
            _semantic(targets=targets),
            {
                "target-1": _resolution(target="one"),
                "target-2": _resolution(target="two", environment_class="production"),
            },
        )


def test_full_decision_identity_schema_and_mutation_detection() -> None:
    result = target_mapping._evaluate_target_mapping(
        _request(), _policy(), _semantic(), {"target-1": _resolution()}
    )
    target_mapping._verify_internal(result)
    mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
        lambda value: value["targets"][0].update({"storage_mode": "external"}),
        lambda value: value["claims"].update({"target_exists": True}),
        lambda value: value["request"].update({"artifact_id": "artifact-2"}),
    )
    for mutation in mutations:
        changed = deepcopy(result)
        mutation(changed)
        with pytest.raises(ValueError):
            target_mapping._verify_internal(changed)


def test_atomic_publication_retry_cancellation_collision_and_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = target_mapping._evaluate_target_mapping(
        _request(), _policy(), _semantic(), {"target-1": _resolution()}
    )

    def reconstruct_first(
        _request_value: TargetMappingRequest,
        _policy_value: TargetPackagingPolicy,
        _semantic_value: SemanticEvidence,
        _resolution_values: tuple[ResolutionEvidence, ...],
    ) -> dict[str, Any]:
        return first

    monkeypatch.setattr(target_mapping, "_reconstruct", reconstruct_first)
    semantic = cast(SemanticEvidence, object())
    resolutions: tuple[ResolutionEvidence, ...] = ()
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                lambda _: run_target_mapping(
                    _request(), _policy(), semantic, resolutions, evidence_root=tmp_path
                ),
                range(2),
            )
        )
    assert outcomes[0].result_path == outcomes[1].result_path

    cancelled_request = _request(attempt_id="attempt-cancelled")
    with pytest.raises(InterruptedError):
        run_target_mapping(
            cancelled_request,
            _policy(),
            semantic,
            resolutions,
            evidence_root=tmp_path,
            cancel_check=lambda: True,
        )
    cancelled_path, _ = target_mapping._paths(tmp_path, cancelled_request)
    assert not cancelled_path.exists()

    isolated = target_mapping._evaluate_target_mapping(
        _request(workload_id="workload-2"),
        _policy(),
        {**_semantic(), "request": {**_semantic()["request"], "workload_id": "workload-2"}},
        {
            "target-1": {
                **_resolution(),
                "identity": {**_resolution()["identity"], "workload_id": "workload-2"},
            }
        },
    )

    def choose_reconstruction(
        selected_request: TargetMappingRequest,
        _policy_value: TargetPackagingPolicy,
        _semantic_value: SemanticEvidence,
        _resolution_values: tuple[ResolutionEvidence, ...],
    ) -> dict[str, Any]:
        return first if selected_request.workload_id == "workload-1" else isolated

    monkeypatch.setattr(target_mapping, "_reconstruct", choose_reconstruction)
    second = run_target_mapping(
        _request(workload_id="workload-2"),
        _policy(),
        semantic,
        resolutions,
        evidence_root=tmp_path,
    )
    assert second.result_path != outcomes[0].result_path

    existing = json.loads(outcomes[0].result_path.read_text())
    existing["state"] = "blocked"
    outcomes[0].result_path.write_text(json.dumps(existing), encoding="utf-8")
    with pytest.raises(ValueError):
        run_target_mapping(_request(), _policy(), semantic, resolutions, evidence_root=tmp_path)


def test_public_and_packaged_schema_bytes_are_identical() -> None:
    public = (ROOT / "schemas" / "target-mapping-result.schema.json").read_bytes()
    packaged = (ROOT / "src" / "smf" / "schemas" / "target-mapping-result.schema.json").read_bytes()
    assert public == packaged
