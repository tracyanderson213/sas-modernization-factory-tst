from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import smf.unity_catalog_validation as uc
from smf.immutable_files import publish_json
from smf.restartable_ingestion import (
    RestartableIngestionConfig,
    RestartableIngestionRequest,
    _claims,
)
from smf.target_mapping import (
    TargetMappingRequest,
    TargetPackagingPolicy,
    TargetPolicyBinding,
    _evaluate_target_mapping,
)
from smf.unity_catalog_validation import (
    CurrentIngestionEvidence,
    CurrentTargetMappingEvidence,
    UnityCatalogValidationPolicy,
    UnityCatalogValidationRequest,
    evaluate_unity_catalog_validation,
    publish_unity_catalog_validation,
    verify_unity_catalog_validation,
    verify_unity_catalog_validation_against_inputs,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

SHA_A = "a" * 64
SHA_B = "b" * 64


def _target_mapping() -> dict[str, object]:
    request = TargetMappingRequest(
        "client",
        "deployment",
        "evaluation",
        "evaluation",
        "workload",
        "source",
        "run",
        "attempt",
        "artifact",
        "2026-09-21T12:00:00Z",
    )
    policy = TargetPackagingPolicy(
        "target-policy",
        "1.0.0",
        "offline-evaluation-contract",
        "2026-09-20T00:00:00Z",
        "2026-09-22T00:00:00Z",
        "delta",
        "managed",
        "environment_resolved_location_not_accessed",
        "deny_implicit_evolution",
        "deny",
        "reject_casefold_qualified_name",
        "deny_without_external_authority",
        (TargetPolicyBinding("target", "SOURCE.TABLE"),),
    )
    column = {
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
    semantic = {
        "request": {
            "client_id": "client",
            "workload_id": "workload",
            "source_id": "source",
            "run_id": "run",
            "attempt_id": "attempt",
        },
        "state": "qualified_underlying_mapping",
        "policy": {"issued_at": "2026-09-20T00:00:00Z", "valid_until": "2026-09-22T00:00:00Z"},
        "targets": [
            {
                "target_dataset_id": "target",
                "target_dataset_version": "1.0.0",
                "target_namespace": "logical",
                "transformation_id": "identity",
                "transformation_version": "1.0.0",
                "columns": [column],
                "target_descriptor_digest": digest_value([column]),
            }
        ],
        "result_id": "BASE02-result",
        "content_digest": SHA_A,
        "policy_digest": SHA_B,
    }
    resolution = {
        "identity": {
            "client_id": "client",
            "deployment_id": "deployment",
            "environment_id": "evaluation",
            "environment_class": "evaluation",
            "workload_id": "workload",
            "source_id": "source",
            "run_id": "run",
            "attempt_id": "attempt",
            "artifact_id": "artifact",
            "access_mode": "write",
            "evaluation_time": "2026-09-21T12:00:00Z",
        },
        "status": "resolved",
        "resolution": {
            "binding_id": "binding",
            "binding_version": "1.0.0",
            "logical_dataset": "SOURCE.TABLE",
            "catalog": "smf_eval",
            "schema": "conversion",
            "table": "table_one",
            "qualified_name": "smf_eval.conversion.table_one",
            "environment_id": "evaluation",
            "environment_class": "evaluation",
            "namespace_source": "explicit_governed_binding",
            "authority_reference": "owner",
            "access_mode": "write",
        },
        "result_id": "BASE03-result",
        "content_digest": SHA_B,
        "canonical_evidence_reference": (
            "runs/run/workloads/workload/target-resolution-attempts/attempt/"
            "target-resolution.result.json"
        ),
    }
    return _evaluate_target_mapping(request, policy, semantic, {"target": resolution})


def _ingestion() -> dict[str, object]:
    req = RestartableIngestionRequest(
        "client",
        "workload",
        "source",
        "run",
        "attempt",
        "source.sas7bdat",
        SHA_A,
        10,
        "sas7bdat",
        "target",
    )
    config = RestartableIngestionConfig()
    result: dict[str, object] = {
        "schema_version": "1.0",
        "result_id": "DBPKG04-result",
        "request": req.binding(),
        "request_digest": digest_value(req.binding()),
        "config": config.binding(),
        "state": "complete_local_delta",
        "checkpoints": [
            {"phase": "admission", "content_digest": SHA_A},
            {"phase": "delta", "content_digest": SHA_B},
        ],
        "dependencies": {},
        "delta": {"manifest": [{"path": "part.parquet", "sha256": SHA_A}]},
        "reconciliation": {"passed": True},
        "exceptions": [],
        "claims": _claims(),
        "content_digest": "",
    }
    result["content_digest"] = digest_value({**result, "content_digest": ""})
    return result


def _case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    Path,
    CurrentTargetMappingEvidence,
    CurrentIngestionEvidence,
    UnityCatalogValidationRequest,
    UnityCatalogValidationPolicy,
]:
    root = tmp_path / "evidence"
    mapping, ingestion = _target_mapping(), _ingestion()
    mapping_path, ingestion_path = root / "mapping.json", root / "ingestion.json"
    publish_json(mapping_path, mapping, "mapping", root=root)
    publish_json(ingestion_path, ingestion, "ingestion", root=root)
    monkeypatch.setattr(
        uc, "verify_target_mapping", lambda *args, **kwargs: SimpleNamespace(result=mapping)
    )
    monkeypatch.setattr(
        uc,
        "verify_restartable_ingestion",
        lambda *args, **kwargs: SimpleNamespace(result=ingestion),
    )
    request = UnityCatalogValidationRequest(
        "client",
        "deployment",
        "evaluation",
        "workload",
        "source",
        "run",
        "attempt",
        "target",
        "2026-09-21T12:00:00Z",
        cast(str, mapping["content_digest"]),
        cast(str, ingestion["content_digest"]),
        "DBX02-result",
        SHA_A,
        "DBX03-result",
        SHA_B,
    )
    policy = UnityCatalogValidationPolicy(
        "uc-policy",
        "1.0.0",
        "2026-09-20T00:00:00Z",
        "2026-09-22T00:00:00Z",
        "smf_eval",
        "conversion",
        "table_one",
        "managed-identity-binding",
    )
    opaque = cast(Any, None)
    current_request = cast(Any, SimpleNamespace(evaluation_time=request.evaluation_time))
    current_policy = cast(Any, SimpleNamespace(valid_until="2026-09-22T00:00:00Z"))
    current_snapshot = cast(
        Any,
        SimpleNamespace(
            evaluation_time=request.evaluation_time, valid_until="2026-09-22T00:00:00Z"
        ),
    )
    mapping_evidence = CurrentTargetMappingEvidence(
        mapping_path, current_request, current_policy, opaque, (), root
    )
    ingestion_evidence = CurrentIngestionEvidence(
        result_path=ingestion_path,
        request=opaque,
        local_request=opaque,
        distributed_request=opaque,
        semantic_request=current_request,
        mapping_policy=opaque,
        base04_result_path=mapping_path,
        base02_result_path=ingestion_path,
        source_root=root,
        artifact_root=root,
        evidence_root=root,
        local_config=opaque,
        distributed_config=opaque,
        snapshot_policy=current_snapshot,
    )
    return root, mapping_evidence, ingestion_evidence, request, policy


def test_offline_plan_composes_upstream_without_live_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, mapping, ingestion, request, policy = _case(tmp_path, monkeypatch)
    result = evaluate_unity_catalog_validation(
        request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
    )
    assert result["state"] == "blocked_external_validation"
    assert result["validation_plan"]["write_operations"] == []
    assert result["provider"]["status"] == "not_invoked_not_qualified"
    assert {item["authority"] for item in result["validation_plan"]["external_requirements"]} == {
        "untrusted_expectation_only",
        "pending_external_authority",
    }
    assert not any(result["claims"].values())
    path = publish_unity_catalog_validation(
        result,
        request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
        output_root=root,
    )
    assert json.loads(path.read_text()) == result
    assert (
        verify_unity_catalog_validation_against_inputs(
            path,
            request,
            policy,
            target_mapping_evidence=mapping,
            ingestion_evidence=ingestion,
            output_root=root,
        )
        == result
    )


def test_drift_authority_and_mutation_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, mapping, ingestion, request, policy = _case(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="content drift"):
        evaluate_unity_catalog_validation(
            UnityCatalogValidationRequest(
                **{**request.binding(), "ingestion_content_digest": "f" * 64}
            ),
            policy,
            target_mapping_evidence=mapping,
            ingestion_evidence=ingestion,
        )
    with pytest.raises(ValueError, match="widens"):
        UnityCatalogValidationPolicy(
            **{
                **policy.binding(),
                "required_grants": tuple(policy.required_grants),
                "live_validation_enabled": True,
            }
        ).binding()
    result = evaluate_unity_catalog_validation(
        request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
    )
    forged = deepcopy(result)
    forged["claims"]["unity_catalog_validated"] = True
    with pytest.raises(ValueError):
        verify_unity_catalog_validation(forged)
    recomputed = deepcopy(result)
    recomputed["blockers"] = ["forged_blocker"]
    decision = {k: v for k, v in recomputed.items() if k not in {"result_id", "content_digest"}}
    recomputed["result_id"] = stable_id("DBPKG01", decision)
    recomputed["content_digest"] = digest_value({**recomputed, "content_digest": ""})
    with pytest.raises(ValueError, match="current governed inputs"):
        publish_unity_catalog_validation(
            recomputed,
            request,
            policy,
            target_mapping_evidence=mapping,
            ingestion_evidence=ingestion,
            output_root=root,
        )


def test_target_collision_or_policy_drift_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, mapping, ingestion, request, policy = _case(tmp_path, monkeypatch)
    wrong = UnityCatalogValidationPolicy(
        **{
            **policy.binding(),
            "required_grants": tuple(policy.required_grants),
            "table": "other_table",
        }
    )
    with pytest.raises(ValueError, match="differs from policy"):
        evaluate_unity_catalog_validation(
            request,
            wrong,
            target_mapping_evidence=mapping,
            ingestion_evidence=ingestion,
        )


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("client_id", "other-client"),
        ("workload_id", "other-workload"),
        ("source_id", "other-source"),
        ("run_id", "other-run"),
        ("attempt_id", "other-attempt"),
        ("deployment_id", "other-deployment"),
        ("environment_id", "other-environment"),
    ],
)
def test_replayed_upstream_identity_mismatch_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    changed: str,
) -> None:
    _, mapping_evidence, ingestion_evidence, request, policy = _case(tmp_path, monkeypatch)
    altered = _target_mapping()
    cast(dict[str, object], altered["request"])[field] = changed
    altered["content_digest"] = digest_value({**altered, "content_digest": ""})
    monkeypatch.setattr(
        uc, "verify_target_mapping", lambda *args, **kwargs: SimpleNamespace(result=altered)
    )
    current_request = UnityCatalogValidationRequest(
        **{**request.binding(), "target_mapping_content_digest": altered["content_digest"]}
    )
    with pytest.raises(ValueError, match=f"upstream {field} mismatch"):
        evaluate_unity_catalog_validation(
            current_request,
            policy,
            target_mapping_evidence=mapping_evidence,
            ingestion_evidence=ingestion_evidence,
        )


def test_current_expiry_collision_and_replay_failure_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, mapping_evidence, ingestion_evidence, request, policy = _case(tmp_path, monkeypatch)
    expired_mapping = replace(
        mapping_evidence,
        policy=cast(Any, SimpleNamespace(valid_until=request.evaluation_time)),
    )
    with pytest.raises(ValueError, match="upstream authority is expired"):
        evaluate_unity_catalog_validation(
            request,
            policy,
            target_mapping_evidence=expired_mapping,
            ingestion_evidence=ingestion_evidence,
        )
    expired_ingestion = replace(
        ingestion_evidence,
        snapshot_policy=cast(
            Any,
            SimpleNamespace(
                evaluation_time=request.evaluation_time, valid_until=request.evaluation_time
            ),
        ),
    )
    with pytest.raises(ValueError, match="upstream authority is expired"):
        evaluate_unity_catalog_validation(
            request,
            policy,
            target_mapping_evidence=mapping_evidence,
            ingestion_evidence=expired_ingestion,
        )

    collision = _target_mapping()
    cast(list[object], collision["targets"]).append(
        deepcopy(cast(list[object], collision["targets"])[0])
    )
    collision["content_digest"] = digest_value({**collision, "content_digest": ""})
    monkeypatch.setattr(
        uc, "verify_target_mapping", lambda *args, **kwargs: SimpleNamespace(result=collision)
    )
    collision_request = UnityCatalogValidationRequest(
        **{**request.binding(), "target_mapping_content_digest": collision["content_digest"]}
    )
    with pytest.raises(ValueError, match="absent, ambiguous, or blocked"):
        evaluate_unity_catalog_validation(
            collision_request,
            policy,
            target_mapping_evidence=mapping_evidence,
            ingestion_evidence=ingestion_evidence,
        )

    monkeypatch.setattr(
        uc,
        "verify_target_mapping",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("current replay mutation")),
    )
    with pytest.raises(ValueError, match="current replay mutation"):
        evaluate_unity_catalog_validation(
            request,
            policy,
            target_mapping_evidence=mapping_evidence,
            ingestion_evidence=ingestion_evidence,
        )


def test_dbx_references_never_authorize_and_publication_is_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, mapping, ingestion, request, policy = _case(tmp_path, monkeypatch)
    first = evaluate_unity_catalog_validation(
        request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
    )
    changed_request = UnityCatalogValidationRequest(
        **{
            **request.binding(),
            "authentication_result_id": "forged-auth-reference",
            "authentication_content_digest": "f" * 64,
            "compute_result_id": "forged-compute-reference",
            "compute_content_digest": "e" * 64,
        }
    )
    changed = evaluate_unity_catalog_validation(
        changed_request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
    )
    assert first["result_id"] != changed["result_id"]
    assert first["state"] == changed["state"] == "blocked_external_validation"
    assert not any(first["claims"].values()) and not any(changed["claims"].values())
    first_path = publish_unity_catalog_validation(
        first,
        request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
        output_root=root / "first",
    )
    second_path = publish_unity_catalog_validation(
        changed,
        changed_request,
        policy,
        target_mapping_evidence=mapping,
        ingestion_evidence=ingestion,
        output_root=root / "second",
    )
    assert first_path != second_path
    assert json.loads(first_path.read_text()) == first
    assert json.loads(second_path.read_text()) == changed
