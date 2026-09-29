from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import smf.schema_integration as subject
from smf.schema_integration import (
    CurrentSchemaIntegrationEvidence,
    SchemaIntegrationRequest,
    run_schema_integration,
    verify_schema_integration,
    verify_schema_integration_result,
)
from smf.upstream.crypto import digest_value
from smf.workload.identity import stable_id

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64


def _case() -> tuple[
    SchemaIntegrationRequest, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    identity = {
        "client_id": "fixture-client",
        "workload_id": "fixture-workload",
        "source_id": "fixture-source",
        "run_id": "fixture-run",
        "attempt_id": "attempt-1",
    }
    base04: dict[str, Any] = {
        "identity": identity,
        "result_id": "BASE04-result",
        "content_digest": _A,
        "descriptor_digest": "d" * 64,
        "canonical_descriptor": {
            "columns": [
                {
                    "position": 0,
                    "name": "member_id",
                    "canonical_physical_type": "long",
                    "nullable_observed": False,
                    "declared_sas_metadata": {"storage_width": 8},
                },
                {
                    "position": 1,
                    "name": "name",
                    "canonical_physical_type": "string",
                    "nullable_observed": True,
                    "declared_sas_metadata": {"storage_width": 24},
                },
            ]
        },
    }
    base02: dict[str, Any] = {
        "request": {**identity, "source_dataset_id": "source.members"},
        "result_id": "BASE02-result",
        "content_digest": _B,
        "state": "qualified_underlying_mapping",
        "targets": [
            {
                "target_dataset_id": "target.members",
                "target_descriptor_digest": "e" * 64,
                "columns": [
                    {
                        "source_position": 0,
                        "source_name": "member_id",
                        "target_name": "member_id",
                        "target_physical_type": "long",
                        "expected_storage_width": 8,
                        "underlying_value_authority": True,
                    },
                    {
                        "source_position": 1,
                        "source_name": "name",
                        "target_name": "name",
                        "target_physical_type": "string",
                        "expected_storage_width": 24,
                        "underlying_value_authority": True,
                    },
                ],
            }
        ],
    }
    ingestion: dict[str, Any] = {
        "request": {**identity, "target_id": "target.members"},
        "result_id": "DBPKG04-result",
        "content_digest": "f" * 64,
        "state": "complete_local_delta",
        "reconciliation": {"passed": True},
    }
    dbpkg01: dict[str, Any] = {
        "request": {**identity, "target_dataset_id": "target.members"},
        "result_id": "DBPKG01-result",
        "content_digest": _C,
    }
    request = SchemaIntegrationRequest(
        **identity,
        logical_dataset_id="members",
        source_dataset_id="source.members",
        target_dataset_id="target.members",
        base04_result_id=str(base04["result_id"]),
        base04_content_digest=str(base04["content_digest"]),
        base02_result_id=str(base02["result_id"]),
        base02_content_digest=str(base02["content_digest"]),
        dbpkg01_result_id=str(dbpkg01["result_id"]),
        dbpkg01_content_digest=str(dbpkg01["content_digest"]),
    )
    return request, base04, base02, ingestion, dbpkg01


def _evaluate(case: tuple[Any, ...]) -> dict[str, Any]:
    request, base04, base02, ingestion, dbpkg01 = case
    return subject._evaluate(  # noqa: SLF001 - focused contract test
        request, base04=base04, base02=base02, ingestion=ingestion, dbpkg01=dbpkg01
    )


def test_current_descriptors_are_consumed_by_dp01_comparator() -> None:
    result = _evaluate(_case())

    assert result["state"] == "passed_governed_descriptor_integration"
    assert result["comparison"]["status"] == "passed"
    assert result["blockers"] == []
    assert result["source_snapshot"]["provenance"]["authoritative"] is True
    assert result["target_snapshot"]["provenance"]["authoritative"] is True
    assert result["target_snapshot"]["engine"] == "base02-governed-target-plan"
    assert result["target_snapshot"]["metadata"]["physical_target_schema_observed"] is False
    assert result["evidence_boundary"]["target_physical_schema_observed"] is False
    assert not any(result["claims"].values())
    verify_schema_integration_result(result)


def test_renamed_target_is_visible_as_failed_comparison() -> None:
    case: list[Any] = list(_case())
    base02 = deepcopy(case[2])
    base02["targets"][0]["columns"][1]["target_name"] = "renamed"
    case[2] = base02

    result = _evaluate(tuple(case))

    assert result["state"] == "failed_descriptor_comparison"
    assert result["comparison"]["status"] == "failed"
    assert set(result["blockers"]) == {"SCHEMA-COLUMN-MISSING", "SCHEMA-COLUMN-UNEXPECTED"}


def test_caller_digest_cannot_override_current_upstream_evidence() -> None:
    request, base04, base02, ingestion, dbpkg01 = _case()
    forged = SchemaIntegrationRequest(**{**request.binding(), "dbpkg01_content_digest": "9" * 64})

    with pytest.raises(ValueError, match="content drift"):
        subject._evaluate(  # noqa: SLF001 - focused contract test
            forged, base04=base04, base02=base02, ingestion=ingestion, dbpkg01=dbpkg01
        )


def test_unsupported_physical_type_and_unqualified_target_fail_closed() -> None:
    case: list[Any] = list(_case())
    base04 = deepcopy(case[1])
    base04["canonical_descriptor"]["columns"][0]["canonical_physical_type"] = "variant"
    case[1] = base04
    with pytest.raises(ValueError, match="unsupported canonical physical type"):
        _evaluate(tuple(case))

    case = list(_case())
    base02 = deepcopy(case[2])
    base02["state"] = "blocked"
    case[2] = base02
    with pytest.raises(ValueError, match="absent or ambiguous"):
        _evaluate(tuple(case))


def test_result_mutation_and_prohibited_claim_are_rejected() -> None:
    result = _evaluate(_case())
    mutated = deepcopy(result)
    mutated["upstream"]["dbpkg04_content_digest"] = "0" * 64
    with pytest.raises(ValueError, match="identity mismatch"):
        verify_schema_integration_result(mutated)

    claimed = deepcopy(result)
    claimed["claims"]["migration_complete"] = True
    decision = {
        key: value for key, value in claimed.items() if key not in {"result_id", "content_digest"}
    }
    claimed["result_id"] = stable_id("SCHEMAINT01", decision)
    claimed["content_digest"] = digest_value({**claimed, "content_digest": ""})
    with pytest.raises(ValueError, match="schema validation failed|prohibited claim"):
        verify_schema_integration_result(claimed)


def test_request_rejects_protected_identity() -> None:
    request, *_ = _case()
    unsafe = SchemaIntegrationRequest(**{**request.binding(), "client_id": "token=secret-value"})
    with pytest.raises(ValueError, match="Unsafe"):
        unsafe.binding()


def test_strict_nested_schema_and_plan_classification_cannot_be_forged() -> None:
    result = _evaluate(_case())
    missing = deepcopy(result)
    del missing["source_snapshot"]["columns"][0]["name"]
    with pytest.raises(ValueError, match="schema validation failed"):
        verify_schema_integration_result(missing)

    unknown = deepcopy(result)
    unknown["comparison"]["checks"][0]["caller_override"] = True
    with pytest.raises(ValueError, match="schema validation failed"):
        verify_schema_integration_result(unknown)

    invalid_digest = deepcopy(result)
    invalid_digest["upstream"]["base04_content_digest"] = "not-a-digest"
    with pytest.raises(ValueError, match="schema validation failed"):
        verify_schema_integration_result(invalid_digest)

    reclassified = deepcopy(result)
    reclassified["target_snapshot"]["engine"] = "delta-observed-target"
    reclassified["target_snapshot"]["metadata"]["physical_target_schema_observed"] = True
    reclassified["evidence_boundary"]["target_physical_schema_observed"] = True
    with pytest.raises(ValueError, match="schema validation failed"):
        verify_schema_integration_result(reclassified)


def test_publication_replays_every_current_upstream_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, base04, base02, ingestion, dbpkg01 = _case()
    calls: list[str] = []

    def dbpkg_replay(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append("dbpkg01")
        return dbpkg01

    def ingestion_replay(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append("dbpkg04")
        return SimpleNamespace(result=ingestion)

    def semantic_replay(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append("base02")
        return SimpleNamespace(result=base02)

    def descriptor_replay(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append("base04")
        return SimpleNamespace(result=base04)

    monkeypatch.setattr(subject, "verify_unity_catalog_validation_against_inputs", dbpkg_replay)
    monkeypatch.setattr(subject, "verify_restartable_ingestion", ingestion_replay)
    monkeypatch.setattr(subject, "verify_semantic_mapping", semantic_replay)
    monkeypatch.setattr(subject, "verify_canonical_descriptor", descriptor_replay)
    opaque = cast(Any, object())
    ingestion_evidence = cast(
        Any,
        SimpleNamespace(
            result_path=tmp_path / "dbpkg04.json",
            request=opaque,
            local_request=opaque,
            distributed_request=opaque,
            semantic_request=opaque,
            mapping_policy=opaque,
            base04_result_path=tmp_path / "base04.json",
            base02_result_path=tmp_path / "base02.json",
            source_root=tmp_path,
            artifact_root=tmp_path,
            evidence_root=tmp_path,
            local_config=opaque,
            distributed_config=opaque,
            snapshot_policy=opaque,
        ),
    )
    evidence = CurrentSchemaIntegrationEvidence(
        dbpkg01_result_path=tmp_path / "dbpkg01.json",
        dbpkg01_output_root=tmp_path,
        dbpkg01_request=opaque,
        dbpkg01_policy=opaque,
        target_mapping=opaque,
        ingestion=ingestion_evidence,
    )

    first = run_schema_integration(request, evidence, output_root=tmp_path)
    second = run_schema_integration(request, evidence, output_root=tmp_path)

    assert first == second
    assert calls == ["dbpkg01", "dbpkg04", "base02", "base04"] * 2
    assert (
        verify_schema_integration(first.result_path, request, evidence, output_root=tmp_path)
        == first
    )
    assert calls == ["dbpkg01", "dbpkg04", "base02", "base04"] * 3

    first_bytes = first.result_path.read_bytes()
    second_values = {
        **request.binding(),
        "workload_id": "other-workload",
        "run_id": "other-run",
    }
    second_request = SchemaIntegrationRequest(**second_values)
    for identity in (
        base04["identity"],
        base02["request"],
        ingestion["request"],
        dbpkg01["request"],
    ):
        identity["workload_id"] = "other-workload"
        identity["run_id"] = "other-run"
    other = run_schema_integration(second_request, evidence, output_root=tmp_path)
    assert other.result_path != first.result_path
    assert first.result_path.read_bytes() == first_bytes
    with pytest.raises(ValueError, match="not request-bound"):
        verify_schema_integration(first.result_path, second_request, evidence, output_root=tmp_path)

    mutated = deepcopy(first.result)
    mutated["upstream"]["dbpkg04_content_digest"] = "0" * 64
    first.result_path.chmod(0o600)
    first.result_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(ValueError, match="identity mismatch"):
        verify_schema_integration(first.result_path, request, evidence, output_root=tmp_path)
