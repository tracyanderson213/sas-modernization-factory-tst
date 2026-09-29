from __future__ import annotations

import hashlib
import importlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

import smf.target_mapping as target_mapping

pytest.importorskip("pyspark")
try:
    importlib.import_module("pyreadstat")
except ModuleNotFoundError:
    if os.environ.get("SMF_REQUIRE_BASE10") == "1":
        raise RuntimeError("BASE-10 confidence requires the pinned conversion runtime") from None
    pytest.skip("BASE-10 optional provider runtime is unavailable", allow_module_level=True)

from smf.canonical_descriptor import SnapshotPolicy, run_canonical_descriptor
from smf.distributed_sas_reader import DistributedReaderConfig, DistributedReaderRequest
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest
from smf.semantic_mapping import SemanticMappingRequest, load_mapping_policy, run_semantic_mapping
from smf.target_mapping import (
    ResolutionEvidence,
    SemanticEvidence,
    TargetMappingRequest,
    TargetPackagingPolicy,
    TargetPolicyBinding,
    run_target_mapping,
    verify_target_mapping,
)
from smf.target_resolution import (
    TargetResolutionRequest,
    evaluate_target_resolution,
    publish_target_resolution,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"
POLICY_PATH = ROOT / "examples" / "policies" / "base02-public-fixture-mapping-v1.json"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_BASE10") == "1":
        raise RuntimeError("BASE-10 confidence requires the exact qualified SCALE-01 bundle")
    pytest.skip("BASE-10 qualified SCALE-01 bundle is unavailable", allow_module_level=True)


def _local_request() -> ReaderRequest:
    return ReaderRequest(
        client_id="public-upstream",
        workload_id="base02-public-fixture",
        source_id="ag121a-supp-sample",
        run_id="base02-run",
        attempt_id="attempt-1",
        relative_path=SOURCE.name,
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        source_byte_count=SOURCE.stat().st_size,
    )


def _distributed_request() -> DistributedReaderRequest:
    local = _local_request()
    return DistributedReaderRequest(
        client_id=local.client_id,
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        source_relative_path=local.relative_path,
        source_sha256=local.source_sha256,
        source_byte_count=local.source_byte_count,
        oracle_relative_path=ORACLE.name,
        oracle_sha256=hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        oracle_byte_count=ORACLE.stat().st_size,
    )


def _reader_config() -> ReaderConfig:
    return ReaderConfig(
        PyreadstatProvider().runtime_identity()["distribution_record_sha256"],
        chunk_rows=5_000,
        max_source_bytes=10_000_000,
        max_rows=50_000,
    )


def _snapshot_policy() -> SnapshotPolicy:
    return SnapshotPolicy(
        version="base04-public-fixture-v1",
        acquisition_time="2026-09-20T20:00:00Z",
        evaluation_time="2026-09-20T20:01:00Z",
        valid_until="2027-09-20T20:00:00Z",
    )


def _semantic_request() -> SemanticMappingRequest:
    return SemanticMappingRequest(
        client_id="public-upstream",
        workload_id="base02-public-fixture",
        source_id="ag121a-supp-sample",
        run_id="base02-run",
        attempt_id="attempt-1",
        source_dataset_id="ag121a-supp-sample",
        source_dataset_version="1.0.0",
        evaluation_time="2026-09-20T20:02:00Z",
    )


def _packaging_policy() -> TargetPackagingPolicy:
    return TargetPackagingPolicy(
        policy_id="base10-public-fixture",
        version="1.0.0",
        authority_scope="offline-evaluation-contract",
        issued_at="2026-09-20T00:00:00Z",
        valid_until="2027-09-20T00:00:00Z",
        table_format="delta",
        storage_mode="managed",
        storage_disposition="environment_resolved_location_not_accessed",
        schema_evolution_policy="deny_implicit_evolution",
        overwrite_policy="deny",
        collision_policy="reject_casefold_qualified_name",
        production_namespace_policy="deny_without_external_authority",
        target_bindings=(TargetPolicyBinding("smf-qualification-ag121a", "SAS.AG121A_SUPP"),),
    )


def _resolution_request(config_root: Path, evidence_root: Path) -> TargetResolutionRequest:
    return TargetResolutionRequest(
        config_root=config_root,
        config_path=config_root / "target-resolution.yaml",
        output_root=evidence_root,
        client_id="public-upstream",
        deployment_id="synthetic-evaluation-deployment",
        environment_id="synthetic-evaluation",
        environment_class="evaluation",
        workload_id="base02-public-fixture",
        source_id="ag121a-supp-sample",
        run_id="base02-run",
        attempt_id="attempt-1",
        artifact_id="artifact-1",
        logical_dataset="SAS.AG121A_SUPP",
        access_mode="write",
        evaluation_time="2026-09-20T20:03:00Z",
    )


def test_actual_semantic_and_namespace_evidence_map_to_planned_delta_and_replay(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    local_request = _local_request()
    distributed_request = _distributed_request()
    local_config = _reader_config()
    distributed_config = DistributedReaderConfig()
    snapshot_policy = _snapshot_policy()
    base04 = run_canonical_descriptor(
        local_request,
        distributed_request,
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        policy=snapshot_policy,
    )
    semantic_request = _semantic_request()
    semantic_policy = load_mapping_policy(POLICY_PATH)
    base02 = run_semantic_mapping(
        semantic_request,
        semantic_policy,
        base04_result_path=base04.result_path,
        local_request=local_request,
        distributed_request=distributed_request,
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        snapshot_policy=snapshot_policy,
    )

    config_root = tmp_path / "configuration"
    config_root.mkdir()
    config = config_root / "target-resolution.yaml"
    config.write_text(
        """\
schema_version: "1.0"
policy_id: base10-public-fixture
policy_version: "1.0.0"
deployment_identity:
  client_id: public-upstream
  deployment_id: synthetic-evaluation-deployment
  environment_id: synthetic-evaluation
environment_class: evaluation
implicit_default_behavior: deny
authority:
  state: active
  qualified_at: "2026-09-20T00:00:00Z"
  valid_until: "2027-09-20T00:00:00Z"
  authority_reference: synthetic-offline-authority
bindings:
  - binding_id: ag121a-target
    binding_version: "1.0.0"
    logical_dataset: SAS.AG121A_SUPP
    environment_id: synthetic-evaluation
    environment_class: evaluation
    access_modes: [write]
    catalog: smf_eval
    schema: conversion
    table: ag121a_supp
    namespace_source: explicit_governed_binding
    authority_reference: synthetic-offline-binding
""",
        encoding="utf-8",
    )
    resolution_request = _resolution_request(config_root, evidence_root)
    resolution_path, _ = publish_target_resolution(
        resolution_request, evaluate_target_resolution(resolution_request)
    )
    request = TargetMappingRequest(
        client_id="public-upstream",
        deployment_id="synthetic-evaluation-deployment",
        environment_id="synthetic-evaluation",
        environment_class="evaluation",
        workload_id="base02-public-fixture",
        source_id="ag121a-supp-sample",
        run_id="base02-run",
        attempt_id="attempt-1",
        artifact_id="artifact-1",
        evaluation_time="2026-09-20T20:04:00Z",
    )
    semantic = SemanticEvidence(
        base02.result_path,
        semantic_request,
        semantic_policy,
        base04.result_path,
        local_request,
        distributed_request,
        FIXTURE_ROOT,
        ARTIFACT_ROOT,
        evidence_root,
        local_config,
        distributed_config,
        snapshot_policy,
    )
    resolutions = (
        ResolutionEvidence("smf-qualification-ag121a", resolution_path, resolution_request),
    )
    execution = run_target_mapping(
        request,
        _packaging_policy(),
        semantic,
        resolutions,
        evidence_root=evidence_root,
    )

    assert execution.result["state"] == "qualified_offline_mapping"
    assert execution.result["targets"][0]["resolved_namespace"]["qualified_name"] == (
        "smf_eval.conversion.ag121a_supp"
    )
    assert (
        execution.result["targets"][0]["schema_digest"]
        == (base02.result["targets"][0]["target_descriptor_digest"])
    )
    assert not any(execution.result["claims"].values())
    assert (
        verify_target_mapping(
            execution.result_path,
            request,
            _packaging_policy(),
            semantic,
            resolutions,
            evidence_root=evidence_root,
        ).result
        == execution.result
    )

    stale = target_mapping._reconstruct(
        replace(request, evaluation_time="2027-09-20T00:00:00Z"),
        replace(_packaging_policy(), valid_until="2027-09-21T00:00:00Z"),
        semantic,
        resolutions,
    )
    assert "target_resolution_blocked:smf-qualification-ag121a" in stale["blockers"]
    assert stale["targets"] == []

    snapshot_expired = target_mapping._reconstruct(
        replace(request, evaluation_time=snapshot_policy.valid_until),
        replace(_packaging_policy(), valid_until="2027-09-21T00:00:00Z"),
        semantic,
        resolutions,
    )
    assert "semantic_snapshot_not_current" in snapshot_expired["blockers"]

    config.write_text(config.read_text().replace("table: ag121a_supp", "table: changed"))
    with pytest.raises(ValueError, match="current governed inputs"):
        verify_target_mapping(
            execution.result_path,
            request,
            _packaging_policy(),
            semantic,
            resolutions,
            evidence_root=evidence_root,
        )
