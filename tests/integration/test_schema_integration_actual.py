from __future__ import annotations

import hashlib
import importlib
import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pyspark")
for dependency in ("pyreadstat", "deltalake", "pyarrow"):
    try:
        importlib.import_module(dependency)
    except ModuleNotFoundError:
        if os.environ.get("SMF_REQUIRE_SCHEMAINT") == "1":
            raise RuntimeError(f"SCHEMA-INT-01 requires pinned {dependency}") from None
        pytest.skip(
            f"SCHEMA-INT-01 optional dependency {dependency} is unavailable",
            allow_module_level=True,
        )

from smf.canonical_descriptor import SnapshotPolicy, run_canonical_descriptor  # noqa: E402
from smf.distributed_sas_reader import (  # noqa: E402
    DistributedReaderConfig,
    DistributedReaderRequest,
)
from smf.restartable_ingestion import (  # noqa: E402
    RestartableIngestionRequest,
    run_restartable_ingestion,
)
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest  # noqa: E402
from smf.schema_integration import (  # noqa: E402
    CurrentSchemaIntegrationEvidence,
    SchemaIntegrationRequest,
    run_schema_integration,
    verify_schema_integration,
)
from smf.semantic_mapping import (  # noqa: E402
    SemanticMappingRequest,
    load_mapping_policy,
    run_semantic_mapping,
)
from smf.target_mapping import (  # noqa: E402
    ResolutionEvidence,
    SemanticEvidence,
    TargetMappingRequest,
    TargetPackagingPolicy,
    TargetPolicyBinding,
    run_target_mapping,
)
from smf.target_resolution import (  # noqa: E402
    TargetResolutionRequest,
    evaluate_target_resolution,
    publish_target_resolution,
)
from smf.unity_catalog_validation import (  # noqa: E402
    CurrentIngestionEvidence,
    CurrentTargetMappingEvidence,
    UnityCatalogValidationPolicy,
    UnityCatalogValidationRequest,
    evaluate_unity_catalog_validation,
    publish_unity_catalog_validation,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"
POLICY_PATH = ROOT / "examples" / "policies" / "base02-public-fixture-mapping-v1.json"
EVALUATED = "2026-09-20T20:04:00Z"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_SCHEMAINT") == "1":
        raise RuntimeError("SCHEMA-INT-01 requires the exact qualified SCALE-01 bundle")
    pytest.skip("SCHEMA-INT-01 qualified SCALE-01 bundle is unavailable", allow_module_level=True)


def test_real_descriptor_to_published_delta_target_dp01_integration(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    shutil.copy2(SOURCE, source_root / SOURCE.name)
    shutil.copy2(ORACLE, source_root / ORACLE.name)
    evidence_root = tmp_path / "evidence"
    local = ReaderRequest(
        client_id="public-upstream",
        workload_id="schema-int-public-fixture",
        source_id="ag121a-supp-sample",
        run_id="schema-int-run",
        attempt_id="attempt-1",
        relative_path=SOURCE.name,
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        source_byte_count=SOURCE.stat().st_size,
    )
    distributed = DistributedReaderRequest(
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
    local_config = ReaderConfig(
        PyreadstatProvider().runtime_identity()["distribution_record_sha256"],
        chunk_rows=5_000,
        max_source_bytes=10_000_000,
        max_rows=50_000,
    )
    distributed_config = DistributedReaderConfig()
    snapshot_policy = SnapshotPolicy(
        version="base04-public-fixture-v1",
        acquisition_time="2026-09-20T20:00:00Z",
        evaluation_time=EVALUATED,
        valid_until="2027-09-20T20:00:00Z",
    )
    base04 = run_canonical_descriptor(
        local,
        distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        policy=snapshot_policy,
    )
    semantic_request = SemanticMappingRequest(
        client_id=local.client_id,
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        source_dataset_id="ag121a-supp-sample",
        source_dataset_version="1.0.0",
        evaluation_time=EVALUATED,
    )
    semantic_policy = load_mapping_policy(POLICY_PATH)
    base02 = run_semantic_mapping(
        semantic_request,
        semantic_policy,
        base04_result_path=base04.result_path,
        local_request=local,
        distributed_request=distributed,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        snapshot_policy=snapshot_policy,
    )

    config_root = tmp_path / "configuration"
    config_root.mkdir()
    config_path = config_root / "target-resolution.yaml"
    config_path.write_text(
        """schema_version: "1.0"
policy_id: schema-int-public-fixture
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
    resolution_request = TargetResolutionRequest(
        config_root=config_root,
        config_path=config_path,
        output_root=evidence_root,
        client_id=local.client_id,
        deployment_id="synthetic-evaluation-deployment",
        environment_id="synthetic-evaluation",
        environment_class="evaluation",
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        artifact_id="artifact-1",
        logical_dataset="SAS.AG121A_SUPP",
        access_mode="write",
        evaluation_time=EVALUATED,
    )
    resolution_path, _ = publish_target_resolution(
        resolution_request, evaluate_target_resolution(resolution_request)
    )
    target_request = TargetMappingRequest(
        client_id=local.client_id,
        deployment_id="synthetic-evaluation-deployment",
        environment_id="synthetic-evaluation",
        environment_class="evaluation",
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        artifact_id="artifact-1",
        evaluation_time=EVALUATED,
    )
    target_policy = TargetPackagingPolicy(
        policy_id="schema-int-public-fixture",
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
    semantic = SemanticEvidence(
        base02.result_path,
        semantic_request,
        semantic_policy,
        base04.result_path,
        local,
        distributed,
        source_root,
        ARTIFACT_ROOT,
        evidence_root,
        local_config,
        distributed_config,
        snapshot_policy,
    )
    resolutions = (
        ResolutionEvidence("smf-qualification-ag121a", resolution_path, resolution_request),
    )
    target = run_target_mapping(
        target_request,
        target_policy,
        semantic,
        resolutions,
        evidence_root=evidence_root,
    )
    ingestion_request = RestartableIngestionRequest(
        client_id=local.client_id,
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        source_relative_path=local.relative_path,
        source_sha256=local.source_sha256,
        source_byte_count=local.source_byte_count,
        asset_kind="sas7bdat",
        target_id="smf-qualification-ag121a",
    )
    ingestion = run_restartable_ingestion(
        ingestion_request,
        local_request=local,
        distributed_request=distributed,
        semantic_request=semantic_request,
        mapping_policy=semantic_policy,
        base04_result_path=base04.result_path,
        base02_result_path=base02.result_path,
        source_root=source_root,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence_root,
        local_config=local_config,
        distributed_config=distributed_config,
        snapshot_policy=snapshot_policy,
    )
    target_evidence = CurrentTargetMappingEvidence(
        target.result_path,
        target_request,
        target_policy,
        semantic,
        resolutions,
        evidence_root,
    )
    ingestion_evidence = CurrentIngestionEvidence(
        ingestion.result_path,
        ingestion_request,
        local,
        distributed,
        semantic_request,
        semantic_policy,
        base04.result_path,
        base02.result_path,
        source_root,
        ARTIFACT_ROOT,
        evidence_root,
        local_config,
        distributed_config,
        snapshot_policy,
    )
    dbpkg_request = UnityCatalogValidationRequest(
        client_id=local.client_id,
        deployment_id="synthetic-evaluation-deployment",
        environment_id="synthetic-evaluation",
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        target_dataset_id="smf-qualification-ag121a",
        evaluation_time=EVALUATED,
        target_mapping_content_digest=target.result["content_digest"],
        ingestion_content_digest=ingestion.result["content_digest"],
        authentication_result_id="DBX02-synthetic",
        authentication_content_digest="a" * 64,
        compute_result_id="DBX03-synthetic",
        compute_content_digest="b" * 64,
    )
    dbpkg_policy = UnityCatalogValidationPolicy(
        "schema-int-uc-policy",
        "1.0.0",
        "2026-09-20T00:00:00Z",
        "2027-09-20T00:00:00Z",
        "smf_eval",
        "conversion",
        "ag121a_supp",
        "synthetic-managed-identity-binding",
    )
    dbpkg = evaluate_unity_catalog_validation(
        dbpkg_request,
        dbpkg_policy,
        target_mapping_evidence=target_evidence,
        ingestion_evidence=ingestion_evidence,
    )
    dbpkg_path = publish_unity_catalog_validation(
        dbpkg,
        dbpkg_request,
        dbpkg_policy,
        target_mapping_evidence=target_evidence,
        ingestion_evidence=ingestion_evidence,
        output_root=evidence_root,
    )
    request = SchemaIntegrationRequest(
        client_id=local.client_id,
        workload_id=local.workload_id,
        source_id=local.source_id,
        run_id=local.run_id,
        attempt_id=local.attempt_id,
        logical_dataset_id="ag121a-supp-sample",
        source_dataset_id="ag121a-supp-sample",
        target_dataset_id="smf-qualification-ag121a",
        base04_result_id=base04.result["result_id"],
        base04_content_digest=base04.result["content_digest"],
        base02_result_id=base02.result["result_id"],
        base02_content_digest=base02.result["content_digest"],
        dbpkg01_result_id=dbpkg["result_id"],
        dbpkg01_content_digest=dbpkg["content_digest"],
    )
    current = CurrentSchemaIntegrationEvidence(
        dbpkg_path,
        evidence_root,
        dbpkg_request,
        dbpkg_policy,
        target_evidence,
        ingestion_evidence,
    )

    execution = run_schema_integration(request, current, output_root=evidence_root)

    assert execution.result["state"] == "passed_governed_descriptor_integration"
    assert execution.result["comparison"]["status"] == "passed"
    assert execution.result["upstream"]["dbpkg04_result_id"] == ingestion.result["result_id"]
    assert execution.result["source_snapshot"]["columns"]
    assert not any(execution.result["claims"].values())
    assert (
        verify_schema_integration(
            execution.result_path, request, current, output_root=evidence_root
        )
        == execution
    )
