from __future__ import annotations

import hashlib
import importlib
import json
import os
from copy import deepcopy
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest
from referencing import Registry, Resource

pytest.importorskip("pyspark")
try:
    importlib.import_module("pyreadstat")
except ModuleNotFoundError:
    if os.environ.get("SMF_REQUIRE_BASE02") == "1":
        raise RuntimeError("BASE-02 confidence requires the pinned conversion runtime") from None
    pytest.skip("BASE-02 optional provider runtime is unavailable", allow_module_level=True)

import smf.semantic_mapping as semantic_mapping
from smf.canonical_descriptor import SnapshotPolicy, run_canonical_descriptor
from smf.distributed_sas_reader import DistributedReaderConfig, DistributedReaderRequest
from smf.sas_reader import PyreadstatProvider, ReaderConfig, ReaderRequest
from smf.semantic_mapping import (
    SemanticMappingExecution,
    SemanticMappingRequest,
    load_mapping_policy,
    run_semantic_mapping,
    verify_semantic_mapping,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "distributed_sas_reader"
ARTIFACT_ROOT = Path(os.environ.get("SMF_SCALE01_ARTIFACT_ROOT", "/nonexistent"))
SOURCE = FIXTURE_ROOT / "ag121a_supp_sample.sas7bdat"
ORACLE = FIXTURE_ROOT / "ag121a_supp_sample.csv"
POLICY_PATH = ROOT / "examples" / "policies" / "base02-public-fixture-mapping-v1.json"

if not (ARTIFACT_ROOT / "spark-sas7bdat-3.0.0-s_2.12.jar").is_file():
    if os.environ.get("SMF_REQUIRE_BASE02") == "1":
        raise RuntimeError("BASE-02 confidence requires the exact qualified SCALE-01 bundle")
    pytest.skip("BASE-02 qualified SCALE-01 bundle is unavailable", allow_module_level=True)


def _local_request(**overrides: Any) -> ReaderRequest:
    values: dict[str, Any] = {
        "client_id": "public-upstream",
        "workload_id": "base02-public-fixture",
        "source_id": "ag121a-supp-sample",
        "run_id": "base02-run",
        "attempt_id": "attempt-1",
        "relative_path": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "source_byte_count": SOURCE.stat().st_size,
    }
    values.update(overrides)
    return ReaderRequest(**values)


def _distributed_request(**overrides: Any) -> DistributedReaderRequest:
    local = _local_request()
    values: dict[str, Any] = {
        "client_id": local.client_id,
        "workload_id": local.workload_id,
        "source_id": local.source_id,
        "run_id": local.run_id,
        "attempt_id": local.attempt_id,
        "source_relative_path": local.relative_path,
        "source_sha256": local.source_sha256,
        "source_byte_count": local.source_byte_count,
        "oracle_relative_path": ORACLE.name,
        "oracle_sha256": hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        "oracle_byte_count": ORACLE.stat().st_size,
    }
    values.update(overrides)
    return DistributedReaderRequest(**values)


def _local_config() -> ReaderConfig:
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


def _request(**overrides: Any) -> SemanticMappingRequest:
    values: dict[str, Any] = {
        "client_id": "public-upstream",
        "workload_id": "base02-public-fixture",
        "source_id": "ag121a-supp-sample",
        "run_id": "base02-run",
        "attempt_id": "attempt-1",
        "source_dataset_id": "ag121a-supp-sample",
        "source_dataset_version": "1.0.0",
        "evaluation_time": "2026-09-20T20:02:00Z",
    }
    values.update(overrides)
    return SemanticMappingRequest(**values)


@pytest.fixture(scope="module")
def base04(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, dict[str, Any]]:
    evidence = tmp_path_factory.mktemp("base02-evidence")
    execution = run_canonical_descriptor(
        _local_request(),
        _distributed_request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        policy=_snapshot_policy(),
    )
    return evidence, execution.result_path, execution.result


def _run(evidence: Path, base04_path: Path, **kwargs: Any):  # type: ignore[no-untyped-def]
    return run_semantic_mapping(
        kwargs.pop("request", _request()),
        kwargs.pop("policy", load_mapping_policy(POLICY_PATH)),
        base04_result_path=base04_path,
        local_request=_local_request(),
        distributed_request=_distributed_request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
        **kwargs,
    )


@pytest.fixture(scope="module")
def base02_execution(
    base04: tuple[Path, Path, dict[str, Any]],
) -> SemanticMappingExecution:
    evidence, base04_path, _ = base04
    return _run(evidence, base04_path)


def _result_validator() -> jsonschema.Draft202012Validator:
    policy_schema = json.loads(
        (ROOT / "schemas" / "dataset-semantic-mapping-policy.schema.json").read_text()
    )
    result_schema = json.loads(
        (ROOT / "schemas" / "dataset-semantic-mapping-result.schema.json").read_text()
    )
    registry = Registry().with_resource(policy_schema["$id"], Resource.from_contents(policy_schema))
    return jsonschema.Draft202012Validator(result_schema, registry=registry)


def test_real_descriptor_maps_underlying_values_and_replays(
    base04: tuple[Path, Path, dict[str, Any]],
    base02_execution: SemanticMappingExecution,
) -> None:
    evidence, base04_path, _ = base04
    execution = base02_execution
    result = execution.result
    assert result["state"] == "qualified_underlying_mapping"
    assert len(result["targets"]) == 1
    assert len(result["targets"][0]["columns"]) == 8
    assert [item["target_physical_type"] for item in result["targets"][0]["columns"]] == [
        "string",
        "string",
        "string",
        "string",
        "double",
        "double",
        "double",
        "double",
    ]
    assert result["targets"][0]["columns"][4]["expected_format"] == "9.6"
    assert result["policy"]["executable_format_allowlist"] == []
    assert result["key_policy"] == {
        "source_declared_keys": [],
        "source_key_authority": "unavailable_not_inferred",
        "source_policy": "descriptor_declared_keys_only",
        "target_policy": "pending_business_owner",
        "target_keys": [],
        "target_key_authority": False,
    }
    assert result["targets"][0]["columns"][2]["expected_storage_width"] == 60
    assert result["execution_authorized"] is False
    assert not any(result["claims"].values())
    assert "special_missing_value_equivalence" in result["unresolved_external_decisions"]
    assert "PHONE" not in json.dumps(result) or "rows" not in result
    replay = verify_semantic_mapping(
        execution.result_path,
        _request(),
        load_mapping_policy(POLICY_PATH),
        base04_result_path=base04_path,
        local_request=_local_request(),
        distributed_request=_distributed_request(),
        source_root=FIXTURE_ROOT,
        artifact_root=ARTIFACT_ROOT,
        evidence_root=evidence,
        local_config=_local_config(),
        distributed_config=DistributedReaderConfig(),
        snapshot_policy=_snapshot_policy(),
    )
    assert replay.result == result


def test_policy_and_schemas_are_strict_and_packaged(
    base02_execution: SemanticMappingExecution,
) -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    for name in (
        "dataset-semantic-mapping-policy.schema.json",
        "dataset-semantic-mapping-result.schema.json",
    ):
        public = (ROOT / "schemas" / name).read_bytes()
        packaged = files("smf.schemas").joinpath(name).read_bytes()
        assert public == packaged
    jsonschema.validate(
        policy,
        json.loads((ROOT / "schemas" / "dataset-semantic-mapping-policy.schema.json").read_text()),
    )
    validator = _result_validator()
    validator.validate(base02_execution.result)

    nested_mutations = []
    for path, operation in (
        (("request", "client_id"), "delete"),
        (("policy", "invented"), "add"),
        (("canonical_descriptor", "descriptor_digest"), "delete"),
        (("targets", 0, "invented"), "add"),
        (("targets", 0, "columns", 0, "source_name"), "delete"),
        (("claims", "semantic_parity"), "delete"),
    ):
        mutated = deepcopy(base02_execution.result)
        parent: Any = mutated
        for key in path[:-1]:
            parent = parent[key]
        if operation == "delete":
            del parent[path[-1]]
        else:
            parent[path[-1]] = False
        nested_mutations.append(mutated)
    for mutated in nested_mutations:
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(mutated)

    extra = deepcopy(policy)
    extra["invented"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            extra,
            json.loads(
                (ROOT / "schemas" / "dataset-semantic-mapping-policy.schema.json").read_text()
            ),
        )


def test_ambiguous_incomplete_rename_and_one_to_many_contracts(
    base04: tuple[Path, Path, dict[str, Any]],
) -> None:
    _, _, descriptor = base04
    policy = load_mapping_policy(POLICY_PATH)
    incomplete = replace(
        policy,
        targets=(replace(policy.targets[0], columns=policy.targets[0].columns[:-1]),),
    )
    assert semantic_mapping._evaluate(_request(), incomplete, descriptor)["blockers"] == [
        "column_mapping_is_incomplete_or_ambiguous"
    ]
    with pytest.raises(ValueError, match="rationale"):
        replace(policy.targets[0].columns[0], target_name="YEAR").validate()
    second = replace(
        policy.targets[0],
        target_dataset_id="smf-qualification-ag121a-copy",
        rationale=(
            "Explicit second bounded target used only to prove attributable one-to-many mechanics."
        ),
    )
    result = semantic_mapping._evaluate(
        _request(), replace(policy, targets=(policy.targets[0], second)), descriptor
    )
    assert [item["target_dataset_id"] for item in result["targets"]] == [
        "smf-qualification-ag121a",
        "smf-qualification-ag121a-copy",
    ]
    with pytest.raises(ValueError, match="ambiguous"):
        replace(policy, targets=(policy.targets[0], policy.targets[0])).validate()


def test_snapshot_format_expiry_and_identity_fail_closed_without_echo(
    base04: tuple[Path, Path, dict[str, Any]],
) -> None:
    _, _, descriptor = base04
    policy = load_mapping_policy(POLICY_PATH)
    assert semantic_mapping._evaluate(
        _request(), replace(policy, source_snapshot_sha256="0" * 64), descriptor
    )["blockers"] == ["source_snapshot_mismatch"]
    changed = deepcopy(descriptor)
    changed["canonical_descriptor"]["columns"][4]["declared_sas_metadata"]["format"] = "BEST12."
    assert semantic_mapping._evaluate(_request(), policy, changed)["blockers"] == [
        "declared_format_or_informat_mismatch"
    ]
    assert semantic_mapping._evaluate(
        _request(evaluation_time=policy.valid_until), policy, descriptor
    )["blockers"] == ["mapping_policy_not_current"]
    changed_width = deepcopy(descriptor)
    changed_width["canonical_descriptor"]["columns"][2]["declared_sas_metadata"][
        "storage_width"
    ] = 59
    assert semantic_mapping._evaluate(_request(), policy, changed_width)["blockers"] == [
        "declared_storage_width_mismatch"
    ]
    canary = "secret-canary-base02"
    with pytest.raises(ValueError) as captured:
        _request(workload_id=canary).validate()
    assert canary not in str(captured.value)


def test_cancellation_retry_mutation_and_workload_isolation(
    tmp_path: Path,
    base04: tuple[Path, Path, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, base04_path, descriptor = base04
    monkeypatch.setattr(
        semantic_mapping,
        "verify_canonical_descriptor",
        lambda *args, **kwargs: SimpleNamespace(result=descriptor),
    )
    with pytest.raises(InterruptedError, match="cancelled"):
        _run(tmp_path, base04_path, cancel_check=lambda: True)
    assert not list(tmp_path.rglob("base02/result.json"))
    recovered = _run(tmp_path, base04_path)
    other = _run(
        tmp_path,
        base04_path,
        request=_request(workload_id="base02-other", run_id="base02-other-run"),
    )
    assert recovered.result_path != other.result_path
    recovered.result_path.chmod(0o600)
    mutated = json.loads(recovered.result_path.read_text(encoding="utf-8"))
    mutated["claims"]["semantic_parity"] = True
    recovered.result_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(ValueError):
        verify_semantic_mapping(
            recovered.result_path,
            _request(),
            load_mapping_policy(POLICY_PATH),
            base04_result_path=base04_path,
            local_request=_local_request(),
            distributed_request=_distributed_request(),
            source_root=FIXTURE_ROOT,
            artifact_root=ARTIFACT_ROOT,
            evidence_root=tmp_path,
            local_config=_local_config(),
            distributed_config=DistributedReaderConfig(),
            snapshot_policy=_snapshot_policy(),
        )
