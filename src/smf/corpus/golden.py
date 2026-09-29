"""Fail-closed golden conversion comparison over canonical corpus evidence."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import jsonschema

from smf.conversion.registry import (
    DEFAULT_REGISTRY,
    ConstructFamily,
    PlanDisposition,
    execute_plan,
    plan_rules,
    qualification_evidence_for_plan,
)
from smf.corpus.regression import (
    CorpusStageRequest,
    RegressionStage,
    StageArtifactInput,
    StageStatus,
    _bound_attempt_path,
    _copy_immutable_bytes,
    _digest_value,
    _load_content_digested,
    _load_stages,
    _publish_json,
    _safe_stage_artifact_bytes,
    record_corpus_stage,
    verify_corpus_snapshot,
)
from smf.workload.identity import stable_id

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "corpus-golden-comparison.schema.json"
)
_PROVIDER_ID = "smf-deterministic"
_PROVIDER_VERSION = "smf-0.1.0"


def validate_golden_comparison(payload: dict[str, Any]) -> None:
    """Validate the strict reconstructable golden-comparison shape."""

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=payload, schema=schema)


def _independent_disposition(source: bytes, target: str) -> tuple[str, bytes | None]:
    """Reproduce the package-owned deterministic decision from immutable source."""

    try:
        plan = plan_rules(source, target)
        if plan.disposition is PlanDisposition.QUALIFIED:
            result = execute_plan(
                source,
                plan,
                workload_id="golden-independent-check",
                source_artifact_id="qualified-source",
                run_id="golden-independent-check",
                attempt_id=plan.plan_id,
            )
            return "generated", result.content.encode("utf-8")
        families = {item["construct_family"] for item in plan.observations}
        if ConstructFamily.SAS_MACRO.value in families:
            return "human_pending", None
        if plan.disposition is PlanDisposition.UNSUPPORTED:
            return "unsupported", None
        return "blocked", None
    except (OSError, UnicodeError, ValueError):
        return "failed", None


def _producer_disposition(stage: dict[str, Any]) -> str:
    status = stage["status"]
    if status == StageStatus.PASSED.value:
        return "generated"
    if status == StageStatus.UNSUPPORTED.value:
        return "unsupported"
    if status == StageStatus.HUMAN_PENDING.value:
        return "human_pending"
    if status in {StageStatus.BLOCKED.value, StageStatus.SKIPPED.value}:
        return "blocked"
    return "failed"


def _build_comparison(qualification_file: Path) -> dict[str, Any]:
    qualification = verify_corpus_snapshot(qualification_file)
    golden = qualification.get("golden_contract")
    if not golden or not qualification.get("golden_contract_digest"):
        raise ValueError("Corpus subject does not declare a qualified golden contract")
    if golden["fixture_classification"] != qualification["evidence_scope"]:
        raise ValueError("Golden fixture classification does not match evidence scope")
    if (
        golden["provider_id"] != _PROVIDER_ID
        or golden["provider_version"] != _PROVIDER_VERSION
        or golden["strategy_id"] != DEFAULT_REGISTRY.registry_id
        or golden["strategy_version"] != DEFAULT_REGISTRY.version
    ):
        raise ValueError("Golden contract names an unsupported provider or strategy version")

    stages = _load_stages(qualification_file)
    conversion = stages.get(RegressionStage.CONVERSION.value)
    if conversion is None:
        raise ValueError("Golden comparison requires canonical conversion evidence")

    source_record = next((item for item in qualification["artifacts"] if item["is_subject"]), None)
    if source_record is None:
        raise ValueError("Golden comparison requires exactly one qualified source subject")
    source_path = _bound_attempt_path(
        qualification_file.parent, source_record["snapshot_uri"], "source snapshot"
    )
    source = source_path.read_bytes()
    if hashlib.sha256(source).hexdigest() != qualification["source_digest"]:
        raise ValueError("Golden comparison source snapshot changed")

    plan = plan_rules(source, qualification["target"])
    independent_disposition, independent_output = _independent_disposition(
        source, qualification["target"]
    )
    producer_disposition = _producer_disposition(conversion)
    artifacts = conversion["artifacts"]
    actual_sha256 = artifacts[0]["sha256"] if len(artifacts) == 1 else None
    actual_size = artifacts[0]["size_bytes"] if len(artifacts) == 1 else None
    expected_sha256 = golden["expected_sha256"]
    expected_size = golden["expected_size_bytes"]

    mismatch = "none"
    behavioral_evidence_digest = None
    producer_evidence = conversion.get("producer_evidence")
    if plan.disposition is PlanDisposition.QUALIFIED:
        source_artifact_id = stable_id(
            "CRART",
            {
                "qualification_id": qualification["qualification_id"],
                "relative_path": source_record["relative_path"],
                "sha256": source_record["sha256"],
            },
        )
        reconstructed = execute_plan(
            source,
            plan,
            workload_id=qualification["workload_id"],
            source_artifact_id=source_artifact_id,
            run_id=qualification["run_id"],
            attempt_id=qualification["attempt_id"],
        )
        expected_producer_evidence = json.loads(json.dumps(reconstructed.metadata, sort_keys=True))
        if (
            producer_evidence != expected_producer_evidence
            or conversion["decision_id"] != plan.plan_id
        ):
            mismatch = "conversion-evidence"
        expectation_id = golden.get("behavioral_expectation_id")
        if expectation_id:
            behavioral = qualification_evidence_for_plan(plan, expectation_id)
            behavioral_evidence_digest = behavioral["evidence_digest"]
            if (
                golden.get("behavioral_evidence_digest") != behavioral_evidence_digest
                or behavioral["source_sha256"] != qualification["source_digest"]
                or behavioral["expected_disposition"] != plan.disposition.value
                or behavioral["expected_output_sha256"] != expected_sha256
            ):
                mismatch = "behavioral-evidence"
        else:
            mismatch = "behavioral-evidence"
    if mismatch == "none" and (
        producer_disposition != golden["expected_disposition"]
        or independent_disposition != golden["expected_disposition"]
    ):
        mismatch = "disposition"
    elif mismatch == "none" and (
        conversion["provider"] != golden["provider_id"]
        or conversion["provider_version"] != golden["provider_version"]
    ):
        mismatch = "provider"
    elif mismatch == "none" and (
        (golden["expected_disposition"] == "generated" and len(artifacts) != 1)
        or (golden["expected_disposition"] != "generated" and artifacts)
    ):
        mismatch = "artifact-count"
    elif mismatch == "none" and golden["expected_disposition"] == "generated":
        assert independent_output is not None
        expected_path = _bound_attempt_path(
            qualification_file.parent, golden["snapshot_uri"], "golden snapshot"
        )
        expected_bytes = expected_path.read_bytes()
        actual_path = _bound_attempt_path(
            qualification_file.parent, artifacts[0]["artifact_uri"], "stage artifact"
        )
        actual_bytes = actual_path.read_bytes()
        if (
            hashlib.sha256(expected_bytes).hexdigest() != expected_sha256
            or len(expected_bytes) != expected_size
            or actual_bytes != expected_bytes
            or independent_output != expected_bytes
        ):
            mismatch = "content"

    identity = {
        key: qualification[key]
        for key in (
            "qualification_id",
            "scenario_id",
            "workload_id",
            "subject_id",
            "run_id",
            "attempt_id",
            "source_digest",
            "bundle_digest",
            "policy_digest",
            "golden_contract_digest",
        )
    }
    material = {
        **identity,
        "golden_id": golden["golden_id"],
        "golden_version": golden["golden_version"],
        "producer_stage_id": conversion["stage_id"],
        "producer_plan_id": conversion["decision_id"],
        "behavioral_expectation_id": golden.get("behavioral_expectation_id"),
        "behavioral_evidence_digest": behavioral_evidence_digest,
        "expected_disposition": golden["expected_disposition"],
        "actual_disposition": producer_disposition,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "mismatch_category": mismatch,
    }
    payload: dict[str, Any] = {
        "schema_version": 1,
        "comparison_id": stable_id("GOLD", material),
        **identity,
        "golden_id": golden["golden_id"],
        "golden_version": golden["golden_version"],
        "comparison_mode": golden["comparison_mode"],
        "provider_id": golden["provider_id"],
        "provider_version": golden["provider_version"],
        "strategy_id": golden["strategy_id"],
        "strategy_version": golden["strategy_version"],
        "producer_stage_id": conversion["stage_id"],
        "producer_plan_id": conversion["decision_id"],
        "behavioral_expectation_id": golden.get("behavioral_expectation_id"),
        "behavioral_evidence_digest": behavioral_evidence_digest,
        "expected_disposition": golden["expected_disposition"],
        "actual_disposition": producer_disposition,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual_sha256,
        "expected_size_bytes": expected_size,
        "actual_size_bytes": actual_size,
        "outcome": "matched" if mismatch == "none" else "mismatched",
        "mismatch_category": mismatch,
    }
    payload["content_digest"] = _digest_value(payload)
    validate_golden_comparison(payload)
    return payload


def compare_golden_conversion(qualification_file: Path) -> Path:
    """Compare canonical conversion evidence to immutable golden bytes exactly once."""

    attempt = qualification_file.parent
    lock_path = attempt / ".golden-comparison.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        comparison_path = attempt / "golden-comparison.json"
        if comparison_path.exists():
            payload = _load_content_digested(comparison_path)
            validate_golden_comparison(payload)
        else:
            payload = _build_comparison(qualification_file)
            _publish_json(comparison_path, payload)

        stage_path = attempt / "stage-golden-comparison.json"
        if not stage_path.exists():
            record_corpus_stage(
                qualification_file,
                CorpusStageRequest(
                    stage=RegressionStage.GOLDEN_COMPARISON,
                    status=(
                        StageStatus.PASSED
                        if payload["outcome"] == "matched"
                        else StageStatus.FAILED
                    ),
                    provider="smf-golden-comparator",
                    provider_version="1.0.0",
                    artifacts=(StageArtifactInput("golden-comparison", comparison_path),),
                    decision_id=payload["comparison_id"],
                    input_artifact_digest=payload["actual_sha256"],
                    reasons=(
                        () if payload["outcome"] == "matched" else (payload["mismatch_category"],)
                    ),
                ),
            )
        else:
            stage = _load_content_digested(stage_path)
            if stage.get("decision_id") != payload["comparison_id"]:
                raise ValueError("Golden comparison stage has a conflicting decision identity")
            artifact = stage["artifacts"][0]
            destination = _bound_attempt_path(
                attempt, artifact["artifact_uri"], "golden stage artifact"
            )
            if not destination.exists():
                safe_bytes = _safe_stage_artifact_bytes(comparison_path)
                _copy_immutable_bytes(safe_bytes, destination, artifact["sha256"])
        return comparison_path
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def load_golden_comparison(path: Path) -> dict[str, Any]:
    """Load a golden result only when its canonical bindings still verify."""

    if path.name != "golden-comparison.json":
        raise ValueError("Golden comparison must use its canonical attempt filename")
    payload = _load_content_digested(path)
    validate_golden_comparison(payload)
    qualification_file = path.with_name("qualification.json")
    expected = _build_comparison(qualification_file)
    if payload != expected:
        raise ValueError("Golden comparison is not derived from canonical evidence")
    stage = _load_stages(qualification_file).get(RegressionStage.GOLDEN_COMPARISON.value)
    if stage is None or stage["decision_id"] != payload["comparison_id"]:
        raise ValueError("Golden comparison lacks its bound stage projection")
    if (stage["status"] == StageStatus.PASSED.value) != (payload["outcome"] == "matched"):
        raise ValueError("Golden comparison stage does not match canonical outcome")
    stage_artifact = _bound_attempt_path(
        path.parent, stage["artifacts"][0]["artifact_uri"], "golden stage artifact"
    )
    if json.loads(stage_artifact.read_text(encoding="utf-8")) != payload:
        raise ValueError("Golden comparison stage artifact is not canonical")
    return payload
