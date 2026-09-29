"""Durable, fail-closed regression admission and evidence projection."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import jsonschema

from smf.corpus.loader import load_corpus_manifest, sha256_file
from smf.corpus.models import CorpusArtifact, CorpusManifest, CorpusRegressionSubject
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value


class RegressionStage(StrEnum):
    CONVERSION = "conversion"
    GOLDEN_COMPARISON = "golden-comparison"
    EXECUTION = "execution"
    VALIDATION = "validation"
    HUMAN_APPROVAL = "human-approval"
    REPAIR = "repair"


class StageStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    HUMAN_PENDING = "human_pending"
    HUMAN_DENIED = "human_denied"
    CANCELLED = "cancelled"


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CHECK_STATUSES = {"pass", "fail", "warning", "not_applicable"}
_PARITY_KINDS = {"structural-parity", "data-parity", "semantic-parity"}
_RESULT_SCHEMA = (
    Path(__file__).resolve().parents[3] / "schemas" / "corpus-regression-result.schema.json"
)


def _component(value: str, label: str) -> str:
    if value in {".", ".."} or not _SAFE_COMPONENT.fullmatch(value):
        raise ValueError(f"Unsafe corpus regression {label}")
    return value


def _digest_value(value: Any) -> str:
    import hashlib

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _publish_json(path: Path, payload: dict[str, Any]) -> None:
    serialized = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == serialized:
            return
        raise FileExistsError(f"Corpus regression evidence already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != serialized:
                raise FileExistsError(
                    f"Corpus regression evidence already exists: {path}"
                ) from None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_content_digested(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Corpus regression evidence must be an object: {path}")
    expected = raw.get("content_digest")
    unsigned = dict(raw)
    unsigned.pop("content_digest", None)
    if expected != _digest_value(unsigned):
        raise ValueError(f"Corpus regression evidence digest mismatch: {path}")
    return raw


def validate_corpus_regression_result(payload: dict[str, Any]) -> None:
    """Reject malformed terminal enums, identities, and telemetry shapes."""

    schema = json.loads(_RESULT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(instance=payload, schema=schema)


@dataclass(frozen=True)
class CorpusRegressionRequest:
    """Exact attempt identity used to admit one declared corpus subject."""

    manifest_path: Path
    scenario_id: str
    workload_id: str
    subject_id: str
    run_id: str
    attempt_id: str
    output_root: Path


@dataclass(frozen=True)
class StageArtifactInput:
    """A concrete downstream artifact to copy into durable attempt evidence."""

    artifact_id: str
    path: Path


@dataclass(frozen=True)
class CorpusStageRequest:
    """Observed stage outcome; identity bindings are supplied by qualification."""

    stage: RegressionStage
    status: StageStatus
    provider: str
    provider_version: str
    artifacts: tuple[StageArtifactInput, ...] = ()
    execution_id: str | None = None
    decision_id: str | None = None
    input_artifact_digest: str | None = None
    validation_kind: str | None = None
    checks: tuple[dict[str, Any], ...] = ()
    evidence_origin: str | None = None
    baseline_evidence_id: str | None = None
    source_execution_id: str | None = None
    producer_evidence: dict[str, Any] | None = None
    reasons: tuple[str, ...] = ()


def _json_normalized(value: Any) -> Any:
    """Return the durable JSON representation used for identity comparisons."""

    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _canonical_golden_conversion_evidence(
    qualification_file: Path,
    qualification: dict[str, Any],
    request: CorpusStageRequest,
) -> dict[str, Any]:
    """Reconstruct package-owned deterministic producer evidence from snapshots."""

    from smf.conversion.registry import (
        DEFAULT_REGISTRY,
        ConstructFamily,
        PlanDisposition,
        execute_plan,
        plan_rules,
    )

    subjects = [item for item in qualification["artifacts"] if item["is_subject"]]
    if len(subjects) != 1:
        raise ValueError("Golden conversion requires exactly one canonical source subject")
    subject = subjects[0]
    source_path = _bound_attempt_path(
        qualification_file.parent, subject["snapshot_uri"], "source snapshot"
    )
    source = source_path.read_bytes()
    plan = plan_rules(source, qualification["target"])
    families = {item["construct_family"] for item in plan.observations}
    if plan.disposition is PlanDisposition.QUALIFIED:
        expected_status = StageStatus.PASSED
    elif ConstructFamily.SAS_MACRO.value in families:
        expected_status = StageStatus.HUMAN_PENDING
    elif plan.disposition is PlanDisposition.UNSUPPORTED:
        expected_status = StageStatus.UNSUPPORTED
    else:
        expected_status = StageStatus.BLOCKED
    if (
        request.status != expected_status
        or request.provider != "smf-deterministic"
        or request.provider_version != "smf-0.1.0"
        or request.decision_id != plan.plan_id
    ):
        raise ValueError("Golden stage lacks package-owned deterministic conversion evidence")

    source_artifact_id = stable_id(
        "CRART",
        {
            "qualification_id": qualification["qualification_id"],
            "relative_path": subject["relative_path"],
            "sha256": subject["sha256"],
        },
    )
    if expected_status is StageStatus.PASSED:
        result = execute_plan(
            source,
            plan,
            workload_id=qualification["workload_id"],
            source_artifact_id=source_artifact_id,
            run_id=qualification["run_id"],
            attempt_id=qualification["attempt_id"],
        )
        canonical = _json_normalized(result.metadata)
        if (
            request.producer_evidence is None
            or _json_normalized(request.producer_evidence) != canonical
        ):
            raise ValueError("Golden stage lacks package-owned deterministic conversion evidence")
        if len(request.artifacts) != 1:
            raise ValueError(
                "Golden deterministic conversion requires exactly one generated artifact"
            )
        generated = _safe_stage_artifact_bytes(request.artifacts[0].path)
        if generated != result.content.encode("utf-8"):
            raise ValueError("Golden generated artifact is not the package-executed plan output")
        return cast(dict[str, Any], canonical)

    if request.artifacts or request.producer_evidence is not None:
        raise ValueError("Non-generated golden conversion cannot supply producer artifacts")
    return cast(
        dict[str, Any],
        _json_normalized(
            {
                "registry": DEFAULT_REGISTRY.snapshot(),
                "plan": plan.to_dict(),
                "applications": [],
                "generated_sha256": None,
                "implementation_version": "smf-0.1.0",
            }
        ),
    )


def _attempt_dir(request: CorpusRegressionRequest) -> Path:
    path = (
        request.output_root
        / "runs"
        / _component(request.run_id, "run_id")
        / "workloads"
        / _component(request.workload_id, "workload_id")
        / "attempts"
        / _component(request.attempt_id, "attempt_id")
        / "corpus-regression"
    )
    root = request.output_root.resolve()
    if not path.resolve().is_relative_to(root):
        raise ValueError("Corpus regression attempt path escapes output root")
    return path


def qualification_path(request: CorpusRegressionRequest) -> Path:
    return _attempt_dir(request) / "qualification.json"


def _bound_attempt_path(attempt: Path, relative_uri: str, label: str) -> Path:
    relative = Path(relative_uri)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Corpus {label} reference escapes its attempt")
    resolved = (attempt / relative).resolve()
    if not resolved.is_relative_to(attempt.resolve()):
        raise ValueError(f"Corpus {label} reference escapes its attempt")
    return resolved


def _subject(manifest: CorpusManifest, request: CorpusRegressionRequest) -> CorpusRegressionSubject:
    if manifest.scenario_id != request.scenario_id:
        raise ValueError("manifest scenario_id does not match requested scenario")
    if manifest.regression is None:
        raise ValueError("manifest does not declare regression subjects")
    matches = [
        item for item in manifest.regression.subjects if item.subject_id == request.subject_id
    ]
    if len(matches) != 1:
        raise ValueError("regression subject identity does not resolve exactly once")
    subject = matches[0]
    if subject.workload_id != request.workload_id:
        raise ValueError("regression workload_id does not match requested workload")
    return subject


def _artifact_record(
    artifact: CorpusArtifact, subject: CorpusRegressionSubject, workload_root: Path
) -> dict[str, Any]:
    resolved = artifact.path.resolve()
    return {
        "relative_path": resolved.relative_to(workload_root).as_posix(),
        "role": artifact.role,
        "sha256": sha256_file(resolved),
        "size_bytes": resolved.stat().st_size,
        "is_subject": resolved == subject.entrypoint.resolve(),
    }


def _copy_immutable(source: Path, destination: Path, expected_digest: str) -> None:
    data = source.read_bytes()
    import hashlib

    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError(f"Qualified source bytes changed before snapshot: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256_file(destination) != expected_digest:
            raise ValueError(f"Immutable corpus snapshot digest mismatch: {destination}")
        return
    with destination.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    destination.chmod(0o444)


def _safe_stage_artifact_bytes(path: Path) -> bytes:
    """Apply the canonical secret boundary before bytes become durable evidence."""

    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Corpus stage evidence must be UTF-8 so it can be sanitized") from exc
    sanitized = sanitize_discovery_value(text)
    if not isinstance(sanitized, str):
        raise TypeError("Canonical stage evidence sanitization returned a non-string")
    return sanitized.encode("utf-8")


def _copy_immutable_bytes(data: bytes, destination: Path, expected_digest: str) -> None:
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("Corpus stage artifact changed during sanitization")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256_file(destination) != expected_digest:
            raise ValueError(f"Immutable corpus stage evidence digest mismatch: {destination}")
        return
    with destination.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    destination.chmod(0o444)


def _recover_snapshot(qualification: dict[str, Any], manifest_path: Path, attempt: Path) -> None:
    """Recover missing snapshot files from reverified source bytes only."""

    if (
        manifest_path.parent.name != "manifests"
        or manifest_path.is_symlink()
        or sha256_file(manifest_path) != qualification["manifest_digest"]
    ):
        raise ValueError("Qualified corpus manifest is missing, changed, or outside its boundary")
    manifest = load_corpus_manifest(manifest_path)
    if manifest.workload is None or not manifest.workload.root.is_relative_to(
        manifest_path.parent.parent.resolve()
    ):
        raise ValueError("Qualified corpus workload root escapes its boundary")
    source_by_relative = {
        artifact.path.resolve().relative_to(manifest.workload.root).as_posix(): artifact.path
        for artifact in manifest.artifacts
        if manifest.workload is not None
        and artifact.path.resolve().is_relative_to(manifest.workload.root)
    }
    for artifact in qualification["artifacts"]:
        destination = _bound_attempt_path(attempt, artifact["snapshot_uri"], "snapshot")
        if destination.exists():
            if sha256_file(destination) != artifact["sha256"]:
                raise ValueError("Immutable corpus snapshot was modified after qualification")
            continue
        source = source_by_relative.get(artifact["relative_path"])
        if source is None:
            raise ValueError("Qualified source closure is no longer reconstructable")
        _copy_immutable(source, destination, artifact["sha256"])
    golden = qualification.get("golden_contract")
    if golden and golden.get("snapshot_uri"):
        destination = _bound_attempt_path(attempt, golden["snapshot_uri"], "golden snapshot")
        if destination.exists():
            if sha256_file(destination) != golden["expected_sha256"]:
                raise ValueError("Immutable corpus golden snapshot was modified")
        else:
            source = source_by_relative.get(golden["relative_path"])
            if source is None:
                raise ValueError("Qualified corpus golden is no longer reconstructable")
            _copy_immutable(source, destination, golden["expected_sha256"])


def admit_corpus_regression(request: CorpusRegressionRequest) -> Path:
    """Admit and snapshot one subject, preserving the first decision across retry."""

    path = qualification_path(request)
    attempt = path.parent
    if path.exists():
        canonical = _load_content_digested(path)
        expected = {
            "scenario_id": request.scenario_id,
            "workload_id": request.workload_id,
            "subject_id": request.subject_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
        }
        if any(canonical.get(key) != value for key, value in expected.items()):
            raise FileExistsError("Corpus regression attempt has conflicting canonical identity")
        if canonical["status"] == "admitted":
            _recover_snapshot(canonical, request.manifest_path, attempt)
        return path

    try:
        if request.manifest_path.parent.name != "manifests" or request.manifest_path.is_symlink():
            raise ValueError("regression manifest must be a non-symlink in a manifests directory")
        manifest = load_corpus_manifest(request.manifest_path)
        subject = _subject(manifest, request)
        if manifest.workload is None or not manifest.workload.root.is_relative_to(
            request.manifest_path.parent.parent.resolve()
        ):
            raise ValueError("regression workload root escapes its corpus boundary")
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        manifest_digest = (
            sha256_file(request.manifest_path) if request.manifest_path.is_file() else None
        )
        reason = sanitize_discovery_value(str(exc))
        blocker = {
            "code": "qualification_prerequisite_missing",
            "status": "unresolved",
            "reason": reason,
        }
        blocked_identity = {
            "scenario_id": request.scenario_id,
            "workload_id": request.workload_id,
            "subject_id": request.subject_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "manifest_digest": manifest_digest,
            "blockers": [blocker],
        }
        blocked_payload = {
            "schema_version": 1,
            "qualification_id": stable_id("CRQ", blocked_identity),
            **blocked_identity,
            "status": "blocked",
            "source_id": None,
            "source_digest": None,
            "bundle_digest": None,
            "policy_digest": None,
            "policy_snapshot": None,
            "golden_contract_digest": None,
            "golden_contract": None,
            "target": None,
            "evidence_scope": "test-only",
            "environment": "test-only",
            "source_provenance": None,
            "artifacts": [],
        }
        blocked_payload["content_digest"] = _digest_value(blocked_payload)
        _publish_json(path, blocked_payload)
        return path
    assert manifest.workload is not None
    manifest_digest = sha256_file(request.manifest_path)
    artifacts_by_path = {item.path.resolve(): item for item in manifest.artifacts}
    artifact_records = [
        _artifact_record(artifacts_by_path[path.resolve()], subject, manifest.workload.root)
        for path in subject.source_closure
    ]
    artifact_records.sort(key=lambda item: item["relative_path"])
    bundle_material = {
        "manifest_digest": manifest_digest,
        "source": asdict(manifest.source),
        "artifacts": artifact_records,
    }
    bundle_digest = _digest_value(bundle_material)
    source_record = next(item for item in artifact_records if item["is_subject"])
    baseline_by_id = {item.evidence_id: item for item in manifest.output_evidence}
    baseline_bindings = [
        {
            "evidence_id": evidence_id,
            "artifact_digest": baseline_by_id[evidence_id].content_hash,
            "evidence_origin": baseline_by_id[evidence_id].evidence_origin,
            "source_execution_id": baseline_by_id[evidence_id].source_execution_id,
            "authoritative": baseline_by_id[evidence_id].authoritative,
            "deterministic": baseline_by_id[evidence_id].deterministic,
        }
        for evidence_id in subject.baseline_evidence_ids
    ]
    golden_contract: dict[str, Any] | None = None
    if subject.golden is not None:
        golden_contract = {
            "golden_id": subject.golden.golden_id,
            "golden_version": subject.golden.golden_version,
            "expected_disposition": subject.golden.expected_disposition,
            "comparison_mode": subject.golden.comparison_mode,
            "provider_id": subject.golden.provider_id,
            "provider_version": subject.golden.provider_version,
            "strategy_id": subject.golden.strategy_id,
            "strategy_version": subject.golden.strategy_version,
            "behavioral_expectation_id": subject.golden.behavioral_expectation_id,
            "behavioral_evidence_digest": subject.golden.behavioral_evidence_digest,
            "rationale": subject.golden.rationale,
            "review_reference": subject.golden.review_reference,
            "fixture_classification": subject.golden.fixture_classification,
            "relative_path": None,
            "expected_sha256": None,
            "expected_size_bytes": None,
            "snapshot_uri": None,
        }
        if subject.golden.artifact_path is not None:
            golden_artifact = artifacts_by_path[subject.golden.artifact_path.resolve()]
            relative = subject.golden.artifact_path.relative_to(manifest.workload.root).as_posix()
            expected_sha256 = sha256_file(subject.golden.artifact_path)
            golden_contract.update(
                {
                    "relative_path": relative,
                    "expected_sha256": expected_sha256,
                    "expected_size_bytes": subject.golden.artifact_path.stat().st_size,
                    "snapshot_uri": (
                        Path("snapshot") / "golden" / expected_sha256 / relative
                    ).as_posix(),
                }
            )
            if golden_artifact.sha256 != expected_sha256:
                raise ValueError("Corpus golden bytes changed after manifest verification")
    golden_contract_digest = _digest_value(golden_contract) if golden_contract else None
    policy_snapshot = {
        "policy_id": subject.validation_policy.policy_id,
        "policy_version": subject.validation_policy.policy_version,
        "validation_kind": subject.validation_policy.validation_kind,
        "target": subject.target,
        "stages": list(subject.stages),
        "oracle_ids": list(subject.oracle_ids),
        "baseline_evidence_ids": list(subject.baseline_evidence_ids),
        "baseline_evidence": baseline_bindings,
        "golden_contract_digest": golden_contract_digest,
    }
    policy_digest = _digest_value(policy_snapshot)
    qualification_id = stable_id(
        "CRQ",
        {
            "scenario_id": request.scenario_id,
            "workload_id": request.workload_id,
            "subject_id": request.subject_id,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "manifest_digest": manifest_digest,
            "source_id": manifest.source.source_id,
            "bundle_digest": bundle_digest,
            "policy_digest": policy_digest,
            "golden_contract_digest": golden_contract_digest,
        },
    )
    snapshot_root = Path("snapshot") / bundle_digest
    for item in artifact_records:
        item["snapshot_uri"] = (snapshot_root / item["relative_path"]).as_posix()
        source = manifest.workload.root / item["relative_path"]
        _copy_immutable(source, attempt / item["snapshot_uri"], item["sha256"])
    if golden_contract and golden_contract["snapshot_uri"]:
        golden_source = manifest.workload.root / golden_contract["relative_path"]
        _copy_immutable(
            golden_source,
            attempt / golden_contract["snapshot_uri"],
            golden_contract["expected_sha256"],
        )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "qualification_id": qualification_id,
        "scenario_id": request.scenario_id,
        "workload_id": request.workload_id,
        "subject_id": request.subject_id,
        "run_id": request.run_id,
        "attempt_id": request.attempt_id,
        "status": "admitted",
        "blockers": [],
        "manifest_digest": manifest_digest,
        "source_id": manifest.source.source_id,
        "source_digest": source_record["sha256"],
        "bundle_digest": bundle_digest,
        "policy_digest": policy_digest,
        "golden_contract_digest": golden_contract_digest,
        "golden_contract": golden_contract,
        "policy_snapshot": policy_snapshot,
        "target": subject.target,
        "evidence_scope": subject.evidence_scope,
        "environment": subject.environment,
        "source_provenance": asdict(manifest.source),
        "artifacts": artifact_records,
    }
    payload["content_digest"] = _digest_value(payload)
    _publish_json(path, payload)
    return path


def verify_corpus_snapshot(qualification_file: Path) -> dict[str, Any]:
    """Reverify every admitted byte immediately before downstream work."""

    qualification = _load_content_digested(qualification_file)
    if qualification.get("status") != "admitted":
        raise ValueError("Corpus regression qualification is not admitted")
    for artifact in qualification["artifacts"]:
        snapshot = _bound_attempt_path(
            qualification_file.parent, artifact["snapshot_uri"], "snapshot"
        )
        if not snapshot.is_file() or sha256_file(snapshot) != artifact["sha256"]:
            raise ValueError("Immutable corpus snapshot is missing or has changed")
    golden = qualification.get("golden_contract")
    if golden and golden.get("snapshot_uri"):
        snapshot = _bound_attempt_path(
            qualification_file.parent, golden["snapshot_uri"], "golden snapshot"
        )
        if not snapshot.is_file() or sha256_file(snapshot) != golden["expected_sha256"]:
            raise ValueError("Immutable corpus golden snapshot is missing or has changed")
    return qualification


def _copy_stage_artifacts(
    attempt: Path, request: CorpusStageRequest, *, target: str
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    prepared: list[tuple[bytes, Path, str]] = []
    for item in request.artifacts:
        artifact_id = _component(item.artifact_id, "artifact_id")
        if artifact_id in seen:
            raise ValueError(f"Duplicate corpus stage artifact id: {artifact_id}")
        seen.add(artifact_id)
        if not item.path.is_file():
            raise FileNotFoundError(item.path)
        safe_bytes = _safe_stage_artifact_bytes(item.path)
        digest = hashlib.sha256(safe_bytes).hexdigest()
        if request.status == StageStatus.PASSED and not safe_bytes.strip():
            raise ValueError("Passed corpus stage artifact must be non-empty")
        suffix = item.path.suffix[:16]
        uri = Path("evidence") / request.stage.value / f"{artifact_id}{suffix}"
        prepared.append((safe_bytes, uri, digest))
        records.append(
            {
                "artifact_id": artifact_id,
                "artifact_uri": uri.as_posix(),
                "sha256": digest,
                "size_bytes": len(safe_bytes),
            }
        )
    if (
        request.stage == RegressionStage.CONVERSION
        and request.status == StageStatus.PASSED
        and target == "pyspark"
        and not any(_has_meaningful_pyspark_logic(data) for data, _, _ in prepared)
    ):
        raise ValueError("Passed conversion requires meaningful converted workload logic")
    for data, uri, digest in prepared:
        _copy_immutable_bytes(data, attempt / uri, digest)
    return records


def _has_meaningful_pyspark_logic(data: bytes) -> bool:
    """Conservatively recognize data operations, not execution or semantic parity.

    Only inspect top-level expressions/assignments: an uncalled function or a
    session/configuration statement is not converted workload evidence.
    """
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return False
    data_operations = {
        "select",
        "selectExpr",
        "withColumn",
        "withColumnRenamed",
        "filter",
        "where",
        "join",
        "union",
        "unionByName",
        "groupBy",
        "agg",
        "orderBy",
        "sort",
        "drop",
        "dropDuplicates",
        "distinct",
        "limit",
        "fillna",
        "replace",
        "table",
        "range",
        "createDataFrame",
    }

    def has_operation(node: ast.AST) -> bool:
        if isinstance(node, ast.Lambda):
            return False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in data_operations:
                return True
            if node.func.attr == "sql" and node.args:
                query = node.args[0]
                if isinstance(query, ast.Constant) and isinstance(query.value, str):
                    return bool(
                        re.match(
                            r"^\s*(?:SELECT|WITH|INSERT|MERGE|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b",
                            query.value,
                            re.IGNORECASE,
                        )
                    )
        return any(has_operation(child) for child in ast.iter_child_nodes(node))

    return any(
        has_operation(node.value)
        for node in tree.body
        if isinstance(node, ast.Expr | ast.Assign | ast.AnnAssign) and node.value is not None
    )


def record_corpus_stage(qualification_file: Path, request: CorpusStageRequest) -> Path:
    """Persist one strictly bound stage observation under its attempt."""

    qualification = verify_corpus_snapshot(qualification_file)
    stage = RegressionStage(request.stage)
    status = StageStatus(request.status)
    _component(request.provider, "provider")
    _component(request.provider_version, "provider_version")
    # Reject rather than redact identity values: redaction would conflate distinct
    # observations. Validate before any stage artifacts or identity hashes persist.
    identity_metadata = {
        field: getattr(request, field)
        for field in (
            "execution_id",
            "decision_id",
            "input_artifact_digest",
            "validation_kind",
            "evidence_origin",
            "baseline_evidence_id",
            "source_execution_id",
        )
    }
    if sanitize_discovery_value(identity_metadata) != identity_metadata:
        raise ValueError("Corpus stage identity metadata contains credential material")
    if stage == RegressionStage.HUMAN_APPROVAL and status == StageStatus.PASSED:
        raise ValueError("Human approval requires authenticated, attempt-bound attestation")
    canonical_producer_evidence: dict[str, Any] | None = None
    if stage == RegressionStage.CONVERSION and qualification.get("golden_contract"):
        canonical_producer_evidence = _canonical_golden_conversion_evidence(
            qualification_file, qualification, request
        )
    elif request.producer_evidence is not None:
        raise ValueError("Producer evidence is only accepted for a qualified golden conversion")
    if stage == RegressionStage.GOLDEN_COMPARISON:
        if "golden-comparison" not in qualification["policy_snapshot"]["stages"]:
            raise ValueError("Golden comparison is not declared by the qualified subject")
        canonical_path = qualification_file.with_name("golden-comparison.json")
        if (
            len(request.artifacts) != 1
            or request.artifacts[0].path.resolve() != canonical_path.resolve()
            or request.provider != "smf-golden-comparator"
            or request.provider_version != "1.0.0"
        ):
            raise ValueError("Golden comparison requires its canonical comparator evidence")
        from smf.corpus.golden import _build_comparison, validate_golden_comparison

        candidate = _load_content_digested(canonical_path)
        validate_golden_comparison(candidate)
        if candidate != _build_comparison(qualification_file):
            raise ValueError("Golden comparison evidence is not independently reconstructable")
        expected_status = (
            StageStatus.PASSED if candidate["outcome"] == "matched" else StageStatus.FAILED
        )
        if (
            status != expected_status
            or request.decision_id != candidate["comparison_id"]
            or request.input_artifact_digest != candidate["actual_sha256"]
            or request.checks
            or request.validation_kind is not None
            or request.execution_id is not None
        ):
            raise ValueError("Golden comparison stage does not match canonical derived evidence")
    if (
        status == StageStatus.PASSED
        and stage
        in {
            RegressionStage.CONVERSION,
            RegressionStage.EXECUTION,
            RegressionStage.VALIDATION,
        }
        and not request.artifacts
    ):
        raise ValueError("Passed corpus stage requires reconstructable artifact evidence")
    if (
        stage == RegressionStage.EXECUTION
        and status == StageStatus.PASSED
        and not request.execution_id
    ):
        raise ValueError("Passed execution requires an attributable execution_id")
    if stage == RegressionStage.VALIDATION:
        if request.validation_kind not in {"static", *_PARITY_KINDS}:
            raise ValueError("Validation stage requires a supported validation_kind")
        if request.validation_kind != qualification["policy_snapshot"]["validation_kind"]:
            raise ValueError("Validation kind does not match the qualified validation policy")
        if request.evidence_origin not in {None, "sas-executed-baseline"}:
            raise ValueError("Validation stage has an unsupported evidence_origin")
        if request.validation_kind == "static" and any(
            (request.evidence_origin, request.baseline_evidence_id, request.source_execution_id)
        ):
            raise ValueError("Static validation cannot accept parity baseline attestations")
        if status == StageStatus.PASSED:
            if not request.input_artifact_digest:
                raise ValueError("Passed validation requires generated input artifact binding")
            if not request.checks or any(item.get("status") != "pass" for item in request.checks):
                raise ValueError("Passed validation requires concrete passing checks")
            if request.validation_kind in _PARITY_KINDS and (
                request.evidence_origin != "sas-executed-baseline"
                or not request.baseline_evidence_id
                or not request.source_execution_id
            ):
                raise ValueError("Passed parity requires an attributable SAS-executed baseline")
            if (
                request.validation_kind in _PARITY_KINDS
                and request.baseline_evidence_id
                not in qualification["policy_snapshot"]["baseline_evidence_ids"]
            ):
                raise ValueError("Passed parity baseline is not declared by the qualified policy")
            if request.validation_kind in _PARITY_KINDS:
                matches = [
                    item
                    for item in qualification["policy_snapshot"]["baseline_evidence"]
                    if item["evidence_id"] == request.baseline_evidence_id
                    and item["evidence_origin"] == request.evidence_origin
                    and item["source_execution_id"] == request.source_execution_id
                    and item["authoritative"]
                    and item["deterministic"]
                ]
                if len(matches) != 1:
                    raise ValueError("Passed parity evidence is not exactly bound to qualification")
    for check in request.checks:
        if set(check) != {"check_id", "status", "evidence"}:
            raise ValueError("Corpus validation check has malformed fields")
        if check["status"] not in _CHECK_STATUSES or not check["check_id"]:
            raise ValueError("Corpus validation check has unsupported identity or status")
        if not isinstance(check["evidence"], dict) or not check["evidence"]:
            raise ValueError("Corpus validation check requires concrete evidence")
    if (
        stage == RegressionStage.VALIDATION
        and status == StageStatus.PASSED
        and request.validation_kind == "static"
    ):
        conversion_path = qualification_file.parent / "stage-conversion.json"
        if not conversion_path.is_file():
            raise ValueError("Passed static validation requires canonical conversion evidence")
        conversion = _load_stages(qualification_file).get("conversion")
        if conversion is None:
            raise ValueError("Passed static validation requires canonical conversion evidence")
        generated = [
            item
            for item in conversion["artifacts"]
            if item["sha256"] == request.input_artifact_digest
        ]
        if len(generated) != 1:
            raise ValueError("Static validation input does not identify one generated artifact")
        generated_path = _bound_attempt_path(
            qualification_file.parent, generated[0]["artifact_uri"], "stage artifact"
        )
        if qualification["target"] == "pyspark":
            try:
                ast.parse(generated_path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise ValueError("Passed static validation assertion is not reproducible") from exc
        elif not generated_path.read_bytes().strip():
            raise ValueError("Passed static validation assertion is not reproducible")
    artifact_records = _copy_stage_artifacts(
        qualification_file.parent, request, target=qualification["target"]
    )
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
            "manifest_digest",
            "source_id",
        )
    }
    sanitized_checks = sanitize_discovery_value(list(request.checks))
    sanitized_reasons = sanitize_discovery_value(list(request.reasons))
    assert isinstance(sanitized_checks, list)
    assert isinstance(sanitized_reasons, list)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "stage_id": "pending",
        **identity,
        "stage": stage.value,
        "status": status.value,
        "provider": request.provider,
        "provider_version": request.provider_version,
        "execution_id": request.execution_id,
        "decision_id": request.decision_id,
        "input_artifact_digest": request.input_artifact_digest,
        "validation_kind": request.validation_kind,
        "checks": sanitized_checks,
        "evidence_origin": request.evidence_origin,
        "baseline_evidence_id": request.baseline_evidence_id,
        "source_execution_id": request.source_execution_id,
        "producer_evidence": canonical_producer_evidence,
        "artifacts": artifact_records,
        "reasons": sanitized_reasons,
    }
    payload["stage_id"] = stable_id(
        "CRS",
        {
            key: value
            for key, value in payload.items()
            if key not in {"schema_version", "stage_id", "reasons"}
        },
    )
    payload["content_digest"] = _digest_value(payload)
    path = qualification_file.parent / f"stage-{stage.value}.json"
    _publish_json(path, payload)
    return path


def _load_stages(qualification_file: Path) -> dict[str, dict[str, Any]]:
    stages: dict[str, dict[str, Any]] = {}
    qualification = _load_content_digested(qualification_file)
    binding_fields = (
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
        "manifest_digest",
        "source_id",
    )
    for path in sorted(qualification_file.parent.glob("stage-*.json")):
        stage = _load_content_digested(path)
        RegressionStage(stage["stage"])
        StageStatus(stage["status"])
        if any(stage.get(field) != qualification[field] for field in binding_fields):
            raise ValueError("Corpus stage evidence is not bound to qualification")
        if stage["stage"] in stages:
            raise ValueError(f"Duplicate corpus stage identity: {stage['stage']}")
        for artifact in stage["artifacts"]:
            evidence_path = _bound_attempt_path(
                qualification_file.parent, artifact["artifact_uri"], "stage artifact"
            )
            if not evidence_path.is_file() or sha256_file(evidence_path) != artifact["sha256"]:
                raise ValueError("Corpus stage artifact evidence is missing or changed")
        stage_identity = {
            key: value
            for key, value in stage.items()
            if key not in {"schema_version", "stage_id", "content_digest", "reasons"}
        }
        if stage["stage_id"] != stable_id("CRS", stage_identity):
            raise ValueError("Corpus stage identity is not derived from its bound evidence")
        stages[stage["stage"]] = stage
    return stages


def _derive_outcome(
    qualification: dict[str, Any], stages: dict[str, dict[str, Any]]
) -> tuple[list[str], str, dict[str, bool]]:
    if qualification.get("status") == "blocked":
        return (
            [],
            "blocked",
            {
                "generated": False,
                "executed": False,
                "validated": False,
                "parity_passed": False,
                "golden_matched": False,
                "human_assisted": False,
                "blocked": True,
            },
        )
    if qualification.get("status") != "admitted":
        raise ValueError("Corpus qualification has unsupported status")
    declared = set(qualification["policy_snapshot"]["stages"]) - {"admission"}
    stage_for_declared = {
        "conversion": "conversion",
        "execution": "execution",
        "static-validation": "validation",
        "parity-validation": "validation",
        "golden-comparison": "golden-comparison",
    }
    missing = sorted(item for item in declared if stage_for_declared[item] not in stages)
    conversion = stages.get("conversion")
    execution = stages.get("execution")
    validation = stages.get("validation")
    generated = bool(conversion and conversion["status"] == "passed" and conversion["artifacts"])
    executed = bool(execution and execution["status"] == "passed" and execution["execution_id"])
    conversion_digests = (
        {item["sha256"] for item in conversion["artifacts"]} if conversion is not None else set()
    )
    validated = bool(
        validation
        and validation["status"] == "passed"
        and validation["validation_kind"] == qualification["policy_snapshot"]["validation_kind"]
        and validation["checks"]
        and all(item["status"] == "pass" for item in validation["checks"])
        and generated
        and validation["input_artifact_digest"] in conversion_digests
    )
    parity_passed = bool(
        validated
        and validation is not None
        and validation["validation_kind"] in _PARITY_KINDS
        and validation["evidence_origin"] == "sas-executed-baseline"
        and validation["baseline_evidence_id"]
        in qualification["policy_snapshot"]["baseline_evidence_ids"]
        and validation["source_execution_id"]
    )
    golden_comparison = stages.get("golden-comparison")
    golden_matched = bool(
        qualification.get("golden_contract_digest")
        and golden_comparison
        and golden_comparison["status"] == "passed"
        and golden_comparison["decision_id"]
    )
    statuses = {item["status"] for item in stages.values()}
    if "human_denied" in statuses:
        terminal = "human_denied"
    elif "human_pending" in statuses:
        terminal = "human_pending"
    elif "cancelled" in statuses:
        terminal = "cancelled"
    elif "failed" in statuses:
        terminal = "failed"
    elif "unsupported" in statuses:
        terminal = "unsupported"
    elif missing or statuses & {"blocked", "skipped"}:
        terminal = "blocked"
    elif declared and all(
        stages[stage_for_declared[item]]["status"] == "passed" for item in declared
    ):
        terminal = "passed"
    else:
        terminal = "blocked"
    return (
        missing,
        terminal,
        {
            "generated": generated,
            "executed": executed,
            "validated": validated,
            "parity_passed": parity_passed,
            "golden_matched": golden_matched,
            "human_assisted": False,
            "blocked": terminal
            in {"blocked", "unsupported", "human_pending", "human_denied", "cancelled"},
        },
    )


def finalize_corpus_regression(qualification_file: Path) -> Path:
    """Derive terminal outcome and competition telemetry from canonical evidence."""

    qualification = _load_content_digested(qualification_file)
    if qualification.get("status") == "blocked":
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
                "manifest_digest",
                "source_id",
                "evidence_scope",
                "environment",
            )
        }
        telemetry = {
            "generated": False,
            "executed": False,
            "validated": False,
            "parity_passed": False,
            "golden_matched": False,
            "human_assisted": False,
            "blocked": True,
        }
        blocked_result: dict[str, Any] = {
            "schema_version": 1,
            "result_id": stable_id("CRR", {**identity, "blockers": qualification["blockers"]}),
            **identity,
            "stage_ids": [],
            "missing_stages": [],
            "terminal_disposition": "blocked",
            "telemetry": telemetry,
        }
        blocked_result["content_digest"] = _digest_value(blocked_result)
        validate_corpus_regression_result(blocked_result)
        result_path = qualification_file.parent / "result.json"
        _publish_json(result_path, blocked_result)
        event = {
            "schema_version": 1,
            "event_id": stable_id("CRT", {"result_id": blocked_result["result_id"]}),
            "result_id": blocked_result["result_id"],
            **identity,
            "terminal_disposition": "blocked",
            **telemetry,
        }
        _publish_json(qualification_file.parent / "telemetry.json", event)
        return result_path
    qualification = verify_corpus_snapshot(qualification_file)
    stages = _load_stages(qualification_file)
    missing, terminal, telemetry = _derive_outcome(qualification, stages)
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
            "manifest_digest",
            "source_id",
            "evidence_scope",
            "environment",
        )
    }
    payload: dict[str, Any] = {
        "schema_version": 1,
        "result_id": stable_id(
            "CRR",
            {**identity, "stage_ids": sorted(item["stage_id"] for item in stages.values())},
        ),
        **identity,
        "stage_ids": sorted(item["stage_id"] for item in stages.values()),
        "missing_stages": missing,
        "terminal_disposition": terminal,
        "telemetry": telemetry,
    }
    payload["content_digest"] = _digest_value(payload)
    validate_corpus_regression_result(payload)
    result_path = qualification_file.parent / "result.json"
    _publish_json(result_path, payload)
    # Telemetry is a derived projection. Retry repairs it without reevaluating stages.
    event = {
        "schema_version": 1,
        "event_id": stable_id("CRT", {"result_id": payload["result_id"]}),
        "result_id": payload["result_id"],
        **identity,
        "terminal_disposition": terminal,
        **telemetry,
    }
    _publish_json(qualification_file.parent / "telemetry.json", event)
    return result_path


def load_corpus_regression_result(path: Path) -> dict[str, Any]:
    """Load a terminal result only when its complete canonical chain verifies."""

    if path.name != "result.json":
        raise ValueError("Corpus result must use its canonical attempt filename")
    payload = _load_content_digested(path)
    validate_corpus_regression_result(payload)
    qualification_file = path.with_name("qualification.json")
    if not qualification_file.is_file():
        raise ValueError("Corpus result lacks its canonical qualification evidence")
    qualification = _load_content_digested(qualification_file)
    if qualification.get("status") == "admitted":
        verify_corpus_snapshot(qualification_file)
        stages = _load_stages(qualification_file)
    elif qualification.get("status") == "blocked":
        stages = _load_stages(qualification_file)
        if stages:
            raise ValueError("Blocked corpus qualification cannot have stage evidence")
    else:
        raise ValueError("Corpus result qualification has unsupported status")
    if qualification["status"] == "admitted":
        expected_qualification_id = stable_id(
            "CRQ",
            {
                "scenario_id": qualification["scenario_id"],
                "workload_id": qualification["workload_id"],
                "subject_id": qualification["subject_id"],
                "run_id": qualification["run_id"],
                "attempt_id": qualification["attempt_id"],
                "manifest_digest": qualification["manifest_digest"],
                "source_id": qualification["source_id"],
                "bundle_digest": qualification["bundle_digest"],
                "policy_digest": qualification["policy_digest"],
                "golden_contract_digest": qualification["golden_contract_digest"],
            },
        )
    else:
        expected_qualification_id = stable_id(
            "CRQ",
            {
                "scenario_id": qualification["scenario_id"],
                "workload_id": qualification["workload_id"],
                "subject_id": qualification["subject_id"],
                "run_id": qualification["run_id"],
                "attempt_id": qualification["attempt_id"],
                "manifest_digest": qualification["manifest_digest"],
                "blockers": qualification["blockers"],
            },
        )
    if qualification["qualification_id"] != expected_qualification_id:
        raise ValueError("Corpus qualification identity is not derived from canonical evidence")
    identity_fields = (
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
        "manifest_digest",
        "source_id",
        "evidence_scope",
        "environment",
    )
    if any(payload.get(field) != qualification.get(field) for field in identity_fields):
        raise ValueError("Corpus result is not bound to its canonical qualification")
    expected_stage_ids = sorted(item["stage_id"] for item in stages.values())
    if payload["stage_ids"] != expected_stage_ids:
        raise ValueError("Corpus result stage identities do not match canonical stage evidence")
    missing, terminal, telemetry = _derive_outcome(qualification, stages)
    if (
        payload["missing_stages"] != missing
        or payload["terminal_disposition"] != terminal
        or payload["telemetry"] != telemetry
    ):
        raise ValueError("Corpus result outcome is not derived from canonical evidence")
    result_material = {field: qualification[field] for field in identity_fields}
    if qualification["status"] == "blocked":
        expected_result_id = stable_id(
            "CRR", {**result_material, "blockers": qualification["blockers"]}
        )
    else:
        expected_result_id = stable_id("CRR", {**result_material, "stage_ids": expected_stage_ids})
    if payload["result_id"] != expected_result_id:
        raise ValueError("Corpus result identity is not derived from canonical evidence")
    telemetry_path = path.with_name("telemetry.json")
    if not telemetry_path.is_file():
        raise ValueError("Corpus result lacks its canonical telemetry projection")
    telemetry_event = json.loads(telemetry_path.read_text(encoding="utf-8"))
    expected_event = {
        "schema_version": 1,
        "event_id": stable_id("CRT", {"result_id": payload["result_id"]}),
        "result_id": payload["result_id"],
        **{field: qualification[field] for field in identity_fields},
        "terminal_disposition": terminal,
        **telemetry,
    }
    if telemetry_event != expected_event:
        raise ValueError("Corpus telemetry is not derived from canonical result evidence")
    return payload
