"""Load and validate corpus manifests."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml

from smf.corpus.models import (
    CorpusArtifact,
    CorpusArtifactRelationship,
    CorpusDataFixture,
    CorpusDependencyExpectation,
    CorpusGoldenExpectation,
    CorpusManifest,
    CorpusOutputEvidence,
    CorpusRegressionDefinition,
    CorpusRegressionSubject,
    CorpusSemanticColumn,
    CorpusSemanticOracle,
    CorpusSemanticSession,
    CorpusSourceRef,
    CorpusValidationPolicyRef,
    CorpusWorkloadDefinition,
)
from smf.discovery.sas_lexical import iter_unquoted_matches
from smf.discovery.sas_static import _strip_comments
from smf.workload.sanitization import sanitize_discovery_value

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "corpus-manifest.schema.json"
_LITERAL_FILE_DEPENDENCY_RE = re.compile(
    r"(?:%include|\binfile|\bfile)\s+(?:'([^']+)'|\"([^\"]+)\"|([^;\s]+))",
    re.IGNORECASE,
)
_PROTECTED_DATA_CANARY_RE = re.compile(r"(?i)secret[-_ ]?canary|phi[-_ ]?canary|pii[-_ ]?canary")


def _literal_file_dependencies(source: Path, workload_root: Path) -> tuple[Path, ...]:
    """Resolve literal include/data references without trusting manifest edges."""

    text = _strip_comments(source.read_text(encoding="utf-8"))
    resolved: set[Path] = set()
    for match in iter_unquoted_matches(_LITERAL_FILE_DEPENDENCY_RE, text):
        value = next(item for item in match.groups() if item)
        if "&" in value or "%" in value or value.lower() in {"cards", "datalines"}:
            continue
        raw = Path(value)
        if raw.is_absolute():
            raise ValueError(f"Corpus literal dependency escapes workload root: {value}")
        candidates = {
            (source.parent / raw).resolve(),
            (workload_root / raw).resolve(),
        }
        inside = {item for item in candidates if item.is_relative_to(workload_root)}
        existing = {item for item in inside if item.is_file()}
        if len(existing) != 1:
            raise ValueError(
                f"Corpus literal dependency is missing or ambiguous for {source}: {value}"
            )
        resolved.update(existing)
    return tuple(sorted(resolved))


def _read_schema(schema_path: Path | None = None) -> dict[str, Any]:
    path = schema_path or _SCHEMA_PATH
    with path.open(encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def validate_corpus_manifest(payload: dict[str, Any], schema_path: Path | None = None) -> None:
    """Validate a decoded manifest against the corpus JSON schema."""

    jsonschema.validate(instance=payload, schema=_read_schema(schema_path))


def sha256_file(path: Path) -> str:
    """Return a stable SHA-256 fingerprint for a corpus artifact."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_corpus_manifest(
    path: Path,
    *,
    verify_files: bool = True,
    schema_path: Path | None = None,
    allow_private: bool = False,
) -> CorpusManifest:
    """Load a corpus YAML manifest and optionally verify its artifact fingerprints."""

    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)

    if not isinstance(raw, dict):
        raise ValueError(f"Corpus manifest must contain a mapping: {path}")

    payload = cast(dict[str, Any], raw)
    validate_corpus_manifest(payload, schema_path=schema_path)

    root = path.parent
    source_raw = cast(dict[str, Any], payload["source"])
    if str(source_raw["origin"]) == "private-client" and not allow_private:
        raise ValueError(
            "Private client corpus cannot be loaded through the shared corpus loader; "
            "use load_private_corpus_manifest with an explicit client policy"
        )

    source = CorpusSourceRef(
        source_id=str(source_raw["source_id"]),
        origin=str(source_raw["origin"]),
        license=str(source_raw["license"]),
        upstream_url=cast(str | None, source_raw.get("upstream_url")),
        upstream_ref=cast(str | None, source_raw.get("upstream_ref")),
        notes=cast(str | None, source_raw.get("notes")),
    )

    artifacts: list[CorpusArtifact] = []
    artifact_paths_seen: set[Path] = set()
    for artifact_raw_value in cast(list[dict[str, Any]], payload.get("artifacts", [])):
        artifact_path = root / str(artifact_raw_value["path"])
        resolved_artifact_path = artifact_path.resolve()
        if resolved_artifact_path in artifact_paths_seen:
            raise ValueError(f"Duplicate corpus artifact path: {artifact_path}")
        artifact_paths_seen.add(resolved_artifact_path)
        declared_sha = cast(str | None, artifact_raw_value.get("sha256"))
        if verify_files:
            if not artifact_path.is_file():
                raise FileNotFoundError(f"Corpus artifact not found: {artifact_path}")
            actual_sha = sha256_file(artifact_path)
            if declared_sha and actual_sha != declared_sha:
                raise ValueError(
                    f"Corpus artifact fingerprint mismatch for {artifact_path}: "
                    f"expected {declared_sha}, got {actual_sha}"
                )
        artifacts.append(
            CorpusArtifact(
                path=artifact_path,
                role=str(artifact_raw_value["role"]),
                sha256=declared_sha,
                source_id=cast(str | None, artifact_raw_value.get("source_id")),
                upstream_path=cast(str | None, artifact_raw_value.get("upstream_path")),
            )
        )

    data_fixtures: list[CorpusDataFixture] = []
    fixture_ids: set[str] = set()
    artifact_by_path = {artifact.path.resolve(): artifact for artifact in artifacts}
    for fixture_raw in cast(list[dict[str, Any]], payload.get("data_fixtures", [])):
        fixture_id = str(fixture_raw["fixture_id"])
        if fixture_id in fixture_ids:
            raise ValueError(f"Duplicate corpus data fixture id: {fixture_id}")
        fixture_ids.add(fixture_id)
        artifact_path = root / str(fixture_raw["artifact"])
        artifact = artifact_by_path.get(artifact_path.resolve())
        if artifact is None:
            raise ValueError(
                f"Corpus data fixture references artifact not declared in manifest: {artifact_path}"
            )
        if artifact.role != "input-data":
            raise ValueError(
                f"Corpus data fixture artifact must have role input-data: {artifact_path}"
            )
        if bool(fixture_raw.get("contains_private_data", False)):
            raise ValueError(
                f"Corpus synthetic data fixture must not contain private data: {fixture_id}"
            )
        data_fixtures.append(
            CorpusDataFixture(
                fixture_id=fixture_id,
                dataset=str(fixture_raw["dataset"]),
                artifact_path=artifact_path,
                format=str(fixture_raw["format"]),
                deterministic=bool(fixture_raw.get("deterministic", True)),
                contains_private_data=False,
            )
        )

    output_evidence: list[CorpusOutputEvidence] = []
    evidence_ids: set[str] = set()
    for evidence_raw in cast(list[dict[str, Any]], payload.get("output_evidence", [])):
        evidence_id = str(evidence_raw["evidence_id"])
        if evidence_id in evidence_ids:
            raise ValueError(f"Duplicate corpus output evidence id: {evidence_id}")
        evidence_ids.add(evidence_id)
        artifact_path = root / str(evidence_raw["artifact"])
        artifact = artifact_by_path.get(artifact_path.resolve())
        if artifact is None:
            raise ValueError(
                "Corpus output evidence references artifact not declared in manifest: "
                f"{artifact_path}"
            )
        if artifact.role != "expected-output":
            raise ValueError(
                f"Corpus output evidence artifact must have role expected-output: {artifact_path}"
            )
        content_hash = str(evidence_raw["content_hash"])
        if artifact.sha256 is None:
            raise ValueError(
                f"Corpus output evidence artifact must declare sha256: {artifact_path}"
            )
        if content_hash != artifact.sha256:
            raise ValueError(
                "Corpus output evidence content hash does not match artifact sha256: "
                f"{artifact_path}"
            )
        origin = str(evidence_raw["evidence_origin"])
        execution_id = cast(str | None, evidence_raw.get("source_execution_id"))
        if origin == "sas-executed-baseline" and not execution_id:
            raise ValueError(f"SAS-executed baseline requires source_execution_id: {evidence_id}")
        output_evidence.append(
            CorpusOutputEvidence(
                evidence_id=evidence_id,
                logical_output=str(evidence_raw["logical_output"]),
                artifact_path=artifact_path,
                format=str(evidence_raw["format"]),
                evidence_origin=origin,
                producer=str(evidence_raw["producer"]),
                content_hash=content_hash,
                deterministic=bool(evidence_raw["deterministic"]),
                authoritative=bool(evidence_raw["authoritative"]),
                source_execution_id=execution_id,
            )
        )

    semantic_oracles: list[CorpusSemanticOracle] = []
    oracle_ids: set[str] = set()
    evidence_by_id = {item.evidence_id: item for item in output_evidence}
    for oracle_raw in cast(list[dict[str, Any]], payload.get("semantic_oracles", [])):
        oracle_id = str(oracle_raw["oracle_id"])
        if oracle_id in oracle_ids:
            raise ValueError(f"Duplicate corpus semantic oracle id: {oracle_id}")
        oracle_ids.add(oracle_id)
        evidence_id = str(oracle_raw["evidence_id"])
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            raise ValueError(f"Semantic oracle references unknown output evidence: {evidence_id}")
        if not evidence.authoritative or not evidence.deterministic:
            raise ValueError(
                f"Semantic oracle evidence must be authoritative and deterministic: {evidence_id}"
            )
        if evidence.format != "json":
            raise ValueError(f"Semantic oracle evidence must use canonical JSON: {evidence_id}")
        if evidence.logical_output != str(oracle_raw["logical_output"]):
            raise ValueError(f"Semantic oracle logical output does not match evidence: {oracle_id}")
        comparison = str(oracle_raw["comparison"])
        keys = tuple(str(item) for item in oracle_raw.get("keys", []))
        if comparison == "keyed" and not keys:
            raise ValueError(f"Keyed semantic oracle requires keys: {oracle_id}")
        if comparison != "keyed" and keys:
            raise ValueError(f"Only keyed semantic oracles may declare keys: {oracle_id}")
        columns = tuple(
            CorpusSemanticColumn(
                name=str(item["name"]),
                logical_type=str(item["logical_type"]),
                nullable=bool(item["nullable"]),
                length=cast(int | None, item.get("length")),
                absolute_tolerance=float(item.get("absolute_tolerance", 0.0)),
                relative_tolerance=float(item.get("relative_tolerance", 0.0)),
            )
            for item in cast(list[dict[str, Any]], oracle_raw["columns"])
        )
        column_names = [item.name for item in columns]
        if len(column_names) != len(set(column_names)):
            raise ValueError(f"Semantic oracle has duplicate column names: {oracle_id}")
        if any(key not in column_names for key in keys):
            raise ValueError(f"Semantic oracle key is not a declared column: {oracle_id}")
        session_raw = cast(dict[str, Any], oracle_raw["session"])
        semantic_oracles.append(
            CorpusSemanticOracle(
                oracle_id=oracle_id,
                logical_output=str(oracle_raw["logical_output"]),
                evidence_id=evidence_id,
                comparison=comparison,
                keys=keys,
                columns=columns,
                authoritative_values=str(oracle_raw.get("authoritative_values", "underlying")),
                session=CorpusSemanticSession(
                    yearcutoff=int(session_raw["yearcutoff"]),
                    locale=str(session_raw["locale"]),
                    encoding=str(session_raw["encoding"]),
                    sort_sequence=str(session_raw["sort_sequence"]),
                    timezone=str(session_raw["timezone"]),
                ),
                behavior=str(oracle_raw["behavior"]),
            )
        )

    if semantic_oracles:
        if source.origin != "smf":
            raise ValueError("Semantic oracle fixtures must be SMF-authored")
        if bool(cast(dict[str, Any], payload.get("metadata", {})).get("private_data", False)):
            raise ValueError("Semantic oracle fixtures must not contain private data")

    dependency_expectations: list[CorpusDependencyExpectation] = []
    dependency_expectation_ids: set[str] = set()
    for expectation_raw in cast(list[dict[str, Any]], payload.get("dependency_expectations", [])):
        expectation_id = str(expectation_raw["expectation_id"])
        if expectation_id in dependency_expectation_ids:
            raise ValueError(f"Duplicate corpus dependency expectation id: {expectation_id}")
        dependency_expectation_ids.add(expectation_id)
        source_path = root / str(expectation_raw["source"])
        if source_path.resolve() not in artifact_by_path:
            raise ValueError(
                f"Corpus dependency expectation source is not a declared artifact: {source_path}"
            )
        resolution = str(expectation_raw["resolution"])
        target_value = cast(str | None, expectation_raw.get("target"))
        unresolved_reference = cast(str | None, expectation_raw.get("unresolved_reference"))
        target_path = root / target_value if target_value is not None else None
        if resolution == "resolved":
            if target_path is None or unresolved_reference is not None:
                raise ValueError(
                    f"Resolved dependency expectation requires only target: {expectation_id}"
                )
            if target_path.resolve() not in artifact_by_path:
                raise ValueError(
                    "Resolved corpus dependency expectation target is not a declared artifact: "
                    f"{target_path}"
                )
        elif target_path is not None or not unresolved_reference:
            raise ValueError(
                "Unresolved dependency expectation requires only unresolved_reference: "
                f"{expectation_id}"
            )
        dependency_expectations.append(
            CorpusDependencyExpectation(
                expectation_id=expectation_id,
                source_path=source_path,
                relationship=str(expectation_raw["relationship"]),
                resolution=resolution,
                evidence_method=str(expectation_raw["evidence_method"]),
                target_path=target_path,
                unresolved_reference=unresolved_reference,
            )
        )

    workload: CorpusWorkloadDefinition | None = None
    workload_raw_value = payload.get("workload")
    if workload_raw_value is not None:
        workload_raw = cast(dict[str, Any], workload_raw_value)
        artifact_paths = {artifact.path.resolve() for artifact in artifacts}
        entrypoints = tuple(root / str(item) for item in workload_raw["entrypoints"])
        relationships = tuple(
            CorpusArtifactRelationship(
                source_path=root / str(item["source"]),
                target_path=root / str(item["target"]),
                relationship=str(item["relationship"]),
            )
            for item in cast(list[dict[str, Any]], workload_raw.get("relationships", []))
        )
        referenced_paths = set(entrypoints)
        referenced_paths.update(item.source_path for item in relationships)
        referenced_paths.update(item.target_path for item in relationships)
        unknown = sorted(
            str(item) for item in referenced_paths if item.resolve() not in artifact_paths
        )
        if unknown:
            raise ValueError(
                "Corpus workload references artifacts not declared in manifest: "
                + ", ".join(unknown)
            )
        workload_root = (root / str(workload_raw["root"])).resolve()
        if verify_files and not workload_root.is_dir():
            raise FileNotFoundError(f"Corpus workload root not found: {workload_root}")
        escaped = sorted(
            str(path) for path in artifact_paths if not path.is_relative_to(workload_root)
        )
        if escaped:
            raise ValueError(
                "Corpus workload artifact escapes workload root: " + ", ".join(escaped)
            )
        workload = CorpusWorkloadDefinition(
            root=workload_root,
            entrypoints=entrypoints,
            relationships=relationships,
        )

    regression: CorpusRegressionDefinition | None = None
    regression_raw_value = payload.get("regression")
    if regression_raw_value is not None:
        if workload is None:
            raise ValueError("Corpus regression subjects require a workload definition")
        regression_raw = cast(dict[str, Any], regression_raw_value)
        artifact_by_resolved_path = {artifact.path.resolve(): artifact for artifact in artifacts}
        entrypoint_paths = {path.resolve() for path in workload.entrypoints}
        subject_ids: set[str] = set()
        subjects: list[CorpusRegressionSubject] = []
        golden_ids: set[str] = set()
        for subject_raw in cast(list[dict[str, Any]], regression_raw["subjects"]):
            subject_id = str(subject_raw["subject_id"])
            if subject_id in subject_ids:
                raise ValueError(f"Duplicate corpus regression subject id: {subject_id}")
            subject_ids.add(subject_id)
            entrypoint = (root / str(subject_raw["entrypoint"])).resolve()
            matches = [
                artifact
                for artifact in artifacts
                if artifact.path.resolve() == entrypoint and artifact.role == "sas-program"
            ]
            if len(matches) != 1 or entrypoint not in entrypoint_paths:
                raise ValueError(
                    "Corpus regression entrypoint must resolve to exactly one declared "
                    f"sas-program workload entrypoint: {subject_id}"
                )
            source_closure = tuple(
                (root / str(item)).resolve()
                for item in cast(list[str], subject_raw["source_closure"])
            )
            if len(source_closure) != len(set(source_closure)):
                raise ValueError(
                    f"Duplicate path in corpus regression source closure: {subject_id}"
                )
            if entrypoint not in source_closure:
                raise ValueError(f"Corpus regression source closure omits entrypoint: {subject_id}")
            unknown_closure = [
                path for path in source_closure if path not in artifact_by_resolved_path
            ]
            if unknown_closure:
                raise ValueError(
                    "Corpus regression source closure references undeclared artifacts: "
                    + ", ".join(str(path) for path in unknown_closure)
                )
            escaped_closure = [
                path for path in source_closure if not path.is_relative_to(workload.root)
            ]
            if escaped_closure:
                raise ValueError(
                    "Corpus regression source closure escapes workload root: "
                    + ", ".join(str(path) for path in escaped_closure)
                )
            closure_set = set(source_closure)
            incomplete = [
                relationship
                for relationship in workload.relationships
                if relationship.source_path.resolve() in closure_set
                and relationship.target_path.resolve() not in closure_set
            ]
            if incomplete:
                raise ValueError(
                    "Corpus regression source closure omits declared relationship targets: "
                    + ", ".join(str(item.target_path) for item in incomplete)
                )
            if verify_files:
                discovered_dependencies: set[Path] = set()
                for closure_path in source_closure:
                    artifact = artifact_by_resolved_path[closure_path]
                    if artifact.role in {"sas-program", "sas-include", "sas-macro"}:
                        discovered_dependencies.update(
                            _literal_file_dependencies(closure_path, workload.root)
                        )
                omitted_dependencies = sorted(discovered_dependencies - closure_set)
                if omitted_dependencies:
                    raise ValueError(
                        "Corpus regression source closure omits literal dependency targets: "
                        + ", ".join(str(item) for item in omitted_dependencies)
                    )
            if verify_files:
                if entrypoint.stat().st_size == 0 or not entrypoint.read_bytes().strip():
                    raise ValueError(f"Corpus regression entrypoint is empty: {subject_id}")
                for closure_path in source_closure:
                    if artifact_by_resolved_path[closure_path].path.is_symlink():
                        raise ValueError(
                            "Corpus regression source closure may not contain symlinks: "
                            f"{closure_path}"
                        )
            subject_oracle_ids = tuple(str(item) for item in subject_raw.get("oracle_ids", []))
            baseline_ids = tuple(str(item) for item in subject_raw.get("baseline_evidence_ids", []))
            known_oracles = {item.oracle_id for item in semantic_oracles}
            evidence_by_id = {item.evidence_id: item for item in output_evidence}
            known_evidence = set(evidence_by_id)
            if set(subject_oracle_ids) - known_oracles:
                raise ValueError(
                    f"Corpus regression subject references unknown oracle: {subject_id}"
                )
            if set(baseline_ids) - known_evidence:
                raise ValueError(
                    f"Corpus regression subject references unknown baseline evidence: {subject_id}"
                )
            policy_raw = cast(dict[str, Any], subject_raw["validation_policy"])
            validation_kind = str(policy_raw["validation_kind"])
            if validation_kind != "static" and not (subject_oracle_ids or baseline_ids):
                raise ValueError(
                    "Corpus parity validation requires bound oracle or baseline evidence: "
                    f"{subject_id}"
                )
            if validation_kind != "static" and baseline_ids:
                invalid_baselines = [
                    evidence_id
                    for evidence_id in baseline_ids
                    if (
                        evidence_by_id[evidence_id].evidence_origin != "sas-executed-baseline"
                        or not evidence_by_id[evidence_id].authoritative
                        or not evidence_by_id[evidence_id].deterministic
                        or not evidence_by_id[evidence_id].source_execution_id
                        or evidence_by_id[evidence_id].artifact_path.resolve() not in closure_set
                    )
                ]
                if invalid_baselines:
                    raise ValueError(
                        "Corpus parity baselines must be authoritative, SAS-executed, "
                        "deterministic, and included in the qualified closure: "
                        + ", ".join(invalid_baselines)
                    )
            stages = tuple(str(item) for item in subject_raw["stages"])
            if "admission" not in stages:
                raise ValueError(f"Corpus regression stages must include admission: {subject_id}")
            if "parity-validation" in stages and validation_kind == "static":
                raise ValueError(
                    f"Static validation policy cannot declare parity-validation: {subject_id}"
                )
            golden: CorpusGoldenExpectation | None = None
            golden_raw_value = subject_raw.get("golden")
            if golden_raw_value is not None:
                golden_raw = cast(dict[str, Any], golden_raw_value)
                golden_id = str(golden_raw["golden_id"])
                if golden_id in golden_ids:
                    raise ValueError(f"Duplicate corpus golden id: {golden_id}")
                golden_ids.add(golden_id)
                if "golden-comparison" not in stages:
                    raise ValueError(
                        f"Corpus golden subject must declare golden-comparison: {subject_id}"
                    )
                expected_disposition = str(golden_raw["expected_disposition"])
                artifact_value = cast(str | None, golden_raw.get("artifact"))
                golden_artifact_path = (root / artifact_value).resolve() if artifact_value else None
                if expected_disposition == "generated":
                    if golden_artifact_path is None:
                        raise ValueError(
                            f"Generated corpus golden requires an expected artifact: {golden_id}"
                        )
                    artifact = artifact_by_resolved_path.get(golden_artifact_path)
                    if artifact is None or artifact.role != "expected-conversion":
                        raise ValueError(
                            "Corpus golden artifact must be declared with role "
                            f"expected-conversion: {golden_id}"
                        )
                    if artifact.sha256 is None:
                        raise ValueError(f"Corpus golden artifact must declare sha256: {golden_id}")
                    if verify_files and (
                        golden_artifact_path.stat().st_size == 0
                        or not golden_artifact_path.read_bytes().strip()
                    ):
                        raise ValueError(f"Corpus golden artifact is empty: {golden_id}")
                    expected_suffix = ".py" if str(subject_raw["target"]) == "pyspark" else ".sql"
                    if golden_artifact_path.suffix != expected_suffix:
                        raise ValueError(
                            f"Corpus golden artifact suffix does not match target: {golden_id}"
                        )
                elif golden_artifact_path is not None:
                    raise ValueError(
                        f"Non-generated corpus golden must not declare an artifact: {golden_id}"
                    )
                golden = CorpusGoldenExpectation(
                    golden_id=golden_id,
                    golden_version=str(golden_raw["golden_version"]),
                    expected_disposition=expected_disposition,
                    comparison_mode=str(golden_raw["comparison_mode"]),
                    provider_id=str(golden_raw["provider_id"]),
                    provider_version=str(golden_raw["provider_version"]),
                    strategy_id=str(golden_raw["strategy_id"]),
                    strategy_version=str(golden_raw["strategy_version"]),
                    behavioral_expectation_id=cast(
                        str | None, golden_raw.get("behavioral_expectation_id")
                    ),
                    behavioral_evidence_digest=cast(
                        str | None, golden_raw.get("behavioral_evidence_digest")
                    ),
                    rationale=str(golden_raw["rationale"]),
                    review_reference=str(golden_raw["review_reference"]),
                    fixture_classification=str(golden_raw["fixture_classification"]),
                    artifact_path=golden_artifact_path,
                )
                golden_identity = {
                    "golden_id": golden.golden_id,
                    "provider_id": golden.provider_id,
                    "provider_version": golden.provider_version,
                    "strategy_id": golden.strategy_id,
                    "strategy_version": golden.strategy_version,
                    "behavioral_expectation_id": golden.behavioral_expectation_id,
                    "behavioral_evidence_digest": golden.behavioral_evidence_digest,
                    "review_reference": golden.review_reference,
                }
                if sanitize_discovery_value(golden_identity) != golden_identity:
                    raise ValueError("Corpus golden identity contains credential material")
                if verify_files and golden_artifact_path is not None:
                    try:
                        golden_text = golden_artifact_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError as exc:
                        raise ValueError("Corpus golden artifact must be UTF-8") from exc
                    if sanitize_discovery_value(
                        golden_text
                    ) != golden_text or _PROTECTED_DATA_CANARY_RE.search(golden_text):
                        raise ValueError("Corpus golden artifact contains credential material")
            subjects.append(
                CorpusRegressionSubject(
                    subject_id=subject_id,
                    workload_id=str(subject_raw["workload_id"]),
                    entrypoint=entrypoint,
                    target=str(subject_raw["target"]),
                    source_closure=source_closure,
                    stages=stages,
                    validation_policy=CorpusValidationPolicyRef(
                        policy_id=str(policy_raw["policy_id"]),
                        policy_version=str(policy_raw["policy_version"]),
                        validation_kind=validation_kind,
                    ),
                    evidence_scope=str(subject_raw["evidence_scope"]),
                    environment=str(subject_raw["environment"]),
                    oracle_ids=subject_oracle_ids,
                    baseline_evidence_ids=baseline_ids,
                    golden=golden,
                )
            )
        regression = CorpusRegressionDefinition(
            version=int(regression_raw["version"]), subjects=tuple(subjects)
        )

    return CorpusManifest(
        schema_version=int(payload["schema_version"]),
        scenario_id=str(payload["scenario_id"]),
        name=str(payload["name"]),
        domain=str(payload["domain"]),
        description=str(payload["description"]),
        source=source,
        capabilities=tuple(str(item) for item in payload.get("capabilities", [])),
        artifacts=tuple(artifacts),
        expected=cast(dict[str, Any], payload.get("expected", {})),
        metadata=cast(dict[str, Any], payload.get("metadata", {})),
        workload=workload,
        data_fixtures=tuple(data_fixtures),
        output_evidence=tuple(output_evidence),
        semantic_oracles=tuple(semantic_oracles),
        dependency_expectations=tuple(dependency_expectations),
        regression=regression,
    )


def load_corpus_manifest_registry(
    directory: Path, *, verify_files: bool = True
) -> tuple[CorpusManifest, ...]:
    """Load all shared manifests while rejecting ambiguous global identities."""

    if not directory.is_dir():
        raise FileNotFoundError(f"Corpus manifest registry not found: {directory}")
    manifests: list[CorpusManifest] = []
    scenario_ids: set[str] = set()
    subject_ids: set[str] = set()
    subject_entrypoints: set[Path] = set()
    golden_ids: set[str] = set()
    for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
        manifest = load_corpus_manifest(path, verify_files=verify_files)
        if manifest.scenario_id in scenario_ids:
            raise ValueError(f"Duplicate corpus scenario id: {manifest.scenario_id}")
        scenario_ids.add(manifest.scenario_id)
        if manifest.regression is not None:
            for subject in manifest.regression.subjects:
                if subject.subject_id in subject_ids:
                    raise ValueError(
                        f"Duplicate corpus regression subject id: {subject.subject_id}"
                    )
                if subject.entrypoint.resolve() in subject_entrypoints:
                    raise ValueError(
                        "Duplicate corpus regression entrypoint: " + str(subject.entrypoint)
                    )
                subject_ids.add(subject.subject_id)
                subject_entrypoints.add(subject.entrypoint.resolve())
                if subject.golden is not None:
                    if subject.golden.golden_id in golden_ids:
                        raise ValueError(f"Duplicate corpus golden id: {subject.golden.golden_id}")
                    golden_ids.add(subject.golden.golden_id)
        manifests.append(manifest)
    return tuple(manifests)
