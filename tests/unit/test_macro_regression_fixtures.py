from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from tests.macro_fixture_loader import (
    QualifiedMacroScenario,
    QualifiedSource,
    discover_qualified_macro_scenario,
    load_macro_fixture_manifest,
)

from smf.discovery import discover_source
from smf.discovery.macro_strategy import STRATEGY_DIGEST
from smf.workload.models import (
    MacroArtifactType,
    MacroObservationKind,
    MacroResolutionKind,
    RelationshipKind,
)

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "macro-regression"
MANIFEST = FIXTURE_ROOT / "manifest.json"


def _scenarios() -> tuple[QualifiedMacroScenario, ...]:
    return load_macro_fixture_manifest(MANIFEST)


def _discover(scenario: QualifiedMacroScenario):
    return discover_qualified_macro_scenario(scenario)


def _actual_summary(workload: Any) -> dict[str, Any]:
    analysis = workload.macro_analysis
    assert analysis is not None
    return {
        "complete": analysis.complete,
        "observation_kinds": dict(
            sorted(Counter(item.kind.value for item in analysis.observations).items())
        ),
        "resolution_kinds": dict(
            sorted(Counter(item.kind.value for item in analysis.resolutions).items())
        ),
        "blocker_reasons": dict(
            sorted(Counter(item.reason.value for item in analysis.blockers).items())
        ),
        "construct_families": tuple(
            sorted({item.construct_family.value for item in analysis.logical_artifacts})
        ),
        "calls_edges": sum(item.kind is RelationshipKind.CALLS for item in workload.relationships),
        "include_occurrences": sum(
            item.kind is MacroObservationKind.INCLUDE_REFERENCE for item in analysis.observations
        ),
    }


def _assert_matches(scenario: QualifiedMacroScenario, workload: Any) -> None:
    assert _actual_summary(workload) == dict(scenario.expected)


@pytest.mark.parametrize("scenario", _scenarios(), ids=lambda item: item.scenario_id)
def test_checked_in_macro_fixtures_match_fresh_static_analysis(
    scenario: QualifiedMacroScenario,
) -> None:
    first = _discover(scenario)
    second = _discover(scenario)
    _assert_matches(scenario, first)
    assert first.to_dict() == second.to_dict()

    analysis = first.macro_analysis
    assert analysis is not None
    assert analysis.strategy_digest == STRATEGY_DIGEST
    assert analysis.expansion_mode == "none"
    payload = first.to_dict()["macro_analysis"]
    assert "expanded_source" not in payload
    assert "expansion_succeeded" not in payload
    assert not {
        "generated",
        "executed",
        "validated",
        "parity_passed",
        "certified",
        "human_approved",
    } & set(payload)

    artifacts = {item.artifact_id: item for item in first.artifacts}
    expected_inventory = {
        (item.logical_path, item.metadata.get("size_bytes"), item.checksum)
        for item in first.artifacts
        if "size_bytes" in item.metadata and item.checksum is not None
    }
    assert {
        (source.relative_path, source.size, source.sha256) for source in scenario.sources
    } == expected_inventory
    assert len({item.observation_id for item in analysis.observations}) == len(
        analysis.observations
    )
    assert len({item.resolution_id for item in analysis.resolutions}) == len(analysis.resolutions)
    assert len({item.logical_artifact_id for item in analysis.logical_artifacts}) == len(
        analysis.logical_artifacts
    )
    source_by_path = {item.relative_path: item for item in scenario.sources}
    for observation in analysis.observations:
        artifact = artifacts[observation.location.source_artifact_id]
        source = source_by_path[artifact.logical_path]
        location = observation.location
        assert location.source_checksum == source.sha256
        assert location.byte_end <= source.size
        assert (
            hashlib.sha256(source.content[location.byte_start : location.byte_end]).hexdigest()
            == location.span_digest
        )


def test_positive_fixture_keeps_macro_format_and_include_evidence_separate() -> None:
    scenario = next(item for item in _scenarios() if item.category == "positive")
    workload = _discover(scenario)
    analysis = workload.macro_analysis
    assert analysis is not None
    definitions = {item.logical_artifact_id: item for item in analysis.logical_artifacts}
    observations = {item.observation_id: item for item in analysis.observations}

    common_calls = [
        item
        for item in analysis.resolutions
        if observations[item.observation_id].normalized_identity == "common"
        and observations[item.observation_id].kind is MacroObservationKind.LITERAL_INVOCATION
    ]
    assert len(common_calls) == 1
    target = definitions[common_calls[0].target_definition_id]
    assert target.artifact_type is MacroArtifactType.SAS_MACRO_DEFINITION
    assert (
        target.location.source_artifact_id
        != observations[common_calls[0].observation_id].location.source_artifact_id
    )
    assert any(
        item.artifact_type is MacroArtifactType.PROC_FORMAT_DEFINITION
        and item.normalized_identity == "common"
        for item in analysis.logical_artifacts
    )

    includes = [
        item
        for item in analysis.observations
        if item.kind is MacroObservationKind.INCLUDE_REFERENCE
    ]
    include_observation_ids = {item.observation_id for item in includes}
    include_resolutions = [
        item for item in analysis.resolutions if item.observation_id in include_observation_ids
    ]
    assert len(includes) == len(include_resolutions) == 2
    assert len({item.observation_id for item in includes}) == 2
    assert len({item.location.byte_start for item in includes}) == 2
    assert len({item.resolution_id for item in include_resolutions}) == 2
    assert {item.kind for item in include_resolutions} == {
        MacroResolutionKind.UNIQUE_STATIC_DEFINITION
    }


def test_false_positive_oracle_mutation_is_detected() -> None:
    scenario = next(
        item for item in _scenarios() if item.scenario_id == "adversarial-false-resolution"
    )
    workload = _discover(scenario)
    forged = dict(scenario.expected)
    forged["resolution_kinds"] = {"unique_static_definition": 7}
    forged_scenario = QualifiedMacroScenario(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        namespace=scenario.namespace,
        root=scenario.root,
        sources=scenario.sources,
        expected=forged,
    )
    with pytest.raises(AssertionError):
        _assert_matches(forged_scenario, workload)
    assert not any(item.kind is RelationshipKind.CALLS for item in workload.relationships)


def _copied_fixture(tmp_path: Path) -> Path:
    copied = tmp_path / "macro-regression"
    shutil.copytree(FIXTURE_ROOT, copied)
    return copied / "manifest.json"


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda data: data.update({"approved": True}), "manifest must contain exactly"),
        (
            lambda data: data["scenarios"][0]["expected"].update({"complete_claim": True}),
            "expected must contain exactly",
        ),
        (
            lambda data: data["scenarios"][0]["expected"]["resolution_kinds"].update(
                {"uniqe_static_definition": 1}
            ),
            "unsupported enum value",
        ),
        (
            lambda data: data["scenarios"][0].update({"root": "../public"}),
            "escapes its fixture boundary",
        ),
        (
            lambda data: data["scenarios"].append(dict(data["scenarios"][0])),
            "Duplicate case-folded scenario id",
        ),
        (
            lambda data: data["scenarios"].append(
                {**data["scenarios"][1], "scenario_id": "distinct-id"}
            ),
            "Duplicate case-folded scenario namespace",
        ),
        (
            lambda data: data["scenarios"][0]["non_claims"].update({"human_approval": True}),
            "cannot assert lifecycle or runtime success",
        ),
        (
            lambda data: data.update({"schema_version": True}),
            "Unsupported macro fixture manifest identity or schema version",
        ),
    ],
)
def test_fixture_manifest_rejects_attestations_unknown_types_and_ambiguous_identity(
    tmp_path: Path, mutation: Any, match: str
) -> None:
    manifest = _copied_fixture(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    mutation(data)
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_macro_fixture_manifest(manifest)


def test_fixture_qualification_rejects_drift_and_undeclared_files(tmp_path: Path) -> None:
    manifest = _copied_fixture(tmp_path)
    load_macro_fixture_manifest(manifest)
    changed = manifest.parent / "positive" / "static" / "main.sas"
    changed.write_bytes(changed.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed after review"):
        load_macro_fixture_manifest(manifest)

    manifest = _copied_fixture(tmp_path / "undeclared")
    extra = manifest.parent / "positive" / "static" / "undeclared.sas"
    extra.write_text("%macro surprise; %mend;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing or undeclared files"):
        load_macro_fixture_manifest(manifest)


def test_fixture_qualification_rejects_boundary_escaping_symlink(tmp_path: Path) -> None:
    manifest = _copied_fixture(tmp_path)
    escaping_root = manifest.parent / "escape"
    escaping_root.symlink_to(tmp_path.parent, target_is_directory=True)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["scenarios"][0]["root"] = "escape"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="may not traverse symlinks"):
        load_macro_fixture_manifest(manifest)


def test_discovery_rejects_source_mutation_after_fixture_qualification(
    tmp_path: Path,
) -> None:
    manifest = _copied_fixture(tmp_path)
    scenario = load_macro_fixture_manifest(manifest)[0]
    before = _discover(scenario)
    qualified = {item.relative_path: item.content for item in scenario.sources}
    changed = scenario.root / "main.sas"
    changed.write_bytes(changed.read_bytes().replace(b"active", b"closed"))
    with pytest.raises(ValueError, match="changed after review"):
        load_macro_fixture_manifest(manifest)
    with pytest.raises(ValueError, match="changed after qualification"):
        _discover(scenario)
    assert before.macro_analysis is not None
    assert qualified["main.sas"] != changed.read_bytes()


def test_discovery_rejects_content_not_bound_to_qualified_digest() -> None:
    scenario = _scenarios()[0]
    source = scenario.sources[0]
    changed_content = bytes([source.content[0] ^ 1]) + source.content[1:]
    forged_source = QualifiedSource(
        relative_path=source.relative_path,
        size=source.size,
        sha256=source.sha256,
        content=changed_content,
    )
    forged = QualifiedMacroScenario(
        scenario_id=scenario.scenario_id,
        category=scenario.category,
        namespace=scenario.namespace,
        root=scenario.root,
        sources=(forged_source, *scenario.sources[1:]),
        expected=scenario.expected,
    )

    with pytest.raises(ValueError, match="Qualified source content changed before analysis"):
        _discover(forged)


def test_concurrent_failure_is_isolated_and_restart_is_deterministic() -> None:
    scenarios = _scenarios()
    with ThreadPoolExecutor(max_workers=len(scenarios)) as executor:
        concurrent = tuple(executor.map(_discover, scenarios))
    sequential = tuple(_discover(item) for item in scenarios)
    assert [item.to_dict() for item in concurrent] == [item.to_dict() for item in sequential]
    workload_ids = {item.workload_id for item in concurrent}
    artifact_ids = [
        artifact.artifact_id for workload in concurrent for artifact in workload.artifacts
    ]
    assert len(workload_ids) == len(scenarios)
    assert len(set(artifact_ids)) == len(artifact_ids)
    assert any(item.macro_analysis and item.macro_analysis.complete is False for item in concurrent)
    assert any(item.macro_analysis and item.macro_analysis.complete is True for item in concurrent)


@pytest.mark.parametrize("with_non_sas", [False, True])
def test_empty_or_non_sas_workload_has_no_eligible_macro_subject(
    tmp_path: Path, with_non_sas: bool
) -> None:
    if with_non_sas:
        (tmp_path / "readme.txt").write_text("no convertible entry point", encoding="utf-8")
    workload = discover_source(tmp_path, namespace="task-05-ineligible").workloads[0]
    analysis = workload.macro_analysis
    assert analysis is not None
    assert analysis.source_inventory == ()
    assert analysis.observations == ()
    assert not any(item.kind is RelationshipKind.CALLS for item in workload.relationships)
    assert not any(item.logical_path.endswith(".sas") for item in workload.artifacts)


def test_synthetic_sensitive_canary_does_not_become_macro_evidence(tmp_path: Path) -> None:
    canary = "pass" + "word=fixture-only-value"
    (tmp_path / "main.sas").write_text(
        f"/* {canary}; %leaked; &leaked */\n%macro safe; %mend;\n%safe;\n",
        encoding="utf-8",
    )
    workload = discover_source(tmp_path, namespace="task-05-security-canary").workloads[0]
    analysis = workload.macro_analysis
    assert analysis is not None
    assert "leaked" not in {item.normalized_identity for item in analysis.observations}
    assert canary not in repr(workload.to_dict())
