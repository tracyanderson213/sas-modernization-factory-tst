from pathlib import Path

import pytest
import yaml

from smf.corpus.loader import load_corpus_manifest

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "dependency-scheduler-foundation.yaml"


def _copy(tmp_path: Path, mutate):
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    mutate(payload)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def test_dependency_scheduler_manifest_loads() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.metadata["framework_stage"] == "CORPUS-06"
    assert len(manifest.dependency_expectations) == 7


def test_fixture_covers_required_dependency_domains() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    kinds = {item.relationship for item in manifest.dependency_expectations}
    assert {"includes", "invokes", "reads", "writes", "schedules", "depends-on"} <= kinds


def test_fixture_preserves_scheduler_and_runtime_evidence_methods() -> None:
    methods = {
        item.evidence_method for item in load_corpus_manifest(MANIFEST).dependency_expectations
    }
    assert methods == {"scheduler-metadata", "static-analysis"}


def test_resolved_expectations_reference_declared_artifacts() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    declared = {item.path.resolve() for item in manifest.artifacts}
    for item in manifest.dependency_expectations:
        assert item.source_path.resolve() in declared
        if item.resolution == "resolved":
            assert item.target_path is not None
            assert item.target_path.resolve() in declared


def test_dynamic_runtime_target_remains_explicitly_unresolved() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    item = next(
        x for x in manifest.dependency_expectations if x.expectation_id == "dynamic-wrapper-target"
    )
    assert item.resolution == "unresolved"
    assert item.target_path is None
    assert item.unresolved_reference == "$PROGRAM"


def test_external_scheduler_dependency_remains_unresolved() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    item = next(
        x
        for x in manifest.dependency_expectations
        if x.expectation_id == "external-autosys-upstream"
    )
    assert item.resolution == "unresolved"
    assert item.unresolved_reference == "LOAD_SOURCE"


def test_duplicate_dependency_expectation_ids_are_rejected(tmp_path: Path) -> None:
    def mutate(payload):
        payload["dependency_expectations"].append(dict(payload["dependency_expectations"][0]))

    with pytest.raises(ValueError, match="Duplicate corpus dependency expectation id"):
        load_corpus_manifest(_copy(tmp_path, mutate), verify_files=False)


def test_resolved_expectation_requires_declared_target(tmp_path: Path) -> None:
    def mutate(payload):
        payload["dependency_expectations"][0]["target"] = "missing.sh"

    with pytest.raises(ValueError, match="target is not a declared artifact"):
        load_corpus_manifest(_copy(tmp_path, mutate), verify_files=False)


def test_unresolved_expectation_cannot_claim_concrete_target(tmp_path: Path) -> None:
    def mutate(payload):
        item = payload["dependency_expectations"][-1]
        item["target"] = payload["artifacts"][0]["path"]

    with pytest.raises(ValueError, match="requires only unresolved_reference"):
        load_corpus_manifest(_copy(tmp_path, mutate), verify_files=False)


def test_legacy_manifests_have_no_dependency_expectations() -> None:
    manifest = load_corpus_manifest(CORPUS_ROOT / "manifests" / "semantic-merge-by.yaml")
    assert manifest.dependency_expectations == ()
