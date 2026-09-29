from pathlib import Path

import pytest
import yaml

from smf.corpus.loader import load_corpus_manifest, sha256_file

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "representative-multi-artifact-foundation.yaml"


def test_representative_workload_has_two_synthetic_data_fixtures() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert len(manifest.data_fixtures) == 2


def test_fixture_ids_are_stable_and_explicit() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert {item.fixture_id for item in manifest.data_fixtures} == {
        "members-input",
        "member-flags-input",
    }


def test_fixture_dataset_bindings_are_explicit() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert {item.dataset for item in manifest.data_fixtures} == {
        "work.members",
        "work.member_flags",
    }


def test_fixture_artifacts_are_declared_as_input_data() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    roles = {artifact.path.resolve(): artifact.role for artifact in manifest.artifacts}
    assert all(
        roles[item.artifact_path.resolve()] == "input-data" for item in manifest.data_fixtures
    )


def test_fixture_files_are_fingerprinted() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    artifacts = {artifact.path.resolve(): artifact for artifact in manifest.artifacts}
    for fixture in manifest.data_fixtures:
        artifact = artifacts[fixture.artifact_path.resolve()]
        assert artifact.sha256 == sha256_file(fixture.artifact_path)


def test_fixture_contract_marks_data_deterministic_and_non_private() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert all(item.deterministic for item in manifest.data_fixtures)
    assert all(not item.contains_private_data for item in manifest.data_fixtures)


def test_workload_declares_reads_to_synthetic_inputs() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.workload is not None
    reads = {
        item.target_path.name
        for item in manifest.workload.relationships
        if item.relationship == "reads"
    }
    assert reads == {"members.csv", "member_flags.csv"}


def test_unknown_fixture_artifact_is_rejected(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text())
    payload["data_fixtures"][0]["artifact"] = "missing.csv"
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(ValueError, match="not declared"):
        load_corpus_manifest(copied, verify_files=False)


def test_non_input_artifact_cannot_be_data_fixture(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text())
    payload["data_fixtures"][0]["artifact"] = payload["artifacts"][0]["path"]
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(ValueError, match="role input-data"):
        load_corpus_manifest(copied, verify_files=False)


def test_private_data_claim_is_rejected_for_synthetic_fixture(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text())
    payload["data_fixtures"][0]["contains_private_data"] = True
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False))
    with pytest.raises(ValueError, match="must not contain private data"):
        load_corpus_manifest(copied, verify_files=False)
