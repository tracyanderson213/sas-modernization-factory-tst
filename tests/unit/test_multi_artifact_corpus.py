from pathlib import Path

import pytest
import yaml

from smf.corpus.loader import load_corpus_manifest

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "representative-multi-artifact-foundation.yaml"


def test_representative_multi_artifact_manifest_loads() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.scenario_id == "representative-multi-artifact-foundation"
    assert manifest.metadata["tier"] == "representative"
    assert len(manifest.artifacts) >= 4
    assert manifest.workload is not None


def test_workload_has_single_declared_entrypoint() -> None:
    workload = load_corpus_manifest(MANIFEST).workload
    assert workload is not None
    assert len(workload.entrypoints) == 1
    assert workload.entrypoints[0].name == "main.sas"


def test_workload_preserves_explicit_artifact_relationships() -> None:
    workload = load_corpus_manifest(MANIFEST).workload
    assert workload is not None
    assert len(workload.relationships) >= 3
    assert {"includes", "configures"}.issubset(
        {item.relationship for item in workload.relationships}
    )


def test_relationship_paths_are_real_declared_artifacts() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert manifest.workload is not None
    declared = {artifact.path.resolve() for artifact in manifest.artifacts}
    for relationship in manifest.workload.relationships:
        assert relationship.source_path.resolve() in declared
        assert relationship.target_path.resolve() in declared


def test_workload_root_is_stable_scenario_directory() -> None:
    workload = load_corpus_manifest(MANIFEST).workload
    assert workload is not None
    assert workload.root.name == "multi-artifact-foundation"
    assert workload.root.is_dir()


def test_manifest_preserves_distinct_artifact_roles() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert {
        "sas-program",
        "sas-include",
        "sas-macro",
        "configuration",
    }.issubset({artifact.role for artifact in manifest.artifacts})


def test_unknown_entrypoint_is_rejected(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["workload"]["entrypoints"] = ["missing.sas"]
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="not declared"):
        load_corpus_manifest(copied, verify_files=False)


def test_unknown_relationship_target_is_rejected(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["workload"]["relationships"][0]["target"] = "missing.sas"
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="not declared"):
        load_corpus_manifest(copied, verify_files=False)


def test_legacy_single_artifact_manifests_remain_supported() -> None:
    manifest = load_corpus_manifest(CORPUS_ROOT / "manifests" / "semantic-merge-by.yaml")
    assert manifest.workload is None


def test_framework_does_not_claim_baseline_or_expected_output() -> None:
    manifest = load_corpus_manifest(MANIFEST)
    assert "baseline" not in manifest.expected
    assert all(artifact.role != "expected-output" for artifact in manifest.artifacts)


def test_regression_source_closure_cannot_omit_relationship_target(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["regression"]["subjects"][0]["source_closure"].pop()
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="omits declared relationship targets"):
        load_corpus_manifest(copied, verify_files=False)


def test_regression_entrypoint_must_be_convertible_sas_program(tmp_path: Path) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    subject = payload["regression"]["subjects"][0]
    subject["entrypoint"] = subject["source_closure"][3]
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one declared sas-program"):
        load_corpus_manifest(copied, verify_files=False)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", "python"),
        ("evidence_scope", "humana-production"),
        ("environment", "production"),
        ("stages", ["admission", "convertedd"]),
    ],
)
def test_regression_manifest_unknown_enums_fail_schema_validation(
    tmp_path: Path, field: str, value: object
) -> None:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    payload["regression"]["subjects"][0][field] = value
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(Exception, match="is not one of"):
        load_corpus_manifest(copied, verify_files=False)
