from pathlib import Path

import pytest

from smf.corpus.loader import load_corpus_manifest, load_corpus_manifest_registry

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"


def test_load_corpus_manifest_with_verified_files() -> None:
    manifest = load_corpus_manifest(CORPUS_ROOT / "manifests" / "smf-smoke.yaml")

    assert manifest.scenario_id == "smf-smoke-external-file"
    assert manifest.source.origin == "smf"
    assert len(manifest.artifacts) == 2
    assert "proc-sql" in manifest.capabilities


def test_corpus_manifest_detects_artifact_tampering(tmp_path: Path) -> None:
    manifest_path = CORPUS_ROOT / "manifests" / "smf-smoke.yaml"
    copied_manifest = tmp_path / "manifest.yaml"
    source = manifest_path.read_text(encoding="utf-8")

    artifact_dir = tmp_path / "source"
    artifact_dir.mkdir()
    sas_file = artifact_dir / "read_external_file.sas"
    csv_file = artifact_dir / "members.csv"
    sas_file.write_text("data x; run;\n", encoding="utf-8")
    csv_file.write_text("member_id\nM1\n", encoding="utf-8")

    source = source.replace(
        "../workloads/smf-smoke/source/read_external_file.sas",
        "source/read_external_file.sas",
    ).replace(
        "../workloads/smf-smoke/source/members.csv",
        "source/members.csv",
    )
    copied_manifest.write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        load_corpus_manifest(copied_manifest)


def test_registry_rejects_duplicate_canonical_scenario_identity(tmp_path: Path) -> None:
    source = (
        CORPUS_ROOT / "manifests" / "representative-multi-artifact-foundation.yaml"
    ).read_text(encoding="utf-8")
    (tmp_path / "one.yaml").write_text(source, encoding="utf-8")
    (tmp_path / "two.yaml").write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate corpus scenario id"):
        load_corpus_manifest_registry(tmp_path, verify_files=False)
