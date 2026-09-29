from pathlib import Path

import pytest
import yaml

from smf.corpus.loader import load_corpus_manifest, sha256_file

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST = CORPUS_ROOT / "manifests" / "semantic-output-evidence-foundation.yaml"


def test_declared_synthetic_output_evidence_loads_with_explicit_authority() -> None:
    evidence = load_corpus_manifest(MANIFEST).output_evidence[0]
    assert evidence.evidence_origin == "declared-synthetic-expectation"
    assert evidence.producer == "smf-authored-oracle"
    assert evidence.deterministic is True
    assert evidence.authoritative is True
    assert evidence.source_execution_id is None


def test_output_evidence_hash_matches_expected_artifact() -> None:
    evidence = load_corpus_manifest(MANIFEST).output_evidence[0]
    assert evidence.content_hash == sha256_file(evidence.artifact_path)


def _copy_manifest(tmp_path: Path, mutate) -> Path:
    payload = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    mutate(payload)
    copied = tmp_path / "manifest.yaml"
    copied.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return copied


def test_output_evidence_must_reference_declared_artifact(tmp_path: Path) -> None:
    copied = _copy_manifest(
        tmp_path, lambda p: p["output_evidence"][0].update(artifact="missing.csv")
    )
    with pytest.raises(ValueError, match="not declared"):
        load_corpus_manifest(copied, verify_files=False)


def test_output_evidence_requires_expected_output_role(tmp_path: Path) -> None:
    copied = _copy_manifest(
        tmp_path,
        lambda p: p["output_evidence"][0].update(
            artifact=p["artifacts"][0]["path"], content_hash=p["artifacts"][0]["sha256"]
        ),
    )
    with pytest.raises(ValueError, match="role expected-output"):
        load_corpus_manifest(copied, verify_files=False)


def test_output_evidence_hash_must_match_artifact_fingerprint(tmp_path: Path) -> None:
    copied = _copy_manifest(
        tmp_path, lambda p: p["output_evidence"][0].update(content_hash="0" * 64)
    )
    with pytest.raises(ValueError, match="does not match artifact sha256"):
        load_corpus_manifest(copied, verify_files=False)


def test_sas_executed_baseline_requires_execution_linkage(tmp_path: Path) -> None:
    copied = _copy_manifest(
        tmp_path, lambda p: p["output_evidence"][0].update(evidence_origin="sas-executed-baseline")
    )
    with pytest.raises(ValueError, match="requires source_execution_id"):
        load_corpus_manifest(copied, verify_files=False)


def test_sas_executed_baseline_preserves_execution_linkage(tmp_path: Path) -> None:
    def mutate(payload):
        payload["output_evidence"][0].update(
            evidence_origin="sas-executed-baseline",
            source_execution_id="sas-run-20260904-001",
            producer="sas-9.4",
        )

    evidence = load_corpus_manifest(
        _copy_manifest(tmp_path, mutate), verify_files=False
    ).output_evidence[0]
    assert evidence.source_execution_id == "sas-run-20260904-001"
    assert evidence.producer == "sas-9.4"


def test_public_reference_artifact_does_not_imply_authority(tmp_path: Path) -> None:
    def mutate(payload):
        payload["output_evidence"][0].update(
            evidence_origin="public-reference-artifact",
            authoritative=False,
            producer="upstream-public-source",
        )

    evidence = load_corpus_manifest(
        _copy_manifest(tmp_path, mutate), verify_files=False
    ).output_evidence[0]
    assert evidence.evidence_origin == "public-reference-artifact"
    assert evidence.authoritative is False


def test_expected_output_role_alone_does_not_create_evidence(tmp_path: Path) -> None:
    def mutate(payload):
        payload.pop("output_evidence")

    manifest = load_corpus_manifest(_copy_manifest(tmp_path, mutate), verify_files=False)
    assert any(a.role == "expected-output" for a in manifest.artifacts)
    assert manifest.output_evidence == ()


def test_duplicate_output_evidence_ids_are_rejected(tmp_path: Path) -> None:
    def mutate(payload):
        payload["output_evidence"].append(dict(payload["output_evidence"][0]))

    copied = _copy_manifest(tmp_path, mutate)
    with pytest.raises(ValueError, match="Duplicate corpus output evidence id"):
        load_corpus_manifest(copied, verify_files=False)
