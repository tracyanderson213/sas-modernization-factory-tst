from pathlib import Path

from smf.corpus.loader import load_corpus_manifest

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"


def test_all_corpus_manifests_load_and_verify() -> None:
    manifests = sorted((CORPUS_ROOT / "manifests").glob("*.yaml"))

    assert len(manifests) >= 3
    loaded = [load_corpus_manifest(path) for path in manifests]
    scenario_ids = {manifest.scenario_id for manifest in loaded}

    assert "smf-smoke-external-file" in scenario_ids
    assert "public-sas-access-odbc-bulkload" in scenario_ids
    assert "public-sas-access-postgres-bulkload" in scenario_ids


def test_public_corpus_keeps_public_provenance() -> None:
    manifests = [
        CORPUS_ROOT / "manifests" / "public-sas-access-odbc-bulkload.yaml",
        CORPUS_ROOT / "manifests" / "public-sas-access-postgres-bulkload.yaml",
    ]

    for path in manifests:
        manifest = load_corpus_manifest(path)
        assert manifest.source.origin == "public-open-source"
        assert manifest.source.license == "Apache-2.0"
        assert manifest.source.upstream_url
        assert manifest.source.upstream_ref
