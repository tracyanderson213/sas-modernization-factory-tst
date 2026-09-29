from pathlib import Path

import yaml

from smf.corpus.loader import load_corpus_manifest, sha256_file

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
EXPECTED_SCENARIOS = {
    "public-sas-access-odbc-bulkload",
    "public-sas-access-postgres-bulkload",
    "public-sas-official-language-breadth",
    "public-sasjs-core-macro-dependency",
    "public-cdisc-core-sas-validation",
}


def test_public_portfolio_is_multi_source_and_untouched() -> None:
    manifests = []
    for scenario_id in EXPECTED_SCENARIOS:
        manifest = load_corpus_manifest(CORPUS_ROOT / "manifests" / f"{scenario_id}.yaml")
        manifests.append(manifest)
        assert manifest.source.origin == "public-open-source"
        assert manifest.source.upstream_ref and len(manifest.source.upstream_ref) == 40
        assert manifest.metadata["tier"] == "untouched-public"
        assert manifest.metadata["modification_status"] == "untouched"
        assert manifest.metadata["independent_authorship"] is True
        assert all(artifact.sha256 for artifact in manifest.artifacts)
        assert all(artifact.upstream_path for artifact in manifest.artifacts)
    assert len({manifest.source.source_id for manifest in manifests}) >= 4


def test_public_source_registry_records_pinned_portfolio_refs() -> None:
    payload = yaml.safe_load((CORPUS_ROOT / "sources.yaml").read_text(encoding="utf-8"))
    sources = {item["source_id"]: item for item in payload["sources"]}
    for source_id in {"sas-code-examples", "sasjs-core", "cdisc-core-sas"}:
        source = sources[source_id]
        assert source["acquisition_status"] == "pinned-public-portfolio"
        assert len(source["upstream_ref"]) == 40
        assert source["modification_status"] == "untouched-required"


def test_public_sas_access_discovery_expectations_survive_acquisition() -> None:
    manifest = load_corpus_manifest(
        CORPUS_ROOT / "manifests" / "public-sas-access-odbc-bulkload.yaml"
    )
    discovery = manifest.expected["discovery"]
    assert set(discovery["reads"]) == {"work.dublkdat", "mybulk.dublktab"}
    assert set(discovery["writes"]) == {"work.dublkdat", "mybulk.dublktab"}
    assert set(discovery["libraries"]) == {"mybulk"}
    assert set(discovery["macro_variables"]) == {"connopt", "dbms"}


def test_public_portfolio_artifact_bytes_match_declared_fingerprints() -> None:
    for scenario_id in EXPECTED_SCENARIOS:
        manifest = load_corpus_manifest(
            CORPUS_ROOT / "manifests" / f"{scenario_id}.yaml",
            verify_files=False,
        )
        for artifact in manifest.artifacts:
            assert artifact.sha256 is not None
            assert sha256_file(artifact.path) == artifact.sha256
