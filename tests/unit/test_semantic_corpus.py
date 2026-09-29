from pathlib import Path

from smf.corpus import load_semantic_registry, load_semantic_result

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
MANIFEST_ROOT = CORPUS_ROOT / "manifests"


def test_semantic_registry_loads_every_instrument_deterministically() -> None:
    manifests = load_semantic_registry(MANIFEST_ROOT)
    instrument_manifests = [manifest for manifest in manifests if manifest.semantic_oracles]

    assert len(instrument_manifests) == 15
    assert [manifest.scenario_id for manifest in manifests] == sorted(
        manifest.scenario_id for manifest in manifests
    )
    assert all(manifest.source.origin == "smf" for manifest in manifests)
    assert all(manifest.metadata["private_data"] is False for manifest in manifests)
    assert all(
        artifact.sha256 for manifest in instrument_manifests for artifact in manifest.artifacts
    )

    oracle_ids: list[str] = []
    for manifest in instrument_manifests:
        for oracle in manifest.semantic_oracles:
            evidence = next(
                item for item in manifest.output_evidence if item.evidence_id == oracle.evidence_id
            )
            assert evidence.evidence_origin == "declared-synthetic-expectation"
            assert evidence.authoritative and evidence.deterministic
            load_semantic_result(evidence.artifact_path, oracle=oracle)
            oracle_ids.append(oracle.oracle_id)
    assert len(oracle_ids) == len(set(oracle_ids))


def test_semantic_instruments_cover_isolated_acceptance_behaviors() -> None:
    primary_behaviors = {
        str(manifest.metadata["primary_behavior"])
        for manifest in load_semantic_registry(MANIFEST_ROOT)
        if manifest.semantic_oracles
    }
    assert {
        "data-step-dates-missing",
        "merge-by",
        "by-retain-lag",
        "macro-generation",
        "proc-sql-lineage",
        "missing-value-ordering",
        "coercion",
        "data-step-iteration",
        "duplicate-key-merge",
        "many-to-many-sql",
        "date-boundaries",
        "numeric-precision",
        "empty-dataset",
        "dynamic-macro",
        "temporal-literals",
    } == primary_behaviors


def test_semantic_programs_are_separate_from_public_workloads() -> None:
    for manifest in load_semantic_registry(MANIFEST_ROOT):
        for artifact in manifest.artifacts:
            assert "workloads/public/" not in artifact.path.as_posix()
