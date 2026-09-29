from pathlib import Path

import jsonschema
import pytest
import yaml

from smf.corpus.loader import load_corpus_manifest
from smf.corpus.promotion import (
    load_regression_promotion,
    load_regression_promotion_registry,
    validate_regression_promotion,
)


def _payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "promotion_id": "reg-public-001",
        "status": "promoted",
        "evidence": {
            "scenario_id": "public-example",
            "manifest_path": "../manifests/public-example.yaml",
            "evidence_class": "untouched-public",
            "artifact_paths": ["../workloads/public/example.sas"],
            "preserved_unchanged": True,
        },
        "failure": {
            "stage": "discover",
            "summary": "Static discovery missed a dependency.",
            "observed_behavior": "Expected include relationship was absent.",
        },
        "regression": {
            "fixture_scenario_id": "semantic-include-regression",
            "fixture_path": "../manifests/semantic-include-regression.yaml",
            "test_path": "../../unit/test_include_regression.py",
            "reproduction_method": "minimal-independent",
            "contains_client_material": False,
        },
        "fix": {"summary": "Recognize the include form.", "commit": "abcdef1"},
    }


def test_observed_record_does_not_require_regression_fixture() -> None:
    payload = _payload()
    payload["status"] = "observed"
    payload.pop("regression")
    payload.pop("fix")
    validate_regression_promotion(payload)


def test_reproduced_record_requires_regression_fixture() -> None:
    payload = _payload()
    payload["status"] = "reproduced"
    payload.pop("regression")
    payload.pop("fix")
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)


def test_promotion_schema_requires_fix_before_promoted() -> None:
    payload = _payload()
    payload.pop("fix")
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)


def test_v2_golden_promotion_requires_attributable_change_provenance() -> None:
    payload = _payload()
    payload["schema_version"] = 2
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)
    payload["golden_change"] = {
        "original_evidence_ref": "evidence://run/workload/attempt/conversion",
        "original_evidence_digest": "a" * 64,
        "reproduction_method": "minimal-independent",
        "old_golden_version": None,
        "new_golden_version": "1.0.0",
        "provider_id": "smf-deterministic",
        "provider_version": "smf-0.1.0",
        "strategy_id": "smf.deterministic.proc_sql",
        "strategy_version": "1.0.0",
        "rationale": "Accepted conversion reproduced without client material.",
        "review_reference": "review-123",
        "fix_commit": "abcdef1",
        "fixture_path": "../manifests/cv03.yaml",
        "test_path": "../../unit/test_cv03.py",
    }
    validate_regression_promotion(payload)


def test_promoted_evidence_must_remain_unchanged() -> None:
    payload = _payload()
    evidence = payload["evidence"]
    assert isinstance(evidence, dict)
    evidence["preserved_unchanged"] = False
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)


def test_private_evidence_cannot_enter_shared_regression_directly() -> None:
    payload = _payload()
    evidence = payload["evidence"]
    regression = payload["regression"]
    assert isinstance(evidence, dict)
    assert isinstance(regression, dict)
    evidence["evidence_class"] = "private-client"
    regression["reproduction_method"] = "direct-synthetic"
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)
    regression["reproduction_method"] = "sanitized-independent"
    regression["contains_client_material"] = True
    with pytest.raises(jsonschema.ValidationError):
        validate_regression_promotion(payload)


def test_loader_resolves_promoted_fixture_and_test_paths(tmp_path: Path) -> None:
    promotions = tmp_path / "promotions"
    manifests = tmp_path / "manifests"
    unit = tmp_path / "unit"
    promotions.mkdir()
    manifests.mkdir()
    unit.mkdir()
    (manifests / "semantic-include-regression.yaml").write_text("scenario: fixture\n")
    (unit / "test_include_regression.py").write_text("def test_placeholder(): pass\n")

    payload = _payload()
    regression = payload["regression"]
    assert isinstance(regression, dict)
    regression["fixture_path"] = "../manifests/semantic-include-regression.yaml"
    regression["test_path"] = "../unit/test_include_regression.py"
    record = promotions / "reg-public-001.yaml"
    record.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    promotion = load_regression_promotion(record, verify_paths=False)
    assert promotion.status == "promoted"
    assert promotion.evidence.scenario_id == "public-example"
    assert promotion.regression is not None
    assert promotion.regression.fixture_path == manifests / "semantic-include-regression.yaml"
    assert promotion.regression.test_path == unit / "test_include_regression.py"
    assert promotion.fix is not None
    assert promotion.fix.commit == "abcdef1"


def test_loader_verifies_evidence_against_source_manifest(tmp_path: Path) -> None:
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "corpus/manifests/public-sas-access-odbc-bulkload.yaml"
    )
    source_manifest = load_corpus_manifest(manifest_path)
    source_artifact = source_manifest.artifacts[0]
    fixture = tmp_path / "fixture.yaml"
    test_file = tmp_path / "test_regression.py"
    fixture.write_text("fixture: true\n", encoding="utf-8")
    test_file.write_text("def test_regression(): pass\n", encoding="utf-8")

    payload = _payload()
    evidence = payload["evidence"]
    regression = payload["regression"]
    assert isinstance(evidence, dict)
    assert isinstance(regression, dict)
    evidence["scenario_id"] = source_manifest.scenario_id
    evidence["manifest_path"] = str(manifest_path)
    evidence["artifact_paths"] = [str(source_artifact.path.relative_to(manifest_path.parent))]
    regression["fixture_path"] = str(fixture)
    regression["test_path"] = str(test_file)
    record = tmp_path / "promotion.yaml"
    record.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    promotion = load_regression_promotion(record)
    assert promotion.evidence.scenario_id == source_manifest.scenario_id

    evidence["artifact_paths"] = ["../workloads/public/not-declared.sas"]
    record.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="not declared"):
        load_regression_promotion(record)


def test_repository_promotion_registry_validates_all_records() -> None:
    registry = Path(__file__).resolve().parents[1] / "corpus/promotions"
    promotions = load_regression_promotion_registry(registry)
    assert len({item.promotion_id for item in promotions}) == len(promotions)


def test_registry_rejects_duplicate_promotion_ids(tmp_path: Path) -> None:
    payload = _payload()
    payload["status"] = "observed"
    payload.pop("regression")
    payload.pop("fix")
    for name in ("first.yaml", "second.yml"):
        (tmp_path / name).write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate regression promotion_id"):
        load_regression_promotion_registry(tmp_path, verify_paths=False)
