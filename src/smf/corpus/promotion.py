"""Evidence-to-regression promotion records for corpus failures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml

from smf.corpus.loader import load_corpus_manifest

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "corpus-regression-promotion.schema.json"
)


@dataclass(frozen=True)
class RegressionEvidence:
    """Original corpus evidence that exposed a factory defect."""

    scenario_id: str
    manifest_path: Path
    evidence_class: str
    artifact_paths: tuple[str, ...]
    preserved_unchanged: bool


@dataclass(frozen=True)
class RegressionFailure:
    """Observed factory behavior that requires regression protection."""

    stage: str
    summary: str
    observed_behavior: str
    issue_url: str | None = None


@dataclass(frozen=True)
class RegressionFixture:
    """Permanent SMF-owned reproduction and its regression test."""

    fixture_scenario_id: str
    fixture_path: Path
    test_path: Path
    reproduction_method: str
    contains_client_material: bool


@dataclass(frozen=True)
class RegressionFix:
    """Factory correction associated with a promoted regression."""

    summary: str
    commit: str


@dataclass(frozen=True)
class GoldenChange:
    """Versioned provenance required when a conversion becomes a golden fixture."""

    original_evidence_ref: str
    original_evidence_digest: str
    reproduction_method: str
    old_golden_version: str | None
    new_golden_version: str
    provider_id: str
    provider_version: str
    strategy_id: str
    strategy_version: str
    rationale: str
    review_reference: str
    fix_commit: str
    fixture_path: str
    test_path: str


@dataclass(frozen=True)
class CorpusRegressionPromotion:
    """Auditable linkage from source evidence to a permanent regression."""

    schema_version: int
    promotion_id: str
    status: str
    evidence: RegressionEvidence
    failure: RegressionFailure
    regression: RegressionFixture | None = None
    fix: RegressionFix | None = None
    golden_change: GoldenChange | None = None


def _read_schema(schema_path: Path | None = None) -> dict[str, Any]:
    path = schema_path or _SCHEMA_PATH
    with path.open(encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def validate_regression_promotion(payload: dict[str, Any], schema_path: Path | None = None) -> None:
    """Validate a decoded evidence-to-regression promotion record."""

    jsonschema.validate(instance=payload, schema=_read_schema(schema_path))


def load_regression_promotion(
    path: Path, *, verify_paths: bool = True, schema_path: Path | None = None
) -> CorpusRegressionPromotion:
    """Load a promotion record and enforce shared-regression safety invariants."""

    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"Regression promotion must contain a mapping: {path}")
    payload = cast(dict[str, Any], raw)
    validate_regression_promotion(payload, schema_path=schema_path)

    evidence_raw = cast(dict[str, Any], payload["evidence"])
    evidence_manifest_path = (path.parent / str(evidence_raw["manifest_path"])).resolve()
    if verify_paths:
        evidence_manifest = load_corpus_manifest(evidence_manifest_path)
        if evidence_manifest.scenario_id != str(evidence_raw["scenario_id"]):
            raise ValueError(
                "Promotion evidence scenario does not match corpus manifest: "
                f"{evidence_raw['scenario_id']} != {evidence_manifest.scenario_id}"
            )
        declared_artifacts = {str(item.path.resolve()) for item in evidence_manifest.artifacts}
        referenced_artifacts = {
            str((evidence_manifest_path.parent / str(item)).resolve())
            for item in evidence_raw["artifact_paths"]
        }
        unknown = sorted(referenced_artifacts - declared_artifacts)
        if unknown:
            raise ValueError(
                "Promotion evidence references artifacts not declared by source manifest: "
                + ", ".join(unknown)
            )
    failure_raw = cast(dict[str, Any], payload["failure"])
    regression_raw = cast(dict[str, Any] | None, payload.get("regression"))
    fix_raw = cast(dict[str, Any] | None, payload.get("fix"))
    golden_raw = cast(dict[str, Any] | None, payload.get("golden_change"))

    fixture_path: Path | None = None
    test_path: Path | None = None
    if regression_raw is not None:
        fixture_path = (path.parent / str(regression_raw["fixture_path"])).resolve()
        test_path = (path.parent / str(regression_raw["test_path"])).resolve()
        if verify_paths and payload["status"] == "promoted":
            missing = [str(item) for item in (fixture_path, test_path) if not item.exists()]
            if missing:
                raise FileNotFoundError("Promoted regression path not found: " + ", ".join(missing))

    return CorpusRegressionPromotion(
        schema_version=int(payload["schema_version"]),
        promotion_id=str(payload["promotion_id"]),
        status=str(payload["status"]),
        evidence=RegressionEvidence(
            scenario_id=str(evidence_raw["scenario_id"]),
            manifest_path=(path.parent / str(evidence_raw["manifest_path"])).resolve(),
            evidence_class=str(evidence_raw["evidence_class"]),
            artifact_paths=tuple(str(item) for item in evidence_raw["artifact_paths"]),
            preserved_unchanged=bool(evidence_raw["preserved_unchanged"]),
        ),
        failure=RegressionFailure(
            stage=str(failure_raw["stage"]),
            summary=str(failure_raw["summary"]),
            observed_behavior=str(failure_raw["observed_behavior"]),
            issue_url=cast(str | None, failure_raw.get("issue_url")),
        ),
        regression=(
            RegressionFixture(
                fixture_scenario_id=str(regression_raw["fixture_scenario_id"]),
                fixture_path=cast(Path, fixture_path),
                test_path=cast(Path, test_path),
                reproduction_method=str(regression_raw["reproduction_method"]),
                contains_client_material=bool(regression_raw["contains_client_material"]),
            )
            if regression_raw is not None
            else None
        ),
        fix=(
            RegressionFix(summary=str(fix_raw["summary"]), commit=str(fix_raw["commit"]))
            if fix_raw is not None
            else None
        ),
        golden_change=(
            GoldenChange(
                original_evidence_ref=str(golden_raw["original_evidence_ref"]),
                original_evidence_digest=str(golden_raw["original_evidence_digest"]),
                reproduction_method=str(golden_raw["reproduction_method"]),
                old_golden_version=cast(str | None, golden_raw["old_golden_version"]),
                new_golden_version=str(golden_raw["new_golden_version"]),
                provider_id=str(golden_raw["provider_id"]),
                provider_version=str(golden_raw["provider_version"]),
                strategy_id=str(golden_raw["strategy_id"]),
                strategy_version=str(golden_raw["strategy_version"]),
                rationale=str(golden_raw["rationale"]),
                review_reference=str(golden_raw["review_reference"]),
                fix_commit=str(golden_raw["fix_commit"]),
                fixture_path=str(golden_raw["fixture_path"]),
                test_path=str(golden_raw["test_path"]),
            )
            if golden_raw is not None
            else None
        ),
    )


def load_regression_promotion_registry(
    directory: Path, *, verify_paths: bool = True
) -> tuple[CorpusRegressionPromotion, ...]:
    """Load and validate every promotion record in a repository registry."""

    if not directory.is_dir():
        raise FileNotFoundError(f"Regression promotion registry not found: {directory}")

    records: list[CorpusRegressionPromotion] = []
    seen_ids: dict[str, Path] = {}
    for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
        promotion = load_regression_promotion(path, verify_paths=verify_paths)
        previous = seen_ids.get(promotion.promotion_id)
        if previous is not None:
            raise ValueError(
                "Duplicate regression promotion_id "
                f"{promotion.promotion_id!r}: {previous} and {path}"
            )
        seen_ids[promotion.promotion_id] = path
        records.append(promotion)
    return tuple(records)
