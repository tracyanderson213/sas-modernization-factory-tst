"""Persistent explicit proof evidence for corpus coverage maturity above observed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml

from smf.corpus.coverage import CoverageDimension, CoverageEvidence, CoverageMaturity
from smf.corpus.regression import load_corpus_regression_result

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "corpus-coverage-evidence.schema.json"
)


def _read_schema(schema_path: Path | None = None) -> dict[str, Any]:
    path = schema_path or _SCHEMA_PATH
    with path.open(encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def validate_coverage_evidence(payload: dict[str, Any], schema_path: Path | None = None) -> None:
    """Validate one explicit higher-maturity proof record."""

    jsonschema.validate(instance=payload, schema=_read_schema(schema_path))


def load_coverage_evidence(path: Path, *, schema_path: Path | None = None) -> CoverageEvidence:
    """Load one attributable proof claim without inferring adjacent maturity states."""

    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"Coverage evidence must contain a mapping: {path}")
    payload = cast(dict[str, Any], raw)
    validate_coverage_evidence(payload, schema_path=schema_path)
    maturity = CoverageMaturity(str(payload["maturity"]))
    if maturity == CoverageMaturity.OBSERVED:
        raise ValueError("Observed coverage must come from corpus manifests, not proof registry")
    evidence_ref = Path(str(payload["evidence_ref"]))
    if evidence_ref.is_absolute() or ".." in evidence_ref.parts:
        raise ValueError("Coverage evidence reference must remain inside its registry")
    result_path = (path.parent / evidence_ref).resolve()
    if not result_path.is_relative_to(path.parent.resolve()):
        raise ValueError("Coverage evidence reference escapes its registry")
    result = load_corpus_regression_result(result_path)
    if result["content_digest"] != payload["result_digest"]:
        raise ValueError("Coverage evidence result digest mismatch")
    if result["scenario_id"] != payload["scenario_id"]:
        raise ValueError("Coverage evidence scenario does not match regression result")
    if result["source_id"] != payload["source_id"]:
        raise ValueError("Coverage evidence source does not match regression result")
    telemetry_field = {
        CoverageMaturity.TESTED: None,
        CoverageMaturity.CONVERTED: "generated",
        CoverageMaturity.EXECUTED: "executed",
        CoverageMaturity.VALIDATED: "validated",
        CoverageMaturity.CERTIFIED: "parity_passed",
    }[maturity]
    if result["terminal_disposition"] != "passed":
        raise ValueError(f"Coverage evidence result does not support {maturity.value} maturity")
    if telemetry_field is not None and not result["telemetry"][telemetry_field]:
        raise ValueError(f"Coverage evidence result does not support {maturity.value} maturity")
    return CoverageEvidence(
        dimension=CoverageDimension(str(payload["dimension"])),
        capability=str(payload["capability"]),
        maturity=maturity,
        scenario_id=str(payload["scenario_id"]),
        evidence_ref=str(result_path),
        source_id=str(payload["source_id"]),
        independent_source=bool(payload["independent_source"]),
        note=cast(str | None, payload.get("note")),
    )


def load_coverage_evidence_registry(directory: Path) -> tuple[CoverageEvidence, ...]:
    """Load all explicit proof claims and reject duplicate evidence identifiers."""

    if not directory.is_dir():
        raise FileNotFoundError(f"Coverage evidence registry not found: {directory}")
    records: list[CoverageEvidence] = []
    seen_ids: dict[str, Path] = {}
    for path in sorted((*directory.glob("*.yaml"), *directory.glob("*.yml"))):
        with path.open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
        if not isinstance(raw, dict):
            raise ValueError(f"Coverage evidence must contain a mapping: {path}")
        payload = cast(dict[str, Any], raw)
        validate_coverage_evidence(payload)
        evidence_id = str(payload["evidence_id"])
        previous = seen_ids.get(evidence_id)
        if previous is not None:
            raise ValueError(
                f"Duplicate coverage evidence_id {evidence_id!r}: {previous} and {path}"
            )
        seen_ids[evidence_id] = path
        records.append(load_coverage_evidence(path))
    return tuple(records)
