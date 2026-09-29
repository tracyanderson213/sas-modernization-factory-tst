"""Attributable multidimensional corpus coverage and proof-maturity reporting."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from smf.corpus.loader import load_corpus_manifest


class CoverageMaturity(StrEnum):
    """Evidence maturity. Levels are distinct claims, not a scalar score."""

    OBSERVED = "observed"
    TESTED = "tested"
    CONVERTED = "converted"
    EXECUTED = "executed"
    VALIDATED = "validated"
    CERTIFIED = "certified"


class CoverageDimension(StrEnum):
    """Required dimensions in the corpus truth meter."""

    SOURCE_DIVERSITY = "source-diversity"
    CONSTRUCT = "construct"
    PROCEDURE = "procedure"
    MACRO_BEHAVIOR = "macro-behavior"
    DATA_ACCESS = "data-access"
    DEPENDENCY = "dependency"
    SCHEDULER = "scheduler"
    TOPOLOGY = "topology"
    COMPLEXITY = "complexity"
    MODERNIZATION_PATTERN = "modernization-pattern"
    VALIDATION_ASSERTION = "validation-assertion"
    UNSUPPORTED_BEHAVIOR = "unsupported-behavior"
    UNRESOLVED_BEHAVIOR = "unresolved-behavior"


@dataclass(frozen=True)
class CoverageEvidence:
    """One attributable claim about one capability at one maturity."""

    dimension: CoverageDimension
    capability: str
    maturity: CoverageMaturity
    scenario_id: str
    evidence_ref: str
    source_id: str
    independent_source: bool
    note: str | None = None


@dataclass(frozen=True)
class CoverageDimensionSummary:
    """Coverage facts for a single dimension without a synthetic percentage."""

    dimension: CoverageDimension
    evidence: tuple[CoverageEvidence, ...]

    @property
    def maturity_counts(self) -> dict[str, int]:
        return {
            maturity.value: sum(item.maturity == maturity for item in self.evidence)
            for maturity in CoverageMaturity
        }

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted({item.capability for item in self.evidence}))


@dataclass(frozen=True)
class CorpusCoverageReport:
    """Truth-meter report retaining evidence and explicit empty dimensions."""

    dimensions: tuple[CoverageDimensionSummary, ...]
    scenario_count: int
    independent_source_count: int

    @property
    def known_gaps(self) -> tuple[CoverageDimension, ...]:
        return tuple(item.dimension for item in self.dimensions if not item.evidence)

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_count": self.scenario_count,
            "independent_source_count": self.independent_source_count,
            "dimensions": [
                {
                    "dimension": item.dimension.value,
                    "capabilities": list(item.capabilities),
                    "maturity_counts": item.maturity_counts,
                    "evidence": [
                        {
                            "capability": evidence.capability,
                            "maturity": evidence.maturity.value,
                            "scenario_id": evidence.scenario_id,
                            "source_id": evidence.source_id,
                            "evidence_ref": evidence.evidence_ref,
                            "independent_source": evidence.independent_source,
                            "note": evidence.note,
                        }
                        for evidence in item.evidence
                    ],
                }
                for item in self.dimensions
            ],
            "known_gaps": [item.value for item in self.known_gaps],
        }


def _classify_capability(capability: str) -> CoverageDimension:
    value = capability.lower()
    if "macro" in value:
        return CoverageDimension.MACRO_BEHAVIOR
    if value.startswith("proc-") or "procedure" in value:
        return CoverageDimension.PROCEDURE
    if any(
        token in value
        for token in ("odbc", "postgres", "libname", "external-file", "infile", "data-access")
    ):
        return CoverageDimension.DATA_ACCESS
    if any(token in value for token in ("scheduler", "schedule", "batch", "cron", "jil")):
        return CoverageDimension.SCHEDULER
    if any(token in value for token in ("dependency", "include", "lineage")):
        return CoverageDimension.DEPENDENCY
    if any(token in value for token in ("topology", "workload-boundary", "external-dependency")):
        return CoverageDimension.TOPOLOGY
    if "complex" in value:
        return CoverageDimension.COMPLEXITY
    if any(token in value for token in ("modernization", "retire", "consolidat", "target-pattern")):
        return CoverageDimension.MODERNIZATION_PATTERN
    if any(token in value for token in ("validation", "parity", "assert")):
        return CoverageDimension.VALIDATION_ASSERTION
    if "unsupported" in value:
        return CoverageDimension.UNSUPPORTED_BEHAVIOR
    if any(token in value for token in ("unresolved", "dynamic")):
        return CoverageDimension.UNRESOLVED_BEHAVIOR
    return CoverageDimension.CONSTRUCT


def observed_coverage_from_manifests(manifest_directory: Path) -> tuple[CoverageEvidence, ...]:
    """Derive OBSERVED claims only from declared corpus evidence.

    Presence in a manifest never implies tested, converted, executed, validated, or certified.
    """

    evidence: list[CoverageEvidence] = []
    for path in sorted(manifest_directory.glob("*.yaml")):
        manifest = load_corpus_manifest(path)
        independent = bool(manifest.metadata.get("independent_authorship", False))
        evidence.append(
            CoverageEvidence(
                dimension=CoverageDimension.SOURCE_DIVERSITY,
                capability=manifest.source.source_id,
                maturity=CoverageMaturity.OBSERVED,
                scenario_id=manifest.scenario_id,
                evidence_ref=str(path),
                source_id=manifest.source.source_id,
                independent_source=independent,
                note=manifest.source.origin,
            )
        )
        for capability in manifest.capabilities:
            evidence.append(
                CoverageEvidence(
                    dimension=_classify_capability(capability),
                    capability=capability,
                    maturity=CoverageMaturity.OBSERVED,
                    scenario_id=manifest.scenario_id,
                    evidence_ref=str(path),
                    source_id=manifest.source.source_id,
                    independent_source=independent,
                )
            )
        for dependency in manifest.dependency_expectations:
            if dependency.resolution == "unresolved":
                dimension = CoverageDimension.UNRESOLVED_BEHAVIOR
                unresolved_reference = dependency.unresolved_reference
                if unresolved_reference is None:
                    raise ValueError(
                        "Unresolved dependency expectation is missing its reference: "
                        f"{dependency.expectation_id}"
                    )
                dependency_capability = unresolved_reference
            else:
                dimension = CoverageDimension.DEPENDENCY
                dependency_capability = dependency.relationship
            evidence.append(
                CoverageEvidence(
                    dimension=dimension,
                    capability=dependency_capability,
                    maturity=CoverageMaturity.OBSERVED,
                    scenario_id=manifest.scenario_id,
                    evidence_ref=f"{path}#{dependency.expectation_id}",
                    source_id=manifest.source.source_id,
                    independent_source=independent,
                    note=dependency.evidence_method,
                )
            )
        for output in manifest.output_evidence:
            evidence.append(
                CoverageEvidence(
                    dimension=CoverageDimension.VALIDATION_ASSERTION,
                    capability=output.logical_output,
                    maturity=CoverageMaturity.OBSERVED,
                    scenario_id=manifest.scenario_id,
                    evidence_ref=f"{path}#{output.evidence_id}",
                    source_id=manifest.source.source_id,
                    independent_source=independent,
                    note=output.evidence_origin,
                )
            )
    return tuple(evidence)


def build_coverage_report(
    evidence: Iterable[CoverageEvidence], *, scenario_count: int | None = None
) -> CorpusCoverageReport:
    """Build a complete dimensional report without inventing aggregate confidence."""

    items = tuple(evidence)
    scenarios = {item.scenario_id for item in items}
    independent_sources = {item.source_id for item in items if item.independent_source}
    summaries = tuple(
        CoverageDimensionSummary(
            dimension=dimension,
            evidence=tuple(item for item in items if item.dimension == dimension),
        )
        for dimension in CoverageDimension
    )
    return CorpusCoverageReport(
        dimensions=summaries,
        scenario_count=len(scenarios) if scenario_count is None else scenario_count,
        independent_source_count=len(independent_sources),
    )


def build_repository_coverage_report(
    manifest_directory: Path, *, evidence_directory: Path | None = None
) -> CorpusCoverageReport:
    """Build the truth meter from observed manifests plus explicit proof evidence."""

    manifest_paths = tuple(sorted(manifest_directory.glob("*.yaml")))
    evidence = list(observed_coverage_from_manifests(manifest_directory))
    if evidence_directory is not None:
        from smf.corpus.coverage_evidence import load_coverage_evidence_registry

        evidence.extend(load_coverage_evidence_registry(evidence_directory))
    return build_coverage_report(evidence, scenario_count=len(manifest_paths))
