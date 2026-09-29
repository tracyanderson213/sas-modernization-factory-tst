"""Conservative Databricks target-pattern mapping.

MOD-05 converts normalized target-state evidence and modernization opportunities into
logical Databricks pattern candidates. It does not select deployment configuration,
prove semantic equivalence, or bypass governed disposition decisions.
"""

from __future__ import annotations

from dataclasses import replace

from smf.workload.identity import stable_id
from smf.workload.models import (
    Confidence,
    DatabricksPatternMapping,
    DatabricksTargetPattern,
    DispositionDecisionStatus,
    ModernizationDisposition,
    TargetDataBehavior,
    TargetExecutionBehavior,
    TargetStatePatternInput,
    Workload,
)


def _common_blockers(item: TargetStatePatternInput) -> set[str]:
    blockers = {f"DBX-BLOCKER-UNRESOLVED:{value}" for value in item.unresolved_items}
    if item.disposition_status is not DispositionDecisionStatus.CONFIRMED:
        blockers.add("DBX-BLOCKER-DISPOSITION-NOT-CONFIRMED")
    if item.selected_disposition in {
        ModernizationDisposition.RETIRE,
        ModernizationDisposition.REPLACE,
        ModernizationDisposition.PRESERVE,
    }:
        blockers.add("DBX-BLOCKER-DISPOSITION-NOT-DATABRICKS-IMPLEMENTATION")
    return blockers


def _mapping(
    workload: Workload,
    item: TargetStatePatternInput,
    pattern: DatabricksTargetPattern,
    *,
    signals: set[str],
    blockers: set[str],
    confidence: Confidence,
) -> DatabricksPatternMapping:
    return DatabricksPatternMapping(
        mapping_id=stable_id(
            "DBP",
            {
                "workload": workload.workload_id,
                "boundary": item.boundary_id,
                "pattern": pattern.value,
            },
        ),
        boundary_id=item.boundary_id,
        pattern=pattern,
        confidence=confidence,
        signal_ids=tuple(sorted(signals)),
        blocker_ids=tuple(sorted(blockers)),
        evidence=item.evidence,
        metadata={
            "basis": "databricks_target_pattern_rules",
            "candidate_only": True,
            "target_feasibility_established": False,
            "semantic_equivalence_established": False,
            "deployment_configuration_selected": False,
            "requires_confirmation": True,
        },
    )


def _mappings_for_input(
    workload: Workload, item: TargetStatePatternInput
) -> tuple[DatabricksPatternMapping, ...]:
    blockers = _common_blockers(item)
    results: list[DatabricksPatternMapping] = []

    if TargetExecutionBehavior.SCHEDULED in item.execution_behaviors:
        results.append(
            _mapping(
                workload,
                item,
                DatabricksTargetPattern.WORKFLOW_JOB,
                signals={"DBX-SCHEDULED-EXECUTION"},
                blockers=set(blockers),
                confidence=Confidence.MEDIUM if not blockers else Confidence.LOW,
            )
        )

    data_transform = (
        TargetDataBehavior.READS_DATA in item.data_behaviors
        and TargetDataBehavior.WRITES_DATA in item.data_behaviors
    )
    if data_transform:
        results.append(
            _mapping(
                workload,
                item,
                DatabricksTargetPattern.BATCH_SPARK,
                signals={"DBX-READ-WRITE-TRANSFORMATION"},
                blockers=set(blockers),
                confidence=Confidence.MEDIUM if not blockers else Confidence.LOW,
            )
        )

    incremental = next(
        (x for x in workload.batch_incremental_opportunities if x.boundary_id == item.boundary_id),
        None,
    )
    if incremental is not None:
        inc_blockers = set(blockers) | set(incremental.blocker_ids)
        results.append(
            _mapping(
                workload,
                item,
                DatabricksTargetPattern.INCREMENTAL_PIPELINE,
                signals={"DBX-INCREMENTAL-OPPORTUNITY", *incremental.signal_ids},
                blockers=inc_blockers,
                confidence=Confidence.LOW,
            )
        )

    if (
        TargetDataBehavior.WRITES_DATA in item.data_behaviors
        or TargetDataBehavior.PRODUCES_OUTPUT in item.data_behaviors
    ):
        results.append(
            _mapping(
                workload,
                item,
                DatabricksTargetPattern.DELTA_TABLE,
                signals={"DBX-PERSISTED-DATA-OUTPUT"},
                blockers=set(blockers),
                confidence=Confidence.MEDIUM if not blockers else Confidence.LOW,
            )
        )

    return tuple(results)


def derive_databricks_pattern_mappings(workload: Workload) -> Workload:
    """Map canonical target-state evidence to conservative Databricks candidates."""

    mappings = tuple(
        mapping
        for item in sorted(workload.target_state_pattern_inputs, key=lambda x: x.boundary_id)
        for mapping in _mappings_for_input(workload, item)
    )
    metadata = {
        **workload.metadata,
        "databricks_target_pattern_mapping": {
            "mapping_count": len(mappings),
            "basis": "databricks_target_pattern_rules",
            "automatic_selection": False,
            "target_feasibility_established": False,
            "semantic_equivalence_established": False,
            "governed_confirmation_required": True,
        },
    }
    return replace(workload, databricks_pattern_mappings=mappings, metadata=metadata)
