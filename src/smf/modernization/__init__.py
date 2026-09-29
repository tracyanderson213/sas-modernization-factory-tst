"""Modernization decision-input foundations."""

from smf.modernization.consolidate import derive_consolidation_candidates
from smf.modernization.databricks_patterns import derive_databricks_pattern_mappings
from smf.modernization.delivery_path import derive_delivery_path_candidates
from smf.modernization.disposition import derive_modernization_disposition_inputs
from smf.modernization.incremental import derive_batch_incremental_opportunities
from smf.modernization.intermediate import derive_intermediate_artifact_elimination_opportunities
from smf.modernization.manifest import derive_target_state_manifest
from smf.modernization.rationale import derive_modernization_rationale_evidence
from smf.modernization.redundancy import derive_logic_similarity_findings
from smf.modernization.retire import derive_retire_candidates
from smf.modernization.target_state import derive_target_state_pattern_inputs
from smf.modernization.waves import derive_migration_wave_groups

__all__ = [
    "derive_batch_incremental_opportunities",
    "derive_consolidation_candidates",
    "derive_databricks_pattern_mappings",
    "derive_delivery_path_candidates",
    "derive_intermediate_artifact_elimination_opportunities",
    "derive_migration_wave_groups",
    "derive_modernization_disposition_inputs",
    "derive_modernization_rationale_evidence",
    "derive_retire_candidates",
    "derive_logic_similarity_findings",
    "derive_target_state_manifest",
    "derive_target_state_pattern_inputs",
]
