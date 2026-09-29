from __future__ import annotations

from pathlib import Path

import pytest
from pilot_test_support import build_inventory, evaluate_selection

from smf.conversion import ConversionRequest, convert_workload
from smf.pilot import verify_selected_workload, write_manifest


def test_selection_admission_does_not_substitute_for_readiness(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    inventory = build_inventory(evidence_root)
    selection = evaluate_selection(evidence_root, inventory)
    path = write_manifest(tmp_path / "out", selection, inventory_root=evidence_root)
    hard = next(item for item in selection.decisions if item.workload_id == "WL-hard")
    verify_selected_workload(
        path,
        inventory_root=evidence_root,
        workload_id="WL-hard",
        boundary_id="WB-hard",
        source_closure_digest=hard.source_closure_digest,
        run_id="run-1",
        attempt_id="attempt-1",
    )
    with pytest.raises(ValueError, match="deployment readiness binding is required"):
        convert_workload(
            ConversionRequest(
                source_file=evidence_root / "sources/hard.sas",
                target="pyspark",
                output_dir=tmp_path / "conversion",
                workload_id="WL-hard",
                source_artifact_id="ART-hard",
                run_id="run-1",
                readiness_attempt_id="attempt-1",
            )
        )
