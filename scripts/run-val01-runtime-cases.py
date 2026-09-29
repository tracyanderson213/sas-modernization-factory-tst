#!/usr/bin/env python3
"""Run each VAL-01 Spark case in an isolated OS session."""

from __future__ import annotations

import os
import subprocess
import sys
import time

CASES = (
    "test_qualified_spark_datacompy_full_row_comparison",
    "test_distributed_adversarial_comparisons[cell]",
    "test_distributed_adversarial_comparisons[unmatched]",
    "test_distributed_adversarial_comparisons[duplicate]",
    "test_distributed_adversarial_comparisons[null]",
    "test_distributed_adversarial_comparisons[type]",
    "test_unqualified_semantics_fail_unsupported[policy0]",
    "test_unqualified_semantics_fail_unsupported[policy1]",
    "test_configured_cell_semantics[tolerance_boundary-column0-True]",
    "test_configured_cell_semantics[tolerance_outside-column1-False]",
    "test_configured_cell_semantics[relative_boundary-column2-True]",
    "test_configured_cell_semantics[relative_outside-column3-False]",
    "test_configured_cell_semantics[null_equal-column4-True]",
    "test_configured_cell_semantics[null_different-column5-False]",
    "test_configured_cell_semantics[nan_equal-column6-True]",
    "test_configured_cell_semantics[nan_different-column7-False]",
    "test_configured_cell_semantics[infinity_equal-column8-True]",
    "test_configured_cell_semantics[infinity_different-column9-False]",
    "test_configured_cell_semantics[coercion-column10-True]",
    "test_configured_cell_semantics[invalid_coercion-column11-False]",
    "test_configured_cell_semantics[coercion_source_positive-column12-True]",
    "test_configured_cell_semantics[coercion_truncation-column13-False]",
    "test_configured_cell_semantics[coercion_overflow-column14-False]",
    "test_configured_cell_semantics[coercion_decimal_loss-column15-False]",
    "test_configured_cell_semantics[coercion_target_noncanonical-column16-False]",
    "test_configured_cell_semantics[coercion_source_noncanonical-column17-False]",
    "test_configured_cell_semantics[duplicate_tiebreak-column18-True]",
    "test_configured_cell_semantics[ambiguous_tiebreak-column19-False]",
    "test_configured_cell_semantics[ordered-column20-True]",
    "test_configured_cell_semantics[order_changed-column21-False]",
    "test_stale_snapshot_binding_rejected",
)


def main() -> int:
    requested = os.environ.get("SMF_VAL01_RUNTIME_CASE")
    cases = (requested,) if requested else CASES
    for case in cases:
        print(f"VAL-01 runtime case START: {case}", flush=True)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                f"tests/integration/test_val01_spark_runtime.py::{case}",
            ],
            check=False,
            start_new_session=True,
        )
        print(
            f"VAL-01 runtime case RETURN: {case} -> {completed.returncode}",
            flush=True,
        )
        if completed.returncode != 0:
            return completed.returncode
        time.sleep(10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
