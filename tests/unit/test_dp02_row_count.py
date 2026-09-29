from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from smf.immutable_files import publish_json
from smf.validation.dp02 import (
    CountObservation,
    DatasetCountBinding,
    DP02Request,
    SourceCountReceipt,
    SparkDataFrameCountAdapter,
    load_source_count_receipt,
    publish_dp02_result,
    reconcile_row_counts,
    verify_current_dp02_result,
    verify_dp02_result,
)
from smf.validation.row_count import RowCountPolicy

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
POLICY = RowCountPolicy("competition-row-count", "1.0.0", "exact")


def _binding(role: str, *, scope_digest: str = DIGEST_C) -> DatasetCountBinding:
    return DatasetCountBinding(
        dataset_id=f"{role}-dataset",
        snapshot_id=f"{role}-snapshot",
        snapshot_digest=DIGEST_A if role == "source" else DIGEST_B,
        scope_id="competition-snapshot",
        scope_digest=scope_digest,
    )


def _receipt(
    count: int | None, *, binding: DatasetCountBinding | None = None
) -> SourceCountReceipt:
    return SourceCountReceipt.prepare(
        receipt_id="qualified-source-receipt",
        binding=binding or _binding("source"),
        count=count,
        provider_id="qualified-source-metadata",
        provider_version="1.0.0",
        authority_id="competition-source-authority",
        authority_digest=DIGEST_C,
    )


def _request(receipt: SourceCountReceipt, **changes: object) -> DP02Request:
    values: dict[str, object] = {
        "client_id": "synthetic-client",
        "workload_id": "workload-a",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "evaluated_at": "2026-09-21T22:00:00Z",
        "source": receipt.binding,
        "target": _binding("target"),
        "source_receipt_id": receipt.receipt_id,
        "source_receipt_content_digest": receipt.content_digest,
        "source_authority_id": receipt.authority_id,
        "source_authority_digest": receipt.authority_digest,
    }
    values.update(changes)
    return DP02Request(**values)  # type: ignore[arg-type]


class _Frame:
    def __init__(self, count: int, *, fail: bool = False) -> None:
        self.value = count
        self.fail = fail
        self.collect_called = False

    def count(self) -> int:
        if self.fail:
            raise RuntimeError("synthetic provider failure")
        return self.value

    def collect(self) -> list[object]:
        self.collect_called = True
        raise AssertionError("DP-02 must not collect rows")


def _publish_receipt(root: Path, receipt: SourceCountReceipt) -> Path:
    path = root / "source" / "receipt.json"
    publish_json(path, receipt.to_dict(), "synthetic source count receipt", root=root)
    return path


def _evaluate(
    source: int | None,
    target: int,
    *,
    frame: _Frame | None = None,
    request_change: dict[str, object] | None = None,
) -> dict[str, object]:
    receipt = _receipt(source)
    request = _request(receipt, **(request_change or {}))
    with TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        path = _publish_receipt(root, receipt)
        return reconcile_row_counts(
            request,
            source_receipt_root=root,
            source_receipt_path=path,
            target_adapter=SparkDataFrameCountAdapter(frame or _Frame(target)),
            policy=POLICY,
        )


def test_distributed_count_passes_without_collecting_rows() -> None:
    frame = _Frame(100)
    result = _evaluate(100, 100, frame=frame)
    assert result["status"] == "passed"
    assert result["reason"] == "within_tolerance"
    assert result["claims"]["distributed_target_count_observed"] is True  # type: ignore[index]
    assert result["claims"]["cell_parity_passed"] is False  # type: ignore[index]
    assert frame.collect_called is False


def test_equal_counts_never_claim_cell_or_data_parity() -> None:
    result = _evaluate(2, 2)
    assert result["claims"] == {
        "snapshot_scope_aligned": True,
        "distributed_target_count_observed": True,
        "row_count_check_passed": True,
        "cell_parity_passed": False,
        "data_parity_passed": False,
        "certified": False,
        "humana_validated": False,
    }


def test_outside_tolerance_is_failed_with_both_counts_preserved() -> None:
    result = _evaluate(100, 101)
    assert result["status"] == "failed"
    assert result["reason"] == "outside_tolerance"
    assert result["source_observation"]["count"] == 100  # type: ignore[index]
    assert result["target_observation"]["count"] == 101  # type: ignore[index]


def test_empty_datasets_are_explicit_and_pass_exact_policy() -> None:
    result = _evaluate(0, 0)
    assert result["status"] == "passed"
    assert result["tolerance_result"]["difference"] == 0  # type: ignore[index]


def test_missing_baseline_and_provider_failure_block_without_error_leakage() -> None:
    missing = _evaluate(None, 0)
    assert missing["status"] == "blocked"
    assert missing["reason"] == "source_count_unavailable"
    failed = _evaluate(1, 0, frame=_Frame(0, fail=True))
    assert failed["status"] == "blocked"
    assert failed["reason"] == "target_count_unavailable"
    assert "synthetic provider failure" not in str(failed)


def test_scope_digest_and_identity_mismatches_block() -> None:
    mismatched_digest = _evaluate(
        10, 10, request_change={"target": _binding("target", scope_digest=DIGEST_B)}
    )
    assert mismatched_digest["reason"] == "snapshot_scope_mismatch"
    mismatched_id = _evaluate(
        10, 10, request_change={"target": replace(_binding("target"), scope_id="other-scope")}
    )
    assert mismatched_id["reason"] == "snapshot_scope_mismatch"
    assert mismatched_id["tolerance_result"] is None


def test_invalid_evaluation_time_is_rejected_even_when_scope_is_blocked() -> None:
    with pytest.raises(ValueError, match="RFC3339"):
        _evaluate(
            10,
            10,
            request_change={
                "evaluated_at": "not-a-time",
                "target": _binding("target", scope_digest=DIGEST_B),
            },
        )


@pytest.mark.parametrize("count", [-1, True])
def test_negative_and_boolean_counts_are_rejected(count: object) -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _evaluate(1, 1, frame=_Frame(count))  # type: ignore[arg-type]


def test_forged_distributed_adapter_is_rejected() -> None:
    class ForgedAdapter(SparkDataFrameCountAdapter):
        def observe(self, binding: DatasetCountBinding) -> CountObservation:
            return CountObservation(
                binding, "forged", "1.0.0", "distributed_aggregate", "observed", 10
            )

    receipt = _receipt(10)
    with TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        path = _publish_receipt(root, receipt)
        with pytest.raises(TypeError, match="exact qualified"):
            reconcile_row_counts(
                _request(receipt),
                source_receipt_root=root,
                source_receipt_path=path,
                target_adapter=ForgedAdapter(_Frame(10)),
                policy=POLICY,
            )


def test_unqualified_target_adapter_is_a_rejected_precondition() -> None:
    receipt = _receipt(10)
    with TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        path = _publish_receipt(root, receipt)
        with pytest.raises(TypeError, match="exact qualified"):
            reconcile_row_counts(
                _request(receipt),
                source_receipt_root=root,
                source_receipt_path=path,
                target_adapter=object(),  # type: ignore[arg-type]
                policy=POLICY,
            )


def test_source_receipt_is_root_confined_and_request_bound(tmp_path: Path) -> None:
    receipt = _receipt(10)
    path = _publish_receipt(tmp_path, receipt)
    assert (
        load_source_count_receipt(tmp_path, path, expected_content_digest=receipt.content_digest)
        == receipt
    )
    substituted = _receipt(11)
    substituted_path = tmp_path / "source" / "substituted.json"
    publish_json(
        substituted_path, substituted.to_dict(), "substituted source count receipt", root=tmp_path
    )
    with pytest.raises(ValueError, match="governed digest"):
        reconcile_row_counts(
            _request(receipt),
            source_receipt_root=tmp_path,
            source_receipt_path=substituted_path,
            target_adapter=SparkDataFrameCountAdapter(_Frame(10)),
            policy=POLICY,
        )
    with pytest.raises(ValueError, match="traversal|escapes"):
        load_source_count_receipt(
            tmp_path,
            tmp_path / ".." / "outside.json",
            expected_content_digest=receipt.content_digest,
        )


def test_source_receipt_rejects_symlinks_and_authority_substitution(tmp_path: Path) -> None:
    receipt = _receipt(10)
    path = _publish_receipt(tmp_path, receipt)
    symlink = tmp_path / "source" / "linked.json"
    symlink.symlink_to(path)
    with pytest.raises(ValueError, match="symlinked|regular file"):
        load_source_count_receipt(tmp_path, symlink, expected_content_digest=receipt.content_digest)
    with pytest.raises(ValueError, match="governed request"):
        reconcile_row_counts(
            replace(_request(receipt), source_authority_digest=DIGEST_B),
            source_receipt_root=tmp_path,
            source_receipt_path=path,
            target_adapter=SparkDataFrameCountAdapter(_Frame(10)),
            policy=POLICY,
        )


def test_source_receipt_swap_during_distributed_count_fails(tmp_path: Path) -> None:
    receipt = _receipt(10)
    path = _publish_receipt(tmp_path, receipt)

    class MutatingFrame(_Frame):
        def count(self) -> int:
            path.write_text("{}\n", encoding="utf-8")
            return self.value

    with pytest.raises(ValueError, match="schema validation|content digest"):
        reconcile_row_counts(
            _request(receipt),
            source_receipt_root=tmp_path,
            source_receipt_path=path,
            target_adapter=SparkDataFrameCountAdapter(MutatingFrame(10)),
            policy=POLICY,
        )


def test_adapter_binds_the_requested_target_snapshot() -> None:
    receipt = _receipt(1)
    with TemporaryDirectory(dir=Path.cwd()) as directory:
        root = Path(directory)
        path = _publish_receipt(root, receipt)
        result = reconcile_row_counts(
            _request(receipt),
            source_receipt_root=root,
            source_receipt_path=path,
            target_adapter=SparkDataFrameCountAdapter(_Frame(1)),
            policy=POLICY,
        )
    assert result["target_observation"]["binding"] == _binding("target").to_dict()  # type: ignore[index]


def test_mutation_claim_escalation_and_nested_schema_weakening_are_rejected() -> None:
    result = _evaluate(1, 1)
    mutated = copy.deepcopy(result)
    mutated["target_observation"]["count"] = 2  # type: ignore[index]
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_dp02_result(mutated)
    escalated = copy.deepcopy(result)
    escalated["claims"]["data_parity_passed"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="schema validation"):
        verify_dp02_result(escalated)
    loose_policy = copy.deepcopy(result)
    loose_policy["policy"]["unknown"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="schema validation"):
        verify_dp02_result(loose_policy)
    loose_nested = copy.deepcopy(result)
    loose_nested["tolerance_result"].pop("request_digest")  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="schema validation"):
        verify_dp02_result(loose_nested)


def test_publication_replays_current_inputs_and_detects_drift(tmp_path: Path) -> None:
    receipt = _receipt(1)
    receipt_path = _publish_receipt(tmp_path, receipt)
    request = _request(receipt)
    frame = _Frame(1)
    result_file = publish_dp02_result(
        tmp_path,
        request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=SparkDataFrameCountAdapter(frame),
        policy=POLICY,
    )
    verify_current_dp02_result(
        result_file,
        request,
        evidence_root=tmp_path,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=SparkDataFrameCountAdapter(frame),
        policy=POLICY,
    )
    frame.value = 2
    with pytest.raises(ValueError, match="current inputs"):
        verify_current_dp02_result(
            result_file,
            request,
            evidence_root=tmp_path,
            source_receipt_root=tmp_path,
            source_receipt_path=receipt_path,
            target_adapter=SparkDataFrameCountAdapter(frame),
            policy=POLICY,
        )


def test_immutable_retry_mutation_and_workload_isolation(tmp_path: Path) -> None:
    receipt = _receipt(1)
    receipt_path = _publish_receipt(tmp_path, receipt)
    first_request = _request(receipt)
    first_path = publish_dp02_result(
        tmp_path,
        first_request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=SparkDataFrameCountAdapter(_Frame(1)),
        policy=POLICY,
    )
    assert (
        publish_dp02_result(
            tmp_path,
            first_request,
            source_receipt_root=tmp_path,
            source_receipt_path=receipt_path,
            target_adapter=SparkDataFrameCountAdapter(_Frame(1)),
            policy=POLICY,
        )
        == first_path
    )
    second_request = replace(first_request, workload_id="workload-b")
    second_path = publish_dp02_result(
        tmp_path,
        second_request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=SparkDataFrameCountAdapter(_Frame(1)),
        policy=POLICY,
    )
    assert second_path != first_path
    first_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises((FileExistsError, ValueError)):
        publish_dp02_result(
            tmp_path,
            first_request,
            source_receipt_root=tmp_path,
            source_receipt_path=receipt_path,
            target_adapter=SparkDataFrameCountAdapter(_Frame(1)),
            policy=POLICY,
        )


def test_public_and_packaged_schemas_match() -> None:
    root = Path(__file__).parents[2]
    for name in ("dp02-row-count-result.schema.json", "dp02-source-count-receipt.schema.json"):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()
