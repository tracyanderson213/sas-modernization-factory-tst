from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from smf.immutable_files import publish_json
from smf.operations.telemetry import (
    TelemetryEventReference,
    TelemetryPolicy,
    TelemetryStream,
    aggregate_telemetry,
    publish_telemetry,
    verify_current_telemetry,
    verify_telemetry_result,
)

SHA_A = "a" * 64
SHA_B = "b" * 64


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _stream(number: int) -> TelemetryStream:
    return TelemetryStream(f"workload-{number}", "run-1", "attempt-1", f"source-{number}", SHA_A)


def _policy(*streams: TelemetryStream, **changes: object) -> TelemetryPolicy:
    values: dict[str, object] = {
        "policy_id": "competition-telemetry",
        "policy_version": "1.0.0",
        "client_id": "synthetic-client",
        "cohort_id": "competition-cohort",
        "authority_id": "synthetic-telemetry-authority",
        "authority_digest": SHA_B,
        "evaluated_at": "2026-09-21T02:00:00Z",
        "streams": tuple(streams or (_stream(1), _stream(2))),
    }
    values.update(changes)
    return TelemetryPolicy(**values)  # type: ignore[arg-type]


def _event(
    workload: int,
    sequence: int,
    *,
    evidence_class: str = "canonical_lifecycle",
    event_kind: str = "lifecycle_projection",
    claims: tuple[bool, bool, bool, bool, bool, bool, bool] = (
        True,
        False,
        False,
        False,
        False,
        False,
        False,
    ),
    disposition: str | None = None,
    blockers: tuple[str, ...] = (),
) -> dict[str, Any]:
    generated, executed, validated, parity, human, blocked, skipped = claims
    payload = {
        "schema_version": "1.0",
        "event_id": f"event-{workload}-{sequence}",
        "sequence": sequence,
        "client_id": "synthetic-client",
        "cohort_id": "competition-cohort",
        "workload_id": f"workload-{workload}",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "source_artifact_id": f"source-{workload}",
        "source_artifact_digest": SHA_A,
        "authority_id": "synthetic-telemetry-authority",
        "authority_digest": SHA_B,
        "observed_at": f"2026-09-21T00:{workload}{sequence}:00Z",
        "evidence_class": evidence_class,
        "source_component": "synthetic-component",
        "source_schema_version": "v1",
        "source_result_id": f"source-result-{workload}-{sequence}",
        "source_result_digest": SHA_A,
        "event_kind": event_kind,
        "claims": {
            "generated": generated,
            "executed": executed,
            "validated": validated,
            "parity_passed": parity,
            "human_assisted": human,
            "blocked": blocked,
            "skipped": skipped,
        },
        "terminal_disposition": disposition,
        "blocker_codes": list(blockers),
        "content_digest": "",
    }
    payload["content_digest"] = _digest(payload)
    return payload


def _publish(root: Path, event: dict[str, Any]) -> TelemetryEventReference:
    relative = f"events/{event['workload_id']}/{event['event_id']}.json"
    publish_json(root / relative, event, "synthetic OPS event", root=root)
    return TelemetryEventReference(
        event["workload_id"],
        event["run_id"],
        event["attempt_id"],
        event["event_id"],
        event["content_digest"],
        relative,
    )


def _reseal(result: dict[str, Any]) -> None:
    projection = {
        key: value for key, value in result.items() if key not in {"result_id", "content_digest"}
    }
    result["result_id"] = _digest(projection)
    result["content_digest"] = _digest(
        {key: value for key, value in result.items() if key != "content_digest"}
    )


def test_canonical_parity_event_is_correlated_without_certifying_it(tmp_path: Path) -> None:
    ref = _publish(
        tmp_path,
        _event(
            1,
            1,
            evidence_class="canonical_validation",
            event_kind="parity_result",
            claims=(True, True, True, True, False, False, False),
            disposition="parity_passed",
        ),
    )
    result = aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))
    stream = result["streams"][0]
    assert stream["qualified_claims"]["parity_passed"] is True
    assert result["claims"]["parity_certified"] is False


@pytest.mark.parametrize("evidence_class", ["log", "recalled"])
def test_logs_and_recalled_events_cannot_establish_truth(
    tmp_path: Path, evidence_class: str
) -> None:
    ref = _publish(
        tmp_path,
        _event(
            1,
            1,
            evidence_class=evidence_class,
            claims=(True, False, False, False, False, False, False),
        ),
    )
    with pytest.raises(ValueError, match="cannot establish"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))


def test_non_validation_event_cannot_claim_parity(tmp_path: Path) -> None:
    ref = _publish(tmp_path, _event(1, 1, claims=(True, True, True, True, False, False, False)))
    with pytest.raises(ValueError, match="canonical validation"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))


def test_missing_and_gapped_streams_are_visible_and_non_authorizing(tmp_path: Path) -> None:
    gap = _publish(tmp_path, _event(1, 2, claims=(True, True, False, False, False, False, False)))
    result = aggregate_telemetry(_policy(), tmp_path, (gap,))
    assert result["summary"] == {
        "expected_streams": 2,
        "complete_streams": 0,
        "gapped_streams": 1,
        "missing_streams": 1,
        "event_count": 1,
        "out_of_order_streams": 0,
    }
    assert result["streams"][0]["missing_sequences"] == [1]
    assert not any(result["streams"][0]["qualified_claims"].values())
    assert result["streams"][1]["blocker_codes"] == ["telemetry_stream_missing"]


def test_out_of_order_delivery_is_sorted_without_inflation(tmp_path: Path) -> None:
    first = _publish(tmp_path, _event(1, 1))
    second = _publish(
        tmp_path, _event(1, 2, claims=(True, True, False, False, False, False, False))
    )
    result = aggregate_telemetry(_policy(_stream(1)), tmp_path, (second, first))
    stream = result["streams"][0]
    assert stream["event_count"] == 2
    assert stream["out_of_order_delivery"] is True
    assert stream["qualified_claims"]["executed"] is True


def test_duplicate_event_identity_and_sequence_are_rejected(tmp_path: Path) -> None:
    first = _publish(tmp_path, _event(1, 1))
    with pytest.raises(ValueError, match="duplicate event identity"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (first, first))
    other = _event(1, 1)
    other["event_id"] = "other-event"
    other["content_digest"] = ""
    other["content_digest"] = _digest(other)
    second = _publish(tmp_path, other)
    with pytest.raises(ValueError, match="duplicate event sequence"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (first, second))


def test_blocked_and_skipped_require_visible_reasons(tmp_path: Path) -> None:
    for claims, disposition in (
        ((False, False, False, False, False, True, False), "blocked"),
        ((False, False, False, False, False, False, True), "skipped"),
    ):
        root = tmp_path / disposition
        ref = _publish(root, _event(1, 1, claims=claims, disposition=disposition))
        with pytest.raises(ValueError, match="requires blocker"):
            aggregate_telemetry(_policy(_stream(1)), root, (ref,))


def test_scope_authority_secret_and_reference_boundaries(tmp_path: Path) -> None:
    wrong = _event(1, 1)
    wrong["authority_digest"] = SHA_A
    wrong["content_digest"] = ""
    wrong["content_digest"] = _digest(wrong)
    ref = _publish(tmp_path, wrong)
    with pytest.raises(ValueError, match="differs from policy"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))
    with pytest.raises(ValueError, match="Unsafe"):
        _policy(_stream(1), client_id="bearer-token").binding()
    with pytest.raises(ValueError, match="unsafe"):
        replace(ref, relative_path="../escape.json").binding()


def test_immutable_publication_replay_mutation_and_isolation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    output = tmp_path / "output"
    ref = _publish(evidence, _event(1, 1))
    policy = _policy(_stream(1))
    path = publish_telemetry(output, policy, evidence, (ref,))
    assert publish_telemetry(output, policy, evidence, (ref,)) == path
    assert verify_current_telemetry(path, output, policy, evidence, (ref,))["result_id"]
    alternate = _policy(_stream(2), cohort_id="other-cohort")
    event = _event(2, 1)
    event["cohort_id"] = "other-cohort"
    event["content_digest"] = ""
    event["content_digest"] = _digest(event)
    alt_root = tmp_path / "alt"
    alt_ref = _publish(alt_root, event)
    assert publish_telemetry(output, alternate, alt_root, (alt_ref,)) != path
    (evidence / ref.relative_path).write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation"):
        verify_current_telemetry(path, output, policy, evidence, (ref,))


def test_coherent_summary_gap_and_claim_escalation_are_rejected(tmp_path: Path) -> None:
    ref = _publish(tmp_path, _event(1, 2))
    result = aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))
    summary = copy.deepcopy(result)
    summary["summary"]["complete_streams"] = 1
    _reseal(summary)
    with pytest.raises(ValueError, match="summary"):
        verify_telemetry_result(summary)
    escalated = copy.deepcopy(result)
    escalated["streams"][0]["qualified_claims"]["parity_passed"] = True
    _reseal(escalated)
    with pytest.raises(ValueError, match="stream projection"):
        verify_telemetry_result(escalated)


@pytest.mark.parametrize(
    ("disposition", "claims", "evidence_class", "event_kind", "blockers"),
    [
        (
            "parity_passed",
            (True, True, True, False, False, False, False),
            "canonical_validation",
            "parity_result",
            (),
        ),
        (
            "validated_no_parity",
            (True, True, False, False, False, False, False),
            "canonical_validation",
            "validation_result",
            (),
        ),
        (
            "blocked",
            (False, False, False, False, False, False, False),
            "canonical_failure",
            "failure",
            ("blocked",),
        ),
        (
            "failed",
            (False, False, False, False, False, True, False),
            "canonical_failure",
            "failure",
            ("failed",),
        ),
        (
            "unsupported",
            (False, False, False, False, False, False, False),
            "canonical_lifecycle",
            "failure",
            ("unsupported",),
        ),
        (
            "skipped",
            (False, False, False, False, False, True, False),
            "canonical_failure",
            "failure",
            ("skipped",),
        ),
    ],
)
def test_terminal_disposition_requires_exact_claims_and_evidence(
    tmp_path: Path,
    disposition: str,
    claims: tuple[bool, bool, bool, bool, bool, bool, bool],
    evidence_class: str,
    event_kind: str,
    blockers: tuple[str, ...],
) -> None:
    ref = _publish(
        tmp_path,
        _event(
            1,
            1,
            disposition=disposition,
            claims=claims,
            evidence_class=evidence_class,
            event_kind=event_kind,
            blockers=blockers,
        ),
    )
    with pytest.raises(ValueError, match="terminal disposition|failure disposition"):
        aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))


def test_stream_rejects_claim_time_regression_and_events_after_terminal(tmp_path: Path) -> None:
    cases = [
        (
            _event(1, 1, claims=(True, True, False, False, False, False, False)),
            _event(1, 2, claims=(True, False, False, False, False, False, False)),
            "regresses",
        ),
        (_event(1, 1), _event(1, 2), "time regresses"),
        (
            _event(
                1,
                1,
                evidence_class="canonical_failure",
                claims=(True, False, False, False, False, True, False),
                disposition="blocked",
                blockers=("guarded",),
            ),
            _event(1, 2),
            "terminal disposition",
        ),
    ]
    cases[1][1]["observed_at"] = "2026-09-21T00:00:00Z"
    cases[1][1]["content_digest"] = ""
    cases[1][1]["content_digest"] = _digest(cases[1][1])
    for index, (first_event, second_event, message) in enumerate(cases):
        root = tmp_path / str(index)
        refs = (_publish(root, first_event), _publish(root, second_event))
        with pytest.raises(ValueError, match=message):
            aggregate_telemetry(_policy(_stream(1)), root, refs)


@pytest.mark.parametrize(
    "mutation",
    [
        "human_assisted",
        "terminal_disposition",
        "last_event_id",
        "out_of_order_delivery",
        "delivery_sequence",
        "event_content",
    ],
)
def test_coherently_resealed_stream_truth_mutations_are_rejected(
    tmp_path: Path, mutation: str
) -> None:
    refs = (_publish(tmp_path, _event(1, 1)),)
    result = aggregate_telemetry(_policy(_stream(1)), tmp_path, refs)
    altered = copy.deepcopy(result)
    stream = altered["streams"][0]
    if mutation == "human_assisted":
        stream["observed_claims"]["human_assisted"] = True
        stream["qualified_claims"]["human_assisted"] = True
    elif mutation == "terminal_disposition":
        stream["terminal_disposition"] = "cancelled"
    elif mutation == "last_event_id":
        stream["last_event_id"] = "invented-event"
    elif mutation == "out_of_order_delivery":
        stream["out_of_order_delivery"] = True
        altered["summary"]["out_of_order_streams"] = 1
    elif mutation == "delivery_sequence":
        stream["delivery_sequence"] = [2]
    else:
        stream["events"][0]["claims"]["human_assisted"] = True
        stream["events"][0]["content_digest"] = ""
        stream["events"][0]["content_digest"] = _digest(stream["events"][0])
    _reseal(altered)
    with pytest.raises(ValueError, match="reconstruct|references|digest|delivery sequence"):
        verify_telemetry_result(altered)


def test_strict_policy_schema_rejects_nested_unknown_fields(tmp_path: Path) -> None:
    ref = _publish(tmp_path, _event(1, 1))
    result = aggregate_telemetry(_policy(_stream(1)), tmp_path, (ref,))
    result["policy"]["unexpected"] = True
    _reseal(result)
    with pytest.raises(ValueError, match="schema validation"):
        verify_telemetry_result(result)


def test_public_and_packaged_schemas_match() -> None:
    root = Path(__file__).parents[2]
    for name in (
        "ops01-telemetry-event.schema.json",
        "ops01-telemetry-policy.schema.json",
        "ops01-telemetry-result.schema.json",
    ):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()
