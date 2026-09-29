"""OPS-01 immutable, gap-visible competition telemetry aggregation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_json

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_CLAIMS = (
    "generated",
    "executed",
    "validated",
    "parity_passed",
    "human_assisted",
    "blocked",
    "skipped",
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe(value: str, label: str) -> str:
    lowered = value.casefold()
    if (
        not isinstance(value, str)
        or not _ID.fullmatch(value)
        or value in {".", ".."}
        or any(marker in lowered for marker in ("secret", "password", "bearer", "token", "api-key"))
    ):
        raise ValueError(f"Unsafe OPS-01 {label}")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"OPS-01 {label} is not a SHA-256 digest")
    return value


def _time(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise ValueError(f"OPS-01 {label} is not canonical UTC")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"OPS-01 {label} is not canonical UTC")
    return parsed


def _schema(name: str) -> dict[str, Any]:
    value = json.loads(files("smf.schemas").joinpath(name).read_text("utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{name} must contain an object")
    return cast(dict[str, Any], value)


def _validate(payload: dict[str, Any], name: str, label: str) -> None:
    related = (
        "ops01-telemetry-event.schema.json",
        "ops01-telemetry-policy.schema.json",
        "ops01-telemetry-result.schema.json",
    )
    resources = []
    for schema_name in related:
        schema = _schema(schema_name)
        resources.append((cast(str, schema["$id"]), Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    errors = sorted(
        Draft202012Validator(_schema(name), registry=registry).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"{label} schema validation failed: {detail}")


@dataclass(frozen=True)
class TelemetryStream:
    workload_id: str
    run_id: str
    attempt_id: str
    source_artifact_id: str
    source_artifact_digest: str

    def binding(self) -> dict[str, str]:
        for name in ("workload_id", "run_id", "attempt_id", "source_artifact_id"):
            _safe(cast(str, getattr(self, name)), name)
        _sha(self.source_artifact_digest, "source_artifact_digest")
        return asdict(self)


@dataclass(frozen=True)
class TelemetryPolicy:
    policy_id: str
    policy_version: str
    client_id: str
    cohort_id: str
    authority_id: str
    authority_digest: str
    evaluated_at: str
    streams: tuple[TelemetryStream, ...]

    def binding(self) -> dict[str, Any]:
        for name in ("policy_id", "policy_version", "client_id", "cohort_id", "authority_id"):
            _safe(cast(str, getattr(self, name)), name)
        _sha(self.authority_digest, "authority_digest")
        _time(self.evaluated_at, "evaluated_at")
        streams = [stream.binding() for stream in self.streams]
        keys = [(item["workload_id"], item["run_id"], item["attempt_id"]) for item in streams]
        if not streams or keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("OPS-01 expected streams must be nonempty, unique, and sorted")
        return {
            "schema_version": "1.0",
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "client_id": self.client_id,
            "cohort_id": self.cohort_id,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
            "evaluated_at": self.evaluated_at,
            "streams": streams,
        }


@dataclass(frozen=True)
class TelemetryEventReference:
    workload_id: str
    run_id: str
    attempt_id: str
    event_id: str
    content_digest: str
    relative_path: str

    def binding(self) -> dict[str, str]:
        for name in ("workload_id", "run_id", "attempt_id", "event_id"):
            _safe(cast(str, getattr(self, name)), f"reference {name}")
        _sha(self.content_digest, "reference content_digest")
        path = Path(self.relative_path)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("OPS-01 event reference path is unsafe")
        return asdict(self)


def _verify_event(payload: dict[str, Any]) -> None:
    _validate(payload, "ops01-telemetry-event.schema.json", "OPS-01 event")
    for name in (
        "event_id",
        "client_id",
        "cohort_id",
        "workload_id",
        "run_id",
        "attempt_id",
        "source_artifact_id",
        "authority_id",
        "source_component",
        "source_schema_version",
        "source_result_id",
        "event_kind",
    ):
        _safe(cast(str, payload[name]), name)
    for name in ("source_artifact_digest", "authority_digest", "source_result_digest"):
        _sha(cast(str, payload[name]), name)
    _time(cast(str, payload["observed_at"]), "observed_at")
    claims = cast(dict[str, bool], payload["claims"])
    if claims["parity_passed"] and not (
        claims["validated"] and claims["executed"] and claims["generated"]
    ):
        raise ValueError("OPS-01 parity claim lacks prerequisite stages")
    if claims["validated"] and not (claims["executed"] and claims["generated"]):
        raise ValueError("OPS-01 validation claim lacks prerequisite stages")
    if claims["executed"] and not claims["generated"]:
        raise ValueError("OPS-01 execution claim lacks generation")
    if claims["blocked"] and claims["skipped"]:
        raise ValueError("OPS-01 blocked and skipped claims are mutually exclusive")
    evidence_class = payload["evidence_class"]
    if evidence_class in {"log", "recalled"} and (
        any(claims.values()) or payload["terminal_disposition"] is not None
    ):
        raise ValueError("OPS-01 logs or recalled events cannot establish workload truth")
    if claims["parity_passed"] and not (
        evidence_class == "canonical_validation" and payload["event_kind"] == "parity_result"
    ):
        raise ValueError("OPS-01 parity requires canonical validation evidence")
    if (claims["blocked"] or claims["skipped"]) and not payload["blocker_codes"]:
        raise ValueError("OPS-01 blocked or skipped event requires blocker codes")
    disposition = payload["terminal_disposition"]
    expected: dict[str, dict[str, bool]] = {
        "parity_passed": {
            "generated": True,
            "executed": True,
            "validated": True,
            "parity_passed": True,
            "blocked": False,
            "skipped": False,
        },
        "validated_no_parity": {
            "generated": True,
            "executed": True,
            "validated": True,
            "parity_passed": False,
            "blocked": False,
            "skipped": False,
        },
        "blocked": {"parity_passed": False, "blocked": True, "skipped": False},
        "failed": {"parity_passed": False, "blocked": False, "skipped": False},
        "unsupported": {"parity_passed": False, "blocked": False, "skipped": False},
        "cancelled": {"parity_passed": False, "blocked": False, "skipped": False},
        "outcome_unknown": {"parity_passed": False, "blocked": False, "skipped": False},
        "skipped": {"parity_passed": False, "blocked": False, "skipped": True},
    }
    if disposition is None:
        if claims["parity_passed"] or claims["blocked"] or claims["skipped"]:
            raise ValueError("OPS-01 terminal claim lacks a matching disposition")
    else:
        required = expected[cast(str, disposition)]
        if any(claims[name] is not value for name, value in required.items()):
            raise ValueError("OPS-01 terminal disposition and claims are inconsistent")
        if disposition == "parity_passed" and not (
            evidence_class == "canonical_validation" and payload["event_kind"] == "parity_result"
        ):
            raise ValueError("OPS-01 parity disposition lacks canonical validation evidence")
        if disposition in {
            "blocked",
            "failed",
            "unsupported",
            "outcome_unknown",
            "skipped",
        } and (evidence_class != "canonical_failure" or not payload["blocker_codes"]):
            raise ValueError("OPS-01 failure disposition requires canonical blocker evidence")
        if disposition == "validated_no_parity" and evidence_class != "canonical_validation":
            raise ValueError("OPS-01 validation disposition requires canonical validation evidence")
        if disposition == "cancelled" and evidence_class != "canonical_lifecycle":
            raise ValueError("OPS-01 cancellation requires canonical lifecycle evidence")
    if payload["content_digest"] != _digest({**payload, "content_digest": ""}):
        raise ValueError("OPS-01 event content digest mismatch")


def _load_event(root: Path, reference: TelemetryEventReference) -> dict[str, Any]:
    ref = reference.binding()
    payload = read_published_json(root / ref["relative_path"], root=root, label="OPS-01 event")
    if not isinstance(payload, dict):
        raise ValueError("OPS-01 event must be an object")
    _verify_event(payload)
    if any(
        payload[name] != ref[name]
        for name in ("workload_id", "run_id", "attempt_id", "event_id", "content_digest")
    ):
        raise ValueError("OPS-01 event reference mismatch")
    return payload


def _stream_projection(
    stream: TelemetryStream, events: list[dict[str, Any]], delivered: list[int]
) -> dict[str, Any]:
    if not events:
        return {
            **stream.binding(),
            "events": [],
            "delivery_sequence": [],
            "ingestion_state": "missing",
            "event_count": 0,
            "missing_sequences": [1],
            "out_of_order_delivery": False,
            "last_event_id": None,
            "terminal_disposition": "ingestion_incomplete",
            "observed_claims": {name: False for name in _CLAIMS},
            "qualified_claims": {name: False for name in _CLAIMS},
            "blocker_codes": ["telemetry_stream_missing"],
        }
    for event in events:
        _verify_event(event)
    events.sort(key=lambda item: item["sequence"])
    sequences = [item["sequence"] for item in events]
    if len(sequences) != len(set(sequences)):
        raise ValueError("OPS-01 duplicate event sequence")
    if sorted(delivered) != sequences:
        raise ValueError("OPS-01 delivery sequence differs from bound events")
    observed_times = [_time(cast(str, item["observed_at"]), "observed_at") for item in events]
    if observed_times != sorted(observed_times):
        raise ValueError("OPS-01 event time regresses across sequence")
    progressive = ("generated", "executed", "validated", "parity_passed", "human_assisted")
    for name in progressive:
        values = [cast(bool, item["claims"][name]) for item in events]
        if any(before and not after for before, after in zip(values, values[1:], strict=False)):
            raise ValueError(f"OPS-01 {name} claim regresses across sequence")
    terminal_indexes = [
        index for index, item in enumerate(events) if item["terminal_disposition"] is not None
    ]
    if terminal_indexes and terminal_indexes != [len(events) - 1]:
        raise ValueError("OPS-01 terminal disposition must occur once on the last event")
    missing = [value for value in range(1, max(sequences) + 1) if value not in sequences]
    out_of_order = delivered != sorted(delivered)
    observed = {name: any(item["claims"][name] for item in events) for name in _CLAIMS}
    if observed["parity_passed"] and not observed["validated"]:
        raise ValueError("OPS-01 stream parity lacks validation")
    blockers = sorted({code for item in events for code in item["blocker_codes"]})
    if missing:
        blockers.append("telemetry_sequence_gap")
    complete = not missing
    return {
        **stream.binding(),
        "events": events,
        "delivery_sequence": delivered,
        "ingestion_state": "complete" if complete else "gapped",
        "event_count": len(events),
        "missing_sequences": missing,
        "out_of_order_delivery": out_of_order,
        "last_event_id": events[-1]["event_id"],
        "terminal_disposition": events[-1]["terminal_disposition"]
        if complete
        else "ingestion_incomplete",
        "observed_claims": observed,
        "qualified_claims": observed if complete else {name: False for name in _CLAIMS},
        "blocker_codes": sorted(set(blockers)),
    }


def aggregate_telemetry(
    policy: TelemetryPolicy, evidence_root: Path, references: tuple[TelemetryEventReference, ...]
) -> dict[str, Any]:
    policy_value = policy.binding()
    stream_map = {(item.workload_id, item.run_id, item.attempt_id): item for item in policy.streams}
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {key: [] for key in stream_map}
    delivered: dict[tuple[str, str, str], list[int]] = {key: [] for key in stream_map}
    seen_events: set[str] = set()
    for reference in references:
        event = _load_event(evidence_root, reference)
        if event["event_id"] in seen_events:
            raise ValueError("OPS-01 duplicate event identity")
        seen_events.add(event["event_id"])
        key = (event["workload_id"], event["run_id"], event["attempt_id"])
        stream = stream_map.get(key)
        if stream is None:
            raise ValueError("OPS-01 event is outside the governed streams")
        if (
            event["client_id"] != policy.client_id
            or event["cohort_id"] != policy.cohort_id
            or event["authority_id"] != policy.authority_id
            or event["authority_digest"] != policy.authority_digest
            or event["source_artifact_id"] != stream.source_artifact_id
            or event["source_artifact_digest"] != stream.source_artifact_digest
            or _time(event["observed_at"], "observed_at")
            > _time(policy.evaluated_at, "evaluated_at")
        ):
            raise ValueError("OPS-01 event identity or authority differs from policy")
        grouped[key].append(event)
        delivered[key].append(event["sequence"])
    streams = [
        _stream_projection(stream, grouped[key], delivered[key])
        for key, stream in stream_map.items()
    ]
    bound_refs = sorted(
        (ref.binding() for ref in references),
        key=lambda item: (
            item["workload_id"],
            item["run_id"],
            item["attempt_id"],
            item["event_id"],
        ),
    )
    summary = {
        "expected_streams": len(streams),
        "complete_streams": sum(item["ingestion_state"] == "complete" for item in streams),
        "gapped_streams": sum(item["ingestion_state"] == "gapped" for item in streams),
        "missing_streams": sum(item["ingestion_state"] == "missing" for item in streams),
        "event_count": len(references),
        "out_of_order_streams": sum(item["out_of_order_delivery"] for item in streams),
    }
    projection = {
        "schema_version": "1.0",
        "policy": policy_value,
        "policy_digest": _digest(policy_value),
        "event_references": bound_refs,
        "event_set_digest": _digest(bound_refs),
        "streams": streams,
        "summary": summary,
        "claims": {
            "telemetry_aggregated": True,
            "parity_certified": False,
            "humana_validated": False,
            "production_observability": False,
            "migration_complete": False,
        },
    }
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_telemetry_result(result)
    return result


def verify_telemetry_result(result: dict[str, Any]) -> None:
    _validate(result, "ops01-telemetry-result.schema.json", "OPS-01 result")
    content = dict(result)
    observed_content = cast(str, content.pop("content_digest"))
    if observed_content != _digest(content):
        raise ValueError("OPS-01 result content digest mismatch")
    projection = dict(content)
    observed_id = cast(str, projection.pop("result_id"))
    if observed_id != _digest(projection):
        raise ValueError("OPS-01 result identity mismatch")
    policy_value = cast(dict[str, Any], result["policy"])
    policy = TelemetryPolicy(
        policy_value["policy_id"],
        policy_value["policy_version"],
        policy_value["client_id"],
        policy_value["cohort_id"],
        policy_value["authority_id"],
        policy_value["authority_digest"],
        policy_value["evaluated_at"],
        tuple(TelemetryStream(**item) for item in policy_value["streams"]),
    )
    if policy.binding() != policy_value:
        raise ValueError("OPS-01 policy projection is invalid")
    references = [TelemetryEventReference(**item).binding() for item in result["event_references"]]
    if references != sorted(
        references,
        key=lambda item: (
            item["workload_id"],
            item["run_id"],
            item["attempt_id"],
            item["event_id"],
        ),
    ):
        raise ValueError("OPS-01 event references are not canonical")
    streams = cast(list[dict[str, Any]], result["streams"])
    summary = cast(dict[str, int], result["summary"])
    expected_streams = [stream.binding() for stream in policy.streams]
    if [{key: item[key] for key in expected_streams[0]} for item in streams] != expected_streams:
        raise ValueError("OPS-01 stream projections differ from policy")
    for expected_stream, item in zip(policy.streams, streams, strict=True):
        reconstructed = _stream_projection(
            expected_stream,
            [dict(event) for event in cast(list[dict[str, Any]], item["events"])],
            list(cast(list[int], item["delivery_sequence"])),
        )
        if reconstructed != item:
            raise ValueError("OPS-01 stream projection does not reconstruct from bound events")
    expected = {
        "expected_streams": len(streams),
        "complete_streams": sum(item["ingestion_state"] == "complete" for item in streams),
        "gapped_streams": sum(item["ingestion_state"] == "gapped" for item in streams),
        "missing_streams": sum(item["ingestion_state"] == "missing" for item in streams),
        "event_count": sum(item["event_count"] for item in streams),
        "out_of_order_streams": sum(item["out_of_order_delivery"] for item in streams),
    }
    if summary != expected:
        raise ValueError("OPS-01 summary does not reconstruct from streams")
    if any(
        item["ingestion_state"] != "complete" and any(item["qualified_claims"].values())
        for item in streams
    ):
        raise ValueError("OPS-01 incomplete stream cannot qualify claims")
    if summary["event_count"] != len(references):
        raise ValueError("OPS-01 event denominator differs from references")
    embedded = sorted(
        (
            event["workload_id"],
            event["run_id"],
            event["attempt_id"],
            event["event_id"],
            event["content_digest"],
        )
        for stream in streams
        for event in stream["events"]
    )
    referenced = sorted(
        (
            ref["workload_id"],
            ref["run_id"],
            ref["attempt_id"],
            ref["event_id"],
            ref["content_digest"],
        )
        for ref in references
    )
    if embedded != referenced:
        raise ValueError("OPS-01 embedded events differ from governed references")
    if result["policy_digest"] != _digest(result["policy"]) or result[
        "event_set_digest"
    ] != _digest(result["event_references"]):
        raise ValueError("OPS-01 governed input digest mismatch")


def result_path(root: Path, policy: TelemetryPolicy) -> Path:
    policy.binding()
    return root / policy.client_id / policy.cohort_id / "ops01.json"


def publish_telemetry(
    output_root: Path,
    policy: TelemetryPolicy,
    evidence_root: Path,
    references: tuple[TelemetryEventReference, ...],
) -> Path:
    result = aggregate_telemetry(policy, evidence_root, references)
    path = result_path(output_root, policy)
    publish_json(path, result, "OPS-01 telemetry result", root=output_root)
    verify_current_telemetry(path, output_root, policy, evidence_root, references)
    return path


def verify_current_telemetry(
    path: Path,
    output_root: Path,
    policy: TelemetryPolicy,
    evidence_root: Path,
    references: tuple[TelemetryEventReference, ...],
) -> dict[str, Any]:
    if path != result_path(output_root, policy):
        raise ValueError("OPS-01 result path is not policy-bound")
    observed = read_published_json(path, root=output_root, label="OPS-01 telemetry result")
    if not isinstance(observed, dict):
        raise ValueError("OPS-01 published result must be an object")
    verify_telemetry_result(observed)
    current = aggregate_telemetry(policy, evidence_root, references)
    if observed != current:
        raise ValueError("OPS-01 current inputs do not reconstruct immutable evidence")
    return observed
