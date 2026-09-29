"""DP-02 distributed row-count acquisition and governed reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_json
from smf.validation.row_count import (
    RowCountPolicy,
    RowCountRequest,
    evaluate_row_count,
    verify_row_count_result,
)

ObservationMode = Literal["metadata", "distributed_aggregate"]
ObservationState = Literal["observed", "unavailable"]

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(payload: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical(payload)).hexdigest()}"


def _safe_id(value: str, label: str) -> None:
    lowered = value.casefold()
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or any(marker in lowered for marker in ("bearer", "secret", "password", "token"))
    ):
        raise ValueError(f"Unsafe {label}")


def _validate(payload: dict[str, Any]) -> None:
    schemas = {
        name: json.loads(files("smf.schemas").joinpath(name).read_text("utf-8"))
        for name in (
            "dp02-row-count-result.schema.json",
            "row-count-tolerance-policy.schema.json",
            "row-count-tolerance-result.schema.json",
        )
    }
    registry = Registry()
    for dependency in schemas.values():
        registry = registry.with_resource(
            cast(str, dependency["$id"]), Resource.from_contents(dependency)
        )
    errors = sorted(
        Draft202012Validator(
            schemas["dp02-row-count-result.schema.json"], registry=registry
        ).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"DP-02 result schema validation failed: {detail}")


def _validate_source_receipt(payload: dict[str, Any]) -> None:
    schema = json.loads(
        files("smf.schemas").joinpath("dp02-source-count-receipt.schema.json").read_text("utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"DP-02 source receipt schema validation failed: {detail}")


@dataclass(frozen=True)
class DatasetCountBinding:
    dataset_id: str
    snapshot_id: str
    snapshot_digest: str
    scope_id: str
    scope_digest: str

    def to_dict(self) -> dict[str, str]:
        payload = asdict(self)
        for name in ("dataset_id", "snapshot_id", "scope_id"):
            _safe_id(payload[name], name)
        for name in ("snapshot_digest", "scope_digest"):
            if not _DIGEST.fullmatch(payload[name]):
                raise ValueError(f"Invalid {name}")
        return payload


@dataclass(frozen=True)
class CountObservation:
    binding: DatasetCountBinding
    adapter_id: str
    adapter_version: str
    mode: ObservationMode
    state: ObservationState
    count: int | None

    def to_dict(self) -> dict[str, Any]:
        _safe_id(self.adapter_id, "adapter_id")
        _safe_id(self.adapter_version, "adapter_version")
        if self.state == "observed":
            if not isinstance(self.count, int) or isinstance(self.count, bool) or self.count < 0:
                raise ValueError("Observed row count must be a non-negative integer")
        elif self.count is not None:
            raise ValueError("Unavailable observation cannot carry a count")
        return {
            "binding": self.binding.to_dict(),
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "mode": self.mode,
            "state": self.state,
            "count": self.count,
        }


@dataclass(frozen=True)
class SourceCountReceipt:
    """A qualified source count bound to an immutable upstream receipt."""

    receipt_id: str
    binding: DatasetCountBinding
    count: int | None
    provider_id: str
    provider_version: str
    authority_id: str
    authority_digest: str
    content_digest: str
    schema_version: str = "1.0"

    @classmethod
    def prepare(
        cls,
        *,
        receipt_id: str,
        binding: DatasetCountBinding,
        count: int | None,
        provider_id: str,
        provider_version: str,
        authority_id: str,
        authority_digest: str,
    ) -> SourceCountReceipt:
        candidate = cls(
            receipt_id=receipt_id,
            binding=binding,
            count=count,
            provider_id=provider_id,
            provider_version=provider_version,
            authority_id=authority_id,
            authority_digest=authority_digest,
            content_digest="sha256:" + "0" * 64,
        )
        return cls(
            receipt_id=receipt_id,
            binding=binding,
            count=count,
            provider_id=provider_id,
            provider_version=provider_version,
            authority_id=authority_id,
            authority_digest=authority_digest,
            content_digest=_digest(candidate.projection()),
        )

    def projection(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "binding": self.binding.to_dict(),
            "count": self.count,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = {**self.projection(), "content_digest": self.content_digest}
        _validate_source_receipt(payload)
        for name in ("receipt_id", "provider_id", "provider_version", "authority_id"):
            _safe_id(cast(str, payload[name]), name)
        if not _DIGEST.fullmatch(self.authority_digest):
            raise ValueError("Invalid source receipt authority_digest")
        if self.content_digest != _digest(self.projection()):
            raise ValueError("DP-02 source receipt content digest mismatch")
        if self.count is not None and (
            not isinstance(self.count, int) or isinstance(self.count, bool) or self.count < 0
        ):
            raise ValueError("Source receipt count must be a non-negative integer or null")
        return payload

    def observation(self) -> CountObservation:
        self.to_dict()
        return CountObservation(
            binding=self.binding,
            adapter_id=self.provider_id,
            adapter_version=self.provider_version,
            mode="metadata",
            state="observed" if self.count is not None else "unavailable",
            count=self.count,
        )


def load_source_count_receipt(
    root: Path, path: Path, *, expected_content_digest: str
) -> SourceCountReceipt:
    if not _DIGEST.fullmatch(expected_content_digest):
        raise ValueError("Invalid expected source receipt digest")
    payload = read_published_json(path, root=root, label="DP-02 source count receipt")
    if not isinstance(payload, dict):
        raise ValueError("DP-02 source count receipt must be an object")
    _validate_source_receipt(payload)
    receipt = SourceCountReceipt(
        receipt_id=cast(str, payload["receipt_id"]),
        binding=DatasetCountBinding(**cast(dict[str, Any], payload["binding"])),
        count=payload.get("count"),
        provider_id=cast(str, payload["provider_id"]),
        provider_version=cast(str, payload["provider_version"]),
        authority_id=cast(str, payload["authority_id"]),
        authority_digest=cast(str, payload["authority_digest"]),
        content_digest=cast(str, payload["content_digest"]),
        schema_version=cast(str, payload["schema_version"]),
    )
    receipt.to_dict()
    if receipt.content_digest != expected_content_digest:
        raise ValueError("DP-02 source receipt does not match the governed digest")
    return receipt


@dataclass(frozen=True)
class SparkDataFrameCountAdapter:
    """Acquire only Spark's distributed aggregate count; never collect table rows."""

    dataframe: Any
    adapter_id: ClassVar[str] = "spark-dataframe-count"
    adapter_version: ClassVar[str] = "1.0.0"

    def observe(self, binding: DatasetCountBinding) -> CountObservation:
        try:
            count = self.dataframe.count()
        except Exception:  # provider errors become non-authorizing unavailable evidence
            count = None
        return CountObservation(
            binding=binding,
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            mode="distributed_aggregate",
            state="observed" if count is not None else "unavailable",
            count=count,
        )


@dataclass(frozen=True)
class DP02Request:
    client_id: str
    workload_id: str
    run_id: str
    attempt_id: str
    evaluated_at: str
    source: DatasetCountBinding
    target: DatasetCountBinding
    source_receipt_id: str
    source_receipt_content_digest: str
    source_authority_id: str
    source_authority_digest: str
    target_adapter_id: str = SparkDataFrameCountAdapter.adapter_id
    target_adapter_version: str = SparkDataFrameCountAdapter.adapter_version

    def to_dict(self) -> dict[str, Any]:
        for name in (
            "client_id",
            "workload_id",
            "run_id",
            "attempt_id",
            "source_receipt_id",
            "source_authority_id",
            "target_adapter_id",
            "target_adapter_version",
        ):
            _safe_id(cast(str, getattr(self, name)), name)
        for name in ("source_receipt_content_digest", "source_authority_digest"):
            if not _DIGEST.fullmatch(cast(str, getattr(self, name))):
                raise ValueError(f"Invalid {name}")
        if (
            self.target_adapter_id != SparkDataFrameCountAdapter.adapter_id
            or self.target_adapter_version != SparkDataFrameCountAdapter.adapter_version
        ):
            raise ValueError("DP-02 target adapter is not the qualified implementation")
        if not _RFC3339.fullmatch(self.evaluated_at):
            raise ValueError("evaluated_at must be canonical UTC RFC3339")
        try:
            datetime.fromisoformat(self.evaluated_at.removesuffix("Z") + "+00:00")
        except ValueError as exc:
            raise ValueError("evaluated_at must be canonical UTC RFC3339") from exc
        return {
            "client_id": self.client_id,
            "workload_id": self.workload_id,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "evaluated_at": self.evaluated_at,
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "source_receipt_id": self.source_receipt_id,
            "source_receipt_content_digest": self.source_receipt_content_digest,
            "source_authority_id": self.source_authority_id,
            "source_authority_digest": self.source_authority_digest,
            "target_adapter_id": self.target_adapter_id,
            "target_adapter_version": self.target_adapter_version,
        }


def _projection(
    request: DP02Request,
    source: CountObservation,
    target: CountObservation,
    policy: RowCountPolicy,
) -> dict[str, Any]:
    request_payload = request.to_dict()
    source_payload = source.to_dict()
    target_payload = target.to_dict()
    if source.binding != request.source or target.binding != request.target:
        raise ValueError("Count adapter observation is not bound to the requested snapshot")
    blockers: list[str] = []
    if (
        request.source.scope_id != request.target.scope_id
        or request.source.scope_digest != request.target.scope_digest
    ):
        blockers.append("snapshot_scope_mismatch")
    if source.state != "observed":
        blockers.append("source_count_unavailable")
    if target.state != "observed":
        blockers.append("target_count_unavailable")
    tolerance_result: dict[str, Any] | None = None
    if "snapshot_scope_mismatch" not in blockers:
        tolerance_result = evaluate_row_count(
            RowCountRequest(
                client_id=request.client_id,
                workload_id=request.workload_id,
                source_id=request.source.dataset_id,
                run_id=request.run_id,
                attempt_id=request.attempt_id,
                source_snapshot_id=request.source.snapshot_id,
                source_snapshot_digest=request.source.snapshot_digest,
                target_snapshot_id=request.target.snapshot_id,
                target_snapshot_digest=request.target.snapshot_digest,
                evaluated_at=request.evaluated_at,
                source_count=source.count,
                target_count=target.count,
            ),
            policy,
        )
    status = "blocked" if blockers else cast(dict[str, Any], tolerance_result)["status"]
    reason = (
        blockers[0]
        if blockers
        else "within_tolerance"
        if status == "passed"
        else "outside_tolerance"
    )
    return {
        "schema_version": "1.0",
        "request": request_payload,
        "request_digest": _digest(request_payload),
        "source_observation": source_payload,
        "source_observation_digest": _digest(source_payload),
        "target_observation": target_payload,
        "target_observation_digest": _digest(target_payload),
        "policy": policy.to_dict(),
        "status": status,
        "reason": reason,
        "blockers": blockers,
        "tolerance_result": tolerance_result,
        "claims": {
            "snapshot_scope_aligned": "snapshot_scope_mismatch" not in blockers,
            "distributed_target_count_observed": (
                target.mode == "distributed_aggregate" and target.state == "observed"
            ),
            "row_count_check_passed": status == "passed",
            "cell_parity_passed": False,
            "data_parity_passed": False,
            "certified": False,
            "humana_validated": False,
        },
    }


def reconcile_row_counts(
    request: DP02Request,
    *,
    source_receipt_root: Path,
    source_receipt_path: Path,
    target_adapter: SparkDataFrameCountAdapter,
    policy: RowCountPolicy,
) -> dict[str, Any]:
    request.to_dict()
    if type(target_adapter) is not SparkDataFrameCountAdapter:
        raise TypeError("DP-02 target adapter must be the exact qualified implementation")
    receipt = load_source_count_receipt(
        source_receipt_root,
        source_receipt_path,
        expected_content_digest=request.source_receipt_content_digest,
    )
    if (
        receipt.receipt_id != request.source_receipt_id
        or receipt.binding != request.source
        or receipt.authority_id != request.source_authority_id
        or receipt.authority_digest != request.source_authority_digest
    ):
        raise ValueError("DP-02 source receipt does not match the governed request")
    target_observation = target_adapter.observe(request.target)
    current_receipt = load_source_count_receipt(
        source_receipt_root,
        source_receipt_path,
        expected_content_digest=request.source_receipt_content_digest,
    )
    if current_receipt != receipt:
        raise ValueError("DP-02 source receipt changed during distributed count")
    projection = _projection(request, receipt.observation(), target_observation, policy)
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_dp02_result(result)
    return result


def verify_dp02_result(result: dict[str, Any]) -> None:
    _validate(result)
    content = dict(result)
    observed_content = cast(str, content.pop("content_digest"))
    if observed_content != _digest(content):
        raise ValueError("DP-02 content digest mismatch")
    projection = dict(content)
    observed_id = cast(str, projection.pop("result_id"))
    if observed_id != _digest(projection):
        raise ValueError("DP-02 result identity mismatch")
    request_payload = cast(dict[str, Any], result["request"])
    request = DP02Request(
        client_id=request_payload["client_id"],
        workload_id=request_payload["workload_id"],
        run_id=request_payload["run_id"],
        attempt_id=request_payload["attempt_id"],
        evaluated_at=request_payload["evaluated_at"],
        source=DatasetCountBinding(**request_payload["source"]),
        target=DatasetCountBinding(**request_payload["target"]),
        source_receipt_id=request_payload["source_receipt_id"],
        source_receipt_content_digest=request_payload["source_receipt_content_digest"],
        source_authority_id=request_payload["source_authority_id"],
        source_authority_digest=request_payload["source_authority_digest"],
        target_adapter_id=request_payload["target_adapter_id"],
        target_adapter_version=request_payload["target_adapter_version"],
    )
    source_payload = cast(dict[str, Any], result["source_observation"])
    target_payload = cast(dict[str, Any], result["target_observation"])
    source = CountObservation(
        binding=DatasetCountBinding(**source_payload["binding"]),
        **{key: value for key, value in source_payload.items() if key != "binding"},
    )
    target = CountObservation(
        binding=DatasetCountBinding(**target_payload["binding"]),
        **{key: value for key, value in target_payload.items() if key != "binding"},
    )
    policy = RowCountPolicy(**cast(dict[str, Any], result["policy"]))
    expected_projection = _projection(request, source, target, policy)
    expected = {"result_id": _digest(expected_projection), **expected_projection}
    expected["content_digest"] = _digest(expected)
    if result != expected:
        raise ValueError("DP-02 result does not match governed observations and policy")
    tolerance = result["tolerance_result"]
    if tolerance is not None:
        verify_row_count_result(cast(dict[str, Any], tolerance))


def result_path(root: Path, request: DP02Request) -> Path:
    request.to_dict()
    return (
        root
        / request.client_id
        / request.workload_id
        / request.run_id
        / request.attempt_id
        / "dp02"
        / "result.json"
    )


def publish_dp02_result(
    root: Path,
    request: DP02Request,
    *,
    source_receipt_root: Path,
    source_receipt_path: Path,
    target_adapter: SparkDataFrameCountAdapter,
    policy: RowCountPolicy,
) -> Path:
    result = reconcile_row_counts(
        request,
        source_receipt_root=source_receipt_root,
        source_receipt_path=source_receipt_path,
        target_adapter=target_adapter,
        policy=policy,
    )
    path = result_path(root, request)
    publish_json(path, result, "DP-02 row-count result", root=root)
    observed = read_published_json(path, root=root, label="DP-02 row-count result")
    if not isinstance(observed, dict):
        raise ValueError("Published DP-02 result must be an object")
    verify_dp02_result(observed)
    if observed != result:
        raise ValueError("Published DP-02 result differs from candidate")
    return path


def verify_current_dp02_result(
    result_path_value: Path,
    request: DP02Request,
    *,
    evidence_root: Path,
    source_receipt_root: Path,
    source_receipt_path: Path,
    target_adapter: SparkDataFrameCountAdapter,
    policy: RowCountPolicy,
) -> dict[str, Any]:
    expected_path = result_path(evidence_root, request)
    if result_path_value != expected_path:
        raise ValueError("DP-02 result path is not request-bound")
    observed = read_published_json(
        result_path_value, root=evidence_root, label="DP-02 row-count result"
    )
    if not isinstance(observed, dict):
        raise ValueError("Published DP-02 result must be an object")
    verify_dp02_result(observed)
    current = reconcile_row_counts(
        request,
        source_receipt_root=source_receipt_root,
        source_receipt_path=source_receipt_path,
        target_adapter=target_adapter,
        policy=policy,
    )
    if observed != current:
        raise ValueError("DP-02 current inputs do not reconstruct immutable evidence")
    return observed
