"""DP-03 distributed keyed aggregate acquisition and reconciliation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import sign_payload, verify_proof
from smf.validation.aggregate_tolerance import (
    AggregatePolicy,
    AggregateRequest,
    GroupObservation,
    evaluate_aggregates,
    verify_aggregate_result,
)

ObservationState = Literal["observed", "unavailable"]
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")
_MAX_GROUP_KEYS = 32
_MAX_GROUP_VALUE_LENGTH = 128


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _safe_id(value: str, label: str) -> None:
    lowered = value.casefold()
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or any(marker in lowered for marker in ("bearer", "secret", "password", "token"))
    ):
        raise ValueError(f"Unsafe DP-03 {label}")


@dataclass(frozen=True)
class DP03TrustPolicy:
    policy_id: str
    policy_version: str
    verification_keys: tuple[tuple[str, str], ...]
    source_key_ids: tuple[str, ...]
    target_key_ids: tuple[str, ...]
    source_authorities: tuple[str, ...]
    target_authorities: tuple[str, ...]
    group_token_key: bytes

    def public_payload(self) -> dict[str, Any]:
        _safe_id(self.policy_id, "trust policy id")
        _safe_id(self.policy_version, "trust policy version")
        keys = dict(self.verification_keys)
        if len(keys) != len(self.verification_keys):
            raise ValueError("Duplicate DP-03 verification key identity")
        source_keys, target_keys = set(self.source_key_ids), set(self.target_key_ids)
        if not source_keys or not target_keys or source_keys & target_keys:
            raise ValueError("DP-03 signing key domains must be non-empty and distinct")
        if not (source_keys | target_keys).issubset(keys):
            raise ValueError("DP-03 trust policy references an unknown signing key")
        try:
            key_material = {
                key_id: base64.b64decode(value, validate=True) for key_id, value in keys.items()
            }
        except (ValueError, binascii.Error) as exc:
            raise ValueError("DP-03 verification key is not canonical base64") from exc
        if any(len(value) != 32 for value in key_material.values()):
            raise ValueError("DP-03 verification keys must be Ed25519 public keys")
        if len(set(key_material.values())) != len(key_material):
            raise ValueError("DP-03 trust domains cannot alias public key material")
        if not self.source_authorities or not self.target_authorities:
            raise ValueError("DP-03 authority domains cannot be empty")
        if set(self.source_authorities) & set(self.target_authorities):
            raise ValueError("DP-03 authority domains must be distinct")
        for value in (
            *keys,
            *self.source_authorities,
            *self.target_authorities,
        ):
            _safe_id(value, "trust identity")
        if len(self.group_token_key) < 32:
            raise ValueError("DP-03 protected-group token key must be at least 32 bytes")
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "verification_keys": {key: keys[key] for key in sorted(keys)},
            "source_key_ids": sorted(source_keys),
            "target_key_ids": sorted(target_keys),
            "source_authorities": sorted(self.source_authorities),
            "target_authorities": sorted(self.target_authorities),
            "group_token_key_digest": "sha256:" + hashlib.sha256(self.group_token_key).hexdigest(),
        }

    @property
    def digest(self) -> str:
        return _digest(self.public_payload())


def _protected_group_value(value: str, trust_policy: DP03TrustPolicy) -> str:
    if len(value) > _MAX_GROUP_VALUE_LENGTH:
        raise ValueError("DP-03 group value exceeds the governed bound")
    if not contains_protected_data(value):
        return value
    token = hmac.new(trust_policy.group_token_key, value.encode(), hashlib.sha256).hexdigest()
    return f"protected-{token}"


def _protect_groups(
    groups: tuple[GroupObservation, ...], trust_policy: DP03TrustPolicy
) -> tuple[GroupObservation, ...]:
    protected: list[GroupObservation] = []
    for group in groups:
        if len(group.group) > _MAX_GROUP_KEYS:
            raise ValueError("DP-03 group key count exceeds the governed bound")
        protected.append(
            GroupObservation(
                tuple(
                    (key, _protected_group_value(value, trust_policy)) for key, value in group.group
                ),
                group.value,
                group.null_count,
            )
        )
    return tuple(protected)


def _reject_protected_groups(groups: tuple[GroupObservation, ...]) -> None:
    for group in groups:
        if any(contains_protected_data(value) for _, value in group.group):
            raise ValueError("DP-03 protected group value was not tokenized")


def _validate(name: str, payload: dict[str, Any]) -> None:
    schemas = {
        filename: json.loads(files("smf.schemas").joinpath(filename).read_text("utf-8"))
        for filename in (
            "dp03-aggregate-receipt.schema.json",
            "dp03-aggregate-result.schema.json",
            "aggregate-tolerance-result.schema.json",
        )
    }
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(cast(str, schema["$id"]), Resource.from_contents(schema))
    errors = sorted(
        Draft202012Validator(schemas[name], registry=registry).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"DP-03 schema validation failed: {detail}")


def _canonical_decimal(value: object) -> str:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Distributed aggregate value must be decimal") from exc
    if not parsed.is_finite():
        raise ValueError("Distributed aggregate value must be finite")
    return "0" if parsed == 0 else format(parsed.normalize(), "f")


@dataclass(frozen=True)
class AggregateDatasetBinding:
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
                raise ValueError(f"Invalid DP-03 {name}")
        return payload


@dataclass(frozen=True)
class SourceAggregateReceipt:
    receipt_id: str
    binding: AggregateDatasetBinding
    policy_digest: str
    groups: tuple[GroupObservation, ...]
    provider_id: str
    provider_version: str
    authority_id: str
    authority_digest: str
    content_digest: str
    proof: dict[str, str]
    schema_version: str = "1.0"

    @classmethod
    def prepare(
        cls,
        *,
        receipt_id: str,
        binding: AggregateDatasetBinding,
        policy_digest: str,
        groups: tuple[GroupObservation, ...],
        provider_id: str,
        provider_version: str,
        authority_id: str,
        authority_digest: str,
        trust_policy: DP03TrustPolicy,
        signing_key_path: Path,
        signing_key_id: str,
    ) -> SourceAggregateReceipt:
        if signing_key_id not in trust_policy.source_key_ids:
            raise ValueError("DP-03 source receipt signing key is not authorized")
        if authority_id not in trust_policy.source_authorities:
            raise ValueError("DP-03 source receipt authority is not authorized")
        protected_groups = _protect_groups(groups, trust_policy)
        candidate = cls(
            receipt_id,
            binding,
            policy_digest,
            protected_groups,
            provider_id,
            provider_version,
            authority_id,
            authority_digest,
            "sha256:" + "0" * 64,
            {},
        )
        content_digest = _digest(candidate.projection())
        payload = {**candidate.projection(), "content_digest": content_digest}
        sign_payload(payload, private_key_path=signing_key_path, key_id=signing_key_id)
        return cls(
            **{**candidate.__dict__, "content_digest": content_digest, "proof": payload["proof"]}
        )

    def projection(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "binding": self.binding.to_dict(),
            "policy_digest": self.policy_digest,
            "groups": [group.to_dict() for group in self.groups],
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        _reject_protected_groups(self.groups)
        for name in ("receipt_id", "provider_id", "provider_version", "authority_id"):
            _safe_id(cast(str, getattr(self, name)), name)
        for name in ("policy_digest", "authority_digest", "content_digest"):
            if not _DIGEST.fullmatch(cast(str, getattr(self, name))):
                raise ValueError(f"Invalid DP-03 {name}")
        payload = {
            **self.projection(),
            "content_digest": self.content_digest,
            "proof": dict(self.proof),
        }
        _validate("dp03-aggregate-receipt.schema.json", payload)
        if self.content_digest != _digest(self.projection()):
            raise ValueError("DP-03 source aggregate receipt digest mismatch")
        return payload


def _verify_source_receipt(receipt: SourceAggregateReceipt, trust_policy: DP03TrustPolicy) -> None:
    payload = receipt.to_dict()
    if receipt.authority_id not in trust_policy.source_authorities:
        raise ValueError("DP-03 source receipt authority is not trusted")
    verify_proof(
        payload,
        trusted_keys=dict(trust_policy.verification_keys),
        allowed_key_ids=set(trust_policy.source_key_ids),
    )


def publish_source_aggregate_receipt(
    root: Path, receipt: SourceAggregateReceipt, *, trust_policy: DP03TrustPolicy
) -> Path:
    _verify_source_receipt(receipt, trust_policy)
    payload = receipt.to_dict()
    path = root / "source-aggregate-receipts" / receipt.receipt_id / "receipt.json"
    publish_json(path, payload, "DP-03 source aggregate receipt", root=root)
    observed = read_published_json(path, root=root, label="DP-03 source aggregate receipt")
    if observed != payload:
        raise ValueError("Published DP-03 source receipt differs from candidate")
    return path


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DP-03 JSON contains a duplicate key")
        result[key] = value
    return result


def _read_bounded_json(root: Path, path: Path, maximum_groups: int) -> dict[str, Any]:
    root_path = root.resolve()
    candidate = path if path.is_absolute() else root_path / path
    try:
        relative = candidate.relative_to(root_path)
    except ValueError as exc:
        raise ValueError("DP-03 governed input escapes its authorized root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("DP-03 governed input path is unsafe")
    descriptors: list[int] = []
    try:
        current = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(current)
        for part in relative.parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        fd = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
        descriptors.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("DP-03 governed input must be a regular file")
        limit = 65_536 + maximum_groups * 32_768
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise ValueError("DP-03 source receipt exceeds the governed byte bound")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("DP-03 source receipt is not canonical JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("DP-03 source aggregate receipt must be an object")
    return payload


def load_source_aggregate_receipt(
    root: Path,
    path: Path,
    *,
    expected_content_digest: str,
    maximum_groups: int,
    trust_policy: DP03TrustPolicy,
) -> SourceAggregateReceipt:
    if not _DIGEST.fullmatch(expected_content_digest):
        raise ValueError("Invalid governed source aggregate receipt digest")
    payload = _read_bounded_json(root, path, maximum_groups)
    _validate("dp03-aggregate-receipt.schema.json", payload)
    groups = tuple(
        GroupObservation(
            tuple(cast(dict[str, str], item["group"]).items()), item["value"], item["null_count"]
        )
        for item in cast(list[dict[str, Any]], payload["groups"])
    )
    receipt = SourceAggregateReceipt(
        receipt_id=cast(str, payload["receipt_id"]),
        binding=AggregateDatasetBinding(**cast(dict[str, str], payload["binding"])),
        policy_digest=cast(str, payload["policy_digest"]),
        groups=groups,
        provider_id=cast(str, payload["provider_id"]),
        provider_version=cast(str, payload["provider_version"]),
        authority_id=cast(str, payload["authority_id"]),
        authority_digest=cast(str, payload["authority_digest"]),
        content_digest=cast(str, payload["content_digest"]),
        proof=cast(dict[str, str], payload["proof"]),
        schema_version=cast(str, payload["schema_version"]),
    )
    receipt.to_dict()
    _verify_source_receipt(receipt, trust_policy)
    if receipt.content_digest != expected_content_digest:
        raise ValueError("DP-03 source receipt does not match governed digest")
    return receipt


@dataclass(frozen=True)
class AggregateObservation:
    binding: AggregateDatasetBinding
    adapter_id: str
    adapter_version: str
    state: ObservationState
    reason: str
    groups: tuple[GroupObservation, ...]
    execution_id: str
    authority_id: str
    proof: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        _reject_protected_groups(self.groups)
        _safe_id(self.adapter_id, "adapter_id")
        _safe_id(self.adapter_version, "adapter_version")
        if self.state == "observed" and self.reason != "observed":
            raise ValueError("Observed DP-03 aggregate must use observed reason")
        if self.state == "unavailable" and (self.reason == "observed" or self.groups):
            raise ValueError("Unavailable DP-03 aggregate cannot carry groups")
        _safe_id(self.authority_id, "target authority")
        if not _DIGEST.fullmatch(self.execution_id):
            raise ValueError("Invalid DP-03 execution identity")
        return {
            "binding": self.binding.to_dict(),
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "state": self.state,
            "reason": self.reason,
            "groups": [group.to_dict() for group in self.groups],
            "execution_id": self.execution_id,
            "authority_id": self.authority_id,
            "proof": dict(self.proof),
        }


@dataclass(frozen=True)
class SparkKeyedAggregateAdapter:
    """Run group aggregation in Spark and stream only bounded aggregate rows."""

    dataframe: Any
    trust_policy: DP03TrustPolicy
    signing_key_path: Path
    signing_key_id: str
    authority_id: str
    adapter_id: ClassVar[str] = "spark-keyed-aggregate"
    adapter_version: ClassVar[str] = "1.0.0"

    def observe(
        self,
        binding: AggregateDatasetBinding,
        policy: AggregatePolicy,
        *,
        maximum_groups: int,
        request_digest: str,
    ) -> AggregateObservation:
        try:
            keys = list(policy.group_keys)
            measure = policy.measure_id
            sums = self.dataframe.groupBy(*keys).agg({measure: "sum"})
            non_nulls = self.dataframe.groupBy(*keys).agg({measure: "count"})
            totals = self.dataframe.groupBy(*keys).count()
            combined = sums.join(non_nulls, keys, "full_outer").join(totals, keys, "full_outer")
            groups: list[GroupObservation] = []
            for row in combined.toLocalIterator():
                if len(groups) >= maximum_groups:
                    return self.unavailable(
                        binding, "group_limit_exceeded", request_digest=request_digest
                    )
                values = row.asDict(recursive=False)
                if any(not isinstance(values[key], str) for key in policy.group_keys):
                    raise ValueError("Distributed aggregate group values must be canonical strings")
                total = values["count"]
                non_null = values[f"count({measure})"]
                if not isinstance(total, int) or not isinstance(non_null, int):
                    raise ValueError("Distributed aggregate counts must be integers")
                aggregate = values[f"sum({measure})"]
                groups.append(
                    GroupObservation(
                        tuple(
                            (
                                key,
                                _protected_group_value(values[key], self.trust_policy),
                            )
                            for key in policy.group_keys
                        ),
                        None if aggregate is None else _canonical_decimal(aggregate),
                        total - non_null,
                    )
                )
            ordered = tuple(
                sorted(groups, key=lambda item: tuple(value for _, value in item.group))
            )
            for item in ordered:
                item.to_dict()
            return self._signed(binding, "observed", "observed", ordered, request_digest)
        except Exception:
            return self.unavailable(binding, "provider_error", request_digest=request_digest)

    def unavailable(
        self, binding: AggregateDatasetBinding, reason: str, *, request_digest: str
    ) -> AggregateObservation:
        return self._signed(binding, "unavailable", reason, (), request_digest)

    def _signed(
        self,
        binding: AggregateDatasetBinding,
        state: ObservationState,
        reason: str,
        groups: tuple[GroupObservation, ...],
        request_digest: str,
    ) -> AggregateObservation:
        if self.signing_key_id not in self.trust_policy.target_key_ids:
            raise ValueError("DP-03 target signing key is not authorized")
        if self.authority_id not in self.trust_policy.target_authorities:
            raise ValueError("DP-03 target authority is not authorized")
        unsigned = {
            "binding": binding.to_dict(),
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "state": state,
            "reason": reason,
            "groups": [group.to_dict() for group in groups],
            "request_digest": request_digest,
        }
        execution_id = _digest(unsigned)
        candidate = AggregateObservation(
            binding,
            self.adapter_id,
            self.adapter_version,
            state,
            reason,
            groups,
            execution_id,
            self.authority_id,
            {},
        )
        payload = candidate.to_dict()
        sign_payload(payload, private_key_path=self.signing_key_path, key_id=self.signing_key_id)
        return AggregateObservation(**{**candidate.__dict__, "proof": payload["proof"]})


@dataclass(frozen=True)
class DP03Request:
    client_id: str
    workload_id: str
    run_id: str
    attempt_id: str
    evaluated_at: str
    source: AggregateDatasetBinding
    target: AggregateDatasetBinding
    source_receipt_id: str
    source_receipt_content_digest: str
    source_authority_id: str
    source_authority_digest: str
    trust_policy_digest: str
    maximum_groups: int
    target_adapter_id: str = SparkKeyedAggregateAdapter.adapter_id
    target_adapter_version: str = SparkKeyedAggregateAdapter.adapter_version

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
        for name in (
            "source_receipt_content_digest",
            "source_authority_digest",
            "trust_policy_digest",
        ):
            if not _DIGEST.fullmatch(cast(str, getattr(self, name))):
                raise ValueError(f"Invalid DP-03 {name}")
        if not _RFC3339.fullmatch(self.evaluated_at):
            raise ValueError("DP-03 evaluated_at must be canonical UTC RFC3339")
        datetime.fromisoformat(self.evaluated_at.removesuffix("Z") + "+00:00")
        if (
            not isinstance(self.maximum_groups, int)
            or isinstance(self.maximum_groups, bool)
            or not 1 <= self.maximum_groups <= 100_000
        ):
            raise ValueError("DP-03 maximum_groups must be between 1 and 100000")
        if (
            self.target_adapter_id != SparkKeyedAggregateAdapter.adapter_id
            or self.target_adapter_version != SparkKeyedAggregateAdapter.adapter_version
        ):
            raise ValueError("DP-03 target adapter is not the qualified implementation")
        return {
            **asdict(self),
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
        }


def _projection(
    request: DP03Request,
    receipt: SourceAggregateReceipt,
    target: AggregateObservation,
    policy: AggregatePolicy,
    trust_policy: DP03TrustPolicy,
) -> dict[str, Any]:
    request_payload, policy_payload = request.to_dict(), policy.to_dict()
    target_payload = target.to_dict()
    trust_payload = trust_policy.public_payload()
    if request.trust_policy_digest != trust_policy.digest:
        raise ValueError("DP-03 request does not bind the active trust policy")
    _verify_source_receipt(receipt, trust_policy)
    if target.authority_id not in trust_policy.target_authorities:
        raise ValueError("DP-03 target observation authority is not trusted")
    verify_proof(
        target_payload,
        trusted_keys=dict(trust_policy.verification_keys),
        allowed_key_ids=set(trust_policy.target_key_ids),
    )
    expected_policy_digest = _digest(policy_payload)
    if (
        receipt.receipt_id != request.source_receipt_id
        or receipt.binding != request.source
        or receipt.content_digest != request.source_receipt_content_digest
        or receipt.authority_id != request.source_authority_id
        or receipt.authority_digest != request.source_authority_digest
        or receipt.policy_digest != expected_policy_digest
    ):
        raise ValueError("DP-03 source receipt does not match governed request")
    expected_execution_id = _digest(
        {
            "binding": target.binding.to_dict(),
            "adapter_id": target.adapter_id,
            "adapter_version": target.adapter_version,
            "state": target.state,
            "reason": target.reason,
            "groups": [group.to_dict() for group in target.groups],
            "request_digest": _digest(request_payload),
        }
    )
    if target.binding != request.target or target.execution_id != expected_execution_id:
        raise ValueError("DP-03 target observation is not request-bound")
    blockers: list[str] = []
    if len(receipt.groups) > request.maximum_groups:
        blockers.append("source_group_limit_exceeded")
    if (
        request.source.scope_id != request.target.scope_id
        or request.source.scope_digest != request.target.scope_digest
    ):
        blockers.append("snapshot_scope_mismatch")
    if target.state != "observed" and not blockers:
        blockers.append(target.reason)
    aggregate_result: dict[str, Any] | None = None
    if not blockers:
        aggregate_result = evaluate_aggregates(
            AggregateRequest(
                request.client_id,
                request.workload_id,
                request.source.dataset_id,
                request.run_id,
                request.attempt_id,
                request.source.snapshot_digest,
                request.target.snapshot_digest,
                receipt.groups,
                target.groups,
            ),
            policy,
        )
        if aggregate_result["status"] == "blocked":
            blockers.append("aggregate_overflow_bound_exceeded")
    status = "blocked" if blockers else cast(dict[str, Any], aggregate_result)["status"]
    terminal_disposition = (
        "blocked"
        if status == "blocked"
        else "aggregate_matched"
        if status == "passed"
        else "aggregate_mismatch"
    )
    return {
        "schema_version": "1.0",
        "request": request_payload,
        "request_digest": _digest(request_payload),
        "source_receipt": receipt.to_dict(),
        "source_receipt_digest": receipt.content_digest,
        "target_observation": target_payload,
        "target_observation_digest": _digest(target_payload),
        "policy": policy_payload,
        "policy_digest": expected_policy_digest,
        "trust_policy": trust_payload,
        "trust_policy_digest": trust_policy.digest,
        "status": status,
        "terminal_disposition": terminal_disposition,
        "blockers": blockers,
        "aggregate_result": aggregate_result,
        "claims": {
            "generated": False,
            "executed": False,
            "reconciliation_executed": target.state == "observed",
            "distributed_target_aggregates_observed": target.state == "observed",
            "validated": status in {"passed", "failed"},
            "aggregate_check_passed": status == "passed",
            "cell_parity_passed": False,
            "data_parity_passed": False,
            "human_assisted": False,
            "blocked": status == "blocked",
            "certified": False,
            "humana_validated": False,
        },
    }


def reconcile_keyed_aggregates(
    request: DP03Request,
    *,
    source_receipt_root: Path,
    source_receipt_path: Path,
    target_adapter: SparkKeyedAggregateAdapter,
    policy: AggregatePolicy,
    trust_policy: DP03TrustPolicy,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    if cancelled is not None and cancelled():
        raise InterruptedError("DP-03 reconciliation cancelled before provider work")
    request.to_dict()
    policy_digest = _digest(policy.to_dict())
    if type(target_adapter) is not SparkKeyedAggregateAdapter:
        raise TypeError("DP-03 target adapter must be the exact qualified implementation")
    receipt = load_source_aggregate_receipt(
        source_receipt_root,
        source_receipt_path,
        expected_content_digest=request.source_receipt_content_digest,
        maximum_groups=request.maximum_groups,
        trust_policy=trust_policy,
    )
    if (
        receipt.receipt_id != request.source_receipt_id
        or receipt.binding != request.source
        or receipt.policy_digest != policy_digest
        or receipt.authority_id != request.source_authority_id
        or receipt.authority_digest != request.source_authority_digest
    ):
        raise ValueError("DP-03 source receipt does not match governed request")
    source_overflow = len(receipt.groups) > request.maximum_groups
    if not source_overflow:
        evaluate_aggregates(
            AggregateRequest(
                request.client_id,
                request.workload_id,
                request.source.dataset_id,
                request.run_id,
                request.attempt_id,
                request.source.snapshot_digest,
                request.source.snapshot_digest,
                receipt.groups,
                receipt.groups,
            ),
            policy,
        )
    request_digest = _digest(request.to_dict())
    if source_overflow or (
        request.source.scope_id != request.target.scope_id
        or request.source.scope_digest != request.target.scope_digest
    ):
        target = target_adapter.unavailable(
            request.target, "prerequisite_blocked", request_digest=request_digest
        )
    else:
        target = target_adapter.observe(
            request.target,
            policy,
            maximum_groups=request.maximum_groups,
            request_digest=request_digest,
        )
    if cancelled is not None and cancelled():
        raise InterruptedError("DP-03 reconciliation cancelled after provider work")
    if target.binding != request.target:
        raise ValueError("DP-03 target observation is not request-bound")
    current = load_source_aggregate_receipt(
        source_receipt_root,
        source_receipt_path,
        expected_content_digest=request.source_receipt_content_digest,
        maximum_groups=request.maximum_groups,
        trust_policy=trust_policy,
    )
    if current != receipt:
        raise ValueError("DP-03 source receipt changed during distributed aggregation")
    projection = _projection(request, receipt, target, policy, trust_policy)
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_dp03_result(result, trust_policy=trust_policy)
    return result


def verify_dp03_result(result: dict[str, Any], *, trust_policy: DP03TrustPolicy) -> None:
    _validate("dp03-aggregate-result.schema.json", result)
    content = dict(result)
    observed_digest = content.pop("content_digest")
    if observed_digest != _digest(content):
        raise ValueError("DP-03 content digest mismatch")
    projection = dict(content)
    observed_id = projection.pop("result_id")
    if observed_id != _digest(projection):
        raise ValueError("DP-03 result identity mismatch")
    raw_policy = cast(dict[str, Any], result["policy"])
    policy = AggregatePolicy(
        policy_id=raw_policy["policy_id"],
        policy_version=raw_policy["policy_version"],
        measure_id=raw_policy["measure_id"],
        group_keys=tuple(raw_policy["group_keys"]),
        absolute_tolerance=raw_policy["absolute_tolerance"],
        relative_tolerance=raw_policy["relative_tolerance"],
        maximum_absolute_value=raw_policy["maximum_absolute_value"],
        relative_denominator=raw_policy["relative_denominator"],
        null_rule=raw_policy["null_rule"],
        schema_version=raw_policy["schema_version"],
    )

    def binding(payload: dict[str, Any]) -> AggregateDatasetBinding:
        return AggregateDatasetBinding(**cast(dict[str, str], payload))

    def groups(payload: list[dict[str, Any]]) -> tuple[GroupObservation, ...]:
        return tuple(
            GroupObservation(
                tuple(cast(dict[str, str], item["group"]).items()),
                item["value"],
                item["null_count"],
            )
            for item in payload
        )

    raw_request = cast(dict[str, Any], result["request"])
    request = DP03Request(
        client_id=raw_request["client_id"],
        workload_id=raw_request["workload_id"],
        run_id=raw_request["run_id"],
        attempt_id=raw_request["attempt_id"],
        evaluated_at=raw_request["evaluated_at"],
        source=binding(raw_request["source"]),
        target=binding(raw_request["target"]),
        source_receipt_id=raw_request["source_receipt_id"],
        source_receipt_content_digest=raw_request["source_receipt_content_digest"],
        source_authority_id=raw_request["source_authority_id"],
        source_authority_digest=raw_request["source_authority_digest"],
        trust_policy_digest=raw_request["trust_policy_digest"],
        maximum_groups=raw_request["maximum_groups"],
        target_adapter_id=raw_request["target_adapter_id"],
        target_adapter_version=raw_request["target_adapter_version"],
    )
    raw_receipt = cast(dict[str, Any], result["source_receipt"])
    receipt = SourceAggregateReceipt(
        receipt_id=raw_receipt["receipt_id"],
        binding=binding(raw_receipt["binding"]),
        policy_digest=raw_receipt["policy_digest"],
        groups=groups(raw_receipt["groups"]),
        provider_id=raw_receipt["provider_id"],
        provider_version=raw_receipt["provider_version"],
        authority_id=raw_receipt["authority_id"],
        authority_digest=raw_receipt["authority_digest"],
        content_digest=raw_receipt["content_digest"],
        proof=raw_receipt["proof"],
        schema_version=raw_receipt["schema_version"],
    )
    receipt.to_dict()
    raw_target = cast(dict[str, Any], result["target_observation"])
    target = AggregateObservation(
        binding(raw_target["binding"]),
        raw_target["adapter_id"],
        raw_target["adapter_version"],
        raw_target["state"],
        raw_target["reason"],
        groups(raw_target["groups"]),
        raw_target["execution_id"],
        raw_target["authority_id"],
        raw_target["proof"],
    )
    if result["trust_policy"] != trust_policy.public_payload():
        raise ValueError("DP-03 result trust policy differs from active authority")
    expected_projection = _projection(request, receipt, target, policy, trust_policy)
    expected = {"result_id": _digest(expected_projection), **expected_projection}
    expected["content_digest"] = _digest(expected)
    if result != expected:
        raise ValueError("DP-03 result does not match governed observations and policy")
    aggregate = result["aggregate_result"]
    if aggregate is not None:
        verify_aggregate_result(cast(dict[str, Any], aggregate))


def result_path(root: Path, request: DP03Request) -> Path:
    request.to_dict()
    return (
        root
        / request.client_id
        / request.workload_id
        / request.run_id
        / request.attempt_id
        / "dp03"
        / "result.json"
    )


def publish_dp03_result(
    root: Path,
    request: DP03Request,
    *,
    source_receipt_root: Path,
    source_receipt_path: Path,
    target_adapter: SparkKeyedAggregateAdapter,
    policy: AggregatePolicy,
    trust_policy: DP03TrustPolicy,
    cancelled: Callable[[], bool] | None = None,
) -> Path:
    result = reconcile_keyed_aggregates(
        request,
        source_receipt_root=source_receipt_root,
        source_receipt_path=source_receipt_path,
        target_adapter=target_adapter,
        policy=policy,
        trust_policy=trust_policy,
        cancelled=cancelled,
    )
    if cancelled is not None and cancelled():
        raise InterruptedError("DP-03 publication cancelled before immutable write")
    path = result_path(root, request)
    publish_json(path, result, "DP-03 aggregate result", root=root)
    observed = read_published_json(path, root=root, label="DP-03 aggregate result")
    if not isinstance(observed, dict):
        raise ValueError("Published DP-03 result must be an object")
    verify_dp03_result(observed, trust_policy=trust_policy)
    if observed != result:
        raise ValueError("Published DP-03 result differs from candidate")
    return path
