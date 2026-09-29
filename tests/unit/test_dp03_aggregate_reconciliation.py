from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import smf.validation.dp03 as dp03
from smf.validation.aggregate_tolerance import AggregatePolicy, GroupObservation
from smf.validation.dp03 import (
    AggregateDatasetBinding,
    DP03Request,
    DP03TrustPolicy,
    SourceAggregateReceipt,
    SparkKeyedAggregateAdapter,
    publish_dp03_result,
    publish_source_aggregate_receipt,
    reconcile_keyed_aggregates,
    verify_dp03_result,
)


class FakeRow:
    def __init__(self, values: dict[str, Any]) -> None:
        self.values = values

    def asDict(self, *, recursive: bool) -> dict[str, Any]:
        assert recursive is False
        return dict(self.values)


class FakeFrame:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        keys: tuple[str, ...],
        owner: FakeDataFrame,
    ) -> None:
        self.rows = rows
        self.keys = keys
        self.owner = owner

    def join(self, other: FakeFrame, keys: list[str], how: str) -> FakeFrame:
        assert tuple(keys) == self.keys
        assert how == "full_outer"
        indexed: dict[tuple[str, ...], dict[str, Any]] = {}
        for item in (*self.rows, *other.rows):
            key = tuple(str(item[name]) for name in self.keys)
            indexed.setdefault(key, {}).update(item)
        return FakeFrame(list(indexed.values()), self.keys, self.owner)

    def toLocalIterator(self) -> Any:
        self.owner.iterator_calls += 1
        if self.owner.on_iterate is not None:
            callback, self.owner.on_iterate = self.owner.on_iterate, None
            callback()
        return iter(FakeRow(row) for row in self.rows)

    def collect(self) -> None:
        raise AssertionError("DP-03 must not collect")

    def toPandas(self) -> None:
        raise AssertionError("DP-03 must not use pandas")


class FakeGrouped:
    def __init__(self, owner: FakeDataFrame, keys: tuple[str, ...]) -> None:
        self.owner = owner
        self.keys = keys

    def _groups(self) -> dict[tuple[str, ...], list[dict[str, Any]]]:
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for row in self.owner.rows:
            groups.setdefault(tuple(str(row[key]) for key in self.keys), []).append(row)
        return groups

    def agg(self, operation: dict[str, str]) -> FakeFrame:
        assert len(operation) == 1
        measure, name = next(iter(operation.items()))
        output: list[dict[str, Any]] = []
        for identity, rows in self._groups().items():
            values = [row[measure] for row in rows if row[measure] is not None]
            base: dict[str, Any] = dict(zip(self.keys, identity, strict=True))
            if name == "sum":
                base[f"sum({measure})"] = sum(values) if values else None
            elif name == "count":
                base[f"count({measure})"] = len(values)
            else:
                raise AssertionError(name)
            output.append(base)
        return FakeFrame(output, self.keys, self.owner)

    def count(self) -> FakeFrame:
        output = [
            {**dict(zip(self.keys, identity, strict=True)), "count": len(rows)}
            for identity, rows in self._groups().items()
        ]
        return FakeFrame(output, self.keys, self.owner)


class FakeDataFrame:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        fail: bool = False,
        on_iterate: Any = None,
    ) -> None:
        self.rows = rows
        self.fail = fail
        self.on_iterate = on_iterate
        self.group_by_calls = 0
        self.iterator_calls = 0

    def groupBy(self, *keys: str) -> FakeGrouped:
        self.group_by_calls += 1
        if self.fail:
            raise RuntimeError("synthetic provider diagnostic must not persist")
        return FakeGrouped(self, tuple(keys))


def _policy(**overrides: Any) -> AggregatePolicy:
    values: dict[str, Any] = {
        "policy_id": "aggregate-policy",
        "policy_version": "1.0.0",
        "measure_id": "amount",
        "group_keys": ("region",),
        "absolute_tolerance": "1",
        "relative_tolerance": "0",
        "maximum_absolute_value": "1000000",
    }
    values.update(overrides)
    return AggregatePolicy(**values)


def _group(key: str, value: str | None, null_count: int = 0) -> GroupObservation:
    return GroupObservation((("region", key),), value, null_count)


def _binding(name: str, *, scope: str = "shared") -> AggregateDatasetBinding:
    return AggregateDatasetBinding(
        name,
        f"{name}-snapshot",
        "sha256:" + ("1" if name == "source" else "2") * 64,
        scope,
        "sha256:" + "3" * 64,
    )


_CONTEXTS: dict[str, tuple[DP03TrustPolicy, Path, Path]] = {}


def _context(root: Path) -> tuple[DP03TrustPolicy, Path, Path]:
    identity = str(root)
    if identity in _CONTEXTS:
        return _CONTEXTS[identity]
    root.mkdir(parents=True, exist_ok=True)
    values: list[tuple[Path, str]] = []
    for name in ("source", "target"):
        private = Ed25519PrivateKey.generate()
        path = root / f"{name}.pem"
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public = base64.b64encode(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii")
        values.append((path, public))
    trust = DP03TrustPolicy(
        "dp03-trust",
        "1.0.0",
        (("source-key", values[0][1]), ("target-key", values[1][1])),
        ("source-key",),
        ("target-key",),
        ("source-authority",),
        ("target-authority",),
        b"dp03-protected-group-token-key-0001",
    )
    _CONTEXTS[identity] = (trust, values[0][0], values[1][0])
    return _CONTEXTS[identity]


def _adapter(root: Path, frame: FakeDataFrame) -> SparkKeyedAggregateAdapter:
    trust, _, target_key = _context(root)
    return SparkKeyedAggregateAdapter(frame, trust, target_key, "target-key", "target-authority")


def _prepared(
    root: Path,
    source_groups: tuple[GroupObservation, ...],
    *,
    policy: AggregatePolicy | None = None,
    workload_id: str = "workload-1",
    attempt_id: str = "attempt-1",
    target_scope: str = "shared",
    maximum_groups: int = 100,
) -> tuple[DP03Request, AggregatePolicy, Path]:
    selected = policy or _policy()
    trust, source_key, _ = _context(root)
    receipt = SourceAggregateReceipt.prepare(
        receipt_id=f"receipt-{attempt_id}",
        binding=_binding("source"),
        policy_digest=dp03._digest(selected.to_dict()),
        groups=source_groups,
        provider_id="qualified-source-aggregate",
        provider_version="1.0.0",
        authority_id="source-authority",
        authority_digest="sha256:" + "4" * 64,
        trust_policy=trust,
        signing_key_path=source_key,
        signing_key_id="source-key",
    )
    receipt_path = publish_source_aggregate_receipt(root, receipt, trust_policy=trust)
    request = DP03Request(
        "synthetic-client",
        workload_id,
        "run-1",
        attempt_id,
        "2026-09-22T12:00:00Z",
        receipt.binding,
        _binding("target", scope=target_scope),
        receipt.receipt_id,
        receipt.content_digest,
        receipt.authority_id,
        receipt.authority_digest,
        trust.digest,
        maximum_groups,
    )
    return request, selected, receipt_path


def _run(
    root: Path,
    source: tuple[GroupObservation, ...],
    rows: list[dict[str, Any]],
    **kwargs: Any,
) -> tuple[dict[str, Any], FakeDataFrame]:
    request, policy, receipt_path = _prepared(root, source, **kwargs)
    frame = FakeDataFrame(rows)
    trust, _, _ = _context(root)
    result = reconcile_keyed_aggregates(
        request,
        source_receipt_root=root,
        source_receipt_path=receipt_path,
        target_adapter=_adapter(root, frame),
        policy=policy,
        trust_policy=trust,
    )
    return result, frame


def test_distributed_keyed_aggregate_passes_without_collect_or_pandas(tmp_path: Path) -> None:
    result, frame = _run(
        tmp_path,
        (_group("east", "100"), _group("west", "200", 1)),
        [
            {"region": "east", "amount": 40},
            {"region": "east", "amount": 60},
            {"region": "west", "amount": 200},
            {"region": "west", "amount": None},
        ],
    )
    assert result["status"] == "passed"
    assert result["claims"]["distributed_target_aggregates_observed"] is True
    assert result["claims"]["aggregate_check_passed"] is True
    assert result["claims"]["cell_parity_passed"] is False
    assert result["claims"]["data_parity_passed"] is False
    assert frame.group_by_calls == 3
    assert frame.iterator_calls == 1


def test_offsetting_group_errors_and_missing_group_do_not_disappear(tmp_path: Path) -> None:
    failed, _ = _run(
        tmp_path / "offset",
        (_group("east", "100"), _group("west", "200")),
        [{"region": "east", "amount": 102}, {"region": "west", "amount": 198}],
    )
    assert failed["status"] == "failed"
    assert [item["status"] for item in failed["aggregate_result"]["checks"]] == ["failed", "failed"]

    missing, _ = _run(
        tmp_path / "missing",
        (_group("east", "100"), _group("west", "200")),
        [{"region": "east", "amount": 100}],
    )
    assert missing["status"] == "failed"
    assert any(item["reason"] == "missing_group" for item in missing["aggregate_result"]["checks"])


def test_overflow_null_mismatch_and_group_limit_fail_closed(tmp_path: Path) -> None:
    overflow, _ = _run(
        tmp_path / "overflow",
        (_group("east", "100"),),
        [{"region": "east", "amount": 101}],
        policy=_policy(maximum_absolute_value="100"),
    )
    assert overflow["status"] == "blocked"
    assert overflow["blockers"] == ["aggregate_overflow_bound_exceeded"]
    assert overflow["aggregate_result"]["checks"][0]["reason"] == "overflow_bound_exceeded"

    nulls, _ = _run(
        tmp_path / "nulls",
        (_group("east", "100", 0),),
        [{"region": "east", "amount": 100}, {"region": "east", "amount": None}],
    )
    assert nulls["status"] == "failed"
    assert nulls["aggregate_result"]["checks"][0]["reason"] == "null_count_mismatch"

    limited, frame = _run(
        tmp_path / "limit",
        (_group("a", "1"), _group("b", "2")),
        [{"region": "a", "amount": 1}, {"region": "b", "amount": 2}],
        maximum_groups=1,
    )
    assert limited["status"] == "blocked"
    assert limited["blockers"] == ["source_group_limit_exceeded"]
    assert frame.group_by_calls == 0

    target_limited, target_frame = _run(
        tmp_path / "target-limit",
        (_group("a", "1"),),
        [{"region": "a", "amount": 1}, {"region": "b", "amount": 2}],
        maximum_groups=1,
    )
    assert target_limited["status"] == "blocked"
    assert target_limited["blockers"] == ["group_limit_exceeded"]
    assert target_frame.iterator_calls == 1


def test_source_and_target_group_limit_exact_boundary_passes(tmp_path: Path) -> None:
    result, frame = _run(
        tmp_path,
        (_group("a", "1"), _group("b", "2")),
        [{"region": "a", "amount": 1}, {"region": "b", "amount": 2}],
        maximum_groups=2,
    )
    assert result["status"] == "passed"
    assert frame.iterator_calls == 1


def test_provider_failure_is_categorical_and_diagnostic_is_not_persisted(tmp_path: Path) -> None:
    request, policy, receipt_path = _prepared(tmp_path, (_group("east", "1"),))
    trust, _, _ = _context(tmp_path)
    result = reconcile_keyed_aggregates(
        request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=_adapter(tmp_path, FakeDataFrame([], fail=True)),
        policy=policy,
        trust_policy=trust,
    )
    assert result["status"] == "blocked"
    assert result["blockers"] == ["provider_error"]
    assert "synthetic provider diagnostic" not in json.dumps(result)


def test_scope_mismatch_blocks_before_distributed_access(tmp_path: Path) -> None:
    request, policy, receipt_path = _prepared(
        tmp_path, (_group("east", "1"),), target_scope="different"
    )
    frame = FakeDataFrame([{"region": "east", "amount": 1}])
    trust, _, _ = _context(tmp_path)
    result = reconcile_keyed_aggregates(
        request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=_adapter(tmp_path, frame),
        policy=policy,
        trust_policy=trust,
    )
    assert result["blockers"] == ["snapshot_scope_mismatch"]
    assert result["claims"]["reconciliation_executed"] is False
    assert frame.group_by_calls == 0


def test_receipt_mutation_during_distributed_work_is_rejected(tmp_path: Path) -> None:
    request, policy, receipt_path = _prepared(tmp_path, (_group("east", "1"),))

    def mutate() -> None:
        receipt_path.write_text("{}", encoding="utf-8")

    frame = FakeDataFrame([{"region": "east", "amount": 1}], on_iterate=mutate)
    trust, _, _ = _context(tmp_path)
    with pytest.raises(ValueError, match="schema validation|governed digest"):
        reconcile_keyed_aggregates(
            request,
            source_receipt_root=tmp_path,
            source_receipt_path=receipt_path,
            target_adapter=_adapter(tmp_path, frame),
            policy=policy,
            trust_policy=trust,
        )


def test_result_mutation_and_coherent_outer_rehash_are_rejected(tmp_path: Path) -> None:
    result, _ = _run(
        tmp_path,
        (_group("east", "1"),),
        [{"region": "east", "amount": 1}],
    )
    forged = json.loads(json.dumps(result))
    forged["claims"]["aggregate_check_passed"] = False
    forged_projection = dict(forged)
    forged_projection.pop("result_id")
    forged_projection.pop("content_digest")
    forged["result_id"] = dp03._digest(forged_projection)
    forged_without_digest = dict(forged)
    forged_without_digest.pop("content_digest")
    forged["content_digest"] = dp03._digest(forged_without_digest)
    with pytest.raises(ValueError, match="governed observations|claim"):
        verify_dp03_result(forged, trust_policy=_context(tmp_path)[0])


def _rehash_result(result: dict[str, Any]) -> None:
    projection = dict(result)
    projection.pop("result_id", None)
    projection.pop("content_digest", None)
    result["result_id"] = dp03._digest(projection)
    without_digest = dict(result)
    without_digest.pop("content_digest", None)
    result["content_digest"] = dp03._digest(without_digest)


def test_signed_source_and_target_provenance_rejects_coherent_rehash(
    tmp_path: Path,
) -> None:
    result, _ = _run(
        tmp_path,
        (_group("east", "1"),),
        [{"region": "east", "amount": 1}],
    )
    trust, _, _ = _context(tmp_path)

    forged_source = json.loads(json.dumps(result))
    forged_source["source_receipt"]["authority_digest"] = "sha256:" + "9" * 64
    source_projection = dict(forged_source["source_receipt"])
    source_projection.pop("proof")
    source_projection.pop("content_digest")
    forged_source["source_receipt"]["content_digest"] = dp03._digest(source_projection)
    forged_source["source_receipt_digest"] = forged_source["source_receipt"]["content_digest"]
    forged_source["request"]["source_authority_digest"] = "sha256:" + "9" * 64
    forged_source["request"]["source_receipt_content_digest"] = forged_source[
        "source_receipt_digest"
    ]
    forged_source["request_digest"] = dp03._digest(forged_source["request"])
    _rehash_result(forged_source)
    with pytest.raises(ValueError, match="signature"):
        verify_dp03_result(forged_source, trust_policy=trust)

    forged_target = json.loads(json.dumps(result))
    forged_target["target_observation"]["groups"][0]["value"] = "2"
    execution = {
        key: forged_target["target_observation"][key]
        for key in ("binding", "adapter_id", "adapter_version", "state", "reason", "groups")
    }
    execution["request_digest"] = forged_target["request_digest"]
    forged_target["target_observation"]["execution_id"] = dp03._digest(execution)
    forged_target["target_observation_digest"] = dp03._digest(forged_target["target_observation"])
    _rehash_result(forged_target)
    with pytest.raises(ValueError, match="signature"):
        verify_dp03_result(forged_target, trust_policy=trust)


@pytest.mark.parametrize(
    "protected_value",
    (
        "123-45-6789",
        "alice@example.com",
        "member_id: ABCD1234",
        "c2VjcmV0LWNhbmFyeS12YWx1ZQ==",
    ),
)
def test_protected_group_values_are_irreversibly_tokenized(
    tmp_path: Path, protected_value: str
) -> None:
    result, _ = _run(
        tmp_path,
        (_group(protected_value, "1"),),
        [{"region": protected_value, "amount": 1}],
    )
    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "passed"
    assert protected_value not in serialized
    assert result["source_receipt"]["groups"][0]["group"]["region"].startswith("protected-")
    assert result["target_observation"]["groups"][0]["group"]["region"].startswith("protected-")


def test_protected_provider_error_and_direct_raw_evidence_fail_closed(tmp_path: Path) -> None:
    request, policy, receipt_path = _prepared(tmp_path, (_group("member_id: ABCD1234", "1"),))
    trust, _, _ = _context(tmp_path)
    result = reconcile_keyed_aggregates(
        request,
        source_receipt_root=tmp_path,
        source_receipt_path=receipt_path,
        target_adapter=_adapter(tmp_path, FakeDataFrame([], fail=True)),
        policy=policy,
        trust_policy=trust,
    )
    assert result["blockers"] == ["provider_error"]
    assert "ABCD1234" not in json.dumps(result)
    raw_receipt = replace(
        SourceAggregateReceipt.prepare(
            receipt_id="raw-receipt",
            binding=_binding("source"),
            policy_digest=dp03._digest(policy.to_dict()),
            groups=(_group("safe", "1"),),
            provider_id="qualified-source-aggregate",
            provider_version="1.0.0",
            authority_id="source-authority",
            authority_digest="sha256:" + "4" * 64,
            trust_policy=trust,
            signing_key_path=_context(tmp_path)[1],
            signing_key_id="source-key",
        ),
        groups=(_group("123-45-6789", "1"),),
    )
    with pytest.raises(ValueError, match="not tokenized"):
        raw_receipt.to_dict()


def test_publication_is_idempotent_and_workloads_are_isolated(tmp_path: Path) -> None:
    request_a, policy, receipt_a = _prepared(
        tmp_path / "receipts-a", (_group("east", "1"),), workload_id="workload-a"
    )
    adapter_a = _adapter(tmp_path / "receipts-a", FakeDataFrame([{"region": "east", "amount": 1}]))
    trust_a, _, _ = _context(tmp_path / "receipts-a")
    path_a = publish_dp03_result(
        tmp_path / "evidence",
        request_a,
        source_receipt_root=tmp_path / "receipts-a",
        source_receipt_path=receipt_a,
        target_adapter=adapter_a,
        policy=policy,
        trust_policy=trust_a,
    )
    adapter_retry = _adapter(
        tmp_path / "receipts-a", FakeDataFrame([{"region": "east", "amount": 1}])
    )
    assert (
        publish_dp03_result(
            tmp_path / "evidence",
            request_a,
            source_receipt_root=tmp_path / "receipts-a",
            source_receipt_path=receipt_a,
            target_adapter=adapter_retry,
            policy=policy,
            trust_policy=trust_a,
        )
        == path_a
    )

    request_b, policy_b, receipt_b = _prepared(
        tmp_path / "receipts-b", (_group("west", "2"),), workload_id="workload-b"
    )
    trust_b, _, _ = _context(tmp_path / "receipts-b")
    path_b = publish_dp03_result(
        tmp_path / "evidence",
        request_b,
        source_receipt_root=tmp_path / "receipts-b",
        source_receipt_path=receipt_b,
        target_adapter=_adapter(
            tmp_path / "receipts-b", FakeDataFrame([{"region": "west", "amount": 2}])
        ),
        policy=policy_b,
        trust_policy=trust_b,
    )
    assert path_a != path_b
    assert path_a.read_bytes() != path_b.read_bytes()


def test_missing_receipt_unsafe_identity_and_wrong_policy_fail_closed(tmp_path: Path) -> None:
    request, policy, receipt_path = _prepared(tmp_path, (_group("east", "1"),))
    receipt_path.unlink()
    trust, _, _ = _context(tmp_path)
    with pytest.raises(FileNotFoundError):
        reconcile_keyed_aggregates(
            request,
            source_receipt_root=tmp_path,
            source_receipt_path=receipt_path,
            target_adapter=_adapter(tmp_path, FakeDataFrame([])),
            policy=policy,
            trust_policy=trust,
        )

    with pytest.raises(ValueError, match="Unsafe DP-03"):
        replace(request, client_id="secret-canary").to_dict()

    other_root = tmp_path / "wrong-policy"
    other_request, _, other_receipt = _prepared(other_root, (_group("east", "1"),))
    other_trust, _, _ = _context(other_root)
    with pytest.raises(ValueError, match="does not match governed request"):
        reconcile_keyed_aggregates(
            other_request,
            source_receipt_root=other_root,
            source_receipt_path=other_receipt,
            target_adapter=_adapter(other_root, FakeDataFrame([])),
            policy=_policy(absolute_tolerance="2"),
            trust_policy=other_trust,
        )


def test_schema_mirrors_are_exact() -> None:
    root = Path(__file__).resolve().parents[2]
    for name in ("dp03-aggregate-receipt.schema.json", "dp03-aggregate-result.schema.json"):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()


def test_cancellation_bounds_provider_work_and_prevents_publication(tmp_path: Path) -> None:
    receipt_root = tmp_path / "receipts"
    request, policy, receipt_path = _prepared(receipt_root, (_group("east", "1"),))
    trust, _, _ = _context(receipt_root)
    frame = FakeDataFrame([{"region": "east", "amount": 1}])

    with pytest.raises(InterruptedError, match="before provider work"):
        reconcile_keyed_aggregates(
            request,
            source_receipt_root=receipt_root,
            source_receipt_path=receipt_path,
            target_adapter=_adapter(receipt_root, frame),
            policy=policy,
            trust_policy=trust,
            cancelled=lambda: True,
        )
    assert frame.group_by_calls == 0

    after_provider = iter((False, True))
    active_frame = FakeDataFrame([{"region": "east", "amount": 1}])
    with pytest.raises(InterruptedError, match="after provider work"):
        reconcile_keyed_aggregates(
            request,
            source_receipt_root=receipt_root,
            source_receipt_path=receipt_path,
            target_adapter=_adapter(receipt_root, active_frame),
            policy=policy,
            trust_policy=trust,
            cancelled=lambda: next(after_provider),
        )
    assert active_frame.group_by_calls > 0

    checks = iter((False, False, True))
    evidence_root = tmp_path / "cancelled-evidence"
    with pytest.raises(InterruptedError, match="before immutable write"):
        publish_dp03_result(
            evidence_root,
            request,
            source_receipt_root=receipt_root,
            source_receipt_path=receipt_path,
            target_adapter=_adapter(receipt_root, FakeDataFrame([{"region": "east", "amount": 1}])),
            policy=policy,
            trust_policy=trust,
            cancelled=lambda: next(checks),
        )
    assert not evidence_root.exists()
