from __future__ import annotations

import base64
import hashlib
import json
import math
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import smf.validation.dp04 as dp04
from smf.validation.dp04 import (
    ProfileIdentity,
    SasMissing,
    load_policy,
    profile_partition,
    publish_result,
    reconcile_profiles,
    verify_partition,
    verify_result,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
_SOURCE_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TARGET_PRIVATE_KEY = Ed25519PrivateKey.generate()
_SOURCE_PUBLIC_KEY = base64.b64encode(
    _SOURCE_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode()
_TARGET_PUBLIC_KEY = base64.b64encode(
    _TARGET_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
).decode()


def _policy_value(*, method: str = "exact", fraction: str = "1") -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "policy_id": "dp04-strict",
        "policy_version": "v1",
        "columns": [
            {
                "name": "amount",
                "kind": "numeric",
                "numeric_bins": ["0", "10", "100"],
                "categories": [],
                "absolute_tolerance": "0.01",
                "relative_tolerance": "0",
            },
            {
                "name": "status",
                "kind": "categorical",
                "numeric_bins": [],
                "categories": ["paid", "denied"],
                "absolute_tolerance": "0",
                "relative_tolerance": "0",
            },
        ],
        "sampling": {
            "method": method,
            "fraction": fraction,
            "seed": "seed-v1",
            "key_columns": [] if method == "exact" else ["claim_id"],
        },
        "receipt_authorities": [
            {
                "side": "source",
                "authority_id": "fixture-source-authority",
                "key_id": "fixture-source-key",
                "provider_id": "synthetic-source",
                "provider_version": "1",
                "evidence_class": "synthetic_contract",
                "public_key": _SOURCE_PUBLIC_KEY,
            },
            {
                "side": "target",
                "authority_id": "fixture-target-authority",
                "key_id": "fixture-target-key",
                "provider_id": "synthetic-target",
                "provider_version": "1",
                "evidence_class": "synthetic_contract",
                "public_key": _TARGET_PUBLIC_KEY,
            },
        ],
    }


def _policy(tmp_path: Path, **kwargs: str) -> Any:
    path = tmp_path / f"policy-{kwargs.get('method', 'exact')}.json"
    path.write_text(json.dumps(_policy_value(**kwargs)), encoding="utf-8")
    return load_policy(path)


def _identity(side: str, *, workload: str = "workload-1") -> ProfileIdentity:
    return ProfileIdentity(
        client_id="synthetic-client",
        workload_id=workload,
        source_digest=SHA_A if side == "source" else SHA_B,
        run_id="run-1",
        attempt_id="attempt-1",
        artifact_id="claims",
        snapshot_digest=SHA_A if side == "source" else SHA_B,
        provider_id=f"synthetic-{side}",
        provider_version="1",
    )


def _rows() -> list[dict[str, Any]]:
    return [
        {"claim_id": "1", "amount": "5", "status": "paid"},
        {"claim_id": "2", "amount": None, "status": "denied"},
        {"claim_id": "3", "amount": SasMissing(".A"), "status": None},
        {"claim_id": "4", "amount": SasMissing("._"), "status": "other"},
        {"claim_id": "5", "amount": "15", "status": "paid"},
    ]


def _profile_partition(*args: Any, **kwargs: Any) -> dict[str, Any]:
    side = kwargs["side"]
    return profile_partition(
        *args,
        **kwargs,
        authority_id=(
            "fixture-source-authority" if side == "source" else "fixture-target-authority"
        ),
        key_id="fixture-source-key" if side == "source" else "fixture-target-key",
        evidence_class="synthetic_contract",
        signer=(_SOURCE_PRIVATE_KEY.sign if side == "source" else _TARGET_PRIVATE_KEY.sign),
    )


def _profiles(tmp_path: Path) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]]]:
    policy = _policy(tmp_path)
    rows = _rows()
    source = [
        _profile_partition(
            iter(rows[:2]),
            partition_id="source-0",
            side="source",
            identity=_identity("source"),
            policy=policy,
        ),
        _profile_partition(
            iter(rows[2:]),
            partition_id="source-1",
            side="source",
            identity=_identity("source"),
            policy=policy,
        ),
    ]
    target = [
        _profile_partition(
            iter(rows[:3]),
            partition_id="target-0",
            side="target",
            identity=_identity("target"),
            policy=policy,
        ),
        _profile_partition(
            iter(rows[3:]),
            partition_id="target-1",
            side="target",
            identity=_identity("target"),
            policy=policy,
        ),
    ]
    return policy, source, target


def test_distributed_exact_profiles_reconcile_without_collecting_rows(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    result = reconcile_profiles(source, target, policy=policy)
    assert result["outcome"] == "passed"
    assert result["source_profile"]["partition_count"] == 2
    amount = next(item for item in result["source_profile"]["columns"] if item["name"] == "amount")
    assert amount["ordinary_null_count"] == 1
    assert amount["sas_missing_counts"][".A"] == 1
    assert amount["sas_missing_counts"]["._"] == 1
    assert amount["bin_counts"] == [0, 1, 1, 0]
    assert result["claims"] == {
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "human_approved": False,
        "production_ready": False,
    }


def test_ordinary_and_each_sas_missing_category_are_not_collapsed(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    source_rows = [
        {"claim_id": str(index), "amount": SasMissing(code), "status": "paid"}
        for index, code in enumerate([".", "._", ".A", ".Z"])
    ]
    target_rows = deepcopy(source_rows)
    target_rows[2]["amount"] = None
    source = [
        _profile_partition(
            source_rows,
            partition_id="s",
            side="source",
            identity=_identity("source"),
            policy=policy,
        )
    ]
    target = [
        _profile_partition(
            target_rows,
            partition_id="t",
            side="target",
            identity=_identity("target"),
            policy=policy,
        )
    ]
    result = reconcile_profiles(source, target, policy=policy)
    assert result["outcome"] == "failed"
    failures = [item for item in result["checks"] if item["status"] == "fail"]
    assert {item["metric"] for item in failures} >= {"ordinary_null_count", "sas_missing_counts"}


def test_shifted_distribution_and_all_missing_are_distinct_failures(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    source_rows = [{"claim_id": "1", "amount": None, "status": "paid"}]
    target_rows = [{"claim_id": "1", "amount": "500", "status": "denied"}]
    source = [
        _profile_partition(
            source_rows,
            partition_id="s",
            side="source",
            identity=_identity("source"),
            policy=policy,
        )
    ]
    target = [
        _profile_partition(
            target_rows,
            partition_id="t",
            side="target",
            identity=_identity("target"),
            policy=policy,
        )
    ]
    result = reconcile_profiles(source, target, policy=policy)
    assert result["outcome"] == "failed"
    failed_metrics = {item["metric"] for item in result["checks"] if item["status"] == "fail"}
    assert "all_missing" in failed_metrics
    assert "bin_counts" in failed_metrics
    assert "category_counts" in failed_metrics


def test_incompatible_sampling_method_is_not_a_distribution_match(tmp_path: Path) -> None:
    exact = _policy(tmp_path)
    sampled = _policy(tmp_path, method="deterministic_hash", fraction="0.5")
    rows = _rows()
    source = [
        _profile_partition(
            rows, partition_id="s", side="source", identity=_identity("source"), policy=exact
        )
    ]
    target = [
        _profile_partition(
            rows, partition_id="t", side="target", identity=_identity("target"), policy=sampled
        )
    ]
    result = reconcile_profiles(source, target, policy=exact)
    assert result["outcome"] == "incompatible"
    assert "partition_profile_blocked" in result["blockers"]
    assert result["claims"]["validated"] is False


def test_deterministic_sample_scope_is_partition_independent_and_key_bound(tmp_path: Path) -> None:
    policy = _policy(tmp_path, method="deterministic_hash", fraction="1")
    rows = _rows()
    source = [
        _profile_partition(
            rows[:2],
            partition_id="s0",
            side="source",
            identity=_identity("source"),
            policy=policy,
        ),
        _profile_partition(
            rows[2:],
            partition_id="s1",
            side="source",
            identity=_identity("source"),
            policy=policy,
        ),
    ]
    target = [
        _profile_partition(
            rows,
            partition_id="t0",
            side="target",
            identity=_identity("target"),
            policy=policy,
        )
    ]
    assert reconcile_profiles(source, target, policy=policy)["outcome"] == "passed"
    changed_rows = deepcopy(rows)
    changed_rows[0]["claim_id"] = "different-key"
    changed_target = [
        _profile_partition(
            changed_rows,
            partition_id="t1",
            side="target",
            identity=_identity("target"),
            policy=policy,
        )
    ]
    changed = reconcile_profiles(source, changed_target, policy=policy)
    assert changed["outcome"] == "incompatible"
    assert "sample_scope_mismatch" in changed["blockers"]


def test_missing_column_and_nonfinite_numeric_are_explicit_blockers(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    receipt = _profile_partition(
        [{"claim_id": "1", "amount": math.inf}],
        partition_id="s",
        side="source",
        identity=_identity("source"),
        policy=policy,
    )
    assert receipt["status"] == "blocked"
    assert receipt["blockers"] == ["missing_column:status", "non_finite_numeric:amount"]


def test_partition_and_result_mutations_fail_replay(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    changed_partition = deepcopy(source[0])
    changed_partition["columns"][0]["ordinary_null_count"] += 1
    with pytest.raises(ValueError, match="mutation"):
        verify_partition(changed_partition, policy=policy)
    result = reconcile_profiles(source, target, policy=policy)
    changed_result = deepcopy(result)
    changed_result["claims"]["parity_passed"] = True
    with pytest.raises(ValueError):
        verify_result(
            changed_result,
            source_partitions=source,
            target_partitions=target,
            policy=policy,
        )
    internally_inconsistent = deepcopy(source[0])
    internally_inconsistent["columns"][0]["non_missing_count"] += 1
    _resign(internally_inconsistent)
    with pytest.raises(ValueError, match="counts do not reconcile"):
        verify_partition(internally_inconsistent, policy=policy)


def test_immutable_publication_retry_and_two_workload_isolation(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    first = reconcile_profiles(source, target, policy=policy)
    output = tmp_path / "evidence"
    first_path = publish_result(
        output,
        first,
        source_partitions=source,
        target_partitions=target,
        policy=policy,
    )
    assert (
        publish_result(
            output, first, source_partitions=source, target_partitions=target, policy=policy
        )
        == first_path
    )
    second_source = [
        _profile_partition(
            _rows(),
            partition_id="s2",
            side="source",
            identity=_identity("source", workload="workload-2"),
            policy=policy,
        )
    ]
    second_target = [
        _profile_partition(
            _rows(),
            partition_id="t2",
            side="target",
            identity=_identity("target", workload="workload-2"),
            policy=policy,
        )
    ]
    second = reconcile_profiles(second_source, second_target, policy=policy)
    second_path = publish_result(
        output,
        second,
        source_partitions=second_source,
        target_partitions=second_target,
        policy=policy,
    )
    assert first_path != second_path
    assert first_path.read_bytes() != second_path.read_bytes()


def test_duplicate_partitions_and_cross_workload_scope_fail_closed(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    with pytest.raises(ValueError, match="unique"):
        reconcile_profiles([source[0], source[0]], target, policy=policy)
    for profile in target:
        profile["identity"]["workload_id"] = "other-workload"
        _resign(profile)
    result = reconcile_profiles(source, target, policy=policy)
    assert result["outcome"] == "incompatible"
    assert "identity_scope_mismatch" in result["blockers"]


def _digest_for_test(payload: dict[str, Any]) -> str:
    value = {
        key: item for key, item in payload.items() if key not in {"content_digest", "signature"}
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _resign(payload: dict[str, Any]) -> None:
    payload["content_digest"] = _digest_for_test(payload)
    signing = {key: item for key, item in payload.items() if key != "signature"}
    payload["signature"] = base64.b64encode(
        (_SOURCE_PRIVATE_KEY if payload["side"] == "source" else _TARGET_PRIVATE_KEY).sign(
            json.dumps(signing, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        )
    ).decode()


def test_policy_mutation_duplicate_json_unknown_fields_and_unsafe_identity(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    mutated = replace(policy, sampling=replace(policy.sampling, fraction="0.5"))
    with pytest.raises(ValueError, match="diverges"):
        _profile_partition(
            [], partition_id="p", side="source", identity=_identity("source"), policy=mutated
        )
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_policy(duplicate)
    unknown = _policy_value()
    unknown["caller_approved"] = True
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(ValueError, match="Additional properties"):
        load_policy(unknown_path)
    unsafe_identity = replace(_identity("source"), workload_id="../escape")
    with pytest.raises(ValueError, match="Unsafe"):
        _profile_partition(
            [], partition_id="p", side="source", identity=unsafe_identity, policy=policy
        )
    secret_identity = replace(_identity("source"), workload_id="secret-canary-value")
    with pytest.raises(ValueError, match="Unsafe"):
        _profile_partition(
            [], partition_id="p", side="source", identity=secret_identity, policy=policy
        )
    unsafe_policy = _policy_value()
    unsafe_policy["columns"][1]["categories"] = ["member@example.com"]
    unsafe_path = tmp_path / "unsafe-policy.json"
    unsafe_path.write_text(json.dumps(unsafe_policy), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsafe"):
        load_policy(unsafe_path)


def test_undeclared_raw_categories_are_counted_without_persisting_values(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    canary = "member@example.com"
    receipt = _profile_partition(
        [{"claim_id": "1", "amount": "1", "status": canary}],
        partition_id="p",
        side="source",
        identity=_identity("source"),
        policy=policy,
    )
    assert canary not in json.dumps(receipt)
    status = next(item for item in receipt["columns"] if item["name"] == "status")
    assert status["other_count"] == 1


def test_protected_sampling_key_is_rejected_before_hashing(tmp_path: Path) -> None:
    policy = _policy(tmp_path, method="deterministic_hash", fraction="0.5")
    with pytest.raises(ValueError, match="protected data"):
        _profile_partition(
            [{"claim_id": "member@example.com", "amount": "1", "status": "paid"}],
            partition_id="p",
            side="source",
            identity=_identity("source"),
            policy=policy,
        )


def test_replay_rejects_protected_data_and_coherent_rehash(tmp_path: Path) -> None:
    policy, source, _ = _profiles(tmp_path)
    protected = deepcopy(source[0])
    protected["identity"]["provider_id"] = "secret-canary-value"
    protected["content_digest"] = _digest_for_test(protected)
    with pytest.raises(ValueError, match="protected data"):
        verify_partition(protected, policy=policy)

    coherently_rehashed = deepcopy(source[0])
    coherently_rehashed["columns"][0]["sum"] = "999"
    coherently_rehashed["content_digest"] = _digest_for_test(coherently_rehashed)
    with pytest.raises(ValueError, match="signature"):
        verify_partition(coherently_rehashed, policy=policy)


def test_cancellation_before_publication_writes_no_state(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    result = reconcile_profiles(source, target, policy=policy)
    output = tmp_path / "cancelled-evidence"
    calls = iter((False, True))
    with pytest.raises(InterruptedError, match="immutable write"):
        publish_result(
            output,
            result,
            source_partitions=source,
            target_partitions=target,
            policy=policy,
            cancelled=lambda: next(calls),
        )
    assert not output.exists()


def test_caller_cannot_upgrade_synthetic_receipts_to_runtime_claims(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    result = reconcile_profiles(source, target, policy=policy)
    assert result["outcome"] == "passed"
    assert result["evidence_class"] == "synthetic_contract"
    assert result["claims"]["executed"] is False
    assert result["claims"]["validated"] is False
    assert result["claims"]["parity_passed"] is False

    forged = deepcopy(result)
    forged["claims"]["executed"] = True
    forged["content_digest"] = _digest_for_test(forged)
    with pytest.raises(ValueError, match="schema validation"):
        verify_result(
            forged,
            source_partitions=source,
            target_partitions=target,
            policy=policy,
        )


def test_authority_domains_are_side_bound_and_cross_side_signing_fails(tmp_path: Path) -> None:
    shared_authority = _policy_value()
    shared_authority["receipt_authorities"][1]["authority_id"] = "fixture-source-authority"
    path = tmp_path / "shared-authority.json"
    path.write_text(json.dumps(shared_authority), encoding="utf-8")
    with pytest.raises(ValueError, match="authority domains must be distinct"):
        load_policy(path)

    shared_material = _policy_value()
    shared_material["receipt_authorities"][1]["public_key"] = _SOURCE_PUBLIC_KEY
    path = tmp_path / "shared-material.json"
    path.write_text(json.dumps(shared_material), encoding="utf-8")
    with pytest.raises(ValueError, match="key material must be distinct"):
        load_policy(path)

    policy = _policy(tmp_path)
    with pytest.raises(ValueError, match="signature is invalid"):
        profile_partition(
            _rows(),
            partition_id="source-cross-signed",
            side="source",
            identity=_identity("source"),
            policy=policy,
            authority_id="fixture-source-authority",
            key_id="fixture-source-key",
            evidence_class="synthetic_contract",
            signer=_TARGET_PRIVATE_KEY.sign,
        )


def test_sampling_keys_use_closed_types_and_reject_encoded_protected_data(tmp_path: Path) -> None:
    policy = _policy(tmp_path, method="deterministic_hash", fraction="1")

    class CallerObject:
        def __str__(self) -> str:
            return "apparently-safe"

    for unsafe in (CallerObject(), 1.5, "c2VjcmV0LWNhbmFyeS12YWx1ZQ=="):
        with pytest.raises(ValueError, match="unsupported type|protected data"):
            _profile_partition(
                [{"claim_id": unsafe, "amount": "1", "status": "paid"}],
                partition_id="unsafe-key",
                side="source",
                identity=_identity("source"),
                policy=policy,
            )

    integer = _profile_partition(
        [{"claim_id": 1, "amount": "1", "status": "paid"}],
        partition_id="integer-key",
        side="source",
        identity=_identity("source"),
        policy=policy,
    )
    string = _profile_partition(
        [{"claim_id": "1", "amount": "1", "status": "paid"}],
        partition_id="string-key",
        side="source",
        identity=_identity("source"),
        policy=policy,
    )
    assert integer["sample_key_sum"] != string["sample_key_sum"]


@pytest.mark.parametrize(
    ("field", "limit"),
    (("columns", 128), ("numeric_bins", 256), ("categories", 512), ("key_columns", 16)),
)
def test_policy_cardinality_caps_accept_boundary_and_reject_overflow(
    tmp_path: Path, field: str, limit: int
) -> None:
    def value(count: int) -> dict[str, Any]:
        payload = _policy_value(method="deterministic_hash", fraction="1")
        if field == "columns":
            payload["columns"] = [
                {
                    "name": f"c{index}",
                    "kind": "categorical",
                    "numeric_bins": [],
                    "categories": ["x"],
                    "absolute_tolerance": "0",
                    "relative_tolerance": "0",
                }
                for index in range(count)
            ]
        elif field == "numeric_bins":
            payload["columns"][0][field] = [str(index) for index in range(count)]
        elif field == "categories":
            payload["columns"][1][field] = [f"v{index}" for index in range(count)]
        else:
            payload["sampling"][field] = [f"k{index}" for index in range(count)]
        return payload

    boundary = tmp_path / f"{field}-boundary.json"
    boundary.write_text(json.dumps(value(limit)), encoding="utf-8")
    load_policy(boundary)
    overflow = tmp_path / f"{field}-overflow.json"
    overflow.write_text(json.dumps(value(limit + 1)), encoding="utf-8")
    with pytest.raises(ValueError, match="schema validation|governed bound"):
        load_policy(overflow)


def test_partition_check_digest_and_evidence_caps_are_exact(tmp_path: Path) -> None:
    policy, source, target = _profiles(tmp_path)
    result = reconcile_profiles(source, target, policy=policy)

    original_partition_cap = dp04._MAX_PARTITIONS_PER_SIDE
    dp04._MAX_PARTITIONS_PER_SIDE = 2
    try:
        dp04._merge(source, policy)
        with pytest.raises(ValueError, match="partition count"):
            dp04._merge([*source, source[0]], policy)
    finally:
        dp04._MAX_PARTITIONS_PER_SIDE = original_partition_cap

    schema_candidate = deepcopy(result)
    schema_candidate["source_profile"]["partition_count"] = 4096
    schema_candidate["source_profile"]["partition_digests"] = ["a" * 64] * 4096
    schema_candidate["checks"] = [result["checks"][0]] * 1282
    dp04._validate("dp04-result.schema.json", schema_candidate)
    schema_candidate["source_profile"]["partition_count"] = 4097
    schema_candidate["source_profile"]["partition_digests"].append("a" * 64)
    with pytest.raises(ValueError, match="schema validation"):
        dp04._validate("dp04-result.schema.json", schema_candidate)
    schema_candidate = deepcopy(result)
    schema_candidate["checks"] = [result["checks"][0]] * 1283
    with pytest.raises(ValueError, match="schema validation"):
        dp04._validate("dp04-result.schema.json", schema_candidate)

    name = "dp04-result.schema.json"
    original_byte_cap = dp04._EVIDENCE_LIMITS[name]
    exact_size = len(dp04._canonical_bytes(result))
    try:
        dp04._EVIDENCE_LIMITS[name] = exact_size
        verify_result(result, source_partitions=source, target_partitions=target, policy=policy)
        dp04._EVIDENCE_LIMITS[name] = exact_size - 1
        with pytest.raises(ValueError, match="byte bound"):
            verify_result(result, source_partitions=source, target_partitions=target, policy=policy)
    finally:
        dp04._EVIDENCE_LIMITS[name] = original_byte_cap


def test_schema_files_are_packaged_byte_identically() -> None:
    from importlib.resources import files

    for name in (
        "dp04-policy.schema.json",
        "dp04-partition-profile.schema.json",
        "dp04-result.schema.json",
    ):
        assert (
            Path("schemas", name).read_bytes() == files("smf.schemas").joinpath(name).read_bytes()
        )
