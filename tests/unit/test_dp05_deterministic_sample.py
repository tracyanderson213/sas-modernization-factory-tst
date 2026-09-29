from __future__ import annotations

import base64
import json
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import smf.validation.dp05 as dp05
from smf.validation.dp05 import (
    DP05Request,
    DP05TrustPolicy,
    SampleDatasetBinding,
    SamplePolicy,
    StableSampleAdapter,
    compare_deterministic_samples,
    publish_dp05_result,
    verify_dp05_result,
    verify_sample_observation,
)

_KEY_ROOT = Path(tempfile.mkdtemp(prefix="smf-dp05-tests-"))


def _make_key(name: str) -> tuple[Path, str]:
    key = Ed25519PrivateKey.generate()
    path = _KEY_ROOT / f"{name}.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")
    return path, public


_SOURCE_KEY, _SOURCE_PUBLIC = _make_key("source")
_TARGET_KEY, _TARGET_PUBLIC = _make_key("target")
_TRUST = DP05TrustPolicy(
    "dp05-trust",
    "1.0.0",
    (("source-key", _SOURCE_PUBLIC), ("target-key", _TARGET_PUBLIC)),
    ("source-key",),
    ("target-key",),
    (("source-authority", "sha256:" + "4" * 64),),
    (("target-authority", "sha256:" + "5" * 64),),
    b"dp05-protected-value-key-00000001",
)


def _binding(name: str, *, scope: str = "shared") -> SampleDatasetBinding:
    return SampleDatasetBinding(
        name,
        f"{name}-snapshot",
        "sha256:" + ("1" if name == "source" else "2") * 64,
        scope,
        "sha256:" + "3" * 64,
    )


def _policy(**overrides: Any) -> SamplePolicy:
    values: dict[str, Any] = {
        "policy_id": "sample-policy",
        "policy_version": "1.0.0",
        "key_columns": ("record_id",),
        "compare_columns": ("amount", "status"),
        "sample_size": 3,
        "seed": "competition-seed",
        "duplicate_policy": "reject",
    }
    values.update(overrides)
    return SamplePolicy(**values)


def _request(**overrides: Any) -> DP05Request:
    values: dict[str, Any] = {
        "client_id": "synthetic-client",
        "workload_id": "workload-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "evaluated_at": "2026-09-22T12:00:00Z",
        "source": _binding("source"),
        "target": _binding("target"),
        "trust_policy_digest": _TRUST.digest,
    }
    values.update(overrides)
    return DP05Request(**values)


def _rows() -> list[dict[str, object]]:
    return [
        {"record_id": "a", "amount": 10, "status": "ok"},
        {"record_id": "b", "amount": 20, "status": "ok"},
        {"record_id": "c", "amount": 30, "status": "ok"},
        {"record_id": "d", "amount": 40, "status": "ok"},
        {"record_id": "e", "amount": 50, "status": "ok"},
    ]


def _ordered(
    rows: Iterable[Mapping[str, object]], policy: SamplePolicy
) -> list[Mapping[str, object]]:
    return sorted(
        rows, key=lambda row: dp05._key_and_row(row, policy, _TRUST.protected_value_key)[:2]
    )


def _adapter(
    rows: Iterable[Mapping[str, object]], policy: SamplePolicy, side: str = "source"
) -> StableSampleAdapter:
    ordered = _ordered(rows, policy)
    return _signed_adapter(lambda: iter(ordered), side)


def _signed_adapter(factory: Any, side: str) -> StableSampleAdapter:
    source = side == "source"
    return StableSampleAdapter(
        factory,
        _SOURCE_KEY if source else _TARGET_KEY,
        "source-key" if source else "target-key",
        "source-authority" if source else "target-authority",
        "sha256:" + ("4" if source else "5") * 64,
    )


def _compare(
    source: list[dict[str, object]],
    target: list[dict[str, object]],
    *,
    policy: SamplePolicy | None = None,
    request: DP05Request | None = None,
) -> dict[str, Any]:
    selected = policy or _policy()
    return compare_deterministic_samples(
        request or _request(),
        selected,
        source_adapter=_adapter(source, selected, "source"),
        target_adapter=_adapter(target, selected, "target"),
        trust_policy=_TRUST,
    )


def test_stable_selection_is_reproducible_bounded_and_sample_only() -> None:
    policy = _policy(sample_size=2)
    first = _compare(_rows(), _rows(), policy=policy)
    second = _compare(list(reversed(_rows())), list(reversed(_rows())), policy=policy)

    assert first == second
    assert first["status"] == "passed"
    assert first["assurance_scope"] == "sample_only"
    assert first["coverage"] == {
        "source_population_count": 5,
        "target_population_count": 5,
        "source_selected_count": 2,
        "target_selected_count": 2,
        "aligned_count": 2,
        "unmatched_count": 0,
        "cell_mismatch_count": 0,
    }
    assert first["claims"]["sample_only_assurance"] is True
    assert first["claims"]["full_dataset_parity_passed"] is False
    assert first["claims"]["cell_parity_passed"] is False
    assert first["claims"]["data_parity_passed"] is False
    assert first["policy"]["seed"] == "competition-seed"
    assert first["policy"]["selection_algorithm"] == "sha256-key-ordinal-v1"


def test_mutated_sampled_cell_and_unmatched_key_fail_explicitly() -> None:
    source = _rows()[:3]
    target = [dict(row) for row in source]
    target[1]["amount"] = 21
    mutated = _compare(source, target)
    assert mutated["status"] == "failed"
    assert mutated["failures"] == ["sampled_cell_mismatch"]
    assert mutated["coverage"]["cell_mismatch_count"] == 1

    unmatched_target = [dict(row) for row in source]
    unmatched_target[2]["record_id"] = "different"
    unmatched = _compare(source, unmatched_target)
    assert unmatched["status"] == "failed"
    assert "unmatched_sample_rows" in unmatched["failures"]
    assert unmatched["coverage"]["unmatched_count"] == 2


def test_duplicate_policy_rejects_or_stably_aligns() -> None:
    duplicate = [
        {"record_id": "a", "amount": 10, "status": "one"},
        {"record_id": "a", "amount": 11, "status": "two"},
    ]
    rejected = _compare(duplicate, duplicate)
    assert rejected["status"] == "failed"
    assert rejected["failures"] == ["source_duplicate_keys", "target_duplicate_keys"]

    stable = _compare(
        duplicate, list(reversed(duplicate)), policy=_policy(duplicate_policy="stable_ordinal")
    )
    assert stable["status"] == "passed"
    assert stable["source_observation"]["duplicate_key_count"] == 1
    assert sorted(row["duplicate_ordinal"] for row in stable["source_observation"]["rows"]) == [
        0,
        1,
    ]

    bounded = _compare(
        duplicate,
        duplicate,
        policy=_policy(duplicate_policy="stable_ordinal", maximum_duplicate_rows_per_key=1),
    )
    assert bounded["status"] == "failed"
    assert bounded["source_observation"]["reason"] == "duplicate_limit_exceeded"


def test_noncanonical_stream_is_explicit_biased_selection_failure() -> None:
    policy = _policy()
    ordered = _ordered(_rows()[:3], policy)
    biased = _signed_adapter(lambda: iter(reversed(ordered)), "source")
    result = compare_deterministic_samples(
        _request(),
        policy,
        source_adapter=biased,
        target_adapter=_adapter(_rows()[:3], policy, "target"),
        trust_policy=_TRUST,
    )
    assert result["status"] == "failed"
    assert result["failures"] == [
        "population_count_mismatch",
        "source_biased_selection",
        "unmatched_sample_rows",
    ]
    assert result["claims"]["sample_check_passed"] is False


def test_population_difference_fails_even_when_selected_rows_could_match() -> None:
    policy = _policy(sample_size=1)
    result = _compare(
        _rows(), _rows() + [{"record_id": "z", "amount": 99, "status": "ok"}], policy=policy
    )
    assert result["status"] == "failed"
    assert "population_count_mismatch" in result["failures"]


def test_scope_mismatch_blocks_without_invoking_providers() -> None:
    calls = {"source": 0, "target": 0}

    def source() -> Iterable[Mapping[str, object]]:
        calls["source"] += 1
        return iter(_rows())

    def target() -> Iterable[Mapping[str, object]]:
        calls["target"] += 1
        return iter(_rows())

    request = _request(target=_binding("target", scope="different"))
    result = compare_deterministic_samples(
        request,
        _policy(),
        source_adapter=StableSampleAdapter(source),
        target_adapter=StableSampleAdapter(target),
        trust_policy=_TRUST,
    )
    assert result["status"] == "blocked"
    assert result["blockers"] == ["snapshot_scope_mismatch"]
    assert calls == {"source": 0, "target": 0}


def test_provider_failure_and_protected_canary_are_categorical() -> None:
    def failure() -> Iterable[Mapping[str, object]]:
        raise RuntimeError("provider detail secret-canary must not persist")

    result = compare_deterministic_samples(
        _request(),
        _policy(),
        source_adapter=_signed_adapter(failure, "source"),
        target_adapter=_adapter(_rows(), _policy(), "target"),
        trust_policy=_TRUST,
    )
    assert result["status"] == "blocked"
    assert result["blockers"] == ["source_provider_error"]
    assert "secret-canary" not in json.dumps(result)

    canary_rows = [{"record_id": "a", "amount": 1, "status": "password=secret-canary-value"}]
    protected = compare_deterministic_samples(
        _request(),
        _policy(),
        source_adapter=_signed_adapter(lambda: iter(canary_rows), "source"),
        target_adapter=_signed_adapter(lambda: iter(canary_rows), "target"),
        trust_policy=_TRUST,
    )
    assert protected["status"] == "blocked"
    assert "secret-canary-value" not in json.dumps(protected)


def test_observation_and_result_mutation_with_rehash_fail_reconstruction() -> None:
    policy = _policy(sample_size=2)
    result = _compare(_rows(), _rows(), policy=policy)
    forged = json.loads(json.dumps(result))
    forged["source_observation"]["rows"][0]["selection_score"] = "sha256:" + "0" * 64
    observation_projection = dict(forged["source_observation"])
    observation_projection.pop("content_digest")
    forged["source_observation"]["content_digest"] = dp05._digest(observation_projection)
    projection = dict(forged)
    projection.pop("result_id")
    projection.pop("content_digest")
    forged["result_id"] = dp05._digest(projection)
    content = dict(forged)
    content.pop("content_digest")
    forged["content_digest"] = dp05._digest(content)
    with pytest.raises(ValueError, match="biased or mutated"):
        verify_dp05_result(forged, trust_policy=_TRUST)

    request_digest = dp05._digest(_request().to_dict())
    observation = _adapter(_rows(), policy, "source").observe(
        _binding("source"), policy, _TRUST, side="source", request_digest=request_digest
    )
    bad_row = replace(observation.rows[0], selection_score="sha256:" + "f" * 64)
    with pytest.raises(ValueError, match="biased or unordered|biased or mutated"):
        verify_sample_observation(
            replace(observation, rows=(bad_row, *observation.rows[1:])),
            policy,
            _TRUST,
            side="source",
            request_digest=request_digest,
        )

    coherent = json.loads(json.dumps(result))
    for side in ("source_observation", "target_observation"):
        coherent[side]["rows"][0]["cell_digests"]["amount"] = "sha256:" + "9" * 64
        observation_projection = dict(coherent[side])
        observation_projection.pop("content_digest")
        observation_projection.pop("proof")
        observation_projection.pop("execution_id")
        authority_side = "source" if side.startswith("source") else "target"
        coherent[side]["execution_id"] = dp05._digest(
            {
                "observation": observation_projection,
                "request_digest": coherent["request_digest"],
                "policy_digest": coherent["policy_digest"],
                "side": authority_side,
            }
        )
        coherent[side]["content_digest"] = dp05._digest(
            {**observation_projection, "execution_id": coherent[side]["execution_id"]}
        )
    projection = dict(coherent)
    projection.pop("result_id")
    projection.pop("content_digest")
    coherent["result_id"] = dp05._digest(projection)
    content = dict(coherent)
    content.pop("content_digest")
    coherent["content_digest"] = dp05._digest(content)
    with pytest.raises(ValueError, match="signature"):
        verify_dp05_result(coherent, trust_policy=_TRUST)


def test_missing_and_untrusted_runtime_authority_are_explicit_blockers() -> None:
    policy = _policy()
    missing = compare_deterministic_samples(
        _request(),
        policy,
        source_adapter=StableSampleAdapter(lambda: iter(_ordered(_rows(), policy))),
        target_adapter=_adapter(_rows(), policy, "target"),
        trust_policy=_TRUST,
    )
    assert missing["status"] == "blocked"
    assert missing["blockers"] == ["source_authority_missing"]
    assert missing["claims"]["sample_validation_executed"] is False

    untrusted = StableSampleAdapter(
        lambda: iter(_ordered(_rows(), policy)),
        _SOURCE_KEY,
        "source-key",
        "unknown-authority",
        "sha256:" + "4" * 64,
    )
    result = compare_deterministic_samples(
        _request(),
        policy,
        source_adapter=untrusted,
        target_adapter=_adapter(_rows(), policy, "target"),
        trust_policy=_TRUST,
    )
    assert result["status"] == "blocked"
    assert result["blockers"] == ["source_authority_untrusted"]


@pytest.mark.parametrize("member_id", ["ABCD1234", 123456789])
def test_governed_sensitive_member_id_is_hmac_protected_before_hashing(
    member_id: object,
) -> None:
    policy = _policy(
        key_columns=("member_id",),
        compare_columns=("amount",),
        sensitive_columns=("member_id",),
        sample_size=1,
    )
    rows = [{"member_id": member_id, "amount": 1}]
    result = _compare(rows, rows, policy=policy)
    assert result["status"] == "passed"
    assert str(member_id) not in json.dumps(result)
    assert _TRUST.protected_value_key.hex() not in json.dumps(result)

    with pytest.raises(ValueError, match="requires governed classification"):
        _policy(
            key_columns=("member_id",),
            compare_columns=("amount",),
            sample_size=1,
        ).to_dict()


def test_immutable_retry_and_cross_workload_isolation(tmp_path: Path) -> None:
    policy = _policy(sample_size=5)
    request_a = _request(workload_id="workload-a")
    path_a = publish_dp05_result(
        tmp_path,
        request_a,
        policy,
        source_adapter=_adapter(_rows(), policy, "source"),
        target_adapter=_adapter(_rows(), policy, "target"),
        trust_policy=_TRUST,
    )
    assert (
        publish_dp05_result(
            tmp_path,
            request_a,
            policy,
            source_adapter=_adapter(_rows(), policy, "source"),
            target_adapter=_adapter(_rows(), policy, "target"),
            trust_policy=_TRUST,
        )
        == path_a
    )

    request_b = _request(workload_id="workload-b")
    path_b = publish_dp05_result(
        tmp_path,
        request_b,
        policy,
        source_adapter=_adapter(_rows(), policy, "source"),
        target_adapter=_adapter(_rows(), policy, "target"),
        trust_policy=_TRUST,
    )
    assert path_a != path_b
    assert path_a.read_bytes() != path_b.read_bytes()

    changed = [dict(row) for row in _rows()]
    changed[0]["amount"] = 999
    with pytest.raises(FileExistsError, match="different bytes"):
        publish_dp05_result(
            tmp_path,
            request_a,
            policy,
            source_adapter=_adapter(_rows(), policy, "source"),
            target_adapter=_adapter(changed, policy, "target"),
            trust_policy=_TRUST,
        )


def test_empty_inputs_unsafe_policy_and_schema_mirrors_fail_closed() -> None:
    empty = _compare([], [])
    assert empty["status"] == "blocked"
    assert empty["blockers"] == ["source_empty_population", "target_empty_population"]

    with pytest.raises(ValueError, match="Unsafe DP-05"):
        _policy(seed="secret-canary").to_dict()

    with pytest.raises(ValueError, match="Unsafe DP-05 client_id"):
        _request(client_id="123-45-6789").to_dict()
    with pytest.raises(ValueError, match="Unsafe DP-05 dataset_id"):
        replace(_binding("source"), dataset_id="member@example.com").to_dict()

    root = Path(__file__).resolve().parents[2]
    for name in ("dp05-sample-observation.schema.json", "dp05-sample-result.schema.json"):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()
