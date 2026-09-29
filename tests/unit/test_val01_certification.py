from __future__ import annotations

import base64
import hashlib
import importlib
import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import smf.validation.val01 as val01
from smf.immutable_files import publish_json
from smf.upstream.crypto import sign_payload
from smf.validation.val01 import (
    ColumnPolicy,
    CurrentEvidence,
    DBX04CurrentEvidence,
    DP02CurrentEvidence,
    DP03CurrentEvidence,
    DP04CurrentEvidence,
    DP05CurrentEvidence,
    EvidenceBinding,
    RuntimeManifest,
    RuntimeTrustPolicy,
    SchemaCurrentEvidence,
    SnapshotBinding,
    SparkDataComPyComparator,
    SyntheticComparator,
    ValidationPolicy,
    ValidationRequest,
    evaluate_val01,
    hmac_mismatch_key,
    hmac_mismatch_value,
    publish_val01_result,
    verify_val01_result,
)

_REAL_PREREQUISITE_VERIFIER = val01._verify_current_prerequisite


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _key(tmp_path: Path) -> tuple[Path, str]:
    private = Ed25519PrivateKey.generate()
    path = tmp_path / "runtime.pem"
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
    ).decode()
    return path, public


def _policy(**overrides: Any) -> ValidationPolicy:
    values: dict[str, Any] = {
        "policy_id": "full-row-policy",
        "policy_version": "1.0.0",
        "key_columns": ("record_id",),
        "columns": (
            ColumnPolicy("amount", "decimal", absolute_tolerance="0.01"),
            ColumnPolicy("service_date", "date", timezone="UTC", yearcutoff=1920),
            ColumnPolicy("status", "string", string_policy="trim"),
        ),
        "maximum_mismatch_references": 10,
    }
    values.update(overrides)
    return ValidationPolicy(**values)


def _runtime(public: str, *, qualified: bool = False) -> RuntimeManifest:
    records = tuple(
        (name, "1.0.0", "sha256:" + f"{index + 1:x}" * 64)
        for index, name in enumerate(
            (
                "pyspark",
                "py4j",
                "datacompy",
                "numpy",
                "pandas",
                "pyarrow",
                "grpcio",
                "grpcio-status",
                "googleapis-common-protos",
            )
        )
    )
    return RuntimeManifest(
        manifest_id="val01-runtime",
        manifest_version="1.0.0",
        provider_id="spark-datacompy",
        provider_version="1.0.0",
        spark_version="3.5.8",
        datacompy_version="1.0.4",
        evidence_class="qualified_runtime" if qualified else "synthetic_contract",
        qualified=qualified,
        authority_id="validation-runtime",
        authority_digest="sha256:" + "a" * 64,
        verification_key_id="validation-key",
        verification_key=public,
        mismatch_hmac_key=b"val01-mismatch-hmac-key-material-0001",
        python_version="3.11.15" if qualified else "",
        platform_id="test-platform" if qualified else "",
        distribution_records=records if qualified else (),
    )


def _trust(runtime: RuntimeManifest) -> RuntimeTrustPolicy:
    return RuntimeTrustPolicy(
        "runtime-trust",
        "1.0.0",
        (runtime.digest,),
        (
            (
                runtime.authority_id,
                runtime.authority_digest,
                runtime.verification_key_id,
                runtime.verification_key,
            ),
        ),
    )


def _evidence(root: Path, *, blocked_kind: str | None = None) -> tuple[EvidenceBinding, ...]:
    bindings = []
    for index, kind in enumerate(val01._KINDS):
        payload = {
            "result_id": "sha256:" + f"{index + 1:x}" * 64,
            "content_digest": "sha256:" + f"{index + 7:x}" * 64,
            "status": "blocked" if kind == blocked_kind else "passed",
            "claims": {"blocked": kind == blocked_kind},
            "client_id": "synthetic-client",
            "workload_id": "workload-1",
            "run_id": "run-1",
            "evaluated_at": "2026-09-22T12:00:00Z",
            "source_snapshot_digest": "sha256:" + "1" * 64,
            "target_snapshot_digest": "sha256:" + "2" * 64,
        }
        relative = Path("prerequisites") / f"{kind.lower()}.json"
        publish_json(root / relative, payload, "test prerequisite", root=root)
        raw = (root / relative).read_bytes()
        bindings.append(
            EvidenceBinding(
                kind,
                relative.as_posix(),
                str(payload["result_id"]),
                str(payload["content_digest"]),
                "sha256:" + hashlib.sha256(raw).hexdigest(),
            )
        )
    return tuple(bindings)


def _request(
    root: Path, policy: ValidationPolicy, runtime: RuntimeManifest, trust: RuntimeTrustPolicy
) -> ValidationRequest:
    return ValidationRequest(
        client_id="synthetic-client",
        workload_id="workload-1",
        run_id="run-1",
        attempt_id="attempt-1",
        evaluated_at="2026-09-22T12:00:00Z",
        source=SnapshotBinding("source-data", "source-snapshot", "sha256:" + "1" * 64),
        target=SnapshotBinding("target-data", "target-snapshot", "sha256:" + "2" * 64),
        prerequisites=_evidence(root),
        policy_digest=_digest(policy.to_dict()),
        trust_policy_digest=trust.digest,
        runtime_manifest_digest=runtime.digest,
    )


def _current(request: ValidationRequest) -> CurrentEvidence:
    by_kind = {binding.kind: binding for binding in request.prerequisites}
    return CurrentEvidence(
        SchemaCurrentEvidence(by_kind["SCHEMA-INT-01"], None, None),  # type: ignore[arg-type]
        DP02CurrentEvidence(by_kind["DP-02"], None, Path("."), Path("."), None, None),  # type: ignore[arg-type]
        DP03CurrentEvidence(by_kind["DP-03"], None),  # type: ignore[arg-type]
        DP04CurrentEvidence(by_kind["DP-04"], (), (), None),  # type: ignore[arg-type]
        DP05CurrentEvidence(by_kind["DP-05"], None),  # type: ignore[arg-type]
        DBX04CurrentEvidence(by_kind["DBX-04"], None, None, None),  # type: ignore[arg-type]
    )


@pytest.fixture(autouse=True)
def _composition_prerequisite_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Composition tests isolate VAL-01; exact verifier wiring has dedicated tests."""

    monkeypatch.setattr(val01, "_verify_current_prerequisite", lambda *args: None)


def _receipt_factory(key_path: Path, *, changed: dict[str, Any] | None = None) -> Any:
    def factory(
        request: ValidationRequest, policy: ValidationPolicy, runtime: RuntimeManifest
    ) -> dict[str, Any]:
        receipt: dict[str, Any] = {
            "schema_version": "1.0",
            "request_digest": _digest(request.to_dict()),
            "policy_digest": _digest(policy.to_dict()),
            "runtime_manifest_digest": runtime.digest,
            "provider_id": runtime.provider_id,
            "provider_version": runtime.provider_version,
            "authority_id": runtime.authority_id,
            "authority_digest": runtime.authority_digest,
            "state": "observed",
            "reason": "observed",
            "source_count": 2,
            "target_count": 2,
            "matched_count": 2,
            "source_only_count": 0,
            "target_only_count": 0,
            "cell_mismatch_count": 0,
            "duplicate_key_count": 0,
            "null_key_count": 0,
            "primary_match": True,
            "datacompy_match": True,
            "mismatch_references": [],
            "proof": None,
        }
        receipt.update(changed or {})
        sign_payload(receipt, private_key_path=key_path, key_id=runtime.verification_key_id)
        return receipt

    return factory


def test_synthetic_composition_pass_is_non_authorizing(tmp_path: Path) -> None:
    key, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    result = evaluate_val01(
        tmp_path,
        request,
        policy,
        trust,
        runtime,
        SyntheticComparator(_receipt_factory(key)),
        _current(request),
    )
    assert result["status"] == "blocked"
    assert result["blockers"] == [
        "runtime_authority_unavailable",
        "snapshot_authority_unavailable",
    ]
    assert result["receipt"]["primary_match"] is True
    assert not any(result["claims"].values())


def test_runtime_unavailable_blocks_without_pandas_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    result = evaluate_val01(tmp_path, request, policy, trust, runtime, None, _current(request))
    assert result["status"] == "blocked"
    assert result["blockers"] == ["comparator_runtime_unavailable"]
    assert result["receipt"]["proof"] is None
    val01._verify_receipt(
        result["receipt"], _digest(request.to_dict()), _digest(policy.to_dict()), runtime
    )
    malformed_receipt = json.loads(json.dumps(result["receipt"]))
    malformed_receipt["reason"] = "provider_failure"
    with pytest.raises(ValueError, match="unsigned comparator receipt"):
        val01._verify_receipt(
            malformed_receipt, _digest(request.to_dict()), _digest(policy.to_dict()), runtime
        )
    real_import = importlib.import_module

    def unavailable(name: str) -> Any:
        if name == "pyspark":
            raise ModuleNotFoundError("deterministic test runtime absence")
        return real_import(name)

    monkeypatch.setattr(importlib, "import_module", unavailable)
    assert SparkDataComPyComparator.runtime_available(runtime) is False
    forged = json.loads(json.dumps(result))
    forged["status"] = "passed"
    forged["blockers"] = []
    projection = dict(forged)
    projection.pop("result_id")
    projection.pop("content_digest")
    forged["result_id"] = _digest(projection)
    content = dict(forged)
    content.pop("content_digest")
    forged["content_digest"] = _digest(content)
    with pytest.raises(ValueError, match="unsigned runtime blocker"):
        verify_val01_result(
            tmp_path,
            forged,
            policy=policy,
            trust_policy=trust,
            runtime=runtime,
            current_evidence=_current(request),
        )


def test_mismatch_and_independent_disagreement_fail(tmp_path: Path) -> None:
    key, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    mismatch = evaluate_val01(
        tmp_path,
        request,
        policy,
        trust,
        runtime,
        SyntheticComparator(
            _receipt_factory(
                key,
                changed={
                    "cell_mismatch_count": 1,
                    "primary_match": False,
                    "datacompy_match": False,
                },
            )
        ),
        _current(request),
    )
    assert mismatch["status"] == "failed"
    disagreement = evaluate_val01(
        tmp_path,
        request,
        policy,
        trust,
        runtime,
        SyntheticComparator(_receipt_factory(key, changed={"datacompy_match": False})),
        _current(request),
    )
    assert disagreement["status"] == "failed"
    assert "independent_comparator_disagreement" in disagreement["blockers"]


def test_coherent_receipt_and_result_mutation_rejected(tmp_path: Path) -> None:
    key, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    result = evaluate_val01(
        tmp_path,
        request,
        policy,
        trust,
        runtime,
        SyntheticComparator(_receipt_factory(key)),
        _current(request),
    )
    forged = json.loads(json.dumps(result))
    forged["receipt"]["cell_mismatch_count"] = 1
    projection = dict(forged)
    projection.pop("result_id")
    projection.pop("content_digest")
    forged["result_id"] = _digest(projection)
    content = dict(forged)
    content.pop("content_digest")
    forged["content_digest"] = _digest(content)
    with pytest.raises(ValueError, match="signature"):
        verify_val01_result(
            tmp_path,
            forged,
            policy=policy,
            trust_policy=trust,
            runtime=runtime,
            current_evidence=_current(request),
        )


def test_prerequisite_drift_and_nonqualifying_status_fail(tmp_path: Path) -> None:
    _, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    path = tmp_path / request.prerequisites[0].relative_path
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bytes differ"):
        evaluate_val01(tmp_path, request, policy, trust, runtime, None, _current(request))

    other = tmp_path / "blocked"
    other.mkdir()
    blocked_request = replace(
        request,
        prerequisites=_evidence(other, blocked_kind="DP-03"),
    )
    with pytest.raises(ValueError, match="non-qualifying"):
        evaluate_val01(
            other,
            blocked_request,
            policy,
            trust,
            runtime,
            None,
            _current(blocked_request),
        )


def test_runtime_trust_is_independent_and_exact(tmp_path: Path) -> None:
    key, public = _key(tmp_path)
    policy = _policy()
    runtime = _runtime(public, qualified=True)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    with pytest.raises(ValueError, match="RECORD closure is incomplete"):
        replace(runtime, distribution_records=runtime.distribution_records[:-1]).public_payload()
    untrusted = replace(runtime, provider_version="1.0.1")
    with pytest.raises(ValueError, match="independently allowlisted"):
        evaluate_val01(
            tmp_path,
            replace(request, runtime_manifest_digest=untrusted.digest),
            policy,
            trust,
            untrusted,
            None,
            _current(request),
        )
    with pytest.raises(TypeError, match="built-in Spark"):
        evaluate_val01(
            tmp_path,
            request,
            policy,
            trust,
            runtime,
            SyntheticComparator(_receipt_factory(key)),
            _current(request),
        )


def test_policy_is_explicit_and_default_deny() -> None:
    with pytest.raises(ValueError, match="YEARCUTOFF"):
        ColumnPolicy("event_date", "date").to_dict()
    with pytest.raises(ValueError, match="tie-break"):
        _policy(duplicate_policy="deterministic_tiebreak").to_dict()
    with pytest.raises(ValueError, match="cannot carry tie-break"):
        _policy(tie_break_columns=("status",)).to_dict()
    with pytest.raises(ValueError, match="order columns"):
        _policy(order_policy="ordered").to_dict()
    with pytest.raises(ValueError, match="non-negative"):
        ColumnPolicy("amount", "decimal", absolute_tolerance="-1").to_dict()
    with pytest.raises(ValueError, match="must not exceed one"):
        ColumnPolicy("amount", "decimal", relative_tolerance="1.0001").to_dict()
    with pytest.raises(ValueError, match="formula is unsupported"):
        ColumnPolicy(
            "amount",
            "decimal",
            relative_denominator="source_absolute",  # type: ignore[arg-type]
        ).to_dict()


def test_governed_spark_type_families_are_closed() -> None:
    assert val01._spark_type_matches("integer", "bigint")
    assert val01._spark_type_matches("decimal", "decimal(38,18)")
    assert val01._spark_type_matches("float", "double")
    assert val01._spark_type_matches("timestamp", "timestamp_ntz")
    assert not val01._spark_type_matches("integer", "double")
    assert not val01._spark_type_matches("string", "varchar(64)")
    assert not val01._spark_type_matches("unsupported", "string")
    assert val01._coercion_pair_allowed("float", "string", "double", "source_to_target")
    assert val01._coercion_pair_allowed("integer", "bigint", "double", "target_to_source")
    assert not val01._coercion_pair_allowed("float", "boolean", "double", "source_to_target")
    assert not val01._coercion_pair_allowed("string", "bigint", "string", "source_to_target")
    assert val01._datacompy_float_tolerance(Decimal("0")) == 0.0
    assert 0.01 < val01._datacompy_float_tolerance(Decimal("0.01")) < 0.010000000001


def test_policy_count_disposition_allows_only_governed_alignment() -> None:
    counts = {
        "source_only_count": 0,
        "target_only_count": 0,
        "cell_mismatch_count": 0,
        "duplicate_key_count": 1,
        "null_key_count": 1,
    }
    assert not val01._counts_match_policy(counts, _policy())
    aligned = _policy(
        duplicate_policy="deterministic_tiebreak",
        tie_break_columns=("status",),
        null_key_policy="match",
    )
    assert val01._counts_match_policy(counts, aligned)
    counts["cell_mismatch_count"] = 1
    assert not val01._counts_match_policy(counts, aligned)


def test_protected_identity_and_hmac_numeric_key() -> None:
    with pytest.raises(ValueError, match="Unsafe VAL-01"):
        SnapshotBinding("123-45-6789", "snapshot", "sha256:" + "1" * 64).to_dict()
    key = b"val01-mismatch-hmac-key-material-0001"
    token = hmac_mismatch_key((123456789,), key)
    assert token.startswith("hmac-sha256:")
    assert "123456789" not in token
    value_token = hmac_mismatch_value("source", "amount", "canary-secret", key)
    rotated = hmac_mismatch_value("source", "amount", "canary-secret", key + b"-rotation")
    assert "canary-secret" not in value_token
    assert value_token != rotated
    assert hmac_mismatch_value("source", "amount", float("nan"), key).startswith("hmac-sha256:")
    assert hmac_mismatch_value("target", "amount", float("inf"), key).startswith("hmac-sha256:")
    with pytest.raises(ValueError, match="unsupported"):
        hmac_mismatch_key((object(),), key)


def test_cancel_retry_and_workload_isolation(tmp_path: Path) -> None:
    key, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    trust = _trust(runtime)
    request = _request(tmp_path, policy, runtime, trust)
    comparator = SyntheticComparator(_receipt_factory(key))
    with pytest.raises(RuntimeError, match="cancelled"):
        publish_val01_result(
            tmp_path,
            request,
            policy,
            trust,
            runtime,
            comparator,
            _current(request),
            cancelled=lambda: True,
        )
    assert not (tmp_path / "runs").exists()
    first = publish_val01_result(
        tmp_path, request, policy, trust, runtime, comparator, _current(request)
    )
    assert (
        publish_val01_result(
            tmp_path, request, policy, trust, runtime, comparator, _current(request)
        )
        == first
    )
    other_root = tmp_path / "other-evidence"
    other_root.mkdir()
    other_request = replace(
        request,
        workload_id="workload-2",
        prerequisites=_evidence(other_root),
    )
    for binding in other_request.prerequisites:
        path = other_root / binding.relative_path
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["workload_id"] = "workload-2"
        path.unlink()
        publish_json(path, payload, "test prerequisite", root=other_root)
    other_request = replace(
        other_request,
        prerequisites=tuple(
            replace(
                binding,
                artifact_digest="sha256:"
                + hashlib.sha256((other_root / binding.relative_path).read_bytes()).hexdigest(),
            )
            for binding in other_request.prerequisites
        ),
    )
    second = publish_val01_result(
        other_root,
        other_request,
        policy,
        trust,
        runtime,
        comparator,
        _current(other_request),
    )
    assert first != second
    assert first.read_bytes() != second.read_bytes()


def test_static_distributed_boundary_and_schema_mirrors() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "src/smf/validation/val01.py").read_text(encoding="utf-8")
    assert "toPandas" not in source
    assert ".collect(" not in source
    assert "PandasCompare" not in source
    assert 'join(right, condition, "full_outer")' in source
    assert ".toLocalIterator()" in source
    assert "SparkSQLCompare" in source
    for name in ("val01-comparator-receipt.schema.json", "val01-result.schema.json"):
        assert (root / "schemas" / name).read_bytes() == (
            root / "src/smf/schemas" / name
        ).read_bytes()


def test_typed_current_evidence_dispatch_cannot_use_generic_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, public = _key(tmp_path)
    policy, runtime = _policy(), _runtime(public)
    request = _request(tmp_path, policy, runtime, _trust(runtime))
    current = _current(request)
    called: list[str] = []
    monkeypatch.setattr(val01, "verify_schema_integration", lambda *a, **k: called.append("schema"))
    monkeypatch.setattr(val01, "verify_current_dp02_result", lambda *a, **k: called.append("dp02"))
    monkeypatch.setattr(val01, "verify_dp03_result", lambda *a, **k: called.append("dp03"))
    monkeypatch.setattr(val01, "verify_dp04_result", lambda *a, **k: called.append("dp04"))
    monkeypatch.setattr(val01, "verify_dp05_result", lambda *a, **k: called.append("dp05"))
    monkeypatch.setattr(val01, "verify_runtime_evidence", lambda *a, **k: called.append("dbx04"))
    for binding in request.prerequisites:
        _REAL_PREREQUISITE_VERIFIER(
            tmp_path,
            binding.kind,
            tmp_path / binding.relative_path,
            {},
            current,
        )
    assert called == ["schema", "dp02", "dp03", "dp04", "dp05", "dbx04"]
