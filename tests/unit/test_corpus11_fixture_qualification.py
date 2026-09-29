from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.corpus.fixture_qualification import (
    FixturePolicy,
    evaluate_fixture_manifest,
    load_fixture_manifest,
    load_fixture_policy,
    publish_fixture_result,
    verify_fixture_result,
)
from smf.upstream.crypto import sign_payload

SHA = "a" * 64
WHEN = "2026-09-20T12:00:00Z"


def _key(tmp_path: Path, name: str) -> tuple[Path, str]:
    private = Ed25519PrivateKey.generate()
    path = tmp_path / f"{name}.pem"
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


def _write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _contract(tmp_path: Path) -> tuple[Any, dict[str, Any], Path, Path]:
    policy_key, policy_public = _key(tmp_path, "policy")
    manifest_key, manifest_public = _key(tmp_path, "manifest")
    prerequisite_key, prerequisite_public = _key(tmp_path, "prerequisite")
    evaluator_key, evaluator_public = _key(tmp_path, "evaluator")
    policy_value = {
        "schema_version": "1.0",
        "policy_id": "corpus-policy",
        "policy_version": "v1",
        "client_id": "synthetic-client",
        "allowed_purposes": ["reader_evaluation", "regression"],
        "allowed_media_types": ["application/x-sas-data"],
        "allowed_license_ids": ["Apache-2.0"],
        "customer_authorities": [],
        "max_evidence_age_seconds": 3600,
        "verification_keys": {
            "manifest-key": manifest_public,
            "prerequisite-key": prerequisite_public,
            "evaluator-key": evaluator_public,
        },
        "manifest_key_ids": ["manifest-key"],
        "prerequisite_key_ids": ["prerequisite-key"],
        "evaluator_key_ids": ["evaluator-key"],
        "manifest_authorities": ["synthetic-manifest-authority"],
        "prerequisite_authorities": ["synthetic-prerequisite-authority"],
        "evaluator_authorities": ["synthetic-evaluator"],
        "prerequisites": [
            {"prerequisite_id": "UPQ-01", "result_digest": "1" * 64},
            {"prerequisite_id": "LIC-01", "result_digest": "2" * 64},
        ],
        "authority": "synthetic-policy-authority",
    }
    sign_payload(policy_value, private_key_path=policy_key, key_id="policy-key")
    policy_path = tmp_path / "policy.json"
    _write(policy_path, policy_value)
    policy = load_fixture_policy(
        policy_path,
        trusted_policy_keys={"policy-key": policy_public},
        allowed_policy_key_ids={"policy-key"},
        allowed_policy_authorities={"synthetic-policy-authority"},
    )
    root = tmp_path / "fixtures"
    root.mkdir()
    data = b"synthetic sas7bdat contract bytes"
    (root / "sample.sas7bdat").write_bytes(data)
    binding = {
        "client_id": "synthetic-client",
        "workload_id": "workload-1",
        "source_digest": SHA,
        "run_id": "run-1",
        "attempt_id": "attempt-1",
    }
    prerequisites = []
    for prerequisite_id, digest in (("UPQ-01", "1" * 64), ("LIC-01", "2" * 64)):
        receipt = {
            "prerequisite_id": prerequisite_id,
            "status": "complete",
            "result_digest": digest,
            **binding,
            "authority": "synthetic-prerequisite-authority",
        }
        sign_payload(receipt, private_key_path=prerequisite_key, key_id="prerequisite-key")
        prerequisites.append(receipt)
    manifest = {
        "schema_version": "1.0",
        "manifest_id": "manifest-1",
        "manifest_revision": "fixture-contract-r1",
        **binding,
        "collected_at": WHEN,
        "evidence_class": "synthetic_contract",
        "purpose": "reader_evaluation",
        "fixtures": [
            {
                "fixture_id": "licensed-sample",
                "logical_path": "sample.sas7bdat",
                "media_type": "application/x-sas-data",
                "byte_count": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "producer": "synthetic-test",
                "producer_version": "1",
                "sas_artifact": "sas7bdat",
                "sas_version": None,
                "source_revision": "synthetic-fixture-r1",
                "asset_class": "licensed",
                "permitted_purposes": ["reader_evaluation"],
                "redistribution": "license_permitted",
                "license": {
                    "license_id": "Apache-2.0",
                    "evidence_digest": "3" * 64,
                    "status": "verified",
                },
                "provenance_digest": "4" * 64,
                "authority": "synthetic-manifest-authority",
            }
        ],
        "prerequisites": prerequisites,
        "authority": "synthetic-manifest-authority",
    }
    sign_payload(manifest, private_key_path=manifest_key, key_id="manifest-key")
    return policy, manifest, root, evaluator_key


def _evaluate(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], Any, Path]:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    result = evaluate_fixture_manifest(
        manifest,
        policy=policy,
        evaluated_at="2026-09-20T12:30:00Z",
        fixture_root=root,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    return result, manifest, policy, root


def _resign_manifest(manifest: dict[str, Any], tmp_path: Path) -> None:
    manifest.pop("proof", None)
    sign_payload(manifest, private_key_path=tmp_path / "manifest.pem", key_id="manifest-key")


def _resign_prerequisite(receipt: dict[str, Any], tmp_path: Path) -> None:
    receipt.pop("proof", None)
    sign_payload(
        receipt,
        private_key_path=tmp_path / "prerequisite.pem",
        key_id="prerequisite-key",
    )


def test_synthetic_licensed_contract_pass_is_non_authorizing(tmp_path: Path) -> None:
    result, _, _, _ = _evaluate(tmp_path)
    assert result["outcome"] == "qualified_contract"
    assert result["decisions"][0]["asset_class"] == "licensed"
    assert not any(result["claims"].values())


@pytest.mark.parametrize(
    ("asset_class", "redistribution", "expected"),
    [
        ("evaluation_only", "evaluation_only", "qualified_contract"),
        ("customer_controlled", "customer_controlled", "incompatible"),
        ("prohibited", "prohibited", "denied"),
    ],
)
def test_all_asset_classes_are_explicit(
    tmp_path: Path, asset_class: str, redistribution: str, expected: str
) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    manifest["fixtures"][0]["asset_class"] = asset_class
    manifest["fixtures"][0]["redistribution"] = redistribution
    manifest.pop("proof")
    manifest_key = tmp_path / "manifest.pem"
    sign_payload(manifest, private_key_path=manifest_key, key_id="manifest-key")
    result = evaluate_fixture_manifest(
        manifest,
        policy=policy,
        evaluated_at="2026-09-20T12:30:00Z",
        fixture_root=root,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    assert result["outcome"] == expected


def test_missing_bytes_remain_blocked(tmp_path: Path) -> None:
    policy, manifest, _, evaluator_key = _contract(tmp_path)
    result = evaluate_fixture_manifest(
        manifest,
        policy=policy,
        evaluated_at="2026-09-20T12:30:00Z",
        fixture_root=None,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    assert result["outcome"] == "blocked"
    assert result["decisions"][0]["blockers"] == ["fixture_bytes_missing"]


def test_mutated_bytes_fail_closed(tmp_path: Path) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    (root / "sample.sas7bdat").write_bytes(b"changed")
    result = evaluate_fixture_manifest(
        manifest,
        policy=policy,
        evaluated_at="2026-09-20T12:30:00Z",
        fixture_root=root,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    assert result["outcome"] == "incompatible"
    assert "fixture_byte_identity_mismatch" in result["decisions"][0]["blockers"]


def test_manifest_mutation_breaks_signature(tmp_path: Path) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    manifest["purpose"] = "regression"
    with pytest.raises(ValueError, match="signature"):
        evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yaml"
    path.write_text("schema_version: '1.0'\nschema_version: '1.0'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_fixture_manifest(path)


def test_duplicate_json_keys_and_unknown_fields_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_fixture_manifest(duplicate)
    _, manifest, _, _ = _contract(tmp_path)
    manifest["caller_approved"] = True
    unknown = tmp_path / "unknown.json"
    _write(unknown, manifest)
    with pytest.raises(ValueError, match="Additional properties"):
        load_fixture_manifest(unknown)


@pytest.mark.parametrize("field", ["allowed_license_ids", "customer_authorities", "prerequisites"])
def test_admitted_policy_drift_is_rejected(tmp_path: Path, field: str) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    payload = json.loads(policy.canonical_bytes)
    payload[field] = ["untrusted-customer"] if field == "customer_authorities" else []
    object.__setattr__(
        policy,
        "canonical_bytes",
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )
    with pytest.raises(ValueError, match="changed after admission"):
        evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )


def test_policy_signing_domain_cannot_overlap_operational_domains(tmp_path: Path) -> None:
    policy, _, _, _ = _contract(tmp_path)
    payload = json.loads(policy.canonical_bytes)
    policy_key, policy_public = _key(tmp_path, "overlap-policy")
    payload["verification_keys"]["overlap-policy-key"] = policy_public
    payload["manifest_key_ids"].append("overlap-policy-key")
    payload.pop("proof")
    sign_payload(payload, private_key_path=policy_key, key_id="overlap-policy-key")
    path = tmp_path / "overlap-policy.json"
    _write(path, payload)
    with pytest.raises(ValueError, match="independent"):
        load_fixture_policy(
            path,
            trusted_policy_keys={"overlap-policy-key": policy_public},
            allowed_policy_key_ids={"overlap-policy-key"},
            allowed_policy_authorities={"synthetic-policy-authority"},
        )


def test_admitted_policy_trust_root_drift_is_rejected(tmp_path: Path) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    payload = json.loads(policy.canonical_bytes)
    payload["verification_keys"]["manifest-key"] = "changed-trust-root"
    object.__setattr__(
        policy,
        "canonical_bytes",
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    )
    with pytest.raises(ValueError, match="changed after admission"):
        evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )


def test_external_policy_trust_configuration_drift_is_rejected(tmp_path: Path) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    object.__setattr__(policy, "allowed_policy_authorities", ("different-authority",))
    with pytest.raises(ValueError, match="trust roots changed"):
        evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )


@pytest.mark.parametrize("overlap", ["signing_keys", "authorities"])
def test_direct_policy_construction_cannot_bypass_domain_separation(
    tmp_path: Path, overlap: str
) -> None:
    result, manifest, policy, root = _evaluate(tmp_path)
    payload = json.loads(policy.canonical_bytes)
    if overlap == "signing_keys":
        payload["manifest_key_ids"] = list(payload["prerequisite_key_ids"])
    else:
        payload["manifest_authorities"] = list(payload["prerequisite_authorities"])
    payload.pop("proof")
    sign_payload(payload, private_key_path=tmp_path / "policy.pem", key_id="policy-key")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    forged = FixturePolicy(
        canonical_bytes=canonical,
        digest=hashlib.sha256(canonical).hexdigest(),
        trusted_policy_keys=policy.trusted_policy_keys,
        allowed_policy_key_ids=policy.allowed_policy_key_ids,
        allowed_policy_authorities=policy.allowed_policy_authorities,
        trust_digest=policy.trust_digest,
    )
    with pytest.raises(ValueError, match="distinct"):
        evaluate_fixture_manifest(
            manifest,
            policy=forged,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=tmp_path / "evaluator.pem",
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )
    with pytest.raises(ValueError, match="distinct"):
        verify_fixture_result(
            result,
            manifest=manifest,
            policy=forged,
            fixture_root=root,
        )


@pytest.mark.parametrize("alias_kind", ["operational_operational", "policy_operational"])
def test_direct_policy_construction_rejects_public_key_aliases(
    tmp_path: Path, alias_kind: str
) -> None:
    result, manifest, policy, root = _evaluate(tmp_path)
    payload = json.loads(policy.canonical_bytes)
    if alias_kind == "operational_operational":
        payload["verification_keys"]["evaluator-key"] = payload["verification_keys"]["manifest-key"]
    else:
        payload["verification_keys"]["manifest-key"] = dict(policy.trusted_policy_keys)[
            "policy-key"
        ]
    payload.pop("proof")
    sign_payload(payload, private_key_path=tmp_path / "policy.pem", key_id="policy-key")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    forged = FixturePolicy(
        canonical_bytes=canonical,
        digest=hashlib.sha256(canonical).hexdigest(),
        trusted_policy_keys=policy.trusted_policy_keys,
        allowed_policy_key_ids=policy.allowed_policy_key_ids,
        allowed_policy_authorities=policy.allowed_policy_authorities,
        trust_digest=policy.trust_digest,
    )
    with pytest.raises(ValueError, match="public-key material"):
        evaluate_fixture_manifest(
            manifest,
            policy=forged,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=tmp_path / "evaluator.pem",
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )
    with pytest.raises(ValueError, match="public-key material"):
        verify_fixture_result(
            result,
            manifest=manifest,
            policy=forged,
            fixture_root=root,
        )


@pytest.mark.parametrize("prerequisite_id", ["UPQ-01", "LIC-01"])
@pytest.mark.parametrize("defect", ["missing_signature", "bad_signature", "digest", "subject"])
def test_prerequisite_defects_fail_closed(
    tmp_path: Path, prerequisite_id: str, defect: str
) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    receipt = next(
        item for item in manifest["prerequisites"] if item["prerequisite_id"] == prerequisite_id
    )
    if defect == "missing_signature":
        receipt.pop("proof")
    elif defect == "bad_signature":
        receipt["proof"]["value"] = "not-base64"
    elif defect == "digest":
        receipt["result_digest"] = "9" * 64
        _resign_prerequisite(receipt, tmp_path)
    else:
        receipt["workload_id"] = "other-workload"
        _resign_prerequisite(receipt, tmp_path)
    _resign_manifest(manifest, tmp_path)
    if defect in {"missing_signature", "bad_signature"}:
        with pytest.raises(ValueError):
            evaluate_fixture_manifest(
                manifest,
                policy=policy,
                evaluated_at="2026-09-20T12:30:00Z",
                fixture_root=root,
                evaluator_private_key=evaluator_key,
                evaluator_key_id="evaluator-key",
                evaluator_authority="synthetic-evaluator",
            )
    else:
        result = evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )
        assert result["outcome"] == "blocked"
        assert any(prerequisite_id.lower() in item for item in result["blockers"])


@pytest.mark.parametrize("unsafe_kind", ["symlink", "traversal", "directory"])
def test_unsafe_fixture_paths_fail_closed(tmp_path: Path, unsafe_kind: str) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    if unsafe_kind == "symlink":
        (root / "linked.sas7bdat").symlink_to(root / "sample.sas7bdat")
        manifest["fixtures"][0]["logical_path"] = "linked.sas7bdat"
    elif unsafe_kind == "traversal":
        manifest["fixtures"][0]["logical_path"] = "../outside.sas7bdat"
    else:
        (root / "dataset-dir").mkdir()
        manifest["fixtures"][0]["logical_path"] = "dataset-dir"
    _resign_manifest(manifest, tmp_path)
    if unsafe_kind == "traversal":
        with pytest.raises(ValueError, match="schema"):
            evaluate_fixture_manifest(
                manifest,
                policy=policy,
                evaluated_at="2026-09-20T12:30:00Z",
                fixture_root=root,
                evaluator_private_key=evaluator_key,
                evaluator_key_id="evaluator-key",
                evaluator_authority="synthetic-evaluator",
            )
    else:
        result = evaluate_fixture_manifest(
            manifest,
            policy=policy,
            evaluated_at="2026-09-20T12:30:00Z",
            fixture_root=root,
            evaluator_private_key=evaluator_key,
            evaluator_key_id="evaluator-key",
            evaluator_authority="synthetic-evaluator",
        )
        assert result["outcome"] == "blocked"
        assert "fixture_bytes_missing_or_unsafe" in result["decisions"][0]["blockers"]


def test_two_workloads_publish_to_isolated_paths(tmp_path: Path) -> None:
    first, manifest, policy, root = _evaluate(tmp_path)
    evaluator_key = tmp_path / "evaluator.pem"
    second_manifest = deepcopy(manifest)
    second_manifest["workload_id"] = "workload-2"
    second_manifest["run_id"] = "run-2"
    for receipt in second_manifest["prerequisites"]:
        receipt["workload_id"] = "workload-2"
        receipt["run_id"] = "run-2"
        _resign_prerequisite(receipt, tmp_path)
    _resign_manifest(second_manifest, tmp_path)
    second = evaluate_fixture_manifest(
        second_manifest,
        policy=policy,
        evaluated_at="2026-09-20T12:30:00Z",
        fixture_root=root,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    output = tmp_path / "isolated-evidence"
    first_path = publish_fixture_result(
        output, first, manifest=manifest, policy=policy, fixture_root=root
    )
    second_path = publish_fixture_result(
        output, second, manifest=second_manifest, policy=policy, fixture_root=root
    )
    assert first_path != second_path
    assert "workload-1" in first_path.parts
    assert "workload-2" in second_path.parts


def test_result_cross_workload_and_claim_mutations_are_rejected(tmp_path: Path) -> None:
    result, manifest, policy, _ = _evaluate(tmp_path)
    changed = deepcopy(result)
    changed["workload_id"] = "other-workload"
    with pytest.raises(ValueError):
        verify_fixture_result(changed, manifest=manifest, policy=policy, fixture_root=None)
    changed = deepcopy(result)
    changed["claims"]["production_ready"] = True
    with pytest.raises(ValueError):
        verify_fixture_result(changed, manifest=manifest, policy=policy, fixture_root=None)


def test_immutable_publication_is_idempotent_and_rejects_collision(tmp_path: Path) -> None:
    result, manifest, policy, _ = _evaluate(tmp_path)
    output = tmp_path / "evidence"
    fixture_root = tmp_path / "fixtures"
    path = publish_fixture_result(
        output, result, manifest=manifest, policy=policy, fixture_root=fixture_root
    )
    assert (
        publish_fixture_result(
            output, result, manifest=manifest, policy=policy, fixture_root=fixture_root
        )
        == path
    )
    path.write_text("{}", encoding="utf-8")
    with pytest.raises((FileExistsError, ValueError)):
        publish_fixture_result(
            output, result, manifest=manifest, policy=policy, fixture_root=fixture_root
        )


def test_stale_manifest_is_visible(tmp_path: Path) -> None:
    policy, manifest, root, evaluator_key = _contract(tmp_path)
    result = evaluate_fixture_manifest(
        manifest,
        policy=policy,
        evaluated_at="2026-09-20T14:00:01Z",
        fixture_root=root,
        evaluator_private_key=evaluator_key,
        evaluator_key_id="evaluator-key",
        evaluator_authority="synthetic-evaluator",
    )
    assert result["outcome"] == "stale"
    assert result["blockers"] == ["manifest_stale"]
