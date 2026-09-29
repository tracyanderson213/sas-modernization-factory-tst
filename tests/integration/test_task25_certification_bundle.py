from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.certification_bundle import (
    POSITIVE_STATE,
    ROLES,
    CertificationBundleRequest,
    evaluate_certification_bundle,
    publish_certification_bundle,
    verify_certification_bundle,
)
from smf.upstream.crypto import canonical_bytes, digest_value


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


def _sign(value: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> None:
    unsigned = dict(value)
    unsigned.pop("proof", None)
    value["proof"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical_bytes(unsigned))).decode("ascii"),
    }


def _fixture(
    root: Path,
    *,
    expired_approval: bool = False,
    cross_run_source: bool = False,
    failed_role: str | None = None,
    workload_id: str = "workload-one",
    output_root: Path | None = None,
    incompatible_role: str | None = None,
    disconnected_role: str | None = None,
    protected_payload_role: str | None = None,
    payload_symlink_role: str | None = None,
) -> CertificationBundleRequest:
    evidence_root = root / "evidence"
    evidence_root.mkdir(parents=True)
    root_key = Ed25519PrivateKey.generate()
    producer_key = Ed25519PrivateKey.generate()
    identity = {
        "client_id": "client-one",
        "workload_id": workload_id,
        "source_id": "source-one",
        "run_id": "run-one",
        "attempt_id": "attempt-one",
    }
    policy: dict[str, Any] = {
        "schema_version": "1.0",
        "policy_id": "competition-certification",
        "policy_version": "1.0",
        "policy_digest": "0" * 64,
        "identity": identity,
        "required_roles": list(ROLES),
        "contract_versions": {role: "1.0" for role in ROLES},
        "role_authorities": [{"role": role, "key_ids": ["producer-one"]} for role in ROLES],
        "verification_keys": {"producer-one": _public(producer_key)},
        "evidence_class": "synthetic_contract",
        "authority_key_id": "policy-root",
        "valid_from": "2026-09-20T00:00:00Z",
        "valid_until": "2026-09-28T00:00:00Z",
    }
    policy["policy_digest"] = digest_value(
        {key: value for key, value in policy.items() if key != "policy_digest"}
    )
    _sign(policy, root_key, "policy-root")
    (evidence_root / "policy.json").write_text(json.dumps(policy, sort_keys=True) + "\n")

    prior: list[str] = []
    paths: list[str] = []
    for index, role in enumerate(ROLES, start=1):
        payload = (
            b"secret-canary do-not-persist"
            if role == protected_payload_role
            else json.dumps({"role": role, "safe": True}, sort_keys=True).encode()
        )
        payload_path = f"payloads/{role}.json"
        (evidence_root / "payloads").mkdir(exist_ok=True)
        (evidence_root / payload_path).write_bytes(payload)
        if role == payload_symlink_role:
            linked_path = f"payloads/{role}-linked.json"
            (evidence_root / linked_path).symlink_to(evidence_root / payload_path)
            payload_path = linked_path
        evidence_identity = dict(identity)
        if role == "source" and cross_run_source:
            evidence_identity["run_id"] = "other-run"
        evidence: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_id": f"evidence-{index}",
            "evidence_digest": "0" * 64,
            "role": role,
            "contract_version": "2.0" if role == incompatible_role else "1.0",
            **evidence_identity,
            "policy_digest": policy["policy_digest"],
            "payload_ref": payload_path,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "state": "failed" if role == failed_role else POSITIVE_STATE[role],
            "predecessor_digests": (
                (["f" * 64] + list(prior[1:]))
                if role == disconnected_role and prior
                else list(prior)
            ),
            "issued_at": "2026-09-21T11:00:00Z",
            "expires_at": (
                "2026-09-21T12:00:00Z"
                if role == "completion_approval" and expired_approval
                else "2026-09-22T00:00:00Z"
            ),
        }
        evidence["evidence_digest"] = digest_value(
            {key: value for key, value in evidence.items() if key != "evidence_digest"}
        )
        _sign(evidence, producer_key, "producer-one")
        relative = f"records/{role}.json"
        (evidence_root / "records").mkdir(exist_ok=True)
        (evidence_root / relative).write_text(json.dumps(evidence, sort_keys=True) + "\n")
        paths.append(relative)
        prior.append(evidence["evidence_digest"])
    return CertificationBundleRequest(
        evidence_root=evidence_root,
        output_root=output_root or root / "output",
        policy_relative_path="policy.json",
        evidence_relative_paths=tuple(paths),
        trust_roots={"policy-root": _public(root_key)},
        evaluated_at="2026-09-21T12:00:00Z",
    )


def test_complete_signed_synthetic_chain_is_reconstructable_but_not_certified(
    tmp_path: Path,
) -> None:
    request = _fixture(tmp_path)
    result = evaluate_certification_bundle(request)
    assert [item["role"] for item in result["chain"]] == list(ROLES)
    assert result["blockers"] == ["external_certification_authority_required"]
    assert result["claims"]["executed"] is True
    assert result["claims"]["validated"] is True
    assert result["claims"]["approval_verified"] is False
    assert result["claims"]["certified"] is False
    assert result["claims"]["promoted"] is False
    observed, path = publish_certification_bundle(request)
    assert path.is_file() and observed == result
    assert publish_certification_bundle(request) == (observed, path)


def test_missing_baseline_and_nonpassing_state_remain_explicit(tmp_path: Path) -> None:
    request = _fixture(tmp_path)
    paths = tuple(path for path in request.evidence_relative_paths if "baseline" not in path)
    missing = evaluate_certification_bundle(replace(request, evidence_relative_paths=paths))
    assert "missing:baseline" in missing["blockers"]
    assert missing["claims"]["certified"] is False

    request = _fixture(tmp_path / "blocked", failed_role="conversion")
    failed = evaluate_certification_bundle(request)
    assert "conversion:failed" in failed["blockers"]
    assert failed["claims"]["certified"] is False


def test_tampered_payload_expired_approval_and_self_asserted_success_fail(tmp_path: Path) -> None:
    request = _fixture(tmp_path)
    (request.evidence_root / "payloads/validation.json").write_text('{"tampered":true}\n')
    with pytest.raises(ValueError, match="payload bytes changed"):
        evaluate_certification_bundle(request)

    request = _fixture(tmp_path / "expired", expired_approval=True)
    with pytest.raises(ValueError, match="not current"):
        evaluate_certification_bundle(request)

    request = _fixture(tmp_path / "asserted")
    result = evaluate_certification_bundle(request)
    forged = copy.deepcopy(result)
    forged["claims"]["certified"] = True
    with pytest.raises(ValueError, match="schema validation|current governed"):
        verify_certification_bundle(forged, request)


def test_policy_substitution_symlink_traversal_and_cross_run_fail(tmp_path: Path) -> None:
    request = _fixture(tmp_path)
    with pytest.raises(ValueError, match="safe relative"):
        evaluate_certification_bundle(replace(request, policy_relative_path="../policy.json"))
    link = request.evidence_root / "linked.json"
    link.symlink_to(request.evidence_root / "policy.json")
    with pytest.raises(ValueError, match="symlink|regular"):
        evaluate_certification_bundle(replace(request, policy_relative_path="linked.json"))

    cross_run = _fixture(tmp_path / "cross-run", cross_run_source=True)
    with pytest.raises(ValueError, match="identity"):
        evaluate_certification_bundle(cross_run)


def test_duplicate_unknown_and_cross_workload_publication_are_isolated(tmp_path: Path) -> None:
    request = _fixture(tmp_path)
    duplicated = replace(
        request,
        evidence_relative_paths=request.evidence_relative_paths
        + (request.evidence_relative_paths[0],),
    )
    with pytest.raises(ValueError, match="roles must be unique"):
        evaluate_certification_bundle(duplicated)

    result, first = publish_certification_bundle(request)
    other = _fixture(
        tmp_path / "other",
        workload_id="workload-two",
        output_root=request.output_root,
    )
    other_result, second = publish_certification_bundle(other)
    assert first != second and first.is_file() and second.is_file()
    assert result["identity"]["workload_id"] == "workload-one"
    assert other_result["identity"]["workload_id"] == "workload-two"

    first.write_text("{}\n")
    with pytest.raises((ValueError, FileExistsError)):
        publish_certification_bundle(request)


def test_signature_version_chain_schema_symlink_and_protected_negatives(tmp_path: Path) -> None:
    request = _fixture(tmp_path / "policy-signature")
    policy_path = request.evidence_root / "policy.json"
    policy = json.loads(policy_path.read_text())
    policy["proof"]["value"] = "A" * len(policy["proof"]["value"])
    policy_path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="signature"):
        evaluate_certification_bundle(request)

    request = _fixture(tmp_path / "record-signature")
    record_path = request.evidence_root / "records/source.json"
    record = json.loads(record_path.read_text())
    record["proof"]["value"] = "A" * len(record["proof"]["value"])
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="signature"):
        evaluate_certification_bundle(request)

    with pytest.raises(ValueError, match="contract version"):
        evaluate_certification_bundle(
            _fixture(tmp_path / "version", incompatible_role="validation")
        )
    with pytest.raises(ValueError, match="disconnected"):
        evaluate_certification_bundle(
            _fixture(tmp_path / "chain", disconnected_role="reconciliation")
        )

    request = _fixture(tmp_path / "evidence-link")
    original = request.evidence_root / "records/source.json"
    linked = request.evidence_root / "records/source-linked.json"
    linked.symlink_to(original)
    paths = ("records/source-linked.json",) + request.evidence_relative_paths[1:]
    with pytest.raises(ValueError, match="symlink|regular"):
        evaluate_certification_bundle(replace(request, evidence_relative_paths=paths))

    request = _fixture(tmp_path / "payload-link", payload_symlink_role="source")
    with pytest.raises(ValueError, match="symlink|regular"):
        evaluate_certification_bundle(request)

    request = _fixture(tmp_path / "protected", protected_payload_role="validation")
    with pytest.raises(ValueError, match="protected material") as caught:
        evaluate_certification_bundle(request)
    assert "do-not-persist" not in str(caught.value)

    request = _fixture(tmp_path / "unknown")
    record_path = request.evidence_root / "records/source.json"
    record = json.loads(record_path.read_text())
    record["caller_success"] = True
    record_path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="schema validation"):
        evaluate_certification_bundle(request)


def test_security_critical_helper_bytes_are_manifest_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _fixture(tmp_path)
    first = evaluate_certification_bundle(request)
    paths = {item["path"] for item in first["implementation_manifest"]}
    assert {
        "smf/security/ai_admission.py",
        "smf/upstream/crypto.py",
        "smf/workload/identity.py",
    }.issubset(paths)

    original = Path.read_bytes

    def mutated(path: Path) -> bytes:
        value = original(path)
        if path.as_posix().endswith(("/upstream/crypto.py", "/workload/identity.py")):
            return value + b"\n# mutation"
        return value

    monkeypatch.setattr(Path, "read_bytes", mutated)
    second = evaluate_certification_bundle(request)
    assert first["content_digest"] != second["content_digest"]
    assert first["implementation_manifest"] != second["implementation_manifest"]


@pytest.mark.parametrize(
    "name",
    [
        "certification-policy.schema.json",
        "certification-evidence.schema.json",
        "certification-bundle-result.schema.json",
    ],
)
def test_public_and_packaged_certification_schemas_are_identical(name: str) -> None:
    root = Path(__file__).parents[2]
    assert (root / "schemas" / name).read_bytes() == (root / "src/smf/schemas" / name).read_bytes()
