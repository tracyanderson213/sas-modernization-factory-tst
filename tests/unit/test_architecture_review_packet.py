from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_security_configuration import write_configuration

from smf.architecture_review import (
    ArchitectureReviewRequest,
    assemble_packet,
    load_packet,
    require_execution_authority,
    write_packet,
)
from smf.architecture_review.projection import shared_projection
from smf.architecture_review.schema import validate
from smf.discovery import discover_source
from smf.readiness.policy import digest_value
from smf.security.configuration import canonical_json


def request(tmp_path: Path, **changes: object) -> ArchitectureReviewRequest:
    root = Path.cwd()
    discovery = discover_source(root / "examples/simple", provider="filesystem").to_dict()
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    workload = discovery["workloads"][0]
    entry = next(item for item in workload["artifacts"] if item["kind"] == "sas_program")
    boundary = next(
        item for item in workload["boundaries"] if entry["artifact_id"] in item["artifact_ids"]
    )
    values: dict[str, object] = {
        "repo_root": Path("/"),
        "factory_config": root / "deployments/humana/factory.yaml",
        "threat_model": root / "docs/architecture/security-threat-model.yaml",
        "requirements": root / "competition/requirements.yaml",
        "source": root / "examples/simple/example.sas",
        "discovery_manifest": discovery_path,
        "workload_id": workload["workload_id"],
        "subject_id": entry["artifact_id"],
        "boundary_id": boundary["boundary_id"],
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "assessed_revision": "rev-1",
    }
    values.update(changes)
    return ArchitectureReviewRequest(**values)  # type: ignore[arg-type]


def signed_decision(
    expected: dict[str, str], key: Ed25519PrivateKey, *, purpose: str, state: str = "approved"
) -> dict[str, object]:
    now = datetime.now(UTC)
    evidence: dict[str, object] = {
        "evidence_id": "evidence-1",
        "state": state,
        "authority": "security-authority",
        "purpose": purpose,
        "decision_id": "decision-1",
        "owner_assignment_ref": "assignment-1",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        **expected,
        "proof": {"algorithm": "ed25519", "key_id": "key-1", "value": ""},
    }
    unsigned = {name: value for name, value in evidence.items() if name != "proof"}
    evidence["proof"]["value"] = base64.b64encode(key.sign(canonical_json(unsigned))).decode()  # type: ignore[index]
    return evidence


def write_decision(path: Path, evidence: dict[str, object]) -> Path:
    path.write_text(json.dumps(evidence), encoding="utf-8")
    return path


def install_ready_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    base_request: ArchitectureReviewRequest,
    base_packet: dict[str, object],
) -> tuple[Path, dict[str, object]]:
    discovery = json.loads(base_request.discovery_manifest.read_text(encoding="utf-8"))
    workload = next(
        item for item in discovery["workloads"] if item["workload_id"] == base_request.workload_id
    )
    identity = base_packet["identity"]
    configuration = base_packet["configuration"]
    assert isinstance(identity, dict) and isinstance(configuration, dict)
    manifest: dict[str, object] = {
        "result_id": "ready-result-1",
        "content_digest": "a" * 64,
        "classification": "READY",
        "workload_id": base_request.workload_id,
        "workload_digest": digest_value(workload),
        "boundary_id": base_request.boundary_id,
        "run_id": base_request.run_id,
        "attempt_id": base_request.attempt_id,
        "policy_id": "ready-policy-1",
        "policy_version": "1.0",
        "policy_digest": "b" * 64,
        "policy_snapshot": {
            "prerequisite_binding": {
                "client_id": identity["client_id"],
                "deployment_id": identity["deployment_id"],
                "environment_id": identity["environment_id"],
                "configuration_digest": configuration["configuration_digest"],
            }
        },
        "qualification_input": {"workload": workload},
        "prerequisite_checklist": [],
    }
    path = tmp_path / "readiness.manifest.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "smf.architecture_review.engine.load_readiness_manifest", lambda _: manifest
    )
    return path, manifest


def request_for_source_tree(
    tmp_path: Path, source_root: Path, entry_name: str
) -> ArchitectureReviewRequest:
    discovery = discover_source(source_root, provider="filesystem").to_dict()
    discovery_path = tmp_path / f"{entry_name}-discovery.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    workload = discovery["workloads"][0]
    entry = next(item for item in workload["artifacts"] if item["name"] == entry_name)
    boundary = next(
        item for item in workload["boundaries"] if entry["artifact_id"] in item["artifact_ids"]
    )
    return request(
        tmp_path,
        source=source_root / entry_name,
        discovery_manifest=discovery_path,
        workload_id=workload["workload_id"],
        subject_id=entry["artifact_id"],
        boundary_id=boundary["boundary_id"],
    )


def test_packet_is_exactly_bound_non_authorizing_and_fail_closed(tmp_path: Path) -> None:
    packet = assemble_packet(request(tmp_path))
    assert packet["authority"] == "non_authorizing"
    assert packet["source"]["entry_artifact_id"] == packet["identity"]["subject_id"]
    assert packet["source"]["source_closure_digest"]
    assert packet["source"]["sha256"]
    assert packet["henv01_readiness"] == {"state": "missing"}
    assert packet["terminal_disposition"] == "blocked"
    assert packet["lifecycle"] == {
        "packet_generated": True,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "human_assisted": False,
        "blocked": True,
    }
    assert {item["requirement_refs"][0] for item in packet["approval_requests"]} == {
        f"HC-REQ-{index:02d}" for index in range(1, 11)
    }


def test_humana_prerequisites_keep_requirement_ownership_separate() -> None:
    policy = yaml.safe_load(Path("deployments/humana/readiness-policy.yaml").read_text())
    owners = {
        item["prerequisite_id"]: item["owner_assignment_ref"] for item in policy["prerequisites"]
    }
    assert all(value.startswith("assignment-pending-") for value in owners.values())
    assert not any(value.startswith("HC-REQ-") for value in owners.values())


@pytest.mark.parametrize("source", ["empty.sas", "not-sas.txt"])
def test_empty_or_nonconvertible_subject_is_rejected(tmp_path: Path, source: str) -> None:
    path = tmp_path / source
    path.write_text("" if source.endswith(".sas") else "data work.x; run;", encoding="utf-8")
    with pytest.raises(ValueError, match="meaningful SAS entry point"):
        assemble_packet(
            request(
                tmp_path,
                source=path,
            )
        )


def test_boundary_escape_and_sensitive_disclosure_identity_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes repository scope"):
        assemble_packet(request(tmp_path, source=Path("../outside.sas")))
    with pytest.raises(ValueError, match="Unsafe recipient_class"):
        assemble_packet(request(tmp_path, recipient_class="patient@example.com"))


def test_unknown_lifecycle_or_decision_enum_cannot_bypass_schema(tmp_path: Path) -> None:
    packet = assemble_packet(request(tmp_path))
    packet["lifecycle"]["executed"] = True
    with pytest.raises(ValueError, match="Architecture review schema validation failed"):
        validate("architecture-review-packet.schema.json", packet)
    packet = assemble_packet(request(tmp_path))
    packet["approval_requests"][0]["decision_state"] = "aproved"
    with pytest.raises(ValueError, match="Architecture review schema validation failed"):
        validate("architecture-review-packet.schema.json", packet)


def test_append_only_retry_recovers_derived_artifacts_and_isolates_workloads(
    tmp_path: Path,
) -> None:
    first = assemble_packet(request(tmp_path))
    first_path = write_packet(tmp_path, first)
    first_path.with_name("packet.telemetry.json").unlink()
    assert write_packet(tmp_path, first) == first_path
    assert first_path.with_name("packet.telemetry.json").is_file()
    assert load_packet(first_path) == first

    changed = copy.deepcopy(first)
    changed["terminal_disposition"] = "review_ready"
    changed["content_digest"] = digest_value({**changed, "content_digest": ""})
    with pytest.raises(FileExistsError, match="Conflicting immutable"):
        write_packet(tmp_path, changed)

    second = assemble_packet(request(tmp_path, run_id="run-2", attempt_id="attempt-2"))
    second_path = write_packet(tmp_path, second)
    assert second_path != first_path
    assert load_packet(first_path)["identity"]["run_id"] == "run-1"


def test_request_strings_cannot_authorize_shared_projection(tmp_path: Path) -> None:
    packet = assemble_packet(
        request(
            tmp_path,
            recipient_class="humana-security-reviewers",
            disclosure_policy_revision="disclosure-v1",
            retention_policy_ref="retention-v1",
        )
    )
    assert shared_projection(packet) is None


def test_mutated_canonical_bytes_are_rejected(tmp_path: Path) -> None:
    packet = assemble_packet(request(tmp_path))
    path = write_packet(tmp_path, packet)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["identity"]["attempt_id"] = "attempt-2"
    payload["content_digest"] = digest_value({**payload, "content_digest": ""})
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="identity mismatch"):
        load_packet(path)


def test_discovery_replay_rejects_mutation_and_source_substitution(tmp_path: Path) -> None:
    base = request(tmp_path)
    payload = json.loads(base.discovery_manifest.read_text(encoding="utf-8"))
    payload["workloads"][0]["artifacts"][0]["checksum"] = "0" * 64
    base.discovery_manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic replay"):
        assemble_packet(base)

    base = request(tmp_path)
    substituted = tmp_path / "substituted.sas"
    substituted.write_text("data work.other; run;", encoding="utf-8")
    with pytest.raises(ValueError, match="canonical entry point"):
        assemble_packet(request(tmp_path, source=substituted))


def test_comment_only_and_symlink_sources_are_rejected_before_qualification(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    comments = source_root / "comments.sas"
    comments.write_text("/* comments only */\n* still only a comment;\n", encoding="utf-8")
    discovery = discover_source(source_root, provider="filesystem").to_dict()
    discovery_path = tmp_path / "comments-discovery.json"
    discovery_path.write_text(json.dumps(discovery), encoding="utf-8")
    workload = discovery["workloads"][0]
    artifact = workload["artifacts"][0]
    boundary = workload["boundaries"][0]
    with pytest.raises(ValueError, match="meaningful SAS"):
        assemble_packet(
            request(
                tmp_path,
                source=comments,
                discovery_manifest=discovery_path,
                workload_id=workload["workload_id"],
                subject_id=artifact["artifact_id"],
                boundary_id=boundary["boundary_id"],
            )
        )

    alias = tmp_path / "source-link.sas"
    alias.symlink_to(Path.cwd() / "examples/simple/example.sas")
    with pytest.raises(ValueError, match="regular file"):
        assemble_packet(request(tmp_path, source=alias))

    parent_alias = tmp_path / "source-parent-link"
    parent_alias.symlink_to(Path.cwd() / "examples/simple", target_is_directory=True)
    with pytest.raises(ValueError, match="regular file"):
        assemble_packet(request(tmp_path, source=parent_alias / "example.sas"))


@pytest.mark.parametrize("source_text", ["%let x=1;\n", "%include 'other.sas';\n"])
def test_static_only_sas_is_not_a_meaningful_execution_subject(
    tmp_path: Path, source_text: str
) -> None:
    source_root = tmp_path / "static-source"
    source_root.mkdir()
    (source_root / "main.sas").write_text(source_text, encoding="utf-8")
    (source_root / "other.sas").write_text("%let y=2;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="meaningful SAS"):
        assemble_packet(request_for_source_tree(tmp_path, source_root, "main.sas"))


def test_sensitive_canary_in_transitive_source_closure_is_rejected(tmp_path: Path) -> None:
    source_root = tmp_path / "sensitive-closure"
    source_root.mkdir()
    (source_root / "main.sas").write_text(
        "%include 'included.sas';\ndata work.out; set work.in; run;\n", encoding="utf-8"
    )
    (source_root / "included.sas").write_text(
        "%let password=secret-canary-closure;\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Source closure artifact contains sensitive"):
        assemble_packet(request_for_source_tree(tmp_path, source_root, "main.sas"))


@pytest.mark.parametrize("mutated_name", ["main.sas", "included.sas"])
def test_post_assembly_source_mutation_fails_before_persistence(
    tmp_path: Path, mutated_name: str
) -> None:
    source_root = tmp_path / "mutable-source"
    source_root.mkdir()
    (source_root / "main.sas").write_text(
        "%include 'included.sas';\ndata work.out; set work.in; run;\n", encoding="utf-8"
    )
    (source_root / "included.sas").write_text("%let x=1;\n", encoding="utf-8")
    packet = assemble_packet(request_for_source_tree(tmp_path, source_root, "main.sas"))
    (source_root / mutated_name).write_text("data work.changed; run;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source snapshot changed"):
        write_packet(tmp_path / "out", packet)


@pytest.mark.parametrize("mutated_name", ["main.sas", "included.sas"])
def test_persisted_packet_revalidates_entry_and_closure_before_use(
    tmp_path: Path, mutated_name: str
) -> None:
    source_root = tmp_path / "persisted-source"
    source_root.mkdir()
    (source_root / "main.sas").write_text(
        "%include 'included.sas';\ndata work.out; set work.in; run;\n", encoding="utf-8"
    )
    (source_root / "included.sas").write_text("%let x=1;\n", encoding="utf-8")
    packet = assemble_packet(request_for_source_tree(tmp_path, source_root, "main.sas"))
    path = write_packet(tmp_path / "out", packet)

    (source_root / mutated_name).write_text("data work.changed; run;\n", encoding="utf-8")

    with pytest.raises(ValueError, match="source snapshot changed"):
        load_packet(path)


def test_signed_henv01_decision_is_exactly_bound_but_packet_never_authorizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_request = request(tmp_path)
    base = assemble_packet(base_request)
    readiness_path, readiness = install_ready_manifest(monkeypatch, tmp_path, base_request, base)
    _, key, policy, bindings = write_configuration(tmp_path)
    expected = {
        "client_id": base["identity"]["client_id"],
        "deployment_id": base["identity"]["deployment_id"],
        "environment_id": base["identity"]["environment_id"],
        "workload_id": base["identity"]["workload_id"],
        "workload_digest": base["source"]["workload_digest"],
        "boundary_id": base["identity"]["boundary_id"],
        "subject_id": base["identity"]["subject_id"],
        "source_sha256": base["source"]["sha256"],
        "run_id": base["identity"]["run_id"],
        "attempt_id": base["identity"]["attempt_id"],
        "assessed_revision": base["assessed_revision"],
        "configuration_digest": base["configuration"]["configuration_digest"],
        "readiness_result_id": str(readiness["result_id"]),
        "readiness_manifest_digest": str(readiness["content_digest"]),
    }
    evidence = signed_decision(expected, key, purpose="henv01-protected-execution")
    evidence_path = write_decision(tmp_path / "activation.json", evidence)
    packet = assemble_packet(
        request(
            tmp_path,
            security_policy=policy,
            security_bindings=bindings,
            activation_evidence=evidence_path,
            readiness_manifest=readiness_path,
        )
    )
    assert packet["protected_execution_decision"]["state"] == "verified"
    assert not any(
        item["code"] == "protected_execution_decision_missing" for item in packet["blockers"]
    )
    with pytest.raises(ValueError, match="non-authorizing"):
        require_execution_authority(packet)


@pytest.mark.parametrize(
    "mutation",
    ["forged", "stale", "expired", "cross_environment", "cross_boundary", "different_source"],
)
def test_forged_stale_and_cross_subject_henv01_decisions_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    base_request = request(tmp_path)
    base = assemble_packet(base_request)
    readiness_path, readiness = install_ready_manifest(monkeypatch, tmp_path, base_request, base)
    _, key, policy, bindings = write_configuration(tmp_path)
    expected = {
        "client_id": base["identity"]["client_id"],
        "deployment_id": base["identity"]["deployment_id"],
        "environment_id": base["identity"]["environment_id"],
        "workload_id": base["identity"]["workload_id"],
        "workload_digest": base["source"]["workload_digest"],
        "boundary_id": base["identity"]["boundary_id"],
        "subject_id": base["identity"]["subject_id"],
        "source_sha256": base["source"]["sha256"],
        "run_id": base["identity"]["run_id"],
        "attempt_id": base["identity"]["attempt_id"],
        "assessed_revision": base["assessed_revision"],
        "configuration_digest": base["configuration"]["configuration_digest"],
        "readiness_result_id": str(readiness["result_id"]),
        "readiness_manifest_digest": str(readiness["content_digest"]),
    }
    evidence = signed_decision(expected, key, purpose="henv01-protected-execution")
    if mutation == "forged":
        evidence["proof"]["value"] = base64.b64encode(b"x" * 64).decode()  # type: ignore[index]
    elif mutation == "stale":
        evidence["issued_at"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    elif mutation == "expired":
        evidence["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    elif mutation == "cross_environment":
        evidence["environment_id"] = "other-environment"
    elif mutation == "cross_boundary":
        evidence["boundary_id"] = "other-boundary"
    else:
        evidence["source_sha256"] = "0" * 64
    path = write_decision(tmp_path / f"{mutation}.json", evidence)
    with pytest.raises(ValueError, match="Governed decision"):
        assemble_packet(
            request(
                tmp_path,
                security_policy=policy,
                security_bindings=bindings,
                activation_evidence=path,
                readiness_manifest=readiness_path,
            )
        )


def test_signed_activation_cannot_substitute_missing_readiness(tmp_path: Path) -> None:
    base = assemble_packet(request(tmp_path))
    _, key, policy, bindings = write_configuration(tmp_path)
    expected = {
        "client_id": base["identity"]["client_id"],
        "deployment_id": base["identity"]["deployment_id"],
        "environment_id": base["identity"]["environment_id"],
        "workload_id": base["identity"]["workload_id"],
        "workload_digest": base["source"]["workload_digest"],
        "boundary_id": base["identity"]["boundary_id"],
        "subject_id": base["identity"]["subject_id"],
        "source_sha256": base["source"]["sha256"],
        "run_id": base["identity"]["run_id"],
        "attempt_id": base["identity"]["attempt_id"],
        "assessed_revision": base["assessed_revision"],
        "configuration_digest": base["configuration"]["configuration_digest"],
        "readiness_result_id": "invented-ready",
        "readiness_manifest_digest": "0" * 64,
    }
    path = write_decision(
        tmp_path / "activation-without-readiness.json",
        signed_decision(expected, key, purpose="henv01-protected-execution"),
    )
    with pytest.raises(ValueError, match="requires exact-source READY"):
        assemble_packet(
            request(
                tmp_path,
                security_policy=policy,
                security_bindings=bindings,
                activation_evidence=path,
            )
        )


@pytest.mark.parametrize("mutation", ["source", "closure", "classification"])
def test_activation_rejects_nonready_or_differently_bound_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    base_request = request(tmp_path)
    base = assemble_packet(base_request)
    readiness_path, readiness = install_ready_manifest(monkeypatch, tmp_path, base_request, base)
    qualification = readiness["qualification_input"]
    assert isinstance(qualification, dict)
    workload = qualification["workload"]
    assert isinstance(workload, dict)
    if mutation == "source":
        entry = next(
            item
            for item in workload["artifacts"]  # type: ignore[union-attr]
            if item["artifact_id"] == base_request.subject_id
        )
        entry["checksum"] = "0" * 64
    elif mutation == "closure":
        boundary = next(
            item
            for item in workload["boundaries"]  # type: ignore[union-attr]
            if item["boundary_id"] == base_request.boundary_id
        )
        boundary["artifact_ids"] = []
    else:
        readiness["classification"] = "BLOCKED"
    _, key, policy, bindings = write_configuration(tmp_path)
    expected = {
        "client_id": base["identity"]["client_id"],
        "deployment_id": base["identity"]["deployment_id"],
        "environment_id": base["identity"]["environment_id"],
        "workload_id": base["identity"]["workload_id"],
        "workload_digest": base["source"]["workload_digest"],
        "boundary_id": base["identity"]["boundary_id"],
        "subject_id": base["identity"]["subject_id"],
        "source_sha256": base["source"]["sha256"],
        "run_id": base["identity"]["run_id"],
        "attempt_id": base["identity"]["attempt_id"],
        "assessed_revision": base["assessed_revision"],
        "configuration_digest": base["configuration"]["configuration_digest"],
        "readiness_result_id": str(readiness["result_id"]),
        "readiness_manifest_digest": str(readiness["content_digest"]),
    }
    evidence_path = write_decision(
        tmp_path / f"activation-{mutation}.json",
        signed_decision(expected, key, purpose="henv01-protected-execution"),
    )
    expected_message = (
        "source closure" if mutation != "classification" else "requires exact-source READY"
    )
    with pytest.raises(ValueError, match=expected_message):
        assemble_packet(
            request(
                tmp_path,
                readiness_manifest=readiness_path,
                security_policy=policy,
                security_bindings=bindings,
                activation_evidence=evidence_path,
            )
        )


def test_signed_disclosure_is_required_and_shared_payload_schema_is_strict(tmp_path: Path) -> None:
    base = assemble_packet(request(tmp_path))
    _, key, policy, bindings = write_configuration(tmp_path)
    expected = {
        "client_id": base["identity"]["client_id"],
        "deployment_id": base["identity"]["deployment_id"],
        "environment_id": base["identity"]["environment_id"],
        "assessed_revision": base["assessed_revision"],
        "recipient_class": "humana-security-reviewers",
        "disclosure_policy_revision": "disclosure-v1",
        "retention_policy_ref": "retention-v1",
    }
    decision = signed_decision(expected, key, purpose="architecture-review-shared-disclosure")
    decision_path = write_decision(tmp_path / "disclosure.json", decision)
    packet = assemble_packet(
        request(
            tmp_path,
            security_policy=policy,
            security_bindings=bindings,
            disclosure_evidence=decision_path,
            recipient_class=expected["recipient_class"],
            disclosure_policy_revision=expected["disclosure_policy_revision"],
            retention_policy_ref=expected["retention_policy_ref"],
        )
    )
    shared = shared_projection(packet)
    assert shared is not None
    encoded = json.dumps(shared)
    assert "value_digest" not in encoded and "owner_role" not in encoded
    shared["payload"]["free_text"] = "patient@example.com"
    with pytest.raises(ValueError, match="schema validation failed"):
        validate("architecture-review-projection.schema.json", shared)


def test_sensitive_requirement_free_text_is_rejected_before_hashing(tmp_path: Path) -> None:
    requirements = yaml.safe_load(Path("competition/requirements.yaml").read_text())
    requirements["requirements"]["HC-REQ-01"]["owner_role"] = "patient@example.com"
    path = tmp_path / "requirements.yaml"
    path.write_text(yaml.safe_dump(requirements), encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive durable content"):
        assemble_packet(request(tmp_path, requirements=path))
