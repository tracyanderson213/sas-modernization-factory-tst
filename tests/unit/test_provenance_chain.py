from __future__ import annotations

import argparse
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from itertools import combinations
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.cli.main import run_verify_provenance
from smf.provenance import (
    build_provenance_chain,
    load_provenance_policy,
    publish_provenance_chain,
    verify_provenance_chain,
)
from smf.provenance.engine import derive_node_id
from smf.workload.lineage import LineageArtifact, build_run_lineage


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sign_node(node: dict[str, Any], private: Ed25519PrivateKey) -> dict[str, Any]:
    node["node_id"] = derive_node_id(node)
    material = dict(node)
    material.pop("proof", None)
    node["proof"] = {
        "algorithm": "ed25519",
        "key_id": "producer-key",
        "value": base64.b64encode(private.sign(_canonical(material))).decode(),
    }
    return node


def _fixture(
    tmp_path: Path, *, client: str = "client-a", second_entrypoint: bool = False
) -> dict[str, Any]:
    evidence = tmp_path / "evidence"
    source = evidence / "artifacts/source.sas"
    generated = evidence / "artifacts/generated.py"
    result = evidence / "artifacts/execution.json"
    source.parent.mkdir(parents=True)
    source.write_text("proc sql; select id from members; quit;\n", encoding="utf-8")
    second_source = evidence / "artifacts/second.sas"
    if second_entrypoint:
        second_source.write_text("proc print data=members; run;\n", encoding="utf-8")
    generated.write_text("print('bounded offline execution')\n", encoding="utf-8")
    _write_json(result, {"exit_code": 0, "status": "succeeded"})

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    stages = [
        "source_intake",
        "strategy",
        "conversion",
        "generated_artifact",
        "execution",
        "validation",
        "repair",
        "human_decision",
    ]
    policy = {
        "schema_version": "1.0",
        "policy_id": "offline-provenance",
        "policy_version": "1.0",
        "required_stages": stages,
        "producers": [
            {
                "evidence_type": stage,
                "authority": "factory-producer",
                "key_id": "producer-key",
                "public_key": base64.b64encode(public).decode(),
            }
            for stage in stages
        ],
    }
    policy["policy_digest"] = hashlib.sha256(_canonical(policy)).hexdigest()
    _write_json(tmp_path / "policy.json", policy)
    policy_digest = policy["policy_digest"]
    lineage_artifacts = [
        LineageArtifact(
            subject_id="source-main",
            kind="sas_program",
            logical_path="artifacts/source.sas",
            sha256=_digest(source),
            size_bytes=source.stat().st_size,
            entrypoint=True,
        )
    ]
    if second_entrypoint:
        lineage_artifacts.append(
            LineageArtifact(
                subject_id="source-second",
                kind="sas_program",
                logical_path="artifacts/second.sas",
                sha256=_digest(second_source),
                size_bytes=second_source.stat().st_size,
                entrypoint=True,
            )
        )
    lineage = build_run_lineage(
        client_id=client,
        workload_key="workload-a",
        artifacts=tuple(lineage_artifacts),
        operation="conversion",
        target="pyspark",
        policy_digest=policy_digest,
        strategy_digest="1" * 64,
        configuration_digest="2" * 64,
        idempotency_key="run-key",
        attempt_key="attempt-key",
        provider="deterministic",
        provider_version="1.0",
        qualified_input_digests=tuple(item.sha256 for item in lineage_artifacts),
    )
    _write_json(evidence / "lineage.json", lineage.to_dict())

    artifacts = {
        "source": {
            "artifact_id": "source-main",
            "artifact_ref": "artifacts/source.sas",
            "sha256": _digest(source),
        },
        "generated": {
            "artifact_id": "generated-main",
            "artifact_ref": "artifacts/generated.py",
            "sha256": _digest(generated),
        },
        "result": {
            "artifact_id": "execution-result",
            "artifact_ref": "artifacts/execution.json",
            "sha256": _digest(result),
        },
    }
    source_outputs = [artifacts["source"]]
    if second_entrypoint:
        source_outputs.append(
            {
                "artifact_id": "source-second",
                "artifact_ref": "artifacts/second.sas",
                "sha256": _digest(second_source),
            }
        )
    definitions = [
        ("source_intake", "admitted", [artifacts["source"]], source_outputs),
        ("strategy", "selected", [artifacts["source"]], [artifacts["source"]]),
        ("conversion", "converted", [artifacts["source"]], [artifacts["generated"]]),
        (
            "generated_artifact",
            "generated",
            [artifacts["generated"]],
            [artifacts["generated"]],
        ),
        ("execution", "succeeded", [artifacts["generated"]], [artifacts["result"]]),
        ("validation", "validated", [artifacts["result"]], [artifacts["result"]]),
        ("repair", "not_required", [artifacts["result"]], [artifacts["result"]]),
        ("human_decision", "not_required", [artifacts["result"]], []),
    ]
    refs: list[str] = []
    previous: str | None = None
    for index, (stage, status, inputs, outputs) in enumerate(definitions):
        original = (
            evidence / "lineage.json"
            if stage == "source_intake"
            else evidence / f"original/{stage}.json"
        )
        if stage != "source_intake":
            _write_json(original, {"producer": stage, "status": status, "sequence": index})
        node: dict[str, Any] = {
            "schema_version": "1.0",
            "node_id": "",
            "node_type": stage,
            "status": status,
            "client_id": lineage.client_id,
            "workload_id": lineage.workload_id,
            "source_revision_id": lineage.source_revision_id,
            "run_id": lineage.run_id,
            "attempt_id": lineage.attempt_id,
            "lineage_id": lineage.lineage_id,
            "subject_id": "source-main",
            "authority": "factory-producer",
            "producer_id": f"{stage}-producer",
            "producer_version": "1.0",
            "decision_id": f"decision-{index}",
            "policy_digest": policy_digest,
            "configuration_digest": "2" * 64,
            "strategy_digest": "1" * 64,
            "provider_id": "deterministic",
            "provider_version": "1.0",
            "original_evidence_type": f"smf.{stage}",
            "original_evidence_version": "1.0",
            "original_evidence_ref": (
                "lineage.json" if stage == "source_intake" else f"original/{stage}.json"
            ),
            "original_evidence_sha256": _digest(original),
            "inputs": deepcopy(inputs),
            "outputs": deepcopy(outputs),
            "predecessor_node_ids": [] if previous is None else [previous],
            "supersedes_node_id": None,
            "reason_code": None,
            "proof": {"algorithm": "ed25519", "key_id": "producer-key", "value": "x" * 88},
        }
        _sign_node(node, private)
        reference = f"nodes/{index:02d}-{stage}.json"
        _write_json(evidence / reference, node)
        refs.append(reference)
        previous = node["node_id"]
    return {
        "evidence": evidence,
        "source": source,
        "generated": generated,
        "result": result,
        "policy_path": tmp_path / "policy.json",
        "lineage": lineage,
        "refs": refs,
        "private": private,
    }


def _build(fixture: dict[str, Any], refs: list[str] | None = None) -> dict[str, Any]:
    return build_provenance_chain(
        lineage_ref="lineage.json",
        node_refs=refs or fixture["refs"],
        evidence_root=fixture["evidence"],
        source_root=fixture["evidence"],
        policy=load_provenance_policy(fixture["policy_path"]),
    )


def _publish(output: Path, chain: dict[str, Any], fixture: dict[str, Any]) -> Path:
    return publish_provenance_chain(
        output,
        chain,
        evidence_root=fixture["evidence"],
        source_root=fixture["evidence"],
        policy=load_provenance_policy(fixture["policy_path"]),
    )


def test_complete_chain_is_reconstructable_and_non_authorizing(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)

    assert chain["terminal_disposition"] == "validated"
    assert chain["telemetry"] == {
        "generated": True,
        "executed": True,
        "validated": True,
        "parity_passed": False,
        "human_assisted": False,
        "human_approved": False,
        "certified": False,
        "blocked": False,
    }
    assert chain["authorizes_execution"] is False
    path = _publish(tmp_path / "out", chain, fixture)
    assert (
        verify_provenance_chain(
            path,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
        == chain
    )


def test_cli_replays_verified_chain_without_producer_side_effects(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)
    path = _publish(tmp_path / "canonical", chain, fixture)

    exit_code = run_verify_provenance(
        argparse.Namespace(
            chain=str(path),
            evidence_root=str(fixture["evidence"]),
            source_root=str(fixture["evidence"]),
            policy=str(fixture["policy_path"]),
            out=str(tmp_path / "recovered"),
            json=True,
        )
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["terminal_disposition"] == "validated"
    assert output["authorizes_execution"] is False


def test_missing_prerequisites_fail_closed_and_cannot_count_as_success(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture, fixture["refs"][:4])

    assert chain["terminal_disposition"] == "blocked_missing"
    assert chain["telemetry"]["generated"] is True
    assert chain["telemetry"]["executed"] is False
    assert chain["telemetry"]["validated"] is False
    assert chain["telemetry"]["blocked"] is True


def test_every_truncated_stage_policy_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    complete = json.loads(fixture["policy_path"].read_text(encoding="utf-8"))
    stages = complete["required_stages"]

    for count in range(len(stages)):
        for subset in combinations(stages, count):
            policy = deepcopy(complete)
            policy["required_stages"] = list(subset)
            policy.pop("policy_digest")
            policy["policy_digest"] = hashlib.sha256(_canonical(policy)).hexdigest()
            _write_json(fixture["policy_path"], policy)
            with pytest.raises(
                ValueError, match="complete canonical stage sequence|fields are invalid"
            ):
                load_provenance_policy(fixture["policy_path"])


def test_multi_entrypoint_workload_cannot_validate_only_one_subject(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, second_entrypoint=True)

    with pytest.raises(ValueError, match="exactly one eligible entrypoint"):
        _build(fixture)


def test_publication_rejects_forged_mappings_before_writing(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output = tmp_path / "out"
    forged = {
        "run_id": fixture["lineage"].run_id,
        "workload_id": fixture["lineage"].workload_id,
        "attempt_id": fixture["lineage"].attempt_id,
        "chain_id": "PC-v1-" + "0" * 64,
        "telemetry": {
            "validated": True,
            "parity_passed": True,
            "human_approved": True,
            "certified": True,
        },
    }
    with pytest.raises(ValueError, match="invalid|reconstruction"):
        publish_provenance_chain(
            output,
            forged,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
    assert not output.exists()

    forged = _build(fixture)
    forged["telemetry"]["human_approved"] = True
    with pytest.raises(ValueError, match="reconstruction"):
        publish_provenance_chain(
            output,
            forged,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "unsafe_id",
    ["..", "../../escaped", "/tmp/escaped", "%2e%2e", "nested/value", "nested\\value"],
)
def test_publication_rejects_unsafe_identity_paths(tmp_path: Path, unsafe_id: str) -> None:
    fixture = _fixture(tmp_path)
    forged = _build(fixture)
    forged["run_id"] = unsafe_id
    output = tmp_path / "out"

    with pytest.raises(ValueError, match="invalid|reconstruction|Unsafe"):
        publish_provenance_chain(
            output,
            forged,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
    assert not output.exists()


def test_publication_rejects_symlink_boundary(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)
    output = tmp_path / "out"
    outside = tmp_path / "outside"
    outside.mkdir()
    output.mkdir()
    (output / "runs").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink boundary"):
        publish_provenance_chain(
            output,
            chain,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("target", ["original", "artifact", "source"])
def test_authoritative_byte_mutation_invalidates_positive_claim(
    tmp_path: Path, target: str
) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)
    path = _publish(tmp_path / "out", chain, fixture)
    if target == "original":
        changed = fixture["evidence"] / "original/validation.json"
    elif target == "artifact":
        changed = fixture["generated"]
    else:
        changed = fixture["source"]
    changed.write_bytes(changed.read_bytes() + b"x")

    with pytest.raises(ValueError, match="missing or changed|immutable binding|source closure"):
        verify_provenance_chain(
            path,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )


def test_unsigned_self_asserted_success_and_unknown_enums_are_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    node_path = fixture["evidence"] / fixture["refs"][4]
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["approved"] = True
    _write_json(node_path, node)
    with pytest.raises(ValueError, match="fields are invalid"):
        _build(fixture)

    fixture = _fixture(tmp_path / "enum")
    node_path = fixture["evidence"] / fixture["refs"][3]
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["status"] = "succeededd"
    _write_json(node_path, node)
    with pytest.raises(ValueError, match="fields are invalid"):
        _build(fixture)


def test_cross_run_substitution_and_secret_identity_are_rejected(tmp_path: Path) -> None:
    first = _fixture(tmp_path / "first")
    second = _fixture(tmp_path / "second", client="client-b")
    foreign = second["evidence"] / second["refs"][0]
    destination = first["evidence"] / "nodes/foreign.json"
    destination.write_bytes(foreign.read_bytes())
    with pytest.raises(ValueError, match="substituted"):
        _build(first, ["nodes/foreign.json"])

    node_path = first["evidence"] / first["refs"][0]
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["reason_code"] = "secret-canary-DO-NOT-PERSIST"
    _sign_node(node, first["private"])
    _write_json(node_path, node)
    with pytest.raises(ValueError, match="Unsafe provenance reason_code"):
        _build(first)

    protected = _fixture(tmp_path / "protected")
    original = protected["evidence"] / "original/validation.json"
    original.write_text('{"message":"secret-canary-DO-NOT-PERSIST"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Protected content"):
        _build(protected)


def test_caller_cannot_substitute_a_new_trust_policy(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    policy_path = fixture["policy_path"]
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["policy_version"] = "2.0"
    policy.pop("policy_digest")
    policy["policy_digest"] = hashlib.sha256(_canonical(policy)).hexdigest()
    _write_json(policy_path, policy)

    with pytest.raises(ValueError, match="lineage is not bound"):
        _build(fixture)


def test_retry_recovers_projection_without_changing_canonical_chain(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)
    path = _publish(tmp_path / "out", chain, fixture)
    first_bytes = path.read_bytes()
    telemetry = path.with_name("telemetry.json")
    telemetry.unlink()

    assert _publish(tmp_path / "out", chain, fixture) == path
    assert path.read_bytes() == first_bytes
    assert telemetry.is_file()


def test_two_workloads_publish_without_global_serialization_or_cross_state(
    tmp_path: Path,
) -> None:
    first = _fixture(tmp_path / "first", client="client-a")
    second = _fixture(tmp_path / "second", client="client-b")
    first_chain = _build(first)
    second_chain = _build(second)
    output = tmp_path / "shared-output"

    with ThreadPoolExecutor(max_workers=2) as pool:
        paths = list(
            pool.map(
                lambda item: _publish(output, item[0], item[1]),
                ((first_chain, first), (second_chain, second)),
            )
        )

    assert paths[0] != paths[1]
    assert paths[0].is_file() and paths[1].is_file()
    assert first_chain["workload_id"] != second_chain["workload_id"]


@pytest.mark.parametrize(
    ("state", "disposition"),
    [("pending", "human_pending"), ("denied", "human_denied"), ("expired", "human_pending")],
)
def test_human_denial_pending_and_expiry_remain_distinct(
    tmp_path: Path, state: str, disposition: str
) -> None:
    fixture = _fixture(tmp_path)
    node_path = fixture["evidence"] / fixture["refs"][-1]
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["status"] = state
    node["reason_code"] = f"approval-{state}"
    _sign_node(node, fixture["private"])
    _write_json(node_path, node)

    chain = _build(fixture)
    assert chain["terminal_disposition"] == disposition
    assert chain["telemetry"]["validated"] is True
    assert chain["telemetry"]["blocked"] is True
    assert chain["telemetry"]["human_approved"] is False


def test_duplicate_and_boundary_escaping_references_fail_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    with pytest.raises(ValueError, match="Duplicate or ambiguous"):
        _build(fixture, [fixture["refs"][0], fixture["refs"][0]])

    node_path = fixture["evidence"] / fixture["refs"][0]
    node = json.loads(node_path.read_text(encoding="utf-8"))
    duplicate = deepcopy(node["outputs"][0])
    duplicate["artifact_ref"] = "artifacts/generated.py"
    duplicate["sha256"] = _digest(fixture["generated"])
    node["outputs"].append(duplicate)
    _sign_node(node, fixture["private"])
    _write_json(node_path, node)
    with pytest.raises(ValueError, match="Duplicate provenance outputs"):
        _build(fixture, [fixture["refs"][0]])

    with pytest.raises(ValueError, match="fields are invalid|Unsafe provenance"):
        build_provenance_chain(
            lineage_ref="../lineage.json",
            node_refs=[],
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )


def test_tampered_summary_cannot_replace_original_evidence(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    chain = _build(fixture)
    path = _publish(tmp_path / "out", chain, fixture)
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["telemetry"]["parity_passed"] = True
    _write_json(path, stored)

    with pytest.raises(ValueError, match="fields are invalid|does not match reconstruction"):
        verify_provenance_chain(
            path,
            evidence_root=fixture["evidence"],
            source_root=fixture["evidence"],
            policy=load_provenance_policy(fixture["policy_path"]),
        )
