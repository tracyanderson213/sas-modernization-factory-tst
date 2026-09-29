import base64
import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.deployment import (
    initialize_deployment_template,
    load_deployment_snapshot,
    preflight_deployment,
)
from smf.readiness.policy import digest_value


def copy_humana(tmp_path: Path) -> Path:
    target = tmp_path / "humana"
    shutil.copytree("deployments/humana", target)
    return target


def write_yaml(path: Path, payload: dict) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def activate_synthetic_bundle(root: Path) -> None:
    factory = yaml.safe_load((root / "factory.yaml").read_text())
    factory["template_status"] = "active"
    write_yaml(root / "factory.yaml", factory)
    databricks = yaml.safe_load((root / "databricks.yaml").read_text())
    for index, binding in enumerate(databricks["bindings"], start=1):
        binding.update(state="active", value=f"approved-ref-{index}")
        if binding["role"] == "compute_policy":
            binding["value"] = "compute-policy.yaml"
    write_yaml(root / "databricks.yaml", databricks)
    policy = yaml.safe_load((root / "compute-policy.yaml").read_text())
    authority_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    policy["policy_state"] = "active"
    policy["authority_ref"] = "humana-change-governance"
    policy["authority_key_id"] = "humana-readiness-v1"
    policy["authority_signature"] = None
    policy["valid_from"] = "2026-01-01T00:00:00Z"
    policy["valid_until"] = "2027-01-01T00:00:00Z"
    policy["max_availability_age_seconds"] = 300
    policy["profiles"] = [
        {
            "profile_id": "synthetic-isolated",
            "priority": 1,
            "compute_type": "job_cluster",
            "access_mode": "single_user",
            "dbr_version": "16.4-lts",
            "spark_version": "3.5.2",
            "scala_version": "2.12",
            "jvm_version": "17",
            "node_type": "synthetic-node",
            "min_workers": 1,
            "max_workers": 1,
            "max_concurrent_workloads": 1,
            "max_cost_usd": 1.0,
            "max_runtime_seconds": 60,
            "max_retries": 0,
            "cancellation_deadline_seconds": 10,
            "forced_termination_deadline_seconds": 20,
            "network_policy_id": "synthetic-network",
            "source_scope_id": "synthetic-source",
            "output_scope_id": "synthetic-output",
            "target": "pyspark",
            "workload_class": "synthetic",
            "single_workload_isolation": True,
        }
    ]
    authority_payload = dict(policy)
    authority_payload.pop("policy_digest")
    authority_payload.pop("authority_signature")
    policy["authority_signature"] = base64.b64encode(
        authority_key.sign(
            json.dumps(
                {
                    "contract": "smf-validation-compute-policy-authority-v1",
                    **authority_payload,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    ).decode()
    unsigned = dict(policy)
    unsigned.pop("policy_digest")
    policy["policy_digest"] = digest_value(
        {"contract": "smf-validation-compute-policy-v1", **unsigned}
    )
    write_yaml(root / "compute-policy.yaml", policy)
    readiness = yaml.safe_load((root / "readiness-policy.yaml").read_text())
    readiness["verification_keys"]["humana-readiness-v1"] = base64.b64encode(
        authority_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    write_yaml(root / "readiness-policy.yaml", readiness)


def test_pending_humana_policy_has_no_fabricated_freshness_value() -> None:
    policy = yaml.safe_load(Path("deployments/humana/compute-policy.yaml").read_text())

    assert policy["policy_state"] == "pending"
    assert policy["profiles"] == []
    assert policy["max_availability_age_seconds"] is None
    assert policy["authority_ref"] is None
    assert policy["authority_key_id"] is None
    assert policy["authority_signature"] is None
    assert policy["valid_from"] is None
    assert policy["valid_until"] is None


def configuration_digest(root: Path) -> str:
    names = [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
    ]
    return digest_value(
        {
            "files": [
                {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
                for name in names
            ]
        }
    )


def synthetic_ready_manifest(tmp_path: Path, root: Path) -> tuple[Path, dict[str, str]]:
    import test_readiness_engine as readiness_helpers

    from smf.readiness import ReadinessRequest, evaluate_readiness, write_manifest
    from smf.readiness.policy import readiness_policy_from_dict, serialize_readiness_policy

    policy_payload = serialize_readiness_policy(readiness_helpers._prerequisite_policy())
    policy_payload["prerequisite_binding"] = {
        "client_id": "humana",
        "deployment_id": "humana-competition-pilot",
        "environment_id": "humana-databricks-pilot",
        "configuration_digest": configuration_digest(root),
    }
    policy = readiness_policy_from_dict(policy_payload)
    write_yaml(root / "readiness-policy.yaml", serialize_readiness_policy(policy))

    evidence_root = tmp_path / "prerequisite-results"
    prerequisite = readiness_helpers._prerequisite_evidence(run_id="run-henv02", attempt_id="1")
    prerequisite.update(
        client_id="humana",
        deployment_id="humana-competition-pilot",
        environment_id="humana-databricks-pilot",
        configuration_digest=configuration_digest(root),
    )
    readiness_helpers._persist_prerequisite_result(evidence_root, prerequisite)
    workload = readiness_helpers._workload()
    evidence = readiness_helpers._attest_for_policy(
        [*readiness_helpers._evidence(), prerequisite], policy
    )
    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=evidence,
            run_id="run-henv02",
            attempt_id="1",
            result_root=evidence_root,
        ),
        policy,
    )
    manifest = write_manifest(tmp_path / "readiness-evidence", result)
    return manifest, {
        "workload_id": "WL-one",
        "run_id": "run-henv02",
        "attempt_id": "1",
    }


def test_checked_in_humana_skeleton_is_valid_but_fails_closed() -> None:
    snapshot = load_deployment_snapshot(Path("deployments/humana/factory.yaml"))
    result = preflight_deployment(Path("deployments/humana/factory.yaml"))

    assert snapshot.client_id == "humana"
    assert len(snapshot.bindings) == 16
    assert result.status == "unresolved"
    assert {item["code"] for item in result.blockers} >= {
        "binding_placeholder",
        "binding_pending",
        "compute_policy_pending",
        "template_not_active",
    }
    assert result.lifecycle == {
        "template_generated": True,
        "preflight_qualified": False,
        "preflight_blocked": True,
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
    }


def test_ed25519_public_key_text_is_not_mistaken_for_databricks_token(
    tmp_path: Path,
) -> None:
    root = copy_humana(tmp_path)
    readiness_path = root / "readiness-policy.yaml"
    readiness = yaml.safe_load(readiness_path.read_text())
    readiness["verification_keys"]["pending-readiness-key"] = (
        "Xk2OJAs0g59+ppzVAQ4vCOlnEvuUdaPiADK9IyBrk9M="
    )
    write_yaml(readiness_path, readiness)

    snapshot = load_deployment_snapshot(root / "factory.yaml")

    assert snapshot.template_status.value == "placeholder"


@pytest.mark.parametrize("state", ["actve", "enabled", "approved", True])
def test_unknown_or_authorizing_binding_state_is_rejected(tmp_path: Path, state: object) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "databricks.yaml").read_text())
    payload["bindings"][0]["state"] = state
    write_yaml(root / "databricks.yaml", payload)

    with pytest.raises(ValueError, match="schema validation|state"):
        load_deployment_snapshot(root / "factory.yaml")


@pytest.mark.parametrize(
    "field,value",
    [
        ("template_status", "ready"),
        ("template_status", "approved"),
    ],
)
def test_self_asserted_factory_authority_is_rejected(
    tmp_path: Path, field: str, value: str
) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "factory.yaml").read_text())
    payload[field] = value
    write_yaml(root / "factory.yaml", payload)

    with pytest.raises(ValueError, match="template_status"):
        load_deployment_snapshot(root / "factory.yaml")


def test_caller_supplied_ready_boolean_cannot_authorize_preflight(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "databricks.yaml").read_text())
    payload["ready"] = True
    write_yaml(root / "databricks.yaml", payload)

    with pytest.raises(ValueError, match="schema validation"):
        load_deployment_snapshot(root / "factory.yaml")


def test_mixed_environment_and_duplicate_identity_fail_closed(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "databricks.yaml").read_text())
    payload["deployment_identity"]["environment_id"] = "other-environment"
    write_yaml(root / "databricks.yaml", payload)
    with pytest.raises(ValueError, match="Mixed-environment"):
        load_deployment_snapshot(root / "factory.yaml")

    root = copy_humana(tmp_path / "duplicate")
    text = (root / "factory.yaml").read_text()
    (root / "factory.yaml").write_text(text + "\ntemplate_status: active\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_deployment_snapshot(root / "factory.yaml")


@pytest.mark.parametrize(
    "name",
    [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
        "readiness-policy.yaml",
    ],
)
def test_every_protected_configuration_rejects_duplicate_yaml_keys(
    tmp_path: Path, name: str
) -> None:
    root = copy_humana(tmp_path)
    path = root / name
    key = {
        "security-policy.yaml": "version: 2",
        "validation-policy.yaml": "version: 1",
        "readiness-policy.yaml": "policy_id: duplicate",
    }.get(name, "schema_version: '1.0'")
    path.write_text(path.read_text() + f"\n{key}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate protected configuration key"):
        load_deployment_snapshot(root / "factory.yaml")


def test_active_compute_policy_requires_governed_authority_proof(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)
    policy = yaml.safe_load((root / "compute-policy.yaml").read_text())
    policy["authority_signature"] = base64.b64encode(b"forged").decode()
    unsigned = dict(policy)
    unsigned.pop("policy_digest")
    policy["policy_digest"] = digest_value(
        {"contract": "smf-validation-compute-policy-v1", **unsigned}
    )
    write_yaml(root / "compute-policy.yaml", policy)
    readiness = yaml.safe_load((root / "readiness-policy.yaml").read_text())
    readiness["prerequisite_binding"]["configuration_digest"] = configuration_digest(root)
    write_yaml(root / "readiness-policy.yaml", readiness)

    with pytest.raises(ValueError, match="authority proof is invalid"):
        load_deployment_snapshot(root / "factory.yaml")


def test_compute_policy_must_participate_in_configuration_digest(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    factory = yaml.safe_load((root / "factory.yaml").read_text())
    factory["readiness"]["configuration_files"].remove("compute-policy.yaml")
    write_yaml(root / "factory.yaml", factory)

    with pytest.raises(
        ValueError, match="snapshot digest mismatch|configuration scope is incomplete"
    ):
        load_deployment_snapshot(root / "factory.yaml")


@pytest.mark.parametrize(
    "value",
    [
        "dapi0123456789secret",
        "https://user:secret@example.invalid",
        "DB_PASSWORD=secret-canary-HENV02",
        "client_secret",
    ],
)
def test_embedded_credentials_are_rejected_without_echo(tmp_path: Path, value: str) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "databricks.yaml").read_text())
    payload["bindings"][0].update(state="active", value=value)
    write_yaml(root / "databricks.yaml", payload)
    with pytest.raises(ValueError, match="embedded credential") as failure:
        load_deployment_snapshot(root / "factory.yaml")
    assert value not in str(failure.value)


@pytest.mark.parametrize(
    "name",
    [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
        "readiness-policy.yaml",
    ],
)
def test_secret_bearing_mapping_keys_are_rejected_before_hashing(tmp_path: Path, name: str) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / name).read_text())
    canary = f"client_secret_canary_{name.replace('.', '_')}"
    payload[canary] = "opaque"
    write_yaml(root / name, payload)

    with pytest.raises(ValueError, match="embedded credential") as failure:
        load_deployment_snapshot(root / "factory.yaml")
    assert canary not in str(failure.value)


@pytest.mark.parametrize("path", ["../outside.yaml", "%2e%2e/outside.yaml", "https://x.invalid/a"])
def test_provider_path_cannot_escape_deployment(tmp_path: Path, path: str) -> None:
    root = copy_humana(tmp_path)
    payload = yaml.safe_load((root / "factory.yaml").read_text())
    payload["deployment"]["configuration"] = path
    write_yaml(root / "factory.yaml", payload)
    with pytest.raises(ValueError, match="relative|escapes"):
        load_deployment_snapshot(root / "factory.yaml")


def test_provider_path_rejects_symlink(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    target = root / "databricks.yaml"
    alternate = root / "alternate.yaml"
    alternate.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(alternate.name)

    with pytest.raises(ValueError, match="regular deployment file"):
        load_deployment_snapshot(root / "factory.yaml")


def test_denied_and_pending_are_distinct_terminal_states(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    pending = preflight_deployment(root / "factory.yaml")
    assert pending.status == "unresolved"

    payload = yaml.safe_load((root / "databricks.yaml").read_text())
    payload["bindings"][0]["state"] = "denied"
    write_yaml(root / "databricks.yaml", payload)
    readiness = yaml.safe_load((root / "readiness-policy.yaml").read_text())

    import hashlib

    from smf.readiness.policy import digest_value

    names = [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
    ]
    readiness["prerequisite_binding"]["configuration_digest"] = digest_value(
        {
            "files": [
                {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest()}
                for name in names
            ]
        }
    )
    write_yaml(root / "readiness-policy.yaml", readiness)

    denied = preflight_deployment(root / "factory.yaml")
    assert denied.status == "blocked"
    assert any(item["code"] == "binding_denied" for item in denied.blockers)


def test_template_generation_is_idempotent_and_collision_safe(tmp_path: Path) -> None:
    output = tmp_path / "generated"
    first = initialize_deployment_template("humana", output)
    before = {path.name: path.read_bytes() for path in first}
    second = initialize_deployment_template("humana", output)
    assert first == second
    assert before == {path.name: path.read_bytes() for path in second}

    (output / "databricks.yaml").write_text("conflict", encoding="utf-8")
    with pytest.raises(FileExistsError, match="collision"):
        initialize_deployment_template("humana", output)


def test_configuration_mutation_changes_bundle_and_breaks_readiness_digest(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    before = load_deployment_snapshot(root / "factory.yaml")
    policy = root / "validation-policy.yaml"
    policy.write_bytes(policy.read_bytes() + b"\n# changed\n")
    with pytest.raises(ValueError, match="snapshot digest mismatch"):
        load_deployment_snapshot(root / "factory.yaml")
    assert before.bundle_digest


def test_active_configuration_still_requires_attributable_readiness(tmp_path: Path) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)

    # Rebind the existing HENV-01 policy to the exact changed bytes.
    import hashlib

    from smf.readiness.policy import digest_value

    files = [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
    ]
    digest = digest_value(
        {
            "files": [
                {
                    "path": name,
                    "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                }
                for name in files
            ]
        }
    )
    readiness = yaml.safe_load((root / "readiness-policy.yaml").read_text())
    readiness["prerequisite_binding"]["configuration_digest"] = digest
    write_yaml(root / "readiness-policy.yaml", readiness)

    result = preflight_deployment(root / "factory.yaml")
    assert result.status == "unresolved"
    assert result.blockers == (
        {
            "code": "readiness_evidence_missing",
            "binding_id": "readiness-manifest",
            "state": "missing",
        },
    )
    assert not result.lifecycle["preflight_qualified"]


def test_all_active_synthetic_bundle_with_valid_ready_manifest_qualifies(
    tmp_path: Path,
) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)
    manifest, context = synthetic_ready_manifest(tmp_path, root)

    result = preflight_deployment(root / "factory.yaml", manifest, **context)

    assert result.status == "qualified"
    assert result.lifecycle["preflight_qualified"]
    assert not any(
        result.lifecycle[claim]
        for claim in ("generated", "executed", "validated", "parity_passed", "certified")
    )
    manifest_payload = json.loads(manifest.read_text())
    assert result.readiness_evidence == {
        "result_id": manifest_payload["result_id"],
        "manifest_digest": manifest_payload["content_digest"],
        "policy_id": manifest_payload["policy_id"],
        "policy_version": manifest_payload["policy_version"],
        "policy_digest": manifest_payload["policy_digest"],
        **context,
    }


def test_ready_manifest_cannot_replay_across_preflight_context(
    tmp_path: Path,
) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)
    manifest, context = synthetic_ready_manifest(tmp_path, root)

    for field, value in (
        ("workload_id", "WL-other"),
        ("run_id", "run-other"),
        ("attempt_id", "2"),
    ):
        replay_context = {**context, field: value}
        result = preflight_deployment(root / "factory.yaml", manifest, **replay_context)
        assert result.status == "unresolved"
        assert result.blockers[0]["code"] == "readiness_evidence_mismatch"

    absent_context = preflight_deployment(root / "factory.yaml", manifest)
    assert absent_context.status == "unresolved"
    assert absent_context.blockers[0]["code"] == "readiness_evidence_mismatch"


def test_tampered_manifest_identity_or_digest_cannot_qualify(
    tmp_path: Path,
) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)
    manifest, context = synthetic_ready_manifest(tmp_path, root)
    payload = json.loads(manifest.read_text())
    payload["result_id"] = "READY-0000000000000000"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="content digest mismatch"):
        preflight_deployment(root / "factory.yaml", manifest, **context)


def test_ready_manifest_cannot_qualify_against_stale_readiness_policy(
    tmp_path: Path,
) -> None:
    root = copy_humana(tmp_path)
    activate_synthetic_bundle(root)
    manifest, context = synthetic_ready_manifest(tmp_path, root)
    policy_path = root / "readiness-policy.yaml"
    policy = yaml.safe_load(policy_path.read_text())
    policy["policy_version"] = "stale-replay-rejected"
    write_yaml(policy_path, policy)

    result = preflight_deployment(root / "factory.yaml", manifest, **context)

    assert result.status == "unresolved"
    assert result.blockers[0]["code"] == "readiness_evidence_mismatch"


def test_schema_copy_is_packaged_identically() -> None:
    from importlib.resources import files

    name = "deployment-configuration.schema.json"
    assert (Path("schemas") / name).read_bytes() == files("smf.schemas").joinpath(name).read_bytes()


@pytest.mark.parametrize(
    "name",
    [
        "factory.yaml",
        "databricks.yaml",
        "compute-policy.yaml",
        "security-policy.yaml",
        "validation-policy.yaml",
        "readiness-policy.yaml",
    ],
)
def test_reviewed_and_packaged_templates_match(name: str) -> None:
    from importlib.resources import files

    packaged = files("smf.deployment.templates").joinpath("humana", name)
    assert (Path("deployments/humana") / name).read_bytes() == packaged.read_bytes()
