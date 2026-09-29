from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.discovery.macro_strategy import (
    STRATEGY_DIGEST,
    STRATEGY_ID,
    STRATEGY_VERSION,
    strategy_snapshot,
)
from smf.readiness.attestation import attestation_payload
from smf.readiness.policy import digest_value, load_readiness_policy
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value


def attest_evidence(records):
    authenticated = sanitize_discovery_value(deepcopy(records))
    assert isinstance(authenticated, list)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    policy_digest = load_readiness_policy(
        Path("tests/fixtures/readiness-policy.yaml")
    ).policy_digest
    for item in authenticated:
        item["policy_digest"] = policy_digest
        signature = key.sign(attestation_payload(item))
        item["proof"] = {
            "algorithm": "ed25519",
            "key_id": "humana-readiness-v1",
            "value": base64.b64encode(signature).decode("ascii"),
        }
    return tuple(authenticated)


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    workload = {
        "workload_id": "WL-cli",
        "name": "cli",
        "artifacts": [
            {
                "artifact_id": "ART-cli",
                "kind": "sas_program",
                "checksum": "a" * 64,
                "evidence": [
                    {
                        "evidence_id": "DISC-cli",
                        "method": "filesystem",
                        "source": "canonical-discovery",
                        "confidence": "high",
                    }
                ],
            }
        ],
        "datasets": [
            {"dataset_id": "DATA-in", "kind": "sas_dataset"},
            {"dataset_id": "DATA-out", "kind": "sas_dataset"},
        ],
        "relationships": [
            {"source_id": "ART-cli", "kind": "reads", "target_id": "DATA-in"},
            {"source_id": "ART-cli", "kind": "writes", "target_id": "DATA-out"},
        ],
        "external_dependencies": [],
        "dependency_graph": {"graph_id": "GRAPH-cli", "unresolved": []},
        "outputs": [
            {
                "output_id": "OUT-cli",
                "dataset_id": "DATA-out",
                "consumer_resolution": "confirmed",
                "consumer_ids": ["claims-reporting"],
            }
        ],
        "boundaries": [],
        "macro_analysis": {
            "analysis_id": "MAN-cli",
            "discovery_id": "MDISC-cli",
            "workload_id": "WL-cli",
            "strategy_id": STRATEGY_ID,
            "strategy_version": STRATEGY_VERSION,
            "strategy_digest": STRATEGY_DIGEST,
            "strategy_snapshot": strategy_snapshot(),
            "expansion_mode": "none",
            "complete": True,
            "source_inventory": [{"source_artifact_id": "ART-cli", "source_checksum": "a" * 64}],
            "logical_artifacts": [],
            "observations": [],
            "resolutions": [],
            "blockers": [],
            "limits_applied": strategy_snapshot()["limits"],
        },
    }
    macro = workload["macro_analysis"]
    macro["discovery_id"] = stable_id(
        "MDISC",
        {
            "workload": "WL-cli",
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
        },
    )
    macro["analysis_id"] = stable_id(
        "MAN",
        {
            "discovery": macro["discovery_id"],
            "workload": "WL-cli",
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
            "limits": macro["limits_applied"],
            "logical_artifacts": [],
            "observations": [],
            "resolutions": [],
            "blockers": [],
            "complete": True,
        },
    )
    discovery = tmp_path / "discovery.json"
    discovery.write_text(json.dumps({"workloads": [workload]}), encoding="utf-8")
    now = datetime.now(UTC).isoformat()
    evidence = [
        {
            "evidence_id": "EV-discovery",
            "workload_id": "WL-cli",
            "subject_id": "WL-cli",
            "kind": "discovery_snapshot",
            "status": "pass",
            "workload_digest": digest_value(workload),
            "snapshot_uri": "evidence://discovery/WL-cli/DISCOVERY-RUN-cli",
            "observed_at": now,
            "authority": "smf-discovery-service",
            "acquisition_source": "governed-discovery-store",
            "execution_id": "DISCOVERY-RUN-cli",
        },
        {
            "evidence_id": "EV-assessment",
            "workload_id": "WL-cli",
            "subject_id": "ART-cli",
            "kind": "assessment",
            "status": "pass",
            "source_checksum": "a" * 64,
            "complexity": "simple",
            "risk_factors": [],
            "unsupported_constructs": [],
            "observed_at": now,
            "authority": "humana-assessment-service",
            "acquisition_source": "governed-assessment-store",
            "execution_id": "ASSESS-RUN-cli",
        },
        {
            "evidence_id": "EV-map-in",
            "workload_id": "WL-cli",
            "subject_id": "DATA-in",
            "kind": "dataset_mapping",
            "direction": "input",
            "approved": True,
            "target_dataset_id": "claims_input",
            "target_catalog": "humana",
            "target_schema": "modernized",
            "mapping_digest": "b" * 64,
            "authority": "humana-data-governance",
            "acquisition_source": "governed-mapping-registry",
            "decision_id": "MAP-DECISION-IN",
            "status": "pass",
            "observed_at": now,
        },
        {
            "evidence_id": "EV-map-out",
            "workload_id": "WL-cli",
            "subject_id": "DATA-out",
            "kind": "dataset_mapping",
            "direction": "output",
            "approved": True,
            "target_dataset_id": "claims_output",
            "target_catalog": "humana",
            "target_schema": "modernized",
            "mapping_digest": "c" * 64,
            "authority": "humana-data-governance",
            "acquisition_source": "governed-mapping-registry",
            "decision_id": "MAP-DECISION-OUT",
            "status": "pass",
            "observed_at": now,
        },
        {
            "evidence_id": "EV-baseline",
            "workload_id": "WL-cli",
            "subject_id": "DATA-out",
            "kind": "baseline",
            "authority": "sas-executed-baseline",
            "acquisition_source": "governed-baseline-store",
            "checksum": "d" * 64,
            "artifact_uri": "evidence://baselines/SAS-RUN-cli/DATA-out",
            "artifact_digest": "d" * 64,
            "schema_digest": "e" * 64,
            "measurement_ids": ["row-count", "schema", "content"],
            "source_execution_id": "SAS-RUN-cli",
            "workload_digest": digest_value(workload),
            "qualified_boundary_id": None,
            "status": "pass",
            "observed_at": now,
        },
        *(
            {
                "evidence_id": f"EV-{check_id}",
                "workload_id": "WL-cli",
                "subject_id": "WL-cli",
                "kind": kind,
                "check_id": check_id,
                "status": "pass",
                "observed_at": now,
                "authority": "humana-platform-control-plane",
                "acquisition_source": "readiness-evidence-adapter",
                "execution_id": f"CHECK-RUN-{check_id}",
            }
            for kind, check_id in (
                ("environment", "target_workspace_access"),
                ("environment", "governed_catalog_access"),
                ("runtime", "target_runtime_compatible"),
            )
        ),
    ]
    bundle = tmp_path / "evidence.json"
    bundle.write_text(
        json.dumps({"workload_id": "WL-cli", "evidence": attest_evidence(evidence)}),
        encoding="utf-8",
    )
    return discovery, bundle


def _run(
    tmp_path: Path, discovery: Path, bundle: Path, attempt: str
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "ready",
            str(discovery),
            str(bundle),
            "--policy",
            "tests/fixtures/readiness-policy.yaml",
            "--run-id",
            "run-cli",
            "--attempt-id",
            attempt,
            "--out",
            str(tmp_path / "out"),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_ready_cli_positive_restart_and_retry(tmp_path: Path) -> None:
    discovery, bundle = _inputs(tmp_path)
    first = _run(tmp_path, discovery, bundle, "1")
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)["classification"] == "READY"
    manifest = tmp_path / "out/runs/run-cli/workloads/WL-cli/attempts/1/readiness.manifest.json"
    assert json.loads(manifest.read_text(encoding="utf-8"))["classification"] == "READY"
    telemetry = manifest.with_name("readiness.telemetry.json")
    assert json.loads(telemetry.read_text(encoding="utf-8"))["outcome"] == "ready"

    # A retry is a distinct append-only attempt and does not alter attempt 1.
    before = manifest.read_bytes()
    second = _run(tmp_path, discovery, bundle, "2")
    assert second.returncode == 0, second.stderr
    assert manifest.read_bytes() == before
    assert (manifest.parent.parent / "2/readiness.manifest.json").exists()


def test_ready_cli_repairs_missing_telemetry_from_canonical_manifest(tmp_path: Path) -> None:
    discovery, bundle = _inputs(tmp_path)
    first = _run(tmp_path, discovery, bundle, "1")
    assert first.returncode == 0, first.stderr
    manifest = tmp_path / "out/runs/run-cli/workloads/WL-cli/attempts/1/readiness.manifest.json"
    canonical = manifest.read_bytes()
    telemetry = manifest.with_name("readiness.telemetry.json")
    telemetry.unlink()

    restarted = _run(tmp_path, discovery, bundle, "1")

    assert restarted.returncode == 0, restarted.stderr
    assert manifest.read_bytes() == canonical
    assert json.loads(restarted.stdout)["result_id"] == json.loads(canonical)["result_id"]
    assert (
        json.loads(telemetry.read_text(encoding="utf-8"))["readiness_result_id"]
        == json.loads(canonical)["result_id"]
    )


def test_ready_cli_non_ready_persists_and_returns_nonzero(tmp_path: Path) -> None:
    discovery, bundle = _inputs(tmp_path)
    payload = json.loads(bundle.read_text(encoding="utf-8"))
    payload["evidence"] = payload["evidence"][:-1]
    bundle.write_text(json.dumps(payload), encoding="utf-8")

    completed = _run(tmp_path, discovery, bundle, "1")

    assert completed.returncode == 2
    assert json.loads(completed.stdout)["classification"] == "NEEDS_EVIDENCE"
    assert (
        tmp_path / "out/runs/run-cli/workloads/WL-cli/attempts/1/readiness.manifest.json"
    ).exists()


def test_convert_cli_consumes_humana_mandatory_binding(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "smf.cli.main",
            "convert",
            str(source),
            "--deployment-config",
            "deployments/humana/factory.yaml",
            "--workload-id",
            "WL-cli",
            "--run-id",
            "run-cli",
            "--readiness-attempt-id",
            "1",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )

    assert completed.returncode == 1
    assert "readiness manifest is required" in completed.stderr
