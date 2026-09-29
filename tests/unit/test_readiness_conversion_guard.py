import base64
import hashlib
import json
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.conversion import ConversionRequest, convert_workload
from smf.conversion.engine import _admit_conversion
from smf.conversion.providers.base import ProviderResult
from smf.conversion.registry import execute_plan as execute_registry_plan
from smf.discovery.macro_strategy import (
    STRATEGY_DIGEST,
    STRATEGY_ID,
    STRATEGY_VERSION,
    strategy_snapshot,
)
from smf.readiness import (
    ReadinessRequest,
    evaluate_readiness,
    load_readiness_policy,
    write_manifest,
)
from smf.readiness.attestation import attestation_payload
from smf.readiness.deployment import load_deployment_readiness
from smf.readiness.policy import digest_value
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

POLICY = Path("tests/fixtures/readiness-policy.yaml")
DEPLOYMENT = Path("tests/fixtures/readiness-factory.yaml")


@pytest.mark.parametrize(
    "filename",
    ["factory.yaml", "databricks.yaml", "security-policy.yaml", "validation-policy.yaml"],
)
def test_humana_deployment_rejects_mutated_bound_configuration(
    tmp_path: Path, filename: str
) -> None:
    deployment = tmp_path / "humana"
    shutil.copytree("deployments/humana", deployment)
    load_deployment_readiness(deployment / "factory.yaml")
    target = deployment / filename
    target.write_bytes(target.read_bytes() + b"\n# unauthorized mutation\n")

    with pytest.raises(ValueError, match="configuration snapshot digest mismatch"):
        load_deployment_readiness(deployment / "factory.yaml")

    source = tmp_path / "qualified-source.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="configuration snapshot digest mismatch"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=deployment / "factory.yaml",
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=tmp_path / "readiness.manifest.json",
            )
        )
    provider.assert_not_called()


def attest_evidence(records):
    authenticated = sanitize_discovery_value(list(deepcopy(records)))
    assert isinstance(authenticated, list)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    policy_digest = load_readiness_policy(POLICY).policy_digest
    for item in authenticated:
        item["policy_digest"] = policy_digest
        signature = key.sign(attestation_payload(item))
        item["proof"] = {
            "algorithm": "ed25519",
            "key_id": "humana-readiness-v1",
            "value": base64.b64encode(signature).decode("ascii"),
        }
    return tuple(authenticated)


def _ready_manifest(
    tmp_path: Path,
    source: Path,
    *,
    omit_runtime: bool = False,
    authenticate: bool = True,
    workload_id: str = "WL-guard",
    run_id: str = "run-1",
    attempt_id: str = "1",
    omitted_assessment_fields: tuple[str, ...] = (),
    macro_dependent: bool = False,
) -> tuple[Path, str]:
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    workload = {
        "workload_id": workload_id,
        "artifacts": [
            {
                "artifact_id": "ART-source",
                "kind": "sas_program",
                "checksum": checksum,
                "evidence": [
                    {
                        "evidence_id": "DISC-source",
                        "method": "filesystem",
                        "source": "canonical-discovery",
                        "confidence": "high",
                    }
                ],
            }
        ],
        "datasets": [],
        "relationships": [],
        "external_dependencies": [],
        "dependency_graph": {"graph_id": f"GRAPH-{workload_id}", "unresolved": []},
        "outputs": [],
        "boundaries": [],
        "macro_analysis": {
            "analysis_id": f"MAN-{workload_id}",
            "discovery_id": f"MDISC-{workload_id}",
            "workload_id": workload_id,
            "strategy_id": STRATEGY_ID,
            "strategy_version": STRATEGY_VERSION,
            "strategy_digest": STRATEGY_DIGEST,
            "strategy_snapshot": strategy_snapshot(),
            "expansion_mode": "none",
            "complete": True,
            "source_inventory": [{"source_artifact_id": "ART-source", "source_checksum": checksum}],
            "logical_artifacts": [],
            "observations": [],
            "resolutions": [],
            "blockers": [],
            "limits_applied": strategy_snapshot()["limits"],
        },
    }
    if macro_dependent:
        macro = workload["macro_analysis"]
        raw = source.read_bytes()
        token = b"%macro helper"
        start = raw.index(token)
        location = {
            "source_artifact_id": "ART-source",
            "source_checksum": checksum,
            "byte_start": start,
            "byte_end": start + len(token),
            "line": 1,
            "column": 1,
            "span_digest": hashlib.sha256(token).hexdigest(),
        }
        macro["logical_artifacts"] = [
            {
                "logical_artifact_id": "MDEF-helper",
                "artifact_type": "sas_macro_definition",
                "construct_family": "sas_macro_processor",
                "normalized_identity": "helper",
                "location": location,
            }
        ]
        macro["observations"] = [
            {
                "observation_id": "MOBS-helper",
                "kind": "definition",
                "construct_family": "sas_macro_processor",
                "normalized_identity": "helper",
                "location": location,
                "logical_artifact_id": "MDEF-helper",
            }
        ]
    macro = workload["macro_analysis"]
    macro["discovery_id"] = stable_id(
        "MDISC",
        {
            "workload": workload_id,
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
        },
    )
    macro["analysis_id"] = stable_id(
        "MAN",
        {
            "discovery": macro["discovery_id"],
            "workload": workload_id,
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
            "limits": macro["limits_applied"],
            "logical_artifacts": sorted(
                item["logical_artifact_id"] for item in macro["logical_artifacts"]
            ),
            "observations": sorted(item["observation_id"] for item in macro["observations"]),
            "resolutions": [],
            "blockers": [],
            "complete": True,
        },
    )
    observed_at = datetime.now(UTC).isoformat()
    named_evidence = tuple(
        {
            "evidence_id": f"EV-{check_id}",
            "workload_id": workload_id,
            "subject_id": workload_id,
            "kind": kind,
            "status": "pass",
            "check_id": check_id,
            "observed_at": observed_at,
            "authority": "humana-platform-control-plane",
            "acquisition_source": "readiness-evidence-adapter",
            "execution_id": f"CHECK-RUN-{check_id}",
        }
        for kind, check_id in (
            ("environment", "target_workspace_access"),
            ("environment", "governed_catalog_access"),
            ("runtime", "target_runtime_compatible"),
        )
        if not (omit_runtime and kind == "runtime")
    )
    assessment_evidence = {
        "evidence_id": "EV-assessment",
        "workload_id": workload_id,
        "subject_id": "ART-source",
        "kind": "assessment",
        "status": "pass",
        "source_checksum": checksum,
        "complexity": "simple",
        "risk_factors": [],
        "unsupported_constructs": [],
        "observed_at": observed_at,
        "authority": "humana-assessment-service",
        "acquisition_source": "governed-assessment-store",
        "execution_id": "ASSESS-RUN-source",
    }
    for field in omitted_assessment_fields:
        assessment_evidence.pop(field)
    evidence = (
        {
            "evidence_id": "EV-discovery",
            "workload_id": workload_id,
            "subject_id": workload_id,
            "kind": "discovery_snapshot",
            "status": "pass",
            "workload_digest": digest_value(workload),
            "snapshot_uri": f"evidence://discovery/{workload_id}/DISCOVERY-RUN-source",
            "observed_at": observed_at,
            "authority": "smf-discovery-service",
            "acquisition_source": "governed-discovery-store",
            "execution_id": "DISCOVERY-RUN-source",
        },
        assessment_evidence,
        *named_evidence,
    )
    policy = load_readiness_policy(POLICY)
    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=attest_evidence(evidence) if authenticate else evidence,
            run_id=run_id,
            attempt_id=attempt_id,
        ),
        policy,
    )
    return write_manifest(tmp_path / "evidence", result), policy.policy_digest


def test_spoofed_authority_labels_without_attestation_cannot_authorize_conversion(
    tmp_path: Path,
) -> None:
    source = tmp_path / "spoofed.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, _ = _ready_manifest(tmp_path, source, authenticate=False)
    assert json.loads(manifest.read_text(encoding="utf-8"))["classification"] == "NEEDS_EVIDENCE"

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="classification is NEEDS_EVIDENCE"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
            )
        )
    provider.assert_not_called()


def test_omitting_all_readiness_arguments_blocks_before_provider(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="deployment readiness binding is required"),
    ):
        convert_workload(ConversionRequest(source_file=source))
    provider.assert_not_called()


def test_macro_dependent_ready_workload_routes_to_review_without_generation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "macro.sas"
    source.write_text("%macro helper; %mend;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, source, macro_dependent=True)

    with patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider:
        result = convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
                readiness_policy_digest=policy_digest,
                output_dir=tmp_path / "out",
            )
        )

    assert result.status == "review_required"
    assert result.provider == "none"
    assert result.metadata["macro_strategy_digest"] == STRATEGY_DIGEST
    assert len(result.output_files) == 1
    assert result.output_files[0].endswith("conversion.manifest.json")
    provider.assert_not_called()


def test_humana_binding_requires_readiness_without_optional_flag(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="readiness manifest is required"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=Path("deployments/humana/factory.yaml"),
                workload_id="WL-guard",
                run_id="run-1",
                readiness_attempt_id="1",
            )
        )
    provider.assert_not_called()


def test_caller_supplied_manifest_without_deployment_authority_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, _ = _ready_manifest(tmp_path, source)

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="deployment readiness binding is required"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
            )
        )
    provider.assert_not_called()


def test_non_ready_manifest_blocks_provider(tmp_path: Path) -> None:
    workload = {
        "workload_id": "WL-guard",
        "artifacts": [],
        "datasets": [],
        "relationships": [],
        "external_dependencies": [],
        "dependency_graph": None,
        "outputs": [],
        "boundaries": [],
    }
    result = evaluate_readiness(
        ReadinessRequest(workload=workload, evidence=(), run_id="run-1", attempt_id="1"),
        load_readiness_policy(Path("deployments/humana/readiness-policy.yaml")),
    )
    manifest = write_manifest(tmp_path / "evidence", result)
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="classification"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=Path("deployments/humana/factory.yaml"),
                workload_id="WL-guard",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
            )
        )
    provider.assert_not_called()


@pytest.mark.parametrize(
    "omitted_fields",
    [
        ("complexity",),
        ("risk_factors",),
        ("unsupported_constructs",),
        ("complexity", "risk_factors", "unsupported_constructs"),
    ],
)
def test_incomplete_assessment_manifest_cannot_authorize_conversion(
    tmp_path: Path,
    omitted_fields: tuple[str, ...],
) -> None:
    source = tmp_path / "incomplete-assessment.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(
        tmp_path,
        source,
        omitted_assessment_fields=omitted_fields,
    )
    assert json.loads(manifest.read_text(encoding="utf-8"))["classification"] == "NEEDS_EVIDENCE"

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="classification is NEEDS_EVIDENCE"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
                readiness_policy_digest=policy_digest,
            )
        )
    provider.assert_not_called()


def test_ready_identity_or_policy_mismatch_blocks_provider(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, source)

    for changed in (
        {"workload_id": "WL-other"},
        {"run_id": "run-other"},
        {"readiness_attempt_id": "2"},
        {"readiness_policy_digest": "0" * 64},
    ):
        values = {
            "source_file": source,
            "deployment_config": DEPLOYMENT,
            "workload_id": "WL-guard",
            "source_artifact_id": "ART-source",
            "run_id": "run-1",
            "readiness_attempt_id": "1",
            "readiness_manifest": manifest,
            "readiness_policy_digest": policy_digest,
            **changed,
        }
        with (
            patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
            pytest.raises(ValueError, match="blocked"),
        ):
            convert_workload(ConversionRequest(**values))
        provider.assert_not_called()


def test_recalculated_digest_cannot_forge_ready_decision(tmp_path: Path) -> None:
    source = tmp_path / "simple.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, source, omit_runtime=True)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["classification"] == "NEEDS_EVIDENCE"
    payload["classification"] = "READY"
    payload["blockers"] = []
    payload["missing_evidence"] = []
    payload["next_actions"] = []
    payload["terminal_disposition"] = "admitted"
    payload["content_digest"] = digest_value(
        {key: value for key, value in payload.items() if key != "content_digest"}
    )
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with (
        patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
        pytest.raises(ValueError, match="decision does not match"),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
                readiness_policy_digest=policy_digest,
            )
        )
    provider.assert_not_called()


def test_ready_manifest_is_bound_to_exact_source_bytes(tmp_path: Path) -> None:
    qualified = tmp_path / "qualified.sas"
    qualified.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, qualified)
    different = tmp_path / "different.sas"
    different.write_text("proc sql; select 2; quit;\n", encoding="utf-8")

    for source_artifact_id, message in (
        (None, "source artifact identity"),
        ("ART-other", "does not belong"),
        ("ART-source", "checksum does not match"),
    ):
        with (
            patch("smf.conversion.engine.Sas2DatabricksProvider.convert") as provider,
            pytest.raises(ValueError, match=message),
        ):
            convert_workload(
                ConversionRequest(
                    source_file=different,
                    deployment_config=DEPLOYMENT,
                    workload_id="WL-guard",
                    source_artifact_id=source_artifact_id,
                    run_id="run-1",
                    readiness_attempt_id="1",
                    readiness_manifest=manifest,
                    readiness_policy_digest=policy_digest,
                )
            )
        provider.assert_not_called()


def test_exact_qualified_source_is_admitted_with_artifact_metadata(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, source)

    metadata = _admit_conversion(
        ConversionRequest(
            source_file=source,
            deployment_config=DEPLOYMENT,
            workload_id="WL-guard",
            source_artifact_id="ART-source",
            run_id="run-1",
            readiness_attempt_id="1",
            readiness_manifest=manifest,
            readiness_policy_digest=policy_digest,
        )
    )

    assert metadata["readiness_source_artifact_id"] == "ART-source"
    assert metadata["readiness_source_checksum"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_conversion_uses_immutable_admitted_source_when_original_mutates(tmp_path: Path) -> None:
    admitted = "proc sql; select 1; quit;\n"
    mutated = "proc sql; select 999; quit;\n"
    source = tmp_path / "qualified.sas"
    source.write_text(admitted, encoding="utf-8")
    manifest, policy_digest = _ready_manifest(tmp_path, source)
    converted_bytes: list[str] = []

    def mutate_during_assessment(path: str) -> dict[str, str]:
        source.write_text(mutated, encoding="utf-8")
        return {"automation_route": "deterministic"}

    def capture_conversion(path: Path, target: str) -> ProviderResult:
        converted_bytes.append(path.read_text(encoding="utf-8"))
        return ProviderResult(content="# generated\n", provider="test")

    with (
        patch("smf.conversion.engine.assess_sas_file", side_effect=mutate_during_assessment),
        patch(
            "smf.conversion.engine.Sas2DatabricksProvider.convert",
            side_effect=capture_conversion,
        ),
    ):
        convert_workload(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                output_dir=tmp_path / "out",
                workload_id="WL-guard",
                source_artifact_id="ART-source",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
                readiness_policy_digest=policy_digest,
            )
        )

    assert converted_bytes == [admitted]


def test_distinct_qualified_identities_with_same_source_name_are_isolated(
    tmp_path: Path,
) -> None:
    first_source = tmp_path / "first" / "same.sas"
    second_source = tmp_path / "second" / "same.sas"
    first_source.parent.mkdir()
    second_source.parent.mkdir()
    first_source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    second_source.write_text("proc sql; select 2; quit;\n", encoding="utf-8")
    first_manifest, _ = _ready_manifest(
        tmp_path / "first-evidence",
        first_source,
        workload_id="WL-1",
        run_id="run-1",
        attempt_id="attempt-1",
    )
    second_manifest, _ = _ready_manifest(
        tmp_path / "second-evidence",
        second_source,
        workload_id="WL-2",
        run_id="run-2",
        attempt_id="attempt-2",
    )
    output_root = tmp_path / "out"

    def request(source: Path, manifest: Path, workload: str, run: str, attempt: str):
        return ConversionRequest(
            source_file=source,
            output_dir=output_root,
            deployment_config=DEPLOYMENT,
            workload_id=workload,
            source_artifact_id="ART-source",
            run_id=run,
            readiness_attempt_id=attempt,
            readiness_manifest=manifest,
        )

    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        patch(
            "smf.conversion.engine.Sas2DatabricksProvider.convert",
            return_value=ProviderResult(content="# generated\n", provider="test"),
        ),
    ):
        first = convert_workload(
            request(first_source, first_manifest, "WL-1", "run-1", "attempt-1")
        )
        second = convert_workload(
            request(second_source, second_manifest, "WL-2", "run-2", "attempt-2")
        )

    first_manifest_path = Path(first.output_files[-1])
    second_manifest_path = Path(second.output_files[-1])
    assert first_manifest_path != second_manifest_path
    assert first_manifest_path.exists() and second_manifest_path.exists()
    first_payload = json.loads(first_manifest_path.read_text(encoding="utf-8"))
    second_payload = json.loads(second_manifest_path.read_text(encoding="utf-8"))
    assert first_payload["metadata"]["readiness_workload_id"] == "WL-1"
    assert second_payload["metadata"]["readiness_workload_id"] == "WL-2"
    assert first_payload["metadata"]["assessment"]["workload_id"] == "WL-1"
    assert second_payload["metadata"]["assessment"]["workload_id"] == "WL-2"


def test_conversion_attempt_output_is_collision_rejecting(tmp_path: Path) -> None:
    source = tmp_path / "same.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    manifest, _ = _ready_manifest(tmp_path / "qualified", source)
    request = ConversionRequest(
        source_file=source,
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        readiness_manifest=manifest,
    )

    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        patch(
            "smf.conversion.engine.Sas2DatabricksProvider.convert",
            return_value=ProviderResult(content="# generated\n", provider="test"),
        ) as provider,
    ):
        first = convert_workload(request)
        first_bytes = Path(first.output_files[-1]).read_bytes()
        with pytest.raises(FileExistsError, match="already exists"):
            convert_workload(request)

    assert provider.call_count == 1
    assert Path(first.output_files[-1]).read_bytes() == first_bytes


def test_deterministic_registry_publishes_bound_evidence_and_recovers_derived_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select count(*) as rows from source.members; quit;\n")
    manifest, policy_digest = _ready_manifest(tmp_path / "qualified", source)
    request = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
        readiness_policy_digest=policy_digest,
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        first = convert_workload(request)
        result_path = next(
            Path(item) for item in first.output_files if item.endswith("manifest.json")
        )
        generated_path = next(Path(item) for item in first.output_files if item.endswith(".sql"))
        telemetry_path = result_path.with_name("conversion.telemetry.json")
        generated_path.unlink()
        telemetry_path.unlink()
        second = convert_workload(request)

    assert first.status == second.status == "converted"
    assert first.metadata["rule_plan"]["workload_id"] == "WL-guard"
    assert first.metadata["rule_plan"]["attempt_id"] == "convert-1"
    assert first.metadata["telemetry"] == {
        "generated": True,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "human_pending": False,
        "human_denied": False,
        "blocked": False,
        "unsupported": False,
        "failed": False,
    }
    assert generated_path.is_file() and telemetry_path.is_file()


def test_temporal_conversion_requires_policy_and_recovers_bound_mapping_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "temporal.sas"
    source.write_text(
        "proc sql; select * from source.members where service_date >= '01JAN1960'd; quit;\n"
    )
    manifest, policy_digest = _ready_manifest(tmp_path / "qualified", source)
    base = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
        readiness_policy_digest=policy_digest,
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        blocked = convert_workload(base)
    assert blocked.status == "blocked"
    assert blocked.metadata["telemetry"]["blocked"] is True
    assert blocked.metadata["telemetry"]["generated"] is False

    authorized = ConversionRequest(
        **{
            **base.__dict__,
            "conversion_attempt_id": "convert-2",
            "temporal_policy": Path("examples/policies/sas-temporal-utc.json"),
        }
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        first = convert_workload(authorized)
        mappings_path = next(
            Path(item) for item in first.output_files if item.endswith("temporal-mappings.json")
        )
        mappings_path.unlink()
        second = convert_workload(authorized)

    assert first.status == second.status == "converted"
    payload = json.loads(mappings_path.read_text())
    mapping = payload["mappings"][0]
    assert mapping["workload_id"] == "WL-guard"
    assert mapping["run_id"] == "run-1"
    assert mapping["attempt_id"] == "convert-2"
    assert mapping["source_artifact_id"] == "ART-source"
    assert mapping["generated_sha256"] == first.metadata["provider_metadata"]["generated_sha256"]

    canonical_mapping_bytes = mappings_path.read_bytes()
    outside_mapping = tmp_path / "outside-temporal-mappings.json"
    outside_mapping.write_bytes(canonical_mapping_bytes)
    mappings_path.unlink()
    mappings_path.symlink_to(outside_mapping)
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        pytest.raises(ValueError, match="symlink|regular file"),
    ):
        convert_workload(authorized)
    mappings_path.unlink()
    mappings_path.write_bytes(canonical_mapping_bytes)

    payload["mappings"][0]["attempt_id"] = "ATT-FORGED"
    mappings_path.write_text(json.dumps(payload))
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        pytest.raises(ValueError, match="mapping evidence mismatch"),
    ):
        convert_workload(authorized)

    forged = {
        **first.metadata["provider_metadata"]["temporal_mappings"][0],
        "approved": True,
    }
    mappings_path.write_text(json.dumps({"mappings": [forged]}))
    result_path = next(
        Path(item) for item in first.output_files if item.endswith("conversion.manifest.json")
    )
    result_payload = json.loads(result_path.read_text())
    result_payload["metadata"]["provider_metadata"]["temporal_mappings"] = [forged]
    result_path.write_text(json.dumps(result_payload))
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        pytest.raises(ValueError, match="mapping fields are malformed"),
    ):
        convert_workload(authorized)


def test_value_conversion_requires_policy_and_recovers_bound_mapping_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "values.sas"
    source.write_text("proc sql; select * from source.members where ' 001.50 '=1; quit;\n")
    manifest, policy_digest = _ready_manifest(
        tmp_path / "qualified-values",
        source,
        workload_id="WL-values",
        run_id="run-values",
    )
    base = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out-values",
        deployment_config=DEPLOYMENT,
        workload_id="WL-values",
        source_artifact_id="ART-source",
        run_id="run-values",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
        readiness_policy_digest=policy_digest,
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        blocked = convert_workload(base)
    assert blocked.status == "blocked"
    assert blocked.metadata["telemetry"]["generated"] is False

    authorized = ConversionRequest(
        **{
            **base.__dict__,
            "conversion_attempt_id": "convert-2",
            "value_compatibility_policy": Path("examples/policies/sas-value-compatibility-v1.json"),
        }
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        first = convert_workload(authorized)
        mappings_path = next(
            Path(item) for item in first.output_files if item.endswith("value-mappings.json")
        )
        mappings_path.unlink()
        second = convert_workload(authorized)

    assert first.status == second.status == "converted"
    mapping = json.loads(mappings_path.read_text())["mappings"][0]
    assert mapping["workload_id"] == "WL-values"
    assert mapping["run_id"] == "run-values"
    assert mapping["attempt_id"] == "convert-2"
    assert mapping["source_artifact_id"] == "ART-source"
    assert mapping["policy_digest"] == first.metadata["rule_plan"]["value_policy_digest"]
    assert mapping["generated_sha256"] == first.metadata["provider_metadata"]["generated_sha256"]

    canonical_mapping_bytes = mappings_path.read_bytes()
    outside_mapping = tmp_path / "outside-value-mappings.json"
    outside_mapping.write_bytes(canonical_mapping_bytes)
    mappings_path.unlink()
    mappings_path.symlink_to(outside_mapping)
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        pytest.raises(ValueError, match="symlink|regular file"),
    ):
        convert_workload(authorized)
    mappings_path.unlink()
    mappings_path.write_bytes(canonical_mapping_bytes)

    payload = json.loads(mappings_path.read_text())
    payload["mappings"][0]["approved"] = True
    mappings_path.write_text(json.dumps(payload))
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        pytest.raises(ValueError, match="mapping evidence mismatch"),
    ):
        convert_workload(authorized)


def test_deterministic_same_attempt_concurrency_invokes_transform_once(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n")
    manifest, _ = _ready_manifest(tmp_path / "qualified", source)
    request = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
    )
    count = 0
    count_lock = threading.Lock()

    def counted(*args, **kwargs):
        nonlocal count
        with count_lock:
            count += 1
        return execute_registry_plan(*args, **kwargs)

    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        patch("smf.conversion.engine.execute_plan", side_effect=counted),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        results = list(pool.map(lambda _: convert_workload(request), range(2)))

    assert count == 1
    assert (
        results[0].metadata["rule_plan"]["plan_id"] == results[1].metadata["rule_plan"]["plan_id"]
    )


def test_deterministic_exception_is_terminal_sanitized_and_not_retried(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n")
    manifest, _ = _ready_manifest(tmp_path / "qualified", source)
    request = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
    )
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        patch(
            "smf.conversion.engine.execute_plan",
            side_effect=RuntimeError("secret-canary-provider-diagnostic"),
        ) as provider,
    ):
        first = convert_workload(request)
        second = convert_workload(request)

    assert first.status == second.status == "failed"
    assert provider.call_count == 1
    manifest_path = next(
        Path(item) for item in first.output_files if item.endswith("manifest.json")
    )
    assert "secret-canary-provider-diagnostic" not in manifest_path.read_text()
    assert first.metadata["telemetry"]["generated"] is False
    assert first.metadata["telemetry"]["failed"] is True


def test_deterministic_caller_model_and_output_symlink_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n")
    manifest, _ = _ready_manifest(tmp_path / "qualified", source)
    output_root = tmp_path / "out"
    base = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=output_root,
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
    )
    with (
        patch(
            "smf.conversion.engine.assess_sas_file",
            return_value={"automation_route": "deterministic"},
        ),
        patch("smf.conversion.engine.execute_plan") as provider,
        pytest.raises(ValueError, match="does not accept a model"),
    ):
        convert_workload(ConversionRequest(**{**base.__dict__, "model": "caller-authority"}))
    provider.assert_not_called()

    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-output"
    linked_root.symlink_to(outside, target_is_directory=True)
    with (
        patch("smf.conversion.engine.execute_plan") as provider,
        pytest.raises(ValueError, match="symlink|non-directory"),
    ):
        convert_workload(ConversionRequest(**{**base.__dict__, "output_dir": linked_root}))
    provider.assert_not_called()

    output_root.mkdir()
    (output_root / "runs").symlink_to(outside, target_is_directory=True)
    with (
        patch("smf.conversion.engine.execute_plan") as provider,
        pytest.raises(ValueError, match="escapes"),
    ):
        convert_workload(base)
    provider.assert_not_called()


def test_forged_generated_telemetry_cannot_survive_deterministic_replay(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n")
    manifest, _ = _ready_manifest(tmp_path / "qualified", source)
    request = ConversionRequest(
        source_file=source,
        target="sparksql",
        provider="deterministic",
        output_dir=tmp_path / "out",
        deployment_config=DEPLOYMENT,
        workload_id="WL-guard",
        source_artifact_id="ART-source",
        run_id="run-1",
        readiness_attempt_id="1",
        conversion_attempt_id="convert-1",
        readiness_manifest=manifest,
    )
    with patch(
        "smf.conversion.engine.assess_sas_file",
        return_value={"automation_route": "deterministic"},
    ):
        result = convert_workload(request)
        result_path = next(
            Path(item) for item in result.output_files if item.endswith("manifest.json")
        )
        payload = json.loads(result_path.read_text())
        payload["metadata"]["telemetry"]["parity_passed"] = True
        result_path.write_text(json.dumps(payload))
        with pytest.raises(ValueError, match="telemetry claim"):
            convert_workload(request)


def test_boundary_manifest_cannot_admit_artifact_from_another_boundary(tmp_path: Path) -> None:
    source = tmp_path / "qualified.sas"
    source.write_text("proc sql; select 1; quit;\n", encoding="utf-8")
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    workload = {
        "workload_id": "WL-guard",
        "artifacts": [
            {
                "artifact_id": artifact_id,
                "kind": "sas_program",
                "checksum": checksum,
                "evidence": [
                    {
                        "evidence_id": f"DISC-{artifact_id}",
                        "method": "filesystem",
                        "source": "canonical-discovery",
                        "confidence": "high",
                    }
                ],
            }
            for artifact_id in ("ART-a", "ART-b")
        ],
        "datasets": [],
        "relationships": [],
        "external_dependencies": [],
        "dependency_graph": {"graph_id": "GRAPH-guard", "unresolved": []},
        "outputs": [],
        "boundaries": [
            {"boundary_id": "BND-a", "artifact_ids": ["ART-a"]},
            {"boundary_id": "BND-b", "artifact_ids": ["ART-b"]},
        ],
        "macro_analysis": {
            "analysis_id": "pending",
            "discovery_id": "pending",
            "workload_id": "WL-guard",
            "strategy_id": STRATEGY_ID,
            "strategy_version": STRATEGY_VERSION,
            "strategy_digest": STRATEGY_DIGEST,
            "strategy_snapshot": strategy_snapshot(),
            "expansion_mode": "none",
            "complete": True,
            "source_inventory": [
                {"source_artifact_id": artifact_id, "source_checksum": checksum}
                for artifact_id in ("ART-a", "ART-b")
            ],
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
            "workload": "WL-guard",
            "inventory": macro["source_inventory"],
            "strategy": STRATEGY_DIGEST,
        },
    )
    macro["analysis_id"] = stable_id(
        "MAN",
        {
            "discovery": macro["discovery_id"],
            "workload": "WL-guard",
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
    observed_at = datetime.now(UTC).isoformat()
    evidence = [
        {
            "evidence_id": "EV-discovery",
            "workload_id": "WL-guard",
            "subject_id": "WL-guard",
            "kind": "discovery_snapshot",
            "status": "pass",
            "workload_digest": digest_value(workload),
            "snapshot_uri": "evidence://discovery/WL-guard/DISCOVERY-RUN-boundary",
            "observed_at": observed_at,
            "authority": "smf-discovery-service",
            "acquisition_source": "governed-discovery-store",
            "execution_id": "DISCOVERY-RUN-boundary",
        },
        {
            "evidence_id": "EV-assessment-a",
            "workload_id": "WL-guard",
            "subject_id": "ART-a",
            "kind": "assessment",
            "status": "pass",
            "source_checksum": checksum,
            "complexity": "simple",
            "risk_factors": [],
            "unsupported_constructs": [],
            "observed_at": observed_at,
            "authority": "humana-assessment-service",
            "acquisition_source": "governed-assessment-store",
            "execution_id": "ASSESS-RUN-a",
        },
        *[
            {
                "evidence_id": f"EV-{check_id}",
                "workload_id": "WL-guard",
                "subject_id": "WL-guard",
                "kind": kind,
                "status": "pass",
                "check_id": check_id,
                "observed_at": observed_at,
                "authority": "humana-platform-control-plane",
                "acquisition_source": "readiness-evidence-adapter",
                "execution_id": f"CHECK-RUN-{check_id}",
            }
            for kind, check_id in (
                ("environment", "target_workspace_access"),
                ("environment", "governed_catalog_access"),
                ("runtime", "target_runtime_compatible"),
            )
        ],
    ]
    policy = load_readiness_policy(POLICY)
    result = evaluate_readiness(
        ReadinessRequest(
            workload=workload,
            evidence=attest_evidence(evidence),
            run_id="run-1",
            attempt_id="1",
            boundary_id="BND-a",
        ),
        policy,
    )
    manifest = write_manifest(tmp_path / "evidence", result)

    with pytest.raises(ValueError, match="readiness boundary"):
        _admit_conversion(
            ConversionRequest(
                source_file=source,
                deployment_config=DEPLOYMENT,
                workload_id="WL-guard",
                source_artifact_id="ART-b",
                run_id="run-1",
                readiness_attempt_id="1",
                readiness_manifest=manifest,
                readiness_policy_digest=policy.policy_digest,
            )
        )
