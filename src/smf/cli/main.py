import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn, cast

from smf.ai_gateway import (
    GatewayPreflightRequest,
    evaluate_gateway_preflight,
    publish_gateway_preflight,
    recover_gateway_preflight,
)
from smf.architecture_review import ArchitectureReviewRequest, assemble_packet, write_packet
from smf.assessment.analyzer import assess_sas_file
from smf.baseline import (
    AcquisitionMode,
    BaselineAcquisitionRequest,
    evaluate_baseline_acquisition,
    load_baseline_policy,
    write_baseline_result,
)
from smf.conversion import ConversionRequest, convert_workload
from smf.deployment import (
    EnvironmentPlanRequest,
    evaluate_environment_plan,
    initialize_deployment_template,
    preflight_deployment,
    publish_environment_plan,
    recover_environment_plan,
)
from smf.discovery import SUPPORTED_PROVIDERS, discover_source
from smf.execution import ExecutionRequest, execute_validation
from smf.intake import (
    IntakeRequest,
    evaluate_batch_intake,
    load_intake_policy,
    write_intake_result,
)
from smf.migration_contract import (
    MigrationCommand,
    MigrationContractRequest,
    evaluate_migration_contract,
    publish_result,
    recover_missing_telemetry,
)
from smf.pilot import (
    PilotSelectionRequest,
    evaluate_pilot_selection,
    load_pilot_policy,
)
from smf.pilot import (
    load_manifest as load_pilot_manifest,
)
from smf.pilot import (
    write_manifest as write_pilot_manifest,
)
from smf.provenance import (
    load_provenance_policy,
    publish_provenance_chain,
    verify_provenance_chain,
)
from smf.readiness import (
    ReadinessRequest,
    evaluate_readiness,
    load_readiness_policy,
)
from smf.readiness import (
    load_manifest as load_readiness_manifest,
)
from smf.readiness import (
    write_manifest as write_readiness_manifest,
)
from smf.readiness.schema import validate_input_schema
from smf.upstream import (
    UpstreamQualificationRequest,
    load_qualification_result,
    load_upstream_inventory,
    load_upstream_policy,
    qualify_upstreams,
    write_qualification_result,
)
from smf.validation import (
    StructuralParityPolicy,
    StructuralParityRequest,
    ValidationRequest,
    compare_structural_schema,
    load_policy,
    load_snapshot,
    validate_conversion,
)

CommandHandler = Callable[[argparse.Namespace], int]


class _SMFArgumentParser(argparse.ArgumentParser):
    """Preserve legacy argparse exits while making new contract usage failures exit 1."""

    _contract_parse = False

    def parse_args(  # type: ignore[override]
        self, args: list[str] | None = None, namespace: argparse.Namespace | None = None
    ) -> argparse.Namespace:
        tokens = args if args is not None else sys.argv[1:]
        type(self)._contract_parse = bool(
            tokens
            and (
                tokens[0] in {"migrate", "ai-gateway"}
                or tokens[:2] == ["deployment-config", "plan"]
            )
        )
        return super().parse_args(args, namespace)

    def error(self, message: str) -> NoReturn:
        if self._contract_parse:
            self.print_usage(sys.stderr)
            self.exit(1, f"{self.prog}: error: {message}\n")
        super().error(message)


def _migration_command(args: argparse.Namespace) -> MigrationCommand:
    command = cast(str, args.command)
    if command == "ai-gateway":
        return MigrationCommand.AI_GATEWAY_PREFLIGHT
    operation = cast(str, args.migrate_command)
    if operation == "exceptions":
        operation = f"exceptions.{cast(str, args.exceptions_command)}"
    return MigrationCommand(operation)


def run_migration_contract(args: argparse.Namespace) -> int:
    try:
        command = _migration_command(args)
        if command is MigrationCommand.AI_GATEWAY_PREFLIGHT:
            gateway_request = GatewayPreflightRequest(
                factory_config_path=Path(cast(str, args.factory_config)),
                gateway_config_path=Path(cast(str, args.gateway_config)),
                output_root=Path(cast(str, args.out)),
                run_id=cast(str, args.run_id),
                attempt_id=cast(str | None, args.attempt_id),
                workload_id=cast(str, args.workload_id),
                evaluation_time=cast(str, args.evaluation_time),
            )
            gateway_prepared = recover_gateway_preflight(
                gateway_request
            ) or evaluate_gateway_preflight(gateway_request)
            result_path, telemetry_path = publish_gateway_preflight(
                gateway_request, gateway_prepared
            )
            summary = {
                "result_path": str(result_path),
                "telemetry_path": str(telemetry_path),
                "result_id": gateway_prepared.result["result_id"],
                "status": gateway_prepared.result["status"],
                "terminal_disposition": gateway_prepared.result["terminal_disposition"],
                "blockers": gateway_prepared.result["blockers"],
                "claims": gateway_prepared.result["claims"],
            }
            print(json.dumps(summary, indent=2))
            return 2
        role_paths: list[tuple[str, Path]] = []
        for role, attribute in (
            ("gateway_configuration", "gateway_config"),
            ("asset_policy", "asset_policy"),
            ("type_policy", "type_policy"),
            ("validation_policy", "validation_policy"),
            ("modernization_policy", "modernization_policy"),
            ("exception_request", "exception_file"),
            ("exception_decision", "decision_file"),
            ("approval_evidence", "approval_file"),
            ("promotion_approval", "promotion_approval"),
        ):
            value = getattr(args, attribute, None)
            if value is not None:
                role_paths.append((role, Path(cast(str, value))))
        action_target: str | None = getattr(args, "from_checkpoint", None)
        action_target = cast(str | None, getattr(args, "stage", None) or action_target)
        approval_record = getattr(args, "approval_record", None)
        if approval_record is not None:
            action_target = f"{action_target}-{cast(str, approval_record)}"
        action_target = cast(str | None, getattr(args, "target", None) or action_target)
        request = MigrationContractRequest(
            command=command,
            run_id=cast(str, args.run_id),
            attempt_id=cast(str | None, getattr(args, "attempt_id", None)),
            output_root=Path(cast(str, args.out)),
            workload_id=cast(str | None, getattr(args, "workload_id", None)),
            source_root=(
                Path(cast(str, args.source_root)) if getattr(args, "source_root", None) else None
            ),
            workload_config=(
                Path(cast(str, args.workload_config))
                if getattr(args, "workload_config", None)
                else None
            ),
            factory_config=(
                Path(cast(str, args.factory_config))
                if getattr(args, "factory_config", None)
                else None
            ),
            role_paths=tuple(role_paths),
            action_target=action_target,
        )
        prepared = recover_missing_telemetry(request) or evaluate_migration_contract(request)
        result_path, telemetry_path = publish_result(
            request.output_root, prepared.result, prepared.telemetry
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    summary = {
        "result_path": str(result_path),
        "telemetry_path": str(telemetry_path),
        "result_id": prepared.result["result_id"],
        "decision_id": prepared.result["decision_id"],
        "status": prepared.result["status"],
        "terminal_disposition": prepared.result["terminal_disposition"],
        "blockers": prepared.result["blockers"],
        "lifecycle": prepared.result["lifecycle"],
    }
    print(json.dumps(summary, indent=2))
    return 2


def run_qualify_upstream(args: argparse.Namespace) -> int:
    try:
        policy_path = Path(cast(str, args.policy))
        inventory_path = Path(cast(str, args.inventory))
        evidence_root = Path(cast(str, args.evidence_root))
        output_root = Path(cast(str, args.out))
        scope_id = cast(str, args.scope_id)
        run_id = cast(str, args.run_id)
        attempt_id = cast(str, args.attempt_id)
        policy = load_upstream_policy(policy_path)
        inventory = load_upstream_inventory(inventory_path)
        canonical_path = (
            output_root
            / "runs"
            / run_id
            / "upstream"
            / scope_id
            / "attempts"
            / attempt_id
            / "qualification.result.json"
        )
        if canonical_path.exists():
            result = load_qualification_result(
                canonical_path,
                output_root=output_root,
                evidence_root=evidence_root,
                trusted_policy=policy,
                trusted_inventory=inventory,
            )
            if result["evaluation_time"] != cast(str, args.evaluation_time):
                raise ValueError("Conflicting evaluation time for immutable qualification attempt")
        else:
            result = qualify_upstreams(
                UpstreamQualificationRequest(
                    policy_path=policy_path,
                    inventory_path=inventory_path,
                    evidence_root=evidence_root,
                    output_root=output_root,
                    scope_id=scope_id,
                    run_id=run_id,
                    attempt_id=attempt_id,
                    evaluation_time=cast(str, args.evaluation_time),
                    signing_key_path=Path(cast(str, args.signing_key)),
                    signing_key_id=cast(str, args.signing_key_id),
                    signing_authority=cast(str, args.signing_authority),
                )
            )
        path = write_qualification_result(
            output_root,
            result,
            evidence_root=evidence_root,
            trusted_policy=policy,
            trusted_inventory=inventory,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "result_path": str(path),
                "result_id": result["result_id"],
                "decision_id": result["decision_id"],
                "outcome": result["outcome"],
                "qualified_count": sum(
                    item["outcome"] == "qualified" for item in result["decisions"]
                ),
                "blocked_count": sum(
                    item["outcome"] != "qualified" for item in result["decisions"]
                ),
                "authorizes_execution": False,
                "human_approved": False,
            },
            indent=2,
        )
    )
    return 0 if result["outcome"] == "qualified" else 2


def run_acquire_baseline(args: argparse.Namespace) -> int:
    try:
        output_root = Path(cast(str, args.out))
        policy_path = Path(cast(str, args.policy))
        request = BaselineAcquisitionRequest(
            acquisition_id=cast(str, args.acquisition_id),
            mode=cast(str, args.mode),
            policy_path=policy_path,
            intake_result_path=Path(cast(str, args.intake_result)),
            intake_policy=load_intake_policy(Path(cast(str, args.intake_policy))),
            package_root=(Path(cast(str, args.package_root)) if args.package_root else None),
            receipt_path=(Path(cast(str, args.receipt)) if args.receipt else None),
            approval_path=(Path(cast(str, args.approval)) if args.approval else None),
            output_root=output_root,
            workload_id=cast(str, args.workload_id),
            workload_revision_id=cast(str, args.workload_revision_id),
            closure_digest=cast(str, args.closure_digest),
            boundary_id=cast(str, args.boundary_id),
            run_id=cast(str, args.run_id),
            attempt_id=cast(str, args.attempt_id),
        )
        prepared = evaluate_baseline_acquisition(request)
        path = write_baseline_result(
            output_root,
            prepared,
            trusted_policy=load_baseline_policy(policy_path),
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    result = prepared.result
    summary = {
        "result_path": str(path),
        "baseline_result_id": result["baseline_result_id"],
        "acquisition_id": result["acquisition_id"],
        "disposition": result["disposition"],
        "baseline_acquired": result["claims"]["baseline_acquired"],
        "generated": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "blockers": result["blockers"],
    }
    print(json.dumps(summary, indent=2))
    return 0 if result["disposition"] == "acquired" else 2


def run_batch_intake(args: argparse.Namespace) -> int:
    try:
        manifest = json.loads(Path(cast(str, args.manifest)).read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Batch intake manifest must be an object")
        policy = load_intake_policy(Path(cast(str, args.policy)))
        output_root = Path(cast(str, args.out))
        result = evaluate_batch_intake(
            IntakeRequest(
                manifest=manifest,
                policy=policy,
                source_root=Path(cast(str, args.source_root)),
                output_root=output_root,
                run_id=cast(str, args.run_id),
                attempt_id=cast(str, args.attempt_id),
            )
        )
        path = write_intake_result(output_root, result, trusted_policy=policy)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    summary = {
        "result_path": str(path),
        "result_id": result["result_id"],
        "batch_revision_id": result["batch_revision_id"],
        "disposition": result["disposition"],
        "expected_script_count": result["expected_script_count"],
        "observed_unique_script_count": result["observed_unique_script_count"],
        "admitted_count": result["admitted_count"],
        "blocked_count": result["blocked_count"],
        "authorizes_execution": False,
        "authorizes_parity": False,
    }
    print(json.dumps(summary if cast(bool, args.json) else summary, indent=2))
    return 0 if result["disposition"] == "admitted" else 2


def run_architecture_review(args: argparse.Namespace) -> int:
    try:
        request = ArchitectureReviewRequest(
            repo_root=Path(cast(str, args.repo_root)),
            factory_config=Path(cast(str, args.factory_config)),
            threat_model=Path(cast(str, args.threat_model)),
            requirements=Path(cast(str, args.requirements)),
            source=Path(cast(str, args.source)),
            discovery_manifest=Path(cast(str, args.discovery_manifest)),
            workload_id=cast(str, args.workload_id),
            subject_id=cast(str, args.subject_id),
            boundary_id=cast(str, args.boundary_id),
            run_id=cast(str, args.run_id),
            attempt_id=cast(str, args.attempt_id),
            assessed_revision=cast(str, args.assessed_revision),
            readiness_manifest=(
                Path(cast(str, args.readiness_manifest)) if args.readiness_manifest else None
            ),
            discovery_namespace=cast(str, args.discovery_namespace),
            security_policy=(
                Path(cast(str, args.security_policy)) if args.security_policy else None
            ),
            security_bindings=(
                Path(cast(str, args.security_bindings)) if args.security_bindings else None
            ),
            activation_evidence=(
                Path(cast(str, args.activation_evidence)) if args.activation_evidence else None
            ),
            disclosure_evidence=(
                Path(cast(str, args.disclosure_evidence)) if args.disclosure_evidence else None
            ),
            recipient_class=cast(str | None, args.recipient_class),
            disclosure_policy_revision=cast(str | None, args.disclosure_policy_revision),
            retention_policy_ref=cast(str | None, args.retention_policy_ref),
        )
        packet = assemble_packet(request)
        path = write_packet(Path(cast(str, args.out)), packet)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    result = {
        "packet_path": str(path),
        "packet_id": packet["packet_id"],
        "terminal_disposition": packet["terminal_disposition"],
        "shared_projection_published": path.with_name("packet.shared.json").exists(),
        "authorizes_execution": False,
    }
    print(json.dumps(result, indent=2))
    return 0 if packet["terminal_disposition"] == "review_ready" else 2


def run_deployment_config_init(args: argparse.Namespace) -> int:
    try:
        paths = initialize_deployment_template(cast(str, args.template), Path(cast(str, args.out)))
        snapshot = preflight_deployment(paths[0])
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    payload = {
        "status": "template_generated",
        "files": [str(path) for path in paths],
        "configuration_digest": snapshot.configuration_digest,
        "bundle_digest": snapshot.bundle_digest,
        "deployment_performed": False,
    }
    print(json.dumps(payload, indent=2))
    return 0


def run_deployment_config_preflight(args: argparse.Namespace) -> int:
    try:
        result = preflight_deployment(
            Path(cast(str, args.config)),
            Path(cast(str, args.readiness_manifest)) if args.readiness_manifest else None,
            workload_id=cast(str | None, args.workload_id),
            run_id=cast(str | None, args.run_id),
            attempt_id=cast(str | None, args.attempt_id),
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status == "qualified" else 2


def run_deployment_config_plan(args: argparse.Namespace) -> int:
    """Publish a deterministic offline environment plan without contacting providers."""

    try:
        request = EnvironmentPlanRequest(
            factory_config_path=Path(cast(str, args.config)),
            environment_config_path=Path(cast(str, args.environment_config)),
            output_root=Path(cast(str, args.out)),
            run_id=cast(str, args.run_id),
            attempt_id=cast(str, args.attempt_id),
        )
        prepared = recover_environment_plan(request) or evaluate_environment_plan(request)
        result_path, telemetry_path = publish_environment_plan(request, prepared)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    summary = {
        "plan_id": prepared.result["plan_id"],
        "status": prepared.result["status"],
        "terminal_disposition": prepared.result["terminal_disposition"],
        "blockers": prepared.result["blockers"],
        "result_path": str(result_path),
        "telemetry_path": str(telemetry_path),
        "claims": prepared.result["claims"],
    }
    print(json.dumps(summary, indent=2))
    return 0 if prepared.result["status"] == "complete" else 2


def _publish_immutable_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically publish canonical discovery bytes without overwriting evidence."""

    serialized = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == serialized:
            return
        raise FileExistsError(f"Discovery output already exists with different content: {path}")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            if path.read_bytes() != serialized:
                raise FileExistsError(
                    f"Discovery output already exists with different content: {path}"
                ) from None
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _print_assessment_explanation(result: dict[str, Any]) -> None:
    print()
    print("Assessment Explanation")
    print("=" * 40)

    breakdown = cast(list[dict[str, Any]], result["score_breakdown"])
    if breakdown:
        for item in breakdown:
            points = cast(int, item["points"])
            reason = cast(str, item["reason"])
            print(f"+{points:<3} {reason}")
    else:
        print("No complexity signals detected")

    print("-" * 40)
    print(f"Score:                  {result['complexity_score']}")
    print(f"Complexity:             {result['complexity']}")
    print(f"Route:                  {result['automation_route']}")
    print(f"Validation Level:       {result['recommended_validation_level']}")

    risk_factors = cast(list[str], result["risk_factors"])
    print()
    print("Risk Factors:")
    if risk_factors:
        for factor in risk_factors:
            print(f"  - {factor}")
    else:
        print("  None")


def run_discover(args: argparse.Namespace) -> int:
    source = Path(cast(str, args.source))
    provider = cast(str, args.provider)
    namespace = cast(str, args.namespace)

    try:
        result = discover_source(source, provider=provider, namespace=namespace)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output = cast(str | None, args.out)
    if output:
        output_path = Path(output)
        try:
            _publish_immutable_json(output_path, result.to_dict())
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if cast(bool, args.json):
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print()
    print("SAS Modernization Factory - Discovery")
    print("=" * 48)
    print(f"Source:                 {result.source}")
    print(f"Provider:               {result.provider}")
    print(f"Candidate Workloads:    {len(result.workloads)}")
    print(f"Artifacts:              {result.artifact_count}")
    print(f"Datasets:               {result.dataset_count}")
    print(f"Relationships:          {result.relationship_count}")
    print(f"Unclassified:           {result.unclassified_count}")

    if output:
        print(f"Discovery Model:        {output}")

    if result.workloads:
        workload = result.workloads[0]
        counts: dict[str, int] = {}
        for artifact in workload.artifacts:
            counts[artifact.kind.value] = counts.get(artifact.kind.value, 0) + 1

        print()
        print("Artifact Classification:")
        for kind, count in sorted(counts.items()):
            print(f"  {kind:<24} {count}")

    print()
    return 0


def run_assess(args: argparse.Namespace) -> int:
    try:
        result: dict[str, Any] = assess_sas_file(cast(str, args.file))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(result, indent=2))
        return 0

    dependencies = cast(dict[str, list[str]], result["dependencies"])

    print()
    print("SAS Modernization Factory")
    print("=" * 40)
    print(f"Workload:               {result['workload_id']}")
    print(f"Source:                 {result['source_file']}")
    print(f"Complexity:             {result['complexity']}")
    print(f"Complexity Score:       {result['complexity_score']}")
    print(f"Route:                  {result['automation_route']}")
    print(f"Confidence:             {result['confidence']:.0%}")
    print(f"Validation Level:       {result['recommended_validation_level']}")
    print(f"Constructs:             {len(result['sas_constructs'])}")
    print(f"Inputs:                 {len(dependencies['inputs'])}")
    print(f"Outputs:                {len(dependencies['outputs'])}")
    print(f"Includes:               {len(dependencies['includes'])}")
    print(f"Risk Factors:           {len(result['risk_factors'])}")
    print(f"Unsupported Constructs: {len(result['unsupported_constructs'])}")

    if cast(bool, args.explain):
        _print_assessment_explanation(result)
    else:
        print()

    return 0


def _conversion_exit_status(status: str) -> int:
    if status in {"converted", "review_required"}:
        return 0
    if status in {"unsupported", "blocked", "human_pending", "human_denied"}:
        return 2
    return 1


def run_convert(args: argparse.Namespace) -> int:
    request = ConversionRequest(
        source_file=Path(cast(str, args.file)),
        target=cast(Any, args.target),
        output_dir=Path(cast(str, args.out)),
        provider=cast(str, args.provider),
        model=cast(str | None, args.model),
        workload_id=cast(str | None, args.workload_id),
        source_artifact_id=cast(str | None, args.source_artifact_id),
        run_id=cast(str | None, args.run_id),
        readiness_attempt_id=cast(str | None, args.readiness_attempt_id),
        conversion_attempt_id=cast(str | None, args.conversion_attempt_id),
        readiness_manifest=(
            Path(cast(str, args.readiness_manifest)) if args.readiness_manifest else None
        ),
        readiness_policy_digest=cast(str | None, args.readiness_policy_digest),
        deployment_config=(
            Path(cast(str, args.deployment_config)) if args.deployment_config else None
        ),
        temporal_policy=(Path(cast(str, args.temporal_policy)) if args.temporal_policy else None),
        value_compatibility_policy=(
            Path(cast(str, args.value_compatibility_policy))
            if args.value_compatibility_policy
            else None
        ),
    )

    try:
        result = convert_workload(request)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(result.to_dict(), indent=2))
        return _conversion_exit_status(result.status)

    print()
    print("SAS Modernization Factory - Conversion")
    print("=" * 48)
    print(f"Source:                 {result.source_file}")
    print(f"Target:                 {result.target}")
    print(f"Route:                  {result.route}")
    print(f"Provider:               {result.provider}")
    print(f"Status:                 {result.status}")
    print(f"Output Files:           {len(result.output_files)}")
    print(f"Warnings:               {len(result.warnings)}")

    if result.output_files:
        print()
        print("Artifacts:")
        for output_file in result.output_files:
            print(f"  - {output_file}")

    if result.warnings:
        print()
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")

    print()
    return _conversion_exit_status(result.status)


def run_ready(args: argparse.Namespace) -> int:
    try:
        discovery = json.loads(Path(cast(str, args.discovery)).read_text(encoding="utf-8"))
        bundle = json.loads(Path(cast(str, args.evidence)).read_text(encoding="utf-8"))
        if not isinstance(discovery, dict) or not isinstance(bundle, dict):
            raise ValueError("Discovery and evidence inputs must be JSON objects")
        workloads = discovery.get("workloads")
        candidates = workloads if isinstance(workloads, list) else [discovery]
        workload_id = cast(str | None, args.workload_id) or bundle.get("workload_id")
        if workload_id is None and len(candidates) == 1:
            workload_id = candidates[0].get("workload_id")
        selected = [item for item in candidates if item.get("workload_id") == workload_id]
        if len(selected) != 1:
            raise ValueError("Select exactly one canonical workload with --workload-id")
        payload = {
            "workload": selected[0],
            "evidence": bundle.get("evidence", []),
            "run_id": cast(str, args.run_id),
            "attempt_id": cast(str, args.attempt_id),
            "boundary_id": cast(str | None, args.boundary_id),
        }
        validate_input_schema(payload)
        policy = load_readiness_policy(Path(cast(str, args.policy)))
        result = evaluate_readiness(
            ReadinessRequest(
                workload=payload["workload"],
                evidence=tuple(payload["evidence"]),
                run_id=payload["run_id"],
                attempt_id=payload["attempt_id"],
                boundary_id=payload["boundary_id"],
                result_root=(
                    Path(cast(str, args.evidence_root)).resolve()
                    if args.evidence_root
                    else Path(cast(str, args.evidence)).resolve().parent
                ),
            ),
            policy,
        )
        path = write_readiness_manifest(Path(cast(str, args.out)), result)
        persisted_result = load_readiness_manifest(path)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(persisted_result, indent=2))
    else:
        print()
        print("SAS Modernization Factory - Workload Readiness")
        print("=" * 52)
        print(f"Workload:               {result.workload_id}")
        print(f"Run / Attempt:          {result.run_id} / {result.attempt_id}")
        print(f"Classification:         {result.classification.value}")
        print(f"Blockers:               {len(result.blockers)}")
        print(f"Missing evidence:       {len(result.missing_evidence)}")
        print(f"Manifest:               {path}")
        print()
    return 0 if persisted_result["classification"] == "READY" else 2


def run_select_pilot(args: argparse.Namespace) -> int:
    """Select a bounded cohort without executing or approving any workload."""
    try:
        inventory_path = Path(cast(str, args.inventory)).resolve()
        raw = json.loads(inventory_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Pilot inventory must be a JSON object")
        policy = load_pilot_policy(Path(cast(str, args.policy)))
        result = evaluate_pilot_selection(
            PilotSelectionRequest(
                inventory=raw,
                policy=policy,
                inventory_root=inventory_path.parent,
                run_id=cast(str, args.run_id),
                attempt_id=cast(str, args.attempt_id),
            )
        )
        path = write_pilot_manifest(
            Path(cast(str, args.out)), result, inventory_root=inventory_path.parent
        )
        persisted = load_pilot_manifest(path, inventory_root=inventory_path.parent)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if cast(bool, args.json):
        print(json.dumps(persisted, indent=2))
    else:
        print()
        print("SAS Modernization Factory - Pilot Selection")
        print("=" * 50)
        print(f"Selection:              {persisted['selection_id']}")
        print(f"Inventory denominator:  {persisted['full_inventory_denominator']}")
        print(
            f"Selected / excluded:    {persisted['selected_count']} / {persisted['excluded_count']}"
        )
        print(f"Disposition:            {persisted['disposition']}")
        print(f"Manifest:               {path}")
        print()
    return 0 if persisted["disposition"] == "qualified" else 2


def _print_validation_checks(result: Any) -> None:
    print()
    print("Validation Checks")
    print("=" * 48)

    for check in result.checks:
        print(f"[{check.status.upper():14}] {check.check_id}  {check.name}")
        print(f"                  {check.message}")


def run_validate(args: argparse.Namespace) -> int:
    request = ValidationRequest(
        source_file=Path(cast(str, args.source)),
        generated_file=Path(cast(str, args.generated)),
        target=cast(str, args.target),
        output_dir=Path(cast(str, args.out)),
        minimum_confidence=cast(float, args.minimum_confidence),
    )

    try:
        result = validate_conversion(request)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print()
    print("SAS Modernization Factory - Validation")
    print("=" * 48)
    print(f"Source:                 {result.source_file}")
    print(f"Generated:              {result.generated_file}")
    print(f"Target:                 {result.target}")
    print(f"Status:                 {result.status}")
    print(f"Confidence:             {result.confidence:.0%}")
    print(f"Human Review:           {result.requires_human_review}")
    print(f"Checks:                 {len(result.checks)}")
    print(f"Warnings:               {len(result.warnings)}")

    if cast(bool, args.explain):
        _print_validation_checks(result)

    if result.output_files:
        print()
        print("Artifacts:")
        for output_file in result.output_files:
            print(f"  - {output_file}")

    print()
    return 1 if result.status == "failed" else 0


def run_execute(args: argparse.Namespace) -> int:
    request = ExecutionRequest(
        source_file=Path(cast(str, args.source)),
        generated_file=Path(cast(str, args.generated)),
        target=cast(str, args.target),
        provider=cast(str, args.provider),
        output_dir=Path(cast(str, args.out)),
        timeout_seconds=cast(int, args.timeout),
        allow_writes=cast(bool, args.allow_writes),
        run_id=cast(str, getattr(args, "run_id", "standalone")),
        attempt_id=cast(str, getattr(args, "attempt_id", "1")),
        workload_id=cast(str | None, getattr(args, "workload_id", None)),
    )

    try:
        result = execute_validation(request)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.status in {"succeeded", "submitted"} else 1

    print()
    print("SAS Modernization Factory - Execution")
    print("=" * 48)
    print(f"Source:                 {result.source_file}")
    print(f"Generated:              {result.generated_file}")
    print(f"Target:                 {result.target}")
    print(f"Provider:               {result.provider}")
    print(f"Status:                 {result.status}")
    print(f"Duration:               {result.duration_seconds:.3f}s")
    print(f"Exit Code:              {result.exit_code}")
    print(f"Run ID:                 {result.run_id}")
    print(f"Workspace:              {result.workspace_host}")
    print(f"Warnings:               {len(result.warnings)}")

    if result.stderr:
        print()
        print("Execution Error / Block Reason:")
        print(result.stderr)

    if result.warnings:
        print()
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")

    if result.output_files:
        print()
        print("Artifacts:")
        for output_file in result.output_files:
            print(f"  - {output_file}")

    print()

    return 0 if result.status in {"succeeded", "submitted"} else 1


def run_verify_provenance(args: argparse.Namespace) -> int:
    """Replay a persisted provenance chain without running producer operations."""

    try:
        evidence_root = Path(cast(str, args.evidence_root))
        source_root = Path(cast(str, args.source_root))
        policy = load_provenance_policy(Path(cast(str, args.policy)))
        chain = verify_provenance_chain(
            Path(cast(str, args.chain)),
            evidence_root=evidence_root,
            source_root=source_root,
            policy=policy,
        )
        output = cast(str | None, args.out)
        projection_path = (
            publish_provenance_chain(
                Path(output),
                chain,
                evidence_root=evidence_root,
                source_root=source_root,
                policy=policy,
            )
            if output is not None
            else None
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    summary = {
        "chain_id": chain["chain_id"],
        "terminal_disposition": chain["terminal_disposition"],
        "telemetry": chain["telemetry"],
        "missing_stages": chain["missing_stages"],
        "projection_path": str(projection_path) if projection_path is not None else None,
        "authorizes_execution": False,
        "authorizes_approval": False,
        "authorizes_certification": False,
    }
    if cast(bool, args.json):
        print(json.dumps(summary, indent=2))
    else:
        print()
        print("SAS Modernization Factory - Provenance Verification")
        print("=" * 56)
        print(f"Chain:                   {chain['chain_id']}")
        print(f"Disposition:             {chain['terminal_disposition']}")
        print(f"Missing stages:          {len(chain['missing_stages'])}")
        print(f"Generated:               {chain['telemetry']['generated']}")
        print(f"Executed:                {chain['telemetry']['executed']}")
        print(f"Validated:               {chain['telemetry']['validated']}")
        print(f"Parity passed:           {chain['telemetry']['parity_passed']}")
        print(f"Human assisted:          {chain['telemetry']['human_assisted']}")
        print(f"Human approved:          {chain['telemetry']['human_approved']}")
        print()
    return 0 if chain["terminal_disposition"] == "validated" else 2


def run_validate_schema(args: argparse.Namespace) -> int:
    try:
        source = load_snapshot(Path(cast(str, args.source_schema)))
        target = load_snapshot(Path(cast(str, args.target_schema)))
        policy_path = cast(str | None, args.policy)
        policy = load_policy(Path(policy_path)) if policy_path else StructuralParityPolicy()
        result = compare_structural_schema(
            StructuralParityRequest(
                source=source,
                target=target,
                policy=policy,
                output_dir=Path(cast(str, args.out)),
            )
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if cast(bool, args.json):
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.status == "passed" else 1

    print()
    print("SAS Modernization Factory - Structural Schema Parity")
    print("=" * 58)
    print(f"Dataset:                {source.logical_dataset_id}")
    print(f"Status:                 {result.status}")
    print(f"Policy:                 {policy.policy_id}@{policy.policy_version}")
    print(f"Checks:                 {len(result.checks)}")
    failures = [check for check in result.checks if check.status != "pass"]
    if failures:
        print()
        print("Blocking diagnostics:")
        for check in failures:
            print(f"  [{check.status.upper()}] {check.code} {check.path}: {check.diagnostic}")
    print()
    print(f"Manifest:               {result.output_files[0]}")
    print()
    return 0 if result.status == "passed" else 1


def _add_run_contract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workload-id", default=None)
    parser.add_argument("--out", default="out")
    parser.add_argument("--json", action="store_true")


def _add_source_contract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", "--source-root", dest="source_root", required=True)
    parser.add_argument("--workload-config", required=True)
    parser.add_argument("--factory-config", required=True)
    parser.add_argument("--gateway-config", required=True)
    parser.add_argument("--asset-policy", required=True)
    parser.add_argument("--type-policy", required=True)
    parser.add_argument("--validation-policy", required=True)
    parser.add_argument("--workload-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--out", default="out")
    parser.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = _SMFArgumentParser(
        prog="smf",
        description="SAS Modernization Factory",
    )

    subparsers = parser.add_subparsers(dest="command")

    migrate_parser = subparsers.add_parser(
        "migrate", help="Emit offline, non-operational migration contract evidence"
    )
    migrate_commands = migrate_parser.add_subparsers(dest="migrate_command")
    migrate_convert = migrate_commands.add_parser(
        "convert", help="Qualify inputs and emit an explicit not-implemented result"
    )
    _add_source_contract_arguments(migrate_convert)
    migrate_convert.set_defaults(func=run_migration_contract)
    migrate_modernize = migrate_commands.add_parser(
        "modernize", help="Qualify inputs and emit an explicit not-implemented result"
    )
    _add_source_contract_arguments(migrate_modernize)
    migrate_modernize.add_argument("--modernization-policy", required=True)
    migrate_modernize.set_defaults(func=run_migration_contract)

    migrate_status = migrate_commands.add_parser(
        "status", help="Emit a blocked run-ledger status contract"
    )
    _add_run_contract_arguments(migrate_status)
    migrate_status.set_defaults(func=run_migration_contract)
    migrate_resume = migrate_commands.add_parser(
        "resume", help="Emit a non-mutating resume contract"
    )
    _add_run_contract_arguments(migrate_resume)
    migrate_resume.add_argument(
        "--from-checkpoint",
        required=True,
        choices=["latest-safe", "approved-modernization-architecture-business-disposition"],
    )
    migrate_resume.add_argument("--factory-config", required=True)
    migrate_resume.set_defaults(func=run_migration_contract)

    exceptions = migrate_commands.add_parser(
        "exceptions", help="Emit non-authorizing exception contract evidence"
    )
    exception_commands = exceptions.add_subparsers(dest="exceptions_command")
    exception_list = exception_commands.add_parser("list", help="List contract boundary")
    _add_run_contract_arguments(exception_list)
    exception_list.set_defaults(func=run_migration_contract)
    exception_submit = exception_commands.add_parser("submit", help="Submit contract boundary")
    _add_run_contract_arguments(exception_submit)
    exception_submit.add_argument("--exception-file", required=True)
    exception_submit.set_defaults(func=run_migration_contract)
    exception_decide = exception_commands.add_parser("decide", help="Decision contract boundary")
    _add_run_contract_arguments(exception_decide)
    exception_decide.add_argument("--decision-file", required=True)
    exception_decide.set_defaults(func=run_migration_contract)

    migrate_approve = migrate_commands.add_parser(
        "approve", help="Emit a non-authorizing approval contract"
    )
    _add_run_contract_arguments(migrate_approve)
    migrate_approve.add_argument(
        "--stage",
        choices=["migration-completion", "modernization-architecture-business-disposition"],
        required=True,
    )
    migrate_approve.add_argument("--approval-record", default=None)
    migrate_approve.add_argument("--approval-file", required=True)
    migrate_approve.set_defaults(func=run_migration_contract)
    migrate_promote = migrate_commands.add_parser(
        "promote", help="Emit a non-mutating promotion contract"
    )
    _add_run_contract_arguments(migrate_promote)
    migrate_promote.add_argument("--target", required=True)
    migrate_promote.add_argument("--promotion-approval", required=True)
    migrate_promote.set_defaults(func=run_migration_contract)

    gateway_parser = subparsers.add_parser(
        "ai-gateway", help="Emit offline AI gateway contract evidence without provider contact"
    )
    gateway_commands = gateway_parser.add_subparsers(dest="ai_gateway_command")
    gateway_preflight = gateway_commands.add_parser(
        "preflight", help="Bind gateway configuration and block before transport"
    )
    gateway_preflight.add_argument("--config", dest="gateway_config", required=True)
    gateway_preflight.add_argument("--factory-config", default="deployments/humana/factory.yaml")
    gateway_preflight.add_argument("--run-id", default="gateway-preflight")
    gateway_preflight.add_argument("--attempt-id", default=None)
    gateway_preflight.add_argument("--workload-id", required=True)
    gateway_preflight.add_argument(
        "--evaluation-time",
        required=True,
        help="Governed RFC 3339 time used for authority freshness evaluation",
    )
    gateway_preflight.add_argument("--out", default="out")
    gateway_preflight.add_argument("--json", action="store_true")
    gateway_preflight.set_defaults(func=run_migration_contract)

    upstream_parser = subparsers.add_parser(
        "upstream", help="Qualify pinned upstream artifacts from offline evidence"
    )
    upstream_commands = upstream_parser.add_subparsers(dest="upstream_command")
    upstream_qualify = upstream_commands.add_parser(
        "qualify", help="Publish signed, non-authorizing upstream qualification evidence"
    )
    upstream_qualify.add_argument("--policy", required=True)
    upstream_qualify.add_argument("--inventory", required=True)
    upstream_qualify.add_argument("--evidence-root", required=True)
    upstream_qualify.add_argument("--scope-id", required=True)
    upstream_qualify.add_argument("--run-id", required=True)
    upstream_qualify.add_argument("--attempt-id", required=True)
    upstream_qualify.add_argument(
        "--evaluation-time",
        required=True,
        help="Bound RFC 3339 time used to evaluate the approved freshness policy",
    )
    upstream_qualify.add_argument("--signing-key", required=True)
    upstream_qualify.add_argument("--signing-key-id", required=True)
    upstream_qualify.add_argument("--signing-authority", required=True)
    upstream_qualify.add_argument("--out", default="out")
    upstream_qualify.add_argument("--json", action="store_true")
    upstream_qualify.set_defaults(func=run_qualify_upstream)

    architecture_parser = subparsers.add_parser(
        "architecture-review", help="Assemble an offline non-authorizing review packet"
    )
    architecture_commands = architecture_parser.add_subparsers(dest="architecture_command")
    architecture_assemble = architecture_commands.add_parser(
        "assemble", help="Assemble and persist immutable architecture/security evidence"
    )
    architecture_assemble.add_argument("source")
    architecture_assemble.add_argument(
        "--discovery-manifest", required=True, help="Canonical discovery JSON to replay and bind"
    )
    architecture_assemble.add_argument("--discovery-namespace", default="default")
    architecture_assemble.add_argument("--repo-root", default=".")
    architecture_assemble.add_argument(
        "--factory-config", default="deployments/humana/factory.yaml"
    )
    architecture_assemble.add_argument(
        "--threat-model", default="docs/architecture/security-threat-model.yaml"
    )
    architecture_assemble.add_argument("--requirements", default="competition/requirements.yaml")
    architecture_assemble.add_argument("--workload-id", required=True)
    architecture_assemble.add_argument("--subject-id", required=True)
    architecture_assemble.add_argument("--boundary-id", required=True)
    architecture_assemble.add_argument("--run-id", required=True)
    architecture_assemble.add_argument("--attempt-id", required=True)
    architecture_assemble.add_argument("--assessed-revision", required=True)
    architecture_assemble.add_argument("--readiness-manifest", default=None)
    architecture_assemble.add_argument("--security-policy", default=None)
    architecture_assemble.add_argument("--security-bindings", default=None)
    architecture_assemble.add_argument("--activation-evidence", default=None)
    architecture_assemble.add_argument("--disclosure-evidence", default=None)
    architecture_assemble.add_argument("--recipient-class", default=None)
    architecture_assemble.add_argument("--disclosure-policy-revision", default=None)
    architecture_assemble.add_argument("--retention-policy-ref", default=None)
    architecture_assemble.add_argument("--out", default="out")
    architecture_assemble.set_defaults(func=run_architecture_review)

    deployment_parser = subparsers.add_parser(
        "deployment-config", help="Generate or preflight offline deployment configuration"
    )
    deployment_commands = deployment_parser.add_subparsers(dest="deployment_command")
    deployment_init = deployment_commands.add_parser(
        "init", help="Generate a deterministic deployment template"
    )
    deployment_init.add_argument("--template", choices=["humana"], required=True)
    deployment_init.add_argument("--out", required=True)
    deployment_init.set_defaults(func=run_deployment_config_init)
    deployment_preflight = deployment_commands.add_parser(
        "preflight", help="Validate bindings without contacting a provider"
    )
    deployment_preflight.add_argument("--config", required=True)
    deployment_preflight.add_argument("--readiness-manifest", default=None)
    deployment_preflight.add_argument("--workload-id", default=None)
    deployment_preflight.add_argument("--run-id", default=None)
    deployment_preflight.add_argument("--attempt-id", default=None)
    deployment_preflight.add_argument("--json", action="store_true")
    deployment_preflight.set_defaults(func=run_deployment_config_preflight)
    deployment_plan = deployment_commands.add_parser(
        "plan", help="Publish a deterministic offline environment plan"
    )
    deployment_plan.add_argument("--config", required=True)
    deployment_plan.add_argument("--environment-config", required=True)
    deployment_plan.add_argument("--out", required=True)
    deployment_plan.add_argument("--run-id", required=True)
    deployment_plan.add_argument("--attempt-id", required=True)
    deployment_plan.add_argument("--json", action="store_true")
    deployment_plan.set_defaults(func=run_deployment_config_plan)

    discover_parser = subparsers.add_parser(
        "discover",
        help="Acquire and inventory SAS estate evidence",
    )
    discover_parser.add_argument(
        "source",
        help="Filesystem source or SAS Content Assessment results directory",
    )
    discover_parser.add_argument(
        "--provider",
        choices=SUPPORTED_PROVIDERS,
        default="auto",
    )
    discover_parser.add_argument("--namespace", default="default")
    discover_parser.add_argument(
        "--out",
        default=None,
        help="Optional path for the serialized discovery model",
    )
    discover_parser.add_argument("--json", action="store_true")
    discover_parser.set_defaults(func=run_discover)

    intake_parser = subparsers.add_parser(
        "intake-batch", help="Admit a signed batch manifest into immutable workload snapshots"
    )
    intake_parser.add_argument("manifest", help="Signed versioned batch manifest JSON")
    intake_parser.add_argument("--policy", required=True, help="Trusted versioned intake policy")
    intake_parser.add_argument("--source-root", required=True, help="Authorized source root")
    intake_parser.add_argument("--run-id", required=True)
    intake_parser.add_argument("--attempt-id", required=True)
    intake_parser.add_argument("--out", default="out")
    intake_parser.add_argument("--json", action="store_true")
    intake_parser.set_defaults(func=run_batch_intake)

    baseline_parser = subparsers.add_parser(
        "acquire-baseline",
        help="Import a cryptographically verified SAS baseline export",
    )
    baseline_parser.add_argument("--acquisition-id", required=True)
    baseline_parser.add_argument(
        "--mode",
        choices=[item.value for item in AcquisitionMode],
        default=AcquisitionMode.APPROVED_EXPORT.value,
    )
    baseline_parser.add_argument("--policy", required=True)
    baseline_parser.add_argument("--intake-result", required=True)
    baseline_parser.add_argument("--intake-policy", required=True)
    baseline_parser.add_argument("--package-root", default=None)
    baseline_parser.add_argument("--receipt", default=None)
    baseline_parser.add_argument("--approval", default=None)
    baseline_parser.add_argument("--workload-id", required=True)
    baseline_parser.add_argument("--workload-revision-id", required=True)
    baseline_parser.add_argument("--closure-digest", required=True)
    baseline_parser.add_argument("--boundary-id", required=True)
    baseline_parser.add_argument("--run-id", required=True)
    baseline_parser.add_argument("--attempt-id", required=True)
    baseline_parser.add_argument("--out", default="out")
    baseline_parser.add_argument("--json", action="store_true")
    baseline_parser.set_defaults(func=run_acquire_baseline)

    assess_parser = subparsers.add_parser("assess", help="Assess a SAS workload")
    assess_parser.add_argument("file", help="Path to the SAS source file")
    assess_parser.add_argument("--json", action="store_true")
    assess_parser.add_argument("--explain", action="store_true")
    assess_parser.set_defaults(func=run_assess)

    convert_parser = subparsers.add_parser(
        "convert",
        help="Convert an assessed SAS workload",
    )
    convert_parser.add_argument("file", help="Path to the SAS source file")
    convert_parser.add_argument(
        "--target",
        choices=["pyspark", "sparksql"],
        default="pyspark",
    )
    convert_parser.add_argument("--out", default="out")
    convert_parser.add_argument("--provider", default="auto")
    convert_parser.add_argument("--model", default=None)
    convert_parser.add_argument("--workload-id", default=None)
    convert_parser.add_argument("--source-artifact-id", default=None)
    convert_parser.add_argument("--run-id", default=None)
    convert_parser.add_argument("--readiness-attempt-id", default=None)
    convert_parser.add_argument(
        "--conversion-attempt-id",
        default=None,
        help="Distinct conversion attempt identity; defaults to the readiness attempt identity",
    )
    convert_parser.add_argument("--readiness-manifest", default=None)
    convert_parser.add_argument("--readiness-policy-digest", default=None)
    convert_parser.add_argument(
        "--deployment-config",
        default=None,
        help="Factory deployment binding; required readiness is enforced automatically",
    )
    convert_parser.add_argument(
        "--temporal-policy",
        default=None,
        help="Explicit versioned SAS date/datetime policy JSON",
    )
    convert_parser.add_argument(
        "--value-compatibility-policy",
        default=None,
        help="Explicit versioned SAS missing-value and implicit-coercion policy JSON",
    )
    convert_parser.add_argument("--json", action="store_true")
    convert_parser.set_defaults(func=run_convert)

    ready_parser = subparsers.add_parser(
        "ready", help="Qualify a canonical workload before conversion"
    )
    ready_parser.add_argument("discovery", help="Canonical discovery JSON")
    ready_parser.add_argument("evidence", help="Readiness evidence bundle JSON")
    ready_parser.add_argument("--policy", required=True, help="Versioned readiness policy")
    ready_parser.add_argument("--run-id", required=True)
    ready_parser.add_argument("--attempt-id", required=True)
    ready_parser.add_argument("--workload-id", default=None)
    ready_parser.add_argument("--boundary-id", default=None)
    ready_parser.add_argument(
        "--evidence-root",
        default=None,
        help="Trusted root for canonical prerequisite and baseline result references",
    )
    ready_parser.add_argument("--out", default="out")
    ready_parser.add_argument("--json", action="store_true")
    ready_parser.set_defaults(func=run_ready)

    pilot_parser = subparsers.add_parser(
        "select-pilot", help="Select a representative pilot cohort from governed offline evidence"
    )
    pilot_parser.add_argument("inventory", help="Versioned canonical pilot inventory JSON")
    pilot_parser.add_argument("--policy", required=True, help="Explicit versioned selection policy")
    pilot_parser.add_argument("--run-id", required=True)
    pilot_parser.add_argument("--attempt-id", required=True)
    pilot_parser.add_argument("--out", default="out")
    pilot_parser.add_argument("--json", action="store_true")
    pilot_parser.set_defaults(func=run_select_pilot)

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a generated Databricks artifact",
    )
    validate_parser.add_argument("source", help="Original SAS source file")
    validate_parser.add_argument("generated", help="Generated artifact")
    validate_parser.add_argument(
        "--target",
        choices=["pyspark", "sparksql"],
        default="pyspark",
    )
    validate_parser.add_argument("--out", default="out")
    validate_parser.add_argument(
        "--minimum-confidence",
        type=float,
        default=0.85,
    )
    validate_parser.add_argument("--explain", action="store_true")
    validate_parser.add_argument("--json", action="store_true")
    validate_parser.set_defaults(func=run_validate)

    schema_parser = subparsers.add_parser(
        "validate-schema",
        help="Compare authoritative source and target schema snapshots",
    )
    schema_parser.add_argument("source_schema", help="Source schema snapshot (JSON or YAML)")
    schema_parser.add_argument("target_schema", help="Target schema snapshot (JSON or YAML)")
    schema_parser.add_argument(
        "--policy",
        default=None,
        help="Versioned structural parity policy (JSON or YAML); defaults to strict",
    )
    schema_parser.add_argument("--out", default="out")
    schema_parser.add_argument("--json", action="store_true")
    schema_parser.set_defaults(func=run_validate_schema)

    execute_parser = subparsers.add_parser(
        "execute",
        help="Execute a validated generated artifact in a validation environment",
    )
    execute_parser.add_argument("source", help="Original SAS source file")
    execute_parser.add_argument("generated", help="Generated artifact")
    execute_parser.add_argument(
        "--target",
        choices=["pyspark", "sparksql"],
        default="pyspark",
    )
    execute_parser.add_argument(
        "--provider",
        choices=["local", "databricks"],
        default="local",
    )
    execute_parser.add_argument("--out", default="out")
    execute_parser.add_argument("--run-id", default="standalone")
    execute_parser.add_argument("--attempt-id", default="1")
    execute_parser.add_argument("--workload-id", default=None)
    execute_parser.add_argument("--timeout", type=int, default=120)
    execute_parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="Request write-enabled execution. Databricks v2 intentionally blocks this.",
    )
    execute_parser.add_argument("--json", action="store_true")
    execute_parser.set_defaults(func=run_execute)

    provenance_parser = subparsers.add_parser(
        "verify-provenance",
        help="Replay a non-authorizing offline provenance chain",
    )
    provenance_parser.add_argument("--chain", required=True)
    provenance_parser.add_argument("--evidence-root", required=True)
    provenance_parser.add_argument("--source-root", required=True)
    provenance_parser.add_argument("--policy", required=True)
    provenance_parser.add_argument(
        "--out",
        default=None,
        help="Optionally recover the canonical chain and telemetry projection",
    )
    provenance_parser.add_argument("--json", action="store_true")
    provenance_parser.set_defaults(func=run_verify_provenance)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 1

    handler = cast(CommandHandler, func)
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
