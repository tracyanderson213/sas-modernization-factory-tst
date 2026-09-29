from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from smf.assessment.analyzer import assess_sas_file
from smf.conversion.manifest import (
    open_lock_file,
    publish_bytes,
    publish_json,
    published_file_exists,
    read_published_bytes,
    read_published_json,
    write_manifest,
)
from smf.conversion.models import ConversionRequest, ConversionResult
from smf.conversion.providers.sas2databricks import Sas2DatabricksProvider
from smf.conversion.registry import PlanDisposition, execute_plan, plan_rules
from smf.conversion.temporal import TemporalPolicy
from smf.conversion.value_semantics import ValueCompatibilityPolicy
from smf.readiness.deployment import load_deployment_readiness
from smf.readiness.manifest import load_manifest
from smf.workload.identity import stable_id


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_temporal_policy(path: Path | None) -> TemporalPolicy | None:
    if path is None:
        return None
    if not path.is_file() or path.is_symlink():
        raise ValueError("Conversion is blocked: temporal policy must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Conversion is blocked: temporal policy is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Conversion is blocked: temporal policy must be an object")
    return TemporalPolicy.from_dict(payload)


def _load_value_policy(path: Path | None) -> ValueCompatibilityPolicy | None:
    if path is None:
        return None
    if not path.is_file() or path.is_symlink():
        raise ValueError("Conversion is blocked: value compatibility policy must be a regular file")
    try:

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            "Conversion is blocked: value compatibility policy is invalid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("Conversion is blocked: value compatibility policy must be an object")
    return ValueCompatibilityPolicy.from_dict(payload)


def _bind_source_artifact(request: ConversionRequest, manifest: dict[str, Any]) -> str:
    artifact_id = request.source_artifact_id
    if artifact_id is None:
        raise ValueError("Conversion is blocked: canonical source artifact identity is incomplete")
    artifacts = manifest["qualification_input"]["workload"]["artifacts"]
    boundary_id = manifest["boundary_id"]
    if boundary_id is not None:
        boundaries = manifest["qualification_input"]["workload"]["boundaries"]
        boundary = next(
            (item for item in boundaries if item.get("boundary_id") == boundary_id), None
        )
        if boundary is None or artifact_id not in boundary.get("artifact_ids", []):
            raise ValueError(
                "Conversion is blocked: source artifact does not belong to readiness boundary"
            )
    matched = [item for item in artifacts if item.get("artifact_id") == artifact_id]
    if len(matched) != 1:
        raise ValueError("Conversion is blocked: source artifact does not belong to workload")
    artifact = matched[0]
    if artifact.get("kind") != "sas_program":
        raise ValueError("Conversion is blocked: source artifact is not a SAS program")
    recorded = artifact.get("checksum")
    if not isinstance(recorded, str):
        raise ValueError("Conversion is blocked: source artifact checksum is absent")
    if len(recorded) != 64 or any(character not in "0123456789abcdef" for character in recorded):
        raise ValueError("Conversion is blocked: source artifact checksum is not canonical SHA-256")
    actual = _sha256(request.source_file)
    if not hmac.compare_digest(actual, recorded):
        raise ValueError("Conversion is blocked: source file checksum does not match artifact")
    return recorded


def _admit_conversion(request: ConversionRequest) -> dict[str, Any]:
    if request.deployment_config is None:
        raise ValueError(
            "Conversion is blocked: an authoritative deployment readiness binding is required"
        )
    binding = load_deployment_readiness(request.deployment_config)
    if not binding.required:
        raise ValueError("Conversion is blocked: deployment does not require readiness")
    bound_digest = binding.policy.policy_digest
    if (
        bound_digest is not None
        and request.readiness_policy_digest is not None
        and request.readiness_policy_digest != bound_digest
    ):
        raise ValueError("Conversion is blocked: requested policy differs from deployment binding")
    expected_policy_digest = bound_digest
    if request.readiness_manifest is None:
        raise ValueError("Conversion is blocked: a readiness manifest is required")
    manifest = load_manifest(request.readiness_manifest)
    expected = {
        "workload_id": request.workload_id,
        "run_id": request.run_id,
        "attempt_id": request.readiness_attempt_id,
    }
    if any(value is None for value in expected.values()):
        raise ValueError("Conversion is blocked: canonical readiness identity is incomplete")
    for field, value in expected.items():
        if manifest[field] != value:
            raise ValueError(f"Conversion is blocked: readiness {field} mismatch")
    if manifest["classification"] != "READY":
        raise ValueError(
            f"Conversion is blocked: readiness classification is {manifest['classification']}"
        )
    if expected_policy_digest is None:
        raise ValueError("Conversion is blocked: an authoritative readiness policy is required")
    if manifest["policy_digest"] != expected_policy_digest:
        raise ValueError("Conversion is blocked: readiness policy is stale or mismatched")
    valid_until = manifest["valid_until"]
    if valid_until is not None:
        expires = datetime.fromisoformat(str(valid_until).replace("Z", "+00:00"))
        if expires.tzinfo is None or datetime.now(UTC) > expires.astimezone(UTC):
            raise ValueError("Conversion is blocked: readiness evidence has expired")
    source_checksum = _bind_source_artifact(request, manifest)
    macro_analysis = manifest["qualification_input"]["workload"].get("macro_analysis")
    if not isinstance(macro_analysis, dict):
        raise ValueError("Conversion is blocked: canonical macro analysis is absent")
    macro_dependent_kinds = {
        "definition",
        "literal_invocation",
        "dynamic_invocation",
        "variable_definition",
        "variable_reference",
        "include_reference",
        "intrinsic_operation",
        "quoting_operation",
    }
    observations = macro_analysis.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("Conversion is blocked: canonical macro observations are malformed")
    macro_dependent = any(
        isinstance(item, dict) and item.get("kind") in macro_dependent_kinds
        for item in observations
    )
    return {
        "readiness_result_id": manifest["result_id"],
        "readiness_workload_id": manifest["workload_id"],
        "readiness_run_id": manifest["run_id"],
        "readiness_attempt_id": manifest["attempt_id"],
        "readiness_boundary_id": manifest["boundary_id"],
        "readiness_policy_digest": manifest["policy_digest"],
        "readiness_source_artifact_id": request.source_artifact_id,
        "readiness_source_checksum": source_checksum,
        "macro_analysis_id": macro_analysis.get("analysis_id"),
        "macro_strategy_digest": macro_analysis.get("strategy_digest"),
        "macro_dependent": macro_dependent,
        "client_id": binding.client_id,
        "deployment_id": binding.deployment_id,
        "environment_id": binding.environment_id,
        "deployment_configuration_digest": binding.configuration_digest,
    }


def _route_from_assessment(assessment: dict[str, Any]) -> str:
    route = str(assessment.get("automation_route", "human_supervised"))
    if route not in {"deterministic", "ai_assisted", "human_supervised"}:
        return "human_supervised"
    return route


def _provider_requires_review(provider_metadata: dict[str, Any]) -> bool:
    summary = provider_metadata.get("summary", {})
    if not isinstance(summary, dict):
        return False

    review_count = summary.get("review", 0)
    try:
        return int(review_count) > 0
    except (TypeError, ValueError):
        return False


def _report_assessment_source(
    assessment: dict[str, Any], source: Path, workload_id: str
) -> dict[str, Any]:
    """Bind snapshot assessment output to the admitted canonical workload."""

    normalized = dict(assessment)
    normalized["source_file"] = str(source)
    normalized["workload_id"] = workload_id
    return normalized


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _component(value: Any, label: str) -> str:
    if not isinstance(value, str) or value in {".", ".."} or not _SAFE_COMPONENT.fullmatch(value):
        raise ValueError(f"Conversion is blocked: unsafe {label}")
    return value


def _conversion_output_dir(request: ConversionRequest) -> Path:
    attempt_id = request.conversion_attempt_id or request.readiness_attempt_id
    output_root = request.output_dir.resolve()
    candidate = (
        request.output_dir
        / "runs"
        / _component(request.run_id, "run_id")
        / "workloads"
        / _component(request.workload_id, "workload_id")
        / "attempts"
        / _component(attempt_id, "conversion_attempt_id")
        / "conversion"
        / _component(request.source_artifact_id, "source_artifact_id")
    )
    relative = candidate.relative_to(request.output_dir)
    if any(
        request.output_dir.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ) or not candidate.resolve().is_relative_to(output_root):
        raise ValueError("Conversion is blocked: output path escapes the configured root")
    return candidate


def convert_workload(request: ConversionRequest) -> ConversionResult:
    if request.target not in {"pyspark", "sparksql"}:
        raise ValueError("Conversion is blocked: unsupported target")
    if request.provider not in {"auto", "deterministic", "sas2databricks"}:
        raise ValueError("Conversion is blocked: unsupported provider")
    source = request.source_file
    if not source.exists():
        raise FileNotFoundError(source)
    readiness_metadata = _admit_conversion(request)

    admitted_bytes = source.read_bytes()
    actual = hashlib.sha256(admitted_bytes).hexdigest()
    if not hmac.compare_digest(actual, readiness_metadata["readiness_source_checksum"]):
        raise ValueError("Conversion is blocked: source changed after readiness admission")
    with tempfile.TemporaryDirectory(prefix="smf-admitted-source-") as temporary_dir:
        snapshot = Path(temporary_dir) / source.name
        snapshot.write_bytes(admitted_bytes)
        snapshot.chmod(0o400)
        return _convert_admitted_source(request, snapshot, source, readiness_metadata)


def _convert_admitted_source(
    request: ConversionRequest,
    source: Path,
    reported_source: Path,
    readiness_metadata: dict[str, Any],
) -> ConversionResult:
    """Assess and convert one stable source path admitted for this attempt."""

    workload_dir = _conversion_output_dir(request)
    if readiness_metadata.get("macro_dependent"):
        if workload_dir.exists():
            raise FileExistsError(f"Conversion attempt output already exists: {workload_dir}")
        result = ConversionResult(
            source_file=str(reported_source),
            target=request.target,
            route="human_supervised",
            provider="none",
            status="review_required",
            warnings=[
                "Macro-dependent source requires a provider that explicitly consumes the "
                "versioned macro strategy and complete immutable source bundle."
            ],
            metadata=readiness_metadata,
        )
        manifest = write_manifest(workload_dir, result.to_dict(), root=request.output_dir)
        result.output_files.append(str(manifest))
        return result
    assessment = _report_assessment_source(
        assess_sas_file(str(source)),
        reported_source,
        readiness_metadata["readiness_workload_id"],
    )
    if readiness_metadata and not hmac.compare_digest(
        _sha256(source), readiness_metadata["readiness_source_checksum"]
    ):
        raise ValueError(
            "Conversion is blocked: admitted source snapshot changed during assessment"
        )
    route = _route_from_assessment(assessment)
    if route == "human_supervised":
        if workload_dir.exists():
            raise FileExistsError(f"Conversion attempt output already exists: {workload_dir}")
        result = ConversionResult(
            source_file=str(reported_source),
            target=request.target,
            route=route,
            provider="none",
            status="review_required",
            warnings=[
                "Assessment requires human supervision. Automatic conversion was not executed."
            ],
            metadata={"assessment": assessment, **readiness_metadata},
        )
        manifest = write_manifest(workload_dir, result.to_dict(), root=request.output_dir)
        result.output_files.append(str(manifest))
        return result

    governed_identity = all(
        readiness_metadata.get(field) for field in ("client_id", "deployment_id", "environment_id")
    )
    deterministic = request.provider == "deterministic" or (
        request.provider == "auto" and governed_identity
    )
    if deterministic:
        if request.model is not None:
            raise ValueError(
                "Conversion is blocked: deterministic provider does not accept a model"
            )
        return _convert_deterministically(
            request, source, reported_source, readiness_metadata, assessment, workload_dir
        )

    if workload_dir.exists():
        raise FileExistsError(f"Conversion attempt output already exists: {workload_dir}")
    provider = Sas2DatabricksProvider()
    converted = provider.convert(source, request.target)

    suffix = ".py" if request.target == "pyspark" else ".sql"
    generated = workload_dir / f"{reported_source.stem}{suffix}"
    publish_bytes(
        generated,
        converted.content.encode("utf-8"),
        "generated artifact",
        root=request.output_dir,
    )

    requires_review = _provider_requires_review(converted.metadata)
    status = "review_required" if requires_review else "converted"

    result = ConversionResult(
        source_file=str(reported_source),
        target=request.target,
        route=route,
        provider=converted.provider,
        status=status,
        output_files=[str(generated)],
        warnings=converted.warnings,
        metadata={
            "assessment": assessment,
            "provider_metadata": converted.metadata,
            "requested_provider": request.provider,
            "requested_model": request.model,
            **readiness_metadata,
        },
    )
    manifest = write_manifest(workload_dir, result.to_dict(), root=request.output_dir)
    result.output_files.append(str(manifest))
    return result


@contextmanager
def _attempt_lock(workload_dir: Path, *, root: Path) -> Iterator[None]:
    """Serialize one attempt without globally serializing independent workloads."""

    import fcntl

    lock_path = workload_dir / ".conversion.lock"
    with open_lock_file(lock_path, root=root) as descriptor:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def _telemetry(status: str, *, generated: bool) -> dict[str, bool]:
    return {
        "generated": generated,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_assisted": False,
        "human_pending": status == "human_pending",
        "human_denied": status == "human_denied",
        "blocked": status == "blocked",
        "unsupported": status == "unsupported",
        "failed": status == "failed",
    }


def _canonical_result(
    path: Path, *, root: Path, expected_plan: dict[str, Any] | None = None
) -> ConversionResult:
    raw = read_published_json(path, root=root, label="canonical manifest")
    if not isinstance(raw, dict) or set(raw) != {
        "source_file",
        "target",
        "route",
        "provider",
        "status",
        "output_files",
        "warnings",
        "metadata",
    }:
        raise ValueError("Canonical conversion result is malformed")
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict) or "telemetry" not in metadata:
        raise ValueError("Canonical deterministic conversion result lacks telemetry")
    status = raw.get("status")
    if status not in {
        "converted",
        "unsupported",
        "blocked",
        "failed",
        "human_pending",
        "human_denied",
    }:
        raise ValueError("Canonical deterministic conversion result has unknown status")
    generated = status == "converted"
    if metadata["telemetry"] != _telemetry(status, generated=generated):
        raise ValueError("Canonical deterministic telemetry claim is not evidence-derived")
    if expected_plan is not None and metadata.get("rule_plan") != expected_plan:
        raise ValueError("Canonical deterministic result plan binding mismatch")
    plan = metadata.get("rule_plan")
    if not isinstance(plan, dict):
        raise ValueError("Canonical deterministic plan evidence is absent")
    allowed_by_plan = {
        "qualified": {"converted", "failed"},
        "unsupported": {"unsupported"},
        "blocked": {"blocked"},
        "human_pending": {"human_pending"},
        "human_denied": {"human_denied"},
    }
    plan_disposition = plan.get("disposition")
    if not isinstance(plan_disposition, str) or status not in allowed_by_plan.get(
        plan_disposition, set()
    ):
        raise ValueError("Canonical deterministic status is not authorized by its plan")
    output_files = raw.get("output_files")
    if not isinstance(output_files, list) or not all(
        isinstance(item, str) for item in output_files
    ):
        raise ValueError("Canonical deterministic output inventory is malformed")
    parent = Path(os.path.abspath(path.parent))
    for item in output_files:
        artifact = Path(item)
        if not Path(os.path.abspath(artifact)).is_relative_to(parent):
            raise ValueError("Canonical deterministic output escapes its attempt boundary")
    if generated:
        generated_paths = [Path(item) for item in output_files if item.endswith((".py", ".sql"))]
        if len(generated_paths) != 1 or not published_file_exists(
            generated_paths[0], root=root, label="generated artifact"
        ):
            raise ValueError("Canonical deterministic generated artifact is absent or ambiguous")
        provider_metadata = metadata.get("provider_metadata")
        if not isinstance(provider_metadata, dict):
            raise ValueError("Canonical deterministic provider evidence is absent")
        generated_digest = hashlib.sha256(
            read_published_bytes(generated_paths[0], root=root, label="generated artifact")
        ).hexdigest()
        if generated_digest != provider_metadata.get("generated_sha256"):
            raise ValueError("Canonical deterministic generated artifact digest mismatch")
        applications = provider_metadata.get("applications")
        applications_path = path.with_name("rule-applications.json")
        if (
            not isinstance(applications, list)
            or not applications
            or not published_file_exists(
                applications_path, root=root, label="rule application evidence"
            )
        ):
            raise ValueError("Canonical deterministic rule application evidence is absent")
        stored_applications = read_published_json(
            applications_path, root=root, label="rule application evidence"
        )
        if stored_applications != {"applications": applications}:
            raise ValueError("Canonical deterministic rule application evidence mismatch")
        selected_rules = plan.get("selected_rules")
        if not isinstance(selected_rules, list) or len(applications) != len(selected_rules):
            raise ValueError("Canonical deterministic rule application inventory mismatch")
        selected_by_id = {
            (item.get("rule_id"), item.get("rule_version")): item
            for item in selected_rules
            if isinstance(item, dict)
        }
        if len(selected_by_id) != len(selected_rules):
            raise ValueError("Canonical deterministic selected rule identity is ambiguous")
        application_ids: set[str] = set()
        for application in applications:
            if (
                not isinstance(application, dict)
                or application.get("applicability") != "applicable"
            ):
                raise ValueError("Canonical deterministic applicability is malformed")
            bindings = {
                "workload_id": plan.get("workload_id"),
                "source_artifact_id": plan.get("source_artifact_id"),
                "run_id": plan.get("run_id"),
                "attempt_id": plan.get("attempt_id"),
                "plan_id": plan.get("plan_id"),
                "registry_digest": plan.get("registry_digest"),
                "input_sha256": plan.get("statement_sha256"),
                "output_sha256": generated_digest,
                "input_byte_start": plan.get("statement_byte_start"),
                "input_byte_end": plan.get("statement_byte_end"),
            }
            if any(application.get(key) != value for key, value in bindings.items()):
                raise ValueError("Canonical deterministic rule application binding mismatch")
            rule_identity = (application.get("rule_id"), application.get("rule_version"))
            selected = selected_by_id.get(rule_identity)
            if selected is None or application.get("descriptor_digest") != selected.get(
                "descriptor_digest"
            ):
                raise ValueError("Canonical deterministic rule application is not selected")
            expected_application_id = stable_id(
                "CVAPP",
                {
                    "plan_id": plan.get("plan_id"),
                    "rule": selected,
                    "workload_id": plan.get("workload_id"),
                    "source_artifact_id": plan.get("source_artifact_id"),
                    "run_id": plan.get("run_id"),
                    "attempt_id": plan.get("attempt_id"),
                },
            )
            if application.get("application_id") != expected_application_id:
                raise ValueError("Canonical deterministic rule application identity mismatch")
            application_ids.add(expected_application_id)
        if len(application_ids) != len(applications):
            raise ValueError("Canonical deterministic rule application identity is duplicated")
        planned_mappings = plan.get("temporal_mappings")
        mappings = provider_metadata.get("temporal_mappings")
        mappings_path = path.with_name("temporal-mappings.json")
        if not isinstance(planned_mappings, list) or not isinstance(mappings, list):
            raise ValueError("Canonical deterministic temporal mapping inventory is malformed")
        if planned_mappings:
            if not published_file_exists(
                mappings_path, root=root, label="temporal mapping evidence"
            ):
                raise ValueError("Canonical deterministic temporal mapping evidence is absent")
            stored_mappings = read_published_json(
                mappings_path, root=root, label="temporal mapping evidence"
            )
            if stored_mappings != {"mappings": mappings}:
                raise ValueError("Canonical deterministic temporal mapping evidence mismatch")
            if len(mappings) != len(planned_mappings):
                raise ValueError("Canonical deterministic temporal mapping inventory mismatch")
            mapping_ids: set[str] = set()
            previous_end = -1
            planned_by_span = {
                (item.get("byte_start"), item.get("byte_end")): item
                for item in planned_mappings
                if isinstance(item, dict)
            }
            if len(planned_by_span) != len(planned_mappings):
                raise ValueError("Canonical deterministic temporal mapping span is ambiguous")
            if not all(isinstance(item, dict) for item in mappings):
                raise ValueError("Canonical deterministic temporal mapping is malformed")
            for mapping in sorted(mappings, key=lambda item: item.get("byte_start", -1)):
                start = mapping.get("byte_start")
                end = mapping.get("byte_end")
                span = (start, end)
                planned = planned_by_span.get(span)
                if planned is None or any(
                    mapping.get(key) != value for key, value in planned.items()
                ):
                    raise ValueError("Canonical deterministic temporal mapping plan mismatch")
                if not isinstance(start, int) or not isinstance(end, int):
                    raise ValueError("Canonical deterministic temporal mapping span is malformed")
                evidence_fields = {
                    "mapping_id",
                    "plan_id",
                    "workload_id",
                    "source_artifact_id",
                    "run_id",
                    "attempt_id",
                    "source_sha256",
                    "generated_sha256",
                    "registry_digest",
                }
                if set(mapping) != set(planned) | evidence_fields:
                    raise ValueError(
                        "Canonical deterministic temporal mapping fields are malformed"
                    )
                if start < previous_end:
                    raise ValueError("Canonical deterministic temporal mapping spans overlap")
                previous_end = end
                identity = {
                    "plan_id": plan.get("plan_id"),
                    "workload_id": plan.get("workload_id"),
                    "source_artifact_id": plan.get("source_artifact_id"),
                    "run_id": plan.get("run_id"),
                    "attempt_id": plan.get("attempt_id"),
                    "source_sha256": plan.get("source_sha256"),
                    "byte_start": start,
                    "byte_end": end,
                    "literal_sha256": mapping.get("literal_sha256"),
                    "policy_digest": plan.get("temporal_policy_digest"),
                    "target_expression_sha256": mapping.get("target_expression_sha256"),
                    "generated_sha256": generated_digest,
                }
                if any(mapping.get(key) != value for key, value in identity.items()):
                    raise ValueError("Canonical deterministic temporal mapping binding mismatch")
                expected_mapping_id = stable_id("CVMAP", identity)
                if mapping.get("mapping_id") != expected_mapping_id:
                    raise ValueError("Canonical deterministic temporal mapping identity mismatch")
                if mapping.get("registry_digest") != plan.get("registry_digest"):
                    raise ValueError("Canonical deterministic temporal registry binding mismatch")
                mapping_ids.add(expected_mapping_id)
            if len(mapping_ids) != len(mappings):
                raise ValueError("Canonical deterministic temporal mapping identity is duplicated")
        elif mappings or published_file_exists(
            mappings_path, root=root, label="temporal mapping evidence"
        ):
            raise ValueError("Non-temporal conversion claims temporal mapping evidence")
        planned_values = plan.get("value_occurrences")
        values = provider_metadata.get("value_mappings")
        values_path = path.with_name("value-mappings.json")
        if not isinstance(planned_values, list) or not isinstance(values, list):
            raise ValueError("Canonical deterministic value mapping inventory is malformed")
        if planned_values:
            if not published_file_exists(values_path, root=root, label="value mapping evidence"):
                raise ValueError("Canonical deterministic value mapping evidence is absent")
            if read_published_json(values_path, root=root, label="value mapping evidence") != {
                "mappings": values
            }:
                raise ValueError("Canonical deterministic value mapping evidence mismatch")
            if len(values) != len(planned_values):
                raise ValueError("Canonical deterministic value mapping inventory mismatch")
            planned_by_span = {
                (item.get("byte_start"), item.get("byte_end")): item
                for item in planned_values
                if isinstance(item, dict)
            }
            if len(planned_by_span) != len(planned_values):
                raise ValueError("Canonical deterministic value mapping span is ambiguous")
            value_mapping_ids: set[str] = set()
            previous_end = -1
            for mapping in sorted(values, key=lambda item: item.get("byte_start", -1)):
                if not isinstance(mapping, dict):
                    raise ValueError("Canonical deterministic value mapping is malformed")
                start, end = mapping.get("byte_start"), mapping.get("byte_end")
                planned = planned_by_span.get((start, end))
                if planned is None or any(
                    mapping.get(key) != value for key, value in planned.items()
                ):
                    raise ValueError("Canonical deterministic value mapping plan mismatch")
                evidence_fields = {
                    "mapping_id",
                    "plan_id",
                    "workload_id",
                    "source_artifact_id",
                    "run_id",
                    "attempt_id",
                    "source_sha256",
                    "generated_sha256",
                    "registry_digest",
                }
                if set(mapping) != set(planned) | evidence_fields:
                    raise ValueError("Canonical deterministic value mapping fields are malformed")
                if not isinstance(start, int) or not isinstance(end, int) or start < previous_end:
                    raise ValueError("Canonical deterministic value mapping spans overlap")
                previous_end = end
                identity = {
                    "plan_id": plan.get("plan_id"),
                    "workload_id": plan.get("workload_id"),
                    "source_artifact_id": plan.get("source_artifact_id"),
                    "run_id": plan.get("run_id"),
                    "attempt_id": plan.get("attempt_id"),
                    "source_sha256": plan.get("source_sha256"),
                    "byte_start": start,
                    "byte_end": end,
                    "source_token_sha256": mapping.get("source_token_sha256"),
                    "policy_digest": plan.get("value_policy_digest"),
                    "target_expression_sha256": mapping.get("target_expression_sha256"),
                    "generated_sha256": generated_digest,
                }
                if any(mapping.get(key) != value for key, value in identity.items()):
                    raise ValueError("Canonical deterministic value mapping binding mismatch")
                expected_id = stable_id("CVVALUE", identity)
                if mapping.get("mapping_id") != expected_id:
                    raise ValueError("Canonical deterministic value mapping identity mismatch")
                if mapping.get("registry_digest") != plan.get("registry_digest"):
                    raise ValueError("Canonical deterministic value registry binding mismatch")
                value_mapping_ids.add(expected_id)
            if len(value_mapping_ids) != len(values):
                raise ValueError("Canonical deterministic value mapping identity is duplicated")
        elif values or published_file_exists(
            values_path, root=root, label="value mapping evidence"
        ):
            raise ValueError("Non-value conversion claims value mapping evidence")
    elif any(item.endswith((".py", ".sql")) for item in output_files):
        raise ValueError("Non-generated deterministic result claims a generated artifact")
    result = ConversionResult(**raw)
    result.output_files.append(str(path))
    telemetry_path = path.with_name("conversion.telemetry.json")
    publish_json(telemetry_path, metadata["telemetry"], "telemetry", root=root)
    result.output_files.append(str(telemetry_path))
    return result


def _convert_deterministically(
    request: ConversionRequest,
    source: Path,
    reported_source: Path,
    readiness_metadata: dict[str, Any],
    assessment: dict[str, Any],
    workload_dir: Path,
) -> ConversionResult:
    """Plan, execute, and publish the package-owned deterministic subset."""

    source_bytes = source.read_bytes()
    attempt_id = request.conversion_attempt_id or request.readiness_attempt_id
    assert request.workload_id is not None
    assert request.source_artifact_id is not None
    assert request.run_id is not None
    assert attempt_id is not None
    with _attempt_lock(workload_dir, root=request.output_dir):
        safe_assessment = dict(assessment)
        safe_assessment["source_file"] = f"artifact:{request.source_artifact_id}"
        temporal_policy = _load_temporal_policy(request.temporal_policy)
        value_policy = _load_value_policy(request.value_compatibility_policy)
        plan = plan_rules(
            source_bytes,
            request.target,
            temporal_policy=temporal_policy,
            value_policy=value_policy,
        )
        plan_payload = json.loads(
            json.dumps(
                {
                    **plan.to_dict(),
                    "client_id": readiness_metadata.get("client_id"),
                    "deployment_id": readiness_metadata.get("deployment_id"),
                    "environment_id": readiness_metadata.get("environment_id"),
                    "workload_id": request.workload_id,
                    "source_artifact_id": request.source_artifact_id,
                    "run_id": request.run_id,
                    "attempt_id": attempt_id,
                    "readiness_result_id": readiness_metadata["readiness_result_id"],
                    "readiness_policy_digest": readiness_metadata["readiness_policy_digest"],
                    "macro_analysis_id": readiness_metadata["macro_analysis_id"],
                    "macro_strategy_digest": readiness_metadata["macro_strategy_digest"],
                    "deployment_configuration_digest": readiness_metadata.get(
                        "deployment_configuration_digest"
                    ),
                }
            )
        )
        plan_path = publish_json(
            workload_dir / "rule-plan.json",
            plan_payload,
            "rule plan",
            root=request.output_dir,
        )
        manifest_path = workload_dir / "conversion.manifest.json"
        if published_file_exists(
            manifest_path, root=request.output_dir, label="canonical manifest"
        ):
            existing = read_published_json(
                manifest_path, root=request.output_dir, label="canonical manifest"
            )
            if not isinstance(existing, dict):
                raise ValueError("Canonical conversion result is malformed")
            existing_metadata = existing.get("metadata")
            if (
                not isinstance(existing_metadata, dict)
                or existing_metadata.get("rule_plan") != plan_payload
            ):
                raise FileExistsError("Conversion attempt identity collides with a different plan")
            if existing.get("status") == "converted":
                generated_paths = [
                    Path(item)
                    for item in existing.get("output_files", [])
                    if isinstance(item, str)
                    if item.endswith((".py", ".sql"))
                ]
                if len(generated_paths) != 1:
                    raise ValueError(
                        "Canonical deterministic result has ambiguous generated output"
                    )
                applications_path = workload_dir / "rule-applications.json"
                mappings_path = workload_dir / "temporal-mappings.json"
                value_mappings_path = workload_dir / "value-mappings.json"
                needs_mappings = bool(plan.temporal_mappings)
                needs_value_mappings = bool(plan.value_occurrences)
                if (
                    not published_file_exists(
                        generated_paths[0],
                        root=request.output_dir,
                        label="generated artifact",
                    )
                    or not published_file_exists(
                        applications_path,
                        root=request.output_dir,
                        label="rule application evidence",
                    )
                    or (
                        needs_mappings
                        and not published_file_exists(
                            mappings_path,
                            root=request.output_dir,
                            label="temporal mapping evidence",
                        )
                    )
                    or (
                        needs_value_mappings
                        and not published_file_exists(
                            value_mappings_path,
                            root=request.output_dir,
                            label="value mapping evidence",
                        )
                    )
                ):
                    replayed = execute_plan(
                        source_bytes,
                        plan,
                        workload_id=request.workload_id,
                        source_artifact_id=request.source_artifact_id,
                        run_id=request.run_id,
                        attempt_id=attempt_id,
                    )
                    publish_bytes(
                        generated_paths[0],
                        replayed.content.encode("utf-8"),
                        "generated artifact",
                        root=request.output_dir,
                    )
                    publish_json(
                        applications_path,
                        {"applications": replayed.metadata["applications"]},
                        "rule applications",
                        root=request.output_dir,
                    )
                    if needs_mappings:
                        publish_json(
                            mappings_path,
                            {"mappings": replayed.metadata["temporal_mappings"]},
                            "temporal mappings",
                            root=request.output_dir,
                        )
                    if needs_value_mappings:
                        publish_json(
                            value_mappings_path,
                            {"mappings": replayed.metadata["value_mappings"]},
                            "value mappings",
                            root=request.output_dir,
                        )
            return _canonical_result(
                manifest_path, root=request.output_dir, expected_plan=plan_payload
            )

        generated = False
        output_files = [str(plan_path)]
        provider_metadata: dict[str, Any] = {}
        warnings: list[str] = []
        status = plan.disposition.value
        provider = "smf-deterministic"
        if plan.disposition is PlanDisposition.QUALIFIED:
            try:
                converted = execute_plan(
                    source_bytes,
                    plan,
                    workload_id=request.workload_id,
                    source_artifact_id=request.source_artifact_id,
                    run_id=request.run_id,
                    attempt_id=attempt_id,
                )
                suffix = ".py" if request.target == "pyspark" else ".sql"
                generated_path = workload_dir / f"{request.source_artifact_id}{suffix}"
                publish_bytes(
                    generated_path,
                    converted.content.encode("utf-8"),
                    "generated artifact",
                    root=request.output_dir,
                )
                applications_path = publish_json(
                    workload_dir / "rule-applications.json",
                    {"applications": converted.metadata["applications"]},
                    "rule applications",
                    root=request.output_dir,
                )
                output_files = [str(generated_path), str(plan_path), str(applications_path)]
                if converted.metadata["temporal_mappings"]:
                    mappings_path = publish_json(
                        workload_dir / "temporal-mappings.json",
                        {"mappings": converted.metadata["temporal_mappings"]},
                        "temporal mappings",
                        root=request.output_dir,
                    )
                    output_files.append(str(mappings_path))
                if converted.metadata["value_mappings"]:
                    value_mappings_path = publish_json(
                        workload_dir / "value-mappings.json",
                        {"mappings": converted.metadata["value_mappings"]},
                        "value mappings",
                        root=request.output_dir,
                    )
                    output_files.append(str(value_mappings_path))
                provider_metadata = converted.metadata
                generated = True
                status = "converted"
            except Exception as exc:
                status = "failed"
                warnings = [
                    "Deterministic transformation failed; diagnostic detail was withheld from "
                    "canonical evidence."
                ]
                provider_metadata = {"failure_type": type(exc).__name__}
        elif plan.blockers:
            warnings = list(plan.blockers)

        telemetry = _telemetry(status, generated=generated)
        metadata = {
            "assessment": safe_assessment,
            "rule_plan": plan_payload,
            "provider_metadata": provider_metadata,
            "requested_provider": request.provider,
            "requested_model": request.model,
            "conversion_attempt_id": attempt_id,
            "telemetry": telemetry,
            **readiness_metadata,
        }
        result = ConversionResult(
            source_file=f"artifact:{request.source_artifact_id}",
            target=request.target,
            route="deterministic",
            provider=provider,
            status=status,
            output_files=output_files,
            warnings=warnings,
            metadata=metadata,
        )
        write_manifest(workload_dir, result.to_dict(), root=request.output_dir)
        publish_json(
            workload_dir / "conversion.telemetry.json",
            telemetry,
            "telemetry",
            root=request.output_dir,
        )
        return _canonical_result(manifest_path, root=request.output_dir, expected_plan=plan_payload)
