from __future__ import annotations

import hashlib
import re
from pathlib import Path

from smf.execution.manifest import write_execution_manifest, write_new_json
from smf.execution.models import ExecutionRequest, ExecutionResult
from smf.execution.providers.databricks import DatabricksExecutionProvider
from smf.execution.providers.local import LocalExecutionProvider
from smf.execution.schema import validate_execution_schema
from smf.validation.engine import validate_conversion
from smf.validation.models import ValidationRequest


def _provider(name: str) -> LocalExecutionProvider | DatabricksExecutionProvider:
    normalized = name.lower()

    if normalized == "local":
        return LocalExecutionProvider()

    if normalized == "databricks":
        return DatabricksExecutionProvider()

    raise ValueError(f"Unsupported execution provider: {name}")


_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _identity(value: str, name: str) -> str:
    if not _IDENTITY.fullmatch(value):
        raise ValueError(f"{name} must be a safe, non-empty canonical identifier")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute_validation(request: ExecutionRequest) -> ExecutionResult:
    if not request.source_file.exists():
        raise FileNotFoundError(request.source_file)

    if not request.generated_file.exists():
        raise FileNotFoundError(request.generated_file)

    run_id = _identity(request.run_id, "run_id")
    attempt_id = _identity(request.attempt_id, "attempt_id")
    workload_id = _identity(request.workload_id or request.source_file.stem, "workload_id")
    source_sha256 = _sha256(request.source_file)
    generated_sha256 = _sha256(request.generated_file)
    attempt_dir = (
        request.output_dir
        / "runs"
        / run_id
        / "workloads"
        / workload_id
        / "attempts"
        / attempt_id
        / "execution"
    )
    claim_path = attempt_dir / "execution.claim.json"
    manifest_path = attempt_dir / "execution.manifest.json"
    if manifest_path.exists():
        raise RuntimeError(
            "execution attempt already has canonical execution evidence; "
            "preserve it and use a distinct reconciled attempt identity"
        )
    if claim_path.exists():
        raise RuntimeError(
            "execution attempt has no terminal manifest; outcome is unknown and retry is prohibited"
        )

    static_result = validate_conversion(
        ValidationRequest(
            source_file=request.source_file,
            generated_file=request.generated_file,
            target=request.target,
            output_dir=request.output_dir,
        )
    )

    if static_result.status == "failed":
        result = ExecutionResult(
            source_file=str(request.source_file),
            generated_file=str(request.generated_file),
            target=request.target,
            provider=request.provider,
            status="blocked",
            duration_seconds=0.0,
            stderr="Static validation failed. Execution was not attempted.",
            warnings=static_result.warnings,
            evidence={
                "static_validation_status": static_result.status,
                "static_validation_confidence": static_result.confidence,
            },
        )
    elif static_result.requires_human_review:
        result = ExecutionResult(
            source_file=str(request.source_file),
            generated_file=str(request.generated_file),
            target=request.target,
            provider=request.provider,
            status="blocked",
            duration_seconds=0.0,
            stderr="Static validation requires human review. Execution was not attempted.",
            warnings=static_result.warnings,
            evidence={
                "static_validation_status": static_result.status,
                "static_validation_confidence": static_result.confidence,
            },
        )
    else:
        # Reserve the attempt before a provider can create external or local side effects.
        write_new_json(
            claim_path,
            {
                "run_id": run_id,
                "attempt_id": attempt_id,
                "workload_id": workload_id,
                "source_file": str(request.source_file),
                "source_sha256": source_sha256,
                "generated_file": str(request.generated_file),
                "generated_sha256": generated_sha256,
                "provider": request.provider,
                "target": request.target,
            },
        )
        if (
            _sha256(request.source_file) != source_sha256
            or _sha256(request.generated_file) != generated_sha256
        ):
            raise RuntimeError("qualified execution inputs changed before provider invocation")
        result = _provider(request.provider).execute(request)
        result.evidence["static_validation_status"] = static_result.status
        result.evidence["static_validation_confidence"] = static_result.confidence

    result.run_id = run_id
    result.evidence.update(
        {
            "attempt_id": attempt_id,
            "workload_id": workload_id,
            "source_sha256": source_sha256,
            "generated_sha256": generated_sha256,
        }
    )
    result.output_files.append(str(manifest_path))

    payload = result.to_dict()
    validate_execution_schema(payload)

    write_execution_manifest(attempt_dir, payload)

    return result
