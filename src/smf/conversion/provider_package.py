from __future__ import annotations

import ast
import hashlib
import hmac
import json
import re
import tempfile
import time
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator

from smf.conversion.manifest import (
    open_lock_file,
    publish_bytes,
    publish_json,
    published_file_exists,
    read_published_bytes,
    read_published_json,
)
from smf.conversion.providers.sas2databricks import (
    DEFAULT_THRESHOLD,
    EVALUATED_REVISION,
    LICENSE_DISPOSITION,
    LICENSE_EXPRESSION,
    QUALIFIED_LICENSE_SHA256,
    QUALIFIED_PACKAGE_MANIFEST_SHA256,
    QUALIFIED_VERSION,
    Sas2DatabricksProvider,
    _python_runtime_identity,
    _qualified_provider_artifact,
)
from smf.workload.identity import stable_id

PackageStatus = Literal["packaged", "review_required", "unsupported", "blocked"]

_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROTECTED_VALUE = re.compile(
    r"(?i)(bearer\s|password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)"
)
_SOURCE_COMMENT = re.compile(r"(?m)^# Source:.*$")
_REVIEW_MARKER = re.compile(r"(?i)(\[review\]|manual-review stub|pending host fulfillment)")


@dataclass(frozen=True)
class ProviderPackageRequest:
    source_file: Path
    source_root: Path
    output_root: Path
    client_id: str
    deployment_id: str
    environment_id: str
    workload_id: str
    source_artifact_id: str
    run_id: str
    attempt_id: str
    expected_source_sha256: str
    source_provenance_file: Path
    source_provenance_root: Path
    expected_source_provenance_sha256: str
    target: Literal["pyspark", "sparksql"] = "pyspark"


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_digest(payload: dict[str, Any]) -> str:
    normalized = {key: value for key, value in payload.items() if key != "content_digest"}
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_bytes(encoded)


def _identity(value: str, label: str) -> str:
    if (
        value in {".", ".."}
        or not _SAFE_COMPONENT.fullmatch(value)
        or _PROTECTED_VALUE.search(value)
    ):
        raise ValueError(f"CV-04 blocked: unsafe {label}")
    return value


def _provenance_text(value: str, label: str) -> str:
    unsafe = (
        not value
        or len(value) > 512
        or "\n" in value
        or "\r" in value
        or _PROTECTED_VALUE.search(value)
    )
    if unsafe:
        raise ValueError(f"CV-04 blocked: unsafe {label}")
    return value


def _reject_protected_payload(payload: bytes, label: str) -> None:
    text = payload.decode("utf-8", errors="ignore")
    if _PROTECTED_VALUE.search(text):
        raise ValueError(f"CV-04 blocked: {label} contains protected or secret-like data")


def _read_source_provenance(request: ProviderPackageRequest, source_sha256: str) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", request.expected_source_provenance_sha256):
        raise ValueError("CV-04 blocked: source provenance digest is not canonical SHA-256")
    payload = read_published_bytes(
        request.source_provenance_file,
        root=request.source_provenance_root,
        label="CV-04 source provenance",
    )
    if not hmac.compare_digest(_sha256_bytes(payload), request.expected_source_provenance_sha256):
        raise ValueError("CV-04 blocked: source provenance bytes differ from admitted digest")
    _reject_protected_payload(payload, "source provenance")
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("CV-04 blocked: source provenance evidence is malformed") from exc
    required = {"evidence_id", "artifact_id", "artifact_sha256", "origin", "revision", "license"}
    if not isinstance(parsed, dict) or set(parsed) != required:
        raise ValueError("CV-04 blocked: source provenance evidence fields are not exact")
    result = {
        "evidence_id": _identity(parsed["evidence_id"], "source_provenance_id"),
        "evidence_digest": request.expected_source_provenance_sha256,
        "origin": _provenance_text(parsed["origin"], "source_origin"),
        "revision": _provenance_text(parsed["revision"], "source_revision"),
        "license": _provenance_text(parsed["license"], "source_license"),
    }
    if parsed["artifact_id"] != request.source_artifact_id or not hmac.compare_digest(
        parsed["artifact_sha256"], source_sha256
    ):
        raise ValueError("CV-04 blocked: source provenance does not bind admitted source")
    return result


def _package_dir(request: ProviderPackageRequest) -> Path:
    parts = (
        _identity(request.run_id, "run_id"),
        _identity(request.workload_id, "workload_id"),
        _identity(request.attempt_id, "attempt_id"),
        _identity(request.source_artifact_id, "source_artifact_id"),
    )
    return (
        request.output_root
        / "runs"
        / parts[0]
        / "workloads"
        / parts[1]
        / "attempts"
        / parts[2]
        / "conversion-packages"
        / parts[3]
    )


def _request_identity(request: ProviderPackageRequest) -> dict[str, str]:
    return {
        "client_id": _identity(request.client_id, "client_id"),
        "deployment_id": _identity(request.deployment_id, "deployment_id"),
        "environment_id": _identity(request.environment_id, "environment_id"),
        "workload_id": _identity(request.workload_id, "workload_id"),
        "source_artifact_id": _identity(request.source_artifact_id, "source_artifact_id"),
        "run_id": _identity(request.run_id, "run_id"),
        "attempt_id": _identity(request.attempt_id, "attempt_id"),
    }


def _exception(code: str, detail: str, *, retryable: bool = False) -> dict[str, Any]:
    return {"code": code, "detail": detail, "retryable": retryable}


def _normalized_content(content: str, artifact_id: str) -> bytes:
    replaced = _SOURCE_COMMENT.sub(f"# Source: artifact:{artifact_id}", content)
    return (replaced.rstrip() + "\n").encode("utf-8")


def _claims(status: PackageStatus) -> dict[str, bool]:
    return {
        "generated": status in {"packaged", "review_required"},
        "package_ready": status == "packaged",
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "ai_repaired": False,
        "production_ready": False,
        "migration_complete": False,
    }


def build_provider_package(request: ProviderPackageRequest) -> Path:
    """Build one immutable, deterministic-first sas2databricks package.

    Two local conversions of the same descriptor-admitted bytes must agree. The wrapper never
    forwards model-provider credentials and never treats upstream review/escalation metadata as
    successful packaging. AIGW repair is a separate downstream record.
    """

    identities = _request_identity(request)
    if request.target not in {"pyspark", "sparksql"}:
        raise ValueError("CV-04 blocked: unsupported target")
    if not re.fullmatch(r"[0-9a-f]{64}", request.expected_source_sha256):
        raise ValueError("CV-04 blocked: expected source digest is not canonical SHA-256")
    source_bytes = read_published_bytes(
        request.source_file,
        root=request.source_root,
        label="CV-04 source",
    )
    source_sha256 = _sha256_bytes(source_bytes)
    if not hmac.compare_digest(source_sha256, request.expected_source_sha256):
        raise ValueError("CV-04 blocked: source bytes differ from the admitted digest")
    _reject_protected_payload(source_bytes, "source")
    provenance = _read_source_provenance(request, source_sha256)

    package_dir = _package_dir(request)
    manifest_path = package_dir / "package.manifest.json"
    with open_lock_file(package_dir / ".package.lock", root=request.output_root):
        if published_file_exists(manifest_path, root=request.output_root, label="CV-04 manifest"):
            verify_provider_package(manifest_path, request)
            return manifest_path

        qualified_artifact = _qualified_provider_artifact()
        provider = Sas2DatabricksProvider()
        durations_ms: list[int] = []
        converted_results = []
        provider_failure: str | None = None
        with tempfile.TemporaryDirectory(prefix="smf-cv04-") as temporary:
            snapshot = Path(temporary) / "source.sas"
            snapshot.write_bytes(source_bytes)
            snapshot.chmod(0o400)
            for _ in range(2):
                started = time.monotonic_ns()
                try:
                    converted_results.append(provider.convert(snapshot, request.target))
                except Exception as exc:
                    provider_failure = type(exc).__name__
                    break
                durations_ms.append(max(1, (time.monotonic_ns() - started) // 1_000_000))

        exceptions: list[dict[str, Any]] = []
        status: PackageStatus
        artifact_name: str | None = None
        artifact_sha256: str | None = None
        summary: dict[str, Any] | None = None
        provider_metadata: dict[str, Any] | None = None
        reproducible = False
        if provider_failure is not None:
            status = "blocked"
            exceptions.append(
                _exception(
                    "PROVIDER_FAILURE",
                    "Pinned deterministic provider failed with "
                    f"{provider_failure}; inspect local run logs.",
                    retryable=True,
                )
            )
        else:
            first, second = converted_results
            first_bytes = _normalized_content(first.content, request.source_artifact_id)
            second_bytes = _normalized_content(second.content, request.source_artifact_id)
            _reject_protected_payload(first_bytes, "generated output")
            _reject_protected_payload(second_bytes, "generated output")
            reproducible = first_bytes == second_bytes and first.metadata == second.metadata
            provider_metadata = first.metadata
            summary = provider_metadata["summary"]
            if not reproducible:
                status = "blocked"
                exceptions.append(
                    _exception(
                        "NON_REPRODUCIBLE_OUTPUT",
                        "Two conversions of identical admitted bytes produced different evidence.",
                    )
                )
            elif int(summary["steps"]) == 0:
                status = "unsupported"
                exceptions.append(
                    _exception(
                        "NO_CONVERTIBLE_STEPS",
                        "The provider found no meaningful deterministic conversion steps.",
                    )
                )
            else:
                review_count = int(summary["review"])
                escalation_count = int(summary["llm_escalations"])
                review_marker = _REVIEW_MARKER.search(first_bytes.decode("utf-8")) is not None
                if review_count or escalation_count or review_marker:
                    status = "review_required"
                    exceptions.append(
                        _exception(
                            "UPSTREAM_REVIEW_REQUIRED",
                            "Provider output contains unresolved review or escalation evidence; "
                            "route through the separately governed repair workflow.",
                        )
                    )
                    artifact_name = (
                        "candidate.py" if request.target == "pyspark" else "candidate.sql"
                    )
                else:
                    status = "packaged"
                    artifact_name = (
                        "entrypoint.py" if request.target == "pyspark" else "entrypoint.sql"
                    )
                    if request.target == "pyspark":
                        try:
                            ast.parse(first_bytes.decode("utf-8"))
                        except (SyntaxError, UnicodeDecodeError):
                            status = "blocked"
                            artifact_name = None
                            exceptions.append(
                                _exception(
                                    "INVALID_GENERATED_SYNTAX",
                                    "Generated PySpark is not valid Python syntax.",
                                )
                            )
                if artifact_name is not None:
                    artifact_path = publish_bytes(
                        package_dir / artifact_name,
                        first_bytes,
                        "CV-04 generated artifact",
                        root=request.output_root,
                    )
                    artifact_sha256 = _sha256_bytes(
                        read_published_bytes(
                            artifact_path,
                            root=request.output_root,
                            label="CV-04 generated artifact",
                        )
                    )

        exception_path: str | None = None
        if exceptions:
            published = publish_json(
                package_dir / "exceptions.json",
                {"exceptions": exceptions},
                "CV-04 exceptions",
                root=request.output_root,
            )
            exception_path = published.name

        package_identity = {
            **identities,
            "source_sha256": source_sha256,
            "source_provenance_digest": request.expected_source_provenance_sha256,
            "target": request.target,
            "provider_version": QUALIFIED_VERSION,
            "provider_revision": EVALUATED_REVISION,
            "provider_executable_sha256": qualified_artifact.executable_sha256,
        }
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "package_id": stable_id("CVPKG", package_identity),
            "identity": identities,
            "status": status,
            "source": {
                "artifact_id": request.source_artifact_id,
                "sha256": source_sha256,
                "bytes": len(source_bytes),
                "lines": len(source_bytes.splitlines()),
                "provenance": provenance,
            },
            "target": request.target,
            "entrypoint": artifact_name if status == "packaged" else None,
            "candidate_artifact": artifact_name if status == "review_required" else None,
            "generated_sha256": artifact_sha256,
            "provider": {
                "name": "sas2databricks",
                "version": QUALIFIED_VERSION,
                "evaluated_revision": EVALUATED_REVISION,
                "record_sha256": qualified_artifact.record_sha256,
                "package_manifest_sha256": qualified_artifact.package_manifest_sha256,
                "executable_sha256": qualified_artifact.executable_sha256,
                "license": {
                    "expression": LICENSE_EXPRESSION,
                    "sha256": qualified_artifact.license_sha256,
                    "disposition": LICENSE_DISPOSITION,
                },
                "runtime_bindings": [
                    {"distribution": name, "version": version, "manifest_sha256": digest}
                    for name, version, digest in qualified_artifact.runtime_bindings
                ],
                "command": [
                    "s2db",
                    "convert",
                    "<admitted-source>",
                    "--target",
                    request.target,
                    "--threshold",
                    DEFAULT_THRESHOLD,
                ],
                "summary": summary,
                "credential_environment_forwarded": False,
                "direct_provider_access_authorized": False,
            },
            "runtime": {
                "python": _python_runtime_identity()[1],
                "python_executable_sha256": _python_runtime_identity()[2],
                "network_downloads_permitted": False,
                "isolated_flags": ["-I", "-S"],
                "dependencies": [
                    "sas2databricks==0.4.0",
                    "sqlglot==30.17.0",
                    "PyYAML==6.0.3",
                ],
            },
            "reproducibility": {
                "executions": len(converted_results),
                "outputs_equal": reproducible,
                "durations_ms": durations_ms,
                "provider_metadata_equal": reproducible,
            },
            "exceptions": exceptions,
            "exception_report": exception_path,
            "claims": _claims(status),
        }
        payload["content_digest"] = _canonical_digest(payload)
        publish_json(manifest_path, payload, "CV-04 manifest", root=request.output_root)
        verify_provider_package(manifest_path, request)
        return manifest_path


def verify_provider_package(manifest_path: Path, request: ProviderPackageRequest) -> dict[str, Any]:
    manifest = read_published_json(
        manifest_path,
        root=request.output_root,
        label="CV-04 manifest",
    )
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0":
        raise ValueError("CV-04 manifest is malformed")
    schema = json.loads(
        files("smf.schemas")
        .joinpath("conversion-provider-package.schema.json")
        .read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest), key=lambda item: list(item.path)
    )
    if errors:
        raise ValueError(f"CV-04 manifest schema violation: {errors[0].message}")
    if manifest.get("content_digest") != _canonical_digest(manifest):
        raise ValueError("CV-04 manifest digest mismatch")
    identities = _request_identity(request)
    if manifest.get("identity") != identities:
        raise ValueError("CV-04 manifest request binding mismatch")
    current_source = read_published_bytes(
        request.source_file,
        root=request.source_root,
        label="CV-04 source",
    )
    if manifest.get("source", {}).get("sha256") != _sha256_bytes(current_source):
        raise ValueError("CV-04 source changed after package publication")
    _reject_protected_payload(current_source, "source")
    expected_provenance = _read_source_provenance(request, _sha256_bytes(current_source))
    if manifest.get("source", {}).get("provenance") != expected_provenance:
        raise ValueError("CV-04 source provenance binding mismatch")
    qualified_artifact = _qualified_provider_artifact()
    provider = manifest.get("provider")
    if not isinstance(provider, dict) or any(
        provider.get(key) != value
        for key, value in {
            "version": QUALIFIED_VERSION,
            "evaluated_revision": EVALUATED_REVISION,
            "record_sha256": qualified_artifact.record_sha256,
            "package_manifest_sha256": QUALIFIED_PACKAGE_MANIFEST_SHA256,
            "executable_sha256": qualified_artifact.executable_sha256,
            "license": {
                "expression": LICENSE_EXPRESSION,
                "sha256": QUALIFIED_LICENSE_SHA256,
                "disposition": LICENSE_DISPOSITION,
            },
            "runtime_bindings": [
                {"distribution": name, "version": version, "manifest_sha256": digest}
                for name, version, digest in qualified_artifact.runtime_bindings
            ],
            "credential_environment_forwarded": False,
            "direct_provider_access_authorized": False,
        }.items()
    ):
        raise ValueError("CV-04 provider binding is stale or unauthorized")
    runtime = manifest.get("runtime")
    expected_runtime = {
        "python": _python_runtime_identity()[1],
        "python_executable_sha256": _python_runtime_identity()[2],
        "network_downloads_permitted": False,
        "isolated_flags": ["-I", "-S"],
        "dependencies": [
            "sas2databricks==0.4.0",
            "sqlglot==30.17.0",
            "PyYAML==6.0.3",
        ],
    }
    if runtime != expected_runtime:
        raise ValueError("CV-04 isolated runtime binding is stale or unauthorized")
    status = manifest.get("status")
    if status not in {"packaged", "review_required", "unsupported", "blocked"}:
        raise ValueError("CV-04 manifest status is invalid")
    if manifest.get("claims") != _claims(status):
        raise ValueError("CV-04 claims are not derived from package status")
    artifact_name = manifest.get("entrypoint") or manifest.get("candidate_artifact")
    generated_sha256 = manifest.get("generated_sha256")
    if artifact_name is not None:
        if artifact_name not in {
            "entrypoint.py",
            "entrypoint.sql",
            "candidate.py",
            "candidate.sql",
        }:
            raise ValueError("CV-04 generated artifact name is not admitted")
        artifact = manifest_path.parent / artifact_name
        actual = _sha256_bytes(
            read_published_bytes(
                artifact,
                root=request.output_root,
                label="CV-04 generated artifact",
            )
        )
        if actual != generated_sha256:
            raise ValueError("CV-04 generated artifact digest mismatch")
    elif generated_sha256 is not None:
        raise ValueError("CV-04 manifest claims an unreferenced generated digest")
    exceptions = manifest.get("exceptions")
    exception_report = manifest.get("exception_report")
    if bool(exceptions) != bool(exception_report):
        raise ValueError("CV-04 exception report binding is inconsistent")
    if exception_report is not None:
        stored = read_published_json(
            manifest_path.parent / exception_report,
            root=request.output_root,
            label="CV-04 exceptions",
        )
        if stored != {"exceptions": exceptions}:
            raise ValueError("CV-04 exception report differs from the manifest")
    return manifest
