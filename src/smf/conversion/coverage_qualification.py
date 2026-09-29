"""Bounded, evidence-first sas2databricks construct coverage qualification."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator

from smf.conversion.manifest import publish_json, read_published_bytes
from smf.conversion.provider_package import (
    ProviderPackageRequest,
    build_provider_package,
    verify_provider_package,
)
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.sanitization import sanitize_discovery_value

CoverageClassification = Literal["supported", "partial", "unsupported", "unresolved"]

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STATUS: dict[str, CoverageClassification] = {
    # Static generation alone cannot establish supported behavioral conversion.
    "packaged": "partial",
    "review_required": "partial",
    "unsupported": "unsupported",
    "blocked": "unresolved",
}
_SEVERITY = {"supported": 0, "partial": 1, "unsupported": 2, "unresolved": 3}
_IMPLEMENTATION_FILES = (
    "src/smf/conversion/__init__.py",
    "src/smf/conversion/coverage_qualification.py",
    "src/smf/conversion/manifest.py",
    "src/smf/conversion/provider_package.py",
    "src/smf/conversion/providers/sas2databricks.py",
    "src/smf/security/ai_admission.py",
    "src/smf/workload/identity.py",
    "src/smf/workload/sanitization.py",
    "src/smf/schemas/conversion-coverage-corpus.schema.json",
    "src/smf/schemas/conversion-coverage-result.schema.json",
)


@dataclass(frozen=True)
class CoverageQualificationRequest:
    corpus_manifest: Path
    corpus_root: Path
    output_root: Path
    expected_manifest_sha256: str
    client_id: str
    deployment_id: str
    environment_id: str
    run_id: str
    attempt_id: str


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _content_digest(payload: dict[str, Any]) -> str:
    subject = {key: value for key, value in payload.items() if key != "content_digest"}
    return _digest(json.dumps(subject, sort_keys=True, separators=(",", ":")).encode())


def _implementation_manifest() -> list[dict[str, str]]:
    root = Path(__file__).resolve().parents[3]
    return [
        {
            "path": relative,
            "sha256": _digest(
                read_published_bytes(
                    root / relative,
                    root=root,
                    label="SPIKE-02 implementation file",
                )
            ),
        }
        for relative in _IMPLEMENTATION_FILES
    ]


def _identity(value: str, label: str) -> str:
    if (
        value in {".", ".."}
        or not _SAFE_ID.fullmatch(value)
        or contains_protected_data(value)
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"SPIKE-02 blocked: unsafe {label}")
    return value


def _schema(name: str) -> dict[str, Any]:
    raw = json.loads(files("smf.schemas").joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("SPIKE-02 packaged schema must be an object")
    return raw


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("SPIKE-02 JSON contains a duplicate key")
        result[key] = value
    return result


def _decode_object(encoded: bytes, label: str) -> dict[str, Any]:
    try:
        raw = json.loads(encoded, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"SPIKE-02 blocked: {label} is invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"SPIKE-02 blocked: {label} must be an object")
    return raw


def _validate(payload: dict[str, Any], schema_name: str, label: str) -> None:
    errors = sorted(
        Draft202012Validator(_schema(schema_name)).iter_errors(payload),
        key=lambda item: list(item.path),
    )
    if errors:
        raise ValueError(f"SPIKE-02 {label} schema violation: {errors[0].message}")


def _load_manifest(request: CoverageQualificationRequest) -> tuple[dict[str, Any], bytes]:
    if not _SHA256.fullmatch(request.expected_manifest_sha256):
        raise ValueError("SPIKE-02 blocked: corpus manifest digest is not canonical SHA-256")
    encoded = read_published_bytes(
        request.corpus_manifest,
        root=request.corpus_root,
        label="SPIKE-02 corpus manifest",
    )
    if _digest(encoded) != request.expected_manifest_sha256:
        raise ValueError("SPIKE-02 blocked: corpus manifest bytes differ from admitted digest")
    raw = _decode_object(encoded, "corpus manifest")
    _validate(raw, "conversion-coverage-corpus.schema.json", "corpus")
    if (
        contains_protected_data(json.dumps(raw, sort_keys=True))
        or sanitize_discovery_value(raw) != raw
    ):
        raise ValueError("SPIKE-02 blocked: corpus manifest contains unsafe durable content")
    subject_ids = [item["subject_id"] for item in raw["subjects"]]
    artifact_ids = [item["source_artifact_id"] for item in raw["subjects"]]
    if len(subject_ids) != len(set(subject_ids)) or len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError("SPIKE-02 blocked: corpus subject identities are ambiguous")
    return raw, encoded


def _result_path(request: CoverageQualificationRequest, coverage_id: str) -> Path:
    return (
        request.output_root
        / "runs"
        / _identity(request.run_id, "run_id")
        / "coverage"
        / _identity(request.attempt_id, "attempt_id")
        / coverage_id
        / "coverage.result.json"
    )


def _provider_request(
    request: CoverageQualificationRequest, subject: dict[str, Any]
) -> ProviderPackageRequest:
    source = request.corpus_root / subject["source_path"]
    provenance = request.corpus_root / subject["provenance_path"]
    return ProviderPackageRequest(
        source_file=source,
        source_root=request.corpus_root,
        output_root=request.output_root,
        client_id=_identity(request.client_id, "client_id"),
        deployment_id=_identity(request.deployment_id, "deployment_id"),
        environment_id=_identity(request.environment_id, "environment_id"),
        workload_id=_identity(subject["subject_id"], "subject_id"),
        source_artifact_id=_identity(subject["source_artifact_id"], "source_artifact_id"),
        run_id=_identity(request.run_id, "run_id"),
        attempt_id=_identity(request.attempt_id, "attempt_id"),
        expected_source_sha256=subject["source_sha256"],
        source_provenance_file=provenance,
        source_provenance_root=request.corpus_root,
        expected_source_provenance_sha256=subject["provenance_sha256"],
        target=subject["target"],
    )


def _construct_results(subjects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for subject in subjects:
        for construct in subject["constructs"]:
            grouped.setdefault(construct, []).append(subject)
    results: list[dict[str, Any]] = []
    for construct, members in sorted(grouped.items()):
        classification = max(
            (member["classification"] for member in members), key=_SEVERITY.__getitem__
        )
        results.append(
            {
                "construct": construct,
                "classification": classification,
                "subject_ids": sorted(member["subject_id"] for member in members),
                "generated_evidence": any(
                    member["generated_status"] != "not_generated" for member in members
                ),
                "static_validation": (
                    "passed"
                    if all(member["static_validation"] == "passed" for member in members)
                    else "not_run"
                ),
                "behavioral_validation": "not_executed",
                "parity": "not_evaluated",
            }
        )
    return results


def _subject_result(
    request: CoverageQualificationRequest,
    subject: dict[str, Any],
    *,
    build: bool,
) -> dict[str, Any]:
    provider_request = _provider_request(request, subject)
    if build:
        package_path = build_provider_package(provider_request)
    else:
        package_path = (
            request.output_root
            / "runs"
            / request.run_id
            / "workloads"
            / subject["subject_id"]
            / "attempts"
            / request.attempt_id
            / "conversion-packages"
            / subject["source_artifact_id"]
            / "package.manifest.json"
        )
    package = verify_provider_package(package_path, provider_request)
    classification = _STATUS[package["status"]]
    generated_status = (
        "packaged"
        if package["entrypoint"] is not None
        else "candidate"
        if package["candidate_artifact"] is not None
        else "not_generated"
    )
    route_to = None
    if package["status"] == "packaged":
        route_to = "VAL-01"
    elif classification == "partial":
        route_to = "AIREP-01"
    elif classification in {"unsupported", "unresolved"}:
        route_to = "CV-04"
    return {
        "subject_id": subject["subject_id"],
        "source_artifact_id": subject["source_artifact_id"],
        "source_sha256": subject["source_sha256"],
        "provenance_sha256": subject["provenance_sha256"],
        "constructs": subject["constructs"],
        "complexity": subject["complexity"],
        "classification": classification,
        "provider_status": package["status"],
        "generated_status": generated_status,
        "static_validation": "passed" if package["status"] == "packaged" else "not_run",
        "behavioral_validation": "not_executed",
        "parity": "not_evaluated",
        "route_to": route_to,
        "exception_codes": [item["code"] for item in package["exceptions"]],
        "package_manifest_uri": package_path.relative_to(request.output_root).as_posix(),
        "package_manifest_digest": package["content_digest"],
        "conversion_durations_ms": package["reproducibility"]["durations_ms"],
    }


def _payload(
    request: CoverageQualificationRequest,
    corpus: dict[str, Any],
    manifest_bytes: bytes,
    *,
    build: bool,
) -> dict[str, Any]:
    identity = {
        "client_id": _identity(request.client_id, "client_id"),
        "deployment_id": _identity(request.deployment_id, "deployment_id"),
        "environment_id": _identity(request.environment_id, "environment_id"),
        "run_id": _identity(request.run_id, "run_id"),
        "attempt_id": _identity(request.attempt_id, "attempt_id"),
        "corpus_id": _identity(corpus["corpus_id"], "corpus_id"),
        "corpus_revision": _identity(corpus["corpus_revision"], "corpus_revision"),
        "corpus_manifest_sha256": _digest(manifest_bytes),
    }
    subject_results = [
        _subject_result(request, subject, build=build) for subject in corpus["subjects"]
    ]
    construct_results = _construct_results(subject_results)
    counts = {
        name: sum(item["classification"] == name for item in subject_results)
        for name in ("supported", "partial", "unsupported", "unresolved")
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "coverage_id": stable_id("SPIKE02", identity),
        "identity": identity,
        "provider": {
            "name": "sas2databricks",
            "version": "0.4.0",
            "evaluation_scope": "bounded_deterministic_generation",
        },
        "implementation_manifest": _implementation_manifest(),
        "subjects": subject_results,
        "constructs": construct_results,
        "metrics": {
            "subject_count": len(subject_results),
            "construct_count": len(construct_results),
            "classification_counts": counts,
            "conversion_executions": sum(
                len(item["conversion_durations_ms"]) for item in subject_results
            ),
            "conversion_duration_ms": sum(
                sum(item["conversion_durations_ms"]) for item in subject_results
            ),
        },
        "claims": {
            "coverage_measured": True,
            "generated_candidates_present": any(
                item["generated_status"] != "not_generated" for item in subject_results
            ),
            "executed": False,
            "behaviorally_validated": False,
            "parity_passed": False,
            "customer_representative": False,
            "production_ready": False,
            "migration_complete": False,
        },
        "content_digest": "",
    }
    payload["content_digest"] = _content_digest(payload)
    return payload


def evaluate_conversion_coverage(request: CoverageQualificationRequest) -> Path:
    """Run the pinned deterministic provider over one governed, attributed corpus."""

    corpus, manifest_bytes = _load_manifest(request)
    identity = {
        "client_id": _identity(request.client_id, "client_id"),
        "deployment_id": _identity(request.deployment_id, "deployment_id"),
        "environment_id": _identity(request.environment_id, "environment_id"),
        "run_id": _identity(request.run_id, "run_id"),
        "attempt_id": _identity(request.attempt_id, "attempt_id"),
        "corpus_id": _identity(corpus["corpus_id"], "corpus_id"),
        "corpus_revision": _identity(corpus["corpus_revision"], "corpus_revision"),
        "corpus_manifest_sha256": _digest(manifest_bytes),
    }
    coverage_id = stable_id("SPIKE02", identity)
    result_path = _result_path(request, coverage_id)
    if result_path.exists():
        verify_conversion_coverage(result_path, request)
        return result_path

    payload = _payload(request, corpus, manifest_bytes, build=True)
    _validate(payload, "conversion-coverage-result.schema.json", "result")
    publish_json(result_path, payload, "SPIKE-02 coverage result", root=request.output_root)
    verify_conversion_coverage(result_path, request)
    return result_path


def verify_conversion_coverage(
    result_path: Path, request: CoverageQualificationRequest
) -> dict[str, Any]:
    """Replay the result against current corpus, source, provenance and package evidence."""

    result = _decode_object(
        read_published_bytes(
            result_path,
            root=request.output_root,
            label="SPIKE-02 coverage result",
        ),
        "coverage result",
    )
    _validate(result, "conversion-coverage-result.schema.json", "result")
    if result["content_digest"] != _content_digest(result):
        raise ValueError("SPIKE-02 result content digest mismatch")
    corpus, manifest_bytes = _load_manifest(request)
    expected = _payload(request, corpus, manifest_bytes, build=False)
    if result != expected:
        raise ValueError("SPIKE-02 current inputs do not reconstruct immutable evidence")
    expected_path = _result_path(request, result["coverage_id"])
    if result_path.absolute() != expected_path.absolute():
        raise ValueError("SPIKE-02 result is outside its canonical path")
    return result
