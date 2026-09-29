from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from smf.conversion import (
    CoverageQualificationRequest,
    evaluate_conversion_coverage,
    verify_conversion_coverage,
)

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "corpus"
MANIFEST = CORPUS / "manifests" / "spike02-sas2databricks-coverage.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _request(output: Path, **changes: object) -> CoverageQualificationRequest:
    values: dict[str, object] = {
        "corpus_manifest": MANIFEST,
        "corpus_root": CORPUS,
        "output_root": output,
        "expected_manifest_sha256": _sha(MANIFEST),
        "client_id": "public-fixture",
        "deployment_id": "offline-test",
        "environment_id": "local",
        "run_id": "spike02-run",
        "attempt_id": "attempt-1",
    }
    values.update(changes)
    return CoverageQualificationRequest(**values)  # type: ignore[arg-type]


def test_real_attributed_corpus_produces_truthful_construct_coverage(tmp_path: Path) -> None:
    request = _request(tmp_path / "out")
    result_path = evaluate_conversion_coverage(request)
    result = verify_conversion_coverage(result_path, request)

    assert [item["classification"] for item in result["subjects"]] == [
        "partial",
        "partial",
        "unsupported",
    ]
    assert result["metrics"]["classification_counts"] == {
        "supported": 0,
        "partial": 2,
        "unsupported": 1,
        "unresolved": 0,
    }
    assert result["metrics"]["conversion_executions"] == 6
    assert result["provider"] == {
        "name": "sas2databricks",
        "version": "0.4.0",
        "evaluation_scope": "bounded_deterministic_generation",
    }
    assert result["claims"] == {
        "coverage_measured": True,
        "generated_candidates_present": True,
        "executed": False,
        "behaviorally_validated": False,
        "parity_passed": False,
        "customer_representative": False,
        "production_ready": False,
        "migration_complete": False,
    }
    assert all(item["behavioral_validation"] == "not_executed" for item in result["subjects"])
    assert all(item["parity"] == "not_evaluated" for item in result["subjects"])
    assert all(item["behavioral_validation"] == "not_executed" for item in result["constructs"])
    assert {item["route_to"] for item in result["subjects"]} == {
        "VAL-01",
        "AIREP-01",
        "CV-04",
    }
    assert evaluate_conversion_coverage(request).read_bytes() == result_path.read_bytes()


def test_packaged_and_repository_schemas_are_byte_identical() -> None:
    for name in (
        "conversion-coverage-corpus.schema.json",
        "conversion-coverage-result.schema.json",
    ):
        assert (ROOT / "schemas" / name).read_bytes() == (
            ROOT / "src" / "smf" / "schemas" / name
        ).read_bytes()


def test_current_source_package_and_coherent_result_mutations_fail(tmp_path: Path) -> None:
    request = _request(tmp_path / "out")
    result_path = evaluate_conversion_coverage(request)
    canonical = result_path.read_text()
    result = json.loads(canonical)

    result_path.write_text('{"schema_version":"1.0",' + canonical[1:])
    with pytest.raises(ValueError, match="duplicate key"):
        verify_conversion_coverage(result_path, request)

    result["subjects"][0]["classification"] = "unsupported"
    subject = {key: value for key, value in result.items() if key != "content_digest"}
    result["content_digest"] = hashlib.sha256(
        json.dumps(subject, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    result_path.write_text(json.dumps(result))
    with pytest.raises(ValueError, match="reconstruct immutable evidence"):
        verify_conversion_coverage(result_path, request)

    other = _request(tmp_path / "other")
    other_result = evaluate_conversion_coverage(other)
    package_uri = json.loads(other_result.read_text())["subjects"][0]["package_manifest_uri"]
    package_path = other.output_root / package_uri
    package = json.loads(package_path.read_text())
    package["status"] = "unsupported"
    package_path.write_text(json.dumps(package))
    with pytest.raises(ValueError, match="schema violation|digest mismatch|claims"):
        verify_conversion_coverage(other_result, other)


def test_manifest_source_and_path_boundaries_fail_closed(tmp_path: Path) -> None:
    copied = tmp_path / "corpus"
    shutil.copytree(CORPUS, copied)
    copied_manifest = copied / "manifests" / MANIFEST.name
    request = _request(
        tmp_path / "out",
        corpus_root=copied,
        corpus_manifest=copied_manifest,
        expected_manifest_sha256=_sha(copied_manifest),
    )
    result_path = evaluate_conversion_coverage(request)
    copied_source = copied / "workloads/public/sas-code-examples/create-column-select.sas"
    copied_source.write_text("proc sql; create table changed as select 1; quit;\n")
    with pytest.raises(ValueError, match="source changed|admitted digest"):
        verify_conversion_coverage(result_path, request)

    duplicate = copied_manifest.read_text()
    copied_manifest.write_text('{"schema_version":"1.0",' + duplicate[1:])
    with pytest.raises(ValueError, match="duplicate key"):
        evaluate_conversion_coverage(
            replace(
                request,
                expected_manifest_sha256=_sha(copied_manifest),
                output_root=tmp_path / "duplicate-out",
            )
        )

    linked = tmp_path / "linked.json"
    linked.symlink_to(copied_manifest)
    with pytest.raises(ValueError, match="symlinked|regular file"):
        evaluate_conversion_coverage(
            replace(
                request,
                corpus_manifest=linked,
                corpus_root=tmp_path,
                expected_manifest_sha256=_sha(copied_manifest),
                output_root=tmp_path / "linked-out",
            )
        )


def test_secret_canary_and_cross_workload_isolation(tmp_path: Path) -> None:
    canary = "api_key-super-secret-canary"
    with pytest.raises(ValueError) as caught:
        evaluate_conversion_coverage(_request(tmp_path / "unsafe", client_id=canary))
    assert canary not in str(caught.value)

    first_request = _request(tmp_path / "isolated", run_id="run-a")
    second_request = _request(tmp_path / "isolated", run_id="run-b")
    first = evaluate_conversion_coverage(first_request)
    second = evaluate_conversion_coverage(second_request)
    assert first != second
    assert first.read_bytes() != second.read_bytes()
    with pytest.raises(ValueError, match="canonical path|identity|reconstruct immutable evidence"):
        verify_conversion_coverage(first, second_request)
