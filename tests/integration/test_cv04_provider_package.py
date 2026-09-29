from __future__ import annotations

import hashlib
import json
import os
from importlib.metadata import distribution, version
from pathlib import Path

import jsonschema
import pytest

from smf.conversion import (
    ProviderPackageRequest,
    build_provider_package,
    verify_provider_package,
)
from smf.conversion.providers import sas2databricks as provider_module
from smf.conversion.providers.base import ProviderResult
from smf.conversion.providers.sas2databricks import QUALIFIED_VERSION

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "tests" / "corpus" / "workloads" / "public"
REPRESENTATIVE = ROOT / "tests" / "corpus" / "workloads" / "representative"
SCHEMA = ROOT / "schemas" / "conversion-provider-package.schema.json"
PUBLIC_MANIFEST = (
    ROOT / "tests" / "corpus" / "manifests" / "public-sas-official-language-breadth.yaml"
)
REPRESENTATIVE_MANIFEST = (
    ROOT / "tests" / "corpus" / "manifests" / "representative-multi-artifact-foundation.yaml"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_provider() -> None:
    try:
        installed = version("sas2databricks")
    except Exception:
        installed = ""
    if installed != QUALIFIED_VERSION:
        if os.environ.get("SMF_REQUIRE_CV04") == "1":
            pytest.fail(f"CV-04 requires sas2databricks {QUALIFIED_VERSION}, found {installed!r}")
        pytest.skip("CV-04 qualified conversion provider is unavailable")


def _request(source: Path, output: Path, **changes: object) -> ProviderPackageRequest:
    if "multi-artifact-foundation" not in source.parts:
        provenance = {
            "evidence_id": "sas-code-examples-579e057f",
            "artifact_id": f"{source.stem}-sas",
            "artifact_sha256": _sha256(source),
            "origin": "https://github.com/sassoftware/sas-code-examples",
            "revision": "579e057f90cd699f744fd6a1c8acaf9243f7ff67",
            "license": "Apache-2.0",
        }
    else:
        provenance = {
            "evidence_id": "smf-representative-v1",
            "artifact_id": f"{source.stem}-sas",
            "artifact_sha256": _sha256(source),
            "origin": "smf-owned-representative-corpus",
            "revision": "representative-multi-artifact-foundation-v1",
            "license": "Apache-2.0",
        }
    provenance_root = output.parent / f"{output.name}-provenance"
    provenance_root.mkdir(parents=True, exist_ok=True)
    provenance_file = provenance_root / "source-provenance.json"
    provenance_file.write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
    values: dict[str, object] = {
        "source_file": source,
        "source_root": ROOT,
        "output_root": output,
        "client_id": "public-fixture",
        "deployment_id": "offline-test",
        "environment_id": "local",
        "workload_id": source.stem,
        "source_artifact_id": f"{source.stem}-sas",
        "run_id": "cv04-run",
        "attempt_id": "attempt-1",
        "expected_source_sha256": _sha256(source),
        "target": "pyspark",
        "source_provenance_file": provenance_file,
        "source_provenance_root": provenance_root,
        "expected_source_provenance_sha256": _sha256(provenance_file),
    }
    values.update(changes)
    return ProviderPackageRequest(**values)  # type: ignore[arg-type]


def test_real_program_builds_reproducible_offline_package(tmp_path: Path) -> None:
    _require_provider()
    source = PUBLIC / "sas-code-examples" / "create-column-select.sas"
    request = _request(source, tmp_path / "out")

    manifest_path = build_provider_package(request)
    manifest = verify_provider_package(manifest_path, request)

    assert manifest["status"] == "packaged"
    assert manifest["provider"]["version"] == "0.4.0"
    assert manifest["provider"]["evaluated_revision"] == (
        "392d3a34c1390f6335fb47e165a4f4f3ac03111c"
    )
    assert manifest["provider"]["credential_environment_forwarded"] is False
    assert manifest["provider"]["direct_provider_access_authorized"] is False
    assert manifest["provider"]["license"]["expression"] == "MIT"
    assert manifest["provider"]["license"]["disposition"] == ("qualified_for_bounded_wrapper")
    assert manifest["reproducibility"]["executions"] == 2
    assert manifest["reproducibility"]["outputs_equal"] is True
    assert manifest["claims"] == {
        "generated": True,
        "package_ready": True,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "human_assisted": False,
        "ai_repaired": False,
        "production_ready": False,
        "migration_complete": False,
    }
    entrypoint = manifest_path.parent / manifest["entrypoint"]
    generated = entrypoint.read_text(encoding="utf-8")
    assert f"artifact:{request.source_artifact_id}" in generated
    assert str(source) not in generated
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(manifest)
    assert build_provider_package(request) == manifest_path


def test_real_review_and_unsupported_programs_fail_closed(tmp_path: Path) -> None:
    _require_provider()
    review_source = PUBLIC / "sas-code-examples" / "by-groupformat.sas"
    review_request = _request(review_source, tmp_path / "review")
    review_manifest = verify_provider_package(
        build_provider_package(review_request), review_request
    )
    assert review_manifest["status"] == "review_required"
    assert review_manifest["entrypoint"] is None
    assert review_manifest["candidate_artifact"] == "candidate.py"
    assert review_manifest["claims"]["package_ready"] is False
    assert review_manifest["claims"]["ai_repaired"] is False
    assert review_manifest["exceptions"][0]["code"] == "UPSTREAM_REVIEW_REQUIRED"

    unsupported_source = REPRESENTATIVE / "multi-artifact-foundation" / "source" / "main.sas"
    unsupported_request = _request(unsupported_source, tmp_path / "unsupported")
    unsupported_manifest = verify_provider_package(
        build_provider_package(unsupported_request), unsupported_request
    )
    assert unsupported_manifest["status"] == "unsupported"
    assert unsupported_manifest["generated_sha256"] is None
    assert unsupported_manifest["exceptions"][0]["code"] == "NO_CONVERTIBLE_STEPS"


def test_mutation_symlink_identity_and_isolation_are_rejected(tmp_path: Path) -> None:
    _require_provider()
    source = PUBLIC / "sas-code-examples" / "create-column-select.sas"
    first = _request(source, tmp_path / "out", workload_id="workload-a")
    second = _request(
        source,
        tmp_path / "out",
        workload_id="workload-b",
        attempt_id="attempt-2",
    )
    first_path = build_provider_package(first)
    second_path = build_provider_package(second)
    assert first_path != second_path
    assert first_path.read_bytes() != second_path.read_bytes()

    entrypoint = first_path.parent / "entrypoint.py"
    entrypoint.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact digest mismatch"):
        verify_provider_package(first_path, first)

    linked = tmp_path / "linked.sas"
    linked.symlink_to(source)
    linked_request = _request(
        linked,
        tmp_path / "linked-out",
        source_root=tmp_path,
        expected_source_sha256=_sha256(source),
    )
    with pytest.raises(ValueError, match="symlinked|regular file"):
        build_provider_package(linked_request)

    canary = "api_key-super-secret-canary"
    unsafe = _request(source, tmp_path / "unsafe", workload_id=canary)
    with pytest.raises(ValueError) as caught:
        build_provider_package(unsafe)
    assert canary not in str(caught.value)


def test_source_mutation_and_manifest_schema_mutation_are_rejected(tmp_path: Path) -> None:
    _require_provider()
    copied_root = tmp_path / "source"
    copied_root.mkdir()
    copied = copied_root / "program.sas"
    original = PUBLIC / "sas-code-examples" / "create-column-select.sas"
    copied.write_bytes(original.read_bytes())
    request = _request(copied, tmp_path / "out", source_root=copied_root)
    manifest_path = build_provider_package(request)

    copied.write_text("data changed; run;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source changed"):
        verify_provider_package(manifest_path, request)

    copied.write_bytes(original.read_bytes())
    manifest = json.loads(manifest_path.read_text())
    manifest["unexpected"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="schema violation|digest mismatch"):
        verify_provider_package(manifest_path, request)


def test_provenance_mutation_and_protected_payloads_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_provider()
    original = PUBLIC / "sas-code-examples" / "create-column-select.sas"
    request = _request(original, tmp_path / "provenance")
    manifest = build_provider_package(request)
    request.source_provenance_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="provenance bytes differ"):
        verify_provider_package(manifest, request)

    secret_source = tmp_path / "secret.sas"
    secret_source.write_text("%let api_key=super-secret-canary;\ndata x; run;\n")
    secret_request = _request(secret_source, tmp_path / "secret-out", source_root=tmp_path)
    with pytest.raises(ValueError) as source_error:
        build_provider_package(secret_request)
    assert "super-secret-canary" not in str(source_error.value)

    output_request = _request(original, tmp_path / "secret-generated")

    def secret_convert(*_args: object, **_kwargs: object) -> ProviderResult:
        return ProviderResult(
            content="# api_key=generated-secret-canary\nprint('x')\n",
            provider="sas2databricks",
            metadata={
                "summary": {
                    "model": "deterministic",
                    "target": "pyspark",
                    "steps": 1,
                    "review": 0,
                    "llm_escalations": 0,
                }
            },
            warnings=[],
        )

    monkeypatch.setattr(provider_module.Sas2DatabricksProvider, "convert", secret_convert)
    with pytest.raises(ValueError) as output_error:
        build_provider_package(output_request)
    assert "generated-secret-canary" not in str(output_error.value)


def test_forged_path_is_ignored_and_package_mutation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_provider()
    source = PUBLIC / "sas-code-examples" / "create-column-select.sas"
    forged = tmp_path / "forged"
    forged.mkdir()
    fake_cli = forged / "s2db"
    fake_cli.write_text("#!/bin/sh\necho forged\n", encoding="utf-8")
    fake_cli.chmod(0o700)
    monkeypatch.setenv("PATH", f"{forged}:{os.environ.get('PATH', '')}")
    request = _request(source, tmp_path / "forged-path-out")
    assert verify_provider_package(build_provider_package(request), request)["status"] == "packaged"

    actual = distribution("sas2databricks")
    mutated = tmp_path / "cli.py"
    mutated.write_text("# mutated package member\n", encoding="utf-8")

    class MutatedDistribution:
        version = actual.version
        _path = actual._path

        def locate_file(self, name: str) -> Path:
            if str(name) == "sas2databricks/cli.py":
                return mutated
            return Path(actual.locate_file(name))

    monkeypatch.setattr(provider_module, "distribution", lambda _name: MutatedDistribution())
    with pytest.raises(RuntimeError, match="differs from qualified RECORD"):
        provider_module._qualified_provider_artifact()


def test_record_traversal_and_runtime_dependency_mutation_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_provider = distribution("sas2databricks")
    fake_info = tmp_path / "sas2databricks-0.4.0.dist-info"
    fake_info.mkdir()
    record = Path(actual_provider._path) / "RECORD"  # type: ignore[attr-defined]
    (fake_info / "RECORD").write_bytes(
        record.read_bytes() + b"../escape.py,sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,1\n"
    )

    class TraversalDistribution:
        version = actual_provider.version
        _path = fake_info

        def locate_file(self, name: str) -> Path:
            return Path(str(actual_provider.locate_file(name)))

    monkeypatch.setattr(provider_module, "distribution", lambda _name: TraversalDistribution())
    with pytest.raises(RuntimeError, match="invalid or duplicate path"):
        provider_module._qualified_provider_artifact()

    actual_sqlglot = distribution("sqlglot")
    mutated = tmp_path / "sqlglot-init.py"
    mutated.write_text("# mutated runtime dependency\n", encoding="utf-8")

    class MutatedRuntimeDistribution:
        version = actual_sqlglot.version
        files = actual_sqlglot.files

        def locate_file(self, name: str) -> Path:
            if str(name) == "sqlglot/__init__.py":
                return mutated
            return Path(str(actual_sqlglot.locate_file(name)))

    def selected_distribution(name: str):  # type: ignore[no-untyped-def]
        if name == "sas2databricks":
            return actual_provider
        if name == "sqlglot":
            return MutatedRuntimeDistribution()
        return distribution(name)

    monkeypatch.setattr(provider_module, "distribution", selected_distribution)
    with pytest.raises(RuntimeError, match="runtime dependency sqlglot is not qualified"):
        provider_module._qualified_provider_artifact()


def test_runtime_closure_is_platform_independent_python_source() -> None:
    artifact = provider_module._qualified_provider_artifact()
    runtime_names = [name for name, _payload in artifact.runtime_files]

    assert runtime_names
    assert all(name.endswith((".py", ".typed")) for name in runtime_names)
    assert not any(name.endswith((".so", ".pyd", ".dll", ".dylib")) for name in runtime_names)
    assert (
        "PyYAML",
        "6.0.3",
        "611b3f160be17edfe09e2cf84e1927951474ba2a302a1c4def99f4f8e3bb7195",
    ) in artifact.runtime_bindings


def test_public_and_packaged_schemas_are_identical() -> None:
    public = SCHEMA.read_bytes()
    packaged = (
        ROOT / "src" / "smf" / "schemas" / "conversion-provider-package.schema.json"
    ).read_bytes()
    assert public == packaged
