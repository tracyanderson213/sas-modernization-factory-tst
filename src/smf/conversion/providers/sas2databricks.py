from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from importlib.metadata import distribution
from pathlib import Path, PurePosixPath
from typing import Any

from smf.conversion.providers.base import ConversionProvider, ProviderResult

SUMMARY_PATTERN = re.compile(
    r"^model=(?P<model>\S+)\s+target=(?P<target>\S+)\s+steps=(?P<steps>\d+)\s+"
    r"review=(?P<review>\d+)\s+llm_escalations=(?P<llm_escalations>\d+)\s*$"
)
QUALIFIED_VERSION = "0.4.0"
EVALUATED_REVISION = "392d3a34c1390f6335fb47e165a4f4f3ac03111c"
QUALIFIED_PACKAGE_MANIFEST_SHA256 = (
    "9c351f836e620d70c2d73ad0f968a8aceda2928931214a9b08133fa6f842216b"
)
QUALIFIED_NORMALIZED_RECORD_SHA256 = (
    "bd0395eb772303b6d624a2434c19c81c76793dea2b055f61d18f56386afdd424"
)
QUALIFIED_LICENSE_SHA256 = "0e5c49601a1879520e327e9f10da5747b10368d549b5329545e3d5f744efa635"
LICENSE_EXPRESSION = "MIT"
LICENSE_DISPOSITION = "qualified_for_bounded_wrapper"
DEFAULT_THRESHOLD = "0.8"
_RUNNER_BYTES = (
    b"import json,sys\nsys.path.insert(0,sys.argv.pop(1))\n"
    b"from sas2databricks.pipeline import migrate_file\n"
    b"r=migrate_file(sys.argv[1],target=sys.argv[2],threshold=0.8)\n"
    b"print(json.dumps({'content':r.code,'summary':{'model':r.model.value,"
    b"'target':r.target,'steps':len(r.reports),'review':r.review_count,"
    b"'llm_escalations':len(r.llm_requests)}},sort_keys=True))\n"
)
_RUNTIME_DISTRIBUTIONS = {
    "sqlglot": (
        "30.17.0",
        ("sqlglot/",),
        "5597d80b4ad667013c4ed06c03143db53e0527b3ce2d58900244efbe64a99374",
    ),
    "PyYAML": (
        "6.0.3",
        ("yaml/",),
        "611b3f160be17edfe09e2cf84e1927951474ba2a302a1c4def99f4f8e3bb7195",
    ),
}


@dataclass(frozen=True)
class QualifiedProviderArtifact:
    executable_bytes: bytes
    executable_sha256: str
    record_sha256: str
    package_manifest_sha256: str
    license_bytes: bytes
    license_sha256: str
    staged_files: tuple[tuple[str, bytes], ...]
    runtime_files: tuple[tuple[str, bytes], ...]
    runtime_bindings: tuple[tuple[str, str, str], ...]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _record_digest(encoded: str) -> str:
    algorithm, value = encoded.split("=", 1)
    if algorithm != "sha256":
        raise RuntimeError("sas2databricks RECORD contains a non-SHA-256 digest")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).hex()


def _read_regular(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"sas2databricks {label} is symlinked or unavailable") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"sas2databricks {label} is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _python_runtime_identity() -> tuple[Path, str, str]:
    runtime = Path(sys.executable).resolve(strict=True)
    payload = _read_regular(runtime, "Python runtime")
    return runtime, ".".join(str(value) for value in sys.version_info[:3]), _sha256(payload)


def _qualified_provider_artifact() -> QualifiedProviderArtifact:
    """Reconstruct the installed wheel from its complete qualified RECORD."""

    installed = distribution("sas2databricks")
    if installed.version != QUALIFIED_VERSION:
        raise RuntimeError(
            f"sas2databricks version {installed.version!r} is not the qualified "
            f"{QUALIFIED_VERSION!r}"
        )
    dist_info = Path(installed._path)  # type: ignore[attr-defined]
    record_bytes = _read_regular(dist_info / "RECORD", "RECORD")
    record_sha256 = _sha256(record_bytes)
    rows = list(csv.reader(record_bytes.decode("utf-8").splitlines()))
    if not rows or any(len(row) != 3 for row in rows):
        raise RuntimeError("sas2databricks RECORD is malformed")
    seen: set[str] = set()
    verified: list[tuple[str, bytes]] = []
    executable_bytes: bytes | None = None
    license_bytes: bytes | None = None
    for name, encoded_digest, encoded_size in rows:
        member = PurePosixPath(name)
        special_launcher = name == "../../../bin/s2db"
        if (
            name in seen
            or member.is_absolute()
            or not member.parts
            or (not special_launcher and any(part in {"", ".", ".."} for part in member.parts))
        ):
            raise RuntimeError("sas2databricks RECORD contains an invalid or duplicate path")
        seen.add(name)
        path = Path(str(installed.locate_file(name)))
        if name.endswith(".pyc"):
            if encoded_digest or encoded_size:
                raise RuntimeError("sas2databricks RECORD unexpectedly hashes bytecode")
            continue
        if name.endswith("/RECORD"):
            if encoded_digest or encoded_size:
                raise RuntimeError("sas2databricks RECORD self-entry is invalid")
            continue
        if not encoded_digest or not encoded_size:
            raise RuntimeError("sas2databricks RECORD has an unhashed governed file")
        payload = _read_regular(path, "installed package member")
        if len(payload) != int(encoded_size) or _sha256(payload) != _record_digest(encoded_digest):
            raise RuntimeError("sas2databricks installed package differs from qualified RECORD")
        if name == "../../../bin/s2db":
            executable_bytes = payload
        elif name.endswith(".dist-info/licenses/LICENSE"):
            license_bytes = payload
        elif name.startswith("sas2databricks/") and name.endswith((".py", ".typed")):
            verified.append((name, payload))
    if executable_bytes is None or license_bytes is None or not verified:
        raise RuntimeError("sas2databricks qualified package is incomplete")
    license_sha256 = _sha256(license_bytes)
    if license_sha256 != QUALIFIED_LICENSE_SHA256:
        raise RuntimeError("sas2databricks license bytes differ from the qualified MIT license")
    package_manifest = "\n".join(
        f"{name}\0{_sha256(payload)}\0{len(payload)}" for name, payload in sorted(verified)
    ).encode()
    package_manifest_sha256 = _sha256(package_manifest)
    if package_manifest_sha256 != QUALIFIED_PACKAGE_MANIFEST_SHA256:
        raise RuntimeError("sas2databricks installed code is not the qualified artifact")
    normalized_record = (
        "\n".join(
            "../../../bin/s2db,<environment-generated-launcher>"
            if row[0] == "../../../bin/s2db"
            else ",".join(row)
            for row in rows
            if not row[0].endswith(".pyc")
        ).encode()
        + b"\n"
    )
    if _sha256(normalized_record) != QUALIFIED_NORMALIZED_RECORD_SHA256:
        raise RuntimeError("sas2databricks RECORD member set is not the qualified artifact")
    runtime_files: list[tuple[str, bytes]] = []
    runtime_bindings: list[tuple[str, str, str]] = []
    for dist_name, (
        required_version,
        prefixes,
        expected_manifest,
    ) in _RUNTIME_DISTRIBUTIONS.items():
        runtime_dist = distribution(dist_name)
        if runtime_dist.version != required_version:
            raise RuntimeError(f"sas2databricks runtime dependency {dist_name} is not qualified")
        members: list[tuple[str, bytes]] = []
        for entry in runtime_dist.files or ():
            relative = str(entry)
            member = PurePosixPath(relative)
            if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
                raise RuntimeError("sas2databricks runtime dependency contains an invalid path")
            # Stage only the qualified, platform-independent Python import closure.
            # PyYAML wheels may also contain a platform-specific ``_yaml`` extension;
            # the deterministic converter does not require it, and admitting it would
            # make the governed manifest differ between Linux and macOS.
            if relative.startswith(prefixes) and relative.endswith((".py", ".typed")):
                members.append(
                    (
                        relative,
                        _read_regular(Path(str(runtime_dist.locate_file(entry))), "runtime member"),
                    )
                )
        manifest = "\n".join(
            f"{name}\0{_sha256(payload)}\0{len(payload)}" for name, payload in sorted(members)
        ).encode()
        manifest_sha256 = _sha256(manifest)
        if not members or manifest_sha256 != expected_manifest:
            raise RuntimeError(f"sas2databricks runtime dependency {dist_name} is not qualified")
        runtime_files.extend(members)
        runtime_bindings.append((dist_name, required_version, manifest_sha256))
    return QualifiedProviderArtifact(
        executable_bytes=_RUNNER_BYTES,
        executable_sha256=_sha256(_RUNNER_BYTES),
        record_sha256=record_sha256,
        package_manifest_sha256=package_manifest_sha256,
        license_bytes=license_bytes,
        license_sha256=license_sha256,
        staged_files=tuple(verified),
        runtime_files=tuple(runtime_files),
        runtime_bindings=tuple(runtime_bindings),
    )


def _parse_cli_output(stdout: str) -> tuple[str, dict[str, Any], list[str]]:
    lines = stdout.splitlines()
    metadata: dict[str, Any] = {}
    warnings: list[str] = []
    if lines:
        match = SUMMARY_PATTERN.match(lines[-1].strip())
        if match:
            metadata = {
                "model": match.group("model"),
                "target": match.group("target"),
                "steps": int(match.group("steps")),
                "review": int(match.group("review")),
                "llm_escalations": int(match.group("llm_escalations")),
            }
            lines = lines[:-1]
    content = "\n".join(lines).rstrip() + "\n"
    if int(metadata.get("review", 0)) > 0:
        warnings.append("sas2databricks flagged conversion step(s) for manual review.")
    if int(metadata.get("llm_escalations", 0)) > 0:
        warnings.append("sas2databricks reported LLM escalation(s).")
    if "pending host fulfillment" in content.lower():
        warnings.append("sas2databricks emitted a pending-host-fulfillment/manual-review stub.")
    return content, metadata, warnings


def _offline_environment() -> dict[str, str]:
    result = {
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR"):
        value = os.environ.get(key)
        if value:
            result[key] = value
    return result


class Sas2DatabricksProvider(ConversionProvider):
    """Adapter around the byte-qualified sas2databricks CLI."""

    name = "sas2databricks"

    def convert(self, source_file: Path, target: str) -> ProviderResult:
        if target not in {"pyspark", "sparksql"}:
            raise ValueError("sas2databricks target is not admitted by the SMF provider")
        if source_file.is_symlink() or not source_file.is_file():
            raise ValueError("sas2databricks source must be a regular non-symlink file")
        artifact = _qualified_provider_artifact()
        python_runtime, python_version, python_sha256 = _python_runtime_identity()
        with tempfile.TemporaryDirectory(prefix="smf-s2db-provider-") as temporary:
            stage = Path(temporary)
            executable = stage / "smf_s2db_runner.py"
            executable.write_bytes(artifact.executable_bytes)
            executable.chmod(0o400)
            for relative, payload in artifact.staged_files:
                destination = stage / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                destination.chmod(0o400)
            for relative, payload in artifact.runtime_files:
                destination = stage / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                destination.chmod(0o400)
            completed = subprocess.run(
                [
                    str(python_runtime),
                    "-I",
                    "-S",
                    str(executable),
                    str(stage),
                    str(source_file),
                    target,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env=_offline_environment(),
            )
        if completed.returncode != 0:
            raise RuntimeError("sas2databricks conversion failed; inspect isolated local logs")
        try:
            response = json.loads(completed.stdout)
            content = response["content"]
            summary_metadata = response["summary"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError("sas2databricks conversion omitted its required result") from exc
        warnings: list[str] = []
        if set(summary_metadata) != {"model", "target", "steps", "review", "llm_escalations"}:
            raise RuntimeError("sas2databricks conversion omitted its required summary")
        if summary_metadata["target"] != target:
            raise RuntimeError("sas2databricks conversion reported a mismatched target")
        if not content.strip():
            raise RuntimeError("sas2databricks conversion returned an empty artifact")
        if summary_metadata["steps"] == 0:
            warnings.append("sas2databricks found no meaningful convertible steps.")
        metadata: dict[str, Any] = {
            "command": [
                "s2db",
                "convert",
                "<admitted-source>",
                "--target",
                target,
                "--threshold",
                DEFAULT_THRESHOLD,
            ],
            "target": target,
            "summary": summary_metadata,
            "provider_version": QUALIFIED_VERSION,
            "evaluated_revision": EVALUATED_REVISION,
            "record_sha256": artifact.record_sha256,
            "package_manifest_sha256": artifact.package_manifest_sha256,
            "executable_sha256": artifact.executable_sha256,
            "license_expression": LICENSE_EXPRESSION,
            "license_sha256": artifact.license_sha256,
            "license_disposition": LICENSE_DISPOSITION,
            "runtime_bindings": [
                {"distribution": name, "version": version, "manifest_sha256": digest}
                for name, version, digest in artifact.runtime_bindings
            ],
            "python_version": python_version,
            "python_executable_sha256": python_sha256,
            "credential_environment_forwarded": False,
            "direct_provider_access_authorized": False,
        }
        return ProviderResult(
            content=content,
            provider=self.name,
            metadata=metadata,
            warnings=warnings,
        )
