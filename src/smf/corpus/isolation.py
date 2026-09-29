"""Hard isolation boundary for private client corpus evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import jsonschema
import yaml

from smf.corpus.loader import load_corpus_manifest
from smf.corpus.models import CorpusManifest

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "private-corpus-policy.schema.json"


_SHARED_CORPUS_ROOTS = (Path("tests/corpus"),)
_FORBIDDEN_PRIVATE_PATHS = (
    Path("tests/corpus/private"),
    Path("tests/corpus/workloads/private"),
    Path("private-corpus"),
)


def validate_shared_corpus_boundary(repository_root: Path) -> None:
    """Fail if private client corpus evidence is present inside the shared repository."""

    root = repository_root.resolve()
    violations: list[str] = []
    for relative in _FORBIDDEN_PRIVATE_PATHS:
        candidate = root / relative
        if candidate.exists():
            violations.append(f"forbidden private corpus path exists: {relative}")

    for relative in _SHARED_CORPUS_ROOTS:
        corpus_root = root / relative
        if not corpus_root.is_dir():
            continue
        for manifest_path in sorted((*corpus_root.rglob("*.yaml"), *corpus_root.rglob("*.yml"))):
            with manifest_path.open(encoding="utf-8") as handle:
                payload = yaml.safe_load(handle)
            if not isinstance(payload, dict):
                continue
            source = payload.get("source")
            if isinstance(source, dict) and source.get("origin") == "private-client":
                violations.append(
                    "private-client corpus manifest is stored in shared repository: "
                    f"{manifest_path.relative_to(root)}"
                )

    if violations:
        details = "\n".join(f"- {item}" for item in violations)
        raise ValueError(f"Private corpus repository boundary violation(s):\n{details}")


@dataclass(frozen=True)
class PrivateCorpusPolicy:
    """Client-specific controls required before private evidence can be loaded."""

    client_id: str
    storage_root: Path
    allowed_principals: tuple[str, ...]
    retention_max_days: int
    execution_workspace_id: str
    network_boundary: str


def _read_schema(schema_path: Path | None = None) -> dict[str, Any]:
    path = schema_path or _SCHEMA_PATH
    with path.open(encoding="utf-8") as handle:
        return cast(dict[str, Any], json.load(handle))


def validate_private_corpus_policy(
    payload: dict[str, Any], schema_path: Path | None = None
) -> None:
    """Validate mandatory private-corpus security and lifecycle controls."""

    jsonschema.validate(instance=payload, schema=_read_schema(schema_path))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def load_private_corpus_policy(
    path: Path, *, repository_root: Path, schema_path: Path | None = None
) -> PrivateCorpusPolicy:
    """Load a client policy and prove its storage root is outside the repository."""

    with path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"Private corpus policy must contain a mapping: {path}")
    payload = cast(dict[str, Any], raw)
    validate_private_corpus_policy(payload, schema_path=schema_path)

    storage = cast(dict[str, Any], payload["storage"])
    storage_root = Path(str(storage["root"])).expanduser().resolve()
    if _is_within(storage_root, repository_root):
        raise ValueError(
            f"Private corpus storage root must be outside the repository: {storage_root}"
        )

    access = cast(dict[str, Any], payload["access"])
    retention = cast(dict[str, Any], payload["retention"])
    execution = cast(dict[str, Any], payload["execution"])
    return PrivateCorpusPolicy(
        client_id=str(payload["client_id"]),
        storage_root=storage_root,
        allowed_principals=tuple(str(item) for item in access["allowed_principals"]),
        retention_max_days=int(retention["max_days"]),
        execution_workspace_id=str(execution["workspace_id"]),
        network_boundary=str(execution["network_boundary"]),
    )


def load_private_corpus_manifest(
    manifest_path: Path,
    *,
    policy: PrivateCorpusPolicy,
    principal: str,
    verify_files: bool = True,
) -> CorpusManifest:
    """Load private evidence only inside its client boundary and for an allowed principal."""

    resolved = manifest_path.resolve()
    if principal not in policy.allowed_principals:
        raise PermissionError(f"Principal is not authorized for client corpus {policy.client_id}")
    if not _is_within(resolved, policy.storage_root):
        raise ValueError(
            "Private corpus manifest must remain inside the configured client storage root: "
            f"{resolved}"
        )
    manifest = load_corpus_manifest(resolved, verify_files=verify_files, allow_private=True)
    if manifest.source.origin != "private-client":
        raise ValueError("Private corpus loader requires source.origin=private-client")
    expected_source_id = f"client:{policy.client_id}"
    if manifest.source.source_id != expected_source_id:
        raise ValueError(
            "Private corpus source_id must bind evidence to its client boundary: "
            f"expected {expected_source_id!r}, got {manifest.source.source_id!r}"
        )
    for artifact in manifest.artifacts:
        if not _is_within(artifact.path, policy.storage_root):
            raise ValueError(
                f"Private corpus artifact escapes client storage root: {artifact.path}"
            )
    return manifest
