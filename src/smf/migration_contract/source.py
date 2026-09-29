"""Fail-closed source acquisition for the migration CLI scaffold."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

_PROTECTED_CANARY = re.compile(rb"(?i)(secret-canary|phi-canary|pii-canary)")
_SAS_INCLUDE_STATEMENT = re.compile(rb"(?is)%include\b.*?;")
_SAS_INCLUDE_TOKEN = re.compile(rb"(?i)%include\b")
_SAS_LITERAL_INCLUDE = re.compile(
    rb"(?is)\A%include\s+(?P<quote>['\"])(?P<path>[^'\"]+)(?P=quote)\s*;\Z"
)


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("Duplicate workload configuration key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _decode_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or urlparse(value).scheme:
        raise ValueError(f"{label} must be a non-empty relative path")
    decoded = value
    for _ in range(4):
        expanded = unquote(decoded)
        if expanded == decoded:
            break
        decoded = expanded
    path = Path(decoded)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} escapes the authorized source root")
    if _PROTECTED_CANARY.search(path.as_posix().encode("utf-8")):
        raise ValueError(f"{label} contains protected material")
    return path


def _read_stable(root: Path, relative: Path, label: str) -> tuple[bytes, os.stat_result]:
    unresolved = root / relative
    if any(
        root.joinpath(*relative.parts[:index]).is_symlink()
        for index in range(1, len(relative.parts) + 1)
    ):
        raise ValueError(f"{label} contains a symlink")
    resolved = unresolved.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} escapes the authorized source root")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    current = os.stat(resolved, follow_symlinks=False)
    identity_current = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    if identity_before != identity_after or identity_after != identity_current:
        raise ValueError("source_mutated_during_qualification")
    return b"".join(chunks), after


def _load_workload(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Workload configuration must be a regular file")
    before = path.stat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        raw = b""
        while chunk := os.read(descriptor, 1024 * 1024):
            raw += chunk
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = path.stat()
    identities = {
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (before, after, current)
    }
    if len(identities) != 1:
        raise ValueError("workload_configuration_mutated_during_qualification")
    if _PROTECTED_CANARY.search(raw):
        raise ValueError("Workload configuration contains protected material")
    try:
        payload = yaml.load(raw.decode("utf-8"), Loader=_UniqueLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("Invalid workload configuration") from exc
    if not isinstance(payload, dict):
        raise ValueError("Workload configuration must be an object")
    return payload, raw


def _literal_include_dependencies(raw: bytes, including: Path) -> list[Path]:
    """Return bounded literal SAS includes or reject an ambiguous include statement."""

    source = re.sub(rb"/\*.*?\*/", b"", raw, flags=re.DOTALL)
    source = re.sub(rb"(?m)^\s*\*[^;]*;", b"", source)
    statements = list(_SAS_INCLUDE_STATEMENT.finditer(source))
    remainder = _SAS_INCLUDE_STATEMENT.sub(b"", source)
    if _SAS_INCLUDE_TOKEN.search(remainder):
        raise ValueError("Source contains an unsupported or unterminated %include")
    dependencies: list[Path] = []
    for statement in statements:
        match = _SAS_LITERAL_INCLUDE.fullmatch(statement.group())
        if match is None:
            raise ValueError("Source contains a non-literal or unsupported %include")
        try:
            value = match.group("path").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Source contains a non-UTF-8 %include path") from exc
        dependency = _decode_relative(value, "Literal include")
        dependencies.append(
            _decode_relative((including.parent / dependency).as_posix(), "Literal include")
        )
    return dependencies


def acquire_source_snapshot(
    source_root: Path, workload_config: Path, workload_id: str
) -> dict[str, Any]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("Source root must be an authorized regular directory")
    root = source_root.resolve()
    payload, workload_bytes = _load_workload(workload_config)
    raw_workloads = payload.get("workloads")
    if raw_workloads is None:
        raw_workloads = [payload]
    if not isinstance(raw_workloads, list) or not raw_workloads:
        raise ValueError("Workload configuration requires non-empty workloads")
    workloads = [item for item in raw_workloads if isinstance(item, dict)]
    ids = [item.get("workload_id") for item in workloads]
    if any(not isinstance(item, str) or not item for item in ids):
        raise ValueError("Every workload requires a non-empty workload_id")
    folded = [str(item).casefold() for item in ids]
    if len(folded) != len(set(folded)):
        raise ValueError("Duplicate canonical workload identity")
    matches = [
        item for item in workloads if str(item["workload_id"]).casefold() == workload_id.casefold()
    ]
    if len(matches) != 1:
        raise ValueError("Workload identity is missing or ambiguous")
    workload = matches[0]
    entries = workload.get("entry_points", workload.get("entrypoints"))
    if entries is None:
        source_files = workload.get("source_files", [])
        if not isinstance(source_files, list):
            raise ValueError("Workload source_files must be an array")
        entries = [
            item
            for item in source_files
            if isinstance(item, dict) and item.get("type") == "sas_program"
        ]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Workload has no convertible entry point")
    if len(entries) != 1:
        raise ValueError("Workload requires exactly one unambiguous eligible entry point")

    inventory: list[dict[str, Any]] = []
    entry_ids: set[str] = set()
    normalized_paths: set[str] = set()
    for index, entry in enumerate(entries):
        entry_id: object
        if isinstance(entry, str):
            entry_id = f"entry-{index + 1}"
            path_value: object = entry
            entry_type = "sas_program"
        elif isinstance(entry, dict) and set(entry).issubset(
            {"entry_point_id", "entrypoint_id", "path", "type"}
        ):
            entry_id = entry.get("entry_point_id", entry.get("entrypoint_id", f"entry-{index + 1}"))
            path_value = entry.get("path")
            entry_type = entry.get("type", "sas_program")
        else:
            raise ValueError("Malformed workload entry point")
        if not isinstance(entry_id, str) or not entry_id or entry_id.casefold() in entry_ids:
            raise ValueError("Duplicate or unsafe entry-point identity")
        if entry_type not in {"sas_program", "sas-program", "sas"}:
            raise ValueError("Workload entry point is not convertible")
        relative = _decode_relative(path_value, "Entry point")
        normalized = relative.as_posix().casefold()
        if normalized in normalized_paths:
            raise ValueError("Duplicate normalized entry-point path")
        entry_ids.add(entry_id.casefold())
        normalized_paths.add(normalized)
        raw, file_stat = _read_stable(root, relative, "Entry point")
        meaningful = re.sub(rb"/\*.*?\*/", b"", raw, flags=re.DOTALL)
        meaningful = re.sub(rb"(?m)^\s*\*[^;]*;\s*$", b"", meaningful)
        if not meaningful.strip():
            raise ValueError("Workload entry point is empty")
        if _PROTECTED_CANARY.search(raw):
            raise ValueError("Source contains protected material")
        inventory.append(
            {
                "entry_point_id": entry_id,
                "path": relative.as_posix(),
                "byte_count": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "device": str(file_stat.st_dev),
                "inode": str(file_stat.st_ino),
            }
        )
    inventory.sort(key=lambda item: (str(item["path"]), str(item["entry_point_id"])))
    closure_values = workload.get("source_closure", workload.get("files"))
    explicit_closure = closure_values is not None
    if not explicit_closure:
        closure_values = [item["path"] for item in inventory]
    if not isinstance(closure_values, list) or not closure_values:
        raise ValueError("Workload source closure must be a non-empty array")
    source_inventory_by_path: dict[str, dict[str, Any]] = {}
    source_bytes_by_path: dict[str, bytes] = {}
    closure_paths: set[str] = set()
    for closure_value in closure_values:
        if isinstance(closure_value, dict) and set(closure_value) == {"path"}:
            closure_value = closure_value["path"]
        relative = _decode_relative(closure_value, "Source closure")
        normalized = relative.as_posix().casefold()
        if normalized in closure_paths:
            raise ValueError("Duplicate normalized source-closure path")
        closure_paths.add(normalized)
        raw, _ = _read_stable(root, relative, "Source closure")
        if not raw:
            raise ValueError("Source closure contains an empty artifact")
        if _PROTECTED_CANARY.search(raw):
            raise ValueError("Source contains protected material")
        source_bytes_by_path[normalized] = raw
        source_inventory_by_path[normalized] = {
            "path": relative.as_posix(),
            "byte_count": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    if not normalized_paths.issubset(closure_paths):
        raise ValueError("Source closure omits an eligible entry point")

    pending = [Path(item["path"]) for item in inventory]
    scanned: set[str] = set()
    while pending:
        including = pending.pop(0)
        normalized = including.as_posix().casefold()
        if normalized in scanned:
            continue
        scanned.add(normalized)
        raw = source_bytes_by_path[normalized]
        for dependency in _literal_include_dependencies(raw, including):
            dependency_key = dependency.as_posix().casefold()
            if dependency_key not in closure_paths:
                if explicit_closure:
                    raise ValueError("Source closure omits literal include dependency")
                dependency_raw, _ = _read_stable(root, dependency, "Literal include")
                if not dependency_raw:
                    raise ValueError("Source closure contains an empty artifact")
                if _PROTECTED_CANARY.search(dependency_raw):
                    raise ValueError("Source contains protected material")
                closure_paths.add(dependency_key)
                source_bytes_by_path[dependency_key] = dependency_raw
                source_inventory_by_path[dependency_key] = {
                    "path": dependency.as_posix(),
                    "byte_count": len(dependency_raw),
                    "sha256": hashlib.sha256(dependency_raw).hexdigest(),
                }
            pending.append(dependency)

    source_inventory = list(source_inventory_by_path.values())
    closure_by_path = {item["path"].casefold(): item for item in source_inventory}
    if any(
        item["sha256"] != closure_by_path[str(item["path"]).casefold()]["sha256"]
        for item in inventory
    ):
        raise ValueError("source_mutated_during_qualification")
    source_inventory.sort(key=lambda item: str(item["path"]))
    closure_digest = hashlib.sha256(
        json.dumps(source_inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "workload_id": str(workload["workload_id"]),
        "subject_id": inventory[0]["entry_point_id"]
        if len(inventory) == 1
        else "multiple-entry-points",
        "source_closure_digest": closure_digest,
        "workload_configuration_digest": hashlib.sha256(workload_bytes).hexdigest(),
        "workload_configuration_byte_count": len(workload_bytes),
        "eligible_entry_points": inventory,
        "source_inventory": source_inventory,
    }
