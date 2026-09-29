"""Strict qualification for the TASK-05 synthetic macro fixture corpus.

The manifest is a test oracle only.  Loading it never creates production evidence
or authorizes a discovery/readiness outcome.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, cast

from smf.discovery import discover_source
from smf.workload.models import (
    MacroConstructFamily,
    MacroObservationKind,
    MacroResolutionKind,
)

_ROOT_KEYS = {"schema_version", "corpus_id", "scenarios"}
_SCENARIO_KEYS = {
    "scenario_id",
    "category",
    "namespace",
    "root",
    "sources",
    "expected",
    "non_claims",
}
_SOURCE_KEYS = {"path", "size", "sha256"}
_EXPECTED_KEYS = {
    "complete",
    "observation_kinds",
    "resolution_kinds",
    "blocker_reasons",
    "construct_families",
    "calls_edges",
    "include_occurrences",
}
_NON_CLAIMS = {
    "expansion",
    "generation",
    "execution",
    "validation",
    "parity",
    "certification",
    "human_approval",
}
_IDENTITY = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CATEGORIES = {"positive", "negative", "adversarial"}


@dataclass(frozen=True)
class QualifiedSource:
    relative_path: str
    size: int
    sha256: str
    content: bytes


@dataclass(frozen=True)
class QualifiedMacroScenario:
    scenario_id: str
    category: str
    namespace: str
    root: Path
    sources: tuple[QualifiedSource, ...]
    expected: Mapping[str, Any]


def _qualified_inventory(
    scenario: QualifiedMacroScenario,
) -> set[tuple[str, int, str]]:
    return {(source.relative_path, source.size, source.sha256) for source in scenario.sources}


def _revalidate_qualified_sources(scenario: QualifiedMacroScenario) -> None:
    """Fail before analysis if the mutable fixture tree no longer matches qualification."""

    if scenario.root.is_symlink() or not scenario.root.resolve(strict=True).is_dir():
        raise ValueError("Fixture root changed after qualification")
    actual_paths = {
        path.relative_to(scenario.root).as_posix()
        for path in scenario.root.rglob("*")
        if path.is_file()
    }
    qualified_paths = {source.relative_path for source in scenario.sources}
    contains_symlink = any(path.is_symlink() for path in scenario.root.rglob("*"))
    if actual_paths != qualified_paths or contains_symlink:
        raise ValueError("Fixture inventory changed after qualification")
    for source in scenario.sources:
        if (
            len(source.content) != source.size
            or hashlib.sha256(source.content).hexdigest() != source.sha256
        ):
            raise ValueError(
                f"Qualified source content changed before analysis: {source.relative_path}"
            )
        path = scenario.root / Path(*PurePosixPath(source.relative_path).parts)
        content = path.read_bytes()
        if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.sha256:
            raise ValueError(f"Fixture source changed after qualification: {source.relative_path}")


def discover_qualified_macro_scenario(scenario: QualifiedMacroScenario) -> Any:
    """Analyze only qualified bytes and verify the analyzer consumed that exact inventory."""

    _revalidate_qualified_sources(scenario)
    with tempfile.TemporaryDirectory(prefix="smf-task-05-") as directory:
        snapshot = Path(directory)
        for source in scenario.sources:
            target = snapshot / Path(*PurePosixPath(source.relative_path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.content)
            os.utime(target, ns=(0, 0))
        workload = discover_source(
            snapshot,
            provider="filesystem",
            namespace=scenario.namespace,
            logical_name=scenario.root.name,
            source_locator=f"task-05-fixture/{scenario.scenario_id}",
        ).workloads[0]

    analyzed_inventory = {
        (artifact.logical_path, artifact.metadata.get("size_bytes"), artifact.checksum)
        for artifact in workload.artifacts
        if "size_bytes" in artifact.metadata and artifact.checksum is not None
    }
    if analyzed_inventory != _qualified_inventory(scenario):
        raise ValueError("Analyzed source inventory differs from qualified fixture inventory")
    return workload


def _exact_keys(value: object, expected: set[str], subject: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{subject} must contain exactly {sorted(expected)}")
    return cast(dict[str, Any], value)


def _relative(value: object, subject: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{subject} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{subject} escapes its fixture boundary")
    return path


def _count_map(value: object, allowed: set[str], subject: str) -> Mapping[str, int]:
    if not isinstance(value, dict):
        raise ValueError(f"{subject} must be an object")
    if any(key not in allowed for key in value):
        raise ValueError(f"{subject} contains an unsupported enum value")
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in value.values()
    ):
        raise ValueError(f"{subject} counts must be non-negative integers")
    return MappingProxyType(dict(sorted(cast(dict[str, int], value).items())))


def load_macro_fixture_manifest(manifest_path: Path) -> tuple[QualifiedMacroScenario, ...]:
    """Reacquire and digest every declared source, failing closed on drift or ambiguity."""

    fixture_root = manifest_path.parent.resolve(strict=True)
    payload = _exact_keys(
        json.loads(manifest_path.read_text(encoding="utf-8")), _ROOT_KEYS, "manifest"
    )
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["corpus_id"] != "task-05-macro-regression"
    ):
        raise ValueError("Unsupported macro fixture manifest identity or schema version")
    raw_scenarios = payload["scenarios"]
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise ValueError("Macro fixture manifest must declare scenarios")

    scenarios: list[QualifiedMacroScenario] = []
    seen_ids: set[str] = set()
    seen_namespaces: set[str] = set()
    seen_roots: set[str] = set()
    for index, raw_scenario in enumerate(raw_scenarios):
        scenario = _exact_keys(raw_scenario, _SCENARIO_KEYS, f"scenario[{index}]")
        scenario_id = scenario["scenario_id"]
        namespace = scenario["namespace"]
        category = scenario["category"]
        if not all(isinstance(item, str) and item for item in (scenario_id, namespace, category)):
            raise ValueError("Scenario identity, namespace, and category must be non-empty strings")
        if (
            _IDENTITY.fullmatch(scenario_id) is None
            or _IDENTITY.fullmatch(namespace) is None
            or category not in _CATEGORIES
        ):
            raise ValueError("Scenario identity, namespace, or category is unsupported")
        folded_id = scenario_id.casefold()
        if folded_id in seen_ids:
            raise ValueError(f"Duplicate case-folded scenario id: {scenario_id}")
        seen_ids.add(folded_id)
        folded_namespace = namespace.casefold()
        if folded_namespace in seen_namespaces:
            raise ValueError(f"Duplicate case-folded scenario namespace: {namespace}")
        seen_namespaces.add(folded_namespace)
        root_relative = _relative(scenario["root"], f"scenario {scenario_id} root")
        folded_root = root_relative.as_posix().casefold()
        if folded_root in seen_roots:
            raise ValueError(f"Duplicate case-folded scenario root: {root_relative}")
        seen_roots.add(folded_root)
        unresolved_root = fixture_root / Path(*root_relative.parts)
        root_parts = [
            fixture_root.joinpath(*root_relative.parts[:index])
            for index in range(1, len(root_relative.parts) + 1)
        ]
        if any(part.is_symlink() for part in root_parts):
            raise ValueError(f"Scenario root may not traverse symlinks: {root_relative}")
        root = unresolved_root.resolve(strict=True)
        if not root.is_dir() or not root.is_relative_to(fixture_root):
            raise ValueError(f"Scenario root is outside the fixture corpus: {root_relative}")

        raw_sources = scenario["sources"]
        if not isinstance(raw_sources, list) or not raw_sources:
            raise ValueError(f"Scenario {scenario_id} must declare at least one source")
        sources: list[QualifiedSource] = []
        declared: set[str] = set()
        for source_index, raw_source in enumerate(raw_sources):
            source = _exact_keys(
                raw_source, _SOURCE_KEYS, f"scenario {scenario_id} source[{source_index}]"
            )
            if (
                type(source["size"]) is not int
                or source["size"] < 0
                or not isinstance(source["sha256"], str)
                or _SHA256.fullmatch(source["sha256"]) is None
            ):
                raise ValueError("Fixture source size or SHA-256 is malformed")
            relative = _relative(source["path"], f"scenario {scenario_id} source path")
            folded = relative.as_posix().casefold()
            if folded in declared:
                raise ValueError(f"Duplicate case-folded source path: {relative}")
            declared.add(folded)
            source_path = root / Path(*relative.parts)
            if source_path.is_symlink():
                raise ValueError(f"Fixture sources may not be symlinks: {relative}")
            resolved = source_path.resolve(strict=True)
            if not resolved.is_file() or not resolved.is_relative_to(root):
                raise ValueError(f"Fixture source escapes scenario root: {relative}")
            content = resolved.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if source["size"] != len(content) or source["sha256"] != digest:
                raise ValueError(f"Fixture source changed after review: {relative}")
            sources.append(QualifiedSource(relative.as_posix(), len(content), digest, content))

        if any(path.is_symlink() for path in root.rglob("*")):
            raise ValueError(f"Scenario {scenario_id} contains an undeclared symlink")
        actual_files = {
            path.relative_to(root).as_posix().casefold()
            for path in root.rglob("*")
            if path.is_file()
        }
        if actual_files != declared:
            raise ValueError(f"Scenario {scenario_id} contains missing or undeclared files")

        expected = _exact_keys(
            scenario["expected"], _EXPECTED_KEYS, f"scenario {scenario_id} expected"
        )
        if not isinstance(expected["complete"], bool):
            raise ValueError("Expected complete must be boolean")
        checked_expected: dict[str, Any] = {
            "complete": expected["complete"],
            "observation_kinds": _count_map(
                expected["observation_kinds"],
                {item.value for item in MacroObservationKind},
                "observation_kinds",
            ),
            "resolution_kinds": _count_map(
                expected["resolution_kinds"],
                {item.value for item in MacroResolutionKind},
                "resolution_kinds",
            ),
            "blocker_reasons": _count_map(
                expected["blocker_reasons"],
                {item.value for item in MacroResolutionKind},
                "blocker_reasons",
            ),
        }
        families = expected["construct_families"]
        allowed_families = {item.value for item in MacroConstructFamily}
        if not isinstance(families, list) or any(item not in allowed_families for item in families):
            raise ValueError("construct_families contains an unsupported enum value")
        if len(set(families)) != len(families):
            raise ValueError("construct_families contains duplicates")
        checked_expected["construct_families"] = tuple(sorted(families))
        for field in ("calls_edges", "include_occurrences"):
            value = expected[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
            checked_expected[field] = value

        non_claims = scenario["non_claims"]
        if not isinstance(non_claims, dict) or set(non_claims) != _NON_CLAIMS:
            raise ValueError("Every governed non-claim must be explicit")
        if any(value is not False for value in non_claims.values()):
            raise ValueError("A fixture manifest cannot assert lifecycle or runtime success")

        scenarios.append(
            QualifiedMacroScenario(
                scenario_id=scenario_id,
                category=category,
                namespace=namespace,
                root=root,
                sources=tuple(sources),
                expected=MappingProxyType(checked_expected),
            )
        )
    return tuple(scenarios)
