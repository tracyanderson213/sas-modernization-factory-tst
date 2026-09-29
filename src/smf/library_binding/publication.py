"""Immutable publication and replay verification for BASE-06 evidence."""

from __future__ import annotations

import json
from contextlib import suppress
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from smf.immutable_files import publish_json, read_published_json
from smf.library_binding.engine import (
    PreparedLibraryBindings,
    assert_persistable,
    evaluate_library_bindings,
    library_binding_projection,
)
from smf.library_binding.models import BindingRequest
from smf.workload.identity import stable_id


def _validate_result(result: dict[str, Any]) -> None:
    schema = json.loads(
        files("smf.schemas")
        .joinpath("sas-library-binding-evidence.schema.json")
        .read_text(encoding="utf-8")
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(result), key=lambda error: list(error.path)
    )
    if errors:
        raise ValueError(f"Library binding result schema violation: {errors[0].message}")
    unsigned = dict(result)
    result_id = unsigned.pop("result_id", None)
    if result_id != stable_id("LBRES", unsigned):
        raise ValueError("Library binding result identity mismatch")
    assert_persistable(result)


def publish_library_bindings(
    prepared: PreparedLibraryBindings, request: BindingRequest, output_root: Path
) -> tuple[Path, Path]:
    regenerated = evaluate_library_bindings(request)
    if regenerated != prepared:
        raise ValueError("Prepared library binding evidence does not match authoritative inputs")
    _validate_result(prepared.result)
    expected_projection = library_binding_projection(prepared.result)
    if prepared.projection != expected_projection:
        raise ValueError("Prepared library binding projection mismatch")
    result_id = str(prepared.result["result_id"])
    result_path = output_root / "library-bindings" / f"{result_id}.json"
    projection_path = output_root / "library-bindings" / f"{result_id}.projection.json"
    with suppress(FileExistsError):
        publish_json(result_path, prepared.result, "library binding result", root=output_root)
    stored_value: Any = read_published_json(
        result_path, root=output_root, label="library binding result"
    )
    if not isinstance(stored_value, dict):
        raise ValueError("Canonical library binding result is invalid")
    stored = cast(dict[str, Any], stored_value)
    _validate_result(stored)
    if stored != prepared.result:
        raise ValueError("Canonical library binding result differs from prepared evidence")
    publish_json(
        projection_path,
        expected_projection,
        "library binding projection",
        root=output_root,
    )
    return result_path, projection_path
