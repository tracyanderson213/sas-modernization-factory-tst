"""Immutable, restart-safe publication for BASE-07 evidence."""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from smf.asset_inventory.engine import PreparedAssetInventory, asset_inventory_projection
from smf.immutable_files import publish_json, read_published_json


def publish_asset_inventory(
    prepared: PreparedAssetInventory, output_root: Path
) -> tuple[Path, Path]:
    result_id = prepared.result["inventory_result_id"]
    result_path = output_root / "asset-inventory" / f"{result_id}.json"
    projection_path = output_root / "asset-inventory" / f"{result_id}.projection.json"
    asset_inventory_projection(prepared.result)
    with suppress(FileExistsError):
        publish_json(result_path, prepared.result, "asset inventory result", root=output_root)
    canonical_value: Any = read_published_json(
        result_path, root=output_root, label="asset inventory result"
    )
    if not isinstance(canonical_value, dict):
        raise ValueError("Canonical asset inventory result is invalid")
    canonical = cast(dict[str, Any], canonical_value)
    if canonical.get("inventory_result_id") != result_id:
        raise ValueError("Canonical asset inventory result identity mismatch")
    projection = asset_inventory_projection(canonical)
    publish_json(
        projection_path,
        projection,
        "asset inventory projection",
        root=output_root,
    )
    return result_path, projection_path
