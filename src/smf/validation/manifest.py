from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_validation_manifest(output_dir: Path, payload: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = output_dir / "validation.manifest.json"
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest
