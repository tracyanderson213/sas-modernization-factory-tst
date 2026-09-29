from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_new_json(path: Path, payload: dict[str, Any]) -> Path:
    """Publish canonical JSON exactly once without replacing prior evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except BaseException:
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return path


def write_execution_manifest(output_dir: Path, payload: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "execution.manifest.json"
    return write_new_json(path, payload)
