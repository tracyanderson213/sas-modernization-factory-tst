"""Stable identity helpers for workload graph entities."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def stable_id(prefix: str, identity: Mapping[str, Any] | Sequence[Any] | str) -> str:
    """Create a deterministic identifier from logical identity, not local file paths."""
    digest = hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"
