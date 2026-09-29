#!/usr/bin/env python3
"""Generate the deterministic DBX-03 independent-review manifest."""

from __future__ import annotations

import json
from pathlib import Path

from smf.security.candidate_manifest import candidate_manifest


def main() -> None:
    root = Path.cwd().resolve()
    relative = "docs/architecture/DBX-03_CANDIDATE_MANIFEST.json"
    destination = root / relative
    payload = candidate_manifest(root, manifest_path=relative)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(payload["candidate_fingerprint"])


if __name__ == "__main__":
    main()
