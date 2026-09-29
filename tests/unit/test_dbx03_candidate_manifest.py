from __future__ import annotations

import copy
from pathlib import Path

from smf.readiness.policy import digest_value
from smf.security.candidate_manifest import verify_candidate_manifest


def test_candidate_manifest_covers_exact_working_tree() -> None:
    root = Path.cwd().resolve()
    manifest = root / "docs/architecture/DBX-03_CANDIDATE_MANIFEST.json"
    recorded = verify_candidate_manifest(root, manifest)
    assert recorded["review_status"] == "pending_independent_protected_review"
    assert recorded["uncommitted_candidate"] is True
    assert recorded["manifest_self_excluded"] is True


def test_manifest_file_mutation_changes_fingerprint() -> None:
    governed = {
        "base_revision": "0" * 40,
        "files": [{"path": "a", "status": " M", "sha256": "1" * 64}],
    }
    original = digest_value(governed)
    mutated = copy.deepcopy(governed)
    mutated["files"][0]["sha256"] = "2" * 64
    assert digest_value(mutated) != original
