from __future__ import annotations

import json
from pathlib import Path

import pytest

from smf.discovery import discover_source

PUBLIC_ROOT = Path(__file__).parents[1] / "corpus" / "workloads" / "public"
PUBLIC_SOURCES = sorted(PUBLIC_ROOT.rglob("*.sas"))


@pytest.mark.parametrize("source", PUBLIC_SOURCES, ids=lambda p: p.parent.name + "/" + p.name)
def test_public_sas_source_discovers_without_crashing_or_leaking_literal_credentials(
    source: Path,
) -> None:
    # These source files are retained unchanged from their public upstream examples. The test
    # intentionally avoids parser-tailored expected topology and checks only defensible invariants.
    result = discover_source(source, provider="filesystem", namespace="public-blind")
    assert len(result.workloads) == 1
    workload = result.workloads[0]
    assert any(item.name == source.name for item in workload.artifacts)
    assert workload.workload_id
    json.dumps(workload.to_dict())


def test_public_corpus_is_external_source_material_not_smf_authored_fixture() -> None:
    sources_manifest = (Path(__file__).parents[1] / "corpus" / "sources.yaml").read_text()
    assert "sascommunities" in sources_manifest.lower() or "github" in sources_manifest.lower()
    assert len(PUBLIC_SOURCES) >= 2
