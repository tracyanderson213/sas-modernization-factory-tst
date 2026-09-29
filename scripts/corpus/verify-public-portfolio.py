#!/usr/bin/env python3
"""Independently verify vendored untouched-public corpus bytes against pinned GitHub sources."""

from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_ROOT = ROOT / "tests" / "corpus" / "manifests"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(upstream_url: str, ref: str, upstream_path: str) -> bytes:
    parsed = urlparse(upstream_url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError(f"Unsupported upstream repository URL: {upstream_url}")
    repo = parsed.path.strip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo.count("/") != 1:
        raise ValueError(f"Expected GitHub owner/repository URL: {upstream_url}")
    encoded = quote(upstream_path, safe="/")
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{encoded}"
    request = Request(url, headers={"User-Agent": "smf-corpus-verifier/1.0"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - constrained HTTPS GitHub URL
        return response.read()


def verify_manifest(path: Path) -> int:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if payload.get("metadata", {}).get("tier") != "untouched-public":
        return 0
    source = payload["source"]
    upstream_url = source.get("upstream_url")
    ref = source.get("upstream_ref")
    if (
        not upstream_url
        or not ref
        or len(ref) != 40
        or any(c not in "0123456789abcdef" for c in ref)
    ):
        raise ValueError(f"Untouched-public manifest lacks a pinned 40-char commit: {path}")
    verified = 0
    for artifact in payload["artifacts"]:
        upstream_path = artifact.get("upstream_path")
        declared = artifact.get("sha256")
        if not upstream_path or not declared:
            raise ValueError(f"Untouched-public artifact lacks provenance fields: {path}")
        local_path = path.parent / artifact["path"]
        local_bytes = local_path.read_bytes()
        upstream_bytes = fetch(upstream_url, ref, upstream_path)
        local_sha = digest(local_bytes)
        upstream_sha = digest(upstream_bytes)
        if local_bytes != upstream_bytes:
            raise ValueError(f"Vendored bytes differ from pinned upstream: {local_path}")
        if local_sha != declared or upstream_sha != declared:
            raise ValueError(f"SHA-256 provenance mismatch: {local_path}")
        verified += 1
        print(f"verified {source['source_id']}:{upstream_path} -> {local_sha}")
    return verified


def main() -> None:
    count = sum(verify_manifest(path) for path in sorted(MANIFEST_ROOT.glob("*.yaml")))
    if count == 0:
        raise ValueError("No untouched-public corpus artifacts found")
    print(f"PUBLIC CORPUS INTEGRITY: PASS - {count} artifacts match pinned upstream bytes")


if __name__ == "__main__":
    main()
