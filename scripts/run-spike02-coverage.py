#!/usr/bin/env python3
"""Run the bounded SPIKE-02 corpus coverage qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from smf.conversion import CoverageQualificationRequest, evaluate_conversion_coverage


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-root", type=Path, default=Path("tests/corpus"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/corpus/manifests/spike02-sas2databricks-coverage.json"),
    )
    parser.add_argument("--output-root", type=Path, default=Path("out/spike02-coverage"))
    parser.add_argument("--run-id", default="spike02-confidence")
    parser.add_argument("--attempt-id", default="attempt-1")
    args = parser.parse_args()
    manifest_digest = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    result = evaluate_conversion_coverage(
        CoverageQualificationRequest(
            corpus_manifest=args.manifest,
            corpus_root=args.corpus_root,
            output_root=args.output_root,
            expected_manifest_sha256=manifest_digest,
            client_id="public-fixture",
            deployment_id="offline-qualification",
            environment_id="local",
            run_id=args.run_id,
            attempt_id=args.attempt_id,
        )
    )
    payload = json.loads(result.read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "result_path": result.as_posix(),
                "content_digest": payload["content_digest"],
                "classification_counts": payload["metrics"]["classification_counts"],
                "claims": payload["claims"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
