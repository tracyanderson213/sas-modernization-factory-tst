#!/usr/bin/env python3
"""Acquire the pinned CORPUS-07 untouched public SAS portfolio."""

from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "corpus"
ACQUIRED = "2026-09-04"

PORTFOLIO = [
    {
        "scenario_id": "public-sas-access-odbc-bulkload",
        "name": "SAS ACCESS ODBC bulk-load sample",
        "domain": "connectivity",
        "source_id": "sas-access-samples",
        "repo": "sascommunities/sas-access-samples",
        "license": "Apache-2.0",
        "ref": "6e2fb148ee64aeda1e8e0a5d49689a0145afee13",
        "files": [
            ("SAS Foundation/ODBC/bulkload.sas", "sas-access-odbc/bulkload.sas", "sas-program")
        ],
        "capabilities": [
            "sas-access",
            "libname",
            "macro-variable-reference",
            "data-step",
            "external-database-write",
        ],
        "expected": {
            "discovery": {
                "reads": ["work.dublkdat", "mybulk.dublktab"],
                "writes": ["work.dublkdat", "mybulk.dublktab"],
                "libraries": ["mybulk"],
                "macro_variables": ["connopt", "dbms"],
            }
        },
    },
    {
        "scenario_id": "public-sas-access-postgres-bulkload",
        "name": "SAS ACCESS PostgreSQL bulk-load sample",
        "domain": "connectivity",
        "source_id": "sas-access-samples",
        "repo": "sascommunities/sas-access-samples",
        "license": "Apache-2.0",
        "ref": "6e2fb148ee64aeda1e8e0a5d49689a0145afee13",
        "files": [
            (
                "SAS Foundation/Postgres/bulkload.sas",
                "sas-access-postgres/bulkload.sas",
                "sas-program",
            )
        ],
        "capabilities": [
            "sas-access",
            "proc-sql",
            "create-table-as-select",
            "data-step",
            "external-database-write",
        ],
    },
    {
        "scenario_id": "public-sas-official-language-breadth",
        "name": "SAS-maintained language breadth slice",
        "domain": "language-breadth",
        "source_id": "sas-code-examples",
        "repo": "sassoftware/sas-code-examples",
        "license": "Apache-2.0",
        "ref": "579e057f90cd699f744fd6a1c8acaf9243f7ff67",
        "files": [
            (
                "By Syntax/DATA Step/Create new column with the SELECT statement.sas",
                "sas-code-examples/create-column-select.sas",
                "sas-program",
            ),
            (
                "By Syntax/FORMAT Procedure/Using the By Groupformat Statement to Process Data.sas",
                "sas-code-examples/by-groupformat.sas",
                "sas-program",
            ),
            (
                "By Syntax/HTTP Procedure/1_Intro to PROC HTTP.sas",
                "sas-code-examples/proc-http-intro.sas",
                "sas-program",
            ),
        ],
        "capabilities": [
            "data-step",
            "select-statement",
            "proc-format",
            "by-group",
            "proc-http",
            "external-http",
        ],
    },
    {
        "scenario_id": "public-sasjs-core-macro-dependency",
        "name": "SASjs Core macro dependency slice",
        "domain": "macro-application",
        "source_id": "sasjs-core",
        "repo": "sasjs/core",
        "license": "MIT",
        "ref": "d57fe80b08e3039be4b702aadbccf811c8704552",
        "files": [
            ("meta/mm_createstp.sas", "sasjs-core/meta/mm_createstp.sas", "sas-macro"),
            ("base/mf_nobs.sas", "sasjs-core/base/mf_nobs.sas", "sas-macro"),
            ("base/mf_verifymacvars.sas", "sasjs-core/base/mf_verifymacvars.sas", "sas-macro"),
            ("meta/mm_getdirectories.sas", "sasjs-core/meta/mm_getdirectories.sas", "sas-macro"),
            (
                "meta/mm_updatestpsourcecode.sas",
                "sasjs-core/meta/mm_updatestpsourcecode.sas",
                "sas-macro",
            ),
            (
                "meta/mm_getservercontexts.sas",
                "sasjs-core/meta/mm_getservercontexts.sas",
                "sas-macro",
            ),
            ("base/mp_abort.sas", "sasjs-core/base/mp_abort.sas", "sas-macro"),
            ("base/mp_dropmembers.sas", "sasjs-core/base/mp_dropmembers.sas", "sas-macro"),
        ],
        "capabilities": [
            "macro-library",
            "macro-dependencies",
            "code-generation",
            "sas9-metadata",
            "stored-process",
        ],
    },
    {
        "scenario_id": "public-cdisc-core-sas-validation",
        "name": "CDISC CORE SAS validation workload slice",
        "domain": "multi-artifact-application",
        "source_id": "cdisc-core-sas",
        "repo": "lexjansen/cdisc-core-sas",
        "license": "MIT",
        "ref": "c9928c6819e0064e41c4af6606dc2839ddf750ef",
        "files": [
            (
                "programs/run_core_validate_data.sas",
                "cdisc-core-sas/programs/run_core_validate_data.sas",
                "sas-program",
            ),
            ("programs/config.sas", "cdisc-core-sas/programs/config.sas", "sas-include"),
        ],
        "capabilities": [
            "multi-artifact",
            "macro-autocall",
            "include",
            "environment-variables",
            "python-integration",
            "clinical-validation",
        ],
    },
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(repo: str, ref: str, upstream_path: str, target: Path) -> None:
    encoded = quote(upstream_path, safe="/")
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{encoded}"
    req = Request(url, headers={"User-Agent": "smf-corpus-acquisition/1.0"})
    with urlopen(req, timeout=30) as response:  # noqa: S310 - pinned HTTPS GitHub source
        data = response.read()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def manifest_for(item: dict[str, object], artifacts: list[dict[str, str]]) -> dict[str, object]:
    scenario_id = str(item["scenario_id"])
    manifest: dict[str, object] = {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "name": item["name"],
        "domain": item["domain"],
        "description": (
            "Untouched public SAS acquired from a pinned upstream revision for "
            "CORPUS-07 realism testing."
        ),
        "source": {
            "source_id": item["source_id"],
            "origin": "public-open-source",
            "license": item["license"],
            "upstream_url": f"https://github.com/{item['repo']}",
            "upstream_ref": item["ref"],
            "notes": (
                "Vendored bytes are untouched. SMF must adapt to the upstream source, "
                "not the reverse."
            ),
        },
        "capabilities": item["capabilities"],
        "artifacts": artifacts,
        "metadata": {
            "tier": "untouched-public",
            "private_data": False,
            "modification_status": "untouched",
            "acquisition_date": ACQUIRED,
            "independent_authorship": True,
        },
    }
    if "expected" in item:
        manifest["expected"] = item["expected"]
    local_paths = [str(a["path"]) for a in artifacts]
    if scenario_id == "public-cdisc-core-sas-validation":
        manifest["workload"] = {
            "root": "../workloads/public/cdisc-core-sas",
            "entrypoints": [local_paths[0]],
            "relationships": [
                {"source": local_paths[0], "target": local_paths[1], "relationship": "includes"}
            ],
        }
    elif scenario_id == "public-sasjs-core-macro-dependency":
        manifest["workload"] = {
            "root": "../workloads/public/sasjs-core",
            "entrypoints": [local_paths[0]],
            "relationships": [
                {"source": local_paths[0], "target": p, "relationship": "depends-on"}
                for p in local_paths[1:]
            ],
        }
    else:
        manifest["workload"] = {
            "root": "../workloads/public",
            "entrypoints": local_paths,
            "relationships": [],
        }
    return manifest


def main() -> None:
    for item in PORTFOLIO:
        artifacts: list[dict[str, str]] = []
        for upstream_path, local_rel, role in item["files"]:  # type: ignore[index]
            target = CORPUS / "workloads" / "public" / local_rel
            download(str(item["repo"]), str(item["ref"]), upstream_path, target)
            artifacts.append(
                {
                    "path": f"../workloads/public/{local_rel}",
                    "role": role,
                    "sha256": sha256(target),
                    "source_id": str(item["source_id"]),
                    "upstream_path": upstream_path,
                }
            )
            print(f"acquired {item['source_id']}:{upstream_path} -> {target.relative_to(ROOT)}")
        manifest = manifest_for(item, artifacts)
        manifest_path = CORPUS / "manifests" / f"{item['scenario_id']}.yaml"
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
        print(f"wrote {manifest_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
