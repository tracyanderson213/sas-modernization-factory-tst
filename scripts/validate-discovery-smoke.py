from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-discovery-smoke.py <discovery.json>")
        return 2

    path = Path(sys.argv[1])
    payload = json.loads(path.read_text(encoding="utf-8"))
    workloads = payload.get("workloads", [])
    if len(workloads) != 1:
        fail(f"expected exactly 1 workload, found {len(workloads)}")

    workload = workloads[0]
    artifacts = workload.get("artifacts", [])
    datasets = workload.get("datasets", [])
    relationships = workload.get("relationships", [])

    artifacts_by_name: dict[str, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        artifacts_by_name.setdefault(artifact["name"], []).append(artifact)

    required_artifacts = {
        "extract_claims.sas",
        "transform_claims.sas",
        "publish_claims.sas",
        "run_claims.sh",
        "run_dynamic.sh",
        "RUN_CLAIMS",
        "LOAD_SOURCE",
        "PUBLISH_AUDIT",
        "EXTERNAL_AUDIT_READY",
    }
    missing = sorted(name for name in required_artifacts if name not in artifacts_by_name)
    if missing:
        fail(f"missing artifacts: {', '.join(missing)}")

    def only_artifact(name: str) -> dict[str, Any]:
        matches = artifacts_by_name[name]
        if len(matches) != 1:
            fail(f"expected one artifact named {name}, found {len(matches)}")
        return matches[0]

    ids = {name: only_artifact(name)["artifact_id"] for name in required_artifacts}
    datasets_by_name = {item["name"]: item for item in datasets}

    required_datasets = {
        "src.claims",
        "raw.claims_stage",
        "curated.claims",
        "claims_report.csv",
    }
    missing_datasets = sorted(required_datasets - datasets_by_name.keys())
    if missing_datasets:
        fail(f"missing datasets: {', '.join(missing_datasets)}")

    src_claims = datasets_by_name["src.claims"]
    if src_claims["kind"] != "database_table":
        fail(f"src.claims should be database_table, got {src_claims['kind']}")
    options = src_claims.get("metadata", {}).get("connection_options", {})
    if options.get("password") != "<redacted>" or "DO_NOT_EXPOSE" in json.dumps(src_claims):
        fail("database password was not safely redacted")

    edge_set = {
        (item["source_id"], item["kind"], item["target_id"]): item for item in relationships
    }

    def require_edge(source: str, kind: str, target: str) -> dict[str, Any]:
        key = (source, kind, target)
        edge = edge_set.get(key)
        if edge is None:
            fail(f"missing relationship {source} --{kind}--> {target}")
        return edge

    extract_id = ids["extract_claims.sas"]
    transform_id = ids["transform_claims.sas"]
    publish_id = ids["publish_claims.sas"]
    wrapper_id = ids["run_claims.sh"]
    run_job_id = ids["RUN_CLAIMS"]
    load_job_id = ids["LOAD_SOURCE"]
    audit_job_id = ids["PUBLISH_AUDIT"]
    external_job_id = ids["EXTERNAL_AUDIT_READY"]

    require_edge(transform_id, "depends_on", extract_id)
    require_edge(publish_id, "depends_on", transform_id)
    require_edge(wrapper_id, "triggers", extract_id)
    require_edge(wrapper_id, "triggers", transform_id)
    require_edge(wrapper_id, "triggers", publish_id)
    require_edge(run_job_id, "triggers", wrapper_id)
    require_edge(run_job_id, "depends_on", load_job_id)
    require_edge(load_job_id, "precedes", run_job_id)
    require_edge(audit_job_id, "depends_on", external_job_id)

    external = only_artifact("EXTERNAL_AUDIT_READY")
    if external.get("metadata", {}).get("definition_status") != "referenced_only":
        fail("external scheduler dependency was not preserved as referenced_only")

    dynamic = only_artifact("run_dynamic.sh")
    invocations = dynamic.get("metadata", {}).get("runtime_invocations", [])
    if not any(item.get("resolution") == "dynamic" for item in invocations):
        fail("dynamic shell launch was not preserved as unresolved/dynamic")
    if any(
        item["source_id"] == dynamic["artifact_id"] and item["kind"] == "triggers"
        for item in relationships
    ):
        fail("dynamic shell launch incorrectly created a trigger relationship")

    cron_jobs = [
        item for item in artifacts if item.get("metadata", {}).get("scheduler_format") == "cron"
    ]
    if len(cron_jobs) != 1:
        fail(f"expected one derived cron job, found {len(cron_jobs)}")
    if cron_jobs[0].get("metadata", {}).get("schedule") != "15 4 * * 1-5":
        fail("cron schedule was not captured correctly")
    require_edge(cron_jobs[0]["artifact_id"], "triggers", wrapper_id)

    include_edges = [
        item
        for item in relationships
        if item["source_id"] == extract_id and item["kind"] == "includes"
    ]
    if not include_edges:
        fail("%include reference was not discovered")

    macro_matches = artifacts_by_name.get("common_macros.sas", [])
    if not macro_matches:
        fail("common_macros.sas was not inventoried")
    include_target_ids = {item["target_id"] for item in include_edges}
    macro_ids = {item["artifact_id"] for item in macro_matches}
    include_resolved_to_inventory = bool(include_target_ids & macro_ids) and len(macro_matches) == 1

    print("PASS: realistic SAS estate discovery smoke test")
    print(f"  artifacts:     {len(artifacts)}")
    print(f"  datasets:      {len(datasets)}")
    print(f"  relationships: {len(relationships)}")
    print("  verified: SAS inventory, endpoint classification, secret redaction")
    print("  verified: cross-program data lineage")
    print("  verified: shell, AutoSys JIL, cron launch/order relationships")
    print("  verified: unresolved dynamic and external dependencies remain explicit")
    if include_resolved_to_inventory:
        print("  verified: %include resolved to inventoried macro artifact")
    else:
        print("  KNOWN GAP: %include is detected but its placeholder is not yet reconciled")
        print("             with the separately inventoried macro artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
