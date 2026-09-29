"""Review-first acceptance publishing. Dry-run and verify never mutate GitHub."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from smf.workload.sanitization import is_secret_field_name, sanitize_discovery_value

BEGIN = "<!-- smf-acceptance:begin -->"
END = "<!-- smf-acceptance:end -->"
FINGERPRINT_PREFIX = "<!-- smf-acceptance:source-sha256="
PLAN = Path("competition/generated/replan.yaml")
SPECS = Path("competition/generated/issue-specs")
AUDIT = Path(".project-audit/acceptance-sync")
KEY = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
FIELDS = """fieldValues(first:100) { pageInfo { hasNextPage } nodes {
 ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { name } } }
 ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2FieldCommon { name } } }
} }"""
CONTENT = (
    """id content { __typename
 ... on Issue { id number title body state updatedAt repository { nameWithOwner } }
 ... on DraftIssue { id title body updatedAt }
} """
    + FIELDS
)
PROJECT = (
    """query($number:Int!,$after:String){viewer{projectV2(number:$number){id
 items(first:100,after:$after){pageInfo{hasNextPage endCursor} nodes{"""
    + CONTENT
    + "}}}}}"
)
NODE = "query($id:ID!){node(id:$id){... on ProjectV2Item{" + CONTENT + "}}}"


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def text_digest(value: str) -> str:
    """Return the byte-level SHA-256 used for body/source publication evidence."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reviewed_text(path: Path, label: str) -> str:
    """Read a reviewed source allowing only the repository's one terminal LF convention."""
    raw = path.read_bytes()
    if b"\r" in raw:
        raise ValueError(f"{label} has unsupported carriage-return line endings")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith((b"\n", b" ", b"\t")):
        raise ValueError(f"{label} has unsupported terminal whitespace")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not strict UTF-8") from error


def safe(value: Any) -> None:
    """Reject explicit credential syntax, not ordinary security-related prose.

    This publication lint is not PHI/PII classification or an exhaustive secret detector.
    It does not change the runtime evidence sanitizer's stricter behavior.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            if is_secret_field_name(str(key)) and child:
                raise ValueError("Credential-bearing field requires review; not exported")
            safe(child)
    elif isinstance(value, list):
        for child in value:
            safe(child)
    elif isinstance(value, str):
        patterns = (
            r"(?i)\b(?:[a-z0-9_]*(?:password|passwd|secret|token|api_key)|"
            r'accountkey|sharedaccesskey|authorization)["\x27]?\s*[:=]\s*["\x27]?[^\s"\x27<>]+',
            r"(?i)\bBearer\s+[A-Za-z0-9._~-]{12,}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"https?://[^\s/:]+:[^\s/@]+@",
            r"(?i)[?&](?:sig|password|token|api_key)=[^\s&]+",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})",
        )
        if any(re.search(pattern, value) for pattern in patterns):
            raise ValueError("Credential-bearing content requires review; not exported")


def load_sources(
    root: Path,
) -> tuple[dict[str, Any], dict[str, str], dict[str, str], str]:
    if (root / PLAN).is_symlink() or not (root / SPECS).resolve().is_relative_to(root.resolve()):
        raise ValueError("Acceptance sources must remain inside the repository")
    plan = yaml.safe_load((root / PLAN).read_text())
    if not isinstance(plan, dict) or not isinstance(plan.get("items"), list):
        raise ValueError("Invalid acceptance replan")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", plan.get("repository", "")):
        raise ValueError("Invalid repository binding")
    # Existing project-common.sh uses viewer-owned projects. Fail rather than target another owner.
    if plan.get("project", {}).get("owner") != "@me":
        raise ValueError("Only explicitly viewer-owned (@me) Projects are supported")
    if not isinstance(plan["project"].get("number"), int) or plan["project"]["number"] < 1:
        raise ValueError("Invalid Project number")
    policy_path = root / SPECS / "_ACCEPTANCE-POLICY.md"
    if policy_path.is_symlink():
        raise ValueError("Policy symlinks are not supported")
    policy = reviewed_text(policy_path, "Shared acceptance policy")
    if not policy:
        raise ValueError("Shared acceptance policy is empty")
    if "smf-acceptance:" in policy:
        raise ValueError("Shared acceptance policy contains a reserved acceptance marker")
    safe(policy)
    raw_specs: dict[str, str] = {}
    specs: dict[str, str] = {}
    for row in plan["items"]:
        key = row.get("backlog_key", "")
        if not KEY.fullmatch(key) or key in specs:
            raise ValueError("Missing, invalid or duplicate local Backlog Key")
        relative = str(SPECS / f"{key}.md")
        path = root / relative
        if row.get("body_file") != relative or path.is_symlink():
            raise ValueError(f"{key}: unexpected body_file or symlink")
        if not path.resolve().is_relative_to((root / SPECS).resolve()):
            raise ValueError(f"{key}: spec escapes its directory")
        text = reviewed_text(path, key)
        if not text.startswith(f"# {key} - "):
            raise ValueError(f"{key}: title/key mismatch")
        for marker in [f"**{key}-AC{i:02}:**" for i in range(1, 4)] + [
            f"**HC-{i:02}:**" for i in range(1, 6)
        ]:
            if text.count(marker) != 1:
                raise ValueError(f"{key}: missing or duplicate acceptance IDs")
        if "smf-acceptance:" in text:
            raise ValueError(f"{key}: source contains a reserved acceptance marker")
        safe(text)
        raw_specs[key] = text
        fingerprint = digest({"spec": text, "policy": policy})
        # Preserve the local review draft verbatim; the explicit apply is publication approval.
        specs[key] = (
            f"{BEGIN}\n<!-- smf-acceptance:source-sha256={fingerprint} -->\n"
            f"## Published acceptance source: {key}\n\n"
            "This managed section reproduces the reviewed local source, including its "
            "draft/history warnings. Publication does not attest implementation completion "
            "or approve deployment.\n\n"
            f"{text}\n\n## Embedded shared acceptance policy\n\n{policy}\n{END}"
        )
    return plan, raw_specs, specs, policy


def load_specs(root: Path) -> tuple[dict[str, Any], dict[str, str]]:
    plan, _, specs, _ = load_sources(root)
    return plan, specs


def managed(body: str) -> str | None:
    if BEGIN not in body and END not in body:
        if "smf-acceptance:" in body:
            raise ValueError("Malformed acceptance marker")
        return None
    if body.count(BEGIN) != 1 or body.count(END) != 1 or body.index(END) < body.index(BEGIN):
        raise ValueError("Malformed or duplicate managed sections")
    return body[body.index(BEGIN) : body.index(END) + len(END)]


def replace_managed(body: str, block: str) -> str:
    old = managed(body)
    if old is None:
        return body + ("\n\n" if body else "") + block + "\n"
    start = body.index(BEGIN)
    return body[:start] + block + body[start + len(old) :]


def exact_source_body(body: str, raw_spec: str, block: str, policy: str) -> str:
    """Adopt a byte-equivalent unmanaged source as one canonical managed block.

    GitHub drops the repository's single terminal newline when storing Issue and DraftIssue
    bodies. No other whitespace or content normalization is permitted.
    """
    if managed(body) is not None:
        return replace_managed(body, block)
    occurrences = body.count(raw_spec)
    if occurrences != 1:
        raise ValueError("Exact-source adoption requires exactly one raw source occurrence")
    if body not in {raw_spec, raw_spec + "\n"}:
        raise ValueError("Exact-source adoption body differs from the reviewed local specification")
    proposed = block + "\n"
    fingerprint = digest({"spec": raw_spec, "policy": policy})
    fingerprint_marker = f"{FINGERPRINT_PREFIX}{fingerprint} -->"
    if (
        proposed.count(BEGIN) != 1
        or proposed.count(END) != 1
        or proposed.count(FINGERPRINT_PREFIX) != 1
        or proposed.count(fingerprint_marker) != 1
        or proposed.count(raw_spec) != 1
        or proposed.count(policy) != 1
    ):
        raise ValueError("Exact-source adoption did not produce one canonical managed block")
    return proposed


def reconcile_priority_text(body: str, priority: str | None) -> tuple[str, dict[str, str] | None]:
    """Propose one exact legacy priority-line edit outside the managed section.

    This is included in the reviewed before/after body, never applied independently.
    Ambiguous repeated labels block publication. Other prose and all Project fields stay intact.
    """
    if priority is None:
        return body, None
    if priority not in {"P0", "P1", "P2", "P3"}:
        raise ValueError("Invalid competition priority for legacy text reconciliation")
    old = managed(body)
    start = body.index(BEGIN) if old is not None else len(body)
    end = start + len(old) if old is not None else start
    pattern = re.compile(r"^([ \t]*-[ \t]+Competition Priority:[ \t]*)(P[0-3])([ \t]*)$", re.M)
    matches = [
        match for match in pattern.finditer(body) if match.end() <= start or match.start() >= end
    ]
    if len(matches) > 1:
        raise ValueError("Multiple unmanaged priority labels require explicit scope reconciliation")
    if not matches or matches[0][2] == priority:
        return body, None
    match = matches[0]
    before = match.group(0)
    after = match[1] + priority + match[3]
    return body[: match.start()] + after + body[match.end() :], {"before": before, "after": after}


def map_node(node: dict[str, Any]) -> dict[str, Any]:
    if node["fieldValues"]["pageInfo"]["hasNextPage"]:
        raise ValueError("Project field pagination is incomplete")
    fields: dict[str, str] = {}
    for field in node["fieldValues"]["nodes"]:
        if "field" in field:
            name = field["field"]["name"]
            if name in fields:
                raise ValueError("Duplicate Project field name")
            fields[name] = field.get("text", field.get("name", ""))
    content = node.get("content") or {}
    return {"item_id": node["id"], "fields": fields, "content": content}


class GitHub:
    def api(self, endpoint: str, payload: dict[str, Any], method: str = "POST") -> dict[str, Any]:
        result = subprocess.run(
            ["gh", "api", endpoint, "--method", method, "--input", "-"],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("GitHub request failed; no raw request/response was printed")
        value: dict[str, Any] = json.loads(result.stdout)
        if value.get("errors"):
            raise RuntimeError("GitHub returned GraphQL errors; operation not verified")
        return value

    def snapshot(self, number: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor = None
        seen: set[str] = set()
        while True:
            result = self.api(
                "graphql",
                {
                    "query": PROJECT,
                    "variables": {
                        "number": number,
                        "after": cursor,
                    },
                },
            )
            page = result["data"]["viewer"]["projectV2"]["items"]
            rows.extend(map_node(n) for n in page["nodes"])
            if not page["pageInfo"]["hasNextPage"]:
                return rows
            cursor = page["pageInfo"]["endCursor"]
            if not cursor or cursor in seen:
                raise ValueError("Incomplete or repeated Project cursor")
            seen.add(cursor)

    def get(self, item_id: str) -> dict[str, Any]:
        result = self.api("graphql", {"query": NODE, "variables": {"id": item_id}})
        return map_node(result["data"]["node"])

    def update(self, remote: dict[str, Any], body: str, repository: str) -> None:
        content = remote["content"]
        if content["__typename"] == "Issue":
            if content["repository"]["nameWithOwner"] != repository:
                raise ValueError("Foreign repository target")
            self.api(f"repos/{repository}/issues/{content['number']}", {"body": body}, "PATCH")
        elif content["__typename"] == "DraftIssue":
            query = """mutation($id:ID!,$body:String!){updateProjectV2DraftIssue(
              input:{draftIssueId:$id,body:$body}){draftIssue{id}}}"""
            self.api("graphql", {"query": query, "variables": {"id": content["id"], "body": body}})
        else:
            raise ValueError("Unsupported content type")


def metadata(remote: dict[str, Any]) -> dict[str, Any]:
    return {
        **remote,
        "content": {k: v for k, v in remote["content"].items() if k not in {"body", "updatedAt"}},
    }


def make_report(
    root: Path,
    remote: list[dict[str, Any]],
    *,
    selected_keys: set[str] | None = None,
    exact_source_adoption: bool = False,
) -> dict[str, Any]:
    plan, raw_specs, specs, policy = load_sources(root)
    known_keys = {row["backlog_key"] for row in plan["items"]}
    if exact_source_adoption and not selected_keys:
        raise ValueError("Exact-source adoption requires explicit unique key selection")
    if selected_keys and selected_keys - known_keys:
        raise ValueError("Unknown exact-source adoption key")
    targets = Counter(r["content"].get("id") for r in remote if r["content"].get("id"))
    entries = []
    for local in plan["items"]:
        key = local["backlog_key"]
        if selected_keys is not None and key not in selected_keys:
            continue
        matches = [r for r in remote if r["fields"].get("Backlog Key") == key]
        entry: dict[str, Any] = {
            "key": key,
            "source_hash": digest(specs[key]),
            "action": "blocked",
            "reason": "",
            "warnings": [],
            "delivery_phase": local.get("delivery_phase"),
            "depends_on": local.get("depends_on", []),
            "planned_priority": local.get("project_fields", {}).get("Priority"),
        }
        if len(matches) != 1:
            entry["reason"] = "missing-live-item" if not matches else "duplicate-live-key"
            entries.append(entry)
            continue
        row = matches[0]
        content = row["content"]
        entry["item_id"] = row["item_id"]
        entry["kind"] = content.get("__typename", "missing")
        entry["number"] = content.get("number")
        entry["remote_hash"] = digest(row)
        fields = row["fields"]
        entry["live_priority"] = fields.get("Priority")
        entry["priority_change"] = (
            entry["planned_priority"] is not None
            and entry["planned_priority"] != entry["live_priority"]
        )
        if entry["priority_change"]:
            entry["warnings"].append("Priority differs: body sync does not update Project fields")
        if local.get("review_disposition") == "reconcile-task-with-completed-parent":
            entry["warnings"].append(
                "Reconcile task evidence with completed parent; no duplicate run"
            )
        if targets[content.get("id")] != 1:
            entry["reason"] = "duplicate-or-missing-content-identity"
        elif content.get("__typename") not in {"Issue", "DraftIssue"}:
            entry["reason"] = "unsupported-content"
        elif (
            content.get("__typename") == "Issue"
            and content.get("repository", {}).get("nameWithOwner") != plan["repository"]
        ):
            entry["reason"] = "foreign-repository"
        elif local.get("issue_number") is not None and local["issue_number"] != content.get(
            "number"
        ):
            entry["reason"] = "planned-issue-mismatch"
        elif (
            content.get("state") == "CLOSED"
            or fields.get("Status") == "Done"
            or fields.get("Implementation State") == "Foundation Complete"
        ):
            entry["reason"] = "completed-item-needs-follow-up-review"
        elif local.get("review_disposition") == "reconcile-task-with-completed-parent":
            entry["reason"] = "task-parent-evidence-reconciliation-required"
        else:
            body = content.get("body") or ""
            try:
                safe(row)
                reconciled, priority_edit = reconcile_priority_text(
                    body, local.get("competition_horizon")
                )
                adoption = exact_source_adoption and managed(body) is None
                if adoption and priority_edit:
                    raise ValueError(
                        "Exact-source adoption cannot reconcile unmanaged priority text"
                    )
                proposed = (
                    exact_source_body(body, raw_specs[key], specs[key], policy)
                    if exact_source_adoption
                    else replace_managed(reconciled, specs[key])
                )
                # GitHub issue bodies have a finite limit; include the complete shared policy.
                if len(proposed.encode("utf-8")) > 60000:
                    raise ValueError("Proposed body exceeds safe publication size")
                entry.update(
                    action="unchanged" if proposed == body else "update",
                    operation=(
                        "exact-source-adoption" if adoption else "managed-section-reconciliation"
                    ),
                    reason="",
                    before=body,
                    after=proposed,
                    metadata=metadata(row),
                    unmanaged_priority_edit=priority_edit,
                    before_bytes=len(body.encode("utf-8")),
                    after_bytes=len(proposed.encode("utf-8")),
                    before_sha256=text_digest(body),
                    after_sha256=text_digest(proposed),
                    raw_spec_sha256=text_digest(raw_specs[key]),
                    shared_policy_sha256=text_digest(policy),
                    managed_block_sha256=text_digest(specs[key]),
                    source_fingerprint=digest({"spec": raw_specs[key], "policy": policy}),
                    source_fingerprint_occurrences=proposed.count(FINGERPRINT_PREFIX),
                    raw_source_occurrences=proposed.count(raw_specs[key]),
                    shared_policy_occurrences=proposed.count(policy),
                    begin_marker_occurrences=proposed.count(BEGIN),
                    end_marker_occurrences=proposed.count(END),
                    project_fields_modified=False,
                    lifecycle_values_modified=False,
                )
                if priority_edit:
                    entry["warnings"].append(
                        "Proposes one legacy priority-line correction; review exact before/after"
                    )
                if adoption:
                    entry["warnings"].append(
                        "Exact-source adoption replaces the byte-equivalent unmanaged body with "
                        "one canonical managed block"
                    )
                elif managed(body) is None and body.strip():
                    entry["warnings"].append("Existing text retained; review for conflicting scope")
                if local["disposition"] == "DEFER":
                    entry["warnings"].append("Deferred: publishing criteria does not activate work")
            except ValueError as error:
                entry["reason"] = str(error)
        entries.append(entry)
    report: dict[str, Any] = {
        "schema_version": 1,
        "repository": plan["repository"],
        "project": plan["project"],
        "plan_hash": digest(plan),
        "selected_keys": sorted(selected_keys) if selected_keys is not None else [],
        "exact_source_adoption": exact_source_adoption,
        "created_at": datetime.now(UTC).isoformat(),
        "entries": entries,
        "counts": dict(Counter(e["action"] for e in entries)),
        "planned_priority_changes": sum(bool(e.get("priority_change")) for e in entries),
        "project_fields_applied": False,
        "unmatched_live_keys": sorted(
            {r["fields"].get("Backlog Key", "") for r in remote} - set(specs) - {""}
        ),
    }
    safe(report)
    report["report_hash"] = digest(report)
    return report


def save(path: Path, value: Any) -> None:
    safe(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite evidence from a previous operation.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def save_summary(path: Path, report: dict[str, Any]) -> None:
    publication_note = (
        "Exact-source adoption is limited to the explicitly selected records. The unmanaged body "
        "must byte-match its reviewed source except for one terminal newline; publication replaces "
        "it with exactly one canonical managed source and one shared policy."
        if report.get("exact_source_adoption")
        else "Unmanaged text is retained except a reported exact legacy priority-line correction; "
        "inspect all before/after text for conflicting acceptance scope."
    )
    lines = [
        "# Acceptance publication dry-run",
        "",
        f"Created: {report['created_at']}",
        "",
        "**No GitHub writes were made.** All rows require review before explicit apply.",
        "",
        f"Counts: {json.dumps(report['counts'], sort_keys=True)}",
        f"Planned priority differences: {report.get('planned_priority_changes', 0)}. "
        "Body apply NEVER updates Project fields; review a separate field operation.",
        "",
        f"Exact before/after bodies and hashes: [{path.stem}.json]({path.stem}.json).",
        "",
        "Completed items are blocked for follow-up review, not reopened or rewritten.",
        publication_note,
        "Review the JSON before/after bodies; this summary alone is not approval input.",
        "",
        "| Key | Target | Phase | Priority live → planned | Action | Reason / warnings |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for entry in report["entries"]:
        target = (
            f"Issue #{entry['number']}" if entry.get("number") else entry.get("kind", "unresolved")
        )
        reason = entry["reason"] or "; ".join(entry["warnings"]) or "Exact match"
        priority = f"{entry.get('live_priority')} → {entry.get('planned_priority')}"
        lines.append(
            f"| {entry['key']} | {target} | {entry.get('delivery_phase')} | "
            f"{priority} | {entry['action']} | {reason} |"
        )
    safe(lines)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def apply_report(
    root: Path, approved: dict[str, Any], keys: list[str], client: GitHub
) -> list[str]:
    unsigned = {k: v for k, v in approved.items() if k != "report_hash"}
    if approved.get("report_hash") != digest(unsigned):
        raise ValueError("Review report changed; generate and review a fresh dry-run")
    if not keys or len(set(keys)) != len(keys):
        raise ValueError("Explicit unique --key selections are required")
    plan, _ = load_specs(root)
    if approved["repository"] != plan["repository"] or approved["project"] != plan["project"]:
        raise ValueError("Report Project/repository binding changed")
    adoption = bool(approved.get("exact_source_adoption"))
    selected = set(approved.get("selected_keys", [])) if adoption else None
    if adoption and (not selected or set(keys) != selected):
        raise ValueError(
            "Exact-source adoption apply keys must exactly match the reviewed selection"
        )
    fresh = make_report(
        root,
        client.snapshot(plan["project"]["number"]),
        selected_keys=selected,
        exact_source_adoption=adoption,
    )
    if approved.get("plan_hash") != fresh["plan_hash"]:
        raise ValueError("Replan changed since review")
    old = {e["key"]: e for e in approved["entries"]}
    now = {e["key"]: e for e in fresh["entries"]}
    for key in keys:
        if key not in old or key not in now or now[key] != old[key]:
            raise ValueError(f"{key}: local or remote content changed since review")
        if old[key]["action"] not in {"update", "unchanged"}:
            raise ValueError(f"{key}: blocked records cannot be applied")
        if adoption and old[key].get("operation") not in {
            "exact-source-adoption",
            "managed-section-reconciliation",
        }:
            raise ValueError(f"{key}: reviewed report is not an exact-source adoption report")
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    verified = []
    for key in keys:
        entry = now[key]
        current_plan, current_specs = load_specs(root)
        if (
            digest(current_plan) != approved["plan_hash"]
            or digest(current_specs[key]) != entry["source_hash"]
        ):
            raise ValueError(f"{key}: local source changed immediately before update")
        current = client.get(entry["item_id"])
        if digest(current) != entry["remote_hash"]:
            raise ValueError(f"{key}: remote changed immediately before update")
        # Durable intent exists even if a network response is lost. Do not blindly retry.
        save(root / AUDIT / stamp / f"{key}-intent.json", entry)
        if entry["action"] == "update":
            client.update(current, entry["after"], plan["repository"])
        observed = client.get(entry["item_id"])
        if observed["content"]["body"] != entry["after"] or metadata(observed) != entry["metadata"]:
            raise ValueError(f"{key}: read-back mismatch; stop and inspect, no rollback attempted")
        receipt = {
            "key": key,
            "item_id": entry["item_id"],
            "number": entry["number"],
            "source_hash": entry["source_hash"],
            "body_hash": digest(entry["after"]),
            "repository": plan["repository"],
            "review_report_hash": approved["report_hash"],
        }
        save(root / AUDIT / stamp / f"{key}-verified.json", receipt)
        verified.append(key)
    return verified


def require_current_acceptance(root: Path, key: str, body: str, *, offline: bool) -> None:
    if not (root / PLAN).exists():
        return
    plan, specs = load_specs(root)
    if key not in specs:
        return
    if offline:
        raise ValueError("Competition launches require live acceptance verification, not --offline")
    local = next(row for row in plan["items"] if row["backlog_key"] == key)
    if local.get("review_disposition") == "reconcile-task-with-completed-parent":
        raise ValueError(f"{key}: reconcile task/parent acceptance evidence before launch")
    if managed(body) != specs[key]:
        raise ValueError(
            f"{key}: live acceptance is missing or stale; review and sync before launch"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=["dry-run", "verify", "apply"], nargs="?", default="dry-run"
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, help="Approved dry-run JSON, required for apply")
    parser.add_argument("--key", action="append", default=[])
    parser.add_argument(
        "--exact-source-adoption",
        action="store_true",
        help=(
            "For an explicitly selected dry-run, replace a byte-equivalent unmanaged source "
            "with one canonical managed block"
        ),
    )
    args = parser.parse_args(argv)
    if args.mode == "dry-run" and args.key and not args.exact_source_adoption:
        parser.error(
            "dry-run covers the full replan unless --exact-source-adoption is explicitly selected"
        )
    if args.exact_source_adoption and (
        args.mode != "dry-run" or not args.key or len(set(args.key)) != len(args.key)
    ):
        parser.error(
            "--exact-source-adoption requires dry-run with explicit unique --key selections"
        )
    if args.mode != "apply" and args.report:
        parser.error("--report is only valid for apply")
    root = args.repo_root.resolve()
    client = GitHub()
    try:
        if args.mode == "apply":
            if not args.report or not args.key:
                parser.error("apply requires --report and at least one --key")
            approved = json.loads(args.report.read_text())
            print(json.dumps({"verified": apply_report(root, approved, args.key, client)}))
            return 0
        plan, _ = load_specs(root)
        report = make_report(
            root,
            client.snapshot(plan["project"]["number"]),
            selected_keys=set(args.key) if args.exact_source_adoption else None,
            exact_source_adoption=args.exact_source_adoption,
        )
        if args.mode == "verify":
            selected = [e for e in report["entries"] if not args.key or e["key"] in args.key]
            if set(args.key) - {e["key"] for e in selected}:
                raise ValueError("Unknown verification key")
            for entry in selected:
                print(f"{entry['key']}: {entry['action']} {entry['reason']}")
            return 0 if all(e["action"] == "unchanged" for e in selected) else 1
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = root / AUDIT / f"dry-run-{stamp}.json"
        save(destination, report)
        save_summary(destination.with_suffix(".md"), report)
        print(
            json.dumps(
                {
                    "report": str(destination),
                    "counts": report["counts"],
                    "records": len(report["entries"]),
                },
                indent=2,
            )
        )
        return 0
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        print(f"Acceptance sync stopped: {sanitize_discovery_value(str(error))}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
