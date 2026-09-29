from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .review_feedback import ReviewFinding, finding_signature

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNSPECIFIED": 0}
_MAX_EXAMPLES_PER_LEARNING = 8
_PROMPT_DETAIL_LIMIT = 320


def _registry_path(repo_root: Path) -> Path:
    return repo_root / ".smf-agent" / "review-learning.json"


def _pattern_catalog(repo_root: Path) -> list[dict[str, Any]]:
    path = repo_root / "scripts/engineering-agent/review-patterns.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    patterns = payload.get("patterns") or []
    return [item for item in patterns if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _novel_id(finding: ReviewFinding) -> str:
    digest = hashlib.sha256(finding_signature(finding).encode("utf-8")).hexdigest()[:12]
    return f"LEARNED-{digest.upper()}"


def _term_matches(text: str, term: str) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return False
    pattern = r"(?<![a-z0-9_])" + re.escape(normalized).replace(r"\ ", r"\s+") + r"(?![a-z0-9_])"
    return re.search(pattern, text.lower()) is not None


def classify_finding(repo_root: Path, finding: ReviewFinding) -> str | None:
    """Map only clearly supported reviewer findings to static defect patterns."""
    title = finding.title.lower()
    detail = finding.detail.lower()
    candidates: list[tuple[int, int, str]] = []

    for item in _pattern_catalog(repo_root):
        terms = item.get("match_terms") or []
        if not isinstance(terms, list):
            continue

        title_hits = sum(_term_matches(title, str(term)) for term in terms)
        detail_hits = sum(_term_matches(detail, str(term)) for term in terms)
        if not title_hits and not detail_hits:
            continue

        score = title_hits * 4 + detail_hits
        candidates.append((score, title_hits, str(item.get("id"))))

    if not candidates:
        return None

    candidates.sort(reverse=True)
    best = candidates[0]
    if sum(1 for item in candidates if item[:2] == best[:2]) != 1:
        return None

    score, title_hits, pattern_id = best
    if title_hits == 0 and score < 2:
        return None
    return pattern_id


def load_learning_registry(repo_root: Path) -> dict[str, Any]:
    path = _registry_path(repo_root)
    if not path.exists():
        return {"version": 1, "findings": {}}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), dict):
        raise ValueError(f"Invalid review learning registry: {path}")
    return payload


def record_review_learning(
    repo_root: Path,
    finding: ReviewFinding,
    *,
    backlog_key: str,
    run_dir: Path,
    previously_seen_signatures: set[str],
    review_disposition: str = "blocking",
) -> dict[str, Any]:
    """Persist cross-item reviewer learning outside the Git-tracked product surface."""
    registry = load_learning_registry(repo_root)
    entries: dict[str, Any] = registry["findings"]
    signature = finding_signature(finding)
    static_pattern = classify_finding(repo_root, finding)
    learning_id = static_pattern or _novel_id(finding)
    current = entries.get(learning_id, {})
    examples = _existing_examples(current)
    existing_signatures = {
        *map(str, current.get("signatures", [])),
        *(str(example.get("signature", "")) for example in examples),
    }
    exact_repeat = signature in existing_signatures or signature in previously_seen_signatures
    same_family_new_manifestation = bool(
        static_pattern and current and signature not in existing_signatures
    )
    backlog_keys = sorted({*map(str, current.get("backlog_keys", [])), backlog_key})
    source_runs = [*map(str, current.get("source_runs", []))]
    run_value = str(run_dir)
    if run_value not in source_runs:
        source_runs.append(run_value)
    seen_before = bool(current) or signature in previously_seen_signatures
    timestamp = _now()
    matching_example = next(
        (example for example in examples if example.get("signature") == signature), None
    )
    if matching_example is None:
        examples.append(
            {
                "signature": signature,
                "severity": finding.severity,
                "title": finding.title,
                "detail_excerpt": finding.detail[:1200],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "occurrences": 1,
                "review_disposition": review_disposition,
            }
        )
    else:
        matching_example.update(
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail_excerpt": finding.detail[:1200],
                "last_seen": timestamp,
                "occurrences": int(matching_example.get("occurrences", 0)) + 1,
                "review_disposition": review_disposition,
            }
        )
    examples.sort(key=lambda example: str(example.get("last_seen", "")), reverse=True)
    examples = examples[:_MAX_EXAMPLES_PER_LEARNING]
    if exact_repeat:
        discovery_kind = "exact_repeated_finding"
    elif same_family_new_manifestation:
        discovery_kind = "same_static_family_new_manifestation"
    elif static_pattern:
        discovery_kind = "known_static_family_first_manifestation"
    else:
        discovery_kind = "genuinely_novel_finding"
    entries[learning_id] = {
        "learning_id": learning_id,
        "static_pattern_id": static_pattern,
        # Retain the legacy representative fields for registry compatibility. New
        # manifestations are accumulated in ``examples`` instead of overwriting them.
        "signature": str(current.get("signature") or signature),
        "severity": str(current.get("severity") or finding.severity),
        "title": str(current.get("title") or finding.title),
        "detail_excerpt": str(current.get("detail_excerpt") or finding.detail[:1200]),
        "examples": examples,
        "signatures": sorted({*existing_signatures, signature}),
        "first_seen": str(current.get("first_seen") or timestamp),
        "last_seen": timestamp,
        "occurrences": int(current.get("occurrences", 0)) + 1,
        "backlog_keys": backlog_keys,
        "source_runs": source_runs[-20:],
        "escape_analysis": {
            "known_before_review": seen_before or static_pattern is not None,
            "escaped_architect_specification": static_pattern is not None,
            "escaped_developer_self_review": True,
            "escaped_deterministic_gates": True,
            "novel_reviewer_discovery": static_pattern is None and not seen_before,
            "exact_repeated_finding": exact_repeat,
            "same_static_family_new_manifestation": same_family_new_manifestation,
            "durable_family_id": static_pattern,
            "discovery_kind": discovery_kind,
        },
    }
    path = _registry_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    learned = entries[learning_id]
    if not isinstance(learned, dict):
        raise TypeError("learning registry entry must be an object")
    return learned


def _existing_examples(entry: dict[str, Any]) -> list[dict[str, Any]]:
    raw_examples = entry.get("examples")
    if isinstance(raw_examples, list):
        return [dict(example) for example in raw_examples if isinstance(example, dict)]
    if not entry or not entry.get("signature"):
        return []
    return [
        {
            "signature": str(entry.get("signature", "")),
            "severity": str(entry.get("severity", "UNSPECIFIED")),
            "title": str(entry.get("title", "Reviewer finding")),
            "detail_excerpt": str(entry.get("detail_excerpt", "")),
            "first_seen": str(entry.get("first_seen", "")),
            "last_seen": str(entry.get("last_seen", "")),
            "occurrences": int(entry.get("occurrences", 1)),
            "review_disposition": str(entry.get("review_disposition", "blocking")),
        }
    ]


def learned_patterns_for_prompt(repo_root: Path, *, limit: int = 12) -> str:
    """Return bounded accumulated examples of static and novel reviewer findings."""
    entries = list(load_learning_registry(repo_root)["findings"].values())
    accumulated: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        for example in _existing_examples(item):
            accumulated.append((item, example))
    accumulated.sort(key=lambda pair: str(pair[1].get("last_seen", "")), reverse=True)
    accumulated.sort(
        key=lambda pair: (
            -_SEVERITY_RANK.get(str(pair[1].get("severity", "UNSPECIFIED")), 0),
            -int(pair[1].get("occurrences", 0)),
        )
    )
    bounded_limit = max(0, limit)
    selected = accumulated[:bounded_limit]
    if bounded_limit >= 2:
        static = next((pair for pair in accumulated if pair[0].get("static_pattern_id")), None)
        novel = next((pair for pair in accumulated if not pair[0].get("static_pattern_id")), None)
        for representative in (static, novel):
            if representative is not None and representative not in selected:
                selected[-1] = representative
    if not selected:
        return "- No additional learned reviewer patterns have been persisted yet."
    lines: list[str] = []
    for item, example in selected:
        detail = " ".join(str(example.get("detail_excerpt", "")).split())
        if len(detail) > _PROMPT_DETAIL_LIMIT:
            detail = detail[: _PROMPT_DETAIL_LIMIT - 1].rstrip() + "…"
        lines.append(
            f"- {item['learning_id']} [{example.get('severity', 'UNSPECIFIED')}]: "
            f"{example.get('title', 'Reviewer finding')} "
            f"[{example.get('review_disposition', 'blocking')}] "
            f"(seen {example.get('occurrences', 0)}x; family seen "
            f"{item.get('occurrences', 0)}x across "
            f"{len(item.get('backlog_keys', []))} backlog item(s)) — Detail: {detail}"
        )
    return "\n".join(lines)
