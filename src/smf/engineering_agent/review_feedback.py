from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

_HISTORY_DETAIL_LIMIT = 600


class ReviewMode(StrEnum):
    DISCOVERY = "discovery"
    CLOSURE = "closure"


class ClosureDisposition(StrEnum):
    UNRESOLVED_BLOCKER = "unresolved_blocker"
    ACCEPTANCE_CRITERIA_REGRESSION = "acceptance_criteria_regression"
    DEFERRED = "deferred"


@dataclass(frozen=True)
class ReviewFinding:
    finding_id: str
    severity: str
    title: str
    detail: str
    closure_disposition: ClosureDisposition | None = None
    blocking_finding_id: str | None = None
    acceptance_criterion: str | None = None


@dataclass(frozen=True)
class ReviewPacket:
    verdict: str
    findings: tuple[ReviewFinding, ...]
    raw_review: str

    @property
    def passed(self) -> bool:
        return self.verdict == "PASS"


def _severity(text: str) -> str:
    match = re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b", text, re.IGNORECASE)
    return match.group(1).upper() if match else "UNSPECIFIED"


def _title(text: str) -> str:
    first = text.strip().splitlines()[0].strip()
    first = re.sub(r"^\*\*", "", first)
    first = re.sub(r"\*\*$", "", first)
    first = re.sub(r"^(?:critical|high|medium|low)\s*[-:]+\s*", "", first, flags=re.I)
    return first.strip()[:240] or "Reviewer finding"


def _closure_metadata(
    text: str,
) -> tuple[ClosureDisposition | None, str | None, str | None]:
    disposition_match = re.search(
        r"(?im)^\s*(?:[-*]\s*)?closure disposition\s*:\s*([a-z_ -]+?)\s*$", text
    )
    disposition: ClosureDisposition | None = None
    if disposition_match:
        raw = re.sub(r"[ -]+", "_", disposition_match.group(1).strip().lower())
        try:
            disposition = ClosureDisposition(raw)
        except ValueError as exc:
            supported = ", ".join(item.value for item in ClosureDisposition)
            raise ValueError(
                f"Unsupported closure disposition {raw!r}; expected one of: {supported}."
            ) from exc
    blocker_match = re.search(
        r"(?im)^\s*(?:[-*]\s*)?blocking finding(?: id)?\s*:\s*(BF-\d{3,})\s*$", text
    )
    criterion_match = re.search(r"(?im)^\s*(?:[-*]\s*)?acceptance criterion\s*:\s*(.+?)\s*$", text)
    return (
        disposition,
        blocker_match.group(1).upper() if blocker_match else None,
        criterion_match.group(1).strip() if criterion_match else None,
    )


def parse_review(text: str) -> ReviewPacket:
    raw = text.strip()
    if not raw:
        raise ValueError("Reviewer returned no final review.")
    first = raw.splitlines()[0].strip().upper().lstrip("#").strip()
    if first.startswith("PASS"):
        return ReviewPacket("PASS", (), raw)
    if not first.startswith("FAIL"):
        raise ValueError("Reviewer final response must begin with PASS or FAIL.")

    body = "\n".join(raw.splitlines()[1:]).strip()
    matches = list(re.finditer(r"(?m)^\s*(\d+)\.\s+(.*?)(?=^\s*\d+\.\s+|\Z)", body, re.S))
    chunks = [match.group(2).strip() for match in matches]
    # Keep trailing review-wide verification prose out of the final numbered finding.
    if chunks:
        markers = (
            r"(?im)^\s*verification\s*:",
            r"(?im)^\s*overall verification\s*:",
            r"(?im)^\s*the .* probes otherwise failed closed\.",
            r"(?im)^\s*all .* probes otherwise failed closed\.",
            r"(?im)^\s*ruff\b.*\bpassed\b",
        )
        final = chunks[-1]
        cut = len(final)
        for pattern in markers:
            match = re.search(pattern, final)
            if match:
                cut = min(cut, match.start())
        chunks[-1] = final[:cut].rstrip()
    if not chunks and body:
        chunks = [body]
    findings_list: list[ReviewFinding] = []
    for index, chunk in enumerate(chunks, 1):
        disposition, blocker_id, criterion = _closure_metadata(chunk)
        findings_list.append(
            ReviewFinding(
                finding_id=f"RF-{index:03d}",
                severity=_severity(chunk),
                title=_title(chunk),
                detail=chunk,
                closure_disposition=disposition,
                blocking_finding_id=blocker_id,
                acceptance_criterion=criterion,
            )
        )
    findings = tuple(findings_list)
    if not findings:
        raise ValueError("FAIL review must contain at least one concrete finding.")
    return ReviewPacket("FAIL", findings, raw)


def write_review_packet(path: Path, packet: ReviewPacket) -> None:
    payload: dict[str, Any] = {
        "verdict": packet.verdict,
        "findings": [asdict(item) for item in packet.findings],
        "raw_review": packet.raw_review,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_review_packet(path: Path) -> ReviewPacket:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: list[ReviewFinding] = []
    for item in payload.get("findings", []):
        decoded = dict(item)
        disposition = decoded.get("closure_disposition")
        if disposition is not None:
            decoded["closure_disposition"] = ClosureDisposition(disposition)
        findings.append(ReviewFinding(**decoded))
    return ReviewPacket(
        verdict=str(payload["verdict"]),
        findings=tuple(findings),
        raw_review=str(payload.get("raw_review", "")),
    )


def finding_signature(finding: ReviewFinding) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", finding.title.lower()).strip()
    return normalized


def _finding_family(finding: ReviewFinding, families: Mapping[str, str | None]) -> str | None:
    return (
        families.get(finding_signature(finding))
        or families.get(finding.title)
        or families.get(finding.finding_id)
    )


def render_repair_brief(
    current: ReviewPacket | None,
    history: tuple[ReviewPacket, ...],
    adversarial_patterns: str,
    gate_failure: str = "",
    finding_families: Mapping[str, str | None] | None = None,
    blocking_ids: Mapping[str, str] | None = None,
) -> str:
    families = finding_families or {}
    ids = blocking_ids or {}
    lines = [
        "# Developer Repair Brief",
        "",
        "Repair protocol: reproduce each defect first, add a regression test that fails before "
        "the fix, implement the smallest architecture-consistent fix, rerun the focused "
        "regression, then run all required gates. Never weaken a gate or delete evidence to "
        "obtain green output.",
        "",
    ]
    if gate_failure:
        lines.extend(["## Deterministic gate failure", "", gate_failure, ""])
    if current and current.findings:
        lines.extend(["## Current unresolved reviewer findings", ""])
        for finding in current.findings:
            family = _finding_family(finding, families)
            blocking_id = ids.get(finding_signature(finding))
            lines.extend(
                [
                    f"### {blocking_id or finding.finding_id} [{finding.severity}] {finding.title}",
                    "",
                    finding.detail,
                    "",
                ]
            )
            if family:
                lines.extend(
                    [
                        f"Durable defect family: {family}",
                        "",
                        "Self-review guidance: repair the underlying invariant and consider "
                        f"sibling manifestations of {family}. The closure reviewer will block "
                        "this item only for the exact blocker, a deterministic-gate failure, or "
                        "an explicit acceptance-criteria regression.",
                        "",
                    ]
                )
    historical = [packet for packet in history if packet.findings]
    if historical:
        lines.extend(
            [
                "## Historical reviewer findings that must remain fixed",
                "",
                "Do not regress any previously discovered defect class. Existing regression "
                "tests must remain.",
                "",
            ]
        )
        seen: set[str] = set()
        for packet in historical:
            for finding in packet.findings:
                signature = finding_signature(finding)
                if signature in seen:
                    continue
                seen.add(signature)
                family = _finding_family(finding, families)
                family_text = f"; durable family {family}" if family else ""
                lines.append(f"- [{finding.severity}] {finding.title}{family_text}")
        lines.append("")
    lines.extend(["## Required adversarial self-review", "", adversarial_patterns.strip(), ""])
    return "\n".join(lines).strip() + "\n"


def render_reviewer_convergence_context(
    history: tuple[ReviewPacket, ...],
    finding_families: Mapping[str, str | None],
    *,
    limit: int = 16,
    mode: ReviewMode | None = None,
    blocking_ids: Mapping[str, str] | None = None,
) -> str:
    """Render bounded prior-review evidence that a reviewer must independently reprobe."""
    findings: list[ReviewFinding] = []
    seen: set[str] = set()
    for packet in reversed(history):
        for finding in reversed(packet.findings):
            signature = finding_signature(finding)
            if signature not in seen:
                seen.add(signature)
                findings.append(finding)
    selected = findings[: max(0, limit)]
    selected_mode = mode or (ReviewMode.CLOSURE if selected else ReviewMode.DISCOVERY)
    ids = blocking_ids or {}
    if not selected:
        return (
            f"# Review mode: {selected_mode.value.upper()}\n\n"
            "No unresolved blocking findings exist in this run or continuation."
        )

    lines = [
        f"# Review mode: {selected_mode.value.upper()}",
        "",
        "The findings below are the complete unresolved blocking set. Verify them all in one "
        "closure pass. A finding outside this set is non-blocking unless it is an explicit "
        "deterministic-gate or acceptance-criteria regression. Record new sibling manifestations, "
        "unsupported combinations, and hardening opportunities as DEFERRED; they must not keep "
        "the current item open.",
        "",
    ]
    for finding in selected:
        family = _finding_family(finding, finding_families)
        detail = " ".join(finding.detail.split())
        if len(detail) > _HISTORY_DETAIL_LIMIT:
            detail = detail[: _HISTORY_DETAIL_LIMIT - 1].rstrip() + "…"
        lines.extend(
            [
                f"### {ids.get(finding_signature(finding), finding.finding_id)} "
                f"[{finding.severity}] {finding.title}",
                "",
                f"- Durable defect family: {family or 'unmapped novel finding'}",
                f"- Prior finding detail: {detail}",
                "",
            ]
        )
    omitted = len(findings) - len(selected)
    if omitted:
        lines.append(f"{omitted} older unique finding(s) omitted from this bounded context.\n")
    return "\n".join(lines).strip() + "\n"
