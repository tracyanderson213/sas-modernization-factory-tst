from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .review_feedback import (
    ClosureDisposition,
    ReviewFinding,
    ReviewMode,
    ReviewPacket,
    finding_signature,
)


@dataclass(frozen=True)
class BlockingFinding:
    blocking_id: str
    finding: ReviewFinding
    origin: str


@dataclass(frozen=True)
class DeferredFinding:
    finding: ReviewFinding
    reason: str


@dataclass(frozen=True)
class ReviewScope:
    mode: ReviewMode
    unresolved: tuple[BlockingFinding, ...] = ()
    resolved: tuple[BlockingFinding, ...] = ()
    deferred: tuple[DeferredFinding, ...] = ()


def discovery_scope(packet: ReviewPacket) -> ReviewScope:
    if packet.passed:
        return ReviewScope(ReviewMode.DISCOVERY)
    return ReviewScope(
        ReviewMode.CLOSURE,
        unresolved=tuple(
            BlockingFinding(f"BF-{index:03d}", finding, "discovery")
            for index, finding in enumerate(packet.findings, 1)
        ),
    )


def _next_blocking_id(scope: ReviewScope) -> str:
    ids = [item.blocking_id for item in (*scope.unresolved, *scope.resolved)]
    numbers = [int(item.removeprefix("BF-")) for item in ids]
    return f"BF-{max(numbers, default=0) + 1:03d}"


def _criterion_is_attributable(criterion: str, acceptance_context: str) -> bool:
    normalized_criterion = re.sub(r"\s+", " ", criterion).strip().casefold()
    normalized_context = re.sub(r"\s+", " ", acceptance_context).strip().casefold()
    return bool(normalized_criterion) and normalized_criterion in normalized_context


def classify_closure(
    packet: ReviewPacket, scope: ReviewScope, *, acceptance_context: str = ""
) -> ReviewScope:
    """Apply closure policy without allowing novel sibling probes to broaden repair scope."""
    if scope.mode is not ReviewMode.CLOSURE:
        raise ValueError("Closure classification requires an established discovery scope.")
    if packet.passed:
        return ReviewScope(
            ReviewMode.CLOSURE,
            resolved=(*scope.resolved, *scope.unresolved),
            deferred=scope.deferred,
        )

    by_id = {item.blocking_id: item for item in scope.unresolved}
    by_signature = {finding_signature(item.finding): item for item in scope.unresolved}
    still_blocking: list[BlockingFinding] = []
    deferred: list[DeferredFinding] = list(scope.deferred)
    matched_ids: set[str] = set()
    next_id = _next_blocking_id(scope)

    for finding in packet.findings:
        exact = by_signature.get(finding_signature(finding))
        referenced = by_id.get(finding.blocking_finding_id or "")
        if finding.blocking_finding_id and referenced is None:
            raise ValueError(
                f"Closure review referenced unknown blocking finding {finding.blocking_finding_id}."
            )
        if exact is not None:
            if exact.blocking_id in matched_ids:
                raise ValueError(
                    f"Closure review matched blocking finding {exact.blocking_id} more than once."
                )
            still_blocking.append(BlockingFinding(exact.blocking_id, finding, exact.origin))
            matched_ids.add(exact.blocking_id)
            continue
        if (
            referenced is not None
            and finding.closure_disposition is not ClosureDisposition.DEFERRED
        ):
            if referenced.blocking_id in matched_ids:
                raise ValueError(
                    "Closure review matched blocking finding "
                    f"{referenced.blocking_id} more than once."
                )
            still_blocking.append(
                BlockingFinding(referenced.blocking_id, finding, referenced.origin)
            )
            matched_ids.add(referenced.blocking_id)
            continue
        if finding.closure_disposition is ClosureDisposition.UNRESOLVED_BLOCKER:
            raise ValueError("An unresolved blocker must reference a known blocking finding ID.")
        if finding.closure_disposition is ClosureDisposition.ACCEPTANCE_CRITERIA_REGRESSION:
            if not finding.acceptance_criterion:
                raise ValueError(
                    "An acceptance-criteria regression must name the regressed criterion."
                )
            if not _criterion_is_attributable(finding.acceptance_criterion, acceptance_context):
                deferred.append(
                    DeferredFinding(
                        finding,
                        "claimed acceptance criterion is not attributable to the backlog item",
                    )
                )
                continue
            still_blocking.append(BlockingFinding(next_id, finding, "acceptance_regression"))
            number = int(next_id.removeprefix("BF-")) + 1
            next_id = f"BF-{number:03d}"
            continue
        deferred.append(
            DeferredFinding(
                finding,
                "new closure finding outside the established blocking set",
            )
        )

    newly_resolved = tuple(item for item in scope.unresolved if item.blocking_id not in matched_ids)
    return ReviewScope(
        ReviewMode.CLOSURE,
        unresolved=tuple(still_blocking),
        resolved=(*scope.resolved, *newly_resolved),
        deferred=tuple(deferred),
    )


def blocking_packet(scope: ReviewScope) -> ReviewPacket | None:
    if not scope.unresolved:
        return None
    findings = tuple(item.finding for item in scope.unresolved)
    return ReviewPacket("FAIL", findings, "\n".join(item.detail for item in findings))


def _finding_from_payload(payload: dict[str, Any]) -> ReviewFinding:
    decoded = dict(payload)
    disposition = decoded.get("closure_disposition")
    if disposition is not None:
        decoded["closure_disposition"] = ClosureDisposition(disposition)
    return ReviewFinding(**decoded)


def _blocking_from_payload(payload: dict[str, Any]) -> BlockingFinding:
    return BlockingFinding(
        blocking_id=str(payload["blocking_id"]),
        finding=_finding_from_payload(dict(payload["finding"])),
        origin=str(payload["origin"]),
    )


def write_review_scope(path: Path, scope: ReviewScope) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(asdict(scope), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def load_review_scope(path: Path) -> ReviewScope:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return ReviewScope(
        mode=ReviewMode(payload["mode"]),
        unresolved=tuple(_blocking_from_payload(item) for item in payload.get("unresolved", [])),
        resolved=tuple(_blocking_from_payload(item) for item in payload.get("resolved", [])),
        deferred=tuple(
            DeferredFinding(
                finding=_finding_from_payload(dict(item["finding"])),
                reason=str(item["reason"]),
            )
            for item in payload.get("deferred", [])
        ),
    )
