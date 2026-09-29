from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import BacklogItem, RunState


def create_run_dir(repo_root: Path, key: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base = repo_root / ".smf-agent" / "runs" / key
    run_dir = base / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = base / f"{stamp}-{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True)
    return run_dir


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def initialize_run(
    run_dir: Path, item: BacklogItem, worktree: Path, *, continuation_of: Path | None = None
) -> None:
    write_json(run_dir / "backlog-item.json", asdict(item))
    payload: dict[str, Any] = {
        "backlog_key": item.key,
        "state": RunState.CREATED.value,
        "worktree": str(worktree),
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "events": [],
    }
    if continuation_of is not None:
        payload["continuation_of"] = str(continuation_of)
    write_json(run_dir / "run.json", payload)


def record_event(run_dir: Path, state: RunState, message: str, **details: Any) -> None:
    path = run_dir / "run.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["state"] = state.value
    payload["updated_at"] = datetime.now(UTC).isoformat()
    payload["events"].append(
        {
            "at": datetime.now(UTC).isoformat(),
            "state": state.value,
            "message": message,
            "details": details,
        }
    )
    write_json(path, payload)


def write_final_report(run_dir: Path, state: RunState, message: str) -> None:
    (run_dir / "final-report.md").write_text(
        f"# SMF Engineering Agent Run\n\n**State:** {state.value}\n\n**Result:** {message}\n",
        encoding="utf-8",
    )


def latest_stopped_run(repo_root: Path, key: str) -> Path:
    base = repo_root / ".smf-agent" / "runs" / key
    if not base.exists():
        raise ValueError(f"No prior agent runs found for {key}.")
    for candidate in sorted((p for p in base.iterdir() if p.is_dir()), reverse=True):
        run_file = candidate / "run.json"
        if (
            run_file.exists()
            and json.loads(run_file.read_text(encoding="utf-8")).get("state")
            == RunState.STOPPED.value
        ):
            return candidate
    raise ValueError(f"No stopped agent run found for {key}.")


def load_run_payload(run_dir: Path) -> dict[str, Any]:
    decoded: object = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError(f"Agent run payload must be a JSON object: {run_dir / 'run.json'}")
    return {str(key): value for key, value in decoded.items()}


def latest_reviewer_findings(run_dir: Path) -> str:
    reviews = sorted(run_dir.glob("reviewer-final-*.md"))
    if not reviews:
        raise ValueError(f"Stopped run has no reviewer findings: {run_dir}")
    text = reviews[-1].read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"Latest reviewer findings are empty: {reviews[-1]}")
    return text


def continuation_chain(run_dir: Path) -> tuple[Path, ...]:
    """Return oldest-to-newest run directories in a continuation chain."""
    chain: list[Path] = []
    current: Path | None = run_dir
    seen: set[Path] = set()
    while current is not None:
        resolved = current.resolve()
        if resolved in seen:
            raise ValueError("Agent continuation chain contains a cycle.")
        seen.add(resolved)
        chain.append(current)
        payload = load_run_payload(current)
        parent = payload.get("continuation_of")
        current = Path(str(parent)) if parent else None
    return tuple(reversed(chain))


def reviewer_history(run_dir: Path) -> tuple[str, ...]:
    """Return every non-empty reviewer final message across the continuation chain."""
    reviews: list[str] = []
    for candidate in continuation_chain(run_dir):
        for path in sorted(candidate.glob("reviewer-final-*.md")):
            text = path.read_text(encoding="utf-8").strip()
            if text:
                reviews.append(text)
    return tuple(reviews)
