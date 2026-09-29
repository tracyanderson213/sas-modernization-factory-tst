from __future__ import annotations

from pathlib import Path

import yaml

from .models import BacklogItem
from .review_feedback import ReviewMode
from .review_learning import learned_patterns_for_prompt


def _review_patterns(repo_root: Path) -> str:
    path = repo_root / "scripts/engineering-agent/review-patterns.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    patterns = payload.get("patterns") or []
    return "\n".join(
        f"- {item.get('id')}: {item.get('instruction')}"
        for item in patterns
        if isinstance(item, dict)
    )


def render_role_prompt(
    repo_root: Path,
    role: str,
    item: BacklogItem,
    *,
    repair_context: str = "",
    reviewer_context: str = "",
    review_mode: ReviewMode = ReviewMode.DISCOVERY,
) -> str:
    template = (repo_root / "scripts/engineering-agent/prompts" / f"{role}.md").read_text(
        encoding="utf-8"
    )
    return template.format(
        backlog_key=item.key,
        title=item.title,
        priority=item.priority,
        status=item.status,
        implementation_state=item.implementation_state,
        issue_number=item.issue_number or "draft",
        acceptance_context=(
            item.issue_body or "No issue body present in the current Project snapshot."
        ),
        repair_context=repair_context or "No prior repair context.",
        reviewer_context=(
            reviewer_context or "No prior reviewer findings exist in this run or continuation."
        ),
        review_mode=review_mode.value.upper(),
        adversarial_patterns=(
            _review_patterns(repo_root)
            + "\n\nCross-item learned reviewer patterns:\n"
            + learned_patterns_for_prompt(repo_root)
        ),
    )
