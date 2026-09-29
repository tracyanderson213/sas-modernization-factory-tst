from __future__ import annotations

from collections.abc import Iterable

PUBLIC_EVIDENCE_PREFIX = "tests/corpus/workloads/public/"
PRIVATE_BOUNDARY_PREFIXES = (
    "tests/corpus/private/",
    "tests/corpus/workloads/private/",
    "private-corpus/",
)
QUALITY_CONTROL_PATHS = {
    ".gitignore",
    ".pre-commit-config.yaml",
    "CODEOWNERS",
    "competition/COMPETITION-PLAN.md",
    "competition/generated/replan.yaml",
    "competition/requirements.yaml",
    "Makefile",
    "SECURITY.md",
    "pyproject.toml",
    "docs/architecture/security-model.md",
    "deployments/humana/security-policy.yaml",
    "scripts/test-discovery-confidence.sh",
    "src/smf/workload/sanitization.py",
}
QUALITY_CONTROL_PREFIXES = (
    ".github/workflows/",
    "competition/generated/issue-specs/",
    "scripts/engineering-agent/",
    "scripts/project-tools/",
    "src/smf/engineering_agent/",
)


def forbidden_developer_changes(paths: Iterable[str]) -> tuple[str, ...]:
    violations: list[str] = []
    for path in paths:
        if (
            path.startswith(PUBLIC_EVIDENCE_PREFIX)
            or any(path.startswith(prefix) for prefix in PRIVATE_BOUNDARY_PREFIXES)
            or any(path.startswith(prefix) for prefix in QUALITY_CONTROL_PREFIXES)
            or path in QUALITY_CONTROL_PATHS
        ):
            violations.append(path)
    return tuple(sorted(set(violations)))


def role_write_violations(
    before: Iterable[str], after: Iterable[str], *, role: str
) -> tuple[str, ...]:
    changed = set(after) - set(before)
    allowed = {f"agent-artifacts/{'architect' if role == 'architect' else 'review'}.md"}
    return tuple(sorted(path for path in changed if path not in allowed))
