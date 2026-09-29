from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def create_worktree(repo_root: Path, key: str, base: str = "main") -> Path:
    target = repo_root.parent / ".smf-agent-worktrees" / key.lower()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ValueError(f"Worktree already exists: {target}")
    branch = f"agent/{key.lower()}"
    if (
        subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            cwd=repo_root,
            check=False,
        ).returncode
        == 0
    ):
        raise ValueError(f"Agent branch already exists: {branch}")
    subprocess.run(
        ["git", "worktree", "add", "-b", branch, str(target), base], cwd=repo_root, check=True
    )
    return target


def commit_candidate(worktree: Path, key: str) -> str:
    """Commit one reviewed candidate locally and return its immutable commit SHA."""
    subprocess.run(["git", "diff", "--check"], cwd=worktree, check=True)
    # agent-artifacts/ is repository-ignored by contract.  Passing an explicit
    # exclude pathspec for that ignored directory makes some Git versions fail
    # the otherwise successful add with "path is ignored".  A normal add
    # already excludes ignored, untracked run artifacts while still staging all
    # reviewed tracked and untracked candidate changes.
    subprocess.run(["git", "add", "-A", "--", "."], cwd=worktree, check=True)
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], cwd=worktree, check=False
    ).returncode
    if staged == 0:
        raise ValueError(f"{key}: reviewed candidate contains no committable changes")
    if staged != 1:
        raise RuntimeError(f"{key}: unable to inspect staged candidate")
    subprocess.run(["git", "commit", "-m", f"feat: implement {key}"], cwd=worktree, check=True)
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=worktree,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_changed_paths(worktree: Path) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "-uall"],
        cwd=worktree,
        text=True,
        capture_output=True,
        check=True,
    )
    paths: list[str] = []
    for line in completed.stdout.splitlines():
        if line:
            path = line[3:].split(" -> ")[-1]
            paths.append(path)
    return tuple(sorted(set(paths)))


def implementation_fingerprint(worktree: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    diff = subprocess.run(
        ["git", "diff", "--binary", "HEAD", "--", ".", ":(exclude)agent-artifacts/**"],
        cwd=worktree,
        capture_output=True,
        check=True,
    ).stdout
    digest.update(diff)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=worktree,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    for relative in sorted(path for path in untracked if not path.startswith("agent-artifacts/")):
        digest.update(relative.encode())
        digest.update((worktree / relative).read_bytes())
    return digest.hexdigest()


def _replace_tree_contents(source: Path, target: Path) -> None:
    """Mirror source working-tree contents into target while preserving target/.git."""

    for child in target.iterdir():
        if child.name == ".git":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()

    for child in source.iterdir():
        if child.name == ".git":
            continue
        destination = target / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, destination, symlinks=True)
        elif child.is_symlink():
            destination.symlink_to(child.readlink())
        else:
            shutil.copy2(child, destination)


def _remove_prior_review_artifact(review_root: Path) -> None:
    review = review_root / "agent-artifacts" / "review.md"
    if review.exists():
        review.unlink()


@contextmanager
def disposable_review_workspace(worktree: Path) -> Iterator[Path]:
    """Create an isolated writable Git snapshot of the candidate for independent review.

    The snapshot has its own local .git directory based on the candidate HEAD, then receives
    an exact mirror of the candidate working tree. Reviewer writes, caches, and temporary
    files therefore cannot mutate the authoritative candidate worktree.
    """

    with tempfile.TemporaryDirectory(prefix="smf-review-") as temporary:
        review_root = Path(temporary) / "candidate"
        subprocess.run(
            ["git", "clone", "--quiet", "--no-hardlinks", str(worktree), str(review_root)],
            check=True,
            text=True,
            capture_output=True,
        )
        _replace_tree_contents(worktree, review_root)
        _remove_prior_review_artifact(review_root)
        yield review_root
