from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import TextIO

from .models import AgentInvocation

_CODEX_SANDBOX = {
    "architect": "read-only",
    "developer": "workspace-write",
    "reviewer": "workspace-write",
}


def codex_command(
    worktree: Path,
    role: str,
    final_message_path: Path,
    *,
    executable: str = "codex",
) -> list[str]:
    try:
        sandbox = _CODEX_SANDBOX[role]
    except KeyError as exc:
        raise ValueError(f"Unsupported agent role: {role}") from exc
    return [
        executable,
        "--ask-for-approval",
        "never",
        "exec",
        "--sandbox",
        sandbox,
        "--ephemeral",
        "--cd",
        str(worktree),
        "--output-last-message",
        str(final_message_path),
        "-",
    ]


def _external_command(runner: str, role: str) -> list[str]:
    return [*shlex.split(runner), role]


def _pump(stream: TextIO, target: TextIO, console: TextIO) -> None:
    try:
        for line in iter(stream.readline, ""):
            target.write(line)
            target.flush()
            console.write(line)
            console.flush()
    finally:
        stream.close()


def run_external_agent(
    worktree: Path,
    role: str,
    prompt: str,
    run_dir: Path,
    command: str | None = None,
    attempt: int = 1,
) -> AgentInvocation:
    runner = command or os.environ.get("SMF_AGENT_RUNNER") or "codex"
    run_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = run_dir / f"{role}-prompt-{attempt}.md"
    stdout_path = run_dir / f"{role}-stdout-{attempt}.txt"
    stderr_path = run_dir / f"{role}-stderr-{attempt}.txt"
    final_message_path = run_dir / f"{role}-final-{attempt}.md"
    prompt_path.write_text(prompt, encoding="utf-8")

    if runner == "codex":
        executable = shutil.which("codex")
        if executable is None:
            raise ValueError("Codex runner selected but 'codex' is not installed or not on PATH.")
        argv = codex_command(worktree, role, final_message_path, executable=executable)
    else:
        argv = _external_command(runner, role)

    env = os.environ.copy()
    with (
        stdout_path.open("w", encoding="utf-8") as stdout_file,
        stderr_path.open("w", encoding="utf-8") as stderr_file,
    ):
        process = subprocess.Popen(
            argv,
            cwd=worktree,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        out_thread = threading.Thread(
            target=_pump, args=(process.stdout, stdout_file, sys.stdout), daemon=True
        )
        err_thread = threading.Thread(
            target=_pump, args=(process.stderr, stderr_file, sys.stderr), daemon=True
        )
        out_thread.start()
        err_thread.start()
        process.stdin.write(prompt)
        process.stdin.close()
        returncode = process.wait()
        out_thread.join()
        err_thread.join()

    if runner != "codex":
        final_message_path.write_text(stdout_path.read_text(encoding="utf-8"), encoding="utf-8")
    return AgentInvocation(role, returncode, stdout_path, stderr_path, final_message_path)
