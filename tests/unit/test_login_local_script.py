from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "login-local.sh"


def _run(
    shell: str,
    command: str,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [shell, "-c", command],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _fake_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    state = tmp_path / "state"
    root.mkdir()
    bin_dir.mkdir()
    state.mkdir()
    activate = root / ".venv" / "bin" / "activate"
    activate.parent.mkdir(parents=True)
    activate.write_text(
        f'export VIRTUAL_ENV="{root / ".venv"}"\nexport PATH="{bin_dir}:$PATH"\n',
        encoding="utf-8",
    )

    _write_executable(
        bin_dir / "git",
        "#!/bin/sh\n"
        f"[ \"$1 $2\" = \"rev-parse --show-toplevel\" ] && printf '%s\\n' '{root}' && exit 0\n"
        "exit 2\n",
    )
    _write_executable(
        bin_dir / "python",
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  --version) echo 'Python 3.12.test' ;;\n"
        "  -c) exit 0 ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
    )

    command_log = state / "commands.log"
    _write_executable(
        bin_dir / "az",
        f"""#!/bin/sh
printf 'az' >> '{command_log}'
printf ' %s' "$@" >> '{command_log}'
printf '\n' >> '{command_log}'
case "$1" in
  login) touch '{state / "azure"}'; exit 0 ;;
  account)
    case "$2" in
      get-access-token) [ -f '{state / "azure"}' ]; exit $? ;;
      set) exit 0 ;;
      show)
        case "$*" in
          *"--query name"*) echo 'test-account' ;;
          *) echo '00000000-0000-0000-0000-000000000000' ;;
        esac
        exit 0 ;;
    esac ;;
esac
exit 2
""",
    )
    _write_executable(
        bin_dir / "databricks",
        f"""#!/bin/sh
printf 'databricks' >> '{command_log}'
printf ' %s' "$@" >> '{command_log}'
printf '\n' >> '{command_log}'
case "$1 $2" in
  "auth login") touch '{state / "databricks"}'; exit 0 ;;
  "auth describe") [ -f '{state / "databricks"}' ]; exit $? ;;
  "current-user me") [ -f '{state / "databricks"}' ]; exit $? ;;
esac
exit 2
""",
    )
    _write_executable(
        bin_dir / "gh",
        f"""#!/bin/sh
printf 'gh' >> '{command_log}'
printf ' %s' "$@" >> '{command_log}'
printf '\n' >> '{command_log}'
case "$1 $2" in
  "auth login") touch '{state / "github"}'; exit 0 ;;
  "auth status") [ -f '{state / "github"}' ]; exit $? ;;
esac
exit 2
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "SMF_AZURE_TENANT_ID": "tenant-identifier",
            "SMF_AZURE_SUBSCRIPTION": "subscription-identifier",
            "SMF_DATABRICKS_PROFILE": "test-profile",
            "SMF_DATABRICKS_HOST": "https://example.invalid",
            "AZURE_ACCESS_TOKEN": "AZURE_SECRET_CANARY",
            "DATABRICKS_TOKEN": "DATABRICKS_SECRET_CANARY",
            "GH_TOKEN": "GITHUB_SECRET_CANARY",
        }
    )
    return command_log, env


def test_script_is_executable_but_not_world_writable() -> None:
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755


@pytest.mark.parametrize("shell", ["/bin/bash", "/bin/zsh"])
def test_source_help_and_skip_mode_are_shell_compatible(shell: str) -> None:
    if not Path(shell).exists():
        pytest.skip(f"{shell} is unavailable")

    help_result = _run(shell, f'source "{SCRIPT}" --help')
    assert help_result.returncode == 0
    assert "Usage: source scripts/login-local.sh" in help_result.stdout

    skip_result = _run(
        shell,
        f'source "{SCRIPT}" --skip-azure --skip-databricks --skip-github',
    )
    assert skip_result.returncode == 1
    assert ".venv does not exist" in skip_result.stderr


def test_direct_execution_and_unknown_option_fail_closed() -> None:
    direct = subprocess.run([str(SCRIPT)], text=True, capture_output=True, check=False)
    assert direct.returncode == 2
    assert "source scripts/login-local.sh" in direct.stderr

    unknown = _run("/bin/bash", f'source "{SCRIPT}" --unknown')
    assert unknown.returncode == 2
    assert "Unknown option" in unknown.stderr


@pytest.mark.parametrize("shell", ["/bin/bash", "/bin/zsh"])
def test_existing_cli_auth_is_used_without_exposing_tokens(
    shell: str,
    tmp_path: Path,
) -> None:
    if not Path(shell).exists():
        pytest.skip(f"{shell} is unavailable")
    command_log, env = _fake_repo(tmp_path)

    result = _run(shell, f'source "{SCRIPT}"', env=env)

    assert result.returncode == 0, result.stderr
    assert "Local SMF session is ready" in result.stdout
    assert "Azure:      authenticated" in result.stdout
    assert "Databricks: authenticated (profile: test-profile)" in result.stdout
    assert "GitHub:     authenticated" in result.stdout

    combined = result.stdout + result.stderr + command_log.read_text(encoding="utf-8")
    for canary in ("AZURE_SECRET_CANARY", "DATABRICKS_SECRET_CANARY", "GITHUB_SECRET_CANARY"):
        assert canary not in combined

    log = command_log.read_text(encoding="utf-8")
    assert "az login --tenant tenant-identifier --output none" in log
    assert "az account set --subscription subscription-identifier" in log
    assert "databricks auth login --profile test-profile --host https://example.invalid" in log
    assert "databricks auth describe --profile test-profile" in log
    assert "gh auth login --hostname github.com --git-protocol https --web" in log
    assert set(path.name for path in command_log.parent.iterdir()) == {
        "azure",
        "commands.log",
        "databricks",
        "github",
    }


def test_valid_sessions_are_reused_and_missing_cli_fails_closed(tmp_path: Path) -> None:
    command_log, env = _fake_repo(tmp_path)
    for state_name in ("azure", "databricks", "github"):
        (command_log.parent / state_name).touch()

    reused = _run("/bin/bash", f'source "{SCRIPT}"', env=env)
    assert reused.returncode == 0, reused.stderr
    log = command_log.read_text(encoding="utf-8")
    assert "az login" not in log
    assert "databricks auth login" not in log
    assert "gh auth login" not in log

    (tmp_path / "bin" / "az").unlink()
    env["PATH"] = str(tmp_path / "bin")
    missing = _run("/bin/bash", f'source "{SCRIPT}"', env=env)
    assert missing.returncode == 1
    assert "Azure CLI (az) is not installed" in missing.stderr


def test_static_contract_contains_no_credential_storage_or_token_output() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "az account get-access-token" in source
    assert "databricks auth login" in source
    assert "gh auth login" in source
    assert "--output none" in source
    assert "DATABRICKS_TOKEN" not in source
    assert "GH_TOKEN" not in source
    assert "AZURE_ACCESS_TOKEN" not in source
    assert " > ~/." not in source
    assert " >> ~/." not in source
    assert "security add-generic-password" not in source
    assert "config set" not in source
    assert "auth token" not in source
