"""
Execution engine with strict allowlist and argv-only execution (no shell).
"""

import shlex
import subprocess
from typing import List, Tuple

# Pre-defined allowlisted command prefixes (matched on argv, not raw shell strings)
ALLOWLIST_PREFIXES: List[str] = [
    # System resources & inspection
    "df",
    "free",
    "uptime",
    "ps",
    "top -b -n 1",
    "ss",
    "netstat",
    "ping -c",
    "dig",
    "traceroute",
    "curl",
    "wget -qO-",
    "journalctl",
    # Docker readouts
    "docker ps",
    "docker stats --no-stream",
    "docker logs",
    "docker inspect",
    # Systemd inspection
    "systemctl status",
    "systemctl is-active",
    "systemctl list-units",
    # Git readouts
    "git status",
    "git log",
    "git diff",
    "git branch",
    # Managed scripts directory (path prefix)
    "/opt/server-agents-gateway/scripts/",
]

# Explicit forbidden tokens (meta-interpreters / shell control operators)
DISALLOWED_SUBSTRINGS: List[str] = [
    "bash -c",
    "sh -c",
    "zsh -c",
    "eval",
    "python -c",
    "python3 -c",
    "node -e",
    "perl -e",
    "ruby -e",
    "| bash",
    "| sh",
    "> /opt/server-agents-gateway",
    "rm -rf /",
    "mkfs",
]

BANNED_EXECUTABLES = {
    "bash",
    "sh",
    "zsh",
    "dash",
    "fish",
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "perl",
    "ruby",
    "php",
}

# Tokens that only make sense for shell chaining / redirection
SHELL_OPERATOR_TOKENS = {
    ";",
    "|",
    "||",
    "&",
    "&&",
    "`",
    ">",
    ">>",
    "<",
    "<<",
}


class CommandExecutionError(Exception):
    pass


def _split_argv(command: str) -> List[str]:
    try:
        argv = shlex.split(command.strip())
    except ValueError as exc:
        raise CommandExecutionError(f"403 Forbidden: Malformed command: {exc}") from exc
    if not argv:
        raise CommandExecutionError("403 Forbidden: Empty command")
    return argv


def is_command_allowed(command: str) -> bool:
    cmd_clean = command.strip()
    if not cmd_clean:
        return False

    for bad in DISALLOWED_SUBSTRINGS:
        if bad in cmd_clean:
            return False

    try:
        argv = shlex.split(cmd_clean)
    except ValueError:
        return False
    if not argv:
        return False

    exe = argv[0].rsplit("/", 1)[-1]
    if exe in BANNED_EXECUTABLES:
        return False

    for tok in argv:
        if tok in SHELL_OPERATOR_TOKENS or tok.startswith("$("):
            return False

    for prefix in ALLOWLIST_PREFIXES:
        # Directory allowlist: any executable under the managed scripts path
        if prefix.endswith("/"):
            if argv[0].startswith(prefix):
                return True
            continue
        try:
            prefix_argv = shlex.split(prefix)
        except ValueError:
            continue
        if not prefix_argv:
            continue
        if len(argv) >= len(prefix_argv) and argv[: len(prefix_argv)] == prefix_argv:
            return True
    return False


def execute_allowlisted_command(command: str, timeout_seconds: int = 30) -> Tuple[int, str, str]:
    """
    Executes a command safely under strict allowlist policy using argv (shell=False).
    Returns (exit_code, stdout, stderr).
    Raises CommandExecutionError if command violates policy.
    """
    if not is_command_allowed(command):
        raise CommandExecutionError(
            f"403 Forbidden: Command [{command}] is not permitted by Gateway Allowlist Policy. "
            f"Only pre-approved diagnostics and audited scripts are allowed."
        )

    argv = _split_argv(command)
    try:
        proc = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return (proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return (-1, stdout, stderr + f"\nCommand timed out after {timeout_seconds}s")
    except Exception as e:
        return (-1, "", f"Execution failure: {str(e)}")
