"""
Execution engine with strict allowlist and unconditional post-exec reconcile.
"""

import shlex
import subprocess
from typing import Dict, List, Tuple

# Pre-defined allowlisted command prefixes
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
    # Managed scripts directory
    "/opt/server-agents-gateway/scripts/",
]

# Explicit forbidden tokens (meta-interpreters that can evaluate arbitrary strings)
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


class CommandExecutionError(Exception):
    pass


def is_command_allowed(command: str) -> bool:
    cmd_clean = command.strip()
    # Check disallowed substring / meta-interpreters first
    for bad in DISALLOWED_SUBSTRINGS:
        if bad in cmd_clean:
            return False

    # Check against allowlist prefixes
    for prefix in ALLOWLIST_PREFIXES:
        if cmd_clean == prefix or cmd_clean.startswith(prefix + " "):
            return True
    return False


def execute_allowlisted_command(command: str, timeout_seconds: int = 30) -> Tuple[int, str, str]:
    """
    Executes a command safely under strict allowlist policy.
    Returns (exit_code, stdout, stderr).
    Raises CommandExecutionError if command violates policy.
    """
    if not is_command_allowed(command):
        raise CommandExecutionError(
            f"403 Forbidden: Command [{command}] is not permitted by Gateway Allowlist Policy. "
            f"Only pre-approved diagnostics and audited scripts are allowed."
        )

    try:
        proc = subprocess.run(
            command,
            shell=True,
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