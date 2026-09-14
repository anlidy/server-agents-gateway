"""
Open bash -lc execution with PATH-injected rm wrapper.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .config import config


class CommandExecutionError(Exception):
    pass


def clip_output(stdout: str, stderr: str, max_bytes: int) -> Tuple[str, str, bool]:
    out_b = (stdout or "").encode("utf-8")
    err_b = (stderr or "").encode("utf-8")
    if len(out_b) + len(err_b) <= max_bytes:
        return stdout or "", stderr or "", False
    if len(out_b) >= max_bytes:
        cut = out_b[:max_bytes].decode("utf-8", errors="ignore") + "\n[truncated]\n"
        return cut, "\n[truncated]\n", True
    remain = max_bytes - len(out_b)
    cut_err = err_b[:remain].decode("utf-8", errors="ignore") + "\n[truncated]\n"
    return stdout or "", cut_err, True


def execute_shell(
    command: str,
    cwd: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    agent_id: str = "",
) -> Tuple[int, str, str, bool]:
    cmd = (command or "").strip()
    if not cmd:
        raise CommandExecutionError("Empty command")
    if len(cmd.encode("utf-8")) > 64 * 1024:
        raise CommandExecutionError("Command too long")
    timeout = config.shell_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
    timeout = min(max(1, timeout), config.shell_timeout_max)
    workdir = cwd or config.shell_cwd
    if not Path(workdir).is_dir():
        raise CommandExecutionError(f"cwd does not exist: {workdir}")

    env = os.environ.copy()
    wrappers = str(config.wrappers_dir)
    env["PATH"] = wrappers + os.pathsep + env.get("PATH", "")
    if agent_id:
        env["SAG_AGENT_ID"] = agent_id

    proc = subprocess.Popen(
        ["/bin/bash", "-lc", cmd],
        cwd=workdir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        code = proc.returncode if proc.returncode is not None else -1
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except Exception:
                pass
        stdout, stderr = proc.communicate()
        code = -1
        stderr = (stderr or "") + f"\nCommand timed out after {timeout}s"
    stdout, stderr, truncated = clip_output(stdout or "", stderr or "", config.audit_body_max_bytes)
    if timed_out:
        truncated = truncated  # keep clip flag; exit_code already -1
    return code, stdout, stderr, truncated
