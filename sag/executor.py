"""
Open bash -lc execution. rm is bound to the wrapper by absolute path.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
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


def _operator_popen_args(cmd: str, cwd: Optional[str], agent_id: str):
    """operator：降权到普通用户，干净的环境，rm 进回收站 spool。cwd 在降权后的 shell 里 cd，
    这样进不去的目录就是进不去（Popen 的 cwd 是在 setuid 之前以 root 身份 chdir 的）。"""
    from .privilege import SAFE_PATH, ensure_home, operator_env, operator_identity, popen_kwargs, wrap_argv, WORKER

    ident = operator_identity()
    ensure_home(ident)
    workdir = cwd or ident.home
    env = operator_env(
        ident,
        agent_id,
        {
            "SAG_TRASH_SPOOL": ident.spool_dir,
            "SAG_TRASH_MAX_BYTES": str(config.operator_trash_max_mb * 1024 * 1024),
        },
    )
    rm_cmd = f"{shlex.quote(sys.executable)} -I {shlex.quote(str(WORKER))}"
    setup = (
        f"PATH={shlex.quote(SAFE_PATH)}; export PATH; "
        f"rm() {{ {rm_cmd} rm \"$@\"; }}; export -f rm; "
        f"cd -- {shlex.quote(workdir)} || exit 1; "
    )
    argv = wrap_argv(["/bin/bash", "-lc", setup + cmd])
    return argv, ident.home, env, popen_kwargs(ident), workdir


def execute_shell(
    command: str,
    cwd: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    agent_id: str = "",
    privileged: bool = True,
) -> Tuple[int, str, str, bool]:
    cmd = (command or "").strip()
    if not cmd:
        raise CommandExecutionError("Empty command")
    if len(cmd.encode("utf-8")) > 64 * 1024:
        raise CommandExecutionError("Command too long")
    timeout = config.shell_timeout_seconds if timeout_seconds is None else int(timeout_seconds)
    timeout = min(max(1, timeout), config.shell_timeout_max)
    if not privileged:
        argv, popen_cwd, env, extra, _workdir = _operator_popen_args(cmd, cwd, agent_id)
        return _run(argv, popen_cwd, env, timeout, extra)
    workdir = cwd or config.shell_cwd
    if not Path(workdir).is_dir():
        raise CommandExecutionError(f"cwd does not exist: {workdir}")

    env = os.environ.copy()
    wrappers = Path(config.wrappers_dir).resolve()
    abs_rm = wrappers / "rm"
    path = str(wrappers) + os.pathsep + env.get("PATH", "")
    env["PATH"] = path
    if agent_id:
        env["SAG_AGENT_ID"] = agent_id
    # Login shells rewrite PATH. Re-export an absolute wrappers dir and bind
    # rm() to the wrapper's absolute path so `rm ./file` never depends on PATH.
    setup = (
        f"PATH={shlex.quote(path)}; export PATH; "
        f"rm() {{ {shlex.quote(str(abs_rm))} \"$@\"; }}; "
        f"export -f rm; "
    )

    return _run(["/bin/bash", "-lc", setup + cmd], workdir, env, timeout, {})


def _run(argv, workdir, env, timeout, extra) -> Tuple[int, str, str, bool]:
    proc = subprocess.Popen(
        argv,
        cwd=workdir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        **extra,
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
