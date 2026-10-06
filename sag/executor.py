"""
Open bash -lc execution. A top-level rm() (not exported) calls the recycle-bin wrapper.
"""

from __future__ import annotations

import codecs
import os
import selectors
import shlex
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

from .config import config


class CommandExecutionError(Exception):
    pass


_READ_CHUNK = 64 * 1024
_TRUNCATED_MARK = "\n[truncated]\n"
# After the group is killed, how long to keep reading for EOF before giving up on the pipes.
_KILL_DRAIN_SECONDS = 1.0


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


class _Capture:
    """
    Keeps the first `cap` bytes of one pipe. Whatever follows is still read and
    thrown away, so the writer never blocks on a full pipe and the gateway never
    holds more than `cap` bytes per stream.
    """

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.buf = bytearray()
        self.dropped = False

    def feed(self, data: bytes) -> None:
        room = self.cap - len(self.buf)
        if room > 0:
            self.buf += data[:room]
        if len(data) > max(room, 0):
            self.dropped = True

    def text(self) -> str:
        # Command output is arbitrary bytes (binary files, other encodings): decoding must never fail.
        # While truncated, hold back a trailing partial UTF-8 sequence instead of emitting U+FFFD for it.
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        text = decoder.decode(bytes(self.buf), final=not self.dropped)
        # The pipes used to be read in text mode, which turned \r\n and \r into \n; keep that contract.
        return text.replace("\r\n", "\n").replace("\r", "\n")


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except Exception:
            pass


def _collect(proc: subprocess.Popen, out: _Capture, err: _Capture, timeout: int) -> Tuple[bool, bool]:
    """
    Read both pipes until EOF, then reap the shell, all within `timeout` seconds.
    On timeout the whole process group is killed, but we only wait a moment for
    the pipes to close: a detached process (setsid, double fork) can outlive the
    kill and keep them open, and must not keep this call, or its worker thread, alive.
    Returns (timed_out, pipes_still_held).
    """
    deadline = time.monotonic() + timeout
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, out)
    sel.register(proc.stderr, selectors.EVENT_READ, err)

    def pump(wait: float) -> None:
        for key, _ in sel.select(max(wait, 0.0)):
            data = os.read(key.fd, _READ_CHUNK)
            if data:
                key.data.feed(data)
            else:
                sel.unregister(key.fileobj)

    timed_out = False
    try:
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            pump(left)
        if not timed_out:
            try:
                proc.wait(timeout=max(deadline - time.monotonic(), 0.0))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            _kill_group(proc)
            end = time.monotonic() + _KILL_DRAIN_SECONDS
            while sel.get_map() and time.monotonic() < end:
                pump(min(end - time.monotonic(), 0.05))
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        held = bool(sel.get_map())
    finally:
        sel.close()
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except OSError:
                pass
    return timed_out, held


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
    abs_rm = Path(config.wrappers_dir).resolve() / "rm"
    if agent_id:
        env["SAG_AGENT_ID"] = agent_id
    # Only `rm` typed in this command line goes to the recycle bin: rm() lives in
    # this one shell and is NOT exported, and the wrapper is NOT put on PATH.
    # Child processes (dpkg maintainer scripts, make, installers, xargs, find
    # -exec, sudo) get the real rm. Exporting it once made cloudflared's postrm
    # trash the new binary behind a symlink during apt upgrade (2026-09-29).
    setup = f"rm() {{ {shlex.quote(str(abs_rm))} \"$@\"; }}; "

    # Bytes, not text: output can be anything and must never abort the call after
    # the command has already run. stdin is closed so a command that reads it gets
    # EOF instead of waiting on whatever the gateway inherited.
    proc = subprocess.Popen(
        ["/bin/bash", "-lc", setup + cmd],
        cwd=workdir,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    cap = config.audit_body_max_bytes
    out, err = _Capture(cap), _Capture(cap)
    timed_out, pipes_held = _collect(proc, out, err, timeout)

    stdout, stderr = out.text(), err.text()
    if out.dropped:
        stdout += _TRUNCATED_MARK
    if err.dropped:
        stderr += _TRUNCATED_MARK
    if timed_out:
        code = -1
        stderr += f"\nCommand timed out after {timeout}s"
        if pipes_held:
            stderr += "\nA detached background process still holds the output pipes; stopped waiting for it."
    else:
        code = proc.returncode if proc.returncode is not None else -1
    stdout, stderr, clipped = clip_output(stdout, stderr, cap)
    return code, stdout, stderr, clipped or out.dropped or err.dropped
