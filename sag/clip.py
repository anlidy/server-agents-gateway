"""
Clipping of command output to a byte budget, shared by the executor and the audit log.
"""

from __future__ import annotations

from typing import Tuple

TRUNCATED_MARK = "\n[truncated]\n"
# stderr is guaranteed this fraction of the budget (or all of it, if it is smaller): errors, the
# timeout notes and the recycle-bin ids are short, and must not be the first thing a big stdout evicts.
STDERR_RESERVE_DIVISOR = 8


def _cut(raw: bytes, keep: int, text: str) -> str:
    if keep >= len(raw):
        return text
    return raw[:keep].decode("utf-8", errors="ignore") + TRUNCATED_MARK


def clip_output(stdout: str, stderr: str, max_bytes: int) -> Tuple[str, str, bool]:
    """
    Fit both streams into `max_bytes` (UTF-8). stdout gets the budget stderr does not need, stderr is
    guaranteed max_bytes // STDERR_RESERVE_DIVISOR. Each stream that lost bytes ends with TRUNCATED_MARK.
    Returns (stdout, stderr, clipped).
    """
    out_b = (stdout or "").encode("utf-8")
    err_b = (stderr or "").encode("utf-8")
    if len(out_b) + len(err_b) <= max_bytes:
        return stdout or "", stderr or "", False
    reserve = min(len(err_b), max_bytes // STDERR_RESERVE_DIVISOR)
    out_keep = min(len(out_b), max_bytes - reserve)
    err_keep = min(len(err_b), max_bytes - out_keep)
    return _cut(out_b, out_keep, stdout or ""), _cut(err_b, err_keep, stderr or ""), True
