"""
admin 把某个目录（或文件）授权给 operator 组读写，落在 POSIX ACL 上：
    setfacl -R -P -m g:sag-operators:rwX <path>      （已有内容）
    find -P <path> -type d -exec setfacl -d -m ...    （之后新建的内容继承）
撤销用 -x 删掉这条组 ACL。授权记录存在 operator_grants 表里，便于列出和审计。

授权是 admin 的决定，这里只挡几种"等于直接交出 root"或会让 operator 改到 SAG 自己的路径，
防止手滑；它不是访问控制本身（访问控制是内核按 ACL 判定）。
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List

from .config import config
from .db import append_audit, get_db_connection

# 可在测试里替换
run_cmd: Callable[..., subprocess.CompletedProcess] = subprocess.run

_DENY_EXACT = {"/", "/etc", "/usr", "/var", "/opt", "/home", "/srv", "/boot", "/root", "/bin", "/sbin",
               "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/sys", "/dev", "/run", "/snap"}
# 这些目录下的任何东西被 operator 改写，都能换来 root（被 root 执行或决定谁能提权）
_DENY_TREES = ("/etc/sudoers.d", "/etc/sudoers", "/etc/systemd", "/lib/systemd", "/usr", "/bin", "/sbin",
               "/lib", "/lib64", "/boot", "/root", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
               "/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab", "/var/spool/cron", "/etc/pam.d",
               "/etc/security", "/etc/ssh", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
               "/etc/ld.so.preload", "/etc/ld.so.conf.d", "/etc/profile.d", "/etc/polkit-1",
               "/etc/apt", "/var/lib/dpkg", "/etc/docker", "/var/lib/docker", "/run/docker.sock",
               "/var/run/docker.sock")


class GrantError(ValueError):
    pass


def _under(path: Path, root: str) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def check_grantable(path: Path) -> None:
    p = str(path)
    if p in _DENY_EXACT:
        raise GrantError(f"refusing to grant a top-level system directory: {p}")
    for tree in _DENY_TREES:
        if _under(path, tree):
            raise GrantError(f"refusing to grant {p}: anything under {tree} can be turned into root")
    gw = Path(config.gateway_root).resolve()
    data = Path(config.db_path).resolve().parent
    for protected in (gw, data):
        if _under(path, str(protected)) or _under(protected, p):
            raise GrantError(f"refusing to grant {p}: it contains or is inside SAG itself ({protected})")


def _perm(access: str) -> str:
    if access == "rw":
        return "rwX"
    if access == "ro":
        return "rX"
    raise GrantError("access must be 'rw' or 'ro'")


def _run(argv: List[str]) -> None:
    proc = run_cmd(argv, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise GrantError(f"{' '.join(argv[:3])} … failed: {(proc.stderr or proc.stdout or '').strip()[:500]}")


def _apply(path: Path, entry: str, remove: bool) -> None:
    group = config.operator_group
    flag = "-x" if remove else "-m"
    spec = f"g:{group}" if remove else f"g:{group}:{entry}"
    _run(["setfacl", "-R", "-P", flag, spec, str(path)])
    if path.is_dir():
        _run(["find", "-P", str(path), "-type", "d", "-exec", "setfacl", "-d", flag, spec, "{}", "+"])


def _operator_access(path: Path, agent_id: str) -> Dict[str, Any]:
    from .privilege import call_worker

    try:
        return call_worker("access", {"path": str(path)}, agent_id=agent_id)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}


def grant_path(caller: str, privileged: bool, path: str, access: str = "rw", reason: str = "") -> Dict[str, Any]:
    if not privileged:
        raise PermissionError("only admin agents can grant paths to operators")
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(str(target))
    check_grantable(target)
    access = (access or "rw").strip().lower()
    _apply(target, _perm(access), remove=False)
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO operator_grants (path, access, granted_by, granted_at, reason) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET access = excluded.access, granted_by = excluded.granted_by,
                granted_at = excluded.granted_at, reason = excluded.reason;
            """,
            (str(target), access, caller, now, reason or ""),
        )
        conn.commit()
    effective = _operator_access(target, caller)
    warning = None
    want_write = access == "rw"
    if effective.get("error") or (want_write and not effective.get("write")) or not effective.get("read"):
        warning = (
            "ACL applied, but the operator user still cannot use this path as expected. "
            "A parent directory probably lacks x for others (e.g. mode 700); grant or fix the parent."
        )
    append_audit(agent_id=caller, tool_name="hub_grant_path", action_type="grant_add", target=str(target),
                 reason=reason or "", status="SUCCESS",
                 params={"access": access, "group": config.operator_group, "effective": effective})
    out = {"path": str(target), "access": access, "group": config.operator_group, "operator_access": effective}
    if warning:
        out["warning"] = warning
    return out


def revoke_grant(caller: str, privileged: bool, path: str, reason: str = "") -> Dict[str, Any]:
    if not privileged:
        raise PermissionError("only admin agents can revoke path grants")
    target = Path(path).resolve()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM operator_grants WHERE path = ?;", (str(target),)).fetchone()
    if target.exists():
        _apply(target, "", remove=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM operator_grants WHERE path = ?;", (str(target),))
        conn.commit()
    append_audit(agent_id=caller, tool_name="hub_revoke_grant", action_type="grant_remove", target=str(target),
                 reason=reason or "", status="SUCCESS" if row else "NOT_FOUND",
                 params={"group": config.operator_group})
    return {"path": str(target), "status": "REVOKED" if row else "NOT_RECORDED_BUT_ACL_CLEARED"}


def list_grants() -> Dict[str, Any]:
    with get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM operator_grants ORDER BY path;").fetchall()
    return {"group": config.operator_group, "grants": [dict(r) for r in rows]}
