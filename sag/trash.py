"""
Recycle bin for MCP file tools and the rm wrapper.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import config
from .db import get_db_connection


class ProtectedPathError(Exception):
    pass


def lexical_path(path: Any) -> Path:
    """
    Absolute path with the parent directories resolved but the last component
    kept as-is, like rm/unlink: a symlink operand means the link, not its target.
    """
    p = Path(os.path.abspath(os.path.expanduser(str(path))))
    return p.parent.resolve() / p.name if p.name else p


def is_protected(path: Path, follow: bool = True) -> bool:
    """follow=True for writes (they go through symlinks); False for removals (they don't)."""
    p = path.resolve() if follow else lexical_path(path)
    db = Path(config.db_path).resolve()
    envf = Path(config.gateway_root).resolve() / ".env"
    data = Path(config.db_path).resolve().parent
    if p == db or p == envf:
        return True
    try:
        p.relative_to(data)
        return True
    except ValueError:
        return False


def _assert_not_protected(path: Path) -> None:
    if is_protected(path, follow=False):
        raise ProtectedPathError(f"Refusing to modify protected path: {path}")


def _now() -> datetime:
    return datetime.now().astimezone()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")


def _dir_size(path: Path) -> int:
    total = 0
    if path.is_symlink() or path.is_file():
        return path.lstat().st_size
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).lstat().st_size
            except OSError:
                pass
    return total


def _move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        if src.is_symlink():
            os.symlink(os.readlink(src), dst)
            src.unlink()
        elif src.is_dir():
            shutil.copytree(src, dst, symlinks=True)
            shutil.rmtree(src)
        else:
            shutil.copy2(src, dst, follow_symlinks=False)
            src.unlink()


def trash_put(
    path: Path,
    source: str,
    agent_id: str,
    audit_id: Optional[str] = None,
    keep: bool = False,
) -> str:
    """
    Move `path` into the recycle bin. A symlink is trashed as the link itself.
    keep=True copies a regular file instead of moving it, so the caller can then
    rewrite it in place (same inode, owner and mode; matters for bind mounts).
    """
    target = lexical_path(path)
    if not os.path.lexists(target):
        raise FileNotFoundError(str(target))
    _assert_not_protected(target)
    is_dir = target.is_dir() and not target.is_symlink()
    if keep and (is_dir or target.is_symlink()):
        raise ValueError(f"keep=True needs a regular file: {target}")
    item_id = str(uuid.uuid4())
    trash_dir = Path(config.db_path).resolve().parent / "trash" / item_id
    payload = trash_dir / "payload"
    trash_dir.mkdir(parents=True, exist_ok=True)
    if keep:
        shutil.copy2(target, payload)
    else:
        _move(target, payload)
    size_bytes = _dir_size(payload)
    now = _now()
    expires = now + timedelta(days=config.trash_retention_days)
    rel = f"trash/{item_id}/payload"
    meta = {
        "id": item_id,
        "original_path": str(target),
        "stored_relpath": rel,
        "deleted_by": agent_id,
        "deleted_at": _iso(now),
        "expires_at": _iso(expires),
        "source": source,
        "audit_id": audit_id,
        "is_dir": is_dir,
        "size_bytes": size_bytes,
    }
    (trash_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO trash_items (
                id, original_path, stored_relpath, deleted_by, deleted_at,
                expires_at, source, audit_id, is_dir, size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                item_id,
                str(target),
                rel,
                agent_id,
                meta["deleted_at"],
                meta["expires_at"],
                source,
                audit_id,
                1 if is_dir else 0,
                size_bytes,
            ),
        )
        conn.commit()
    return item_id


def list_trash(prefix: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM trash_items"
    params: List[Any] = []
    if prefix:
        sql += " WHERE original_path LIKE ?"
        params.append(prefix + "%")
    sql += " ORDER BY deleted_at DESC LIMIT ?;"
    params.append(max(1, min(int(limit), 200)))
    with get_db_connection() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def restore_trash(item_id: str) -> Dict[str, Any]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM trash_items WHERE id = ?;", (item_id,)).fetchone()
        if not row:
            return {"status": "FAILED", "error": "trash item not found"}
        item = dict(row)
    dest = Path(item["original_path"])
    payload = Path(config.db_path).resolve().parent / item["stored_relpath"]
    if not os.path.lexists(payload):
        return {"status": "FAILED", "error": "payload missing"}
    if os.path.lexists(dest):
        return {"status": "FAILED", "error": "destination exists", "path": str(dest)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    _move(payload, dest)
    trash_dir = payload.parent
    shutil.rmtree(trash_dir, ignore_errors=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM trash_items WHERE id = ?;", (item_id,))
        conn.commit()
    return {"status": "RESTORED", "path": str(dest), "trash_id": item_id}


def purge_expired_trash() -> int:
    now = _iso(_now())
    with get_db_connection() as conn:
        rows = list(conn.execute("SELECT id, stored_relpath FROM trash_items WHERE expires_at <= ?;", (now,)))
        for row in rows:
            payload = Path(config.db_path).resolve().parent / row["stored_relpath"]
            shutil.rmtree(payload.parent, ignore_errors=True)
            conn.execute("DELETE FROM trash_items WHERE id = ?;", (row["id"],))
        conn.commit()
        return len(rows)


def select_trash(
    ids: Optional[List[str]] = None,
    deleted_by: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    prefix: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Trash rows matching every given filter. No filter at all matches nothing."""
    conds, params = [], []
    if ids:
        conds.append(f"id IN ({','.join('?' * len(ids))})")
        params.extend(ids)
    if deleted_by:
        conds.append("deleted_by = ?")
        params.append(deleted_by)
    if since:
        conds.append("deleted_at >= ?")
        params.append(since)
    if until:
        conds.append("deleted_at <= ?")
        params.append(until)
    if prefix:
        conds.append("original_path LIKE ?")
        params.append(prefix + "%")
    if not conds:
        return []
    sql = f"SELECT * FROM trash_items WHERE {' AND '.join(conds)} ORDER BY deleted_at;"
    with get_db_connection() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def purge_trash_items(ids: List[str]) -> int:
    """Permanently delete these trash items (payload + row). Root CLI only, never an MCP tool."""
    with get_db_connection() as conn:
        n = 0
        for item_id in ids:
            row = conn.execute("SELECT stored_relpath FROM trash_items WHERE id = ?;", (item_id,)).fetchone()
            if not row:
                continue
            payload = Path(config.db_path).resolve().parent / row["stored_relpath"]
            shutil.rmtree(payload.parent, ignore_errors=True)
            conn.execute("DELETE FROM trash_items WHERE id = ?;", (item_id,))
            n += 1
        conn.commit()
        return n


def trash_from_rm_argv(argv: List[str], agent_id: Optional[str] = None) -> int:
    """GNU-rm-ish front-end that trash_puts operands. Prints SAG_TRASH ids on stderr."""
    recursive = False
    force = False
    dir_ok = False
    operands: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            operands.extend(argv[i + 1 :])
            break
        if a in ("-r", "-R", "--recursive"):
            recursive = True
        elif a == "-f":
            force = True
        elif a == "-d" or a == "--dir":
            dir_ok = True
        elif a == "-v" or a == "--verbose":
            pass
        elif a.startswith("-") and a != "-":
            # bundled short flags
            if a.startswith("--"):
                print(f"rm: unsupported option {a}", file=__import__("sys").stderr)
                return 1
            for ch in a[1:]:
                if ch in ("r", "R"):
                    recursive = True
                elif ch == "f":
                    force = True
                elif ch == "d":
                    dir_ok = True
                elif ch == "v":
                    pass
                else:
                    print(f"rm: unsupported option -{ch}", file=__import__("sys").stderr)
                    return 1
        else:
            operands.append(a)
        i += 1

    if not operands:
        return 0 if force else 1

    who = agent_id or os.environ.get("SAG_AGENT_ID") or "unknown"
    errors = False
    for op in operands:
        try:
            resolved = lexical_path(op)
        except OSError:
            resolved = Path(os.path.abspath(os.path.expanduser(op)))
        if not os.path.lexists(resolved):
            if not force:
                print(f"rm: cannot remove '{op}': No such file or directory", file=__import__("sys").stderr)
                errors = True
            continue
        if resolved.is_dir() and not resolved.is_symlink() and not recursive and not dir_ok:
            print(f"rm: cannot remove '{op}': Is a directory", file=__import__("sys").stderr)
            errors = True
            continue
        try:
            item_id = trash_put(resolved, source="rm_wrapper", agent_id=who)
            print(f"SAG_TRASH {item_id}", file=__import__("sys").stderr)
        except ProtectedPathError as exc:
            print(f"rm: {exc}", file=__import__("sys").stderr)
            errors = True
        except Exception as exc:
            if not force:
                print(f"rm: {exc}", file=__import__("sys").stderr)
                errors = True
    return 1 if errors else 0
