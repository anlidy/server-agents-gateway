"""
Recycle bin for MCP file tools and the rm wrapper.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import sys
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


def _remove_tree(path: Path) -> None:
    """Remove a file, link or directory tree; whatever could not be removed stays (check lexists)."""
    if os.path.lexists(path):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                path.unlink()
            except OSError:
                pass


def _move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.rename(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        # Across devices: copy, then delete the source. A copy that fails halfway must not
        # leave a partial destination behind (the source is still whole at that point).
        try:
            if src.is_symlink():
                os.symlink(os.readlink(src), dst)
            elif src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
        except BaseException:
            _remove_tree(dst)
            raise
        if src.is_dir() and not src.is_symlink():
            shutil.rmtree(src)
        else:
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
    try:
        if keep:
            shutil.copy2(target, payload)
        else:
            _move(target, payload)
    except BaseException:
        # Nothing was stored (a failed copy removes its own partial payload): do not leave an
        # orphan directory that no row points to and nothing will ever purge.
        if not os.path.lexists(payload):
            shutil.rmtree(trash_dir, ignore_errors=True)
        raise
    try:
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
    except BaseException:
        # Could not record it (disk full, database locked): undo, so the caller's error is true
        # and the file is still where it was. If moving it back fails too, the payload and its
        # meta.json stay in the bin for a manual restore.
        try:
            if keep:
                shutil.rmtree(trash_dir, ignore_errors=True)
            elif not os.path.lexists(target):
                _move(payload, target)
                shutil.rmtree(trash_dir, ignore_errors=True)
        except BaseException:
            pass
        raise
    return item_id


def list_trash(prefix: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM trash_items"
    params: List[Any] = []
    if prefix:
        sql += " WHERE original_path LIKE ?"
        params.append(prefix + "%")
    sql += " ORDER BY deleted_at DESC, rowid DESC LIMIT ?;"
    params.append(max(1, min(int(limit), 200)))
    with get_db_connection() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def restore_trash(item_id: str, overwrite: bool = False, agent_id: str = "unknown") -> Dict[str, Any]:
    """
    Put a recycle-bin item back at its original path. If something is there already this fails,
    unless overwrite=True: then what is there now goes into the bin first (its id comes back as
    displaced_trash_id), so undoing an overwrite is itself undoable.
    """
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM trash_items WHERE id = ?;", (item_id,)).fetchone()
        if not row:
            return {"status": "FAILED", "error": "trash item not found"}
        item = dict(row)
    dest = Path(item["original_path"])
    payload = Path(config.db_path).resolve().parent / item["stored_relpath"]
    if not os.path.lexists(payload):
        return {"status": "FAILED", "error": "payload missing"}
    displaced = None
    if os.path.lexists(dest):
        if not overwrite:
            return {"status": "FAILED", "error": "destination exists", "path": str(dest)}
        in_place = (
            dest.is_file() and not dest.is_symlink() and payload.is_file() and not payload.is_symlink()
        )
        # A regular file is rewritten in place (same inode and owner, like hub_write_file); anything
        # else (a directory, a link, a type change) is moved aside.
        displaced = trash_put(dest, source="restore_overwrite", agent_id=agent_id, keep=in_place)
        if in_place:
            shutil.copyfile(payload, dest)
            shutil.copymode(payload, dest)
            _finish_restore(payload, item_id)
            return {"status": "RESTORED", "path": str(dest), "trash_id": item_id, "displaced_trash_id": displaced}
    dest.parent.mkdir(parents=True, exist_ok=True)
    _move(payload, dest)
    _finish_restore(payload, item_id)
    result = {"status": "RESTORED", "path": str(dest), "trash_id": item_id}
    if displaced:
        result["displaced_trash_id"] = displaced
    return result


def _finish_restore(payload: Path, item_id: str) -> None:
    shutil.rmtree(payload.parent, ignore_errors=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM trash_items WHERE id = ?;", (item_id,))
        conn.commit()


def purge_expired_trash() -> int:
    now = _iso(_now())
    with get_db_connection() as conn:
        rows = list(conn.execute("SELECT id, stored_relpath FROM trash_items WHERE expires_at <= ?;", (now,)))
        purged = 0
        for row in rows:
            payload = Path(config.db_path).resolve().parent / row["stored_relpath"]
            shutil.rmtree(payload.parent, ignore_errors=True)
            if os.path.lexists(payload.parent):
                continue  # could not remove it: keep the row so the next pass retries
            conn.execute("DELETE FROM trash_items WHERE id = ?;", (row["id"],))
            purged += 1
        conn.commit()
        return purged


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
            if os.path.lexists(payload.parent):
                continue  # could not remove it: keep the row (and do not count it)
            conn.execute("DELETE FROM trash_items WHERE id = ?;", (item_id,))
            n += 1
        conn.commit()
        return n


_RM_LONG_FLAGS = {
    "--recursive": "recursive",
    "--force": "force",
    "--dir": "dir_ok",
    # accepted and ignored: the bin never crosses a filesystem boundary prompt and never "preserves root"
    "--verbose": None,
    "--one-file-system": None,
    "--preserve-root": None,
    "--no-preserve-root": None,
    "--interactive=never": None,
}


def _report_trash_id(item_id: str) -> None:
    """Tell the gateway (SAG_TRASH_FILE) or, run by hand, the user (stderr) which bin item was created."""
    path = os.environ.get("SAG_TRASH_FILE")
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(item_id + "\n")
            return
        except OSError:
            pass
    print(f"SAG_TRASH {item_id}", file=sys.stderr)


def trash_from_rm_argv(argv: List[str], agent_id: Optional[str] = None) -> int:
    """GNU-rm-ish front-end that trash_puts operands. Reports each new bin id via _report_trash_id."""
    flags = {"recursive": False, "force": False, "dir_ok": False}
    operands: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            operands.extend(argv[i + 1 :])
            break
        if a.startswith("--"):
            if a not in _RM_LONG_FLAGS:
                print(f"rm: unsupported option {a}", file=sys.stderr)
                return 1
            if _RM_LONG_FLAGS[a]:
                flags[_RM_LONG_FLAGS[a]] = True
        elif a.startswith("-") and a != "-":
            for ch in a[1:]:  # bundled short flags
                if ch in ("r", "R"):
                    flags["recursive"] = True
                elif ch == "f":
                    flags["force"] = True
                elif ch == "d":
                    flags["dir_ok"] = True
                elif ch != "v":
                    print(f"rm: unsupported option -{ch}", file=sys.stderr)
                    return 1
        else:
            operands.append(a)
        i += 1
    recursive, force, dir_ok = flags["recursive"], flags["force"], flags["dir_ok"]

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
                print(f"rm: cannot remove '{op}': No such file or directory", file=sys.stderr)
                errors = True
            continue
        if resolved.is_dir() and not resolved.is_symlink() and not recursive and not dir_ok:
            print(f"rm: cannot remove '{op}': Is a directory", file=sys.stderr)
            errors = True
            continue
        try:
            item_id = trash_put(resolved, source="rm_wrapper", agent_id=who)
            _report_trash_id(item_id)
        except ProtectedPathError as exc:
            print(f"rm: {exc}", file=sys.stderr)
            errors = True
        except Exception as exc:
            if not force:
                print(f"rm: {exc}", file=sys.stderr)
                errors = True
    return 1 if errors else 0
