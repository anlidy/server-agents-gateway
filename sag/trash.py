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


def is_protected(path: Path) -> bool:
    p = path.resolve()
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
    if is_protected(path):
        raise ProtectedPathError(f"Refusing to modify protected path: {path}")


def _now() -> datetime:
    return datetime.now().astimezone()


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")


def _dir_size(path: Path) -> int:
    total = 0
    if path.is_file():
        return path.stat().st_size
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
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
        if src.is_dir():
            shutil.copytree(src, dst)
            shutil.rmtree(src)
        else:
            shutil.copy2(src, dst)
            src.unlink()


def trash_put(
    path: Path,
    source: str,
    agent_id: str,
    audit_id: Optional[str] = None,
) -> str:
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(str(target))
    _assert_not_protected(target)
    item_id = str(uuid.uuid4())
    trash_dir = Path(config.db_path).resolve().parent / "trash" / item_id
    payload = trash_dir / "payload"
    trash_dir.mkdir(parents=True, exist_ok=True)
    is_dir = target.is_dir()
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


TAR_PAYLOAD = "payload.tar"


def is_operator_payload(item: Dict[str, Any]) -> bool:
    """operator 删除的条目以 tar 存放，只能以 operator 身份还原。"""
    return str(item.get("stored_relpath") or "").endswith("/" + TAR_PAYLOAD)


def store_tar_payload(
    src,
    original_path: str,
    is_dir: bool,
    size_bytes: int,
    agent_id: str,
    source: str,
) -> str:
    """把 operator 打好的 tar（文件对象）拷进回收站。root 只拷贝，不解包。"""
    item_id = str(uuid.uuid4())
    trash_dir = Path(config.db_path).resolve().parent / "trash" / item_id
    trash_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(trash_dir, 0o700)
    payload = trash_dir / TAR_PAYLOAD
    with open(payload, "wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    now = _now()
    expires = now + timedelta(days=config.trash_retention_days)
    rel = f"trash/{item_id}/{TAR_PAYLOAD}"
    meta = {
        "id": item_id,
        "original_path": original_path,
        "stored_relpath": rel,
        "deleted_by": agent_id,
        "deleted_at": _iso(now),
        "expires_at": _iso(expires),
        "source": source,
        "audit_id": None,
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?);
            """,
            (item_id, original_path, rel, agent_id, meta["deleted_at"], meta["expires_at"],
             source, 1 if is_dir else 0, size_bytes),
        )
        conn.commit()
    return item_id


def get_trash_item(item_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM trash_items WHERE id = ?;", (item_id,)).fetchone()
        return dict(row) if row else None


def list_trash(prefix: Optional[str] = None, limit: int = 50, operator_only: bool = False) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM trash_items"
    params: List[Any] = []
    cond: List[str] = []
    if prefix:
        cond.append("original_path LIKE ?")
        params.append(prefix + "%")
    if operator_only:
        cond.append("stored_relpath LIKE ?")
        params.append("%/" + TAR_PAYLOAD)
    if cond:
        sql += " WHERE " + " AND ".join(cond)
    sql += " ORDER BY deleted_at DESC LIMIT ?;"
    params.append(max(1, min(int(limit), 200)))
    with get_db_connection() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def restore_trash(item_id: str, as_operator: bool = False, agent_id: str = "") -> Dict[str, Any]:
    item = get_trash_item(item_id)
    if not item:
        return {"status": "FAILED", "error": "trash item not found"}
    if is_operator_payload(item):
        return _restore_tar_item(item, agent_id)
    if as_operator:
        return {
            "status": "FAILED",
            "error": "this item was deleted with root privileges; only an admin can restore it "
            "(or ask via hub_request_elevation)",
        }
    dest = Path(item["original_path"])
    payload = Path(config.db_path).resolve().parent / item["stored_relpath"]
    if not payload.exists():
        return {"status": "FAILED", "error": "payload missing"}
    if dest.exists():
        return {"status": "FAILED", "error": "destination exists", "path": str(dest)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    _move(payload, dest)
    trash_dir = payload.parent
    shutil.rmtree(trash_dir, ignore_errors=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM trash_items WHERE id = ?;", (item_id,))
        conn.commit()
    return {"status": "RESTORED", "path": str(dest), "trash_id": item_id}


def _restore_tar_item(item: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
    # 不论谁调用，operator 删除的内容都以 operator 身份解包还原：
    # 路径和 tar 内容都来自 operator，root 解包会被利用来往任意位置写文件。
    from .privilege import restore_tar_as_operator

    payload = Path(config.db_path).resolve().parent / item["stored_relpath"]
    if not payload.exists():
        return {"status": "FAILED", "error": "payload missing"}
    try:
        restore_tar_as_operator(payload, item["original_path"], agent_id)
    except FileExistsError:
        return {"status": "FAILED", "error": "destination exists", "path": item["original_path"]}
    except (OSError, ValueError, RuntimeError) as exc:
        return {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}", "path": item["original_path"]}
    shutil.rmtree(payload.parent, ignore_errors=True)
    with get_db_connection() as conn:
        conn.execute("DELETE FROM trash_items WHERE id = ?;", (item["id"],))
        conn.commit()
    return {"status": "RESTORED", "path": item["original_path"], "trash_id": item["id"], "restored_as": "operator"}


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
        p = Path(op).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        try:
            resolved = p.resolve()
        except OSError:
            resolved = Path(os.path.abspath(str(p)))
        if not resolved.exists():
            if not force:
                print(f"rm: cannot remove '{op}': No such file or directory", file=__import__("sys").stderr)
                errors = True
            continue
        if resolved.is_dir() and not recursive and not dir_ok:
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
