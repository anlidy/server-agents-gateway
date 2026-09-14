"""
v2 MCP tool implementations.
"""

from __future__ import annotations

import difflib
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_LIST_DIR_MAX = 2000

from .auth import issue_agent_token, revoke_agent_token
from .config import config
from .db import append_audit, get_audit_event, query_audit_logs
from .executor import CommandExecutionError, execute_shell
from .overview import overview_path, read_overview, write_handwritten
from .reconciler import collect_host_status, reconcile
from .trash import ProtectedPathError, is_protected, list_trash, restore_trash, trash_put


def _audit_then_raise(agent_id, tool_name, action_type, target, reason, status, exc, **kwargs):
    append_audit(
        agent_id=agent_id,
        tool_name=tool_name,
        action_type=action_type,
        target=str(target),
        reason=reason or "",
        status=status,
        stderr=str(exc),
        **kwargs,
    )
    raise exc


def _extract_trash_ids(stderr: str) -> tuple[str, List[str]]:
    ids: List[str] = []
    keep: List[str] = []
    for line in (stderr or "").splitlines(True):
        if line.startswith("SAG_TRASH "):
            token = line.split()[1].strip() if len(line.split()) > 1 else ""
            if token:
                ids.append(token)
        else:
            keep.append(line)
    return "".join(keep), ids


def tool_shell(
    agent_id: str,
    command: str,
    reason: str,
    cwd: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    start = time.time()
    code, stdout, stderr, truncated = -1, "", "", False
    try:
        code, stdout, stderr, truncated = execute_shell(
            command, cwd=cwd, timeout_seconds=timeout_seconds, agent_id=agent_id
        )
    except CommandExecutionError as exc:
        append_audit(
            agent_id=agent_id,
            tool_name="hub_shell",
            action_type="shell_exec",
            target=(command or "")[:200],
            reason=reason,
            status="REJECTED",
            params={"command": command, "cwd": cwd, "timeout_seconds": timeout_seconds},
            stderr=str(exc),
        )
        raise
    finally:
        try:
            reconcile()
        except Exception:
            pass
    stderr, trash_ids = _extract_trash_ids(stderr)
    duration_ms = int((time.time() - start) * 1000)
    status = "SUCCESS" if code == 0 else "FAILED"
    workdir = cwd or config.shell_cwd
    append_audit(
        agent_id=agent_id,
        tool_name="hub_shell",
        action_type="shell_exec",
        target=(command or "")[:200],
        reason=reason,
        status=status,
        exit_code=code,
        cwd=workdir,
        duration_ms=duration_ms,
        params={
            "command": command,
            "cwd": workdir,
            "timeout_seconds": timeout_seconds,
            "trash_ids": trash_ids,
        },
        trash_id=trash_ids[0] if trash_ids else None,
        stdout=stdout,
        stderr=stderr,
    )
    return {
        "command": command,
        "cwd": workdir,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
        "truncated": truncated,
        "duration_ms": duration_ms,
        "trash_ids": trash_ids,
    }


def tool_read_file(
    agent_id: str,
    path: str,
    offset: int = 1,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    target = Path(path).resolve()
    if not target.exists():
        append_audit(
            agent_id=agent_id,
            tool_name="hub_read_file",
            action_type="file_read",
            target=str(target),
            reason="",
            status="FAILED",
        )
        raise FileNotFoundError(str(target))
    if target.is_dir():
        exc = IsADirectoryError(str(target))
        _audit_then_raise(agent_id, "hub_read_file", "file_read", target, "", "FAILED", exc)
    raw = target.read_bytes()
    if b"\x00" in raw[:8192]:
        exc = ValueError("binary file")
        _audit_then_raise(agent_id, "hub_read_file", "file_read", target, "", "FAILED", exc)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _audit_then_raise(agent_id, "hub_read_file", "file_read", target, "", "FAILED", exc)
    lines = text.splitlines(True)
    start = max(int(offset) - 1, 0)
    chunk = lines[start:] if limit is None else lines[start : start + int(limit)]
    content = "".join(chunk)
    append_audit(
        agent_id=agent_id,
        tool_name="hub_read_file",
        action_type="file_read",
        target=str(target),
        reason="",
        status="SUCCESS",
        stdout=content,
        params={"offset": offset, "limit": limit},
    )
    return {"path": str(target), "content": content}


def tool_list_dir(agent_id: str, path: str) -> Dict[str, Any]:
    target = Path(path).resolve()
    if not target.exists():
        append_audit(
            agent_id=agent_id,
            tool_name="hub_list_dir",
            action_type="dir_list",
            target=str(target),
            reason="",
            status="FAILED",
        )
        raise FileNotFoundError(str(target))
    if not target.is_dir():
        exc = NotADirectoryError(str(target))
        _audit_then_raise(agent_id, "hub_list_dir", "dir_list", target, "", "FAILED", exc)
    entries: List[Dict[str, Any]] = []
    truncated = False
    try:
        names = sorted(p.name for p in target.iterdir())
    except OSError as exc:
        _audit_then_raise(agent_id, "hub_list_dir", "dir_list", target, "", "FAILED", exc)
    if len(names) > _LIST_DIR_MAX:
        names = names[:_LIST_DIR_MAX]
        truncated = True
    for name in names:
        child = target / name
        try:
            st = child.lstat()
        except OSError:
            continue
        entries.append(
            {
                "name": name,
                "is_dir": stat.S_ISDIR(st.st_mode),
                "is_symlink": stat.S_ISLNK(st.st_mode),
                "size": st.st_size,
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime)),
            }
        )
    append_audit(
        agent_id=agent_id,
        tool_name="hub_list_dir",
        action_type="dir_list",
        target=str(target),
        reason="",
        status="SUCCESS",
        params={"count": len(entries), "truncated": truncated},
    )
    return {"path": str(target), "entries": entries, "truncated": truncated}


def tool_mkdir(agent_id: str, path: str, reason: str) -> Dict[str, Any]:
    target = Path(path).resolve()
    if is_protected(target):
        _audit_then_raise(
            agent_id,
            "hub_mkdir",
            "dir_create",
            target,
            reason,
            "REJECTED",
            ProtectedPathError(f"Refusing to modify protected path: {target}"),
        )
    if target.exists() and not target.is_dir():
        exc = NotADirectoryError(f"exists and is not a directory: {target}")
        _audit_then_raise(agent_id, "hub_mkdir", "dir_create", target, reason, "FAILED", exc)
    existed = target.is_dir()
    target.mkdir(parents=True, exist_ok=True)
    append_audit(
        agent_id=agent_id,
        tool_name="hub_mkdir",
        action_type="dir_create",
        target=str(target),
        reason=reason,
        status="SUCCESS",
        params={"existed": existed},
    )
    return {"path": str(target), "existed": existed}


def tool_patch_file(
    agent_id: str,
    path: str,
    old_string: str,
    new_string: str,
    reason: str,
    replace_all: bool = False,
) -> Dict[str, Any]:
    target = Path(path).resolve()
    if is_protected(target):
        _audit_then_raise(
            agent_id,
            "hub_patch_file",
            "file_patch",
            target,
            reason,
            "REJECTED",
            ProtectedPathError(f"Refusing to modify protected path: {target}"),
        )
    if not old_string:
        exc = ValueError("old_string must not be empty")
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    if not target.exists():
        append_audit(
            agent_id=agent_id,
            tool_name="hub_patch_file",
            action_type="file_patch",
            target=str(target),
            reason=reason,
            status="FAILED",
        )
        raise FileNotFoundError(str(target))
    if target.is_dir():
        exc = IsADirectoryError(str(target))
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    raw = target.read_bytes()
    if b"\x00" in raw[:8192]:
        exc = ValueError("binary file")
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    try:
        old = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    n = old.count(old_string)
    if n == 0:
        exc = ValueError("old_string not found")
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    if n > 1 and not replace_all:
        exc = ValueError(f"old_string matched {n} times; pass replace_all=true or make it unique")
        _audit_then_raise(agent_id, "hub_patch_file", "file_patch", target, reason, "FAILED", exc)
    new = old.replace(old_string, new_string) if replace_all else old.replace(old_string, new_string, 1)
    replacements = n if replace_all else 1
    trash_id = trash_put(target, source="patch_file", agent_id=agent_id)
    if target.resolve() == overview_path().resolve():
        write_handwritten(new)
    else:
        target.write_text(new, encoding="utf-8")
    try:
        reconcile()
    except Exception:
        pass
    diff_lines = list(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=f"a/{target.name}",
            tofile=f"b/{target.name}",
            lineterm="",
        )
    )
    append_audit(
        agent_id=agent_id,
        tool_name="hub_patch_file",
        action_type="file_patch",
        target=str(target),
        reason=reason,
        status="SUCCESS",
        trash_id=trash_id,
        diff="\n".join(diff_lines),
        params={"replacements": replacements, "replace_all": bool(replace_all)},
    )
    return {
        "path": str(target),
        "replacements": replacements,
        "trash_id": trash_id,
    }


def tool_write_file(agent_id: str, path: str, content: str, reason: str) -> Dict[str, Any]:
    target = Path(path).resolve()
    if is_protected(target):
        _audit_then_raise(
            agent_id,
            "hub_write_file",
            "file_write",
            target,
            reason,
            "REJECTED",
            ProtectedPathError(f"Refusing to modify protected path: {target}"),
        )
    old = ""
    trash_id = None
    existed = target.exists()
    if existed:
        try:
            old = target.read_text(encoding="utf-8")
        except Exception:
            old = ""
        trash_id = trash_put(target, source="write_file", agent_id=agent_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.resolve() == overview_path().resolve():
        write_handwritten(content)
        try:
            reconcile()
        except Exception:
            pass
    else:
        target.write_text(content, encoding="utf-8")
        try:
            reconcile()
        except Exception:
            pass
    diff_lines = list(
        difflib.unified_diff(
            old.splitlines(),
            content.splitlines(),
            fromfile=f"a/{target.name}",
            tofile=f"b/{target.name}",
            lineterm="",
        )
    )
    append_audit(
        agent_id=agent_id,
        tool_name="hub_write_file",
        action_type="file_write",
        target=str(target),
        reason=reason,
        status="SUCCESS",
        trash_id=trash_id,
        diff="\n".join(diff_lines),
        params={"created": not existed},
    )
    return {"path": str(target), "bytes_written": len(content.encode("utf-8")), "trash_id": trash_id}


def tool_delete_file(agent_id: str, path: str, reason: str) -> Dict[str, Any]:
    target = Path(path).resolve()
    if is_protected(target):
        _audit_then_raise(
            agent_id,
            "hub_delete_file",
            "file_delete",
            target,
            reason,
            "REJECTED",
            ProtectedPathError(f"Refusing to modify protected path: {target}"),
        )
    if not target.exists():
        append_audit(
            agent_id=agent_id,
            tool_name="hub_delete_file",
            action_type="file_delete",
            target=str(target),
            reason=reason,
            status="FAILED",
        )
        return {"path": str(target), "status": "NOT_FOUND"}
    trash_id = trash_put(target, source="delete_file", agent_id=agent_id)
    try:
        reconcile()
    except Exception:
        pass
    append_audit(
        agent_id=agent_id,
        tool_name="hub_delete_file",
        action_type="file_delete",
        target=str(target),
        reason=reason,
        status="SUCCESS",
        trash_id=trash_id,
    )
    return {"path": str(target), "status": "TRASHED", "trash_id": trash_id}


def tool_list_trash(agent_id: str, prefix: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    items = list_trash(prefix=prefix, limit=limit)
    append_audit(
        agent_id=agent_id,
        tool_name="hub_list_trash",
        action_type="trash_list",
        target=prefix or "trash",
        reason="",
        status="SUCCESS",
        params={"count": len(items)},
    )
    return items


def tool_restore_file(agent_id: str, trash_id: str, reason: str) -> Dict[str, Any]:
    result = restore_trash(trash_id)
    status = "SUCCESS" if result.get("status") == "RESTORED" else "FAILED"
    append_audit(
        agent_id=agent_id,
        tool_name="hub_restore_file",
        action_type="file_restore",
        target=result.get("path") or trash_id,
        reason=reason,
        status=status,
        trash_id=trash_id,
        params=result,
    )
    try:
        reconcile()
    except Exception:
        pass
    return result


def tool_get_overview() -> str:
    from .overview import ensure_document

    ensure_document()
    return read_overview()


def tool_rebuild_overview(reason: str = "refresh status") -> str:
    reconcile()
    append_audit(
        agent_id="system",
        tool_name="hub_rebuild_overview",
        action_type="overview_rebuild",
        target="SERVER_AGENTS.md",
        reason=reason,
        status="SUCCESS",
    )
    return read_overview()


def tool_get_status() -> Dict[str, Any]:
    return collect_host_status()


def tool_query_audit_logs(**kwargs) -> List[Dict[str, Any]]:
    rows = query_audit_logs(**kwargs)
    return rows


def tool_get_audit_event(event_id: str) -> Dict[str, Any]:
    return get_audit_event(event_id)


def tool_issue_agent_token(caller_agent_id: str, caller_role: str, agent_id: str) -> Dict[str, Any]:
    if caller_agent_id != config.root_admin_agent_id or caller_role != "admin":
        raise PermissionError(
            f"403 Forbidden: Only designated root admin '{config.root_admin_agent_id}' "
            f"has authority to issue tokens. Caller is [{caller_agent_id}]."
        )
    if agent_id == config.root_admin_agent_id:
        raise ValueError(f"400 Bad Request: Cannot re-issue token for primary admin '{config.root_admin_agent_id}'.")
    assigned_role = "operator"
    new_token = issue_agent_token(agent_id, assigned_role)
    append_audit(
        agent_id=caller_agent_id,
        tool_name="hub_issue_agent_token",
        action_type="token_issue",
        target=f"agent:{agent_id}",
        reason=f"Issued operator token for agent {agent_id}",
        status="SUCCESS",
        params={"target_agent_id": agent_id, "role": assigned_role},
    )
    return {
        "agent_id": agent_id,
        "role": assigned_role,
        "token": new_token,
        "status": "ISSUED",
        "note": "Provide this bearer token to the target agent. It cannot be retrieved again in plaintext.",
    }


def tool_revoke_agent_token(caller_agent_id: str, caller_role: str, agent_id: str) -> Dict[str, Any]:
    if caller_agent_id != config.root_admin_agent_id or caller_role != "admin":
        raise PermissionError(
            f"403 Forbidden: Only designated root admin '{config.root_admin_agent_id}' "
            f"has authority to revoke tokens. Caller is [{caller_agent_id}]."
        )
    if agent_id == config.root_admin_agent_id:
        raise ValueError(f"400 Bad Request: Cannot revoke primary root admin '{config.root_admin_agent_id}'.")
    success = revoke_agent_token(agent_id)
    append_audit(
        agent_id=caller_agent_id,
        tool_name="hub_revoke_agent_token",
        action_type="token_revoke",
        target=f"agent:{agent_id}",
        reason=f"Revoked token for agent {agent_id}",
        status="SUCCESS" if success else "NOT_FOUND",
        params={"target_agent_id": agent_id},
    )
    return {"agent_id": agent_id, "status": "REVOKED" if success else "NOT_FOUND"}
