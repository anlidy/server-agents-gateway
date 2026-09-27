"""
提权审批：operator 提交需要 root 的操作 → 通知 admin → admin 批准后 SAG 以 root 原样执行。

- 请求内容（payload）提交后不可修改；批准只接受 request_id 和备注。执行前校验 payload 的 sha256。
- 过期（默认 24 小时）的请求不能再批准。
- 执行结果（stdout/stderr/退出码/diff）脱敏后存进 elevation_requests，并通过协作消息通知申请人。
"""

from __future__ import annotations

import difflib
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import collab
from .audit_redact import redact_secrets, redact_structure
from .config import config
from .db import append_audit, get_db_connection

KINDS = ("shell", "write_file", "patch_file")
STATUSES = ("pending", "approved", "rejected", "expired", "executed", "failed")  # approved = 正在执行
SYSTEM_SENDER = "sag:system"
RESULT_TEXT_MAX = 64 * 1024
PREVIEW = 300


class ElevationError(ValueError):
    pass


def _now_iso(ts: Optional[float] = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts if ts is not None else time.time()))


def _canonical(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def _clip(text: Optional[str], limit: int = RESULT_TEXT_MAX) -> Optional[str]:
    if text is None:
        return None
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore") + "\n[truncated]\n"


def admin_agents(conn) -> List[str]:
    rows = conn.execute(
        "SELECT agent_id FROM agent_credentials WHERE status = 'ACTIVE' AND role = 'admin' ORDER BY agent_id;"
    ).fetchall()
    return [r["agent_id"] for r in rows]


def _build_payload(kind: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if kind == "shell":
        command = (args.get("command") or "").strip()
        if not command:
            raise ElevationError("kind=shell needs `command`")
        if len(command.encode("utf-8")) > 64 * 1024:
            raise ElevationError("command too long")
        payload: Dict[str, Any] = {"command": command}
        if args.get("cwd"):
            payload["cwd"] = str(args["cwd"])
        if args.get("timeout_seconds") is not None:
            t = int(args["timeout_seconds"])
            payload["timeout_seconds"] = min(max(1, t), config.shell_timeout_max)
        return payload
    if kind in ("write_file", "patch_file"):
        path = (args.get("path") or "").strip()
        if not path or not path.startswith("/"):
            raise ElevationError(f"kind={kind} needs an absolute `path`")
        if kind == "write_file":
            if args.get("content") is None:
                raise ElevationError("kind=write_file needs `content`")
            content = str(args["content"])
            if len(content.encode("utf-8")) > 2 * 1024 * 1024:
                raise ElevationError("content too large (max 2MB)")
            return {"path": path, "content": content}
        if not args.get("old_string"):
            raise ElevationError("kind=patch_file needs a non-empty `old_string`")
        if args.get("new_string") is None:
            raise ElevationError("kind=patch_file needs `new_string`")
        return {
            "path": path,
            "old_string": str(args["old_string"]),
            "new_string": str(args["new_string"]),
            "replace_all": collab._as_bool(args.get("replace_all")),
        }
    raise ElevationError(f"kind must be one of {', '.join(KINDS)}")


def _describe(kind: str, payload: Dict[str, Any]) -> str:
    if kind == "shell":
        lines = [f"命令（以 root 执行）：\n```\n{payload['command']}\n```"]
        if payload.get("cwd"):
            lines.append(f"cwd: {payload['cwd']}")
        if payload.get("timeout_seconds"):
            lines.append(f"timeout: {payload['timeout_seconds']}s")
        return "\n".join(lines)
    if kind == "write_file":
        c = payload["content"]
        preview = c if len(c) <= 2000 else c[:2000] + "\n…（共 %d 字符）" % len(c)
        return f"以 root 写入 {payload['path']}，内容：\n```\n{preview}\n```"
    return (
        f"以 root 修改 {payload['path']}"
        + ("（全部替换）" if payload.get("replace_all") else "")
        + f"\n把：\n```\n{payload['old_string']}\n```\n替换为：\n```\n{payload['new_string']}\n```"
    )


def _notify(conn, sender: str, recipients: List[str], subject: str, body: str,
            thread_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    wanted = [r for r in dict.fromkeys(recipients) if r]
    if not wanted:
        return None
    return collab._insert_message(
        conn, sender, ",".join(wanted), wanted, collab._clean_subject(subject), body, thread_id=thread_id
    )


# --------------------------------------------------------------------------- request


def request_elevation(agent_id: str, privileged: bool, kind: str, reason: str, **args) -> Dict[str, Any]:
    if privileged:
        raise ElevationError("you already run as root (admin); no elevation needed")
    reason = (reason or "").strip()
    if not reason:
        raise ElevationError("reason is required: explain why this needs root")
    kind = (kind or "").strip()
    payload = _build_payload(kind, args)
    payload_json = _canonical(payload)
    sha = _sha(payload_json)
    now = time.time()
    expires = now + config.elevation_ttl_hours * 3600
    req_id = "e_" + uuid.uuid4().hex[:12]
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO elevation_requests
                (id, agent_id, kind, payload_json, payload_sha256, reason, status,
                 created_at, created_ts, expires_at, expires_ts)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?);
            """,
            (req_id, agent_id, kind, payload_json, sha, reason, _now_iso(now), now, _now_iso(expires), expires),
        )
        admins = admin_agents(conn)
        body = (
            f"{agent_id} 申请以 root 执行（{req_id}，{config.elevation_ttl_hours} 小时内有效）。\n\n"
            f"理由：{reason}\n\n{_describe(kind, payload)}\n\n"
            f"sha256: {sha}\n\n"
            f"批准：hub_approve_elevation(request_id=\"{req_id}\")；拒绝：hub_reject_elevation。\n"
            f"或在服务器上：sudo python3 -m sag elevation approve {req_id}"
        )
        msg = _notify(conn, agent_id, admins, f"[提权申请] {reason}", body)
        if msg:
            conn.execute("UPDATE elevation_requests SET thread_id = ? WHERE id = ?;", (msg["thread_id"], req_id))
        conn.commit()
    append_audit(
        agent_id=agent_id,
        tool_name="hub_request_elevation",
        action_type="elevation_request",
        target=f"elevation:{req_id}",
        reason=reason,
        status="SUCCESS",
        params={"request_id": req_id, "kind": kind, "payload": payload, "sha256": sha, "notified": admins},
    )
    return {
        "id": req_id,
        "status": "pending",
        "kind": kind,
        "expires_at": _now_iso(expires),
        "payload_sha256": sha,
        "notified_admins": admins,
        "note": "An admin must approve it. You will get a message with the result; "
        "check hub_list_elevations(request_id=...) any time.",
    }


# --------------------------------------------------------------------------- expire / list


def expire_elevations() -> int:
    now = time.time()
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM elevation_requests WHERE status = 'pending' AND expires_ts <= ?;", (now,)
        ).fetchall()
        for r in rows:
            cur = conn.execute(
                """
                UPDATE elevation_requests SET status = 'expired', decided_by = ?, decided_at = ?
                WHERE id = ? AND status = 'pending';
                """,
                (SYSTEM_SENDER, _now_iso(now), r["id"]),
            )
            if cur.rowcount:
                _notify(conn, SYSTEM_SENDER, [r["agent_id"]], f"[提权已过期] {r['reason']}",
                        f"提权申请 {r['id']} 在 {r['expires_at']} 前没有被处理，已过期，未执行。需要的话请重新提交。",
                        thread_id=r["thread_id"])
        conn.commit()
    for r in rows:
        append_audit(agent_id=SYSTEM_SENDER, tool_name="hub_list_elevations", action_type="elevation_expire",
                     target=f"elevation:{r['id']}", reason=r["reason"], status="SUCCESS",
                     params={"request_id": r["id"], "requester": r["agent_id"]})
    return len(rows)


def _row_view(r, full: bool) -> Dict[str, Any]:
    payload = json.loads(r["payload_json"])
    d: Dict[str, Any] = {
        "id": r["id"],
        "agent_id": r["agent_id"],
        "kind": r["kind"],
        "reason": r["reason"],
        "status": r["status"],
        "created_at": r["created_at"],
        "expires_at": r["expires_at"],
        "decided_by": r["decided_by"],
        "decided_at": r["decided_at"],
        "decision_note": r["decision_note"],
        "exit_code": r["exit_code"],
        "payload_sha256": r["payload_sha256"],
        "thread_id": r["thread_id"],
    }
    if full:
        d["payload"] = payload
        d["result"] = json.loads(r["result_json"]) if r["result_json"] else None
    else:
        d["payload"] = {
            k: (v if not isinstance(v, str) or len(v) <= PREVIEW else v[:PREVIEW] + "…")
            for k, v in payload.items()
        }
    return d


def list_elevations(agent_id: str, privileged: bool, status: Optional[str] = "pending",
                    request_id: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    expire_elevations()
    with get_db_connection() as conn:
        if request_id:
            r = conn.execute("SELECT * FROM elevation_requests WHERE id = ?;", (request_id.strip(),)).fetchone()
            if not r or (not privileged and r["agent_id"] != agent_id):
                raise ElevationError(f"elevation request not found: {request_id}")
            return {"requests": [_row_view(r, full=True)]}
        cond: List[str] = []
        params: List[Any] = []
        st = (status or "pending").strip().lower()
        if st != "all":
            if st not in STATUSES:
                raise ElevationError(f"status must be all or one of {', '.join(STATUSES)}")
            cond.append("status = ?")
            params.append(st)
        if not privileged:
            cond.append("agent_id = ?")
            params.append(agent_id)
        where = f"WHERE {' AND '.join(cond)}" if cond else ""
        limit = max(1, min(int(limit or 20), 100))
        rows = conn.execute(
            f"SELECT * FROM elevation_requests {where} ORDER BY created_ts DESC LIMIT ?;", (*params, limit)
        ).fetchall()
    return {"status_filter": st, "requests": [_row_view(r, full=False) for r in rows]}


# --------------------------------------------------------------------------- decide


def _claim(conn, request_id: str, approver: str, new_status: str, note: Optional[str]):
    r = conn.execute("SELECT * FROM elevation_requests WHERE id = ?;", ((request_id or "").strip(),)).fetchone()
    if not r:
        raise ElevationError(f"elevation request not found: {request_id}")
    if r["status"] != "pending":
        raise ElevationError(f"request {r['id']} is already {r['status']}")
    if r["expires_ts"] <= time.time():
        raise ElevationError(f"request {r['id']} has expired")
    cur = conn.execute(
        """
        UPDATE elevation_requests SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?
        WHERE id = ? AND status = 'pending';
        """,
        (new_status, approver, _now_iso(), note, r["id"]),
    )
    if cur.rowcount != 1:
        raise ElevationError(f"request {r['id']} was decided concurrently")
    conn.commit()
    return r


def reject_elevation(approver: str, privileged: bool, request_id: str, note: Optional[str] = None) -> Dict[str, Any]:
    if not privileged:
        raise PermissionError("only admin agents can reject elevation requests")
    expire_elevations()
    note = (note or "").strip() or None
    with get_db_connection() as conn:
        r = _claim(conn, request_id, approver, "rejected", note)
        _notify(conn, approver, [r["agent_id"]], f"[提权被拒绝] {r['reason']}",
                f"提权申请 {r['id']} 被 {approver} 拒绝，未执行。" + (f"\n\n备注：{note}" if note else ""),
                thread_id=r["thread_id"])
        conn.commit()
    append_audit(agent_id=approver, tool_name="hub_reject_elevation", action_type="elevation_reject",
                 target=f"elevation:{r['id']}", reason=note or "", status="SUCCESS",
                 params={"request_id": r["id"], "requester": r["agent_id"]})
    return {"id": r["id"], "status": "rejected", "decided_by": approver}


def _read_text_or_empty(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        return ""


def _execute(r, approver: str) -> Dict[str, Any]:
    from .tools import tool_patch_file, tool_shell, tool_write_file

    payload = json.loads(r["payload_json"])
    label = f"[提权 {r['id']}，申请人 {r['agent_id']}，批准人 {approver}] {r['reason']}"
    kind = r["kind"]
    if kind == "shell":
        res = tool_shell(approver, payload["command"], label, cwd=payload.get("cwd"),
                         timeout_seconds=payload.get("timeout_seconds"), privileged=True)
        return {
            "ok": res["exit_code"] == 0,
            "exit_code": res["exit_code"],
            "stdout": res["stdout"],
            "stderr": res["stderr"],
            "truncated": res["truncated"],
            "cwd": res["cwd"],
            "duration_ms": res["duration_ms"],
            "trash_ids": res["trash_ids"],
        }
    path = payload["path"]
    before = _read_text_or_empty(path)
    if kind == "write_file":
        res = tool_write_file(approver, path, payload["content"], label, privileged=True)
    else:
        res = tool_patch_file(approver, path, payload["old_string"], payload["new_string"], label,
                              replace_all=payload.get("replace_all", False), privileged=True)
    after = _read_text_or_empty(path)
    diff = "\n".join(difflib.unified_diff(before.splitlines(), after.splitlines(),
                                          fromfile=f"a/{Path(path).name}", tofile=f"b/{Path(path).name}",
                                          lineterm=""))
    return {"ok": True, "exit_code": 0, "path": res.get("path"), "trash_id": res.get("trash_id"),
            "replacements": res.get("replacements"), "diff": diff}


def approve_elevation(approver: str, privileged: bool, request_id: str, note: Optional[str] = None) -> Dict[str, Any]:
    """批准并以 root 原样执行。不接受任何改写请求内容的参数。"""
    if not privileged:
        raise PermissionError("only admin agents can approve elevation requests")
    expire_elevations()
    note = (note or "").strip() or None
    with get_db_connection() as conn:
        r = _claim(conn, request_id, approver, "approved", note)
    if _sha(r["payload_json"]) != r["payload_sha256"]:
        result = {"ok": False, "exit_code": None, "error": "payload integrity check failed; not executed"}
    else:
        try:
            result = _execute(r, approver)
        except Exception as exc:  # noqa: BLE001
            result = {"ok": False, "exit_code": None, "error": f"{type(exc).__name__}: {exc}"}
    for k in ("stdout", "stderr", "diff", "error"):
        if result.get(k):
            result[k] = _clip(redact_secrets(result[k]))
    result = redact_structure(result)
    status = "executed" if result.get("ok") else "failed"
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE elevation_requests SET status = ?, result_json = ?, exit_code = ? WHERE id = ?;",
            (status, json.dumps(result, ensure_ascii=False), result.get("exit_code"), r["id"]),
        )
        summary = [f"提权申请 {r['id']} 已由 {approver} 批准并以 root 执行：{'成功' if status == 'executed' else '失败'}。"]
        if note:
            summary.append(f"备注：{note}")
        if result.get("exit_code") is not None:
            summary.append(f"退出码：{result['exit_code']}")
        for k, title in (("error", "错误"), ("stdout", "stdout"), ("stderr", "stderr"), ("diff", "diff")):
            v = result.get(k)
            if v:
                tail = v if len(v) <= 1500 else "…" + v[-1500:]
                summary.append(f"{title}：\n```\n{tail}\n```")
        summary.append(f"完整结果：hub_list_elevations(request_id=\"{r['id']}\")")
        _notify(conn, approver, [r["agent_id"]], f"[提权已执行] {r['reason']}", "\n\n".join(summary),
                thread_id=r["thread_id"])
        conn.commit()
    append_audit(
        agent_id=approver,
        tool_name="hub_approve_elevation",
        action_type="elevation_execute",
        target=f"elevation:{r['id']}",
        reason=r["reason"],
        status="SUCCESS" if status == "executed" else "FAILED",
        exit_code=result.get("exit_code"),
        params={"request_id": r["id"], "requester": r["agent_id"], "kind": r["kind"],
                "sha256": r["payload_sha256"], "note": note},
        stdout=result.get("stdout"),
        stderr=result.get("stderr") or result.get("error"),
        diff=result.get("diff"),
    )
    return {"id": r["id"], "status": status, "requester": r["agent_id"], "result": result}
