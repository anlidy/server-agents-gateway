"""
Agent 协作：消息（收件箱 / 线程 / 已读）与任务交接。

发件人一律来自调用者 token 对应的 agent_id（由 server.dispatch_tool 传入），
工具参数里没有 from 字段，无法伪造。消息正文原样存进 agent_messages
（交接时可能需要原文），审计里只按 append_audit 的规则脱敏后记录。
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

from .db import append_audit, get_db_connection

BODY_MAX_BYTES = 64 * 1024
SUBJECT_MAX_CHARS = 200
PREVIEW_CHARS = 280
TASK_STATUSES = ("open", "claimed", "done", "cancelled")
TASK_ACTIONS = ("claim", "release", "done", "cancel", "reopen", "comment")
_GROUP_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

# 这些工具本身就是在看收件箱，不再附未读提示。
NO_HINT_TOOLS = frozenset({"hub_inbox", "hub_read_message", "hub_mark_read"})


class CollabError(ValueError):
    pass


def _as_bool(value: Any, default: bool = False) -> bool:
    """部分客户端把布尔值当字符串传（"false"），这里统一一下。"""
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return bool(value)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _clean_text(value: Optional[str], field: str, max_bytes: int = BODY_MAX_BYTES) -> str:
    text = (value or "").strip()
    if len(text.encode("utf-8")) > max_bytes:
        raise CollabError(f"{field} too long (max {max_bytes} bytes)")
    return text


def _clean_subject(subject: Optional[str]) -> str:
    s = " ".join((subject or "").split())
    return s[:SUBJECT_MAX_CHARS]


# ---------------------------------------------------------------------------
# Agents & groups
# ---------------------------------------------------------------------------


def _active_agents(conn) -> List[str]:
    rows = conn.execute(
        "SELECT agent_id FROM agent_credentials WHERE status = 'ACTIVE' ORDER BY agent_id;"
    ).fetchall()
    return [r["agent_id"] for r in rows]


def _groups_by_agent(conn) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for r in conn.execute("SELECT group_name, agent_id FROM agent_groups ORDER BY group_name;"):
        out.setdefault(r["agent_id"], []).append(r["group_name"])
    return out


def _split_targets(to: Union[str, Sequence[str], None]) -> List[str]:
    if to is None:
        return []
    items: Iterable[str] = [to] if isinstance(to, str) else to
    out: List[str] = []
    for item in items:
        for part in str(item).split(","):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


def resolve_recipients(conn, sender: str, to: Union[str, Sequence[str], None]) -> tuple[str, List[str]]:
    """
    展开收件人表达式，返回 (规范化后的 to 字符串, 收件人 agent_id 列表)。

    - `mobile:xiaoyao`：具体 agent（必须是 ACTIVE 的已签发 agent；可以发给自己）
    - `*`：所有 ACTIVE agent（不含自己）
    - `wsl:*`：agent_id 以 `wsl:` 开头的 ACTIVE agent（不含自己）
    - `@ops`：组 ops 的 ACTIVE 成员（不含自己）
    多个目标用逗号分隔或传数组，取并集。
    """
    targets = _split_targets(to)
    if not targets:
        raise CollabError("`to` is required: an agent_id, `*`, `prefix:*`, or `@group`")
    active = _active_agents(conn)
    active_set = set(active)
    recipients: List[str] = []

    def add(agent: str) -> None:
        if agent not in recipients:
            recipients.append(agent)

    for t in targets:
        if t.startswith("@"):
            name = t[1:]
            rows = conn.execute(
                "SELECT agent_id FROM agent_groups WHERE group_name = ? ORDER BY agent_id;", (name,)
            ).fetchall()
            if not rows:
                raise CollabError(f"unknown group: {t} (use hub_list_agents to see groups)")
            for r in rows:
                if r["agent_id"] in active_set and r["agent_id"] != sender:
                    add(r["agent_id"])
        elif t.endswith("*"):
            prefix = t[:-1]
            for a in active:
                if a.startswith(prefix) and a != sender:
                    add(a)
        else:
            if t not in active_set:
                raise CollabError(
                    f"unknown or revoked agent: {t}. Known agents: {', '.join(active) or '(none)'}"
                )
            add(t)
    if not recipients:
        raise CollabError(f"`to` matched no other active agent: {', '.join(targets)}")
    return ",".join(targets), recipients


def list_agents(caller: str, include_revoked: bool = False) -> Dict[str, Any]:
    with get_db_connection() as conn:
        sql = "SELECT agent_id, role, status, created_at, last_used_at FROM agent_credentials"
        if not _as_bool(include_revoked):
            sql += " WHERE status = 'ACTIVE'"
        sql += " ORDER BY COALESCE(last_used_at, '') DESC, agent_id;"
        rows = conn.execute(sql).fetchall()
        groups = _groups_by_agent(conn)
        group_rows = conn.execute(
            "SELECT group_name, agent_id FROM agent_groups ORDER BY group_name, agent_id;"
        ).fetchall()
    agents = []
    for r in rows:
        agents.append(
            {
                "agent_id": r["agent_id"],
                "role": r["role"],
                "status": r["status"],
                "last_active_at": r["last_used_at"],
                "created_at": r["created_at"],
                "groups": groups.get(r["agent_id"], []),
                "is_you": r["agent_id"] == caller,
            }
        )
    group_map: Dict[str, List[str]] = {}
    for g in group_rows:
        group_map.setdefault(g["group_name"], []).append(g["agent_id"])
    return {"you": caller, "agents": agents, "groups": group_map}


def set_group(caller: str, group: str, members: Union[str, Sequence[str], None]) -> Dict[str, Any]:
    name = (group or "").strip().lstrip("@")
    if not _GROUP_RE.match(name):
        raise CollabError("group name must match [A-Za-z0-9_.-]{1,64}")
    wanted = _split_targets(members)
    now = _now()
    with get_db_connection() as conn:
        known = {
            r["agent_id"] for r in conn.execute("SELECT agent_id FROM agent_credentials;").fetchall()
        }
        unknown = [m for m in wanted if m not in known]
        if unknown:
            raise CollabError(f"unknown agent(s): {', '.join(unknown)}")
        conn.execute("DELETE FROM agent_groups WHERE group_name = ?;", (name,))
        for m in wanted:
            conn.execute(
                "INSERT INTO agent_groups (group_name, agent_id, added_by, added_at) VALUES (?, ?, ?, ?);",
                (name, m, caller, now),
            )
        conn.commit()
    append_audit(
        agent_id=caller,
        tool_name="hub_set_group",
        action_type="group_set",
        target=f"@{name}",
        reason="",
        status="SUCCESS",
        params={"group": name, "members": wanted},
    )
    return {"group": f"@{name}", "members": wanted, "status": "DELETED" if not wanted else "SET"}


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


def _insert_message(
    conn,
    sender: str,
    to_spec: str,
    recipients: List[str],
    subject: str,
    body: str,
    thread_id: Optional[str] = None,
    reply_to: Optional[str] = None,
    task_id: Optional[str] = None,
) -> Dict[str, Any]:
    msg_id = _new_id("m")
    thread = thread_id or msg_id
    now = _now()
    conn.execute(
        """
        INSERT INTO agent_messages
            (id, thread_id, reply_to, from_agent, to_agent, subject, body, task_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (msg_id, thread, reply_to, sender, to_spec, subject, body, task_id, now),
    )
    for r in recipients:
        conn.execute(
            "INSERT OR IGNORE INTO agent_message_recipients (message_id, agent_id, read_at) VALUES (?, ?, NULL);",
            (msg_id, r),
        )
    return {
        "id": msg_id,
        "thread_id": thread,
        "reply_to": reply_to,
        "to": to_spec,
        "recipients": recipients,
        "subject": subject,
        "task_id": task_id,
        "created_at": now,
    }


def _audit_message(sender: str, tool_name: str, action: str, msg: Dict[str, Any], body: str) -> None:
    append_audit(
        agent_id=sender,
        tool_name=tool_name,
        action_type=action,
        target=f"to:{msg['to']}",
        reason=msg.get("subject") or "",
        status="SUCCESS",
        params={
            "message_id": msg["id"],
            "thread_id": msg["thread_id"],
            "reply_to": msg.get("reply_to"),
            "task_id": msg.get("task_id"),
            "subject": msg.get("subject"),
            "recipients": msg["recipients"],
        },
        stdout=body,  # append_audit 会脱敏
    )


def send_message(
    sender: str,
    to: Union[str, Sequence[str]],
    body: str,
    subject: str = "",
    thread_id: Optional[str] = None,
) -> Dict[str, Any]:
    body = _clean_text(body, "body")
    if not body:
        raise CollabError("body must not be empty")
    subject = _clean_subject(subject)
    with get_db_connection() as conn:
        reply_to = None
        task_id = None
        if thread_id:
            root = conn.execute(
                "SELECT id, subject, task_id FROM agent_messages WHERE thread_id = ? ORDER BY created_at, rowid LIMIT 1;",
                (thread_id,),
            ).fetchone()
            if not root:
                raise CollabError(f"thread not found: {thread_id}")
            if not _can_see_thread(conn, sender, thread_id):
                raise CollabError(f"thread not found: {thread_id}")
            last = conn.execute(
                "SELECT id FROM agent_messages WHERE thread_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;",
                (thread_id,),
            ).fetchone()
            reply_to = last["id"]
            task_id = root["task_id"]
            if not subject:
                subject = _re_subject(root["subject"])
        to_spec, recipients = resolve_recipients(conn, sender, to)
        msg = _insert_message(
            conn, sender, to_spec, recipients, subject, body,
            thread_id=thread_id, reply_to=reply_to, task_id=task_id,
        )
        conn.commit()
    _audit_message(sender, "hub_send_message", "message_send", msg, body)
    return {"status": "SENT", **msg}


def _re_subject(subject: str) -> str:
    s = subject or ""
    if not s or s.lower().startswith("re:"):
        return s
    return _clean_subject("Re: " + s)


def _can_see_message(conn, agent: str, msg_row) -> bool:
    if msg_row["from_agent"] == agent:
        return True
    r = conn.execute(
        "SELECT 1 FROM agent_message_recipients WHERE message_id = ? AND agent_id = ?;",
        (msg_row["id"], agent),
    ).fetchone()
    return r is not None


def _can_see_thread(conn, agent: str, thread_id: str) -> bool:
    r = conn.execute(
        """
        SELECT 1 FROM agent_messages m
        LEFT JOIN agent_message_recipients r ON r.message_id = m.id AND r.agent_id = ?
        WHERE m.thread_id = ? AND (m.from_agent = ? OR r.agent_id IS NOT NULL)
        LIMIT 1;
        """,
        (agent, thread_id, agent),
    ).fetchone()
    return r is not None


def _get_visible_message(conn, agent: str, message_id: str):
    row = conn.execute("SELECT * FROM agent_messages WHERE id = ?;", ((message_id or "").strip(),)).fetchone()
    if not row or not _can_see_message(conn, agent, row):
        raise CollabError(f"message not found: {message_id}")
    return row


def reply(
    sender: str,
    message_id: str,
    body: str,
    reply_all: bool = False,
    subject: Optional[str] = None,
) -> Dict[str, Any]:
    body = _clean_text(body, "body")
    if not body:
        raise CollabError("body must not be empty")
    with get_db_connection() as conn:
        orig = _get_visible_message(conn, sender, message_id)
        targets: List[str] = []
        if orig["from_agent"] != sender:
            targets.append(orig["from_agent"])
        if _as_bool(reply_all) or orig["from_agent"] == sender:
            # 回复自己发出的消息 = 追加给原收件人
            for r in conn.execute(
                "SELECT agent_id FROM agent_message_recipients WHERE message_id = ? ORDER BY agent_id;",
                (orig["id"],),
            ):
                if r["agent_id"] != sender and r["agent_id"] not in targets:
                    targets.append(r["agent_id"])
        active = set(_active_agents(conn))
        targets = [t for t in targets if t in active]
        if not targets:
            raise CollabError("nobody left to reply to (original participants are revoked)")
        to_spec, recipients = resolve_recipients(conn, sender, targets)
        subj = _clean_subject(subject) if subject else _re_subject(orig["subject"])
        msg = _insert_message(
            conn, sender, to_spec, recipients, subj, body,
            thread_id=orig["thread_id"], reply_to=orig["id"], task_id=orig["task_id"],
        )
        # 回复即视为已读原消息
        conn.execute(
            "UPDATE agent_message_recipients SET read_at = ? WHERE message_id = ? AND agent_id = ? AND read_at IS NULL;",
            (_now(), orig["id"], sender),
        )
        conn.commit()
    _audit_message(sender, "hub_reply", "message_reply", msg, body)
    return {"status": "SENT", **msg}


def _row_to_msg(row, agent: str, full: bool) -> Dict[str, Any]:
    body = row["body"] or ""
    out: Dict[str, Any] = {
        "id": row["id"],
        "thread_id": row["thread_id"],
        "from": row["from_agent"],
        "to": row["to_agent"],
        "subject": row["subject"],
        "created_at": row["created_at"],
    }
    if row["reply_to"]:
        out["reply_to"] = row["reply_to"]
    if row["task_id"]:
        out["task_id"] = row["task_id"]
    if full or len(body) <= PREVIEW_CHARS:
        out["body"] = body
    else:
        out["body"] = body[:PREVIEW_CHARS] + "…"
        out["body_truncated"] = True
    return out


def unread_count(agent: str) -> int:
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS n FROM agent_message_recipients WHERE agent_id = ? AND read_at IS NULL;",
            (agent,),
        ).fetchone()["n"]


def inbox(
    agent: str,
    unread_only: Optional[bool] = None,
    thread_id: Optional[str] = None,
    from_agent: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 20), 100))
    with get_db_connection() as conn:
        if thread_id:
            if not _can_see_thread(conn, agent, thread_id):
                raise CollabError(f"thread not found: {thread_id}")
            rows = conn.execute(
                """
                SELECT m.*, r.read_at AS read_at, r.agent_id AS rcpt
                FROM agent_messages m
                LEFT JOIN agent_message_recipients r ON r.message_id = m.id AND r.agent_id = ?
                WHERE m.thread_id = ? AND (m.from_agent = ? OR r.agent_id IS NOT NULL)
                ORDER BY m.created_at, m.rowid;
                """,
                (agent, thread_id, agent),
            ).fetchall()
            if _as_bool(unread_only):
                rows = [r for r in rows if r["rcpt"] is not None and r["read_at"] is None]
            rows = rows[-limit:]
            messages = []
            newly_read = []
            for r in rows:
                was_unread = r["rcpt"] is not None and r["read_at"] is None
                m = _row_to_msg(r, agent, full=True)
                m["read"] = not was_unread
                messages.append(m)
                if was_unread:
                    newly_read.append(r["id"])
            now = _now()
            for mid in newly_read:
                conn.execute(
                    "UPDATE agent_message_recipients SET read_at = ? WHERE message_id = ? AND agent_id = ?;",
                    (now, mid, agent),
                )
            conn.commit()
            remaining = conn.execute(
                "SELECT COUNT(*) AS n FROM agent_message_recipients WHERE agent_id = ? AND read_at IS NULL;",
                (agent,),
            ).fetchone()["n"]
            return {
                "you": agent,
                "thread_id": thread_id,
                "messages": messages,
                "marked_read": len(newly_read),
                "unread_total": remaining,
            }

        only_unread = _as_bool(unread_only, default=True)
        cond = ["r.agent_id = ?"]
        params: List[Any] = [agent]
        if only_unread:
            cond.append("r.read_at IS NULL")
        if from_agent:
            cond.append("m.from_agent = ?")
            params.append(from_agent)
        rows = conn.execute(
            f"""
            SELECT m.*, r.read_at AS read_at, r.agent_id AS rcpt
            FROM agent_message_recipients r
            JOIN agent_messages m ON m.id = r.message_id
            WHERE {' AND '.join(cond)}
            ORDER BY m.created_at DESC, m.rowid DESC
            LIMIT ?;
            """,
            (*params, limit),
        ).fetchall()
        total_unread = conn.execute(
            "SELECT COUNT(*) AS n FROM agent_message_recipients WHERE agent_id = ? AND read_at IS NULL;",
            (agent,),
        ).fetchone()["n"]
    messages = []
    for r in rows:
        m = _row_to_msg(r, agent, full=False)
        m["read"] = r["read_at"] is not None
        messages.append(m)
    return {
        "you": agent,
        "unread_only": only_unread,
        "unread_total": total_unread,
        "messages": messages,
        "hint": (
            "Bodies are previews. hub_read_message(id) shows one in full and marks it read; "
            "hub_inbox(thread_id=...) shows a whole thread and marks it read."
        ),
    }


def read_message(agent: str, message_id: str, mark_read: bool = True) -> Dict[str, Any]:
    mark_read = _as_bool(mark_read, default=True)
    with get_db_connection() as conn:
        row = _get_visible_message(conn, agent, message_id)
        rcpts = conn.execute(
            "SELECT agent_id, read_at FROM agent_message_recipients WHERE message_id = ? ORDER BY agent_id;",
            (row["id"],),
        ).fetchall()
        mine = next((r for r in rcpts if r["agent_id"] == agent), None)
        was_unread = mine is not None and mine["read_at"] is None
        now = _now()
        if was_unread and mark_read:
            conn.execute(
                "UPDATE agent_message_recipients SET read_at = ? WHERE message_id = ? AND agent_id = ?;",
                (now, row["id"], agent),
            )
            conn.commit()
        thread_size = conn.execute(
            "SELECT COUNT(*) AS n FROM agent_messages WHERE thread_id = ?;", (row["thread_id"],)
        ).fetchone()["n"]
    msg = _row_to_msg(row, agent, full=True)
    msg["read"] = not was_unread or mark_read
    msg["recipients"] = [
        {"agent_id": r["agent_id"], "read_at": (now if (r["agent_id"] == agent and was_unread and mark_read) else r["read_at"])}
        for r in rcpts
    ]
    msg["thread_messages"] = thread_size
    return msg


def mark_read(
    agent: str,
    message_ids: Union[str, Sequence[str], None] = None,
    thread_id: Optional[str] = None,
    all: bool = False,
) -> Dict[str, Any]:
    ids = _split_targets(message_ids)
    all = _as_bool(all)
    if not ids and not thread_id and not all:
        raise CollabError("pass message_ids, thread_id, or all=true")
    now = _now()
    with get_db_connection() as conn:
        n = 0
        if all:
            n += conn.execute(
                "UPDATE agent_message_recipients SET read_at = ? WHERE agent_id = ? AND read_at IS NULL;",
                (now, agent),
            ).rowcount
        else:
            for mid in ids:
                n += conn.execute(
                    "UPDATE agent_message_recipients SET read_at = ? WHERE message_id = ? AND agent_id = ? AND read_at IS NULL;",
                    (now, mid, agent),
                ).rowcount
            if thread_id:
                n += conn.execute(
                    """
                    UPDATE agent_message_recipients SET read_at = ?
                    WHERE agent_id = ? AND read_at IS NULL
                      AND message_id IN (SELECT id FROM agent_messages WHERE thread_id = ?);
                    """,
                    (now, agent, thread_id),
                ).rowcount
        conn.commit()
        remaining = conn.execute(
            "SELECT COUNT(*) AS n FROM agent_message_recipients WHERE agent_id = ? AND read_at IS NULL;",
            (agent,),
        ).fetchone()["n"]
    return {"marked_read": n, "unread_total": remaining}


def unread_hint(agent: str) -> Optional[str]:
    """一行简短提示；没有未读返回 None。"""
    try:
        with get_db_connection() as conn:
            n = conn.execute(
                "SELECT COUNT(*) AS n FROM agent_message_recipients WHERE agent_id = ? AND read_at IS NULL;",
                (agent,),
            ).fetchone()["n"]
            if not n:
                return None
            latest = conn.execute(
                """
                SELECT m.from_agent, m.subject FROM agent_message_recipients r
                JOIN agent_messages m ON m.id = r.message_id
                WHERE r.agent_id = ? AND r.read_at IS NULL
                ORDER BY m.created_at DESC, m.rowid DESC LIMIT 1;
                """,
                (agent,),
            ).fetchone()
    except Exception:
        return None
    subj = (latest["subject"] or "").strip() if latest else ""
    if len(subj) > 40:
        subj = subj[:40] + "…"
    who = latest["from_agent"] if latest else "?"
    detail = f"最新来自 {who}" + (f"：{subj}" if subj else "")
    return f"[SAG] 你有 {n} 条未读消息（{detail}），用 hub_inbox 查看。"


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


def _task_dict(row) -> Dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _get_task(conn, task_id: str):
    row = conn.execute("SELECT * FROM agent_tasks WHERE id = ?;", ((task_id or "").strip(),)).fetchone()
    if not row:
        raise CollabError(f"task not found: {task_id}")
    return row


def _notify_task(conn, sender: str, task, targets: Iterable[Optional[str]], subject: str, body: str) -> Optional[Dict[str, Any]]:
    active = set(_active_agents(conn))
    wanted = []
    for t in targets:
        if t and t != sender and t in active and t not in wanted:
            wanted.append(t)
    if not wanted:
        return None
    to_spec, recipients = resolve_recipients(conn, sender, wanted)
    thread = task["thread_id"]
    reply_to = None
    if thread:
        last = conn.execute(
            "SELECT id FROM agent_messages WHERE thread_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;",
            (thread,),
        ).fetchone()
        reply_to = last["id"] if last else None
    msg = _insert_message(
        conn, sender, to_spec, recipients, _clean_subject(subject), body,
        thread_id=thread, reply_to=reply_to, task_id=task["id"],
    )
    if not thread:
        conn.execute("UPDATE agent_tasks SET thread_id = ? WHERE id = ?;", (msg["thread_id"], task["id"]))
    return msg


def create_task(
    creator: str,
    title: str,
    description: str = "",
    assignee: Optional[str] = None,
    notify: bool = True,
) -> Dict[str, Any]:
    title = _clean_subject(title)
    if not title:
        raise CollabError("title must not be empty")
    description = _clean_text(description, "description")
    assignee = (assignee or "").strip() or None
    now = _now()
    task_id = _new_id("t")
    msg = None
    with get_db_connection() as conn:
        if assignee and assignee not in set(_active_agents(conn)):
            raise CollabError(f"unknown or revoked agent: {assignee}")
        conn.execute(
            """
            INSERT INTO agent_tasks
                (id, title, description, status, created_by, assignee, result, thread_id, created_at, updated_at)
            VALUES (?, ?, ?, 'open', ?, ?, NULL, NULL, ?, ?);
            """,
            (task_id, title, description, creator, assignee, now, now),
        )
        if _as_bool(notify, default=True):
            body = f"新任务 {task_id}：{title}\n"
            if assignee:
                body += f"指派给：{assignee}\n"
            else:
                body += "未指派，谁接手谁 hub_update_task(action=claim)。\n"
            if description:
                body += f"\n{description}\n"
            if assignee and assignee == creator:
                targets: List[str] = []
            elif assignee:
                targets = [assignee]
            else:
                targets = [a for a in _active_agents(conn) if a != creator]
            task_row = _get_task(conn, task_id)
            msg = _notify_task(conn, creator, task_row, targets, f"[任务] {title}", body)
        conn.commit()
        task = _task_dict(_get_task(conn, task_id))
    append_audit(
        agent_id=creator,
        tool_name="hub_create_task",
        action_type="task_create",
        target=f"task:{task_id}",
        reason=title,
        status="SUCCESS",
        params={"task_id": task_id, "assignee": assignee, "notified": msg["recipients"] if msg else []},
        stdout=description,
    )
    return {"status": "CREATED", "task": task, "notified": msg["recipients"] if msg else []}


def list_tasks(
    agent: str,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    created_by: Optional[str] = None,
    task_id: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    with get_db_connection() as conn:
        if task_id:
            task = _task_dict(_get_task(conn, task_id))
            return {"tasks": [task]}
        cond: List[str] = []
        params: List[Any] = []
        st = (status or "active").strip().lower()
        if st == "active":
            cond.append("status IN ('open', 'claimed')")
        elif st != "all":
            if st not in TASK_STATUSES:
                raise CollabError(f"status must be one of active, all, {', '.join(TASK_STATUSES)}")
            cond.append("status = ?")
            params.append(st)
        if assignee:
            cond.append("assignee = ?")
            params.append(agent if assignee == "me" else assignee)
        if created_by:
            cond.append("created_by = ?")
            params.append(agent if created_by == "me" else created_by)
        where = f"WHERE {' AND '.join(cond)}" if cond else ""
        limit = max(1, min(int(limit or 20), 100))
        rows = conn.execute(
            f"SELECT * FROM agent_tasks {where} ORDER BY updated_at DESC, rowid DESC LIMIT ?;",
            (*params, limit),
        ).fetchall()
    tasks = []
    for r in rows:
        d = _task_dict(r)
        if d.get("description") and len(d["description"]) > PREVIEW_CHARS:
            d["description"] = d["description"][:PREVIEW_CHARS] + "…"
        if d.get("result") and len(d["result"]) > PREVIEW_CHARS:
            d["result"] = d["result"][:PREVIEW_CHARS] + "…"
        tasks.append(d)
    return {"you": agent, "status_filter": st, "tasks": tasks}


def update_task(
    agent: str,
    task_id: str,
    action: str,
    result: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    action = (action or "").strip().lower()
    if action not in TASK_ACTIONS:
        raise CollabError(f"action must be one of {', '.join(TASK_ACTIONS)}")
    result = _clean_text(result, "result") or None
    note = _clean_text(note, "note") or None
    now = _now()
    with get_db_connection() as conn:
        task = _get_task(conn, task_id)
        status = task["status"]
        creator = task["created_by"]
        assignee = task["assignee"]
        involved = agent in (creator, assignee)
        new_status = status
        new_assignee = assignee
        new_result = task["result"]
        closed_at = task["closed_at"]

        if action == "claim":
            if status == "claimed" and assignee == agent:
                pass
            elif status != "open":
                raise CollabError(f"task is {status}" + (f" by {assignee}" if assignee else "") + "; cannot claim")
            elif assignee and assignee != agent:
                raise CollabError(f"task is assigned to {assignee}; ask them or the creator ({creator})")
            new_status, new_assignee = "claimed", agent
        elif action == "release":
            if status != "claimed":
                raise CollabError(f"task is {status}; only claimed tasks can be released")
            if not involved:
                raise CollabError(f"only {assignee} or the creator {creator} can release this task")
            new_status, new_assignee = "open", None
        elif action == "done":
            if status not in ("open", "claimed"):
                raise CollabError(f"task is already {status}")
            if assignee and not involved:
                raise CollabError(f"task is assigned to {assignee}; only they or the creator can finish it")
            new_status = "done"
            new_assignee = assignee or agent
            new_result = result if result is not None else (note or new_result)
            closed_at = now
        elif action == "cancel":
            if status in ("done", "cancelled"):
                raise CollabError(f"task is already {status}")
            if assignee and not involved:
                raise CollabError(f"only the creator {creator} or assignee {assignee} can cancel")
            if not assignee and agent != creator:
                raise CollabError(f"only the creator {creator} can cancel an unassigned task")
            new_status = "cancelled"
            new_result = result if result is not None else (note or new_result)
            closed_at = now
        elif action == "reopen":
            if status not in ("done", "cancelled"):
                raise CollabError(f"task is {status}; nothing to reopen")
            if not involved:
                raise CollabError(f"only the creator {creator} or assignee {assignee} can reopen")
            new_status, closed_at = "open", None
        elif action == "comment":
            if not (note or result):
                raise CollabError("comment needs `note`")

        if action != "comment":
            conn.execute(
                """
                UPDATE agent_tasks SET status = ?, assignee = ?, result = ?, updated_at = ?, closed_at = ?
                WHERE id = ?;
                """,
                (new_status, new_assignee, new_result, now, closed_at, task["id"]),
            )
        else:
            conn.execute("UPDATE agent_tasks SET updated_at = ? WHERE id = ?;", (now, task["id"]))

        labels = {
            "claim": "已认领",
            "release": "已放回（重新开放）",
            "done": "已完成",
            "cancel": "已取消",
            "reopen": "已重新打开",
            "comment": "有新备注",
        }
        body = f"任务 {task['id']}「{task['title']}」{labels[action]}（{agent}）。"
        text = (note or result) if action == "comment" else (result or note)
        if text:
            body += f"\n\n{text}"
        msg = _notify_task(
            conn, agent, _get_task(conn, task["id"]),
            [creator, assignee, new_assignee],
            f"[任务{labels[action]}] {task['title']}", body,
        )
        conn.commit()
        updated = _task_dict(_get_task(conn, task["id"]))
    append_audit(
        agent_id=agent,
        tool_name="hub_update_task",
        action_type=f"task_{action}",
        target=f"task:{task['id']}",
        reason=task["title"],
        status="SUCCESS",
        params={"task_id": task["id"], "action": action, "from_status": status, "to_status": updated["status"],
                "notified": msg["recipients"] if msg else []},
        stdout=text or "",
    )
    return {"status": "UPDATED", "task": updated, "notified": msg["recipients"] if msg else []}
