"""
SQLite layer: credentials, split audit logs, trash index, v1 migration.
"""

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .audit_redact import redact_secrets, redact_structure
from .config import config

_ACTION_TO_TOOL = {
    "shell_exec": "hub_shell",
    "file_create": "hub_write_file",
    "file_modify": "hub_write_file",
    "file_delete": "hub_delete_file",
    "token_issue": "hub_issue_agent_token",
    "token_revoke": "hub_revoke_agent_token",
    "lock_acquire": "hub_claim",
    "lock_renew": "hub_claim",
    "lock_release": "hub_release_claim",
    "asset_register": "hub_upsert_asset",
}


@contextmanager
def get_db_connection() -> Iterator[sqlite3.Connection]:
    db_file = Path(config.db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db_connection() as conn:
        conn.executescript(
            """
        CREATE TABLE IF NOT EXISTS agent_credentials (
            token_hash TEXT PRIMARY KEY,
            agent_id TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL,
            last_used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            exit_code INTEGER,
            cwd TEXT,
            duration_ms INTEGER,
            params_json TEXT,
            trash_id TEXT,
            output_bytes INTEGER NOT NULL DEFAULT 0,
            truncated INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_ae_time ON audit_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ae_agent_time ON audit_events(agent_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ae_tool ON audit_events(tool_name, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ae_action ON audit_events(action_type, status);
        CREATE INDEX IF NOT EXISTS idx_ae_target ON audit_events(target);

        CREATE TABLE IF NOT EXISTS audit_bodies (
            event_id TEXT PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
            stdout TEXT,
            stderr TEXT,
            diff TEXT
        );

        CREATE TABLE IF NOT EXISTS trash_items (
            id TEXT PRIMARY KEY,
            original_path TEXT NOT NULL,
            stored_relpath TEXT NOT NULL,
            deleted_by TEXT NOT NULL,
            deleted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            source TEXT NOT NULL,
            audit_id TEXT,
            is_dir INTEGER NOT NULL DEFAULT 0,
            size_bytes INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_trash_path ON trash_items(original_path);
        CREATE INDEX IF NOT EXISTS idx_trash_exp ON trash_items(expires_at);
        """
        )
        conn.commit()
    _migrate_v1_audit()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;", (name,)
    ).fetchone()
    return row is not None


def _migrate_v1_audit() -> None:
    with get_db_connection() as conn:
        if not _table_exists(conn, "gateway_audit_logs"):
            return
        count = conn.execute("SELECT COUNT(*) AS n FROM audit_events;").fetchone()["n"]
        if count == 0:
            rows = conn.execute("SELECT * FROM gateway_audit_logs;").fetchall()
            for row in rows:
                d = dict(row)
                tool_name = _ACTION_TO_TOOL.get(d.get("action_type") or "", "hub_shell")
                stdout = d.get("output_summary")
                diff = d.get("diff_snapshot")
                conn.execute(
                    """
                    INSERT OR IGNORE INTO audit_events (
                        id, timestamp, agent_id, tool_name, action_type, target, reason,
                        status, exit_code, cwd, duration_ms, params_json, trash_id,
                        output_bytes, truncated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL, ?, 0);
                    """,
                    (
                        d["id"],
                        d["timestamp"],
                        d["agent_id"],
                        tool_name,
                        d["action_type"],
                        d["target"],
                        d.get("intent_reason") or "",
                        d["status"],
                        d.get("duration_ms"),
                        d.get("params_json"),
                        len(stdout or ""),
                    ),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO audit_bodies (event_id, stdout, stderr, diff)
                    VALUES (?, ?, NULL, ?);
                    """,
                    (d["id"], stdout, diff),
                )
        conn.execute("ALTER TABLE gateway_audit_logs RENAME TO gateway_audit_logs_v1;")
        conn.commit()


def _clip_text(text: str, max_bytes: int) -> tuple[str, bool]:
    if not text:
        return text, False
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    cut = raw[:max_bytes].decode("utf-8", errors="ignore")
    return cut + "\n[truncated]\n", True


def append_audit(
    agent_id: str,
    tool_name: str,
    action_type: str,
    target: str,
    reason: str,
    status: str,
    exit_code: Optional[int] = None,
    cwd: Optional[str] = None,
    duration_ms: Optional[int] = None,
    params: Optional[Dict[str, Any]] = None,
    trash_id: Optional[str] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    diff: Optional[str] = None,
) -> str:
    log_id = str(uuid.uuid4())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    safe_target = redact_secrets(target or "")
    safe_reason = redact_secrets(reason or "")
    safe_params = redact_structure(params or {})
    safe_stdout = redact_secrets(stdout) if stdout else stdout
    safe_stderr = redact_secrets(stderr) if stderr else stderr
    safe_diff = redact_secrets(diff) if diff else diff
    if safe_diff:
        safe_diff, _ = _clip_text(safe_diff, 64 * 1024)
    max_body = config.audit_body_max_bytes
    truncated = False
    out = safe_stdout or ""
    err = safe_stderr or ""
    out_b = out.encode("utf-8")
    err_b = err.encode("utf-8")
    if len(out_b) + len(err_b) > max_body:
        truncated = True
        if len(out_b) > max_body:
            out, _ = _clip_text(out, max_body)
            err = "\n[truncated]\n"
        else:
            remain = max_body - len(out_b)
            err, _ = _clip_text(err, remain)
    output_bytes = len(out.encode("utf-8")) + len(err.encode("utf-8"))
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
                id, timestamp, agent_id, tool_name, action_type, target, reason,
                status, exit_code, cwd, duration_ms, params_json, trash_id,
                output_bytes, truncated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                log_id,
                now_iso,
                agent_id,
                tool_name,
                action_type,
                safe_target,
                safe_reason,
                status,
                exit_code,
                cwd,
                duration_ms,
                json.dumps(safe_params, ensure_ascii=False),
                trash_id,
                output_bytes,
                1 if truncated else 0,
            ),
        )
        conn.execute(
            "INSERT INTO audit_bodies (event_id, stdout, stderr, diff) VALUES (?, ?, ?, ?);",
            (log_id, out if out else safe_stdout, err if err else safe_stderr, safe_diff),
        )
        conn.commit()
    return log_id


def query_audit_logs(
    since: Optional[str] = None,
    until: Optional[str] = None,
    agent_id: Optional[str] = None,
    target: Optional[str] = None,
    action_type: Optional[str] = None,
    tool_name: Optional[str] = None,
    status: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    conditions = []
    params: List[Any] = []
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)
    if until:
        conditions.append("timestamp <= ?")
        params.append(until)
    if agent_id:
        conditions.append("agent_id = ?")
        params.append(agent_id)
    if target:
        if "*" in target or "%" in target:
            conditions.append("target LIKE ?")
            params.append(target.replace("*", "%"))
        else:
            conditions.append("target = ?")
            params.append(target)
    if action_type:
        conditions.append("action_type = ?")
        params.append(action_type)
    if tool_name:
        conditions.append("tool_name = ?")
        params.append(tool_name)
    if status:
        conditions.append("status = ?")
        params.append(status)
    if keyword:
        conditions.append("(reason LIKE ? OR params_json LIKE ?)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    limit = max(1, min(int(limit), 200))
    query = f"SELECT * FROM audit_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])
    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def get_audit_event(event_id: str) -> Dict[str, Any]:
    with get_db_connection() as conn:
        row = conn.execute(
            """
            SELECT e.*, b.stdout, b.stderr, b.diff
            FROM audit_events e
            LEFT JOIN audit_bodies b ON b.event_id = e.id
            WHERE e.id = ?;
            """,
            (event_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Audit event not found: {event_id}")
        return dict(row)
