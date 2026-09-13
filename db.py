"""
Database layer for server-agents-gateway using SQLite.
Implements credentials, dual-state assets (CMDB), fencing leases, and multi-dimensional audit logs.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from config import config
from audit_redact import redact_secrets, redact_structure


def get_db_connection() -> sqlite3.Connection:
    db_file = Path(config.db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    with get_db_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS agent_credentials (
            token_hash TEXT PRIMARY KEY,
            agent_id TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL,
            last_used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS gateway_assets (
            key TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            endpoints_json TEXT,
            config_paths_json TEXT,
            desired_state TEXT NOT NULL,
            observed_state TEXT NOT NULL,
            drift_status TEXT NOT NULL,
            lock_required INTEGER DEFAULT 0,
            last_discovered_at TEXT NOT NULL,
            last_modified_by TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_assets_lock ON gateway_assets(lock_required);
        CREATE INDEX IF NOT EXISTS idx_assets_category ON gateway_assets(category);

        CREATE TABLE IF NOT EXISTS active_leases (
            resource_key TEXT PRIMARY KEY,
            lease_token INTEGER NOT NULL,
            locked_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lease_token_seq (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_token INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO lease_token_seq (id, next_token) VALUES (1, 1000);

        CREATE TABLE IF NOT EXISTS gateway_audit_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            intent_reason TEXT NOT NULL,
            lease_token INTEGER,
            is_temporary INTEGER DEFAULT 0,
            params_json TEXT,
            status TEXT NOT NULL,
            duration_ms INTEGER,
            diff_snapshot TEXT,
            output_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_audit_time ON gateway_audit_logs(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_agent_time ON gateway_audit_logs(agent_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_target ON gateway_audit_logs(target);
        CREATE INDEX IF NOT EXISTS idx_audit_action_status ON gateway_audit_logs(action_type, status);
        CREATE INDEX IF NOT EXISTS idx_audit_temp ON gateway_audit_logs(is_temporary, timestamp DESC);
        """)


def get_next_lease_token() -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT next_token FROM lease_token_seq WHERE id = 1;")
        current = cursor.fetchone()["next_token"]
        next_val = current + 1
        cursor.execute("UPDATE lease_token_seq SET next_token = ? WHERE id = 1;", (next_val,))
        conn.commit()
        return current


def append_audit_log(
    agent_id: str,
    action_type: str,
    target: str,
    intent_reason: str,
    status: str,
    lease_token: Optional[int] = None,
    is_temporary: bool = False,
    params: Optional[Dict[str, Any]] = None,
    duration_ms: Optional[int] = None,
    diff_snapshot: Optional[str] = None,
    output_summary: Optional[str] = None,
) -> str:
    log_id = str(uuid.uuid4())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    # Redact secrets before persistence so operators querying audits cannot read tokens
    safe_target = redact_secrets(target)
    safe_reason = redact_secrets(intent_reason)
    safe_params = redact_structure(params or {})
    safe_diff = redact_secrets(diff_snapshot) if diff_snapshot else None
    safe_output = redact_secrets(output_summary) if output_summary else None
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO gateway_audit_logs (
                id, timestamp, agent_id, action_type, target, intent_reason,
                lease_token, is_temporary, params_json, status, duration_ms,
                diff_snapshot, output_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                log_id,
                now_iso,
                agent_id,
                action_type,
                safe_target,
                safe_reason,
                lease_token,
                1 if is_temporary else 0,
                json.dumps(safe_params, ensure_ascii=False),
                status,
                duration_ms,
                safe_diff,
                safe_output,
            ),
        )
        conn.commit()
    return log_id


def query_audit_logs(
    since: Optional[str] = None,
    until: Optional[str] = None,
    agent_id: Optional[str] = None,
    target: Optional[str] = None,
    action_type: Optional[str] = None,
    status: Optional[str] = None,
    is_temporary: Optional[bool] = None,
    keyword: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    conditions = []
    params = []

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
    if status:
        conditions.append("status = ?")
        params.append(status)
    if is_temporary is not None:
        conditions.append("is_temporary = ?")
        params.append(1 if is_temporary else 0)
    if keyword:
        conditions.append("(intent_reason LIKE ? OR output_summary LIKE ?)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"SELECT * FROM gateway_audit_logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
    params.extend([limit, offset])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
