"""
Implementation of the 14 Standard MCP Tools.
Deterministic, secure, and audited.
"""

import difflib
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from auth import authenticate_bearer_token, issue_agent_token, revoke_agent_token
from config import config
from db import append_audit_log, get_db_connection, query_audit_logs
from executor import execute_allowlisted_command
from llm_compiler import compile_overview_with_llm, get_current_overview
from lock_manager import acquire_lock, release_lock, renew_lock, verify_write_permission
from reconciler import reconcile_observed_state, scan_system_snapshot


def tool_acquire_lock(agent_id: str, resource_key: str, reason: str, ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
    lease_token, expires_at = acquire_lock(resource_key, agent_id, reason, ttl_seconds)
    append_audit_log(
        agent_id=agent_id,
        action_type="lock_acquire",
        target=resource_key,
        intent_reason=reason,
        lease_token=lease_token,
        status="SUCCESS",
        params={"ttl_seconds": ttl_seconds, "expires_at": expires_at},
    )
    return {"resource_key": resource_key, "lease_token": lease_token, "expires_at": expires_at, "status": "LOCKED"}


def tool_renew_lock(agent_id: str, resource_key: str, lease_token: int, ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
    new_expires_at = renew_lock(resource_key, lease_token, agent_id, ttl_seconds)
    append_audit_log(
        agent_id=agent_id,
        action_type="lock_renew",
        target=resource_key,
        intent_reason="heartbeat renewal",
        lease_token=lease_token,
        status="SUCCESS",
        params={"new_expires_at": new_expires_at},
    )
    return {"resource_key": resource_key, "lease_token": lease_token, "expires_at": new_expires_at, "status": "RENEWED"}


def tool_release_lock(agent_id: str, resource_key: str, lease_token: int) -> Dict[str, Any]:
    success = release_lock(resource_key, lease_token, agent_id)
    append_audit_log(
        agent_id=agent_id,
        action_type="lock_release",
        target=resource_key,
        intent_reason="release lock",
        lease_token=lease_token,
        status="SUCCESS" if success else "FAILED",
    )
    return {"resource_key": resource_key, "status": "RELEASED" if success else "NOT_FOUND"}


def tool_edit_file(
    agent_id: str,
    path: str,
    content: str,
    reason: str,
    lease_token: Optional[int] = None,
    is_temporary: bool = False,
    ttl_hours: Optional[int] = None,
) -> Dict[str, Any]:
    target_path = Path(path).resolve()
    # Check lock requirement dynamically
    verify_write_permission(str(target_path), agent_id, lease_token)

    # Auto-detect temporary file
    if "/tmp/" in str(target_path) or "/var/tmp/" in str(target_path) or target_path.name.startswith(("tmp.", "test_")):
        is_temporary = True

    # Calculate diff
    old_content = ""
    if target_path.exists():
        try:
            old_content = target_path.read_text(encoding="utf-8")
            # Create safety backup
            backup_path = target_path.with_suffix(f"{target_path.suffix}.bak")
            shutil.copy2(target_path, backup_path)
        except Exception:
            pass

    diff_lines = list(
        difflib.unified_diff(
            old_content.splitlines(),
            content.splitlines(),
            fromfile=f"a/{target_path.name}",
            tofile=f"b/{target_path.name}",
            lineterm="",
        )
    )
    diff_snapshot = "\n".join(diff_lines[:50])

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content, encoding="utf-8")

    append_audit_log(
        agent_id=agent_id,
        action_type="file_modify" if old_content else "file_create",
        target=str(target_path),
        intent_reason=reason,
        lease_token=lease_token,
        is_temporary=is_temporary,
        diff_snapshot=diff_snapshot,
        status="SUCCESS",
    )
    return {"path": str(target_path), "bytes_written": len(content.encode("utf-8")), "is_temporary": is_temporary}


def tool_delete_file(agent_id: str, path: str, reason: str, lease_token: Optional[int] = None) -> Dict[str, Any]:
    target_path = Path(path).resolve()
    verify_write_permission(str(target_path), agent_id, lease_token)

    if not target_path.exists():
        return {"path": str(target_path), "status": "NOT_FOUND"}

    if target_path.is_dir():
        shutil.rmtree(target_path)
    else:
        target_path.unlink()

    append_audit_log(
        agent_id=agent_id,
        action_type="file_delete",
        target=str(target_path),
        intent_reason=reason,
        lease_token=lease_token,
        status="SUCCESS",
    )
    return {"path": str(target_path), "status": "DELETED"}


def tool_cleanup_temp(agent_id: str, older_than_hours: int = 24) -> Dict[str, Any]:
    now = time.time()
    cutoff_time = now - (older_than_hours * 3600)
    cleaned_paths = []

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT target, timestamp FROM gateway_audit_logs
            WHERE is_temporary = 1 AND action_type IN ('file_create', 'file_modify')
            ORDER BY timestamp DESC;
            """
        )
        candidates = cursor.fetchall()

    for row in candidates:
        p = Path(row["target"])
        if p.exists() and p.stat().st_mtime < cutoff_time:
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                cleaned_paths.append(str(p))
            except Exception:
                pass

    append_audit_log(
        agent_id=agent_id,
        action_type="temp_cleanup",
        target="batch",
        intent_reason=f"Cleanup temp files older than {older_than_hours}h",
        status="SUCCESS",
        output_summary=f"Cleaned {len(cleaned_paths)} files",
    )
    return {"cleaned_count": len(cleaned_paths), "cleaned_paths": cleaned_paths}


def tool_manage_service(
    agent_id: str,
    service_type: str,
    name: str,
    action: str,
    reason: str,
    lease_token: Optional[int] = None,
) -> Dict[str, Any]:
    asset_key = f"{service_type}:{name}"
    verify_write_permission(asset_key, agent_id, lease_token)

    cmd = []
    if service_type == "docker":
        cmd = ["docker", action, name]
    elif service_type == "systemd":
        cmd = ["systemctl", action, name if name.endswith(".service") else f"{name}.service"]
    else:
        raise ValueError(f"Unknown service_type: {service_type}")

    start_time = time.time()
    exit_code, stdout, stderr = -1, "", ""
    try:
        import subprocess
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        exit_code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    finally:
        duration_ms = int((time.time() - start_time) * 1000)
        # Unconditional post-exec reconcile
        reconcile_observed_state()

    status = "SUCCESS" if exit_code == 0 else "FAILED"
    append_audit_log(
        agent_id=agent_id,
        action_type=f"{service_type}_{action}",
        target=asset_key,
        intent_reason=reason,
        lease_token=lease_token,
        status=status,
        duration_ms=duration_ms,
        output_summary=stdout[:300] if exit_code == 0 else stderr[:300],
    )
    return {"service": asset_key, "action": action, "exit_code": exit_code, "status": status, "output": stdout or stderr}


def tool_execute_command(agent_id: str, command: str, reason: str, timeout_seconds: int = 30) -> Dict[str, Any]:
    start_time = time.time()
    exit_code, stdout, stderr = -1, "", ""
    try:
        exit_code, stdout, stderr = execute_allowlisted_command(command, timeout_seconds)
    finally:
        duration_ms = int((time.time() - start_time) * 1000)
        # Unconditional drift reconcile regardless of exit code!
        reconcile_observed_state()

    status = "SUCCESS" if exit_code == 0 else "FAILED"
    append_audit_log(
        agent_id=agent_id,
        action_type="shell_exec",
        target=command.split()[0] if command else "shell",
        intent_reason=reason,
        params={"command": command},
        status=status,
        duration_ms=duration_ms,
        output_summary=(stdout if exit_code == 0 else stderr)[:400],
    )
    return {"command": command, "exit_code": exit_code, "stdout": stdout, "stderr": stderr}


def tool_register_asset(
    agent_id: str,
    key: str,
    category: str,
    name: str,
    description: str,
    endpoints: Optional[List[str]] = None,
    configs: Optional[List[str]] = None,
    lock_required: bool = False,
) -> Dict[str, Any]:
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO gateway_assets (
                key, category, name, description, endpoints_json, config_paths_json,
                desired_state, observed_state, drift_status, lock_required,
                last_discovered_at, last_modified_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'UNKNOWN', 'IN_SYNC', ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                category = excluded.category,
                name = excluded.name,
                description = excluded.description,
                endpoints_json = excluded.endpoints_json,
                config_paths_json = excluded.config_paths_json,
                lock_required = excluded.lock_required,
                last_modified_by = excluded.last_modified_by,
                updated_at = excluded.updated_at;
            """,
            (
                key,
                category,
                name,
                description,
                json.dumps(endpoints or [], ensure_ascii=False),
                json.dumps(configs or [], ensure_ascii=False),
                1 if lock_required else 0,
                now_iso,
                agent_id,
                now_iso,
            ),
        )
        conn.commit()

    append_audit_log(
        agent_id=agent_id,
        action_type="asset_register",
        target=key,
        intent_reason=f"Registered asset {name} (lock_required={lock_required})",
        status="SUCCESS",
    )
    return {"key": key, "status": "REGISTERED", "lock_required": lock_required}


def tool_get_overview() -> str:
    return get_current_overview()


def tool_rebuild_overview(reason: str = "agent requested rebuild") -> str:
    return compile_overview_with_llm(reason)


def tool_query_assets(category: Optional[str] = None, query: Optional[str] = None, show_drift_only: bool = False) -> List[Dict[str, Any]]:
    conditions = []
    params = []
    if category:
        conditions.append("category = ?")
        params.append(category)
    if show_drift_only:
        conditions.append("drift_status = 'DRIFTED'")
    if query:
        conditions.append("(name LIKE ? OR description LIKE ? OR key LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM gateway_assets {where} ORDER BY category, name;", params)
        return [dict(r) for r in cursor.fetchall()]


def tool_get_status() -> Dict[str, Any]:
    snapshot = scan_system_snapshot()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT category, count(*) as count FROM gateway_assets GROUP BY category;")
        cat_counts = {r["category"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT count(*) as drift_count FROM gateway_assets WHERE drift_status = 'DRIFTED';")
        drift_count = cursor.fetchone()["drift_count"]

    snapshot["asset_counts"] = cat_counts
    snapshot["drifted_assets_count"] = drift_count
    return snapshot


def tool_query_audit_logs(**kwargs) -> List[Dict[str, Any]]:
    return query_audit_logs(**kwargs)


def tool_issue_agent_token(caller_agent_id: str, caller_role: str, agent_id: str) -> Dict[str, Any]:
    # 权限规则：只有配置的唯一 root admin Agent 拥有在线签发权
    if caller_agent_id != config.root_admin_agent_id or caller_role != "admin":
        raise PermissionError(f"403 Forbidden: Only designated root admin '{config.root_admin_agent_id}' has authority to issue tokens. Caller is [{caller_agent_id}].")

    if agent_id == config.root_admin_agent_id:
        raise ValueError(f"400 Bad Request: Cannot re-issue token for primary admin '{config.root_admin_agent_id}'.")

    # 所有在线签发的外部 Agent 一律强制为受控的 operator 角色，绝不允许拥有 admin 权限
    assigned_role = "operator"
    new_token = issue_agent_token(agent_id, assigned_role)
    append_audit_log(
        agent_id=caller_agent_id,
        action_type="token_issue",
        target=f"agent:{agent_id}",
        intent_reason=f"Issued operator token for agent {agent_id}",
        status="SUCCESS",
        params={"target_agent_id": agent_id, "role": assigned_role},
    )
    return {
        "agent_id": agent_id,
        "role": assigned_role,
        "token": new_token,
        "status": "ISSUED",
        "note": "Please securely provide this bearer token to the target agent. It cannot be retrieved again in plaintext."
    }


def tool_revoke_agent_token(caller_agent_id: str, caller_role: str, agent_id: str) -> Dict[str, Any]:
    # 权限规则：只有配置的唯一 root admin Agent 拥有在线吊销权
    if caller_agent_id != config.root_admin_agent_id or caller_role != "admin":
        raise PermissionError(f"403 Forbidden: Only designated root admin '{config.root_admin_agent_id}' has authority to revoke tokens. Caller is [{caller_agent_id}].")

    if agent_id == config.root_admin_agent_id:
        raise ValueError(f"400 Bad Request: Cannot revoke primary root admin '{config.root_admin_agent_id}'.")

    success = revoke_agent_token(agent_id)
    append_audit_log(
        agent_id=caller_agent_id,
        action_type="token_revoke",
        target=f"agent:{agent_id}",
        intent_reason=f"Revoked token for agent {agent_id}",
        status="SUCCESS" if success else "NOT_FOUND",
    )
    return {
        "agent_id": agent_id,
        "status": "REVOKED" if success else "NOT_FOUND"
    }
