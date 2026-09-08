"""
Concurrency & Lease Manager for server-agents-gateway.
Implements strictly increasing Fencing Tokens and dynamic DB-driven lock checks.
"""

import time
from typing import Optional, Tuple
from config import config
from db import get_db_connection, get_next_lease_token


class LockAcquisitionError(Exception):
    pass


class LockVerificationError(Exception):
    pass


def acquire_lock(resource_key: str, agent_id: str, reason: str, ttl_seconds: Optional[int] = None) -> Tuple[int, int]:
    """
    Acquires an exclusive lock on a resource_key.
    Returns (lease_token, expires_at_epoch).
    Raises LockAcquisitionError if currently held by another agent and not expired.
    """
    now = int(time.time())
    ttl = ttl_seconds or config.default_lease_ttl_seconds
    expires_at = now + ttl
    lease_token = get_next_lease_token()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_leases WHERE resource_key = ?;", (resource_key,))
        existing = cursor.fetchone()

        if existing:
            # Check if expired or held by same agent
            if existing["expires_at"] > now and existing["locked_by"] != agent_id:
                raise LockAcquisitionError(
                    f"Resource [{resource_key}] is currently locked by [{existing['locked_by']}] "
                    f"until epoch {existing['expires_at']}. Reason: {existing['reason']}"
                )

        cursor.execute(
            """
            INSERT INTO active_leases (resource_key, lease_token, locked_by, reason, acquired_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource_key) DO UPDATE SET
                lease_token = excluded.lease_token,
                locked_by = excluded.locked_by,
                reason = excluded.reason,
                acquired_at = excluded.acquired_at,
                expires_at = excluded.expires_at;
            """,
            (resource_key, lease_token, agent_id, reason, now_iso, expires_at),
        )
        conn.commit()
        return (lease_token, expires_at)


def renew_lock(resource_key: str, lease_token: int, agent_id: str, ttl_seconds: Optional[int] = None) -> int:
    """
    Heartbeat renewal for long-running operations.
    Returns new expires_at_epoch.
    """
    now = int(time.time())
    ttl = ttl_seconds or config.default_lease_ttl_seconds
    new_expires_at = now + ttl

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE active_leases
            SET expires_at = ?
            WHERE resource_key = ? AND lease_token = ? AND locked_by = ? AND expires_at > ?;
            """,
            (new_expires_at, resource_key, lease_token, agent_id, now),
        )
        if cursor.rowcount == 0:
            raise LockVerificationError(f"Cannot renew: lock for [{resource_key}] expired, stolen, or token mismatch.")
        conn.commit()
        return new_expires_at


def release_lock(resource_key: str, lease_token: int, agent_id: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM active_leases WHERE resource_key = ? AND lease_token = ? AND locked_by = ?;",
            (resource_key, lease_token, agent_id),
        )
        conn.commit()
        return cursor.rowcount > 0


def verify_write_permission(target_path_or_key: str, agent_id: str, lease_token: Optional[int] = None) -> None:
    """
    Core Deterministic Check:
    Queries gateway_assets dynamically. If the asset requires a lock (lock_required == 1),
    demands a valid, matching, unexpired lease_token.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Find matching asset either by key directly or by config path inclusion
        cursor.execute(
            """
            SELECT key, lock_required FROM gateway_assets
            WHERE key = ? OR config_paths_json LIKE ?;
            """,
            (target_path_or_key, f'%"{target_path_or_key}"%'),
        )
        matched_asset = cursor.fetchone()

        if matched_asset and matched_asset["lock_required"] == 1:
            asset_key = matched_asset["key"]
            if not lease_token:
                raise LockVerificationError(
                    f"423 Locked: Resource [{asset_key}] is a protected asset with lock_required=1. "
                    f"You must acquire a lock and supply lease_token."
                )

            now = int(time.time())
            cursor.execute("SELECT * FROM active_leases WHERE resource_key = ?;", (asset_key,))
            lease = cursor.fetchone()

            if not lease:
                raise LockVerificationError(f"409 Conflict: No active lease found for [{asset_key}].")
            if lease["lease_token"] != lease_token:
                raise LockVerificationError(f"409 Conflict: Lease token mismatch for [{asset_key}].")
            if lease["locked_by"] != agent_id:
                raise LockVerificationError(f"403 Forbidden: Lock held by [{lease['locked_by']}], not [{agent_id}].")
            if lease["expires_at"] <= now:
                raise LockVerificationError(f"409 Conflict: Lease expired at epoch {lease['expires_at']}.")
