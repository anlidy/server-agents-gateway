"""
Authentication module for server-agents-gateway.
Implements Zero-Trust Per-Agent Bearer Token lookup and issuance.
"""

import hashlib
import re
import secrets
import time
from typing import Optional, Tuple
from .db import get_db_connection

# `name` or `prefix:name[:...]`. These ids end up inside the bearer token and inside recipient
# expressions (`*`, `prefix:*`, `@group`, comma lists), so anything beyond this set breaks
# routing and, worse, the audit redaction that has to recognise the token.
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}(:[A-Za-z0-9_.\-]{1,64}){0,3}$")


def validate_agent_id(agent_id: str) -> str:
    if not isinstance(agent_id, str) or not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            "invalid agent_id: use letters, digits, '_', '.', '-', with ':' between parts "
            "(for example laptop:claude); no spaces, '*', ',' or leading '@'"
        )
    return agent_id


def hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def authenticate_bearer_token(bearer_token: str) -> Optional[Tuple[str, str]]:
    """
    Validates a Bearer Token against the database.
    Returns (agent_id, role) if valid and ACTIVE, else None.
    """
    if not bearer_token:
        return None
    token_clean = bearer_token.replace("Bearer ", "").strip()
    token_h = hash_token(token_clean)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT agent_id, role, status FROM agent_credentials
            WHERE token_hash = ?;
            """,
            (token_h,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        if row["status"] != "ACTIVE":
            return None

        # Update last_used_at
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        conn.execute(
            "UPDATE agent_credentials SET last_used_at = ? WHERE token_hash = ?;",
            (now_iso, token_h),
        )
        conn.commit()
        return (row["agent_id"], row["role"])


def issue_agent_token(agent_id: str, role: str = "admin") -> str:
    """
    Generates a secure random 32-byte hex token for a specific Agent and persists it.
    Prefix: ag_<agent_suffix>_<token>
    """
    validate_agent_id(agent_id)
    raw_token = f"sag_{agent_id.replace(':', '_')}_{secrets.token_hex(24)}"
    token_h = hash_token(raw_token)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO agent_credentials (token_hash, agent_id, role, status, created_at)
            VALUES (?, ?, ?, 'ACTIVE', ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                token_hash = excluded.token_hash,
                role = excluded.role,
                status = 'ACTIVE',
                created_at = excluded.created_at;
            """,
            (token_h, agent_id, role, now_iso),
        )
        conn.commit()
    return raw_token


def revoke_agent_token(agent_id: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.execute(
            "UPDATE agent_credentials SET status = 'REVOKED' WHERE agent_id = ?;",
            (agent_id,),
        )
        conn.commit()
        return cursor.rowcount > 0