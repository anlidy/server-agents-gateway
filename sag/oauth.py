"""
最小的 OAuth 2.1 授权服务，给 claude.ai 自定义连接器（网页 / 桌面 / 手机 App）这类只支持 OAuth 的 MCP 客户端用。

- 只有设置了 GATEWAY_PUBLIC_URL 才启用。
- 客户端靠动态注册（RFC 7591）拿 client_id，都是公开客户端，必须用 PKCE S256；
  回调地址受 GATEWAY_OAUTH_REDIRECT_URIS 限制。
- 授权页不做账号登录：root 在服务器上跑 `python3 -m sag oauth-pair <agent_id>` 生成一次性配对码，
  在授权页上输入。配对码决定这次授权挂在哪个 agent 上，之后的令牌就以这个 agent 的身份访问，
  审计、回收站、未读提示都和静态 token 一样。
- 访问令牌 sago_…（默认 1 小时），刷新令牌 sagr_…（默认 30 天，每次刷新都换新的）。
- 吊销 agent（hub_revoke_agent_token）或 `oauth-revoke <agent_id>`，它名下的 OAuth 令牌立即失效。
- 不能给 root admin 配对：OAuth 接入的 agent 一律是 operator。
"""

import base64
import hashlib
import json
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .auth import hash_token, issue_agent_token
from .config import config
from .db import get_db_connection

ACCESS_PREFIX = "sago_"
REFRESH_PREFIX = "sagr_"
CODE_TTL_SECONDS = 5 * 60
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 去掉了容易看混的 I L O 0 1
LOOPBACK = "loopback"


class OAuthError(Exception):
    """RFC 6749 形式的错误：error 是标准错误码。"""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def enabled() -> bool:
    return bool(config.public_url)


def _now() -> int:
    return int(time.time())


def _iso(ts: Optional[int]) -> Optional[str]:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else None


# --- 回调地址 -------------------------------------------------------------------

def canonical_url(url: str) -> str:
    """RFC 8707 resource 的规范形式：scheme 和 host 小写，去掉默认端口、结尾斜杠。"""
    parts = urlsplit(url.strip())
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    port = parts.port
    netloc = host if port is None or (scheme, port) in (("https", 443), ("http", 80)) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}" + (f"?{parts.query}" if parts.query else "")


def is_loopback(uri: str) -> bool:
    parts = urlsplit(uri)
    return parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1") and not parts.fragment


def redirect_allowed(uri: str) -> bool:
    for allowed in config.oauth_redirect_uris:
        if allowed == LOOPBACK and is_loopback(uri):
            return True
        if uri == allowed:
            return True
    return False


def redirect_registered(client: sqlite3.Row, uri: str) -> bool:
    """回调地址必须是注册过的。回环地址按 RFC 8252 忽略端口比较（Claude Code 每次用的端口不同）。"""
    for registered in json.loads(client["redirect_uris"]):
        if uri == registered:
            return True
        if is_loopback(uri) and is_loopback(registered):
            a, b = urlsplit(uri), urlsplit(registered)
            if (a.hostname, a.path, a.query) == (b.hostname, b.path, b.query):
                return True
    return False


# --- 动态注册 -------------------------------------------------------------------

def register_client(body: Dict[str, Any]) -> Dict[str, Any]:
    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) and len(u) <= 512 for u in uris):
        raise OAuthError("invalid_redirect_uri", "redirect_uris must be a non-empty list of URLs")
    if len(uris) > 10:
        raise OAuthError("invalid_redirect_uri", "too many redirect_uris")
    for u in uris:
        if not redirect_allowed(u):
            raise OAuthError("invalid_redirect_uri", f"redirect_uri not allowed: {u}")
    if body.get("token_endpoint_auth_method", "none") != "none":
        raise OAuthError("invalid_client_metadata",
                         "only public clients (token_endpoint_auth_method=none) are supported")
    name = str(body.get("client_name") or "")[:128] or None
    cid = "oac_" + uuid.uuid4().hex
    now = _now()
    with get_db_connection() as conn:
        conn.execute("INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?, ?, ?, ?);",
                     (cid, name, json.dumps(uris), now))
    return {
        "client_id": cid,
        "client_id_issued_at": now,
        "client_name": name,
        "redirect_uris": uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }


def _get_client(conn: sqlite3.Connection, client_id: Optional[str]) -> Optional[sqlite3.Row]:
    if not client_id:
        return None
    return conn.execute("SELECT * FROM oauth_clients WHERE id = ?;", (client_id,)).fetchone()


# --- 配对码 ---------------------------------------------------------------------

def _normalize_pairing(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def create_pairing(agent_id: str, ttl_minutes: Optional[int] = None) -> Tuple[str, int]:
    """返回 (配对码, 过期时间戳)。agent 不存在就以 operator 建一个（静态 token 随即丢弃，只能走 OAuth）。"""
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required")
    if agent_id == config.root_admin_agent_id:
        raise ValueError(f"不能给 root admin（{agent_id}）配对 OAuth")
    with get_db_connection() as conn:
        row = conn.execute("SELECT role, status FROM agent_credentials WHERE agent_id = ?;", (agent_id,)).fetchone()
    if row is None:
        issue_agent_token(agent_id, role="operator")
    elif row["role"] == "admin":
        raise ValueError(f"{agent_id} 是 admin，不能配对 OAuth")
    elif row["status"] != "ACTIVE":
        raise ValueError(f"{agent_id} 已被吊销；先重新签发（issue-token）再配对")

    raw = "".join(secrets.choice(PAIR_ALPHABET) for _ in range(12))
    now = _now()
    expires = now + (ttl_minutes or config.oauth_pairing_ttl_minutes) * 60
    with get_db_connection() as conn:
        _cleanup(conn, now)
        conn.execute(
            "INSERT INTO oauth_pairings (code_hash, agent_id, expires_at, created_at) VALUES (?, ?, ?, ?);",
            (hash_token(raw), agent_id, expires, now),
        )
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}", expires


def _cleanup(conn: sqlite3.Connection, now: int) -> None:
    """清掉早已过期的配对码、授权码和令牌（留一天方便排查）。"""
    cutoff = now - 86400
    conn.execute("DELETE FROM oauth_pairings WHERE expires_at < ?;", (cutoff,))
    conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?;", (cutoff,))
    conn.execute("DELETE FROM oauth_tokens WHERE expires_at < ?;", (cutoff,))


# --- 授权 -----------------------------------------------------------------------

@dataclass
class AuthRequest:
    client: sqlite3.Row
    redirect_uri: str
    state: Optional[str]
    code_challenge: str
    scope: Optional[str]


def check_client_and_redirect(client_id: Optional[str], redirect_uri: Optional[str]) -> Tuple[sqlite3.Row, str]:
    """这两项不对时不能重定向回去（可能是伪造的回调地址），只能在授权页上报错。"""
    with get_db_connection() as conn:
        client = _get_client(conn, client_id)
    if client is None:
        raise OAuthError("invalid_client", "unknown client_id")
    if not redirect_uri or not redirect_registered(client, redirect_uri):
        raise OAuthError("invalid_request", "redirect_uri is not registered for this client")
    return client, redirect_uri


def parse_auth_request(params: Dict[str, str]) -> AuthRequest:
    """先调 check_client_and_redirect；这里抛出的错误可以重定向回客户端。"""
    client, redirect_uri = check_client_and_redirect(params.get("client_id"), params.get("redirect_uri"))
    if params.get("response_type") != "code":
        raise OAuthError("unsupported_response_type", "response_type must be code")
    challenge = params.get("code_challenge") or ""
    if params.get("code_challenge_method") != "S256" or not 43 <= len(challenge) <= 128:
        raise OAuthError("invalid_request", "PKCE with code_challenge_method=S256 is required")
    resource = params.get("resource")
    if resource and canonical_url(resource) != canonical_url(mcp_url()):
        raise OAuthError("invalid_target", "resource does not match this server")
    return AuthRequest(client=client, redirect_uri=redirect_uri, state=params.get("state"),
                       code_challenge=challenge, scope=params.get("scope"))


def approve(req: AuthRequest, pairing_code: str) -> Tuple[str, str]:
    """配对码对了就发授权码（配对码随即作废），返回 (授权码, agent_id)。"""
    code_hash = hash_token(_normalize_pairing(pairing_code))
    now = _now()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT p.agent_id, c.status, c.role FROM oauth_pairings p"
            " JOIN agent_credentials c ON c.agent_id = p.agent_id"
            " WHERE p.code_hash = ? AND p.used_at IS NULL AND p.expires_at > ?;",
            (code_hash, now),
        ).fetchone()
        if row is None or row["status"] != "ACTIVE" or row["role"] == "admin":
            raise OAuthError("access_denied", "配对码不对，或者已经用过、过期了")
        conn.execute("UPDATE oauth_pairings SET used_at = ? WHERE code_hash = ?;", (now, code_hash))
        code = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO oauth_codes (code_hash, oauth_client_id, agent_id, redirect_uri, code_challenge, scope,"
            " expires_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
            (hash_token(code), req.client["id"], row["agent_id"], req.redirect_uri, req.code_challenge,
             req.scope, now + CODE_TTL_SECONDS),
        )
    return code, row["agent_id"]


# --- 令牌 -----------------------------------------------------------------------

def _s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()


def _issue(conn: sqlite3.Connection, *, grant_id: str, oauth_client_id: str, agent_id: str,
           scope: Optional[str]) -> Dict[str, Any]:
    now = _now()
    access_ttl = config.oauth_access_ttl_minutes * 60
    refresh_ttl = config.oauth_refresh_ttl_days * 86400
    access = ACCESS_PREFIX + secrets.token_urlsafe(32)
    refresh = REFRESH_PREFIX + secrets.token_urlsafe(32)
    for token, kind, ttl in ((access, "access", access_ttl), (refresh, "refresh", refresh_ttl)):
        conn.execute(
            "INSERT INTO oauth_tokens (token_hash, kind, grant_id, oauth_client_id, agent_id, scope, expires_at,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            (hash_token(token), kind, grant_id, oauth_client_id, agent_id, scope, now + ttl, now),
        )
    conn.execute("UPDATE oauth_clients SET last_used_at = ? WHERE id = ?;", (now, oauth_client_id))
    out = {"access_token": access, "token_type": "Bearer", "expires_in": access_ttl, "refresh_token": refresh}
    if scope:
        out["scope"] = scope
    return out


def exchange(form: Dict[str, str]) -> Dict[str, Any]:
    resource = form.get("resource")
    if resource and canonical_url(resource) != canonical_url(mcp_url()):
        raise OAuthError("invalid_target", "resource does not match this server")
    grant = form.get("grant_type")
    if grant == "authorization_code":
        return _exchange_code(form)
    if grant == "refresh_token":
        return _refresh(form)
    raise OAuthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token")


def _exchange_code(form: Dict[str, str]) -> Dict[str, Any]:
    code, verifier = form.get("code") or "", form.get("code_verifier") or ""
    now = _now()
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM oauth_codes WHERE code_hash = ?;", (hash_token(code),)).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= now:
            raise OAuthError("invalid_grant", "authorization code is invalid, used or expired")
        if form.get("client_id") and form["client_id"] != row["oauth_client_id"]:
            raise OAuthError("invalid_grant", "code was issued to another client")
        if form.get("redirect_uri") != row["redirect_uri"]:
            raise OAuthError("invalid_grant", "redirect_uri does not match the authorization request")
        if not verifier or _s256(verifier) != row["code_challenge"]:
            raise OAuthError("invalid_grant", "PKCE verification failed")
        conn.execute("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?;", (now, row["code_hash"]))
        return _issue(conn, grant_id="grt_" + uuid.uuid4().hex, oauth_client_id=row["oauth_client_id"],
                      agent_id=row["agent_id"], scope=row["scope"])


def _refresh(form: Dict[str, str]) -> Dict[str, Any]:
    token = form.get("refresh_token") or ""
    now = _now()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT t.*, c.status FROM oauth_tokens t JOIN agent_credentials c ON c.agent_id = t.agent_id"
            " WHERE t.token_hash = ? AND t.kind = 'refresh';",
            (hash_token(token),),
        ).fetchone()
        if row is None or row["revoked_at"] is not None or row["expires_at"] <= now or row["status"] != "ACTIVE":
            raise OAuthError("invalid_grant", "refresh token is invalid, revoked or expired")
        if form.get("client_id") and form["client_id"] != row["oauth_client_id"]:
            raise OAuthError("invalid_grant", "refresh token was issued to another client")
        # 轮换：旧的刷新令牌作废；同一授权下还没过期的访问令牌照常可用到过期
        conn.execute("UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ?;", (now, row["token_hash"]))
        return _issue(conn, grant_id=row["grant_id"], oauth_client_id=row["oauth_client_id"],
                      agent_id=row["agent_id"], scope=row["scope"])


def authenticate_access_token(token: str) -> Optional[Tuple[str, str]]:
    """OAuth 访问令牌 → (agent_id, role)。agent 被吊销时令牌一并失效。"""
    now = _now()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT t.agent_id, c.role, c.status FROM oauth_tokens t"
            " JOIN agent_credentials c ON c.agent_id = t.agent_id"
            " WHERE t.token_hash = ? AND t.kind = 'access' AND t.revoked_at IS NULL AND t.expires_at > ?;",
            (hash_token(token), now),
        ).fetchone()
        if row is None or row["status"] != "ACTIVE" or row["role"] == "admin":
            return None
        conn.execute("UPDATE agent_credentials SET last_used_at = ? WHERE agent_id = ?;",
                     (_iso(now), row["agent_id"]))
        return row["agent_id"], row["role"]


def revoke_token(token: str) -> None:
    """RFC 7009：吊销一个令牌就吊销整个授权。不存在的令牌也当成功。"""
    with get_db_connection() as conn:
        row = conn.execute("SELECT grant_id FROM oauth_tokens WHERE token_hash = ?;", (hash_token(token),)).fetchone()
        if row is not None:
            conn.execute("UPDATE oauth_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE grant_id = ?;",
                         (_now(), row["grant_id"]))


def revoke_agent_grants(agent_id: str) -> int:
    """吊销某个 agent 名下所有 OAuth 令牌和未用的配对码，返回吊销的授权数。"""
    now = _now()
    with get_db_connection() as conn:
        n = conn.execute(
            "SELECT COUNT(DISTINCT grant_id) AS n FROM oauth_tokens WHERE agent_id = ? AND revoked_at IS NULL;",
            (agent_id,),
        ).fetchone()["n"]
        conn.execute("UPDATE oauth_tokens SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL;",
                     (now, agent_id))
        conn.execute("UPDATE oauth_pairings SET used_at = ? WHERE agent_id = ? AND used_at IS NULL;",
                     (now, agent_id))
    return n


def list_grants() -> List[Dict[str, Any]]:
    """每个还有效的授权一行（按刷新令牌算），不含令牌。"""
    now = _now()
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT t.grant_id, t.agent_id, c.name AS client_name, MIN(t.created_at) AS created_at,"
            " MAX(t.expires_at) AS expires_at, c.last_used_at"
            " FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.id = t.oauth_client_id"
            " WHERE t.kind = 'refresh' AND t.revoked_at IS NULL AND t.expires_at > ?"
            " GROUP BY t.grant_id ORDER BY t.agent_id, created_at;",
            (now,),
        ).fetchall()
    return [
        {
            "grant_id": r["grant_id"],
            "agent_id": r["agent_id"],
            "client_name": r["client_name"],
            "refreshed_at": _iso(r["created_at"]),
            "expires_at": _iso(r["expires_at"]),
            "client_last_used_at": _iso(r["last_used_at"]),
        }
        for r in rows
    ]


# --- 元数据 ---------------------------------------------------------------------

def public_base() -> str:
    return config.public_url.rstrip("/")


def mcp_url() -> str:
    return f"{public_base()}/mcp"


def resource_metadata_url() -> str:
    return f"{public_base()}/.well-known/oauth-protected-resource/mcp"


def resource_metadata() -> Dict[str, Any]:
    """RFC 9728 受保护资源元数据。"""
    base = public_base()
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["sag"],
        "bearer_methods_supported": ["header"],
        "resource_name": "server-agents-gateway",
    }


def server_metadata() -> Dict[str, Any]:
    """RFC 8414 授权服务元数据。"""
    base = public_base()
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "registration_endpoint": f"{base}/oauth/register",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["sag", "offline_access"],
    }
