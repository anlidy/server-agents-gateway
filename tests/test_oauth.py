"""
OAuth（claude.ai 连接器）端到端：起一个真的网关，走 注册 → 授权页 → 配对码 → 换令牌 → MCP → 刷新 → 吊销。
"""

import asyncio
import base64
import hashlib
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="sagoauth_"))
(_TEST_ROOT / "cwd").mkdir()
os.environ.setdefault("GATEWAY_DB_PATH", str(_TEST_ROOT / "gateway.db"))
os.environ.setdefault("GATEWAY_OVERVIEW_PATH", str(_TEST_ROOT / "SERVER_AGENTS.md"))
os.environ.setdefault("GATEWAY_SHELL_CWD", str(_TEST_ROOT / "cwd"))

from sag import oauth, server  # noqa: E402
from sag.auth import issue_agent_token, revoke_agent_token  # noqa: E402
from sag.config import config  # noqa: E402
from sag.db import get_db_connection, init_db  # noqa: E402

PUBLIC = "https://sag.example.com"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _set(**kw):
    """config 是 frozen dataclass；测试里临时改字段。"""
    old = {k: getattr(config, k) for k in kw}
    for k, v in kw.items():
        object.__setattr__(config, k, v)
    return old


def _wipe_db():
    for suffix in ("", "-wal", "-shm"):
        p = Path(config.db_path + suffix)
        if p.exists():
            p.unlink()


class _Server:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        started = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            self.srv = self.loop.run_until_complete(asyncio.start_server(server.handle_client, "127.0.0.1", 0))
            self.port = self.srv.sockets[0].getsockname()[1]
            started.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        started.wait(5)

    def stop(self):
        self.loop.call_soon_threadsafe(self.srv.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def _pkce():
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class TestOAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        shutil.rmtree(_TEST_ROOT, ignore_errors=True)

    def setUp(self):
        self._old = _set(public_url=PUBLIC, oauth_only_hosts=("sag.example.com",),
                         oauth_redirect_uris=(CALLBACK, "loopback"), root_admin_agent_id="admin:root")
        _wipe_db()
        init_db()
        issue_agent_token("admin:root", role="admin")

    def tearDown(self):
        _set(**self._old)

    # --- helpers ---------------------------------------------------------------

    def req(self, method, path, body=None, headers=None, host="sag.example.com"):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
        h = {"Host": host, **(headers or {})}
        if isinstance(body, dict):
            body = json.dumps(body)
            h.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data

    def form(self, path, fields, **kw):
        return self.req("POST", path, urlencode(fields),
                        {"Content-Type": "application/x-www-form-urlencoded"}, **kw)

    def register(self, uris=(CALLBACK,)):
        st, _, data = self.req("POST", "/oauth/register", {"client_name": "Claude", "redirect_uris": list(uris)})
        self.assertEqual(st, 201, data)
        return json.loads(data)["client_id"]

    def authorize(self, client_id, pairing, challenge, redirect=CALLBACK, decision="approve"):
        fields = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                  "code_challenge": challenge, "code_challenge_method": "S256", "state": "st8",
                  "resource": f"{PUBLIC}/mcp", "pairing_code": pairing, "decision": decision}
        return self.form("/oauth/authorize", fields)

    def full_flow(self, agent="claude:web"):
        cid = self.register()
        pairing, _ = oauth.create_pairing(agent)
        verifier, challenge = _pkce()
        st, h, _ = self.authorize(cid, pairing, challenge)
        self.assertEqual(st, 302)
        q = parse_qs(urlsplit(h["location"]).query)
        self.assertEqual(q["state"], ["st8"])
        self.assertEqual(q["iss"], [PUBLIC])
        st, _, data = self.form("/oauth/token", {"grant_type": "authorization_code", "code": q["code"][0],
                                                 "code_verifier": verifier, "client_id": cid,
                                                 "redirect_uri": CALLBACK, "resource": f"{PUBLIC}/mcp"})
        self.assertEqual(st, 200, data)
        return cid, json.loads(data)

    def mcp(self, token, method="tools/list", params=None, host="sag.example.com"):
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        return self.req("POST", "/mcp", body, {"Authorization": f"Bearer {token}"}, host=host)

    # --- tests -----------------------------------------------------------------

    def test_discovery_and_401_challenge(self):
        st, h, data = self.req("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(st, 401)
        self.assertIn(f'resource_metadata="{PUBLIC}/.well-known/oauth-protected-resource/mcp"',
                      h["www-authenticate"])
        st, _, data = self.req("GET", "/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(json.loads(data)["resource"], f"{PUBLIC}/mcp")
        st, _, data = self.req("GET", "/.well-known/oauth-authorization-server")
        meta = json.loads(data)
        self.assertEqual(meta["token_endpoint"], f"{PUBLIC}/oauth/token")
        self.assertEqual(meta["code_challenge_methods_supported"], ["S256"])

    def test_full_flow_mcp_refresh_and_revoke(self):
        cid, tok = self.full_flow()
        self.assertTrue(tok["access_token"].startswith("sago_"))
        st, _, data = self.mcp(tok["access_token"])
        self.assertEqual(st, 200, data)
        names = {t["name"] for t in json.loads(data)["result"]["tools"]}
        self.assertIn("hub_shell", names)
        self.assertNotIn("hub_issue_agent_token", names)

        # 工具调用以配对的 agent 身份审计
        st, _, data = self.mcp(tok["access_token"], "tools/call",
                               {"name": "hub_shell", "arguments": {"command": "echo hi", "reason": "t"}})
        self.assertIn("hi", json.loads(data)["result"]["content"][0]["text"])
        with get_db_connection() as conn:
            row = conn.execute("SELECT agent_id FROM audit_events WHERE tool_name='hub_shell'").fetchone()
        self.assertEqual(row["agent_id"], "claude:web")

        # 刷新：换新令牌，旧刷新令牌作废
        st, _, data = self.form("/oauth/token", {"grant_type": "refresh_token",
                                                 "refresh_token": tok["refresh_token"], "client_id": cid})
        self.assertEqual(st, 200, data)
        tok2 = json.loads(data)
        st, _, _ = self.form("/oauth/token", {"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]})
        self.assertEqual(st, 400)
        self.assertEqual(self.mcp(tok2["access_token"])[0], 200)

        # RFC 7009 吊销整个授权
        self.assertEqual(self.form("/oauth/revoke", {"token": tok2["refresh_token"]})[0], 200)
        self.assertEqual(self.mcp(tok2["access_token"])[0], 401)
        self.assertEqual(self.mcp(tok["access_token"])[0], 401)

    def test_revoking_agent_kills_oauth_tokens_for_good(self):
        _, tok = self.full_flow()
        revoke_agent_token("claude:web")
        self.assertEqual(self.mcp(tok["access_token"])[0], 401)
        issue_agent_token("claude:web", role="operator")  # 重新签发不能让旧的 OAuth 授权复活
        self.assertEqual(self.mcp(tok["access_token"])[0], 401)

    def test_oauth_revoke_cli_keeps_static_token(self):
        static = issue_agent_token("claude:web", role="operator")
        _, tok = self.full_flow()
        self.assertEqual(oauth.revoke_agent_grants("claude:web"), 1)
        self.assertEqual(self.mcp(tok["access_token"])[0], 401)
        self.assertEqual(self.mcp(static, host="127.0.0.1")[0], 200)

    def test_static_tokens_rejected_on_public_host(self):
        static = issue_agent_token("wsl:claude", role="operator")
        self.assertEqual(self.mcp(static, host="sag.example.com")[0], 401)
        self.assertEqual(self.mcp(static, host="sag.example.com:443")[0], 401)
        self.assertEqual(self.mcp(static, host="gateway.example.com")[0], 200)
        self.assertEqual(self.mcp(static, host="127.0.0.1:4180")[0], 200)

    def test_single_domain_accepts_both_token_kinds(self):
        _set(oauth_only_hosts=())
        static = issue_agent_token("wsl:claude", role="operator")
        _, tok = self.full_flow()
        self.assertEqual(self.mcp(static)[0], 200)
        self.assertEqual(self.mcp(tok["access_token"])[0], 200)

    def test_pairing_code_is_one_time_and_wrong_code_rejected(self):
        cid = self.register()
        pairing, _ = oauth.create_pairing("claude:web")
        _, challenge = _pkce()
        st, _, data = self.authorize(cid, "AAAA-BBBB-CCCC", challenge)
        self.assertEqual(st, 200)
        self.assertIn("配对码不对", data.decode())
        self.assertEqual(self.authorize(cid, pairing.lower().replace("-", " "), challenge)[0], 302)
        st, _, data = self.authorize(cid, pairing, challenge)
        self.assertEqual(st, 200)
        self.assertIn("配对码不对", data.decode())

    def test_expired_pairing_rejected(self):
        cid = self.register()
        pairing, _ = oauth.create_pairing("claude:web")
        with get_db_connection() as conn:
            conn.execute("UPDATE oauth_pairings SET expires_at = ?", (int(time.time()) - 1,))
        _, challenge = _pkce()
        self.assertEqual(self.authorize(cid, pairing, challenge)[0], 200)

    def test_cannot_pair_admin_or_revoked_agent(self):
        with self.assertRaises(ValueError):
            oauth.create_pairing("admin:root")
        issue_agent_token("old:agent", role="operator")
        revoke_agent_token("old:agent")
        with self.assertRaises(ValueError):
            oauth.create_pairing("old:agent")

    def test_pairing_creates_operator_agent(self):
        oauth.create_pairing("claude:new")
        with get_db_connection() as conn:
            row = conn.execute("SELECT role, status FROM agent_credentials WHERE agent_id='claude:new'").fetchone()
        self.assertEqual((row["role"], row["status"]), ("operator", "ACTIVE"))

    def test_register_rejects_unknown_redirect(self):
        st, _, data = self.req("POST", "/oauth/register", {"redirect_uris": ["https://evil.example/cb"]})
        self.assertEqual(st, 400)
        self.assertEqual(json.loads(data)["error"], "invalid_redirect_uri")
        st, _, _ = self.req("POST", "/oauth/register",
                            {"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "client_secret_basic"})
        self.assertEqual(st, 400)

    def test_authorize_unregistered_redirect_shows_error_page(self):
        cid = self.register()
        _, challenge = _pkce()
        qs = urlencode({"response_type": "code", "client_id": cid, "redirect_uri": "https://claude.com/api/mcp/auth_callback",
                        "code_challenge": challenge, "code_challenge_method": "S256"})
        st, h, data = self.req("GET", f"/oauth/authorize?{qs}")
        self.assertEqual(st, 400)
        self.assertNotIn("location", h)

    def test_consent_page_and_deny(self):
        cid = self.register()
        _, challenge = _pkce()
        qs = urlencode({"response_type": "code", "client_id": cid, "redirect_uri": CALLBACK,
                        "code_challenge": challenge, "code_challenge_method": "S256", "state": "x<y"})
        st, h, data = self.req("GET", f"/oauth/authorize?{qs}")
        self.assertEqual(st, 200)
        self.assertIn("pairing_code", data.decode())
        self.assertIn("x&lt;y", data.decode())
        self.assertEqual(h["x-frame-options"], "DENY")
        st, h, _ = self.authorize(cid, "", challenge, decision="deny")
        self.assertEqual(st, 302)
        self.assertIn("error=access_denied", h["location"])

    def test_pkce_and_code_reuse(self):
        cid = self.register()
        pairing, _ = oauth.create_pairing("claude:web")
        verifier, challenge = _pkce()
        _, h, _ = self.authorize(cid, pairing, challenge)
        code = parse_qs(urlsplit(h["location"]).query)["code"][0]
        base = {"grant_type": "authorization_code", "code": code, "client_id": cid, "redirect_uri": CALLBACK}
        st, _, data = self.form("/oauth/token", {**base, "code_verifier": "x" * 50})
        self.assertEqual(json.loads(data)["error"], "invalid_grant")
        self.assertEqual(self.form("/oauth/token", {**base, "code_verifier": verifier})[0], 200)
        self.assertEqual(self.form("/oauth/token", {**base, "code_verifier": verifier})[0], 400)

    def test_loopback_redirect_ignores_port(self):
        cid = self.register(uris=("http://localhost:12345/callback",))
        pairing, _ = oauth.create_pairing("claude:code")
        _, challenge = _pkce()
        st, h, _ = self.authorize(cid, pairing, challenge, redirect="http://localhost:54321/callback")
        self.assertEqual(st, 302)
        self.assertTrue(h["location"].startswith("http://localhost:54321/callback?code="))

    def test_oauth_off_without_public_url(self):
        _set(public_url="", oauth_only_hosts=())
        st, h, _ = self.req("GET", "/.well-known/oauth-authorization-server")
        self.assertEqual(st, 401)
        self.assertNotIn("www-authenticate", h)


if __name__ == "__main__":
    unittest.main()
