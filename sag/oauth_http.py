"""
OAuth 的 HTTP 路由：发现元数据、动态注册、授权页、令牌、吊销。协议逻辑在 oauth.py。

handle() 是同步函数（要查库），server.py 用 asyncio.to_thread 调它，拿回一个完整的 HTTP 响应。
"""

import html
import json
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit

from . import oauth
from .db import append_audit

MAX_BODY_BYTES = 64 * 1024
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version",
}
_AUTH_FIELDS = ("response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state",
                "scope", "resource")
_REASONS = {200: "OK", 201: "Created", 204: "No Content", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
            404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large"}

_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>连接 SAG</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#1f2328; --muted:#656d76; --card:#fff; --line:#d8dee4; --accent:#1f6feb; --err:#cf222e; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#8d96a0; --card:#161b22; --line:#30363d; --accent:#4493f8; --err:#f85149; }}
}}
body {{ margin:0; background:var(--bg); color:var(--fg); font:16px/1.6 system-ui,-apple-system,"PingFang SC","Noto Sans SC",sans-serif; }}
main {{ max-width:440px; margin:0 auto; padding:40px 16px; }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:24px; }}
h1 {{ font-size:20px; margin:0 0 12px; }}
p {{ margin:8px 0; }}
.muted {{ color:var(--muted); font-size:14px; }}
code {{ font-size:14px; }}
.err {{ color:var(--err); margin:12px 0; }}
.warn {{ border-left:3px solid var(--err); padding-left:10px; }}
input[type=text] {{ box-sizing:border-box; width:100%; font-size:20px; letter-spacing:2px; padding:10px 12px; margin:12px 0;
  border:1px solid var(--line); border-radius:10px; background:var(--bg); color:var(--fg); text-transform:uppercase; }}
.row {{ display:flex; flex-direction:row-reverse; gap:12px; }}  /* 回车提交的是第一个按钮，所以「授权」放前面 */
button {{ flex:1; font-size:16px; padding:10px; border-radius:10px; border:1px solid var(--line); background:var(--bg); color:var(--fg); }}
button.primary {{ background:var(--accent); border-color:var(--accent); color:#fff; }}
</style></head>
<body><main><div class="card">{body}</div></main></body></html>"""


class Response:
    def __init__(self, status: int, body: bytes = b"", content_type: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None):
        self.status = status
        self.body = body
        self.content_type = content_type
        self.headers = dict(headers or {})

    def to_bytes(self) -> bytes:
        lines = [f"HTTP/1.1 {self.status} {_REASONS.get(self.status, '')}"]
        if self.content_type:
            lines.append(f"Content-Type: {self.content_type}")
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        lines += [f"Content-Length: {len(self.body)}", "Connection: close"]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + self.body


def _json(data, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
    return Response(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8", {**_CORS, **(headers or {})})


def _oauth_error(e: oauth.OAuthError) -> Response:
    return _json({"error": e.error, "error_description": e.description}, e.status, _NO_STORE)


def _page(body: str, status: int = 200) -> Response:
    headers = {**_NO_STORE, "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
               "Referrer-Policy": "no-referrer"}
    return Response(status, _PAGE.format(body=body).encode("utf-8"), "text/html; charset=utf-8", headers)


def _error_page(message: str) -> Response:
    return _page(f'<h1>无法连接</h1><p class="err">{html.escape(message)}</p>', status=400)


def _consent_page(client, params: Dict[str, str], error: Optional[str] = None) -> Response:
    host = urlsplit(params["redirect_uri"]).hostname or params["redirect_uri"]
    name = client["name"] or "一个 MCP 客户端"
    hidden = "".join(f'<input type="hidden" name="{f}" value="{html.escape(params[f])}">'
                     for f in _AUTH_FIELDS if params.get(f) is not None)
    loopback = ('<p class="err">回调地址是本机地址：只有在你自己电脑上的客户端（比如 Claude Code）发起时才继续。</p>'
                if oauth.is_loopback(params["redirect_uri"]) else "")
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    body = f"""
<h1>连接 Server Agents Gateway</h1>
<p><b>{html.escape(name)}</b> 请求接入服务器。</p>
<p class="muted">授权后会跳转到 <code>{html.escape(host)}</code>。</p>
<p class="warn">接入后它能以 root 在服务器上执行命令（有审计和回收站）。只在你自己刚发起连接时授权。</p>
{loopback}
<form method="post" action="/oauth/authorize">
{hidden}
<p class="muted">在服务器上用 root 运行 <code>python3 -m sag oauth-pair &lt;agent_id&gt;</code> 拿到配对码，填在这里。配对码决定它以哪个 agent 身份接入。</p>
{err}
<input type="text" name="pairing_code" placeholder="XXXX-XXXX-XXXX" autocomplete="off" autocapitalize="characters" required>
<div class="row">
<button type="submit" name="decision" value="approve" class="primary">授权</button>
<button type="submit" name="decision" value="deny" formnovalidate>拒绝</button>
</div>
</form>"""
    return _page(body)


def _redirect(uri: str, params: Dict[str, Optional[str]]) -> Response:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    return Response(302, headers={**_NO_STORE, "Location": f"{uri}{'&' if '?' in uri else '?'}{query}"})


def _form(body: bytes) -> Dict[str, str]:
    return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))


def _authorize(params: Dict[str, str], submitted: bool) -> Response:
    try:
        client, redirect_uri = oauth.check_client_and_redirect(params.get("client_id"), params.get("redirect_uri"))
    except oauth.OAuthError as e:
        return _error_page(e.description)
    iss = oauth.public_base()
    state = params.get("state")
    try:
        req = oauth.parse_auth_request(params)
    except oauth.OAuthError as e:
        return _redirect(redirect_uri, {"error": e.error, "error_description": e.description, "state": state,
                                        "iss": iss})
    if not submitted:
        return _consent_page(client, params)
    if params.get("decision") != "approve":
        return _redirect(redirect_uri, {"error": "access_denied", "state": state, "iss": iss})
    try:
        code, agent_id = oauth.approve(req, params.get("pairing_code") or "")
    except oauth.OAuthError as e:
        return _consent_page(client, params, error=e.description)
    append_audit(
        agent_id=agent_id,
        tool_name="oauth_authorize",
        action_type="token_issue",
        target=f"agent:{agent_id}",
        reason=f"OAuth 配对授权：{client['name'] or client['id']} → {urlsplit(redirect_uri).hostname}",
        status="SUCCESS",
        params={"oauth_client_id": client["id"], "redirect_uri": redirect_uri},
    )
    return _redirect(redirect_uri, {"code": code, "state": state, "iss": iss})


def is_oauth_path(path: str) -> bool:
    return path.startswith("/.well-known/") or path.startswith("/oauth/")


def handle(method: str, path: str, query: str, body: bytes) -> Response:
    if method == "OPTIONS":
        return Response(204, headers=_CORS)

    if path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
        return _json(oauth.resource_metadata())
    if path in ("/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp",
                "/.well-known/openid-configuration"):
        return _json(oauth.server_metadata())

    if path == "/oauth/authorize":
        if method == "GET":
            return _authorize(dict(parse_qsl(query, keep_blank_values=True)), submitted=False)
        if method == "POST":
            return _authorize(_form(body), submitted=True)
        return Response(405, headers={"Allow": "GET, POST"})

    if method != "POST" and path.startswith("/oauth/"):
        return Response(405, headers={"Allow": "POST"})

    if path == "/oauth/register":
        try:
            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return _oauth_error(oauth.OAuthError("invalid_client_metadata", "body must be a JSON object"))
        try:
            return _json(oauth.register_client(data), 201, _NO_STORE)
        except oauth.OAuthError as e:
            return _oauth_error(e)

    if path == "/oauth/token":
        try:
            return _json(oauth.exchange(_form(body)), 200, _NO_STORE)
        except oauth.OAuthError as e:
            return _oauth_error(e)

    if path == "/oauth/revoke":
        oauth.revoke_token(_form(body).get("token") or "")
        return Response(200, headers={**_CORS, **_NO_STORE})

    return _json({"error": "Not Found"}, 404)


def unauthorized() -> Response:
    """/mcp 等受保护路径没有有效令牌时的 401；启用 OAuth 时带上 resource_metadata，claude.ai 靠它发现授权服务。"""
    headers = {}
    if oauth.enabled():
        headers["WWW-Authenticate"] = f'Bearer resource_metadata="{oauth.resource_metadata_url()}"'
    return _json({"error": "Unauthorized: Invalid or missing Bearer token"}, 401, headers)
