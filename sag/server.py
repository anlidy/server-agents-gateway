"""
Official-Compliant MCP (Model Context Protocol) Server over Streamable HTTP.
Native Python 3.12 asyncio implementation with zero external dependencies.
Primary endpoint is POST /mcp (Streamable HTTP, stateless); legacy HTTP+SSE
(GET /sse + POST /messages) is kept for older clients.
"""

import asyncio
import inspect
import json
import sys
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from . import collab
from .auth import authenticate_bearer_token, issue_agent_token
from .config import config
from .db import append_audit, init_db
from .overview import ensure_document
from .reconciler import reconcile
from .tools import (
    tool_delete_file,
    tool_get_audit_event,
    tool_get_overview,
    tool_get_status,
    tool_issue_agent_token,
    tool_list_dir,
    tool_list_trash,
    tool_mkdir,
    tool_patch_file,
    tool_query_audit_logs,
    tool_read_file,
    tool_rebuild_overview,
    tool_restore_file,
    tool_revoke_agent_token,
    tool_shell,
    tool_write_file,
)

from .tools_spec import MCP_TOOLS_SPEC, ADMIN_ONLY_TOOL_NAMES

def get_tools_for_agent(agent_id: str, role: str) -> list:
    """
    Role-based Tool Visibility:
    Only the configured root admin agent can see and access credential issuance tools.
    All other agents see operational tools without token issuance.
    """
    if agent_id == config.root_admin_agent_id and role == "admin":
        return MCP_TOOLS_SPEC
    return [t for t in MCP_TOOLS_SPEC if t["name"] not in ADMIN_ONLY_TOOL_NAMES]


_SPOOF_KEYS = ("from", "from_agent", "sender", "created_by", "agent_id")
_SENDER_TOOLS = {"hub_send_message", "hub_reply", "hub_create_task", "hub_update_task", "hub_set_group"}


class UnknownToolError(ValueError):
    """The tool does not exist, or exists but is not for this caller (the client cannot tell which)."""


class ToolArgumentError(ValueError):
    """The arguments do not fit the tool: missing, unexpected, or an attempt to set the sender."""


def _reject_spoofing(tool_name: str, args: Dict[str, Any]) -> None:
    bad = [k for k in _SPOOF_KEYS if k in args]
    if bad:
        raise ToolArgumentError(
            f"{tool_name}: '{bad[0]}' is not accepted; the sender is always the agent_id of your token"
        )


def _audit_event(**args: Any) -> Any:
    return tool_get_audit_event(args.get("id") or args.get("event_id"))


def _read_message(agent_id: str, **args: Any) -> Any:
    message_id = args.pop("message_id", None)
    alias = args.pop("id", None)
    return collab.read_message(agent_id, message_id or alias, **args)


# tool name -> (function, how it is called)
#   "agent":    fn(agent_id, **args)             "agent_kw": fn(agent_id=agent_id, **args)
#   "plain":    fn(**args)                       "none":     fn()   (arguments are ignored)
#   "admin":    fn(caller_agent_id=..., caller_role=..., **args)
_TOOL_TABLE = {
    "hub_shell": (tool_shell, "agent"),
    "hub_read_file": (tool_read_file, "agent"),
    "hub_list_dir": (tool_list_dir, "agent"),
    "hub_mkdir": (tool_mkdir, "agent"),
    "hub_write_file": (tool_write_file, "agent"),
    "hub_patch_file": (tool_patch_file, "agent"),
    "hub_delete_file": (tool_delete_file, "agent"),
    "hub_list_trash": (tool_list_trash, "agent"),
    "hub_restore_file": (tool_restore_file, "agent"),
    "hub_get_overview": (tool_get_overview, "plain"),
    "hub_rebuild_overview": (tool_rebuild_overview, "agent_kw"),
    "hub_get_status": (tool_get_status, "none"),
    "hub_query_audit_logs": (tool_query_audit_logs, "plain"),
    "hub_get_audit_event": (_audit_event, "plain"),
    "hub_list_agents": (collab.list_agents, "agent"),
    "hub_set_group": (collab.set_group, "agent"),
    "hub_send_message": (collab.send_message, "agent"),
    "hub_reply": (collab.reply, "agent"),
    "hub_inbox": (collab.inbox, "agent"),
    "hub_read_message": (_read_message, "agent"),
    "hub_mark_read": (collab.mark_read, "agent"),
    "hub_create_task": (collab.create_task, "agent"),
    "hub_list_tasks": (collab.list_tasks, "agent"),
    "hub_update_task": (collab.update_task, "agent"),
    "hub_issue_agent_token": (tool_issue_agent_token, "admin"),
    "hub_revoke_agent_token": (tool_revoke_agent_token, "admin"),
}


def _short(value: Any, limit: int = 500) -> Any:
    """An argument as it goes into the audit row: scalars as they are, anything bigger cut to `limit` chars."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    try:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=repr)
    except Exception:
        text = repr(value)
    return text if len(text) <= limit else f"{text[:limit]}...({len(text)} chars)"


def _summarize_args(arguments: Any) -> Dict[str, Any]:
    if not isinstance(arguments, dict):
        return {"arguments": _short(arguments)}
    return {str(k)[:80]: _short(v) for k, v in list(arguments.items())[:50]}


def _failure_target(tool_name: Any, args: Dict[str, Any]) -> str:
    for key in ("path", "command", "trash_id", "task_id", "message_id", "to", "agent_id"):
        if args.get(key):
            return str(_short(args[key], 200))[:200]
    return str(tool_name)[:200]


def _audit_failure(agent_id: str, tool_name: Any, arguments: Any, exc: BaseException) -> None:
    """Record a call that failed without leaving a row of its own. Never raises: the caller's error wins."""
    rejected = isinstance(exc, (UnknownToolError, ToolArgumentError, PermissionError))
    args = arguments if isinstance(arguments, dict) else {}
    try:
        append_audit(
            agent_id=agent_id,
            tool_name=str(tool_name)[:100],
            action_type="tool_rejected" if rejected else "tool_error",
            target=_failure_target(tool_name, args),
            reason=str(_short(args.get("reason") or "", 500)),
            status="REJECTED" if rejected else "FAILED",
            params=_summarize_args(arguments),
            stderr=getattr(exc, "audit_detail", None) or f"{type(exc).__name__}: {exc}",
        )
    except Exception as audit_exc:
        print(
            f"[audit] could not record failed call {str(tool_name)[:100]!r} by {agent_id}: "
            f"{type(audit_exc).__name__}: {audit_exc}",
            file=sys.stderr,
        )


def _dispatch(agent_id: str, role: str, tool_name: str, arguments: Dict[str, Any]) -> Any:
    entry = _TOOL_TABLE.get(tool_name) if isinstance(tool_name, str) else None
    if entry is None:
        raise UnknownToolError(f"Unknown MCP tool: {tool_name}")
    # Strict isolation: an admin-only tool is "unknown" to everyone but the configured root admin
    if tool_name in ADMIN_ONLY_TOOL_NAMES and (agent_id != config.root_admin_agent_id or role != "admin"):
        exc = UnknownToolError(f"Unknown MCP tool: {tool_name}")
        exc.audit_detail = "admin-only tool called by an agent that is not the root admin"
        raise exc
    if arguments is not None and not isinstance(arguments, dict):
        raise ToolArgumentError(f"{tool_name}: arguments must be an object")

    # Filter out client-side synthetic kwargs (e.g. Operit internal metadata)
    args = {k: v for k, v in (arguments or {}).items() if not str(k).startswith("__")}
    if tool_name in _SENDER_TOOLS:
        _reject_spoofing(tool_name, args)

    fn, mode = entry
    if mode == "none":
        return fn()
    lead: tuple = (agent_id,) if mode == "agent" else ()
    kwargs = dict(args)
    if mode == "agent_kw":
        kwargs["agent_id"] = agent_id
    elif mode == "admin":
        kwargs.update(caller_agent_id=agent_id, caller_role=role)
    try:
        inspect.signature(fn).bind(*lead, **kwargs)
    except TypeError as exc:
        raise ToolArgumentError(f"{tool_name}: {exc}") from None
    return fn(*lead, **kwargs)


def dispatch_tool(agent_id: str, role: str, tool_name: str, arguments: Dict[str, Any]) -> Any:
    """
    Run a tool for an authenticated agent. Whatever fails here leaves an audit row: the tools record
    their own failures (marking the exception sag_audited), everything else (unknown tool, bad
    arguments, an OSError nobody expected) is recorded once, here.
    """
    try:
        return _dispatch(agent_id, role, tool_name, arguments)
    except Exception as exc:
        if not getattr(exc, "sag_audited", False):
            _audit_failure(agent_id, tool_name, arguments, exc)
        raise


class SSESession:
    def __init__(self, session_id: str, agent_id: str, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.agent_id = agent_id
        self.writer = writer
        self.closed = False

    async def send_event(self, event_type: str, data: str):
        if self.closed:
            return
        payload = f"event: {event_type}\ndata: {data}\n\n".encode("utf-8")
        try:
            self.writer.write(payload)
            await self.writer.drain()
        except Exception:
            self.closed = True


_SESSIONS: Dict[str, SSESession] = {}

SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
KEEPALIVE_SECONDS = 15

# 每次启动换一个 boot id，发给 /mcp 客户端的 Mcp-Session-Id 都以它开头。
# 工具列表只在发版重启时变化；重启后旧会话的请求一律回 404，按 MCP 规范
# 客户端必须重新 initialize，也就会重新 tools/list，拿到新工具。
# 服务端不保存会话，只认前缀；不带会话头的请求（sag-call 等）照旧放行。
BOOT_ID = uuid.uuid4().hex[:12]


def _new_session_id() -> str:
    return f"{BOOT_ID}.{uuid.uuid4().hex}"


def _session_is_stale(session_id: str) -> bool:
    return bool(session_id) and not session_id.startswith(BOOT_ID + ".")


# 不按规范重新 initialize 的客户端（如 Operit）会一直带着旧会话 ID。每个旧 ID
# 只回一次 404：守规范的客户端这一次就换了新会话；其余的第二次起放行，
# 第一次放行时在工具结果末尾提示重连。只存在内存里，满了就清空重来。
_STALE_SEEN: Dict[str, bool] = {}  # stale session id -> hint already shown
_STALE_SEEN_MAX = 1000
STALE_SESSION_HINT = (
    "[SAG] 网关重启过，这个 MCP 会话是重启前建立的，工具列表可能已更新。"
    "照常调用不受影响；重连 MCP 可拿到新工具。"
)


def _stale_session_action(session_id: str) -> str:
    """'ok' | 'reject' (first time: 404) | 'hint' (second time: allow + hint) | 'allow'."""
    if not _session_is_stale(session_id):
        return "ok"
    if session_id not in _STALE_SEEN:
        if len(_STALE_SEEN) >= _STALE_SEEN_MAX:
            _STALE_SEEN.clear()
        _STALE_SEEN[session_id] = False
        return "reject"
    if not _STALE_SEEN[session_id]:
        _STALE_SEEN[session_id] = True
        return "hint"
    return "allow"


def _append_hint(response: Optional[Dict[str, Any]], hint: str) -> bool:
    content = ((response or {}).get("result") or {}).get("content")
    if isinstance(content, list):
        content.append({"type": "text", "text": hint})
        return True
    return False


def _rpc_error(rpc_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


async def handle_jsonrpc(agent_id: str, role: str, rpc_req: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(rpc_req, dict):
        return _rpc_error(None, -32600, "Invalid Request")
    rpc_id = rpc_req.get("id")
    try:
        return await _handle_jsonrpc(agent_id, role, rpc_req, rpc_id)
    except Exception as exc:
        # A bug must not drop the connection, nor take the other calls of a batch down with it.
        print(
            f"[server] internal error handling {str(rpc_req.get('method'))[:60]!r}: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return _rpc_error(rpc_id, -32603, "Internal error") if rpc_id is not None else None


async def _handle_jsonrpc(agent_id: str, role: str, rpc_req: Dict[str, Any], rpc_id: Any) -> Optional[Dict[str, Any]]:
    method = rpc_req.get("method")
    params = rpc_req.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _rpc_error(rpc_id, -32602, "Invalid params: expected an object") if rpc_id is not None else None

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "server-agents-gateway",
                    "version": "2.1.3"
                }
            }
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if method == "tools/list":
        visible_tools = get_tools_for_agent(agent_id, role)
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "tools": visible_tools
            }
        }

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments")
        try:
            # Run in a thread so long shell commands don't stall other clients or keepalives
            result = await asyncio.to_thread(dispatch_tool, agent_id, role, tool_name, arguments)
            text_val = json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result
            content = [{"type": "text", "text": text_val}]
            # 未读提示放在独立的第二个 content 项里：content[0] 的 JSON 结构不变，
            # 只解析第一项的客户端不受影响，把所有 text 拼给模型的客户端能看到它。
            if tool_name not in collab.NO_HINT_TOOLS:
                hint = await asyncio.to_thread(collab.unread_hint, agent_id)
                if hint:
                    content.append({"type": "text", "text": hint})
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"content": content},
            }
        except Exception as e:
            return _rpc_error(rpc_id, -32000, str(e))

    if rpc_id is not None:
        return _rpc_error(rpc_id, -32601, f"Method not found: {method}")
    return None


def _write_simple(writer: asyncio.StreamWriter, status: str, body: bytes = b"", extra_headers: bytes = b"") -> None:
    head = f"HTTP/1.1 {status}\r\n".encode()
    if body:
        head += b"Content-Type: application/json; charset=utf-8\r\n"
    head += b"Content-Length: " + str(len(body)).encode() + b"\r\n" + extra_headers + b"Connection: close\r\n\r\n"
    writer.write(head + body)


async def handle_streamable_post(
    agent_id: str, role: str, headers: Dict[str, str], body_data: bytes, writer: asyncio.StreamWriter
) -> None:
    """
    MCP Streamable HTTP. Sessions carry no server state; Mcp-Session-Id only
    marks which boot issued them (see BOOT_ID).
    Notifications/responses only -> 202. Requests -> one SSE stream when the client
    accepts it (with keepalive pings while tools run), otherwise a plain JSON body.
    """
    session_id = headers.get("mcp-session-id", "")
    stale = _stale_session_action(session_id)
    if stale == "reject":
        err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Session expired (gateway restarted); re-initialize"}}
        _write_simple(writer, "404 Not Found", json.dumps(err).encode())
        return

    try:
        payload = json.loads(body_data.decode("utf-8"))
    except Exception:
        err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        _write_simple(writer, "400 Bad Request", json.dumps(err).encode())
        return

    is_batch = isinstance(payload, list)
    messages = payload if is_batch else [payload]
    if not messages or not all(isinstance(m, dict) for m in messages):
        err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        _write_simple(writer, "400 Bad Request", json.dumps(err).encode())
        return

    has_requests = any("method" in m and m.get("id") is not None for m in messages)
    if not has_requests:
        if stale == "hint":
            _STALE_SEEN[session_id] = False  # no tool result here to carry the hint
        for m in messages:
            if "method" in m:
                await handle_jsonrpc(agent_id, role, m)
        _write_simple(writer, "202 Accepted")
        return

    async def run_all() -> list:
        results = await asyncio.gather(*(handle_jsonrpc(agent_id, role, m) for m in messages))
        results = [r for r in results if r]
        if stale == "hint" and not any(_append_hint(r, STALE_SESSION_HINT) for r in results):
            _STALE_SEEN[session_id] = False  # nothing to hang the hint on; show it next time
        return results

    session_header = b""
    if any(m.get("method") == "initialize" for m in messages):
        session_header = f"Mcp-Session-Id: {_new_session_id()}\r\n".encode()

    if "text/event-stream" not in headers.get("accept", ""):
        responses = await run_all()
        out = responses if is_batch else (responses[0] if responses else {})
        _write_simple(writer, "200 OK", json.dumps(out, ensure_ascii=False).encode("utf-8"), session_header)
        return

    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/event-stream; charset=utf-8\r\n"
        b"Cache-Control: no-cache\r\n"
        b"X-Accel-Buffering: no\r\n"
        + session_header +
        b"Connection: close\r\n"
        b"\r\n"
    )
    await writer.drain()

    task = asyncio.create_task(run_all())
    while True:
        done, _ = await asyncio.wait({task}, timeout=KEEPALIVE_SECONDS)
        if done:
            break
        writer.write(b": ping\n\n")
        await writer.drain()

    responses = task.result()
    data = json.dumps(responses if is_batch else responses[0], ensure_ascii=False)
    writer.write(f"event: message\ndata: {data}\n\n".encode("utf-8"))
    await writer.drain()


# A client that connects and then sends nothing (or one byte a minute) must not hold a connection forever.
HEADER_TIMEOUT = 15.0
BODY_TIMEOUT = 120.0
MAX_HEADER_LINES = 100


def _http_error(writer: asyncio.StreamWriter, status: str, message: str) -> None:
    _write_simple(writer, status, json.dumps({"error": message}).encode())


async def _read_head(reader: asyncio.StreamReader):
    """(method, target, headers), None for an empty or malformed request line, "too_many" for a header flood."""
    request_line = await reader.readline()
    if not request_line:
        return None
    parts = request_line.decode("utf-8", errors="ignore").strip().split()
    if len(parts) < 2:
        return None
    headers: Dict[str, str] = {}
    for _ in range(MAX_HEADER_LINES + 1):
        header_line = await reader.readline()
        if not header_line or header_line == b"\r\n" or header_line == b"\n":
            return parts[0], parts[1], headers
        h_str = header_line.decode("utf-8", errors="ignore").strip()
        if ":" in h_str:
            k, v = h_str.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return "too_many"


async def _read_body(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, headers: Dict[str, str], default: bytes = b""
) -> Optional[bytes]:
    """The request body, or None once an error response has been written (or the client went away)."""
    if "transfer-encoding" in headers:
        _http_error(writer, "411 Length Required", "chunked request bodies are not supported; send Content-Length")
        return None
    raw = headers.get("content-length", "")
    if raw == "":
        return default
    if not raw.isdigit():
        _http_error(writer, "400 Bad Request", "invalid Content-Length")
        return None
    length = int(raw)
    if length > config.max_request_bytes:
        _http_error(writer, "413 Payload Too Large", f"request body over {config.max_request_bytes} bytes")
        return None
    if length == 0:
        return default
    try:
        return await asyncio.wait_for(reader.readexactly(length), BODY_TIMEOUT)
    except asyncio.TimeoutError:
        _http_error(writer, "408 Request Timeout", "request body not received in time")
    except asyncio.IncompleteReadError:
        pass  # the client hung up mid-body: nobody to answer
    return None


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        try:
            head = await asyncio.wait_for(_read_head(reader), HEADER_TIMEOUT)
        except asyncio.TimeoutError:
            writer.close()
            return
        if head is None:
            writer.close()
            return
        if head == "too_many":
            _http_error(writer, "431 Request Header Fields Too Large", "too many headers")
            await writer.drain()
            writer.close()
            return
        method, full_path, headers = head

        parsed_url = urllib.parse.urlparse(full_path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Health endpoint
        if path == "/health":
            body = b'{"status": "ok", "service": "server-agents-gateway"}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            return

        # Authenticate Bearer Token
        auth_header = headers.get("authorization", "")
        # Allow token in query parameter for SSE initial connection if header unavailable
        if not auth_header and "token" in query:
            auth_header = f"Bearer {query['token'][0]}"

        auth_res = await asyncio.to_thread(authenticate_bearer_token, auth_header)
        if not auth_res:
            body = b'{"error": "Unauthorized: Invalid or missing Bearer token"}'
            writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            writer.close()
            return

        agent_id, role = auth_res

        # GET /tools
        if method in ("GET", "HEAD") and path == "/tools":
            visible_tools = get_tools_for_agent(agent_id, role)
            body = json.dumps({"tools": visible_tools}, ensure_ascii=False).encode("utf-8")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + (b"" if method == "HEAD" else body))
            await writer.drain()
            writer.close()
            return

        # /mcp (MCP Streamable HTTP). No server-initiated stream, so GET/DELETE are 405.
        if path == "/mcp":
            if method == "POST":
                body_data = await _read_body(reader, writer, headers, default=b"")
                if body_data is not None:
                    await handle_streamable_post(agent_id, role, headers, body_data, writer)
            else:
                _write_simple(writer, "405 Method Not Allowed", extra_headers=b"Allow: POST\r\n")
            await writer.drain()
            writer.close()
            return

        # GET /sse (legacy HTTP+SSE transport)
        if method == "GET" and path in ("/sse", "/"):
            session_id = str(uuid.uuid4())
            sse_session = SSESession(session_id, agent_id, writer)
            _SESSIONS[session_id] = sse_session

            # Send HTTP SSE Headers
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream; charset=utf-8\r\n"
                b"Cache-Control: no-cache\r\n"
                b"Connection: keep-alive\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"\r\n"
            )
            await writer.drain()

            # Send initial endpoint event
            endpoint_url = f"/messages?sessionId={session_id}"
            await sse_session.send_event("endpoint", endpoint_url)

            # Keep SSE stream alive with periodic comment pings
            try:
                while not sse_session.closed:
                    await asyncio.sleep(15)
                    try:
                        writer.write(b": ping\n\n")
                        await writer.drain()
                    except Exception:
                        break
            finally:
                _SESSIONS.pop(session_id, None)
                writer.close()
            return

        # POST /messages (legacy HTTP+SSE message endpoint)
        if method == "POST" and path in ("/messages", "/message", "/rpc"):
            body_data = await _read_body(reader, writer, headers, default=b"{}")
            if body_data is None:
                await writer.drain()
                writer.close()
                return
            try:
                rpc_body = json.loads(body_data.decode("utf-8"))
            except Exception:
                body = b'{"error": "Malformed JSON payload"}'
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                await writer.drain()
                writer.close()
                return

            session_id = query.get("sessionId", [""])[0]
            target_session = _SESSIONS.get(session_id)
            if target_session is not None and target_session.agent_id != agent_id:
                target_session = None  # somebody else's stream: answer on this request instead of pushing into it

            rpc_response = await handle_jsonrpc(agent_id, role, rpc_body)

            # If connected via active SSE, push response through SSE stream
            if target_session and not target_session.closed:
                # Return 202 Accepted to the POST
                writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()

                if rpc_response:
                    await target_session.send_event("message", json.dumps(rpc_response, ensure_ascii=False))
                return

            # Direct HTTP JSON-RPC fallback
            resp_body = json.dumps(rpc_response or {"jsonrpc": "2.0"}, ensure_ascii=False).encode("utf-8")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: " + str(len(resp_body)).encode() + b"\r\nConnection: close\r\n\r\n" + resp_body)
            await writer.drain()
            writer.close()
            return

        # 404 fallback
        body = b'{"error": "Not Found"}'
        writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    except Exception:
        try:
            writer.close()
        except Exception:
            pass


async def _periodic_reconcile_loop():
    """Background desired/observed drift scan. Interval from RECONCILE_INTERVAL_SECONDS."""
    interval = max(5, int(config.reconcile_interval_seconds))
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(reconcile)
        except Exception as exc:
            print(f"[reconcile] periodic pass failed: {exc}")


_BACKGROUND_TASKS: set = set()


def _spawn_background(coro) -> "asyncio.Task":
    """create_task keeps only a weak reference: hold on to the task or it can be collected mid-run."""
    task = asyncio.get_running_loop().create_task(coro)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return task


def configure_event_loop(loop: "asyncio.AbstractEventLoop") -> None:
    """
    Tool calls run in the loop's default executor, which holds min(32, cpu + 4) threads. A hub_shell
    can run for an hour, so a handful of them used to starve every other call (and the token check).
    """
    loop.set_default_executor(ThreadPoolExecutor(max_workers=max(4, config.max_workers), thread_name_prefix="sag"))


async def run_server():
    # Under systemd stdout is a pipe, which Python buffers in blocks: without this the log lines
    # below (and the reconcile failures) would not show up in the journal until much later.
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
    configure_event_loop(asyncio.get_running_loop())
    init_db()
    ensure_document()
    try:
        reconcile()
    except Exception as exc:
        print(f"[reconcile] startup pass failed: {exc}")
    _spawn_background(_periodic_reconcile_loop())
    server = await asyncio.start_server(handle_client, config.host, config.port)
    print(f"🚀 Server Agents Gateway listening on {config.host}:{config.port} ...")
    print(f"🔄 Periodic reconcile every {max(5, int(config.reconcile_interval_seconds))}s")
    async with server:
        await server.serve_forever()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("issue-admin", "issue-root-admin"):
        init_db()
        admin_agent = sys.argv[2] if len(sys.argv) > 2 else config.root_admin_agent_id
        token = issue_agent_token(admin_agent, role="admin")
        print(f"Issued ROOT ADMIN token for [{admin_agent}]: {token}")
        if admin_agent != config.root_admin_agent_id:
            print(
                f"warning: only [{config.root_admin_agent_id}] (ROOT_ADMIN_AGENT_ID) can use the admin tools; "
                f"a token for [{admin_agent}] will not see them. Set ROOT_ADMIN_AGENT_ID={admin_agent} in .env "
                "or issue the token for the configured id.",
                file=sys.stderr,
            )
    elif len(sys.argv) > 1 and sys.argv[1] == "issue-token":
        init_db()
        agent = sys.argv[2] if len(sys.argv) > 2 else "desktop:cursor"
        token = issue_agent_token(agent, role="operator")
        print(f"Issued operator token for [{agent}]: {token}")
    elif len(sys.argv) > 1 and sys.argv[1] == "backup-db":
        init_db()
        sys.exit(_backup_db_cli(sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == "purge-trash":
        init_db()
        sys.exit(_purge_trash_cli(sys.argv[2:]))
    else:
        asyncio.run(run_server())


def _backup_db_cli(argv: list) -> int:
    """Before a release: back up gateway.db and keep only the newest N backups (default 1)."""
    import argparse

    from .db import append_audit, backup_database

    ap = argparse.ArgumentParser(prog="python3 -m sag backup-db")
    ap.add_argument("--label", default="", help="e.g. the version being replaced: 2.1.3")
    ap.add_argument("--keep", type=int, default=None, help=f"backups to keep (default {config.db_backup_keep})")
    args = ap.parse_args(argv)
    res = backup_database(args.label, args.keep)
    append_audit(
        agent_id="root:cli",
        tool_name="backup-db",
        action_type="db_backup",
        target=res["backup"],
        reason=f"backup before release {args.label}".strip(),
        status="SUCCESS",
        params={"removed": res["removed"]},
    )
    print(f"Backup: {res['backup']}")
    for p in res["removed"]:
        print(f"Removed old backup: {p}")
    return 0


def _purge_trash_cli(argv: list) -> int:
    """
    Root-only escape hatch: permanently delete recycle-bin items before they expire.
    Deliberately not an MCP tool, so agents can't empty the safety net themselves.
    Dry run unless --yes. Every real purge is audited.
    """
    import argparse

    from .db import append_audit
    from .trash import purge_trash_items, select_trash

    ap = argparse.ArgumentParser(prog="python3 -m sag purge-trash")
    ap.add_argument("--id", action="append", dest="ids", help="trash id; repeatable")
    ap.add_argument("--deleted-by", help="agent_id that deleted the items")
    ap.add_argument("--since", help="deleted_at >= (ISO, e.g. 2026-09-29T23:20)")
    ap.add_argument("--until", help="deleted_at <= (ISO)")
    ap.add_argument("--prefix", help="original_path prefix")
    ap.add_argument("--reason", default="", help="recorded in the audit log")
    ap.add_argument("--yes", action="store_true", help="actually delete (default: dry run)")
    args = ap.parse_args(argv)

    rows = select_trash(args.ids, args.deleted_by, args.since, args.until, args.prefix)
    if not rows:
        print("No matching trash items (at least one filter is required).")
        return 1
    total = sum(r["size_bytes"] or 0 for r in rows)
    for r in rows:
        print(f"{r['id']}  {r['deleted_at']}  {r['deleted_by']:<16} {r['size_bytes'] or 0:>12}  {r['original_path']}")
    print(f"{len(rows)} items, {total / 1048576:.1f} MiB")
    if not args.yes:
        print("Dry run. Re-run with --yes to delete permanently.")
        return 0
    n = purge_trash_items([r["id"] for r in rows])
    append_audit(
        agent_id="root:cli",
        tool_name="purge-trash",
        action_type="trash_purge",
        target=args.prefix or args.deleted_by or "trash",
        reason=args.reason or "manual purge",
        status="SUCCESS",
        params={
            "filters": {k: v for k, v in vars(args).items() if k not in ("yes", "reason") and v},
            "count": n,
            "bytes": total,
            "ids": [r["id"] for r in rows],
            "paths": [r["original_path"] for r in rows],
        },
    )
    print(f"Purged {n} items.")
    return 0


if __name__ == "__main__":
    main()
