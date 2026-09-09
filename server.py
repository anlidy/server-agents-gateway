"""
Official-Compliant MCP (Model Context Protocol) Server over SSE and Stdio.
Native Python 3.12 asyncio implementation with zero external dependencies.
Supports bidirectional SSE streaming, JSON-RPC 2.0 lifecycle, and full inputSchema definitions.
"""

import asyncio
import json
import os
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, Optional, Set

from auth import authenticate_bearer_token, issue_agent_token
from config import config
from db import init_db
from reconciler import reconcile_observed_state
from tools import (
    tool_acquire_lock,
    tool_cleanup_temp,
    tool_delete_file,
    tool_edit_file,
    tool_execute_command,
    tool_get_overview,
    tool_get_status,
    tool_issue_agent_token,
    tool_manage_service,
    tool_query_assets,
    tool_query_audit_logs,
    tool_rebuild_overview,
    tool_register_asset,
    tool_release_lock,
    tool_renew_lock,
    tool_revoke_agent_token,
)

from tools_spec import MCP_TOOLS_SPEC, ADMIN_ONLY_TOOL_NAMES

def get_tools_for_agent(agent_id: str, role: str) -> list:
    """
    Role-based Tool Visibility:
    Only the configured root admin agent can see and access credential issuance tools.
    All other agents only see the standard 14 operational tools.
    """
    if agent_id == config.root_admin_agent_id and role == "admin":
        return MCP_TOOLS_SPEC
    return [t for t in MCP_TOOLS_SPEC if t["name"] not in ADMIN_ONLY_TOOL_NAMES]


def dispatch_tool(agent_id: str, role: str, tool_name: str, arguments: Dict[str, Any]) -> Any:
    # Strict isolation: if tool is admin-only, deny callers other than the configured root admin as unknown tools
    if tool_name in ADMIN_ONLY_TOOL_NAMES:
        if agent_id != config.root_admin_agent_id or role != "admin":
            raise ValueError(f"Unknown MCP tool: {tool_name}")

    # Filter out client-side synthetic kwargs (e.g. Operit internal metadata)
    cleaned_args = {k: v for k, v in arguments.items() if not k.startswith("__")}

    if tool_name == "hub_acquire_lock":
        return tool_acquire_lock(agent_id, **cleaned_args)
    elif tool_name == "hub_renew_lock":
        return tool_renew_lock(agent_id, **cleaned_args)
    elif tool_name == "hub_release_lock":
        return tool_release_lock(agent_id, **cleaned_args)
    elif tool_name == "hub_manage_service":
        return tool_manage_service(agent_id, **cleaned_args)
    elif tool_name == "hub_edit_file":
        return tool_edit_file(agent_id, **cleaned_args)
    elif tool_name == "hub_delete_file":
        return tool_delete_file(agent_id, **cleaned_args)
    elif tool_name == "hub_cleanup_temp":
        return tool_cleanup_temp(agent_id, **cleaned_args)
    elif tool_name == "hub_execute_command":
        return tool_execute_command(agent_id, **cleaned_args)
    elif tool_name == "hub_register_asset":
        return tool_register_asset(agent_id, **cleaned_args)
    elif tool_name == "hub_get_overview":
        return tool_get_overview()
    elif tool_name == "hub_rebuild_overview":
        return tool_rebuild_overview(**cleaned_args)
    elif tool_name == "hub_query_assets":
        return tool_query_assets(**cleaned_args)
    elif tool_name == "hub_get_status":
        return tool_get_status()
    elif tool_name == "hub_query_audit_logs":
        return tool_query_audit_logs(**cleaned_args)
    elif tool_name == "hub_issue_agent_token":
        return tool_issue_agent_token(caller_agent_id=agent_id, caller_role=role, **cleaned_args)
    elif tool_name == "hub_revoke_agent_token":
        return tool_revoke_agent_token(caller_agent_id=agent_id, caller_role=role, **cleaned_args)
    else:
        raise ValueError(f"Unknown MCP tool: {tool_name}")


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


async def handle_jsonrpc(agent_id: str, role: str, rpc_req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rpc_id = rpc_req.get("id")
    method = rpc_req.get("method")
    params = rpc_req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "server-agents-gateway",
                    "version": "1.0.0"
                }
            }
        }

    if method == "notifications/initialized":
        return None

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
        arguments = params.get("arguments", {})
        try:
            result = dispatch_tool(agent_id, role, tool_name, arguments)
            text_val = json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": text_val
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32000,
                    "message": str(e)
                }
            }

    if rpc_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }
    return None


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        # Read HTTP request line
        request_line = await reader.readline()
        if not request_line:
            writer.close()
            return
        line_str = request_line.decode("utf-8", errors="ignore").strip()
        parts = line_str.split()
        if len(parts) < 2:
            writer.close()
            return
        method, full_path = parts[0], parts[1]

        # Read Headers
        headers = {}
        while True:
            header_line = await reader.readline()
            if not header_line or header_line == b"\r\n" or header_line == b"\n":
                break
            h_str = header_line.decode("utf-8", errors="ignore").strip()
            if ":" in h_str:
                k, v = h_str.split(":", 1)
                headers[k.strip().lower()] = v.strip()

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

        auth_res = authenticate_bearer_token(auth_header)
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

        # GET /sse (MCP Standard SSE Connection)
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

        # POST /messages (MCP Standard Message Endpoint)
        if method == "POST" and path in ("/messages", "/message", "/rpc", "/mcp"):
            content_length = int(headers.get("content-length", 0))
            body_data = await reader.readexactly(content_length) if content_length > 0 else b"{}"
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
            await asyncio.to_thread(reconcile_observed_state)
        except Exception as exc:
            print(f"[reconcile] periodic pass failed: {exc}")


async def run_server():
    init_db()
    asyncio.create_task(_periodic_reconcile_loop())
    server = await asyncio.start_server(handle_client, config.host, config.port)
    print(f"🚀 Server Agents Gateway listening on {config.host}:{config.port} ...")
    print(f"🔄 Periodic reconcile every {max(5, int(config.reconcile_interval_seconds))}s")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("issue-admin", "issue-root-admin"):
        init_db()
        admin_agent = sys.argv[2] if len(sys.argv) > 2 else config.root_admin_agent_id
        token = issue_agent_token(admin_agent, role="admin")
        print(f"👑 Issued ROOT ADMIN token for [{admin_agent}]: {token}")
    elif len(sys.argv) > 1 and sys.argv[1] == "issue-token":
        init_db()
        agent = sys.argv[2] if len(sys.argv) > 2 else "desktop:cursor"
        token = issue_agent_token(agent, role="operator")
        print(f"Issued operator token for [{agent}]: {token}")
    else:
        asyncio.run(run_server())
