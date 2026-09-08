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

MCP_TOOLS_SPEC = [
    {
        "name": "hub_acquire_lock",
        "description": "申请资产或配置的排他租约锁，返回单调递增的 lease_token",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource_key": {"type": "string", "description": "目标资源键，例如 'service:web_api' 或 'file:/etc/nginx/nginx.conf'"},
                "reason": {"type": "string", "description": "申请锁的操作意图与理由"},
                "ttl_seconds": {"type": "integer", "description": "租约超时时间（秒），默认 120", "default": 120}
            },
            "required": ["resource_key", "reason"]
        }
    },
    {
        "name": "hub_renew_lock",
        "description": "对长任务租约锁进行心跳续期，防过期失效",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource_key": {"type": "string", "description": "已加锁的资源键"},
                "lease_token": {"type": "integer", "description": "持有的有效 lease_token"},
                "ttl_seconds": {"type": "integer", "description": "延长的时间（秒），默认 120", "default": 120}
            },
            "required": ["resource_key", "lease_token"]
        }
    },
    {
        "name": "hub_release_lock",
        "description": "凭借合法的 lease_token 主动释放持有的排他锁",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource_key": {"type": "string", "description": "目标资源键"},
                "lease_token": {"type": "integer", "description": "持有的有效 lease_token"}
            },
            "required": ["resource_key", "lease_token"]
        }
    },
    {
        "name": "hub_manage_service",
        "description": "受控启停或重启 Docker 容器或 Systemd 服务（受保护服务强制要求锁）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_type": {"type": "string", "enum": ["docker", "systemd"], "description": "服务类型"},
                "name": {"type": "string", "description": "容器名或服务名"},
                "action": {"type": "string", "enum": ["start", "stop", "restart"], "description": "动作"},
                "reason": {"type": "string", "description": "操作声明的意图与原因"},
                "lease_token": {"type": "integer", "description": "受保护资产时必须传入的锁令牌"}
            },
            "required": ["service_type", "name", "action", "reason"]
        }
    },
    {
        "name": "hub_edit_file",
        "description": "受控原子写入或编辑文件，生成 diff 差异，自动识别临时文件，强制校验锁",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "绝对文件路径"},
                "content": {"type": "string", "description": "要写入的文件完整新内容"},
                "reason": {"type": "string", "description": "修改原因说明"},
                "lease_token": {"type": "integer", "description": "受保护配置资产必须传入的锁令牌"},
                "is_temporary": {"type": "boolean", "description": "显式标记为临时垃圾文件", "default": False},
                "ttl_hours": {"type": "integer", "description": "临时文件建议保留小时数", "default": 24}
            },
            "required": ["path", "content", "reason"]
        }
    },
    {
        "name": "hub_delete_file",
        "description": "受控删除指定文件或目录，受保护资源强制校验锁并记录审计",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要删除的文件或目录绝对路径"},
                "reason": {"type": "string", "description": "删除原因说明"},
                "lease_token": {"type": "integer", "description": "受保护配置资产必须传入的锁令牌"}
            },
            "required": ["path", "reason"]
        }
    },
    {
        "name": "hub_cleanup_temp",
        "description": "扫描并安全批量清理标记为临时且已过期的垃圾文件",
        "inputSchema": {
            "type": "object",
            "properties": {
                "older_than_hours": {"type": "integer", "description": "清理超过多少小时未改动的临时文件", "default": 24}
            }
        }
    },
    {
        "name": "hub_execute_command",
        "description": "严格白名单受控执行系统诊断与审计运维命令，无论成败无条件触发状态比对",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "前缀白名单允许的安全命令（如 df, ps, docker logs 等）"},
                "reason": {"type": "string", "description": "执行该命令的意图说明"},
                "timeout_seconds": {"type": "integer", "description": "执行超时时间", "default": 30}
            },
            "required": ["command", "reason"]
        }
    },
    {
        "name": "hub_register_asset",
        "description": "向 CMDB 注册新资产（容器、服务、文件、记忆库），显式声明 lock_required",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "资产唯一键，如 'service:api', 'memory:core'"},
                "category": {"type": "string", "enum": ["docker", "systemd", "cron", "config_file", "web_app", "memory", "network"], "description": "资产分类"},
                "name": {"type": "string", "description": "易读名称"},
                "description": {"type": "string", "description": "业务用途与职责说明"},
                "endpoints": {"type": "array", "items": {"type": "string"}, "description": "关联端口或通信地址"},
                "configs": {"type": "array", "items": {"type": "string"}, "description": "关联的核心配置文件路径列表"},
                "lock_required": {"type": "boolean", "description": "是否强制要求租约锁保护才能写入", "default": False}
            },
            "required": ["key", "category", "name", "description"]
        }
    },
    {
        "name": "hub_get_overview",
        "description": "获取由 AI 深度编译的系统权威全局架构大盘（SERVER_AGENTS.md）",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "hub_rebuild_overview",
        "description": "触发配置的 AI 模型重新对全服真实资产进行全量深度总结与落盘",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "触发重新编译的原因说明", "default": "agent requested rebuild"}
            }
        }
    },
    {
        "name": "hub_query_assets",
        "description": "查询 CMDB 资产图谱，支持按分类检索、模糊搜索与仅看漂移资产",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "可选过滤分类"},
                "query": {"type": "string", "description": "关键词搜索名称或描述"},
                "show_drift_only": {"type": "boolean", "description": "是否仅列出实测态与期望态脱节的漂移资产", "default": False}
            }
        }
    },
    {
        "name": "hub_get_status",
        "description": "秒级获取系统 CPU、内存、存储负载及资产健康分类概览",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "hub_query_audit_logs",
        "description": "全维度多条件复合检索全端 Agent 操作历史流水",
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "起始时间 (ISO8601 或相对时间)"},
                "until": {"type": "string", "description": "截止时间"},
                "agent_id": {"type": "string", "description": "过滤指定 Agent ID"},
                "target": {"type": "string", "description": "过滤操作目标路径/服务 (支持 * 通配)"},
                "action_type": {"type": "string", "description": "过滤操作类型"},
                "status": {"type": "string", "enum": ["SUCCESS", "FAILED", "REJECTED"], "description": "过滤执行状态"},
                "is_temporary": {"type": "boolean", "description": "是否仅看临时垃圾文件"},
                "keyword": {"type": "string", "description": "意图理由或输出摘要模糊关键词"},
                "limit": {"type": "integer", "description": "返回数量，默认 20", "default": 20}
            }
        }
    },
    {
        "name": "hub_issue_agent_token",
        "description": "【管理员专享】为新 Agent 注册身份并签发专属受控 Bearer Token",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "要注册的 Agent 唯一标识，例如 'desktop:vscode' 或 'server:cron'"}
            },
            "required": ["agent_id"]
        }
    },
    {
        "name": "hub_revoke_agent_token",
        "description": "【管理员专享】一键吊销废除指定 Agent 的访问凭据 Token",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "要吊销的 Agent 唯一标识"}
            },
            "required": ["agent_id"]
        }
    }
]

ADMIN_ONLY_TOOL_NAMES = {"hub_issue_agent_token", "hub_revoke_agent_token"}


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


async def run_server():
    init_db()
    server = await asyncio.start_server(handle_client, config.host, config.port)
    print(f"🚀 Server Agents Gateway listening on {config.host}:{config.port} ...")
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