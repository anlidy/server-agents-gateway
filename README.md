# Server Agents Gateway

A lightweight, zero-trust, deterministic multi-agent orchestration and safe execution gateway designed for Linux servers. Compatible with the Model Context Protocol (MCP).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

**English Documentation** | [简体中文文档](README_zh.md)

---

## 📖 Overview

When multiple heterogeneous AI agents (e.g., mobile agents, desktop IDEs like Cursor/Claude Code, and automated headless daemons) manage the same Linux server via raw SSH or unconstrained shells, critical operational challenges arise:
- **Information Silos**: One agent is unaware of configuration modifications or service restarts executed by another.
- **Concurrent Overwrites**: Competing agents modifying the same file or state simultaneously lead to silent regressions.
- **Control-Plane Escape**: Unrestricted shell access allows agents to bypass audit policies, destabilize running applications, or cause state drift.
- **Identity Spoofing**: Shared secrets and client-declared identity headers render audit logs unreliable.

**Server Agents Gateway** resolves these issues by acting as a single, hardened, deterministic control plane. It enforces per-agent zero-trust authentication, distributed fencing-token concurrency locks, a dual-state CMDB asset registry, strict command execution policies, and comprehensive multi-dimensional audit trails.

---

## ⚡ Key Architectural Features

1. **Tool-First Model Context Protocol (MCP) Design**
   - All capabilities are exposed exclusively as standardized MCP tools via HTTP/SSE and JSON-RPC 2.0 endpoints.
   - Zero reliance on client-side prompt templates or passive resource subscriptions, ensuring 100% compatibility across IDEs, CLI tools, and mobile runtimes.

2. **Zero-Trust Per-Agent Identity Verification**
   - Eliminates shared secrets and client-spoofed identity headers (`X-Agent-ID`).
   - Every connecting agent must provide an exclusive Bearer token. The gateway cryptographically validates the token against the credential database to securely derive the true `agent_id`. Supports granular per-token revocation.

3. **Deterministic Fencing-Token Concurrency Locks**
   - Critical configuration files and mutating service actions can be marked with `lock_required: 1`.
   - Modifying protected assets strictly requires a monotonically increasing `lease_token`.
   - Unlocked writes or expired-lease operations are physically rejected (`423 Locked` / `409 Conflict`), eliminating race conditions and late-arriving write collisions.

4. **Dual-State CMDB & Self-Healing Drift Detection**
   - Tracks both `desired_state` (control-plane intent) and `observed_state` (probed host reality).
   - Reconciles state continuously (default every 60s) and unconditionally in a `finally` block following command execution, immediately flagging out-of-band changes as `DRIFTED`.

5. **Allowlist-Only Shell Execution Sandbox**
   - Abandons easily bypassed regex blacklists in favor of a strict executable prefix allowlist (e.g., read-only diagnostics like `df`, `free`, `ps`, `docker logs`, and pre-audited scripts).
   - Blocks dynamic code execution (`bash -c`, `eval`, piped interpreters) to prevent control-plane tampering.

6. **Pluggable AI-Augmented Overview (Living Documentation)**
   - Automatically compiles and updates an authoritative `SERVER_AGENTS.md` overview by analyzing live CMDB assets and recent audit events.
   - Completely decoupled: works with any standard OpenAI-compatible API endpoint (DeepSeek, OpenAI, Gemini, OneAPI, local LLM proxies).
   - Operates strictly as a read-only explanatory layer without direct control-plane authority.

---

## 🛠️ MCP Tools Specification

The gateway provides 16 standard tools:

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `hub_acquire_lock` | `resource_key`, `reason`, `ttl_seconds?` | Acquire an exclusive lock on an asset; returns a monotonic `lease_token`. |
| `hub_renew_lock` | `resource_key`, `lease_token`, `ttl_seconds?` | Heartbeat renewal for active locks during extended tasks. |
| `hub_release_lock` | `resource_key`, `lease_token` | Release an active lock safely using the verified `lease_token`. |
| `hub_manage_service` | `service_type`, `name`, `action`, `reason`, `lease_token?` | Start, stop, or restart Docker or Systemd services with dynamic lock enforcement. |
| `hub_edit_file` | `path`, `content`, `reason`, `lease_token?`, `is_temporary?`, `ttl_hours?` | Atomically write/edit files with unified diff generation and dynamic lock enforcement. |
| `hub_delete_file` | `path`, `reason`, `lease_token?` | Safely remove files or directories with audit logging and lock verification. |
| `hub_cleanup_temp` | `older_than_hours?` | Scan and remove expired scratch/temporary files. |
| `hub_execute_command`| `command`, `reason`, `timeout_seconds?` | Execute allowlisted commands with unconditional post-execution state reconciliation. |
| `hub_register_asset` | `key`, `category`, `name`, `description`, `endpoints?`, `configs?`, `lock_required?` | Register a new asset into the CMDB with explicit lock requirements. |
| `hub_query_assets` | `category?`, `query?`, `show_drift_only?` | Search registered assets, configurations, and filter out-of-band state drifts. |
| `hub_get_status` | *none* | Retrieve real-time CPU, memory, storage utilization, and asset count summary. |
| `hub_query_audit_logs`| `since?`, `until?`, `agent_id?`, `target?`, `action_type?`, `status?`, `is_temporary?`, `keyword?`, `limit?` | Multi-dimensional query across full operational history. |
| `hub_get_overview` | *none* | Retrieve the compiled living architecture document (`SERVER_AGENTS.md`). |
| `hub_rebuild_overview`| `reason?` | Trigger the configured LLM to recompile the living system overview. |
| `hub_issue_agent_token`| `agent_id` | [Sole Admin Only] Register a new agent identity and issue an operator Bearer Token. |
| `hub_revoke_agent_token`| `agent_id` | [Sole Admin Only] Revoke access credentials for a specified agent. |

---

## 🚀 Quick Start

### 1. Requirements
- Linux (x86_64 or aarch64 / ARM64)
- Python 3.10+ (Standard library only; zero heavy third-party framework dependencies)
- SQLite3

### 2. Installation
```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway

# Copy sample configuration
cp .env.example .env
```

### 3. Configuration (`.env`)
```bash
# Network & Storage
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=4180
GATEWAY_DB_PATH=./data/gateway.db

# Configurable Root Admin (Sole Agent permitted to issue/revoke tokens online)
ROOT_ADMIN_AGENT_ID=admin:root

# Pluggable AI Model Provider (OpenAI Compatible)
AI_PROVIDER_ENABLED=true
AI_PROVIDER_BASE_URL=https://api.deepseek.com/v1
AI_PROVIDER_API_KEY=sk-your-api-key-here
AI_PROVIDER_MODEL=deepseek-chat
AI_PROVIDER_TIMEOUT_SECONDS=30

# Concurrency & Reconciliation
DEFAULT_LEASE_TTL_SECONDS=120
RECONCILE_INTERVAL_SECONDS=60
```

### 4. Issue Agent Tokens (Server CLI)
```bash
# 1. On server host: Issue the ROOT ADMIN token for your primary agent
python3 server.py issue-admin admin:root

# 2. Issue standard operator tokens (can also be issued online later by your root admin agent)
python3 server.py issue-token desktop:cursor
```

### 5. Start Gateway Service
```bash
python3 server.py
```

### 6. Run Self-Test Suite
```bash
python3 test_gateway.py
```

---

- [Deployment & Ingress Guide (Cloudflare Tunnel & Reverse Proxy)](deploy/DOMAIN_INGRESS.md)
- [Systemd Service Unit File](deploy/server-agents-gateway.service)

---

## 🔒 Production Deployment (Systemd & Cloudflare Tunnel)

### Systemd Service
Create `/etc/systemd/system/server-agents-gateway.service`:
```ini
[Unit]
Description=Server Agents Gateway Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/server-agents-gateway
ExecStart=/usr/bin/python3 /opt/server-agents-gateway/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now server-agents-gateway
```

### Client MCP Configuration (e.g., Cursor / Claude Desktop)
Add the server entry to your client configuration:
```json
{
  "mcpServers": {
    "server-agents-gateway": {
      "url": "https://gateway.example.com/sse",
      "headers": {
        "Authorization": "Bearer sag_desktop_cursor_YOUR_EXCLUSIVE_TOKEN"
      }
    }
  }
}
```

---

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).