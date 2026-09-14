# Server Agents Gateway

A personal-server hub for multiple AI agents. MCP over HTTP/SSE. Python 3.10+, stdlib only.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

**English** | [简体中文](README_zh.md)

Version **2.0.0**. Design notes: [docs/v2.md](docs/v2.md).

## What it does

Several agents (phone, desktop IDE, a cron job) share one Linux box. The gateway:

1. **Identifies** each agent with its own bearer token.
2. **Records** every tool call (command, files, output) in SQLite.
3. **Hands** them a real shell (`bash -lc`) plus read/write/delete tools. Deletes go to a recycle bin.
4. **Keeps** a shared markdown map (`SERVER_AGENTS.md`): you write Inventory, the gateway refreshes the status fence.

Safety is audit + trash, not a command allowlist.

## Tools

| Tool | Role |
| :--- | :--- |
| `hub_shell` | `bash -lc`. `rm` is wrapped into trash; `/bin/rm` is a real delete. |
| `hub_read_file` / `hub_write_file` / `hub_patch_file` / `hub_delete_file` | Text files. Overwrite/patch/delete → recycle bin. |
| `hub_list_dir` / `hub_mkdir` | List a directory; mkdir -p. |
| `hub_list_trash` / `hub_restore_file` | Restore by id. 30-day expiry. |
| `hub_get_overview` / `hub_rebuild_overview` | Read `SERVER_AGENTS.md`; rebuild only refreshes the status fence. |
| `hub_get_status` | Load, memory, disks, failed units, probes. |
| `hub_query_audit_logs` / `hub_get_audit_event` | Event list vs full stdout/stderr. |
| `hub_issue_agent_token` / `hub_revoke_agent_token` | Root admin only. |

## Quick start

```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway
cp .env.example .env
python3 server.py issue-admin admin:root
python3 server.py          # or: python3 -m sag
python3 test_gateway.py
```

`.env` (additions on top of host/port/db/admin):

```
GATEWAY_SHELL_CWD=
GATEWAY_SHELL_TIMEOUT_SECONDS=120
GATEWAY_SHELL_TIMEOUT_MAX=3600
GATEWAY_AUDIT_BODY_MAX_BYTES=2097152
GATEWAY_TRASH_RETENTION_DAYS=30
RECONCILE_INTERVAL_SECONDS=60
```

MCP client:

```json
{
  "mcpServers": {
    "server-agents-gateway": {
      "url": "https://gateway.example.com/sse",
      "headers": {
        "Authorization": "Bearer sag_desktop_cursor_YOUR_TOKEN"
      }
    }
  }
}
```

Systemd unit: [deploy/server-agents-gateway.service](deploy/server-agents-gateway.service). Ingress: [deploy/DOMAIN_INGRESS.md](deploy/DOMAIN_INGRESS.md).

## Layout

```
sag/                 # application package
wrappers/rm          # PATH wrapper → recycle bin
tests/               # unit tests
docs/v2.md           # design
deploy/              # systemd + ingress notes
server.py            # `python3 server.py` (systemd)
test_gateway.py      # shim → tests/
data/  .env  SERVER_AGENTS.md   # runtime, stay at repo root
```

On first start the gateway writes a `SERVER_AGENTS.md` skeleton. Fill in `## Host`. Add `###` sections under `## Inventory` when you add services (`- probe: systemd caddy.service`, `- path:`, `- url:`). Who changes topology updates that section.

## License

[Apache License 2.0](LICENSE).
