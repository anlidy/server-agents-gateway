# Server Agents Gateway

**Let several AI agents share one Linux server, and know exactly which one did what.**

[![test](https://github.com/anlidy/server-agents-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/anlidy/server-agents-gateway/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20Streamable%20HTTP-orange.svg)](https://modelcontextprotocol.io/)

**English** | [简体中文](README_zh.md)

The assistant on your phone, Claude Code on your laptop, Cursor, a cron bot: they all want to work on the same VPS. Handing each one an SSH key leaves you with no record of who ran what, no undo, and no way for the agents to coordinate.

SAG is a single MCP server you run on that box. Every agent connects with its own token and gets a real shell. Every command, file change, message and task update is recorded, and so is every call that fails. Deleted files go to a recycle bin. The agents share one markdown map of the server and can message each other or hand off tasks.

One Python process, standard library only. Version **2.1.3**.

```mermaid
flowchart LR
    P["Phone assistant"] --> G
    C["Claude Code / Cursor"] --> G
    B["Cron jobs, bots"] --> G
    subgraph host["Your Linux server"]
        G["SAG<br/>one token per agent"] --> SH["bash -lc"]
        G --> AU[("audit log<br/>SQLite")]
        G --> TR["recycle bin"]
        G --> MS["inbox and tasks"]
        G --> MAP["SERVER_AGENTS.md<br/>shared map + live status"]
    end
```

## What a session looks like

Real calls against a local gateway, trimmed and with paths shortened:

```text
laptop:claude    → hub_shell  "echo 'worker_processes 4;' > app.conf && rm app.conf"
                 ← {"exit_code": 0, "trash_ids": ["ac41bf1b-…"], …}

laptop:claude    → hub_restore_file  {"trash_id": "ac41bf1b-…"}
                 ← {"status": "RESTORED", "path": "/srv/play/app.conf"}

phone:assistant  → hub_send_message  {"to": "laptop:claude", "subject": "nginx",
                                      "body": "Can you check why app.conf disappeared?"}

laptop:claude    → hub_list_dir  {"path": "/srv/play"}          # any tool call
                 ← {"entries": [...]}
                 ← [SAG] 你有 1 条未读消息（最新来自 phone:assistant：nginx），用 hub_inbox 查看。

phone:assistant  → hub_query_audit_logs  {"limit": 5}
                 ← [{"agent_id": "laptop:claude", "tool_name": "hub_shell",
                     "target": "echo 'worker_processes 4;' > app.conf && rm app.conf",
                     "trash_id": "ac41bf1b-…", "exit_code": 0, …}, …]
```

The `rm` was a real shell command, yet the file landed in the trash. The phone agent's message reached the laptop agent as an extra item on its next tool result, because MCP has no reliable server push. That notice is currently in Chinese: "You have 1 unread message (latest from phone:assistant: nginx), see hub_inbox."

## Why not just SSH?

| | One SSH key per agent | SAG |
| :--- | :--- | :--- |
| Who did what | Shell history, if it survived | Every command and file change, and every failed call: agent, command, required `reason`, full stdout/stderr, file diff |
| A bad `rm` | Gone | Recycle bin, restore by id, 30 days |
| "What runs on this box?" | Each agent rediscovers it | One shared `SERVER_AGENTS.md`, status section kept fresh by the gateway |
| Agents coordinating | Notes left in `/tmp` | Inbox, threads, read receipts, task handoff |
| Phone and web agents | Need an SSH client and a key | Any MCP client over HTTPS |
| Leaked secrets in logs | Whatever the agent printed | Tokens and API keys redacted before they reach the audit log |

## What this is, and what it isn't

SAG is for **a personal server shared by agents you trust**, usually all your own. It gives you accountability and undo. It does not give you containment.

- **Not a sandbox.** The gateway runs as root and `hub_shell` is a root shell. It can write `/etc`, manage systemd, and shares `/tmp` with your SSH sessions. **A leaked token is a leaked root shell.** Issue one token per client and revoke the ones you no longer use.
- **Not a tamper-proof audit log.** An agent with root can edit the SQLite file through `hub_shell`. The log is a flight recorder for cooperating agents, not evidence against a hostile one. If you need that, ship the database off the box.
- **Not complete undo.** The trash catches the file tools (overwrite, patch, delete) and an `rm` typed directly in a `hub_shell` command. `mv`, `>` redirection, `sed -i`, `/bin/rm`, and `rm` inside scripts or child processes are real.
- **Not a production control plane.** v1 had command allowlists and locks. On a personal server they mostly got in the way, so v2 dropped them. See [docs/v2.md](docs/v2.md).

The one thing that is enforced: the file tools and the `rm` wrapper refuse to touch `data/` (audit DB, trash) and `.env`.

## Agent collaboration

Agents talk with `hub_send_message` instead of leaving notes in files. Long-lived facts about the server (what runs where, how to restart it) belong in `SERVER_AGENTS.md`.

- **Recipients** (`to`): an agent id (`phone:assistant`), `*` (everyone but you), a prefix (`laptop:*`), or a group (`@ops`); comma-separated. Expanded against active agents at send time.
- **Threads**: the first message's id is the `thread_id`. `hub_reply` answers the sender. `reply_all=true` includes everyone.
- **Read state** is per recipient. `hub_inbox` lists unread messages with previews and doesn't mark anything. `hub_read_message` or `hub_inbox(thread_id=…)` shows the full text and marks it read.
- **Notification**: while an agent has unread mail, every other tool result carries a second content item with the notice shown above. The first item is unchanged.
- **Tasks**: `hub_create_task` notifies the assignee (or everyone). `hub_update_task` actions are `claim` / `release` / `done` / `cancel` / `reopen` / `comment`. Each change is posted to the task's thread.
- **Sender identity** comes from the token and can't be spoofed. Messages and task changes are audited with the same redaction.

```json
{"name": "hub_create_task", "arguments": {"title": "Add a daily backup for the notes app", "assignee": "laptop:claude"}}
{"name": "hub_update_task", "arguments": {"task_id": "t_…", "action": "done", "result": "see /etc/cron.d/notes-backup"}}
```

## Tools

| Tool | Role |
| :--- | :--- |
| `hub_shell` | `bash -lc`. `command` and `reason` required. An `rm` typed in the command goes to the trash; child processes and `/bin/rm` delete for real. Output is capped at 2 MiB. Redirect the output of background jobs (`nohup cmd >log 2>&1 &`), or the call waits for them until the timeout. |
| `hub_read_file` / `hub_write_file` / `hub_patch_file` / `hub_delete_file` | Text files. Overwrite, patch and delete move the old version to the trash. A read returns at most 2 MiB of whole lines; continue from `next_offset`. Pipes and devices are refused. |
| `hub_list_dir` / `hub_mkdir` | List a directory; `mkdir -p`. |
| `hub_list_trash` / `hub_restore_file` | Restore by id. 30-day expiry. `overwrite=true` puts the item back over what is there now (which goes into the trash first), so an overwrite can be undone. |
| `hub_get_overview` / `hub_rebuild_overview` | Read `SERVER_AGENTS.md`; rebuild only refreshes the status section. |
| `hub_get_status` | Load, memory, disks, failed units, service probes. |
| `hub_query_audit_logs` / `hub_get_audit_event` | Event list vs. full stdout/stderr/diff. |
| `hub_list_agents` | Issued agents, last activity, groups (no tokens). |
| `hub_send_message` / `hub_reply` | Message an agent, `*`, `prefix:*` or `@group`; reply in thread. |
| `hub_inbox` / `hub_read_message` / `hub_mark_read` | Unread-first inbox with previews; full read marks read. |
| `hub_set_group` | Define a recipient group. |
| `hub_create_task` / `hub_list_tasks` / `hub_update_task` | Handoff: open → claimed → done / cancelled, with a result. |
| `hub_issue_agent_token` / `hub_revoke_agent_token` | Root admin only. |

## Quick start

### Try it locally

Run it as your normal user first: `hub_shell` then has only your permissions.

```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway
cp .env.example .env                           # optionally point GATEWAY_SHELL_CWD at a scratch dir
python3 server.py issue-admin admin:root       # prints the admin token
python3 server.py issue-token laptop:claude    # prints an operator token
python3 server.py                              # listens on 127.0.0.1:4180
```

Connect Claude Code:

```bash
claude mcp add --transport http sag http://127.0.0.1:4180/mcp --header "Authorization: Bearer sag_laptop_claude_..."
```

Or any MCP client:

```json
{
  "mcpServers": {
    "sag": {
      "url": "http://127.0.0.1:4180/mcp",
      "headers": { "Authorization": "Bearer sag_laptop_claude_..." }
    }
  }
}
```

The legacy SSE transport is still served at `/sse`. Run the tests with `python3 -m unittest discover -s tests`.

### Deploy on a server

1. Clone to `/opt/server-agents-gateway` and install [the systemd unit](deploy/server-agents-gateway.service). It runs as root, on purpose.
2. Expose it only through a Cloudflare Tunnel with Access in front, as described in [deploy/DOMAIN_INGRESS.md](deploy/DOMAIN_INGRESS.md). Never open port 4180 in the firewall.
3. On first start the gateway writes a `SERVER_AGENTS.md` skeleton. Fill in `## Host`. Add a `###` section under `## Inventory` for each service with `- probe:` lines (`systemd <unit>`, `docker <container>`, `http <url>`, `tcp <host:port>`). The gateway keeps the status table between the `sag-status` markers up to date. Whoever changes the topology updates the inventory.

### CLI

Run as root on the server:

| Command | Does |
| :--- | :--- |
| `python3 -m sag issue-admin <agent_id>` | Issue the root admin token. |
| `python3 -m sag issue-token <agent_id>` | Issue an operator token. Admins can also call `hub_issue_agent_token`. |
| `python3 -m sag backup-db --label <version>` | Back up `gateway.db` before an upgrade and keep only the newest backups (`GATEWAY_DB_BACKUP_KEEP`, default 1). |
| `python3 -m sag purge-trash --deleted-by <agent_id> [--yes]` | Empty trash items early. Dry run unless `--yes`. Deliberately not an MCP tool, so agents can't empty their own safety net. |

### Configuration

`.env` (see [.env.example](.env.example)):

```
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=4180
GATEWAY_DB_PATH=./data/gateway.db
ROOT_ADMIN_AGENT_ID=admin:root
GATEWAY_SHELL_CWD=
GATEWAY_SHELL_TIMEOUT_SECONDS=120
GATEWAY_SHELL_TIMEOUT_MAX=3600
GATEWAY_AUDIT_BODY_MAX_BYTES=2097152
GATEWAY_READ_MAX_BYTES=2097152
GATEWAY_MAX_REQUEST_BYTES=16777216
GATEWAY_MAX_WORKERS=64
GATEWAY_TRASH_RETENTION_DAYS=30
RECONCILE_INTERVAL_SECONDS=60
```

## In practice

The author runs SAG on a personal VPS with seven agents: an Android assistant ([Operit](https://github.com/AAswordman/Operit)), Claude Code on a PC and on the server itself, Cursor, Hermes Agent, and a couple of CLI agents. They message each other, claim tasks, and keep the server map current.

Most fixes since 2.1 came from real incidents. For example, 2.1.2 stopped exporting the `rm` wrapper to child processes after it moved cloudflared's freshly installed binary into the trash during an `apt upgrade`. Design notes and the change history are in [docs/v2.md](docs/v2.md) (Chinese).

## Layout

```
sag/                 # application package
wrappers/rm          # rm() target (top-level shell only) → recycle bin
tests/               # unit tests
docs/v2.md           # design and change history
deploy/              # systemd unit, ingress guide
server.py            # `python3 server.py` (systemd)
data/  .env  SERVER_AGENTS.md   # runtime, stay at repo root
```

## License

[Apache License 2.0](LICENSE).
