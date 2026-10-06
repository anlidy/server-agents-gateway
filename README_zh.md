# Server Agents Gateway

**让多个 AI agent 共用一台 Linux 服务器，而且你清楚每个 agent 干了什么。**

[![test](https://github.com/anlidy/server-agents-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/anlidy/server-agents-gateway/actions/workflows/test.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20Streamable%20HTTP-orange.svg)](https://modelcontextprotocol.io/)

[English](README.md) | **简体中文**

手机上的助手、电脑上的 Claude Code、Cursor、定时任务，都想到同一台 VPS 上干活。给每个 agent 发一把 SSH key 的话，谁执行了什么没有记录，删错了没法撤销，agent 之间也没法配合。

SAG 是跑在这台机器上的一个 MCP 服务。每个 agent 用自己的 token 接入，拿到一个真 shell。每条命令、每次文件改动、每条消息和任务变更都会记录下来，失败的调用也记，删掉的文件先进回收站。agent 共享一篇 markdown 写的服务器画像，还能互相发消息、交接任务。

单个 Python 进程，只用标准库。版本 **2.1.3**。

```mermaid
flowchart LR
    P["手机助手"] --> G
    C["Claude Code / Cursor"] --> G
    B["定时任务、机器人"] --> G
    subgraph host["你的 Linux 服务器"]
        G["SAG<br/>每个 agent 一个 token"] --> SH["bash -lc"]
        G --> AU[("审计日志<br/>SQLite")]
        G --> TR["回收站"]
        G --> MS["收件箱和任务"]
        G --> MAP["SERVER_AGENTS.md<br/>共享画像 + 实时状态"]
    end
```

## 用起来是什么样

对本地网关的真实调用，有删减，路径缩短了：

```text
laptop:claude    → hub_shell  "echo 'worker_processes 4;' > app.conf && rm app.conf"
                 ← {"exit_code": 0, "trash_ids": ["ac41bf1b-…"], …}

laptop:claude    → hub_restore_file  {"trash_id": "ac41bf1b-…"}
                 ← {"status": "RESTORED", "path": "/srv/play/app.conf"}

phone:assistant  → hub_send_message  {"to": "laptop:claude", "subject": "nginx",
                                      "body": "帮我看看 app.conf 怎么没了？"}

laptop:claude    → hub_list_dir  {"path": "/srv/play"}          # 随便哪个工具
                 ← {"entries": [...]}
                 ← [SAG] 你有 1 条未读消息（最新来自 phone:assistant：nginx），用 hub_inbox 查看。

phone:assistant  → hub_query_audit_logs  {"limit": 5}
                 ← [{"agent_id": "laptop:claude", "tool_name": "hub_shell",
                     "target": "echo 'worker_processes 4;' > app.conf && rm app.conf",
                     "trash_id": "ac41bf1b-…", "exit_code": 0, …}, …]
```

`rm` 是在 shell 里真敲的，文件却进了回收站。MCP 没法可靠地主动推送，所以手机 agent 发的消息，是附在电脑 agent 下一次工具调用的返回里送到的。

## 为什么不直接用 SSH

| | 每个 agent 一把 SSH key | SAG |
| :--- | :--- | :--- |
| 谁干了什么 | 看 shell 历史，还得它没被清掉 | 每条命令、每次文件改动、每次失败的调用都记：哪个 agent、什么命令、必填的 `reason`、完整 stdout/stderr、文件 diff |
| `rm` 删错了 | 没了 | 进回收站，按 id 还原，保留 30 天 |
| 这台机器上跑着什么 | 每个 agent 自己重新摸一遍 | 共享一篇 `SERVER_AGENTS.md`，状态区由网关自动刷新 |
| agent 之间配合 | 在 `/tmp` 里留纸条 | 收件箱、线程、已读回执、任务交接 |
| 手机和网页端 agent | 要 SSH 客户端和密钥 | 任何 MCP 客户端，走 HTTPS |
| 日志里的密钥 | agent 打印了什么就留什么 | token 和 API key 进审计前打码 |

## 它是什么，不是什么

SAG 面向的是**一台个人服务器，上面跑的都是你信任的 agent**，通常全是你自己的。它给你的是可追溯和可撤销，不是隔离。

- **不是沙箱。** 网关以 root 运行，systemd 单元不带 `ProtectSystem` / `ProtectHome` / `PrivateTmp`。`hub_shell` 就是 root shell，能改 `/etc`、`/usr`、`/root`，能装服务、改 systemd，`/tmp` 和你的 SSH 会话是同一个。这是有意的：个人服务器上 agent 要真正干活，绕道 SSH 反而更不可控。**任何一个 token 泄露，就等于这台服务器的 root 泄露。**
- **审计不防篡改。** 有 root 的 agent 可以通过 `hub_shell` 直接改 SQLite 文件。审计日志是互相配合的 agent 之间的"黑匣子"，不是对付恶意 agent 的证据。需要防篡改的话，把数据库同步到别的机器。
- **撤销不完整。** 回收站兜得住文件工具的覆盖、局部替换、删除，以及 `hub_shell` 命令行里直接写的 `rm`（软链接只移走链接本身）。`mv`、`>` 重定向、`sed -i`、`/bin/rm`、脚本和子进程里的 `rm` 都是真删真改。
- **不是生产控制面。** v1 有命令白名单和锁，放在个人服务器上主要是碍事，v2 就去掉了，见 [docs/v2.md](docs/v2.md)。

唯一强制的一条是自保：文件工具和 `rm` 包装器不碰 `data/`（审计库、回收站）和 `.env`。

保留的安全网：

- **审计**：每条命令、每次文件改动，以及每次失败的调用都写 SQLite（命令、stdout/stderr、diff），可回放；
- **回收站**：见上；
- **脱敏**：token、Bearer 头、常见 API key 进审计前打码（`sag/audit_redact.py`）；
- **自保**：见上。

建议：

1. 只给你信任、且确实需要改机器的 agent 签发 token，一端一个，不共用；
2. 不用的 agent 立刻 `hub_revoke_agent_token`；
3. 公网只经 Cloudflare Tunnel 暴露，不要在防火墙放行 4180；
4. 定期用 `hub_query_audit_logs` 看一眼谁做了什么。

## Agent 协作

agent 之间要说话（提问、回答、交接、"我改了 X，你看一下 Y"），用 `hub_send_message`，**不要**在服务器上建个 md 文件互相留言。服务器的长期事实（有什么服务、怎么重启）才写进 `SERVER_AGENTS.md`。

- **收件人** `to`：具体 agent_id（`mobile:xiaoyao`）、`*`（除自己外所有 agent）、前缀 `wsl:*`、组 `@ops`，可用逗号写多个。发送时按当时 ACTIVE 的 agent 展开，之后新签发的 agent 看不到旧广播。
- **线程**：第一条消息的 id 就是 `thread_id`。`hub_reply` 默认只回原发件人，`reply_all=true` 带上其他收件人；`hub_send_message` 传 `thread_id` 也能接着聊。
- **已读**：每个收件人单独记录 `read_at`。`hub_inbox` 默认只列未读、正文只给预览、不改已读状态；`hub_read_message` 或 `hub_inbox(thread_id=…)` 看全文并标记已读。
- **提醒**：有未读时，**其他工具**的返回结果里会多一个 content 项，就是上面演示里那行 `[SAG] 你有 N 条未读消息…`。原来的第一项 JSON 不变。
- **任务**：`hub_create_task` 建任务并默认通知指派人（没指派就通知所有人）；`hub_update_task` 的 `action` 为 `claim` / `release` / `done` / `cancel` / `reopen` / `comment`，每次变化都会在任务线程里通知创建者和负责人。
- **身份和审计**：发件人取自 token，不能伪造。发送、回复、任务变更都写审计，正文按同样规则脱敏；消息表里存的是原文。

```json
{"name": "hub_create_task", "arguments": {"title": "给笔记应用加每日备份", "assignee": "laptop:claude"}}
{"name": "hub_update_task", "arguments": {"task_id": "t_…", "action": "done", "result": "见 /etc/cron.d/notes-backup"}}
```

## 工具

| 工具 | 作用 |
| :--- | :--- |
| `hub_shell` | `bash -lc`，`command` 和 `reason` 必填。命令里直接写的 `rm` 进回收站；子进程和 `/bin/rm` 是真删。输出上限 2MiB。后台任务要重定向输出（`nohup cmd >log 2>&1 &`），否则这次调用会一直等到超时。 |
| `hub_read_file` / `hub_write_file` / `hub_patch_file` / `hub_delete_file` | 文本文件。覆盖、局部替换、删除都先把旧版本放进回收站。读文件一次最多返回 2MiB 的整行，超出从 `next_offset` 接着读；管道和设备文件不读。 |
| `hub_list_dir` / `hub_mkdir` | 列目录；mkdir -p。 |
| `hub_list_trash` / `hub_restore_file` | 按 id 还原，30 天过期。`overwrite=true` 会覆盖现在的内容（现有内容先进回收站），所以覆盖也能撤销。 |
| `hub_get_overview` / `hub_rebuild_overview` | 读 `SERVER_AGENTS.md`；rebuild 只刷新状态区。 |
| `hub_get_status` | 负载、内存、磁盘、失败单元、服务探活。 |
| `hub_query_audit_logs` / `hub_get_audit_event` | 事件列表 vs 完整的 stdout/stderr/diff。 |
| `hub_list_agents` | 已签发的 agent、最近活跃时间、分组（不含 token）。 |
| `hub_send_message` / `hub_reply` | 发消息给 agent、`*`、`前缀:*` 或 `@组`；在同一线程回复。 |
| `hub_inbox` / `hub_read_message` / `hub_mark_read` | 收件箱（默认只看未读、只给预览）、读全文并标已读、批量标已读。 |
| `hub_set_group` | 定义收件组，发送时写 `@组名`。 |
| `hub_create_task` / `hub_list_tasks` / `hub_update_task` | 任务交接：open → claimed → done / cancelled，附结果。 |
| `hub_issue_agent_token` / `hub_revoke_agent_token` | 仅 root admin。 |

## 快速开始

### 先在本机试

建议先用普通用户跑，这样 `hub_shell` 只有你这个用户的权限。

```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway
cp .env.example .env                           # 可以把 GATEWAY_SHELL_CWD 指到一个临时目录
python3 server.py issue-admin admin:root       # 打印 admin token
python3 server.py issue-token laptop:claude    # 打印 operator token
python3 server.py                              # 监听 127.0.0.1:4180
```

接入 Claude Code：

```bash
claude mcp add --transport http sag http://127.0.0.1:4180/mcp --header "Authorization: Bearer sag_laptop_claude_..."
```

或者任何 MCP 客户端：

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

旧的 SSE 传输仍在 `/sse`。跑测试：`python3 -m unittest discover -s tests`。

### 部署到服务器

1. 克隆到 `/opt/server-agents-gateway`，装上 [systemd 单元](deploy/server-agents-gateway.service)。它以 root 运行，是有意的。
2. 只通过 Cloudflare Tunnel 暴露，前面加 Access，见 [deploy/DOMAIN_INGRESS.md](deploy/DOMAIN_INGRESS.md)。不要在防火墙放行 4180。
3. 第一次启动会写 `SERVER_AGENTS.md` 骨架。人写 `## Host`。上新服务就在 `## Inventory` 下加一个 `###` 小节，写 `- probe:` 行（`systemd <unit>`、`docker <容器>`、`http <url>`、`tcp <host:port>`），网关会刷新 `sag-status` 标记之间的状态表。谁改拓扑谁改那一节。

### 命令行

在服务器上以 root 运行：

| 命令 | 作用 |
| :--- | :--- |
| `python3 -m sag issue-admin <agent_id>` | 签发 root admin token。 |
| `python3 -m sag issue-token <agent_id>` | 签发 operator token。admin 也可以调 `hub_issue_agent_token`。 |
| `python3 -m sag backup-db --label <版本>` | 升级前备份 `gateway.db`，只留最新的几份（`GATEWAY_DB_BACKUP_KEEP`，默认 1）。 |
| `python3 -m sag purge-trash --deleted-by <agent_id> [--yes]` | 提前清空回收站条目，不加 `--yes` 只预览。故意不做成 MCP 工具，agent 没法自己清掉安全网。 |

### 配置

`.env`（见 [.env.example](.env.example)）：

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

## 实际在用

作者在自己的 VPS 上用 SAG 跑着七个 agent：安卓上的助手（[Operit](https://github.com/AAswordman/Operit)）、电脑上和服务器本机上的 Claude Code、Cursor、Hermes Agent，以及两个命令行 agent。它们互相发消息、认领任务，一起维护服务器画像。

2.1 以来的修复大多来自真实事故。比如 2.1.2 不再把 `rm` 包装器导出给子进程，起因是一次 `apt upgrade` 时，cloudflared 的卸载脚本把刚装好的新二进制挪进了回收站。设计说明和变更记录见 [docs/v2.md](docs/v2.md)。

## 目录

```
sag/                 # 应用代码
wrappers/rm          # rm() 的目标（只管最外层 shell）→ 回收站
tests/               # 单元测试
docs/v2.md           # 设计和变更记录
deploy/              # systemd 单元、入口配置
server.py            # `python3 server.py`（systemd 用）
data/  .env  SERVER_AGENTS.md   # 运行时文件，留在仓库根
```

## 许可证

[Apache License 2.0](LICENSE)。
