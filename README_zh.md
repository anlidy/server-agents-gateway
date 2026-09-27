# Server Agents Gateway

个人 Linux 服务器上的多 Agent 协作层。MCP over Streamable HTTP（`/mcp`，旧的 `/sse` 仍保留）。Python 3.10+，仅标准库。

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

[English](README.md) | **简体中文**

版本 **2.3.0**。设计说明：[docs/v2.md](docs/v2.md)。

## 做什么

手机、桌面 IDE、定时任务共用一台机器时，网关负责：

1. **身份**：每端独立 Bearer token。
2. **痕迹**：每次工具调用写入 SQLite，可回放。
3. **手**：真 shell（`bash -lc`）和读/写/删；删除进回收站。
4. **画像**：`SERVER_AGENTS.md`。库存人写，状态围栏网关刷。
5. **协作**：agent 之间原生的消息和任务交接，不用再靠在服务器上写文档留言。

防出事靠审计和回收站，不靠命令白名单。

## 权限与风险（请先读）

网关以 **root** 运行，systemd 单元**不带任何沙箱**（没有 `ProtectSystem` / `ProtectHome` / `PrivateTmp`）：

- `hub_shell` 和文件工具能改 `/etc`、`/usr`、`/root`，能装服务、改 systemd 单元；
- `/tmp` 与宿主、SSH 会话是同一个。

这是有意的：个人服务器上 agent 要真正干活，绕道 SSH 反而更不可控。保留的安全网：

- **审计**：每次改机器的调用都写 SQLite（命令、stdout/stderr、diff），可回放；
- **回收站**：`hub_delete_file`、覆盖写、`hub_patch_file`、shell 里的 `rm` 都先进回收站（`/bin/rm` 仍是真删）；
- **脱敏**：token、Bearer 头、常见 API key 进审计前打码（`sag/audit_redact.py`）；
- **自保**：文件工具和 `rm` 包装器不碰 `data/`（数据库、回收站）和 `.env`，避免误删审计本身。

**风险：任何一个 token 泄露，等于这台服务器的 root 泄露。** 建议：

1. 只给你信任、且确实需要改机器的 agent 签发 token，一端一个，不共用；
2. 不用的 agent 立刻 `hub_revoke_agent_token`；
3. 公网只经 Cloudflare Tunnel 暴露，不要在防火墙放行 4180；
4. 定期用 `hub_query_audit_logs` 看一眼谁做了什么。

## 工具

| 工具 | 作用 |
| :--- | :--- |
| `hub_shell` | `bash -lc`。`rm` 进回收站；`/bin/rm` 仍是真删。 |
| `hub_read_file` / `hub_write_file` / `hub_patch_file` / `hub_delete_file` | 文本文件。覆盖/局部替换/删除先进回收站。 |
| `hub_list_dir` / `hub_mkdir` | 列目录；mkdir -p。 |
| `hub_list_trash` / `hub_restore_file` | 按 id 还原，30 天过期。 |
| `hub_get_overview` / `hub_rebuild_overview` | 读文档；rebuild 只刷新状态围栏。 |
| `hub_get_status` | 负载、内存、磁盘、失败单元、探活。 |
| `hub_query_audit_logs` / `hub_get_audit_event` | 事件列表 vs 完整输出。 |
| `hub_list_agents` | 已签发的 agent、最近活跃时间、分组（不含 token）。 |
| `hub_send_message` / `hub_reply` | 发消息 / 在同一线程回复。发件人取自 token，不能伪造。 |
| `hub_inbox` / `hub_read_message` / `hub_mark_read` | 收件箱（默认只看未读）、读全文并标已读、批量标已读。 |
| `hub_set_group` | 定义收件组，发送时写 `@组名`。 |
| `hub_create_task` / `hub_list_tasks` / `hub_update_task` | 任务交接：open → claimed → done / cancelled，附结果。 |
| `hub_issue_agent_token` / `hub_revoke_agent_token` | 仅 root admin。 |

## Agent 协作

agent 之间要说话（提问、回答、交接、"我改了 X，你看一下 Y"），用 `hub_send_message`，**不要**在服务器上建个 md 文件互相留言。服务器的长期事实（有什么服务、怎么重启）才写进 `SERVER_AGENTS.md`。

- **收件人** `to`：具体 agent_id（`mobile:xiaoyao`）、`*`（除自己外所有 agent）、前缀 `wsl:*`、组 `@ops`，可用逗号写多个。发送时按当时 ACTIVE 的 agent 展开，之后新签发的 agent 看不到旧广播。
- **线程**：第一条消息的 id 就是 `thread_id`。`hub_reply` 默认只回原发件人，`reply_all=true` 带上其他收件人；`hub_send_message` 传 `thread_id` 也能接着聊。
- **已读**：每个收件人单独记录 `read_at`。`hub_inbox` 默认只列未读、正文只给预览、不改已读状态；`hub_read_message` 或 `hub_inbox(thread_id=…)` 看全文并标记已读。
- **提醒**：MCP 不能可靠地主动推送。有未读时，**其他工具**的返回结果里会多一个 content 项：`[SAG] 你有 N 条未读消息（最新来自 …），用 hub_inbox 查看。`原来的第一项 JSON 不变。
- **任务**：`hub_create_task` 建任务并默认通知指派人（没指派就通知所有人）；`hub_update_task` 的 `action` 为 `claim` / `release` / `done` / `cancel` / `reopen` / `comment`，每次变化都会在任务线程里通知创建者和负责人。
- **审计**：发送、回复、任务变更都写审计，正文按同样规则脱敏；消息表里存的是原文。

示例：

```json
{"name": "hub_send_message", "arguments": {"to": "mobile:xiaoyao", "subject": "operit 的三个问题", "body": "1. …\n2. …"}}
{"name": "hub_inbox", "arguments": {}}
{"name": "hub_reply", "arguments": {"message_id": "m_1a2b3c4d5e6f", "body": "第 2 点已改好"}}
{"name": "hub_create_task", "arguments": {"title": "给 xiaoyao-memory 加每日备份", "assignee": "wsl:claude"}}
{"name": "hub_update_task", "arguments": {"task_id": "t_…", "action": "done", "result": "见 /etc/cron.d/xm-backup"}}
```

## claude.ai 连接器（OAuth）

claude.ai 的自定义连接器（网页 / 桌面 / 手机 App）只支持 OAuth。设置 `GATEWAY_PUBLIC_URL` 后网关自带一个最小的 OAuth 2.1 授权服务：动态注册、PKCE，授权页不登录账号，而是填 root 在服务器上用 `python3 -m sag oauth-pair <agent_id>` 生成的一次性配对码。令牌挂在这个 agent 上（一律 operator）。公网域名上只收 OAuth 令牌，不收静态 `sag_` token。详见 [docs/claude-ai.md](docs/claude-ai.md)。

## 快速开始

```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway
cp .env.example .env
python3 server.py issue-admin admin:root
python3 server.py          # 或 python3 -m sag
python3 test_gateway.py
```

第一次启动会写 `SERVER_AGENTS.md` 骨架。人写 `## Host`。上新服务就在 `## Inventory` 加 `###` 小节（`- probe:` / `- path:` / `- url:`）。谁改拓扑谁改那一节。

目录：代码在 `sag/`，测试在 `tests/`，根目录只留 `server.py` 入口。`data/`、`.env`、`SERVER_AGENTS.md` 仍在仓库根。

部署：[deploy/server-agents-gateway.service](deploy/server-agents-gateway.service)、[deploy/DOMAIN_INGRESS.md](deploy/DOMAIN_INGRESS.md)。

## 许可证

[Apache License 2.0](LICENSE)。
