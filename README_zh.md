# Server Agents Gateway

个人 Linux 服务器上的多 Agent 协作层。MCP over Streamable HTTP（`/mcp`，旧的 `/sse` 仍保留）。Python 3.10+，仅标准库。

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

[English](README.md) | **简体中文**

版本 **2.2.0**。设计说明：[docs/v2.md](docs/v2.md)。

## 做什么

手机、桌面 IDE、定时任务共用一台机器时，网关负责：

1. **身份**：每端独立 Bearer token。
2. **痕迹**：每次工具调用写入 SQLite，可回放。
3. **手**：真 shell（`bash -lc`）和读/写/删；删除进回收站。
4. **画像**：`SERVER_AGENTS.md`。库存人写，状态围栏网关刷。
5. **协作**：agent 之间原生的消息和任务交接，不用再靠在服务器上写文档留言。

防出事靠审计和回收站，不靠命令白名单。

## 权限与风险（请先读）

systemd 单元以 root 运行 SAG，本身不带沙箱（没有 `ProtectSystem` / `ProtectHome` / `PrivateTmp`）。**权限按 token 的角色分两级**，在操作系统层面生效：

| | admin（`role=admin`，如 `mobile:xiaoyao`） | operator（其他所有 agent） |
| :--- | :--- | :--- |
| 执行身份 | root | 普通 Unix 用户 `sag-operator`（主组 `sag-operators`） |
| `hub_shell` | 完整 root | 以 `sag-operator` 运行：`setpriv --no-new-privs`、清空附加组、干净的环境变量（HOME/PATH 等），默认 cwd 是它的 home |
| 文件工具 | root 直接做 | 在以 `sag-operator` 身份运行的子进程（`sag/opworker.py`）里做，能不能读写删由内核判定 |
| 可写 | 全部 | 自己的 home、`/tmp`、admin 授权过的目录（`hub_list_grants`），以及 `SERVER_AGENTS.md`（唯一例外，SAG 以 root 代写并记审计） |
| 不能 | — | sudo、docker、写 `/etc` `/usr` 等系统目录、改 SAG 自己（代码、`data/`、`.env`、单元文件）、读 `gateway.db` 和 `.env`、签发/吊销 token |
| 审计 | 全部 | 只能查自己的 |
| 需要 root 时 | — | `hub_request_elevation` 提交，admin 批准后 SAG 以 root 原样执行 |

**提权审批**：operator 用 `hub_request_elevation` 提交 shell 命令（带 cwd/timeout）、写文件或改文件，必须附理由。请求原样存库（记 sha256），通过协作消息通知所有 admin，24 小时后过期。admin 用 `hub_list_elevations` / `hub_approve_elevation` / `hub_reject_elevation` 处理；批准时只能批准或拒绝，不能改内容。执行结果（stdout、stderr、退出码、diff）脱敏后存下来并发消息给申请人，全程记审计。你本人也可以在服务器上直接审批：

```bash
sudo python3 -m sag elevation list          # 待审批
sudo python3 -m sag elevation show e_xxxx   # 完整内容
sudo python3 -m sag elevation approve e_xxxx --note "ok"
sudo python3 -m sag elevation reject  e_xxxx --note "不行"
```

**目录授权**：`hub_grant_path(path, access=rw|ro)`（仅 admin）或 `sudo python3 -m sag grant add <path> [--ro] --reason …`，用 POSIX ACL 给 `sag-operators` 组加权限（含默认 ACL，新文件继承）。拒绝授权系统目录（`/etc/systemd`、`/usr`、sudoers、cron、pam 等）和 SAG 自己的目录。注意：**给 operator 写任何会被 root 执行或读取的东西（部署脚本、root 服务的配置、定时任务），就等于把 root 交出去。**

**回收站**：operator 的 `rm` / `hub_delete_file` 先以 operator 身份把目标打成 tar、再以 operator 身份删除；删不了或读不了（无法备份）就失败，什么都不动。root 进程只把 tar 拷进回收站、从不解包；还原也以 operator 身份解包。root 删掉的东西只有 admin 能还原。

**仍然保留的安全网**：审计、回收站、审计脱敏（`sag/audit_redact.py`）、`data/` 与 `.env` 的自保。

**风险**：

1. **admin token 泄露 = 服务器 root 泄露。** operator token 泄露 = 一个能读大部分系统文件、能访问本机 127.0.0.1 上各服务的普通用户（本机服务自己的鉴权就是最后一道门，比如 Caddy 的 admin API `127.0.0.1:2019` 默认不鉴权）。只给可信 agent 签发 token，一端一个，不用的立刻吊销。
2. SSH 是另一条路：能 SSH 登录 `ubuntu`（免密 sudo）的 agent 不受上面任何限制。
3. 批准提权前看清命令本身；批准就是以 root 执行。
4. 公网只经 Cloudflare Tunnel，不要在防火墙放行 4180；定期 `hub_query_audit_logs` 看一眼。

首次启用（或重装）在服务器上运行一次：`sudo bash scripts/setup_operator.sh`（建用户、把 SAG 目录改成 root 独有、`gateway.db` 与 `.env` 改成 root 600）。

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
| `hub_request_elevation` / `hub_list_elevations` | operator 申请以 root 执行；查看自己的申请和结果。 |
| `hub_approve_elevation` / `hub_reject_elevation` | 仅 admin：批准（以 root 原样执行）或拒绝。 |
| `hub_grant_path` / `hub_revoke_grant` / `hub_list_grants` | admin 用 ACL 授权目录给 operator；所有人可列出。 |
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
