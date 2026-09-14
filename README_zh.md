# Server Agents Gateway

个人 Linux 服务器上的多 Agent 协作层。MCP over HTTP/SSE。Python 3.10+，仅标准库。

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

[English](README.md) | **简体中文**

版本 **2.0.0**。设计说明：[docs/v2.md](docs/v2.md)。

## 做什么

手机、桌面 IDE、定时任务共用一台机器时，网关负责：

1. **身份**：每端独立 Bearer token。
2. **痕迹**：每次工具调用写入 SQLite，可回放。
3. **手**：真 shell（`bash -lc`）和读/写/删；删除进回收站。
4. **画像**：`SERVER_AGENTS.md`。库存人写，状态围栏网关刷。

防出事靠审计和回收站，不靠命令白名单。

## 工具

| 工具 | 作用 |
| :--- | :--- |
| `hub_shell` | `bash -lc`。`rm` 进回收站；`/bin/rm` 仍是真删。 |
| `hub_read_file` / `hub_write_file` / `hub_delete_file` | 文本文件。覆盖/删除先进回收站。 |
| `hub_list_trash` / `hub_restore_file` | 按 id 还原，30 天过期。 |
| `hub_get_overview` / `hub_rebuild_overview` | 读文档；rebuild 只刷新状态围栏。 |
| `hub_get_status` | 负载、内存、磁盘、失败单元、探活。 |
| `hub_query_audit_logs` / `hub_get_audit_event` | 事件列表 vs 完整输出。 |
| `hub_issue_agent_token` / `hub_revoke_agent_token` | 仅 root admin。 |

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
