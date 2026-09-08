# Server Agents Gateway (服务级多 Agent 协同网关)

一个专为 Linux 服务器设计的轻量级、零信任、带活状态资产库与确定性并发控制的受控多 Agent 协同网关。原生兼容 Model Context Protocol (MCP) 规范。

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%20JSON--RPC%202.0-orange.svg)](https://modelcontextprotocol.io/)

[English Documentation](README.md) | **简体中文文档**

---

## 📖 项目背景与核心痛点

当多个不同端的异构 AI Agent（例如手机端智能体、电脑端 Cursor / Claude Code、以及服务器后台常驻的定时任务守护进程）共同连接并管理同一台 Linux 服务器时，通常会遇到以下严峻挑战：
- **信息孤岛与盲人摸象**：各 Agent 分别 SSH 登录，改了什么配置、重启了什么服务，别的 Agent 毫不知情；
- **并发覆写与状态踩踏**：两端同时修改相同配置文件或重启关键容器，导致静默回退或服务炸裂；
- **控制面逃生与系统失控**：无限制的原始 Shell 让 Agent 可以随意逃逸审计策略，造成资产配置与真实状态严重脱节（状态漂移）；
- **身份伪造与凭据共用**：共用统一密钥或依靠客户端自声明的 Header，导致审计日志中的“谁干的”完全不可信，且无法单独吊销某一端。

**Server Agents Gateway** 正是为了解决这一系列问题而诞生的确定性控制面。它提供 Per-Agent 零信任独立凭据反查、带 Fencing Token 的动态排他租约锁、双态 CMDB 资产库、严格命令执行白名单以及全维复合审计检索流水。

---

## ⚡ 核心架构特性

1. **Tool-First MCP 原生规范设计**
   - 所有能力 100% 封装为标准的 MCP Tools（通过 HTTP/SSE 和 JSON-RPC 2.0 提供服务）；
   - 彻底摒弃客户端支持度低且无法主动触发的 Resources 与 Prompts，确保 Operit、Cursor、Claude Code、Hermes 等全生态客户端 100% 免配置调用。

2. **零信任 Per-Agent 独立身份反查**
   - 废除通用共享密码与客户端易篡改的 `X-Agent-ID` 明文 Header；
   - 每端分配独立 Bearer Token，网关根据 Token 强行反查并绑定真实 Agent 身份，支持单端一键独立吊销。

3. **确定性 Fencing Token 租约锁 (并发防踩踏)**
   - 资产表显式声明 `lock_required: 1`，核心配置与关键服务写入前强制动态查库校验；
   - 申请排他锁即生成全局单调递增的 `lease_token`；
   - 物理拦截一切无锁或过期写入（直接返回 `423 Locked` 或 `409 Conflict`），彻底消除后半段覆写碰撞。

4. **双态活资产库与状态自愈巡检 (Desired vs Observed)**
   - 同时维护 `desired_state`（控制面期望状态）与 `observed_state`（实测探针状态）；
   - 后台定期（默认 60s）以及在命令执行后的 `finally` 块中无条件触发真实状态探测，自动捕获带外改动并标记 `DRIFTED`。

5. **严格前缀白名单 Shell 沙箱 (Allowlist-Only)**
   - 彻底摒弃容易被变量拼接、编码绕过的正则黑名单，采用严格的前缀白名单机制（仅开放只读诊断指令与审计脚本）；
   - 坚决物理阻断解释器动态执行（如 `bash -c`、`eval` 等），杜绝篡改网关自身。

6. **可配置的多模型 AI 活文档编译层**
   - 后台可根据真实 CMDB 资产与近期流水，自动生成条理清晰的权威全局大盘 `SERVER_AGENTS.md`；
   - 彻底解耦私有网关，采用标准 OpenAI 兼容协议（可自由配置 DeepSeek、Gemini、OpenAI、OneAPI 等）；
   - 定位为纯只读展示解释层，事实锚定底层，绝不接触控制面。

---

## 🛠️ MCP 标准工具集 (16 个受控工具)

| 工具名称 | 核心参数 | 功能描述与约束 |
| :--- | :--- | :--- |
| `hub_acquire_lock` | `resource_key`, `reason`, `ttl_seconds?` | 申请资源排他锁，返回单调递增的 `lease_token`（默认 120s）。 |
| `hub_renew_lock` | `resource_key`, `lease_token`, `ttl_seconds?` | 长任务租约心跳续期，防止操作中途锁过期。 |
| `hub_release_lock` | `resource_key`, `lease_token` | 凭借合法的 `lease_token` 主动释放排他锁。 |
| `hub_manage_service` | `service_type`, `name`, `action`, `reason`, `lease_token?` | 启停重启 Docker/Systemd 服务，受保护资产强制校验锁。 |
| `hub_edit_file` | `path`, `content`, `reason`, `lease_token?`, `is_temporary?`, `ttl_hours?` | 原子写/改文件，自动生成 diff，识别临时垃圾文件，受保护文件强制校验锁。 |
| `hub_delete_file` | `path`, `reason`, `lease_token?` | 受控删除文件或目录，带审计与强制锁校验。 |
| `hub_cleanup_temp` | `older_than_hours?` | 扫描并批量安全清理已标记过期的临时垃圾文件。 |
| `hub_execute_command`| `command`, `reason`, `timeout_seconds?` | 严格白名单执行系统命令，执行后 `finally` 无条件触发状态比对。 |
| `hub_register_asset` | `key`, `category`, `name`, `description`, `endpoints?`, `configs?`, `lock_required?` | 向 CMDB 注册新资产，并显式声明是否强制加锁（`lock_required`）。 |
| `hub_query_assets` | `category?`, `query?`, `show_drift_only?` | 查询资产拓扑，支持检索端口、配置路径及过滤带外漂移资产。 |
| `hub_get_status` | *无* | 秒级获取 CPU、内存、存储使用率及资产健康度统计大盘。 |
| `hub_query_audit_logs`| `since?`, `until?`, `agent_id?`, `target?`, `action_type?`, `status?`, `is_temporary?`, `keyword?`, `limit?` | 多维度复合检索全端操作历史流水，秒级定位责任端与操作意图。 |
| `hub_get_overview` | *无* | 获取由 AI 编译的权威系统全局架构介绍（`SERVER_AGENTS.md`）。 |
| `hub_rebuild_overview`| `reason?` | 触发配置的 AI 模型重新对全服资产大盘进行深度总结与编译。 |
| `hub_issue_agent_token`| `agent_id` | 【唯一管理员专享】为新 Agent 注册身份并在线签发受控 operator 凭据。 |
| `hub_revoke_agent_token`| `agent_id` | 【唯一管理员专享】一键吊销并废除指定 Agent 的访问凭据 Token。 |

---

## 🚀 快速上手

### 1. 环境准备
- Linux 操作系统 (x86_64 或 aarch64 / ARM64)
- Python 3.10+ (仅依赖标准库，零第三方框架负担)
- SQLite3

### 2. 获取代码与安装
```bash
git clone https://github.com/anlidy/server-agents-gateway.git
cd server-agents-gateway

# 拷贝环境配置文件模板
cp .env.example .env
```

### 3. 配置参数 (`.env`)
```bash
# 基础服务与数据库路径
GATEWAY_HOST=127.0.0.1
GATEWAY_PORT=4180
GATEWAY_DB_PATH=./data/gateway.db

# 可配置的唯一根超级管理员 (仅此 Agent 允许在线签发/吊销其他 Token)
ROOT_ADMIN_AGENT_ID=admin:root

# 可选的 AI 大模型服务提供商 (兼容 OpenAI 接口协议)
AI_PROVIDER_ENABLED=true
AI_PROVIDER_BASE_URL=https://api.deepseek.com/v1
AI_PROVIDER_API_KEY=sk-your-api-key-here
AI_PROVIDER_MODEL=deepseek-chat
AI_PROVIDER_TIMEOUT_SECONDS=30

# 并发租约与自愈巡检间隔
DEFAULT_LEASE_TTL_SECONDS=120
RECONCILE_INTERVAL_SECONDS=60
```

### 4. 签发 Agent 访问凭据 (服务器端本地 CLI)
```bash
# 1. 在服务器本机终端执行：签发根超级管理员 (ROOT ADMIN) 凭据
python3 server.py issue-admin admin:root

# 2. 签发普通 operator 凭据 (亦可在后续由根管理员 Agent 在线直接签发)
python3 server.py issue-token desktop:cursor
```

### 5. 启动网关服务
```bash
python3 server.py
```

### 6. 运行自动化测试套件
```bash
python3 test_gateway.py
```

---

## 🔒 生产环境部署指引 (Systemd 与域名反代)

- 详细部署手册请参阅：👉 **[域名绑定与反向代理权威指引 (deploy/DOMAIN_INGRESS.md)](deploy/DOMAIN_INGRESS.md)**
- 官方守护进程单元文件：👉 **[Systemd Service 文件 (deploy/server-agents-gateway.service)](deploy/server-agents-gateway.service)**

### 快速注册 Systemd 守护进程
```bash
sudo cp deploy/server-agents-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now server-agents-gateway
```

### 客户端 MCP 配置示例 (例如 Cursor / Claude Desktop)
在客户端的 MCP 配置文件中加入：
```json
{
  "mcpServers": {
    "server-agents-gateway": {
      "url": "https://gateway.yourdomain.com/sse",
      "headers": {
        "Authorization": "Bearer sag_desktop_cursor_你的专属Token"
      }
    }
  }
}
```

---

## 📄 开源许可证

本项目基于 [Apache License, Version 2.0](LICENSE) 协议开源。欢迎提交 Issue 与 Pull Request！