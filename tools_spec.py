"""MCP tool specifications for server-agents-gateway."""

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
