"""MCP tool specifications for server-agents-gateway v2."""

MCP_TOOLS_SPEC = [
    {
        "name": "hub_shell",
        "description": (
            "Run a command with bash -lc (pipes and redirects work). "
            "rm goes to the recycle bin via a PATH wrapper; /bin/rm still deletes for real. "
            "If you add, remove, or move a service, update SERVER_AGENTS.md Inventory in the same turn."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Passed to bash -lc"},
                "reason": {"type": "string", "description": "Why this command is being run"},
                "cwd": {"type": "string", "description": "Working directory"},
                "timeout_seconds": {"type": "integer", "description": "Timeout in seconds, default 120, max 3600"},
            },
            "required": ["command", "reason"],
        },
    },
    {
        "name": "hub_read_file",
        "description": "Read a UTF-8 text file. Directories and binary files are rejected.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "offset": {"type": "integer", "description": "1-based start line", "default": 1},
                "limit": {"type": "integer", "description": "Max lines to return"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "hub_write_file",
        "description": (
            "Write a text file. Existing content is moved to the recycle bin first. "
            "If you change topology (new service, URL, path), update SERVER_AGENTS.md Inventory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["path", "content", "reason"],
        },
    },
    {
        "name": "hub_delete_file",
        "description": (
            "Move a file or directory to the recycle bin (30-day retention). "
            "If this removes a service or project, update SERVER_AGENTS.md Inventory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["path", "reason"],
        },
    },
    {
        "name": "hub_list_trash",
        "description": "List recycle-bin entries (metadata only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prefix": {"type": "string", "description": "Filter original_path prefix"},
                "limit": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "hub_restore_file",
        "description": "Restore a recycle-bin item by trash_id. Fails if the original path already exists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trash_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["trash_id", "reason"],
        },
    },
    {
        "name": "hub_get_overview",
        "description": (
            "Read SERVER_AGENTS.md from disk (no cache). "
            "Status fence is auto-refreshed; Inventory/Host/Conventions are handwritten. "
            "Start work by reading this."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "hub_rebuild_overview",
        "description": "Refresh the generated status fence in SERVER_AGENTS.md. Does not rewrite Inventory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "default": "refresh status"},
            },
        },
    },
    {
        "name": "hub_query_audit_logs",
        "description": "List audit events (no stdout/stderr bodies). Use hub_get_audit_event for full output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string"},
                "until": {"type": "string"},
                "agent_id": {"type": "string"},
                "target": {"type": "string"},
                "action_type": {"type": "string"},
                "tool_name": {"type": "string"},
                "status": {"type": "string", "enum": ["SUCCESS", "FAILED", "REJECTED"]},
                "keyword": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "offset": {"type": "integer", "default": 0},
            },
        },
    },
    {
        "name": "hub_get_audit_event",
        "description": "Fetch one audit event including stdout/stderr/diff.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
    {
        "name": "hub_get_status",
        "description": "Host snapshot: load, memory, disks, failed units, docker counts, inventory probes. Not the wiki.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "hub_issue_agent_token",
        "description": "[Admin only] Issue an operator bearer token for a new agent.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent_id": {"type": "string"}},
            "required": ["agent_id"],
        },
    },
    {
        "name": "hub_revoke_agent_token",
        "description": "[Admin only] Revoke an agent's token.",
        "inputSchema": {
            "type": "object",
            "properties": {"agent_id": {"type": "string"}},
            "required": ["agent_id"],
        },
    },
]

ADMIN_ONLY_TOOL_NAMES = {"hub_issue_agent_token", "hub_revoke_agent_token"}
