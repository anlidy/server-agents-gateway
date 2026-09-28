"""MCP tool specifications for server-agents-gateway v2."""

MCP_TOOLS_SPEC = [
    {
        "name": "hub_shell",
        "description": (
            "Run a command with bash -lc (pipes and redirects work). "
            "Runs as root on the host with no sandbox: /etc, /usr, /root and systemd are writable, "
            "and /tmp is the same /tmp that SSH sessions see. Every call is audited. "
            "rm is bound to an absolute-path recycle-bin wrapper; /bin/rm still deletes for real. "
            "If you add, remove, or move a service, update the matching ### in SERVER_AGENTS.md "
            "Inventory (see ## Conventions for `- probe:` format) in the same turn."
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
        "name": "hub_list_dir",
        "description": "List a directory (non-recursive). Returns name, is_dir, size, mtime. Caps at 2000 entries.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "hub_mkdir",
        "description": "Create a directory, including parents (mkdir -p). No-op if it already exists.",
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
        "name": "hub_write_file",
        "description": (
            "Write a text file. Existing content is moved to the recycle bin first. "
            "If you change topology (new service, URL, path), add or edit a ### section "
            "under ## Inventory, including a `- probe:` line if it should be health-checked. "
            "Format is in ## Conventions of SERVER_AGENTS.md."
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
        "name": "hub_patch_file",
        "description": (
            "Replace old_string with new_string in a text file. "
            "Fails if old_string is missing or matches more than once (unless replace_all). "
            "Previous content goes to the recycle bin."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
                "reason": {"type": "string"},
                "replace_all": {"type": "boolean", "default": False},
            },
            "required": ["path", "old_string", "new_string", "reason"],
        },
    },
    {
        "name": "hub_delete_file",
        "description": (
            "Move files or directories to the recycle bin (30-day retention). "
            "Give `path` for one, or `paths` for several (each gets its own audit entry and trash_id). "
            "If this removes a service or project, update SERVER_AGENTS.md Inventory."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}},
                "reason": {"type": "string"},
            },
            "required": ["reason"],
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
            "Read SERVER_AGENTS.md from disk (no cache). Start work by reading this. "
            "Top sag-status fence is generated (do not edit). "
            "Inventory ### sections: add `- probe: systemd|docker|http|tcp ...` to show up/down. "
            "Full format is in ## Conventions in the same file. "
            "Read the whole file once per session; after that use `section` to re-read parts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "section": {
                    "type": "string",
                    "description": (
                        "Optional. `toc` = status table + heading list. Otherwise comma-separated "
                        "## / ### titles (e.g. `sag,Conventions`), each returned with its body."
                    ),
                },
            },
        },
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
        "description": (
            "List audit events, compacted: no stdout/stderr bodies, empty fields dropped, "
            "params only where they add to target. Use hub_get_audit_event for the full row and output."
        ),
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
        "name": "hub_list_agents",
        "description": (
            "List agents that hold a SAG token (agent_id, role, last_active_at, groups) and named groups. "
            "Never returns tokens. Use it to find who to message or assign a task to."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_revoked": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "hub_send_message",
        "description": (
            "Send a message to other agents on this server. Use this (not a file on disk) for anything "
            "addressed to another agent: questions, answers, handoffs, 'I changed X, please check Y', "
            "reviews. Keep files/SERVER_AGENTS.md for durable facts about the server. "
            "The sender is always your token's agent_id. "
            "`to`: an agent_id (see hub_list_agents), `*` for every other agent, `prefix:*` (e.g. `wsl:*`), "
            "`@group`, or several joined by commas. Pass thread_id to continue an existing thread. "
            "Recipients see an unread hint appended to their next tool result."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "agent_id | * | prefix:* | @group, comma-separated for several"},
                "subject": {"type": "string", "description": "One line, <=200 chars"},
                "body": {"type": "string", "description": "Markdown/plain text, <=64KB"},
                "thread_id": {"type": "string", "description": "Optional: continue this thread"},
            },
            "required": ["to", "body"],
        },
    },
    {
        "name": "hub_inbox",
        "description": (
            "Your inbox. Default: unread messages only, newest first, bodies truncated to a preview, "
            "nothing is marked read. unread_only=false shows read ones too. "
            "With thread_id: the whole conversation (your sent messages included), oldest first, full bodies, "
            "and those messages are marked read. Check it when a tool result says you have unread messages."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "unread_only": {"type": "boolean", "default": True},
                "thread_id": {"type": "string"},
                "from_agent": {"type": "string", "description": "Filter by sender"},
                "limit": {"type": "integer", "default": 20, "description": "Max 100"},
            },
        },
    },
    {
        "name": "hub_read_message",
        "description": "Read one message in full and mark it read. Also shows every recipient's read_at.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message_id": {"type": "string"},
                "mark_read": {"type": "boolean", "default": True},
            },
            "required": ["message_id"],
        },
    },
    {
        "name": "hub_mark_read",
        "description": "Mark messages read without opening them: message_ids, a whole thread_id, or all=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message_ids": {"type": "array", "items": {"type": "string"}},
                "thread_id": {"type": "string"},
                "all": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "hub_reply",
        "description": (
            "Reply in the same thread. Goes to the original sender; reply_all=true also includes the "
            "other recipients. Replying to your own message sends it to its recipients. Marks the original read."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message_id": {"type": "string"},
                "body": {"type": "string"},
                "reply_all": {"type": "boolean", "default": False},
                "subject": {"type": "string", "description": "Default: Re: <original subject>"},
            },
            "required": ["message_id", "body"],
        },
    },
    {
        "name": "hub_set_group",
        "description": (
            "Define a named recipient group (send with to=`@name`). Replaces the member list; "
            "an empty list deletes the group. Members must be issued agent_ids."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string", "description": "Name without @, [A-Za-z0-9_.-]"},
                "members": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["group", "members"],
        },
    },
    {
        "name": "hub_create_task",
        "description": (
            "Hand off a piece of work to another agent (or to whoever picks it up). Creates a task with "
            "status open and, by default, messages the assignee (or all other agents if unassigned); "
            "progress messages go to the same thread. Use tasks for work that has an owner and an outcome; "
            "use hub_send_message for plain questions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "assignee": {"type": "string", "description": "Optional agent_id"},
                "notify": {"type": "boolean", "default": True},
            },
            "required": ["title"],
        },
    },
    {
        "name": "hub_list_tasks",
        "description": (
            "List tasks. status: active (default: open+claimed) | open | claimed | done | cancelled | all. "
            "assignee / created_by accept an agent_id or `me`. task_id returns that one task in full."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "default": "active"},
                "assignee": {"type": "string"},
                "created_by": {"type": "string"},
                "task_id": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
        },
    },
    {
        "name": "hub_update_task",
        "description": (
            "Change a task. action: claim (take it; open -> claimed) | release (give it back) | "
            "done (finish; put the outcome in result) | cancel | reopen | comment (note only). "
            "The creator and assignee are notified in the task thread."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "action": {"type": "string", "enum": ["claim", "release", "done", "cancel", "reopen", "comment"]},
                "result": {"type": "string", "description": "Outcome for done/cancel"},
                "note": {"type": "string", "description": "Free text; required for comment"},
            },
            "required": ["task_id", "action"],
        },
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
