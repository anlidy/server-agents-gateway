"""
Tests for server-agents-gateway v2: open shell, trash, split audit, document overview.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="sagtest_"))
(_TEST_ROOT / "data").mkdir()
(_TEST_ROOT / "cwd").mkdir()
os.environ["GATEWAY_DB_PATH"] = str(_TEST_ROOT / "data" / "gateway.db")
os.environ["GATEWAY_OVERVIEW_PATH"] = str(_TEST_ROOT / "SERVER_AGENTS.md")
os.environ["GATEWAY_SHELL_CWD"] = str(_TEST_ROOT / "cwd")
os.environ["GATEWAY_SHELL_TIMEOUT_SECONDS"] = "5"
os.environ["GATEWAY_SHELL_TIMEOUT_MAX"] = "10"
os.environ["AI_PROVIDER_ENABLED"] = "false"

from sag.auth import authenticate_bearer_token, issue_agent_token, revoke_agent_token
from sag.config import config, resolve_config_path
from sag.db import (
    append_audit,
    get_audit_event,
    get_db_connection,
    init_db,
    query_audit_logs,
)
from sag.executor import CommandExecutionError, execute_shell
from sag.overview import (
    STATUS_END,
    STATUS_START,
    ensure_document,
    parse_probes,
    read_overview,
    replace_status_block,
    untracked_containers,
)
from sag.trash import ProtectedPathError, is_protected, list_trash, restore_trash, trash_put
from sag.tools import (
    tool_delete_file,
    tool_get_audit_event,
    tool_get_overview,
    tool_get_status,
    tool_issue_agent_token,
    tool_list_dir,
    tool_list_trash,
    tool_mkdir,
    tool_patch_file,
    tool_query_audit_logs,
    tool_read_file,
    tool_rebuild_overview,
    tool_restore_file,
    tool_revoke_agent_token,
    tool_shell,
    tool_write_file,
)
from sag.tools_spec import MCP_TOOLS_SPEC


def _wipe_db():
    db_p = Path(os.environ["GATEWAY_DB_PATH"])
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_p) + suffix) if suffix else db_p
        if p.exists():
            p.unlink()


class TestGatewayV2(unittest.TestCase):
    def setUp(self):
        _wipe_db()
        init_db()
        trash_root = Path(config.db_path).resolve().parent / "trash"
        if trash_root.exists():
            shutil.rmtree(trash_root)
        cwd = Path(config.shell_cwd)
        cwd.mkdir(parents=True, exist_ok=True)
        for child in list(cwd.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        ov = Path(config.overview_path)
        if ov.exists():
            ov.unlink()

    def tearDown(self):
        _wipe_db()

    def test_relative_config_paths_anchor_at_gateway_root(self):
        root = Path("/opt/server-agents-gateway")
        self.assertEqual(
            resolve_config_path("./data/gateway.db", root),
            (root / "data" / "gateway.db").resolve(),
        )
        self.assertTrue(resolve_config_path("./data/gateway.db", root).is_absolute())
        self.assertEqual(
            resolve_config_path("/var/lib/sag/gateway.db", root),
            Path("/var/lib/sag/gateway.db").resolve(),
        )
        self.assertTrue(Path(config.db_path).is_absolute())
        self.assertTrue(Path(config.overview_path).is_absolute())
        self.assertTrue(Path(config.shell_cwd).is_absolute())

    def test_auth_per_agent_tokens(self):
        token = issue_agent_token("mobile:agent", role="admin")
        self.assertTrue(token.startswith("sag_mobile_agent_"))
        auth = authenticate_bearer_token(f"Bearer {token}")
        self.assertIsNotNone(auth)
        self.assertEqual(auth[0], "mobile:agent")
        self.assertTrue(revoke_agent_token("mobile:agent"))
        self.assertIsNone(authenticate_bearer_token(f"Bearer {token}"))

    def test_tool_issue_and_revoke_token(self):
        with self.assertRaises(PermissionError):
            tool_issue_agent_token(
                caller_agent_id="desktop:other",
                caller_role="admin",
                agent_id="desktop:vscode",
            )
        res = tool_issue_agent_token(
            caller_agent_id=config.root_admin_agent_id,
            caller_role="admin",
            agent_id="desktop:vscode",
        )
        self.assertEqual(res["status"], "ISSUED")
        self.assertEqual(res["role"], "operator")
        auth = authenticate_bearer_token(f"Bearer {res['token']}")
        self.assertEqual(auth[0], "desktop:vscode")
        self.assertEqual(auth[1], "operator")
        events = query_audit_logs(action_type="token_issue", limit=1)
        self.assertTrue(events)
        self.assertNotIn(res["token"], json.dumps(events[0]))
        body = get_audit_event(events[0]["id"])
        self.assertNotIn(res["token"], json.dumps(body))
        revoke_res = tool_revoke_agent_token(
            caller_agent_id=config.root_admin_agent_id,
            caller_role="admin",
            agent_id="desktop:vscode",
        )
        self.assertEqual(revoke_res["status"], "REVOKED")
        self.assertIsNone(authenticate_bearer_token(f"Bearer {res['token']}"))

    def test_shell_pipelines_work(self):
        result = tool_shell("test:agent", "printf hello | wc -c", "pipe check")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["stdout"].strip() in ("5", "5\n") or "5" in result["stdout"])
        rows = query_audit_logs(action_type="shell_exec", limit=1)
        self.assertEqual(rows[0]["status"], "SUCCESS")
        self.assertNotIn("stdout", rows[0])
        body = get_audit_event(rows[0]["id"])
        self.assertIn("5", (body.get("stdout") or ""))

    def test_shell_timeout(self):
        result = tool_shell("test:agent", "sleep 8", "timeout", timeout_seconds=1)
        self.assertEqual(result["exit_code"], -1)
        rows = query_audit_logs(action_type="shell_exec", limit=1)
        self.assertEqual(rows[0]["status"], "FAILED")
        self.assertEqual(rows[0]["exit_code"], -1)

    def test_empty_command_rejected(self):
        with self.assertRaises(CommandExecutionError):
            execute_shell("   ")

    def test_rm_wrapper_goes_to_trash_and_restore(self):
        target = Path(config.shell_cwd) / "keep_me.txt"
        target.write_text("hello-trash", encoding="utf-8")
        result = tool_shell("test:agent", f"rm {target}", "trash via wrapper")
        self.assertEqual(result["exit_code"], 0, msg=result.get("stderr"))
        self.assertFalse(target.exists())
        items = list_trash()
        self.assertTrue(items)
        self.assertEqual(Path(items[0]["original_path"]), target.resolve())
        restored = tool_restore_file("test:agent", items[0]["id"], "put back")
        self.assertEqual(restored["status"], "RESTORED")
        self.assertEqual(target.read_text(encoding="utf-8"), "hello-trash")

    def test_rm_relative_operand_stores_absolute_path(self):
        target = Path(config.shell_cwd) / "rel.txt"
        target.write_text("rel", encoding="utf-8")
        result = tool_shell(
            "test:agent",
            "rm ./rel.txt",
            "relative rm",
            cwd=str(config.shell_cwd),
        )
        self.assertEqual(result["exit_code"], 0, msg=result.get("stderr"))
        self.assertFalse(target.exists())
        items = list_trash()
        self.assertTrue(items)
        stored = Path(items[0]["original_path"])
        self.assertTrue(stored.is_absolute(), msg=items[0]["original_path"])
        self.assertEqual(stored, target.resolve())

    def test_rm_wrapper_survives_path_reset(self):
        target = Path(config.shell_cwd) / "still.txt"
        target.write_text("keep", encoding="utf-8")
        result = tool_shell(
            "test:agent",
            "PATH=/usr/bin:/bin; rm still.txt",
            "path reset",
            cwd=str(config.shell_cwd),
        )
        self.assertEqual(result["exit_code"], 0, msg=result.get("stderr"))
        self.assertFalse(target.exists())
        self.assertTrue(list_trash())

    def test_bin_rm_does_not_enter_trash(self):
        target = Path(config.shell_cwd) / "gone.txt"
        target.write_text("x", encoding="utf-8")
        result = tool_shell("test:agent", f"/bin/rm {target}", "real delete")
        self.assertEqual(result["exit_code"], 0, msg=result.get("stderr"))
        self.assertFalse(target.exists())
        self.assertEqual(list_trash(), [])

    def test_protected_paths_rejected(self):
        db_path = Path(config.db_path).resolve()
        self.assertTrue(is_protected(db_path))
        with self.assertRaises(ProtectedPathError):
            tool_delete_file("test:agent", str(db_path), "wipe db")
        self.assertTrue(db_path.exists())
        env_path = Path(config.gateway_root) / ".env"
        self.assertTrue(is_protected(env_path))

    def test_write_file_trashes_old_content(self):
        path = Path(config.shell_cwd) / "doc.txt"
        path.write_text("old", encoding="utf-8")
        tool_write_file("test:agent", str(path), "new", "overwrite")
        self.assertEqual(path.read_text(encoding="utf-8"), "new")
        items = list_trash()
        self.assertTrue(items)
        restore_trash(items[0]["id"])
        # original path now has "new"; restore should fail
        path2 = Path(config.shell_cwd) / "doc.txt"
        self.assertTrue(path2.exists())
        res = tool_restore_file("test:agent", items[0]["id"], "again")
        self.assertEqual(res["status"], "FAILED")

    def test_restore_conflict_when_dest_exists(self):
        path = Path(config.shell_cwd) / "a.txt"
        path.write_text("v1", encoding="utf-8")
        item_id = trash_put(path, source="delete_file", agent_id="test:agent")
        path.write_text("v2", encoding="utf-8")
        res = tool_restore_file("test:agent", item_id, "conflict")
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(path.read_text(encoding="utf-8"), "v2")

    def test_delete_directory_restore(self):
        d = Path(config.shell_cwd) / "tree"
        d.mkdir()
        (d / "n.txt").write_text("nested", encoding="utf-8")
        tool_delete_file("test:agent", str(d), "rm tree")
        self.assertFalse(d.exists())
        items = [i for i in list_trash() if i["is_dir"]]
        self.assertTrue(items)
        tool_restore_file("test:agent", items[0]["id"], "restore tree")
        self.assertEqual((d / "n.txt").read_text(encoding="utf-8"), "nested")

    def test_audit_redaction_in_shell_log(self):
        raw = (
            "echo Authorization: Bearer sag_cursor_helm_abc123deadbeef "
            "and github_pat_AAA_BBB"
        )
        tool_shell("test:agent", raw, "probe secrets")
        rows = query_audit_logs(agent_id="test:agent", limit=1)
        stored = json.dumps(rows[0])
        self.assertNotIn("sag_cursor_helm_abc123deadbeef", stored)
        body = get_audit_event(rows[0]["id"])
        blob = json.dumps(body)
        self.assertNotIn("sag_cursor_helm_abc123deadbeef", blob)
        self.assertNotIn("github_pat_AAA_BBB", blob)
        self.assertIn("***", blob)

    def test_query_audit_logs_omits_bodies(self):
        append_audit(
            agent_id="test:agent",
            tool_name="hub_shell",
            action_type="shell_exec",
            target="echo",
            reason="x",
            status="SUCCESS",
            stdout="BODY-SHOULD-NOT-LIST",
        )
        rows = tool_query_audit_logs(agent_id="test:agent", limit=5)
        self.assertTrue(rows)
        self.assertNotIn("stdout", rows[0])
        self.assertNotIn("BODY-SHOULD-NOT-LIST", json.dumps(rows[0]))
        full = tool_get_audit_event(rows[0]["id"])
        self.assertIn("BODY-SHOULD-NOT-LIST", full.get("stdout") or "")

    def test_read_write_file(self):
        path = Path(config.shell_cwd) / "note.md"
        tool_write_file("test:agent", str(path), "line1\nline2\nline3\n", "create")
        res = tool_read_file("test:agent", str(path), offset=2, limit=1)
        self.assertEqual(res["content"].strip(), "line2")

    def test_mkdir_and_list_dir(self):
        root = Path(config.shell_cwd) / "newtree"
        nested = root / "a" / "b"
        out = tool_mkdir("test:agent", str(nested), "make dirs")
        self.assertTrue(nested.is_dir())
        self.assertEqual(Path(out["path"]), nested.resolve())
        (nested / "f.txt").write_text("x", encoding="utf-8")
        listing = tool_list_dir("test:agent", str(nested))
        names = {e["name"] for e in listing["entries"]}
        self.assertEqual(names, {"f.txt"})
        self.assertFalse(listing["entries"][0]["is_dir"])
        parent = tool_list_dir("test:agent", str(root / "a"))
        self.assertEqual(parent["entries"][0]["name"], "b")
        self.assertTrue(parent["entries"][0]["is_dir"])
        again = tool_mkdir("test:agent", str(nested), "idempotent")
        self.assertTrue(again.get("existed"))

    def test_mkdir_rejects_file_path(self):
        f = Path(config.shell_cwd) / "notdir.txt"
        f.write_text("x", encoding="utf-8")
        with self.assertRaises(Exception):
            tool_mkdir("test:agent", str(f), "should fail")

    def test_list_dir_rejects_file(self):
        f = Path(config.shell_cwd) / "afile.txt"
        f.write_text("x", encoding="utf-8")
        with self.assertRaises(Exception):
            tool_list_dir("test:agent", str(f))

    def test_patch_file_unique_and_replace_all(self):
        path = Path(config.shell_cwd) / "cfg.txt"
        path.write_text("aaa\nbbb\naaa\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            tool_patch_file("test:agent", str(path), "aaa", "ccc", "not unique")
        self.assertEqual(path.read_text(encoding="utf-8"), "aaa\nbbb\naaa\n")
        out = tool_patch_file("test:agent", str(path), "bbb", "ddd", "unique")
        self.assertEqual(out["replacements"], 1)
        self.assertEqual(path.read_text(encoding="utf-8"), "aaa\nddd\naaa\n")
        out = tool_patch_file(
            "test:agent", str(path), "aaa", "eee", "all", replace_all=True
        )
        self.assertEqual(out["replacements"], 2)
        self.assertEqual(path.read_text(encoding="utf-8"), "eee\nddd\neee\n")
        self.assertTrue(list_trash())
        with self.assertRaises(ValueError):
            tool_patch_file("test:agent", str(path), "zzz", "nope", "missing")
        with self.assertRaises(ValueError):
            tool_patch_file("test:agent", str(path), "", "x", "empty")

    def test_overview_status_refresh_preserves_inventory(self):
        marker = "UNIQUE_INVENTORY_SENTENCE_caddy_reload"
        ensure_document()
        tool_write_file(
            "test:agent",
            config.overview_path,
            f"""# testhost

## Host

personal box

## Inventory

### caddy
- probe: systemd caddy.service
- path: /etc/caddy/Caddyfile

{marker}

## Conventions

who changes topology updates inventory
""",
            "seed inventory",
        )
        before = read_overview()
        self.assertIn(marker, before)
        tool_rebuild_overview("refresh status")
        after = read_overview()
        self.assertIn(marker, after)
        self.assertIn(STATUS_START, after)
        self.assertIn(STATUS_END, after)
        self.assertIn("probe: systemd caddy.service", after)
        start = after.index(STATUS_START)
        end = after.index(STATUS_END)
        self.assertNotIn(marker, after[start:end])

    def test_get_overview_reads_disk(self):
        ensure_document()
        Path(config.overview_path).write_text(
            "# disk\n\n## Host\nfrom-disk\n\n## Inventory\n\n## Conventions\n",
            encoding="utf-8",
        )
        text = tool_get_overview()
        self.assertIn("from-disk", text)

    def test_parse_probes_and_untracked(self):
        inventory = """
## Inventory
### caddy
- probe: systemd caddy.service
### app
- probe: docker app
"""
        probes = parse_probes(inventory)
        self.assertEqual(probes[0]["id"], "caddy")
        self.assertEqual(probes[0]["kind"], "systemd")
        self.assertEqual(probes[1]["kind"], "docker")
        untracked = untracked_containers(inventory, ["app", "orphan"])
        self.assertEqual(untracked, ["docker:orphan"])
        self.assertNotIn("docker:app", untracked)

    def test_get_status_has_vitals(self):
        status = tool_get_status()
        self.assertIn("cpu", status)
        self.assertIn("loadavg", status["cpu"])
        self.assertIn("disks", status)
        self.assertIn("memory_mb", status)
        self.assertIn("probes", status)
        self.assertIn("untracked", status)
        self.assertIn("host", status)

    def test_tools_spec_has_v2_names_only(self):
        names = {t["name"] for t in MCP_TOOLS_SPEC}
        self.assertIn("hub_shell", names)
        self.assertIn("hub_read_file", names)
        self.assertIn("hub_list_dir", names)
        self.assertIn("hub_mkdir", names)
        self.assertIn("hub_patch_file", names)
        self.assertIn("hub_restore_file", names)
        self.assertNotIn("hub_execute_command", names)
        self.assertNotIn("hub_acquire_lock", names)
        self.assertNotIn("hub_register_asset", names)
        self.assertNotIn("hub_manage_service", names)

    def test_v1_audit_migrates(self):
        _wipe_db()
        with get_db_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE gateway_audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    intent_reason TEXT NOT NULL,
                    lease_token INTEGER,
                    is_temporary INTEGER DEFAULT 0,
                    params_json TEXT,
                    status TEXT NOT NULL,
                    duration_ms INTEGER,
                    diff_snapshot TEXT,
                    output_summary TEXT
                );
                """
            )
            conn.execute(
                """
                INSERT INTO gateway_audit_logs (
                    id, timestamp, agent_id, action_type, target, intent_reason,
                    status, output_summary
                ) VALUES ('old-1', '2026-09-01T00:00:00+0800', 'a', 'shell_exec', 'df',
                          'old reason', 'SUCCESS', 'old-out');
                """
            )
        init_db()
        rows = query_audit_logs(limit=10)
        self.assertTrue(any(r["id"] == "old-1" for r in rows))
        body = get_audit_event("old-1")
        self.assertEqual(body.get("stdout"), "old-out")
        self.assertEqual(body.get("reason") or body.get("event", {}).get("reason"), "old reason")
        with get_db_connection() as conn:
            tables = {
                r[0]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        self.assertIn("gateway_audit_logs_v1", tables)
        self.assertNotIn("gateway_audit_logs", tables)

    def test_systemd_unit_has_no_sandbox(self):
        unit = (_ROOT / "deploy" / "server-agents-gateway.service").read_text(encoding="utf-8")
        active = [
            line.strip()
            for line in unit.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertIn("User=root", active)
        for key in ("ProtectSystem", "ProtectHome", "PrivateTmp", "ReadOnlyPaths", "ReadWritePaths"):
            self.assertFalse(
                any(line.startswith(key + "=") for line in active),
                msg=f"{key} should not be set: hub_shell is meant to be real root",
            )

    def test_file_tools_not_limited_to_gateway_root(self):
        # 只有 db / .env / data/ 受自保，其余绝对路径都能写（沙箱已放开）。
        outside = Path(tempfile.mkdtemp(prefix="sag_outside_"))
        try:
            target = outside / "etc-like" / "unit.conf"
            self.assertFalse(is_protected(target))
            tool_write_file("test:agent", str(target), "x=1\n", "write outside gateway root")
            self.assertEqual(target.read_text(encoding="utf-8"), "x=1\n")
            res = tool_delete_file("test:agent", str(target), "cleanup")
            self.assertEqual(res["status"], "TRASHED")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_replace_status_block_keeps_surrounding(self):
        text = f"# h\n\n{STATUS_START}\nold\n{STATUS_END}\n\n## Inventory\nkeep\n"
        out = replace_status_block(text, "new-status")
        self.assertIn("keep", out)
        inner = out.split(STATUS_START)[1].split(STATUS_END)[0]
        self.assertIn("new-status", inner)
        self.assertNotIn("old", inner)


class TestCollab(unittest.TestCase):
    """Agent 之间的消息 / 任务交接。"""

    def setUp(self):
        _wipe_db()
        init_db()
        self.tokens = {}
        for a in ("mobile:xiaoyao", "wsl:pi", "wsl:claude", "cursor:helm"):
            self.tokens[a] = issue_agent_token(a, role="operator")
        issue_agent_token("old:gone", role="operator")
        revoke_agent_token("old:gone")

    def tearDown(self):
        _wipe_db()

    def _call(self, agent, tool, **args):
        from sag.server import dispatch_tool

        return dispatch_tool(agent, "operator", tool, args)

    def _rpc(self, agent, tool, **args):
        import asyncio
        from sag.server import handle_jsonrpc

        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        return asyncio.run(handle_jsonrpc(agent, "operator", req))

    def test_init_db_is_idempotent_and_creates_tables(self):
        init_db()
        init_db()
        with get_db_connection() as conn:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("agent_messages", "agent_message_recipients", "agent_groups", "agent_tasks"):
            self.assertIn(t, tables)

    def test_list_agents_hides_tokens(self):
        authenticate_bearer_token("Bearer " + self.tokens["wsl:pi"])
        out = self._call("wsl:claude", "hub_list_agents")
        ids = [a["agent_id"] for a in out["agents"]]
        self.assertIn("wsl:pi", ids)
        self.assertNotIn("old:gone", ids)
        blob = json.dumps(out)
        for tok in self.tokens.values():
            self.assertNotIn(tok, blob)
        self.assertNotIn("token_hash", blob)
        me = [a for a in out["agents"] if a["is_you"]]
        self.assertEqual([a["agent_id"] for a in me], ["wsl:claude"])
        pi = [a for a in out["agents"] if a["agent_id"] == "wsl:pi"][0]
        self.assertTrue(pi["last_active_at"])
        with_revoked = self._call("wsl:claude", "hub_list_agents", include_revoked=True)
        self.assertIn("old:gone", [a["agent_id"] for a in with_revoked["agents"]])

    def test_direct_message_inbox_read_flow(self):
        sent = self._call("wsl:claude", "hub_send_message", to="mobile:xiaoyao", subject="迁移问题", body="x" * 1000)
        self.assertEqual(sent["recipients"], ["mobile:xiaoyao"])
        self.assertEqual(sent["thread_id"], sent["id"])
        box = self._call("mobile:xiaoyao", "hub_inbox")
        self.assertEqual(box["unread_total"], 1)
        m = box["messages"][0]
        self.assertEqual(m["from"], "wsl:claude")
        self.assertFalse(m["read"])
        self.assertTrue(m.get("body_truncated"))
        self.assertLess(len(m["body"]), 1000)
        # inbox 本身不标已读
        self.assertEqual(self._call("mobile:xiaoyao", "hub_inbox")["unread_total"], 1)
        # 发件人自己的收件箱是空的
        self.assertEqual(self._call("wsl:claude", "hub_inbox")["messages"], [])
        full = self._call("mobile:xiaoyao", "hub_read_message", message_id=sent["id"])
        self.assertEqual(len(full["body"]), 1000)
        self.assertTrue(full["read"])
        self.assertTrue(full["recipients"][0]["read_at"])
        self.assertEqual(self._call("mobile:xiaoyao", "hub_inbox")["unread_total"], 0)
        again = self._call("mobile:xiaoyao", "hub_inbox", unread_only=False)
        self.assertEqual(len(again["messages"]), 1)
        self.assertTrue(again["messages"][0]["read"])
        # 发件人能看到对方已读
        seen = self._call("wsl:claude", "hub_read_message", message_id=sent["id"])
        self.assertTrue(seen["recipients"][0]["read_at"])
        # 旁人看不到
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_read_message", message_id=sent["id"])

    def test_broadcast_prefix_and_group_targets(self):
        b = self._call("wsl:claude", "hub_send_message", to="*", subject="重启 SAG", body="5 分钟后重启")
        self.assertEqual(sorted(b["recipients"]), ["cursor:helm", "mobile:xiaoyao", "wsl:pi"])
        p = self._call("mobile:xiaoyao", "hub_send_message", to="wsl:*", body="wsl 的注意")
        self.assertEqual(sorted(p["recipients"]), ["wsl:claude", "wsl:pi"])
        g = self._call("mobile:xiaoyao", "hub_set_group", group="ops", members=["wsl:pi", "cursor:helm"])
        self.assertEqual(g["group"], "@ops")
        m = self._call("wsl:pi", "hub_send_message", to="@ops", body="组消息")
        self.assertEqual(m["recipients"], ["cursor:helm"])  # 不含自己
        multi = self._call("wsl:pi", "hub_send_message", to="mobile:xiaoyao, @ops", body="两类目标")
        self.assertEqual(sorted(multi["recipients"]), ["cursor:helm", "mobile:xiaoyao"])
        listing = self._call("wsl:pi", "hub_list_agents")
        self.assertEqual(sorted(listing["groups"]["ops"]), ["cursor:helm", "wsl:pi"])
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_send_message", to="@nope", body="x")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_send_message", to="old:gone", body="revoked")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_send_message", to="nobody:here", body="typo")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_send_message", to="wsl:pi", body="")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_set_group", group="bad name!", members=[])

    def test_sender_cannot_be_spoofed(self):
        for key in ("from", "from_agent", "sender"):
            with self.assertRaises(ValueError):
                self._call("wsl:pi", "hub_send_message", to="mobile:xiaoyao", body="hi", **{key: "mobile:xiaoyao"})
        sent = self._call("wsl:pi", "hub_send_message", to="mobile:xiaoyao", body="hi")
        got = self._call("mobile:xiaoyao", "hub_read_message", message_id=sent["id"])
        self.assertEqual(got["from"], "wsl:pi")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_create_task", title="t", created_by="mobile:xiaoyao")

    def test_reply_and_thread_view(self):
        q = self._call("wsl:claude", "hub_send_message", to="mobile:xiaoyao,wsl:pi", subject="端口", body="4190 还用吗？")
        r = self._call("mobile:xiaoyao", "hub_reply", message_id=q["id"], body="还在用")
        self.assertEqual(r["recipients"], ["wsl:claude"])
        self.assertEqual(r["thread_id"], q["thread_id"])
        self.assertEqual(r["subject"], "Re: 端口")
        self.assertEqual(r["reply_to"], q["id"])
        # 回复即已读原消息
        self.assertEqual(self._call("mobile:xiaoyao", "hub_inbox")["unread_total"], 0)
        ra = self._call("wsl:pi", "hub_reply", message_id=q["id"], body="我也用", reply_all=True)
        self.assertEqual(sorted(ra["recipients"]), ["mobile:xiaoyao", "wsl:claude"])
        # 在线程里继续发
        cont = self._call("wsl:claude", "hub_send_message", to="wsl:pi", body="收到", thread_id=q["thread_id"])
        self.assertEqual(cont["thread_id"], q["thread_id"])
        self.assertEqual(cont["subject"], "Re: 端口")
        thread = self._call("wsl:claude", "hub_inbox", thread_id=q["thread_id"])
        self.assertEqual([m["id"] for m in thread["messages"]], [q["id"], r["id"], ra["id"], cont["id"]])
        self.assertEqual(thread["marked_read"], 2)
        self.assertEqual(thread["unread_total"], 0)
        # cursor:helm 不在线程里
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_inbox", thread_id=q["thread_id"])
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_send_message", to="wsl:pi", body="x", thread_id=q["thread_id"])

    def test_reply_to_note_to_self(self):
        note = self._call("wsl:pi", "hub_send_message", to="wsl:pi", subject="备忘", body="记一下")
        r = self._call("wsl:pi", "hub_reply", message_id=note["id"], body="补充")
        self.assertEqual(r["recipients"], ["wsl:pi"])
        self.assertEqual(r["thread_id"], note["thread_id"])
        thread = self._call("wsl:pi", "hub_inbox", thread_id=note["thread_id"])
        self.assertEqual(len(thread["messages"]), 2)
        self.assertEqual(thread["unread_total"], 0)

    def test_mark_read(self):
        a = self._call("wsl:pi", "hub_send_message", to="cursor:helm", body="1")
        self._call("wsl:pi", "hub_send_message", to="cursor:helm", body="2")
        self._call("wsl:pi", "hub_send_message", to="cursor:helm", body="3")
        out = self._call("cursor:helm", "hub_mark_read", message_ids=[a["id"]])
        self.assertEqual(out, {"marked_read": 1, "unread_total": 2})
        out = self._call("cursor:helm", "hub_mark_read", all=True)
        self.assertEqual(out["unread_total"], 0)
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_mark_read")

    def test_string_booleans_from_clients(self):
        self._call("wsl:pi", "hub_send_message", to="cursor:helm", body="1")
        box = self._call("cursor:helm", "hub_inbox", unread_only="false", limit="5")
        self.assertFalse(box["unread_only"])
        self._call("cursor:helm", "hub_mark_read", all="true")
        self.assertEqual(self._call("cursor:helm", "hub_inbox", unread_only="true")["messages"], [])
        quiet = self._call("wsl:pi", "hub_create_task", title="t", notify="false")
        self.assertEqual(quiet["notified"], [])

    def test_message_audit_is_redacted(self):
        secret = "sag_mobile_xiaoyao_deadbeefcafe1234"
        self._call(
            "wsl:pi", "hub_send_message", to="mobile:xiaoyao",
            subject=f"token {secret}", body=f"Authorization: Bearer {secret} github_pat_AAA_BBB",
        )
        rows = query_audit_logs(tool_name="hub_send_message", limit=1)
        self.assertTrue(rows)
        body = get_audit_event(rows[0]["id"])
        blob = json.dumps(body, ensure_ascii=False)
        self.assertNotIn(secret, blob)
        self.assertNotIn("github_pat_AAA_BBB", blob)
        self.assertIn("***", blob)
        self.assertEqual(rows[0]["agent_id"], "wsl:pi")

    def test_unread_hint_in_tool_results(self):
        from sag import collab

        cwd = str(config.shell_cwd)
        resp = self._rpc("mobile:xiaoyao", "hub_list_dir", path=cwd)
        self.assertEqual(len(resp["result"]["content"]), 1)
        self._call("wsl:pi", "hub_send_message", to="mobile:xiaoyao", subject="看一下 caddy", body="...")
        resp = self._rpc("mobile:xiaoyao", "hub_list_dir", path=cwd)
        content = resp["result"]["content"]
        self.assertEqual(len(content), 2)
        # 第一项仍是原来的 JSON，结构不变
        self.assertEqual(json.loads(content[0]["text"])["path"], str(Path(cwd).resolve()))
        self.assertTrue(content[1]["text"].startswith("\n[SAG] "))
        self.assertIn("1 条未读", content[1]["text"])
        self.assertIn("wsl:pi", content[1]["text"])
        self.assertIn("hub_inbox", content[1]["text"])
        self.assertLess(len(content[1]["text"]), 120)
        # 看收件箱的工具不重复提示
        for tool in collab.NO_HINT_TOOLS:
            args = {"all": True} if tool == "hub_mark_read" else {}
            if tool == "hub_read_message":
                continue
            resp = self._rpc("mobile:xiaoyao", tool, **args)
            self.assertEqual(len(resp["result"]["content"]), 1, msg=tool)
        resp = self._rpc("mobile:xiaoyao", "hub_list_dir", path=cwd)
        self.assertEqual(len(resp["result"]["content"]), 1)
        # 出错时仍是 error，不附提示
        self._call("wsl:pi", "hub_send_message", to="mobile:xiaoyao", body="again")
        err = self._rpc("mobile:xiaoyao", "hub_list_dir", path=cwd + "/missing")
        self.assertIn("error", err)

    def test_task_lifecycle(self):
        t = self._call("mobile:xiaoyao", "hub_create_task", title="给 xiaoyao-memory 加备份", description="每天 3 点")
        task = t["task"]
        self.assertEqual(task["status"], "open")
        self.assertEqual(task["created_by"], "mobile:xiaoyao")
        self.assertEqual(sorted(t["notified"]), ["cursor:helm", "wsl:claude", "wsl:pi"])
        box = self._call("wsl:pi", "hub_inbox")
        self.assertEqual(box["messages"][0]["task_id"], task["id"])
        claimed = self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="claim")
        self.assertEqual(claimed["task"]["status"], "claimed")
        self.assertEqual(claimed["task"]["assignee"], "wsl:pi")
        self.assertEqual(claimed["notified"], ["mobile:xiaoyao"])
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_update_task", task_id=task["id"], action="claim")
        with self.assertRaises(ValueError):
            self._call("cursor:helm", "hub_update_task", task_id=task["id"], action="done")
        mine = self._call("wsl:pi", "hub_list_tasks", assignee="me")
        self.assertEqual([x["id"] for x in mine["tasks"]], [task["id"]])
        done = self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="done", result="cron 已加，见 /etc/cron.d/xm-backup")
        self.assertEqual(done["task"]["status"], "done")
        self.assertIn("cron.d", done["task"]["result"])
        self.assertTrue(done["task"]["closed_at"])
        # 创建者在同一线程里收到完成通知
        box = self._call("mobile:xiaoyao", "hub_inbox")
        self.assertTrue(any("已完成" in m["subject"] and m["thread_id"] == task["thread_id"] for m in box["messages"]))
        self.assertEqual(self._call("mobile:xiaoyao", "hub_list_tasks")["tasks"], [])
        self.assertEqual(len(self._call("mobile:xiaoyao", "hub_list_tasks", status="done")["tasks"]), 1)
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="done")
        reopened = self._call("mobile:xiaoyao", "hub_update_task", task_id=task["id"], action="reopen")
        self.assertEqual(reopened["task"]["status"], "open")
        c = self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="comment", note="再看看")
        self.assertEqual(c["task"]["status"], "open")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="comment")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_update_task", task_id=task["id"], action="explode")
        rows = query_audit_logs(tool_name="hub_update_task", limit=10)
        self.assertTrue({"task_claim", "task_done", "task_reopen", "task_comment"} <= {r["action_type"] for r in rows})

    def test_assigned_task_and_cancel(self):
        t = self._call("wsl:claude", "hub_create_task", title="看 SAG 日志", assignee="cursor:helm")
        tid = t["task"]["id"]
        self.assertEqual(t["notified"], ["cursor:helm"])
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_update_task", task_id=tid, action="claim")
        with self.assertRaises(ValueError):
            self._call("wsl:pi", "hub_update_task", task_id=tid, action="cancel")
        ok = self._call("cursor:helm", "hub_update_task", task_id=tid, action="claim")
        self.assertEqual(ok["task"]["status"], "claimed")
        rel = self._call("cursor:helm", "hub_update_task", task_id=tid, action="release")
        self.assertEqual(rel["task"]["status"], "open")
        self.assertIsNone(rel["task"]["assignee"])
        cancelled = self._call("wsl:claude", "hub_update_task", task_id=tid, action="cancel", note="不需要了")
        self.assertEqual(cancelled["task"]["status"], "cancelled")
        self.assertEqual(cancelled["task"]["result"], "不需要了")
        with self.assertRaises(ValueError):
            self._call("wsl:claude", "hub_create_task", title="x", assignee="old:gone")
        with self.assertRaises(ValueError):
            self._call("wsl:claude", "hub_create_task", title="  ")
        quiet = self._call("wsl:claude", "hub_create_task", title="自己记一笔", notify=False)
        self.assertEqual(quiet["notified"], [])
        self.assertIsNone(quiet["task"]["thread_id"])

    def test_collab_tools_visible_to_operators(self):
        from sag.server import get_tools_for_agent

        names = {t["name"] for t in get_tools_for_agent("wsl:pi", "operator")}
        for n in (
            "hub_list_agents", "hub_send_message", "hub_inbox", "hub_read_message", "hub_mark_read",
            "hub_reply", "hub_set_group", "hub_create_task", "hub_list_tasks", "hub_update_task",
        ):
            self.assertIn(n, names)
        self.assertNotIn("hub_issue_agent_token", names)


if __name__ == "__main__":
    unittest.main()
