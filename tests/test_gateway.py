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
from sag.config import config
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
    tool_list_trash,
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

    def test_replace_status_block_keeps_surrounding(self):
        text = f"# h\n\n{STATUS_START}\nold\n{STATUS_END}\n\n## Inventory\nkeep\n"
        out = replace_status_block(text, "new-status")
        self.assertIn("keep", out)
        inner = out.split(STATUS_START)[1].split(STATUS_END)[0]
        self.assertIn("new-status", inner)
        self.assertNotIn("old", inner)


if __name__ == "__main__":
    unittest.main()
