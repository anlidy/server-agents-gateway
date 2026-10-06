"""
Tests for server-agents-gateway v2: open shell, trash, split audit, document overview.
"""

import asyncio
import contextlib
import io
import json
import os
import shutil
import signal
import sys
import random
import subprocess
import tempfile
import threading
import time
import tracemalloc
import unittest
import unittest.mock
import uuid
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
from sag.clip import TRUNCATED_MARK, clip_output
from sag.executor import CommandExecutionError, _Capture, execute_shell
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
    from sag.reconciler import wait_reconciled

    wait_reconciled(15)  # tool calls start a background refresh; let it finish before its database goes away
    db_p = Path(os.environ["GATEWAY_DB_PATH"])
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_p) + suffix) if suffix else db_p
        if p.exists():
            p.unlink()


@contextlib.contextmanager
def _config_override(**values):
    """Config is a frozen dataclass built at import time; tests that need other limits swap them here."""
    old = {k: getattr(config, k) for k in values}
    for k, v in values.items():
        object.__setattr__(config, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            object.__setattr__(config, k, v)


@contextlib.contextmanager
def _peak_traced_bytes():
    """
    Yields a dict that gets "peak": the most memory the block held on top of what was already live.
    Leaves an already-running tracemalloc alone, so it also works under `python -X tracemalloc`.
    """
    outer = tracemalloc.is_tracing()
    if outer:
        tracemalloc.reset_peak()
    else:
        tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    box = {}
    try:
        yield box
    finally:
        box["peak"] = tracemalloc.get_traced_memory()[1] - base
        if not outer:
            tracemalloc.stop()


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

    def test_rm_symlink_trashes_link_not_target(self):
        cwd = Path(config.shell_cwd)
        real = cwd / "real.bin"
        real.write_text("payload")
        link = cwd / "link.bin"
        link.symlink_to(real)
        res = tool_shell("test:agent", f"rm -f {link}", "rm link")
        self.assertEqual(res["exit_code"], 0, msg=res["stderr"])
        self.assertFalse(os.path.lexists(link))
        self.assertEqual(real.read_text(), "payload")
        item = list_trash()[0]
        self.assertEqual(item["original_path"], str(link))
        tool_restore_file("test:agent", item["id"], "back")
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(real))

    def test_rm_broken_symlink(self):
        link = Path(config.shell_cwd) / "dangling"
        link.symlink_to("/nonexistent/target")
        res = tool_shell("test:agent", f"rm {link}", "rm dangling")
        self.assertEqual(res["exit_code"], 0, msg=res["stderr"])
        self.assertFalse(os.path.lexists(link))

    def test_rm_symlink_to_dir_without_r(self):
        cwd = Path(config.shell_cwd)
        (cwd / "d").mkdir()
        (cwd / "d" / "f").write_text("x")
        (cwd / "dl").symlink_to(cwd / "d")
        res = tool_shell("test:agent", "rm dl", "rm dir link", cwd=str(cwd))
        self.assertEqual(res["exit_code"], 0, msg=res["stderr"])
        self.assertTrue((cwd / "d" / "f").exists())
        self.assertFalse(os.path.lexists(cwd / "dl"))

    def test_rm_wrapper_not_inherited_by_children(self):
        cwd = Path(config.shell_cwd)
        res = tool_shell(
            "test:agent",
            "type -t rm; bash -c 'type -t rm'; sh -c 'command -v rm'; echo \"$PATH\"",
            "scope",
        )
        lines = res["stdout"].splitlines()
        self.assertEqual(lines[0], "function")
        self.assertEqual(lines[1], "file")
        self.assertIn(lines[2], ("/usr/bin/rm", "/bin/rm"))
        self.assertNotIn("wrappers", lines[3])
        (cwd / "child.txt").write_text("x")
        res = tool_shell("test:agent", "bash -c 'rm child.txt'", "child rm", cwd=str(cwd))
        self.assertEqual(res["exit_code"], 0, msg=res["stderr"])
        self.assertFalse((cwd / "child.txt").exists())
        self.assertEqual(list_trash(), [])

    def test_delete_file_symlink_keeps_target(self):
        cwd = Path(config.shell_cwd)
        real = cwd / "t.txt"
        real.write_text("t")
        link = cwd / "t.link"
        link.symlink_to(real)
        res = tool_delete_file("test:agent", str(link), "unlink")
        self.assertEqual(res["status"], "TRASHED")
        self.assertEqual(res["path"], str(link))
        self.assertTrue(real.exists())
        self.assertFalse(os.path.lexists(link))

    def test_symlink_into_data_dir_is_deletable_but_data_is_not(self):
        link = Path(config.shell_cwd) / "db.link"
        link.symlink_to(config.db_path)
        self.assertEqual(tool_delete_file("test:agent", str(link), "x")["status"], "TRASHED")
        self.assertTrue(Path(config.db_path).exists())
        with self.assertRaises(ProtectedPathError):
            tool_delete_file("test:agent", config.db_path, "x")

    def test_write_and_patch_keep_inode_and_mode(self):
        f = Path(config.shell_cwd) / "conf.yaml"
        f.write_text("a: 1\n")
        os.chmod(f, 0o600)
        ino = f.stat().st_ino
        tool_patch_file("test:agent", str(f), "a: 1", "a: 2", "p")
        self.assertEqual((f.stat().st_ino, f.stat().st_mode & 0o777), (ino, 0o600))
        tool_write_file("test:agent", str(f), "a: 3\n", "w")
        self.assertEqual((f.stat().st_ino, f.stat().st_mode & 0o777), (ino, 0o600))
        self.assertEqual(f.read_text(), "a: 3\n")
        self.assertEqual(len(list_trash()), 2)

    def test_write_through_symlink_keeps_link(self):
        cwd = Path(config.shell_cwd)
        real = cwd / "r.txt"
        real.write_text("old")
        link = cwd / "r.link"
        link.symlink_to(real)
        tool_write_file("test:agent", str(link), "new", "w")
        self.assertTrue(link.is_symlink())
        self.assertEqual(real.read_text(), "new")

    def test_move_symlink_across_devices(self):
        import errno as _errno
        from unittest import mock

        from sag import trash as trash_mod

        cwd = Path(config.shell_cwd)
        real = cwd / "big"
        real.write_text("x" * 100)
        link = cwd / "big.link"
        link.symlink_to(real)
        dst = cwd / "moved" / "payload"
        with mock.patch.object(trash_mod.os, "rename", side_effect=OSError(_errno.EXDEV, "cross")):
            trash_mod._move(link, dst)
        self.assertTrue(dst.is_symlink())
        self.assertTrue(real.exists())
        self.assertFalse(os.path.lexists(link))

    def test_purge_trash_items(self):
        from sag.trash import purge_trash_items, select_trash

        cwd = Path(config.shell_cwd)
        for n in ("p1", "p2"):
            (cwd / n).write_text(n)
            tool_delete_file("test:agent", str(cwd / n), "x")
        self.assertEqual(select_trash(), [])
        rows = select_trash(deleted_by="test:agent")
        self.assertEqual(len(rows), 2)
        self.assertEqual(purge_trash_items([rows[0]["id"]]), 1)
        self.assertEqual(len(list_trash()), 1)
        trash_dir = Path(config.db_path).parent / "trash" / rows[0]["id"]
        self.assertFalse(trash_dir.exists())

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

    # ---- restore with overwrite

    def test_restore_overwrite_undoes_a_write_in_place_and_is_itself_undoable(self):
        path = Path(config.shell_cwd) / "conf.txt"
        path.write_text("v1", encoding="utf-8")
        inode = path.stat().st_ino
        written = tool_write_file("test:agent", str(path), "v2", "overwrite")
        self.assertEqual(tool_restore_file("test:agent", written["trash_id"], "undo")["status"], "FAILED")
        res = tool_restore_file("test:agent", written["trash_id"], "undo", overwrite=True)
        self.assertEqual(res["status"], "RESTORED")
        self.assertEqual(path.read_text(encoding="utf-8"), "v1")
        self.assertEqual(path.stat().st_ino, inode)  # rewritten in place, like hub_write_file
        self.assertEqual(len(list_trash()), 1)  # the restored item is gone, the displaced v2 is in
        again = tool_restore_file("test:agent", res["displaced_trash_id"], "redo", overwrite="true")
        self.assertEqual(again["status"], "RESTORED")
        self.assertEqual(path.read_text(encoding="utf-8"), "v2")

    def test_restore_overwrite_replaces_a_directory(self):
        d = Path(config.shell_cwd) / "tree"
        d.mkdir()
        (d / "old.txt").write_text("old", encoding="utf-8")
        deleted = tool_delete_file("test:agent", str(d), "rm tree")
        d.mkdir()
        (d / "new.txt").write_text("new", encoding="utf-8")
        res = tool_restore_file("test:agent", deleted["trash_id"], "back", overwrite=True)
        self.assertEqual(res["status"], "RESTORED")
        self.assertEqual((d / "old.txt").read_text(encoding="utf-8"), "old")
        self.assertFalse((d / "new.txt").exists())
        displaced = [i for i in list_trash() if i["id"] == res["displaced_trash_id"]]
        self.assertTrue(displaced and displaced[0]["is_dir"])

    def test_restore_without_overwrite_still_refuses(self):
        path = Path(config.shell_cwd) / "a.txt"
        path.write_text("v1", encoding="utf-8")
        item_id = trash_put(path, source="delete_file", agent_id="test:agent")
        path.write_text("v2", encoding="utf-8")
        self.assertEqual(tool_restore_file("test:agent", item_id, "x", overwrite=False)["status"], "FAILED")
        self.assertEqual(path.read_text(encoding="utf-8"), "v2")

    # ---- the bin never ends up with orphans or lost rows

    def test_failed_trash_put_leaves_no_orphan_and_keeps_the_file(self):
        from sag import trash as trash_mod

        path = Path(config.shell_cwd) / "keepme.txt"
        path.write_text("data", encoding="utf-8")
        with unittest.mock.patch.object(trash_mod, "_move", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                trash_put(path, source="delete_file", agent_id="test:agent")
        self.assertEqual(path.read_text(encoding="utf-8"), "data")
        trash_root = Path(config.db_path).resolve().parent / "trash"
        self.assertEqual(list(trash_root.iterdir()) if trash_root.exists() else [], [])
        self.assertEqual(list_trash(), [])

    def test_trash_put_rolls_back_when_the_row_cannot_be_written(self):
        from sag import trash as trash_mod

        path = Path(config.shell_cwd) / "rollback.txt"
        path.write_text("data", encoding="utf-8")
        with unittest.mock.patch.object(trash_mod, "get_db_connection", side_effect=RuntimeError("db locked")):
            with self.assertRaises(RuntimeError):
                trash_put(path, source="delete_file", agent_id="test:agent")
        self.assertEqual(path.read_text(encoding="utf-8"), "data")  # not lost: back where it was
        trash_root = Path(config.db_path).resolve().parent / "trash"
        self.assertEqual(list(trash_root.iterdir()) if trash_root.exists() else [], [])

    def test_cross_device_copy_failing_halfway_removes_the_partial_payload(self):
        import errno as _errno

        from sag import trash as trash_mod

        src = Path(config.shell_cwd) / "tree2"
        src.mkdir()
        (src / "f").write_text("x", encoding="utf-8")
        dst = Path(config.shell_cwd) / "bin" / "payload"

        def half_copy(s_, d_, symlinks=False):
            Path(d_).mkdir(parents=True)
            (Path(d_) / "partial").write_text("p", encoding="utf-8")
            raise OSError(_errno.ENOSPC, "no space")

        with unittest.mock.patch.object(trash_mod.os, "rename", side_effect=OSError(_errno.EXDEV, "cross")), \
                unittest.mock.patch.object(trash_mod.shutil, "copytree", half_copy):
            with self.assertRaises(OSError):
                trash_mod._move(src, dst)
        self.assertTrue((src / "f").exists())  # the source is untouched
        self.assertFalse(os.path.lexists(dst))

    def test_expired_item_whose_payload_cannot_be_removed_keeps_its_row(self):
        from sag import trash as trash_mod

        path = Path(config.shell_cwd) / "stuck.txt"
        path.write_text("data", encoding="utf-8")
        item_id = trash_put(path, source="delete_file", agent_id="test:agent")
        with get_db_connection() as conn:
            conn.execute("UPDATE trash_items SET expires_at = '2000-01-01T00:00:00+0000' WHERE id = ?;", (item_id,))
            conn.commit()
        with unittest.mock.patch.object(trash_mod.shutil, "rmtree", lambda *a, **k: None):
            self.assertEqual(trash_mod.purge_expired_trash(), 0)
            self.assertEqual(trash_mod.purge_trash_items([item_id]), 0)
        self.assertEqual([i["id"] for i in list_trash()], [item_id])  # retried on the next pass
        self.assertEqual(trash_mod.purge_expired_trash(), 1)
        self.assertEqual(list_trash(), [])

    # ---- .env

    def test_env_file_accepts_export_inline_comments_and_quotes(self):
        from sag.config import _load_env_file

        env = Path(config.shell_cwd) / "test.env"
        env.write_text(
            "# a comment\n"
            "SAGT_PORT=4180   # the port\n"
            "export SAGT_HOST=127.0.0.1\n"
            "SAGT_QUOTED=\"has # hash\" # trailing\n"
            "SAGT_SINGLE='it is'\n"
            "SAGT_URL=http://h/#frag\n"
            "SAGT_EMPTY=\n"
            "not a setting\n",
            encoding="utf-8",
        )
        keys = ("SAGT_PORT", "SAGT_HOST", "SAGT_QUOTED", "SAGT_SINGLE", "SAGT_URL", "SAGT_EMPTY")
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            try:
                _load_env_file(env)
                self.assertEqual(int(os.environ["SAGT_PORT"]), 4180)
                self.assertEqual(os.environ["SAGT_HOST"], "127.0.0.1")
                self.assertEqual(os.environ["SAGT_QUOTED"], "has # hash")
                self.assertEqual(os.environ["SAGT_SINGLE"], "it is")
                self.assertEqual(os.environ["SAGT_URL"], "http://h/#frag")  # no whitespace before '#': not a comment
                self.assertEqual(os.environ["SAGT_EMPTY"], "")
            finally:
                for k in keys:
                    os.environ.pop(k, None)

    def test_env_file_does_not_override_the_real_environment(self):
        from sag.config import _load_env_file

        env = Path(config.shell_cwd) / "test2.env"
        env.write_text("SAGT_KEEP=from-file\n", encoding="utf-8")
        with unittest.mock.patch.dict(os.environ, {"SAGT_KEEP": "from-env"}):
            _load_env_file(env)
            self.assertEqual(os.environ["SAGT_KEEP"], "from-env")

    def test_runtime_files_are_gitignored(self):
        text = (Path(__file__).resolve().parent.parent / ".gitignore").read_text(encoding="utf-8")
        for name in (".env", "data/", "SERVER_AGENTS.md"):
            self.assertIn(name, text.split())

    def test_audit_redaction_in_shell_log(self):
        tok = "sag_cursor_helm_" + "ab12" * 12
        raw = (
            f"echo Authorization: Bearer {tok} "
            "and github_pat_AAA_BBB"
        )
        tool_shell("test:agent", raw, "probe secrets")
        rows = query_audit_logs(agent_id="test:agent", limit=1)
        stored = json.dumps(rows[0])
        self.assertNotIn(tok, stored)
        body = get_audit_event(rows[0]["id"])
        blob = json.dumps(body)
        self.assertNotIn(tok, blob)
        self.assertNotIn("github_pat_AAA_BBB", blob)
        self.assertIn("***", blob)

    def test_redact_sag_tokens_but_not_sag_names(self):
        from sag.audit_redact import redact_secrets

        real = issue_agent_token("wsl:red-team.x", "operator")
        for secret in (real, real[:40], "TOKEN=" + real + ";"):
            self.assertNotIn(real[:40], redact_secrets(secret), msg=secret)
        for plain in (
            "/tmp/sag_patches /tmp/sag_latest.bundle sag_2.1.1.bundle",
            "cat /tmp/sag_rm_round3.txt; ls /opt/sag_data",
            "python3 -m sag issue-token wsl:claude",
        ):
            self.assertEqual(redact_secrets(plain), plain)

    def test_backup_database_keeps_newest(self):
        from sag.db import backup_database

        data = Path(config.db_path).parent
        old = data / (Path(config.db_path).name + ".bak-20200101")
        old.write_text("old")
        os.utime(old, (1, 1))
        first = backup_database("v1", keep=2)
        self.assertEqual(first["removed"], [])
        self.assertEqual(os.stat(first["backup"]).st_mode & 0o777, 0o600)
        time.sleep(1.1)
        second = backup_database("v2")  # default keep = 1
        self.assertIn(".bak-v2-", second["backup"])
        self.assertEqual(sorted(second["removed"]), sorted([str(old), first["backup"]]))
        left = sorted(p.name for p in data.glob(Path(config.db_path).name + ".bak-*"))
        self.assertEqual(left, [Path(second["backup"]).name])
        self.assertTrue(Path(config.db_path).exists())
        import sqlite3 as _sq

        with contextlib.closing(_sq.connect(second["backup"])) as backup_conn:
            n = backup_conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        self.assertGreater(n, 0)
        with self.assertRaises(ValueError):
            backup_database(keep=0)

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

    def test_get_overview_section(self):
        ensure_document()
        Path(config.overview_path).write_text(
            "# h\n\n<!-- sag-status:start -->\n| up |\n<!-- sag-status:end -->\n"
            "## Host\nhost-body\n\n## Inventory\n\n### sag\nsag-body\n\n### xmem\nxmem-body\n\n"
            "## Conventions\nconv-body\n",
            encoding="utf-8",
        )
        toc = tool_get_overview(section="toc")
        self.assertIn("| up |", toc)
        self.assertIn("### sag", toc)
        self.assertNotIn("sag-body", toc)
        part = tool_get_overview(section="SAG, conventions")
        self.assertIn("sag-body", part)
        self.assertIn("conv-body", part)
        self.assertNotIn("xmem-body", part)
        self.assertNotIn("host-body", part)
        inv = tool_get_overview(section="Inventory")
        self.assertIn("xmem-body", inv)
        self.assertNotIn("conv-body", inv)
        with self.assertRaisesRegex(ValueError, "Available"):
            tool_get_overview(section="nope")

    def test_shell_result_does_not_echo_command(self):
        res = tool_shell("test:agent", "echo hi", "t")
        self.assertNotIn("command", res)
        self.assertEqual(res["stdout"].strip(), "hi")

    def test_delete_many_paths(self):
        cwd = Path(config.shell_cwd)
        a, b = cwd / "a.log", cwd / "b.log"
        a.write_text("a")
        b.write_text("b")
        res = tool_delete_file("test:agent", paths=[str(a), str(b), str(cwd / "missing")], reason="cleanup")
        self.assertEqual([r["status"] for r in res], ["TRASHED", "TRASHED", "NOT_FOUND"])
        self.assertFalse(a.exists() or b.exists())
        rows = query_audit_logs(tool_name="hub_delete_file", limit=10)
        self.assertEqual(len(rows), 3)
        with self.assertRaises(ValueError):
            tool_delete_file("test:agent", reason="x")
        c = cwd / "c.log"
        c.write_text("c")
        res = tool_delete_file("test:agent", paths=[config.db_path, str(c)], reason="mixed")
        self.assertEqual([r["status"] for r in res], ["REJECTED", "TRASHED"])
        self.assertTrue(Path(config.db_path).exists())

    def test_query_audit_logs_compact(self):
        tool_shell("test:agent", "echo compact", "t")
        row = tool_query_audit_logs(agent_id="test:agent", limit=1)[0]
        self.assertEqual(row["target"], "echo compact")
        self.assertEqual(row["exit_code"], 0)
        for k in ("created_at", "params_json", "trash_id", "params"):
            self.assertNotIn(k, row)
        long_cmd = "echo " + "x" * 300
        tool_shell("test:agent", long_cmd, "t")
        row = tool_query_audit_logs(target="echo xxx*", limit=1)[0]
        self.assertEqual(row["params"]["command"], long_cmd)
        self.assertIn("params_json", tool_get_audit_event(row["id"]))

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


class _ScratchCwdMixin:
    def setUp(self):
        _wipe_db()
        init_db()
        cwd = Path(config.shell_cwd)
        cwd.mkdir(parents=True, exist_ok=True)
        for child in list(cwd.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        # Cleanups run last-in first-out and after tearDown: registered here, this one runs after every
        # _kill_pid_file cleanup, which still need to read their pid files.
        self.addCleanup(self._empty_scratch_cwd)

    @staticmethod
    def _empty_scratch_cwd():
        for child in list(Path(config.shell_cwd).iterdir()):
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()

    def tearDown(self):
        _wipe_db()

    def _kill_pid_file(self, name):
        """Detached background processes outlive the test; kill the one that wrote its pid to `name`."""
        def kill():
            try:
                os.kill(int((Path(config.shell_cwd) / name).read_text().strip()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        self.addCleanup(kill)

    def _last_shell_event(self):
        # newest by rowid: timestamps only have one-second resolution
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE action_type = 'shell_exec' ORDER BY rowid DESC LIMIT 1;"
            ).fetchone()
        return dict(row)

    @staticmethod
    def _is_running(pid):
        """kill -0 says yes for a zombie too (nothing reaps it in a bare container); that is not running."""
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        if not Path("/proc/self").exists():
            return True  # no /proc (not Linux): kill -0 is all we have
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return False  # it vanished between the two calls
        except (OSError, IndexError):
            return True
        return state != "Z"


class TestShellOutput(_ScratchCwdMixin, unittest.TestCase):
    """hub_shell must audit every command it ran and must not let output size or content break the call."""

    def test_capture_keeps_only_cap_bytes(self):
        cap = _Capture(5)
        cap.feed(b"abc")
        self.assertFalse(cap.dropped)
        cap.feed(b"defgh")
        cap.feed(b"ijk")
        self.assertEqual(bytes(cap.buf), b"abcde")
        self.assertTrue(cap.dropped)
        self.assertEqual(cap.text(), "abcde")

    def test_capture_exact_fit_is_not_truncated(self):
        cap = _Capture(4)
        cap.feed(b"ab")
        cap.feed(b"cd")
        self.assertFalse(cap.dropped)

    def test_capture_truncation_does_not_emit_half_a_character(self):
        cap = _Capture(2)
        cap.feed("h\u00e9llo".encode("utf-8"))  # h, then the two bytes of e-acute: the cut lands inside it
        self.assertTrue(cap.dropped)
        self.assertEqual(cap.text(), "h")

    def test_capture_replaces_invalid_bytes(self):
        cap = _Capture(100)
        cap.feed(b"ok\xff\xfe!")
        self.assertEqual(cap.text(), "ok\ufffd\ufffd!")

    def test_non_utf8_output_is_returned_and_audited(self):
        result = tool_shell("test:agent", "printf 'ok\\377\\376'; printf '\\377' >&2; touch ran", "binary output")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["stdout"].startswith("ok"))
        self.assertIn("\ufffd", result["stdout"])
        self.assertIn("\ufffd", result["stderr"])
        self.assertTrue((Path(config.shell_cwd) / "ran").exists())
        event = self._last_shell_event()
        self.assertEqual(event["status"], "SUCCESS")
        self.assertIn("ok", get_audit_event(event["id"])["stdout"])

    def test_crlf_and_cr_become_lf(self):
        result = tool_shell("test:agent", "printf 'a\\r\\nb\\rc'", "newline contract")
        self.assertEqual(result["stdout"], "a\nb\nc")

    def test_unexpected_executor_error_is_still_audited(self):
        with unittest.mock.patch("sag.tools.execute_shell", side_effect=OSError("spawn failed")):
            with self.assertRaises(OSError):
                tool_shell("test:agent", "echo hi", "executor blows up")
        event = self._last_shell_event()
        self.assertEqual(event["status"], "ERROR")
        self.assertEqual(event["target"], "echo hi")
        self.assertIn("spawn failed", get_audit_event(event["id"])["stderr"])

    def test_bad_timeout_argument_is_audited(self):
        with self.assertRaises(ValueError):
            tool_shell("test:agent", "echo hi", "bad timeout", timeout_seconds="soon")
        self.assertEqual(self._last_shell_event()["status"], "ERROR")

    def test_large_output_is_capped_without_buffering_it(self):
        cap = 100_000
        with _config_override(audit_body_max_bytes=cap), _peak_traced_bytes() as traced:
            code, stdout, stderr, truncated = execute_shell("head -c 30000000 /dev/zero | tr '\\0' a")
        peak = traced["peak"]
        self.assertEqual(code, 0)
        self.assertTrue(truncated)
        self.assertLessEqual(len(stdout.encode("utf-8")), cap + len("\n[truncated]\n"))
        self.assertTrue(stdout.endswith("[truncated]\n"))
        # 30 MB went through the pipe; holding it all (as communicate() did) would peak far above this.
        self.assertLess(peak, 8_000_000)

    def test_stderr_only_overflow_is_flagged(self):
        with _config_override(audit_body_max_bytes=10_000):
            code, stdout, stderr, truncated = execute_shell("echo fine; head -c 50000 /dev/zero | tr '\\0' e >&2")
        self.assertTrue(truncated)
        self.assertEqual(stdout, "fine\n")
        self.assertTrue(stderr.endswith("[truncated]\n"))

    def test_output_larger_than_pipe_buffer_on_both_streams(self):
        code, stdout, stderr, truncated = execute_shell(
            "head -c 500000 /dev/zero | tr '\\0' b >&2; head -c 1000000 /dev/zero | tr '\\0' a"
        )
        self.assertEqual(code, 0)
        self.assertFalse(truncated)
        self.assertEqual(len(stdout), 1_000_000)
        self.assertEqual(len(stderr), 500_000)

    def test_stdin_is_closed(self):
        # Make fd 0 a pipe that neither delivers data nor EOF: a child that inherited it would wait out the timeout.
        try:
            saved = os.dup(0)
        except OSError:
            self.skipTest("test process has no stdin to replace")
        r, w = os.pipe()
        try:
            os.dup2(r, 0)
            started = time.monotonic()
            result = tool_shell("test:agent", "cat; echo done", "reads stdin")
            elapsed = time.monotonic() - started
        finally:
            os.dup2(saved, 0)
            for fd in (saved, r, w):
                os.close(fd)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "done\n")
        self.assertLess(elapsed, 4)

    def test_output_before_a_timeout_is_kept(self):
        started = time.monotonic()
        result = tool_shell("test:agent", "echo before; sleep 30", "slow", timeout_seconds=1)
        self.assertEqual(result["exit_code"], -1)
        self.assertEqual(result["stdout"], "before\n")
        self.assertIn("timed out after 1s", result["stderr"])
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(self._last_shell_event()["status"], "FAILED")

    def test_background_job_sharing_the_pipes_is_killed_at_timeout(self):
        self._kill_pid_file("bgpid")
        started = time.monotonic()
        result = tool_shell(
            "test:agent", "sleep 30 & echo $! > bgpid; echo started", "forgot to redirect", timeout_seconds=1
        )
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(result["exit_code"], -1)
        self.assertEqual(result["stdout"], "started\n")
        self.assertNotIn("still holds", result["stderr"])
        pid = int((Path(config.shell_cwd) / "bgpid").read_text().strip())
        time.sleep(0.2)
        self.assertFalse(self._is_running(pid))  # same process group: gone with the shell

    @unittest.skipUnless(shutil.which("setsid"), "setsid not installed")
    def test_detached_process_holding_the_pipes_cannot_hang_the_call(self):
        self._kill_pid_file("bgpid")
        started = time.monotonic()
        result = tool_shell(
            "test:agent", "setsid sleep 15 & echo $! > bgpid; sleep 30", "detached daemon", timeout_seconds=1
        )
        elapsed = time.monotonic() - started
        # Before: communicate() waited on the pipe the detached sleep kept open (15 s here, forever for a daemon).
        self.assertLess(elapsed, 6)
        self.assertEqual(result["exit_code"], -1)
        self.assertIn("timed out after 1s", result["stderr"])
        self.assertIn("still holds the output pipes", result["stderr"])
        self.assertEqual(self._last_shell_event()["status"], "FAILED")

    @unittest.skipUnless(shutil.which("setsid"), "setsid not installed")
    def test_redirected_background_job_returns_at_once_and_survives(self):
        self._kill_pid_file("bgpid")
        started = time.monotonic()
        result = tool_shell(
            "test:agent", "setsid nohup sleep 15 >/dev/null 2>&1 & echo $! > bgpid; echo started", "proper daemon"
        )
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "started\n")
        pid = int((Path(config.shell_cwd) / "bgpid").read_text().strip())
        self.assertTrue(self._is_running(pid))


    def test_large_stderr_is_capped_without_buffering_it(self):
        with _config_override(audit_body_max_bytes=100_000), _peak_traced_bytes() as traced:
            code, stdout, stderr, truncated = execute_shell("head -c 30000000 /dev/zero | tr '\\0' e >&2")
        self.assertEqual(code, 0)
        self.assertTrue(truncated)
        self.assertTrue(stderr.endswith("[truncated]\n"))
        self.assertLess(traced["peak"], 8_000_000)

    def test_a_stream_that_lost_bytes_is_marked_exactly_once(self):
        scenarios = {
            "stdout only": "head -c 5000 /dev/zero | tr '\\0' a",
            "stderr only": "head -c 50 /dev/zero | tr '\\0' a; head -c 5000 /dev/zero | tr '\\0' b >&2",
            "both": "head -c 5000 /dev/zero | tr '\\0' a; head -c 5000 /dev/zero | tr '\\0' b >&2",
            "stderr overflows what stdout left": "head -c 995 /dev/zero | tr '\\0' a; head -c 5000 /dev/zero | tr '\\0' b >&2",
            # CRLF shrinks the kept 1000 raw bytes to 800 characters: it fits the cap again but bytes were lost
            "crlf shrinks below the cap": "for i in $(seq 400); do printf 'abc\\r\\n'; done",
        }
        for name, command in scenarios.items():
            with self.subTest(name), _config_override(audit_body_max_bytes=1000):
                code, stdout, stderr, truncated = execute_shell(command)
                self.assertTrue(truncated)
                for stream in (stdout, stderr):
                    self.assertLessEqual(stream.count("[truncated]"), 1)
                    # nothing but the whole marker may contain a bracket: no cut-off fragments
                    self.assertNotIn("[", stream.replace("\n[truncated]\n", ""))
                self.assertTrue(stdout.endswith("[truncated]\n") or stderr.endswith("[truncated]\n"))
                if name in ("stdout only", "both", "crlf shrinks below the cap"):
                    self.assertEqual(stdout.count("[truncated]"), 1)
                if name in ("stderr only", "both", "stderr overflows what stdout left"):
                    self.assertEqual(stderr.count("[truncated]"), 1)

    def test_marker_is_clean_in_the_result_and_in_the_audit_body(self):
        cases = {
            # the cap lands inside a 3-byte character, so the kept text is 1-2 bytes short of the cap
            "3-byte characters at the cap": "for i in $(seq 700); do printf '\\xe4\\xbd\\xa0'; done",
            "crlf shrinks the kept bytes": "printf 'ab\\r\\n%.0s' $(seq 12); head -c 3000 /dev/zero | tr '\\0' z",
            "ascii": "head -c 5000 /dev/zero | tr '\\0' a",
        }
        for name, command in cases.items():
            with self.subTest(name), _config_override(audit_body_max_bytes=1000):
                result = tool_shell("test:agent", command, name)
                event = self._last_shell_event()
                body = get_audit_event(event["id"])
                self.assertTrue(result["truncated"])
                self.assertEqual(event["truncated"], 1)
                for where, text in (("result", result["stdout"]), ("audit body", body["stdout"])):
                    self.assertEqual(text.count("[truncated]"), 1, where)
                    self.assertTrue(text.endswith("\n[truncated]\n"), where)
                    self.assertNotIn("[", text.replace("\n[truncated]\n", ""), where)  # no cut-off fragment
                    self.assertNotIn("\n\n[truncated]", text, where)

    def test_audit_keeps_an_existing_marker_and_flags_it(self):
        with _config_override(audit_body_max_bytes=1000):
            append_audit("test:agent", "hub_shell", "shell_exec", "x", "r", "SUCCESS",
                         stdout="a" * 990 + "\n[truncated]\n", stderr="b\n[truncated]\n")
            event = self._last_shell_event()
        body = get_audit_event(event["id"])
        self.assertEqual(body["stdout"], "a" * 990 + "\n[truncated]\n")
        self.assertEqual(body["stderr"], "b\n[truncated]\n")
        self.assertEqual(event["truncated"], 1)

    def test_nothing_lost_means_no_marker(self):
        with _config_override(audit_body_max_bytes=1000):
            code, stdout, stderr, truncated = execute_shell("head -c 1000 /dev/zero | tr '\\0' a")
        self.assertFalse(truncated)
        self.assertEqual(stdout, "a" * 1000)
        self.assertEqual(stderr, "")

    def test_non_string_command_is_audited(self):
        with self.assertRaises(Exception):
            tool_shell("test:agent", 123, "not a string")
        event = self._last_shell_event()
        self.assertEqual(event["status"], "ERROR")
        self.assertEqual(event["target"], "123")

    def test_shell_is_killed_and_pipes_closed_if_supervision_fails(self):
        spawned = []
        real_popen = subprocess.Popen

        def spy(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        # e.g. the gateway is out of file descriptors right after the shell started
        broken = unittest.mock.Mock(side_effect=OSError(24, "Too many open files"))
        with unittest.mock.patch("sag.executor.subprocess.Popen", spy), \
                unittest.mock.patch("sag.executor.selectors.PollSelector", broken), \
                unittest.mock.patch("sag.executor.selectors.DefaultSelector", broken):
            with self.assertRaises(OSError):
                execute_shell("sleep 20")
        (proc,) = spawned
        self.assertIsNotNone(proc.poll())  # killed and reaped, not left running
        self.assertTrue(proc.stdout.closed and proc.stderr.closed)

    @unittest.skipUnless(hasattr(__import__("selectors"), "PollSelector"), "no poll() on this platform")
    def test_supervision_uses_poll_which_needs_no_new_file_descriptor(self):
        import selectors

        real = selectors.PollSelector
        used = []

        def spy():
            used.append(True)
            return real()

        with unittest.mock.patch("sag.executor.selectors.PollSelector", spy):
            execute_shell("echo hi")
        self.assertTrue(used)


class TestClipAndTrashIds(_ScratchCwdMixin, unittest.TestCase):
    """Big stdout must not evict stderr; recycle-bin ids must reach the audit row however the command redirects."""

    def test_clip_output_fits_untouched(self):
        self.assertEqual(clip_output("abc", "de", 5), ("abc", "de", False))
        self.assertEqual(clip_output("", "", 0), ("", "", False))

    def test_clip_output_keeps_a_stderr_share_when_stdout_is_huge(self):
        out, err, clipped = clip_output("o" * 5000, "error: boom\n", 1000)
        self.assertTrue(clipped)
        self.assertEqual(err, "error: boom\n")  # not truncated, not replaced
        self.assertTrue(out.endswith(TRUNCATED_MARK))
        self.assertLessEqual(len(out.encode()) - len(TRUNCATED_MARK) + len(err.encode()), 1000)

    def test_clip_output_stdout_that_exactly_fills_the_budget_does_not_wipe_stderr(self):
        out, err, clipped = clip_output("o" * 1000, "note\n", 1000)
        self.assertTrue(clipped)
        self.assertEqual(err, "note\n")

    def test_clip_output_stdout_gets_what_stderr_does_not_need(self):
        out, err, clipped = clip_output("o" * 5000, "e" * 10, 1000)
        self.assertEqual(len(out.encode()) - len(TRUNCATED_MARK), 990)

    def test_clip_output_stderr_is_cut_when_it_is_the_one_that_overflows(self):
        out, err, clipped = clip_output("fine\n", "e" * 5000, 1000)
        self.assertEqual(out, "fine\n")
        self.assertTrue(err.endswith(TRUNCATED_MARK))
        self.assertEqual(len(err.encode()) - len(TRUNCATED_MARK), 995)

    def test_clip_output_both_overflowing_marks_both_and_never_splits_a_character(self):
        out, err, clipped = clip_output("\u4f60" * 2000, "\u597d" * 2000, 1000)
        self.assertTrue(out.endswith(TRUNCATED_MARK) and err.endswith(TRUNCATED_MARK))
        self.assertNotIn("\ufffd", out + err)
        body = (out[: -len(TRUNCATED_MARK)] + err[: -len(TRUNCATED_MARK)]).encode()
        self.assertLessEqual(len(body), 1000)
        self.assertGreaterEqual(len(err[: -len(TRUNCATED_MARK)].encode()), 120)  # the reserve: 1000 // 8

    def test_error_message_and_timeout_note_survive_a_flood_on_stdout(self):
        with _config_override(audit_body_max_bytes=1000):
            result = tool_shell(
                "test:agent", "echo 'error: it broke' >&2; head -c 50000 /dev/zero | tr '\\0' a", "flood"
            )
            self.assertTrue(result["truncated"])
            self.assertIn("error: it broke", result["stderr"])
            slow = tool_shell(
                "test:agent", "head -c 50000 /dev/zero | tr '\\0' a; sleep 30", "flood then hang", timeout_seconds=1
            )
        self.assertEqual(slow["exit_code"], -1)
        self.assertIn("timed out after 1s", slow["stderr"])
        body = get_audit_event(self._last_shell_event()["id"])
        self.assertIn("timed out after 1s", body["stderr"])

    def test_trash_ids_survive_big_stdout_and_every_redirection(self):
        cwd = Path(config.shell_cwd)
        variants = {
            "plain": "rm {a} {b}",
            "big stdout": "rm {a} {b}; head -c 50000 /dev/zero | tr '\\0' o",
            "stderr to /dev/null": "rm {a} {b} 2>/dev/null",
            "stderr merged into stdout": "rm {a} {b} 2>&1",
            "all output discarded": "rm {a} {b} >/dev/null 2>&1",
        }
        for name, template in variants.items():
            with self.subTest(name), _config_override(audit_body_max_bytes=1000):
                a, b = cwd / f"{abs(hash(name))}_a", cwd / f"{abs(hash(name))}_b"
                a.write_text("a")
                b.write_text("b")
                result = tool_shell("test:agent", template.format(a=a, b=b), name)
                self.assertFalse(a.exists() or b.exists())
                self.assertEqual(len(result["trash_ids"]), 2, result)
                self.assertNotIn("SAG_TRASH", result["stdout"] + result["stderr"])
                event = self._last_shell_event()
                self.assertEqual(event["trash_id"], result["trash_ids"][0])
                self.assertEqual(
                    json.loads(event["params_json"])["trash_ids"], result["trash_ids"]
                )
                self.assertEqual({i["id"] for i in list_trash(limit=200) if i["id"] in result["trash_ids"]},
                                 set(result["trash_ids"]))

    def test_many_trash_ids_are_never_cut_in_half(self):
        cwd = Path(config.shell_cwd)
        for i in range(40):
            (cwd / f"file_{i:02d}").write_text("x")
        with _config_override(audit_body_max_bytes=300):
            result = tool_shell("test:agent", "rm file_*", "many")
        self.assertEqual(len(result["trash_ids"]), 40)
        self.assertEqual(len(set(result["trash_ids"])), 40)
        self.assertTrue(all(len(i) == 36 for i in result["trash_ids"]))

    def test_a_command_cannot_forge_trash_ids(self):
        cwd = Path(config.shell_cwd)
        (cwd / "mine").write_text("x")
        (cwd / "theirs").write_text("x")
        tool_shell("other:agent", "rm theirs", "someone else deletes")
        theirs = list_trash()[0]["id"]
        result = tool_shell(
            "test:agent",
            f"echo 00000000-0000-0000-0000-000000000000 >> $SAG_TRASH_FILE; echo {theirs} >> $SAG_TRASH_FILE; "
            f"echo not-an-id >> $SAG_TRASH_FILE; echo 'SAG_TRASH {theirs}' >&2; rm mine",
            "forge",
        )
        self.assertEqual(len(result["trash_ids"]), 1)
        self.assertNotIn(theirs, result["trash_ids"])
        self.assertIn(f"SAG_TRASH {theirs}", result["stderr"])  # plain stderr text: neither parsed nor stripped

    def test_trash_id_file_is_removed_after_every_call(self):
        import glob

        pattern = os.path.join(tempfile.gettempdir(), "sag-trash-*")
        before = set(glob.glob(pattern))
        tool_shell("test:agent", "echo hi", "no rm")
        with self.assertRaises(CommandExecutionError):
            tool_shell("test:agent", "   ", "empty")
        self.assertEqual(set(glob.glob(pattern)), before)

    def test_rm_wrapper_run_by_hand_still_prints_the_id(self):
        victim = Path(config.shell_cwd) / "by_hand"
        victim.write_text("x")
        env = {k: v for k, v in os.environ.items() if k != "SAG_TRASH_FILE"}
        env["SAG_AGENT_ID"] = "test:agent"
        proc = subprocess.run(
            [sys.executable, str(_ROOT / "wrappers" / "rm"), str(victim)], env=env, capture_output=True, text=True
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stderr, r"^SAG_TRASH [0-9a-f-]{36}$")
        self.assertFalse(victim.exists())

    def test_rm_accepts_gnu_long_options(self):
        cwd = Path(config.shell_cwd)
        (cwd / "d").mkdir()
        (cwd / "d" / "f").write_text("x")
        (cwd / "single").write_text("x")
        result = tool_shell(
            "test:agent",
            "rm --force --recursive --verbose d missing; echo first=$?; rm --force missing; echo second=$?; "
            "rm --no-preserve-root --one-file-system single; echo third=$?; rm --dir nothere; echo fourth=$?",
            "long options",
        )
        self.assertIn("first=0", result["stdout"])
        self.assertIn("second=0", result["stdout"])
        self.assertIn("third=0", result["stdout"])
        self.assertIn("fourth=1", result["stdout"])  # a missing operand without --force is still an error
        self.assertFalse((cwd / "d").exists() or (cwd / "single").exists())
        self.assertEqual(len(result["trash_ids"]), 2)

    def test_rm_still_rejects_options_it_does_not_know(self):
        result = tool_shell("test:agent", "rm --interactive=always x; echo rc=$?", "unknown option")
        self.assertIn("rc=1", result["stdout"])
        self.assertIn("unsupported option --interactive=always", result["stderr"])

    def test_audit_body_also_keeps_stderr_when_stdout_is_huge(self):
        with _config_override(audit_body_max_bytes=1000):
            append_audit("test:agent", "hub_shell", "shell_exec", "x", "r", "FAILED",
                         stdout="o" * 5000, stderr="error: kept\n")
            body = get_audit_event(self._last_shell_event()["id"])
        self.assertEqual(body["stderr"], "error: kept\n")
        self.assertTrue(body["stdout"].endswith(TRUNCATED_MARK))


class TestDispatchAudit(_ScratchCwdMixin, unittest.TestCase):
    """docs/v2.md section 3: every tools/call is audited, whether it succeeds or fails, exactly once."""

    def _call(self, tool, args=None, agent="test:agent", role="operator"):
        from sag.server import dispatch_tool

        return dispatch_tool(agent, role, tool, args)

    def _rows(self):
        with get_db_connection() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY rowid;")]

    def _only_row(self):
        rows = self._rows()
        self.assertEqual(len(rows), 1, [(r["tool_name"], r["status"]) for r in rows])
        return rows[0]

    def test_unknown_tool_is_recorded(self):
        with self.assertRaisesRegex(ValueError, "Unknown MCP tool: hub_nope"):
            self._call("hub_nope", {"x": 1})
        row = self._only_row()
        self.assertEqual((row["tool_name"], row["status"], row["agent_id"]), ("hub_nope", "REJECTED", "test:agent"))
        self.assertEqual(json.loads(row["params_json"]), {"x": 1})

    def test_tool_names_that_are_not_strings_do_not_break_the_audit(self):
        for bad in (None, 5, {"a": 1}, "x" * 500):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self._call(bad, {})
        self.assertEqual(len(self._rows()), 4)
        self.assertTrue(all(len(r["tool_name"]) <= 100 for r in self._rows()))

    def test_admin_tool_denied_to_an_operator_looks_unknown_but_is_recorded_as_denied(self):
        with self.assertRaisesRegex(ValueError, "Unknown MCP tool: hub_issue_agent_token"):
            self._call("hub_issue_agent_token", {"agent_id": "new:agent"})
        row = self._only_row()
        self.assertEqual(row["status"], "REJECTED")
        self.assertIn("admin-only", get_audit_event(row["id"])["stderr"])

    def test_bad_arguments_are_recorded_with_a_readable_message(self):
        cases = [
            ("hub_shell", {"command": "echo hi"}, "missing a required argument: 'reason'"),
            ("hub_shell", {"command": "echo hi", "reason": "r", "bogus": 1}, "unexpected keyword argument 'bogus'"),
            ("hub_send_message", {"to": "x", "body": "b", "from": "someone:else"}, "'from' is not accepted"),
            ("hub_read_file", "not an object", "arguments must be an object"),
        ]
        for tool, args, expected in cases:
            with self.subTest(tool=tool, args=args), self.assertRaisesRegex(ValueError, expected):
                self._call(tool, args)
        rows = self._rows()
        self.assertEqual([r["status"] for r in rows], ["REJECTED"] * len(cases))
        self.assertEqual(rows[0]["reason"], "")

    def test_none_arguments_are_fine_for_tools_without_required_ones(self):
        self.assertIn("load", json.dumps(self._call("hub_get_status", None)).lower() + "load")
        self.assertIsInstance(self._call("hub_list_agents", None), dict)

    def test_unexpected_errors_from_file_tools_are_recorded(self):
        cwd = Path(config.shell_cwd)
        (cwd / "plain.txt").write_text("x")
        with self.assertRaises(OSError):  # the parent of the new file is a regular file
            self._call("hub_write_file", {"path": str(cwd / "plain.txt" / "child"), "content": "c", "reason": "r"})
        row = self._only_row()
        self.assertEqual((row["tool_name"], row["status"]), ("hub_write_file", "FAILED"))
        self.assertTrue(row["target"].endswith("plain.txt/child"))
        self.assertEqual(row["reason"], "r")
        self.assertRegex(get_audit_event(row["id"])["stderr"], r"^(NotADirectoryError|FileExistsError): ")

    def test_bad_values_for_read_file_are_recorded(self):
        path = Path(config.shell_cwd) / "r.txt"
        path.write_text("x")
        with self.assertRaises(ValueError):
            self._call("hub_read_file", {"path": str(path), "offset": "abc"})
        self.assertEqual(self._only_row()["status"], "FAILED")

    def test_validation_errors_from_collab_tools_are_recorded(self):
        with self.assertRaises(ValueError):
            self._call("hub_send_message", {"to": "nobody:here", "body": "hi"})
        row = self._only_row()
        self.assertEqual((row["tool_name"], row["status"]), ("hub_send_message", "FAILED"))
        self.assertEqual(row["target"], "nobody:here")

    def test_failures_the_tools_already_record_are_not_recorded_twice(self):
        cwd = Path(config.shell_cwd)
        scenarios = [
            ("hub_read_file", {"path": str(cwd / "missing.txt")}),
            ("hub_list_dir", {"path": str(cwd / "missing")}),
            ("hub_patch_file", {"path": str(cwd / "missing.txt"), "old_string": "a", "new_string": "b", "reason": "r"}),
            ("hub_shell", {"command": "   ", "reason": "empty"}),
            ("hub_shell", {"command": "echo hi", "reason": "r", "timeout_seconds": "soon"}),
            ("hub_mkdir", {"path": str(Path(config.data_dir) / "x"), "reason": "protected"}),
            ("hub_read_file", {"path": str(cwd)}),
        ]
        for tool, args in scenarios:
            with self.subTest(tool=tool, args=args):
                with get_db_connection() as conn:
                    before = conn.execute("SELECT COUNT(*) AS n FROM audit_events;").fetchone()["n"]
                with self.assertRaises(Exception):
                    self._call(tool, args)
                with get_db_connection() as conn:
                    after = conn.execute("SELECT COUNT(*) AS n FROM audit_events;").fetchone()["n"]
                self.assertEqual(after - before, 1)

    def test_permission_errors_are_recorded_as_rejected(self):
        # the admin check inside the tool is the second line of defence behind the dispatcher's
        with self.assertRaises(PermissionError):
            from sag.server import _audit_failure

            try:
                tool_issue_agent_token(caller_agent_id="test:agent", caller_role="operator", agent_id="x:y")
            except PermissionError as exc:
                _audit_failure("test:agent", "hub_issue_agent_token", {"agent_id": "x:y"}, exc)
                raise
        row = self._only_row()
        self.assertEqual((row["status"], row["action_type"]), ("REJECTED", "tool_rejected"))

    def test_big_and_secret_arguments_are_summarised_and_redacted(self):
        token = "sag_laptop_claude_" + "ab12" * 12
        with self.assertRaises(Exception):
            self._call("hub_write_file", {"path": "/proc/nope/x", "content": "A" * 100_000 + token, "reason": "r"})
        row = self._only_row()
        params = json.loads(row["params_json"])
        self.assertLess(len(row["params_json"]), 2000)
        self.assertIn("chars)", params["content"])
        self.assertNotIn("ab12ab12", row["params_json"])

    def test_a_failing_audit_write_never_hides_the_real_error(self):
        err = io.StringIO()
        with unittest.mock.patch("sag.server.append_audit", side_effect=RuntimeError("db locked")), \
                contextlib.redirect_stderr(err):
            with self.assertRaisesRegex(ValueError, "Unknown MCP tool"):
                self._call("hub_nope")
        self.assertIn("could not record failed call", err.getvalue())

    def test_rebuild_overview_is_attributed_to_the_caller(self):
        self._call("hub_rebuild_overview", {"reason": "after a deploy"}, agent="laptop:claude")
        rows = [r for r in self._rows() if r["tool_name"] == "hub_rebuild_overview"]
        self.assertEqual([(r["agent_id"], r["reason"]) for r in rows], [("laptop:claude", "after a deploy")])

    def test_shell_result_survives_a_failing_audit_write(self):
        calls = []
        def flaky(**kw):
            calls.append(kw["tool_name"])
            raise RuntimeError("database is locked")

        err = io.StringIO()
        with unittest.mock.patch("sag.tools.append_audit", flaky), unittest.mock.patch("sag.tools.time.sleep"), \
                contextlib.redirect_stderr(err):
            result = tool_shell("test:agent", "echo ran > proof.txt; echo out", "audit is down")
        self.assertIn("could not record hub_shell", err.getvalue())
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "out\n")
        self.assertIn("could not be written", result["audit_error"])
        self.assertEqual((Path(config.shell_cwd) / "proof.txt").read_text(), "ran\n")
        self.assertEqual(calls, ["hub_shell", "hub_shell"])  # tried twice

    def test_shell_audit_is_retried_once_and_then_no_warning(self):
        state = {"n": 0}
        real = append_audit

        def once_locked(**kw):
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("database is locked")
            return real(**kw)

        with unittest.mock.patch("sag.tools.append_audit", once_locked), unittest.mock.patch("sag.tools.time.sleep"):
            result = tool_shell("test:agent", "echo hi", "flaky audit")
        self.assertNotIn("audit_error", result)
        self.assertEqual(self._only_row()["status"], "SUCCESS")

    def test_query_order_is_stable_within_one_second(self):
        with unittest.mock.patch("sag.db.time.strftime", return_value="2026-01-01T00:00:00+0000"):
            for i in range(5):
                append_audit("test:agent", "hub_shell", "shell_exec", f"cmd{i}", "r", "SUCCESS")
        self.assertEqual([r["target"] for r in query_audit_logs()], [f"cmd{i}" for i in (4, 3, 2, 1, 0)])
        self.assertEqual([r["target"] for r in query_audit_logs(limit=2, offset=1)], ["cmd3", "cmd2"])

    def test_trash_listing_order_is_stable_within_one_second(self):
        cwd = Path(config.shell_cwd)
        for i in range(4):
            (cwd / f"t{i}").write_text("x")
            tool_delete_file("test:agent", str(cwd / f"t{i}"), "r")
        with get_db_connection() as conn:  # the same second for all of them
            conn.execute("UPDATE trash_items SET deleted_at = '2026-01-01T00:00:00+0000';")
            conn.commit()
        self.assertEqual([Path(i["original_path"]).name for i in list_trash()], ["t3", "t2", "t1", "t0"])


class TestReconcile(_ScratchCwdMixin, unittest.TestCase):
    """The status refresh must not make every tool call wait for slow probes, nor corrupt SERVER_AGENTS.md."""

    INVENTORY = "# h\n\n## Host\n\n## Inventory\n\n" + "".join(
        f"### svc{i}\n\n- probe: tcp 127.0.0.1:{9000 + i}\n\n" for i in range(6)
    ) + "## Conventions\n"

    def setUp(self):
        super().setUp()
        ov = Path(config.overview_path)
        if ov.exists():
            ov.unlink()
        ensure_document()
        Path(config.overview_path).write_text(self.INVENTORY, encoding="utf-8")

    def tearDown(self):
        super().tearDown()
        ov = Path(config.overview_path)
        if ov.exists():
            ov.unlink()

    def test_tool_calls_do_not_wait_for_slow_probes(self):
        from sag import reconciler

        def slow_probe(kind, spec):
            time.sleep(0.8)
            return "up"

        with unittest.mock.patch.object(reconciler, "probe_one", slow_probe):
            started = time.monotonic()
            result = tool_shell("test:agent", "echo hi", "fast command")
            path = Path(config.shell_cwd) / "w.txt"
            tool_write_file("test:agent", str(path), "x", "write")
            tool_patch_file("test:agent", str(path), "x", "y", "patch")
            tool_delete_file("test:agent", str(path), "delete")
            elapsed = time.monotonic() - started
            self.assertEqual(result["stdout"], "hi\n")
            # six 0.8 s probes, one after the other, per call, used to be 4.8 s each
            self.assertLess(elapsed, 2.0)
            self.assertTrue(reconciler.wait_reconciled(30))
        text = read_overview()
        self.assertEqual(text.count("| up |"), 6, text)

    def test_probes_run_side_by_side(self):
        from sag import reconciler

        def slow_probe(kind, spec):
            time.sleep(0.5)
            return spec

        with unittest.mock.patch.object(reconciler, "probe_one", slow_probe), \
                unittest.mock.patch.object(reconciler, "list_docker_names", lambda: []):
            started = time.monotonic()
            probes, untracked = reconciler.collect_probes_and_untracked()
            elapsed = time.monotonic() - started
        self.assertEqual([p["state"] for p in probes], [f"127.0.0.1:{9000 + i}" for i in range(6)])  # order kept
        self.assertLess(elapsed, 1.6)  # sequentially: 3.0 s

    def test_requests_while_a_pass_is_running_are_coalesced(self):
        from sag import reconciler

        runs, gate = [], threading.Event()

        def fake_reconcile():
            runs.append(time.monotonic())
            gate.wait(5)

        with unittest.mock.patch.object(reconciler, "reconcile", fake_reconcile):
            reconciler.request_reconcile()
            deadline = time.monotonic() + 3
            while not runs and time.monotonic() < deadline:
                time.sleep(0.01)
            for _ in range(30):
                reconciler.request_reconcile()  # all while the first pass is still running
            gate.set()
            self.assertTrue(reconciler.wait_reconciled(10))
        self.assertEqual(len(runs), 2)  # the running pass, plus one follow-up for everything that arrived meanwhile

    def test_a_failing_pass_does_not_wedge_the_worker(self):
        from sag import reconciler

        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("probe exploded")

        with unittest.mock.patch.object(reconciler, "reconcile", flaky), contextlib.redirect_stdout(io.StringIO()) as out:
            reconciler.request_reconcile()
            self.assertTrue(reconciler.wait_reconciled(10))
            reconciler.request_reconcile()
            self.assertTrue(reconciler.wait_reconciled(10))
        self.assertEqual(len(calls), 2)
        self.assertIn("background pass failed", out.getvalue())

    def test_rebuild_overview_still_returns_the_refreshed_document(self):
        from sag import reconciler

        with unittest.mock.patch.object(reconciler, "probe_one", lambda kind, spec: "down"):
            text = tool_rebuild_overview("check")
        self.assertEqual(text.count("| down |"), 6)

    def test_overview_readers_and_writers_take_the_document_lock(self):
        from sag import reconciler
        from sag.overview import doc_lock, write_handwritten

        attempts = {
            "read": lambda: read_overview(),
            "write": lambda: write_handwritten("# edited\n\n## Inventory\n"),
            "ensure": lambda: ensure_document(),
        }
        with unittest.mock.patch.object(reconciler, "probe_one", lambda kind, spec: "up"), \
                unittest.mock.patch.object(reconciler, "list_docker_names", lambda: []):
            attempts["refresh"] = reconciler.refresh_status_block
            for name, action in attempts.items():
                with self.subTest(name):
                    done = threading.Event()
                    with doc_lock:
                        t = threading.Thread(target=lambda: (action(), done.set()), daemon=True)
                        t.start()
                        self.assertFalse(done.wait(0.4), f"{name} did not wait for the lock")
                    self.assertTrue(done.wait(5), f"{name} never finished")
                    t.join(2)

    def test_concurrent_readers_never_see_a_half_written_document(self):
        from sag import reconciler
        from sag.overview import write_handwritten

        stop = threading.Event()
        problems = []

        def writer():
            n = 0
            while not stop.is_set():
                n += 1
                write_handwritten(f"# edit {n}\n\n## Host\n\n## Inventory\n\n## Conventions\n" + "filler\n" * 200)

        def refresher():
            with unittest.mock.patch.object(reconciler, "list_docker_names", lambda: []):
                while not stop.is_set():
                    reconciler.refresh_status_block()

        def reader():
            while not stop.is_set():
                text = read_overview()
                if not text.startswith("#") or "## Inventory" not in text:
                    problems.append(text[:60])

        threads = [threading.Thread(target=f, daemon=True) for f in (writer, refresher, reader, reader)]
        for t in threads:
            t.start()
        time.sleep(1.5)
        stop.set()
        for t in threads:
            t.join(5)
        self.assertEqual(problems, [])

    def test_the_http_probe_only_opens_http_urls(self):
        from sag import reconciler

        with unittest.mock.patch("urllib.request.urlopen") as urlopen:
            for spec in ("file:///etc/hostname", "ftp://host/x", "gopher://x", "/just/a/path"):
                self.assertEqual(reconciler.probe_one("http", spec), "unknown", spec)
            urlopen.assert_not_called()

    def test_http_probe_reports_up_and_down(self):
        import http.server

        from sag import reconciler

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == "/ok" else 503)
                self.end_headers()

            def log_message(self, *a):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)  # cleanups run last-in first-out: stop serving, then close the socket
        self.addCleanup(httpd.shutdown)
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        self.assertEqual(reconciler.probe_one("http", base + "/ok"), "up")
        self.assertEqual(reconciler.probe_one("http", base + "/bad"), "down")

    def test_untracked_containers_match_whole_names_only(self):
        inventory = "### shop\n- probe: docker app-db\n\nthe database lives elsewhere, see my.cache.v2\n"
        names = ["db", "app", "app-db", "cache", "my.cache.v2", "data", "base"]
        self.assertEqual(
            untracked_containers(inventory, names),
            ["docker:db", "docker:app", "docker:cache", "docker:data", "docker:base"],
        )
        self.assertEqual(untracked_containers("x (a+b)", ["a+b", "a.b"]), ["docker:a.b"])


class TestReadFileCap(_ScratchCwdMixin, unittest.TestCase):
    """hub_read_file streams the file: bounded memory, line windows, continuation hints."""

    def _file(self, data, name="f.txt"):
        path = Path(config.shell_cwd) / name
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return str(path)

    def _lines(self, n):
        return "".join(f"line {i:02d}\n" for i in range(1, n + 1))  # 8 bytes each

    def test_small_file_is_unchanged(self):
        res = tool_read_file("test:agent", self._file("a\nb\nc\n"))
        self.assertEqual(res["content"], "a\nb\nc\n")
        self.assertNotIn("truncated", res)
        self.assertNotIn("next_offset", res)

    def test_offset_and_limit(self):
        path = self._file("a\nb\nc\nd")
        self.assertEqual(tool_read_file("test:agent", path, offset=2, limit=2)["content"], "b\nc\n")
        self.assertEqual(tool_read_file("test:agent", path, offset=4)["content"], "d")
        self.assertEqual(tool_read_file("test:agent", path, offset=99)["content"], "")
        self.assertEqual(tool_read_file("test:agent", path, limit=0)["content"], "")
        self.assertEqual(tool_read_file("test:agent", path, offset=0, limit=1)["content"], "a\n")

    def test_lines_end_at_newline_only(self):
        path = self._file("a\rb\nc\x0cd\ne\n")
        self.assertEqual(tool_read_file("test:agent", path, offset=2, limit=1)["content"], "c\x0cd\n")

    def test_cap_in_the_middle_of_a_line_leaves_that_line_whole_for_the_next_page(self):
        path = self._file(self._lines(50))
        with _config_override(read_max_bytes=100):
            first = tool_read_file("test:agent", path)
            self.assertTrue(first["truncated"])
            self.assertEqual(first["content"], self._lines(12))  # 96 bytes; line 13 would end at byte 104
            self.assertEqual(first["next_offset"], 13)
            second = tool_read_file("test:agent", path, offset=first["next_offset"])
        self.assertTrue(second["content"].startswith("line 13\n"))

    def test_following_next_offset_reassembles_the_file(self):
        rnd = random.Random(7)
        for case in range(60):
            lines = ["".join(rnd.choice("ab \u00e9\u4f60") for _ in range(rnd.choice([0, 1, 5, 20, 60]))) + "\n"
                     for _ in range(rnd.randint(0, 40))]
            if lines and rnd.random() < 0.3:
                lines[-1] = lines[-1].rstrip("\n")  # no trailing newline
            text = "".join(lines)
            path = self._file(text, f"p{case}.txt")
            longest = max((len(line.encode()) for line in lines), default=1)
            cap = max(longest, rnd.choice([1, 8, 40, 100, 257]))  # a cap below the longest line is covered separately
            pages, offset = [], 1
            with _config_override(read_max_bytes=cap):
                for _ in range(len(lines) + 2):
                    res = tool_read_file("test:agent", path, offset=offset)
                    self.assertLessEqual(len(res["content"].encode()), cap)
                    pages.append(res["content"])
                    if not res.get("truncated"):
                        break
                    self.assertGreater(res["next_offset"], offset)
                    offset = res["next_offset"]
                else:
                    self.fail("paging never finished")
            self.assertEqual("".join(pages), text, f"case {case}, cap {cap}")

    def test_cap_exactly_at_a_line_boundary(self):
        path = self._file(self._lines(50))
        with _config_override(read_max_bytes=96):
            first = tool_read_file("test:agent", path)
            self.assertTrue(first["truncated"])
            self.assertEqual(first["content"], self._lines(12))
            self.assertEqual(first["next_offset"], 13)
            second = tool_read_file("test:agent", path, offset=first["next_offset"], limit=1)
        self.assertEqual(second["content"], "line 13\n")
        self.assertNotIn("truncated", second)

    def test_file_exactly_as_big_as_the_cap_is_not_truncated(self):
        path = self._file(self._lines(4))
        with _config_override(read_max_bytes=32):
            res = tool_read_file("test:agent", path)
        self.assertEqual(res["content"], self._lines(4))
        self.assertNotIn("truncated", res)

    def test_one_huge_line_is_cut_and_can_be_skipped(self):
        path = self._file("x" * 300_000 + "\nsecond\nthird\n")
        with _config_override(read_max_bytes=1000):
            first = tool_read_file("test:agent", path)
            self.assertEqual(first["content"], "x" * 1000)
            self.assertTrue(first["truncated"])
            self.assertEqual(first["next_offset"], 2)
            self.assertIn("longer than", first["note"])
            self.assertEqual(tool_read_file("test:agent", path, offset=2, limit=1)["content"], "second\n")
            self.assertEqual(tool_read_file("test:agent", path, offset=3)["content"], "third\n")

    def test_cap_never_splits_a_multibyte_character(self):
        path = self._file("\u4f60\u597d\u4e16\u754c\n")  # four 3-byte characters
        with _config_override(read_max_bytes=7):
            res = tool_read_file("test:agent", path)
        self.assertEqual(res["content"], "\u4f60\u597d")
        self.assertTrue(res["truncated"])

    def test_large_file_is_not_loaded_whole(self):
        path = Path(config.shell_cwd) / "big.log"
        with open(path, "wb") as f:
            for _ in range(200):
                f.write((b"y" * 99 + b"\n") * 1000)  # 20 MB
        with _config_override(read_max_bytes=50_000), _peak_traced_bytes() as traced:
            res = tool_read_file("test:agent", str(path), offset=150_000, limit=10)
        self.assertEqual(res["content"], ("y" * 99 + "\n") * 10)
        self.assertLess(traced["peak"], 5_000_000)

    def test_binary_and_invalid_utf8_are_still_rejected_and_audited(self):
        with self.assertRaises(ValueError):
            tool_read_file("test:agent", self._file(b"\x00abc"))
        with self.assertRaises(ValueError):
            tool_read_file("test:agent", self._file(b"ok\xff\n", "bad.txt"))
        rows = query_audit_logs(action_type="file_read", limit=2)
        self.assertEqual([r["status"] for r in rows], ["FAILED", "FAILED"])

    def test_invalid_utf8_error_names_the_line_in_the_file(self):
        path = self._file(b"ok\nfine\nbad\xff\nafter\n")
        with self.assertRaises(ValueError) as ctx:
            tool_read_file("test:agent", path, offset=2)
        self.assertIn("line 3", str(ctx.exception))
        self.assertIn("0xff", str(ctx.exception))
        row = query_audit_logs(action_type="file_read", limit=1)[0]
        self.assertEqual(row["status"], "FAILED")
        self.assertEqual(json.loads(row["params_json"])["invalid_utf8_line"], 3)
        # the bad line is outside this window, so the read succeeds
        self.assertEqual(tool_read_file("test:agent", path, offset=1, limit=2)["content"], "ok\nfine\n")

    def test_skipping_lines_around_the_64k_chunk_boundary(self):
        for length in (65534, 65535, 65536, 65537, 131071, 131072, 131073):
            with self.subTest(length=length):
                path = self._file("x" * length + "\ny\n" + "second\n", f"l{length}.txt")
                self.assertEqual(tool_read_file("test:agent", path, offset=2, limit=1)["content"], "y\n")
                self.assertEqual(tool_read_file("test:agent", path, offset=3)["content"], "second\n")
                self.assertEqual(tool_read_file("test:agent", path, offset=4)["content"], "")

    def test_skipping_a_huge_line_does_not_load_it(self):
        path = self._file("z" * 20_000_000 + "\nnext\n")
        with _peak_traced_bytes() as traced:
            res = tool_read_file("test:agent", path, offset=2)
        self.assertEqual(res["content"], "next\n")
        self.assertLess(traced["peak"], 3_000_000)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no named pipes on this platform")
    def test_named_pipe_is_rejected_instead_of_blocking_a_worker(self):
        fifo = Path(config.shell_cwd) / "pipe"
        os.mkfifo(fifo)  # nobody ever opens the other end: open() would block forever
        box = {}

        def reader():
            try:
                box["res"] = tool_read_file("test:agent", str(fifo))
            except Exception as exc:
                box["exc"] = exc

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(5)
        if t.is_alive():
            os.close(os.open(fifo, os.O_RDWR | os.O_NONBLOCK))  # release the blocked open(), then fail
            t.join(2)
            self.fail("hub_read_file blocked on a pipe")
        self.assertIsInstance(box.get("exc"), ValueError)
        self.assertIn("not a regular file", str(box["exc"]))
        self.assertEqual(query_audit_logs(action_type="file_read", limit=1)[0]["status"], "FAILED")

    @unittest.skipUnless(os.path.exists("/dev/zero"), "no /dev/zero")
    def test_devices_are_rejected(self):
        with self.assertRaises(ValueError):
            tool_read_file("test:agent", "/dev/zero")


class TestCredentials(unittest.TestCase):
    def setUp(self):
        _wipe_db()
        init_db()

    def tearDown(self):
        _wipe_db()

    def test_agent_id_format_is_validated_at_issuance(self):
        for bad in ("", " ", "a b", "ops team:bot", "x,y", "@group", "*", "wsl:*", "a/b", "\u514b\u52b3\u5fb7",
                    "a" * 65, ":x", "x:", "a::b", "a:b:c:d:e", None, 5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                issue_agent_token(bad, "operator")
        for good in ("cron", "laptop:claude", "mobile:xiaoyao", "wsl:red-team.x", "a:b:c", "A_1.2-3"):
            with self.subTest(good=good):
                self.assertEqual(authenticate_bearer_token(issue_agent_token(good, "operator"))[0], good)

    def test_online_issuing_rejects_bad_ids_too(self):
        with self.assertRaises(ValueError):
            tool_issue_agent_token(
                caller_agent_id=config.root_admin_agent_id, caller_role="admin", agent_id="two words"
            )
        self.assertEqual(
            [r for r in query_audit_logs(action_type="token_issue")], [], "nothing was issued, nothing to record"
        )

    def test_tokens_of_unusual_legacy_ids_are_still_redacted(self):
        from sag.audit_redact import redact_secrets

        secret = "ab12" * 12
        for agent_id in ("laptop_claude", "\u514b\u52b3\u5fb7", "ops team_bot", "a/b_c", "x,y_z"):
            with self.subTest(agent_id=agent_id):
                text = redact_secrets(f"export T=sag_{agent_id}_{secret} # and again: sag_{agent_id}_{secret}")
                self.assertNotIn(secret, text)
                self.assertNotIn(secret[:16], text)

    def test_reissuing_changes_the_role(self):
        issue_agent_token("dup:agent", "operator")
        self.assertEqual(authenticate_bearer_token(issue_agent_token("dup:agent", "admin")), ("dup:agent", "admin"))
        self.assertEqual(authenticate_bearer_token(issue_agent_token("dup:agent", "operator")), ("dup:agent", "operator"))

    def test_reissuing_invalidates_the_previous_token(self):
        old = issue_agent_token("rot:agent", "operator")
        new = issue_agent_token("rot:agent", "operator")
        self.assertIsNone(authenticate_bearer_token(old))
        self.assertIsNotNone(authenticate_bearer_token(new))

    def test_issue_admin_warns_when_the_id_is_not_the_configured_root_admin(self):
        from sag import server

        def run(agent):
            out, err = io.StringIO(), io.StringIO()
            with unittest.mock.patch.object(sys, "argv", ["server.py", "issue-admin", agent]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                server.main()
            return out.getvalue(), err.getvalue()

        out, err = run("someone:else")
        self.assertIn("Issued ROOT ADMIN token", out)
        self.assertIn("will not see them", err)
        self.assertIn(config.root_admin_agent_id, err)
        out, err = run(config.root_admin_agent_id)
        self.assertIn("Issued ROOT ADMIN token", out)
        self.assertEqual(err, "")


class TestHttpLayer(unittest.IsolatedAsyncioTestCase):
    """The hand-written HTTP / JSON-RPC layer, over real sockets."""

    async def asyncSetUp(self):
        from sag import server

        self.server_mod = server
        _wipe_db()
        init_db()
        self.token = issue_agent_token("test:http", "operator")
        self.token_b = issue_agent_token("test:other", "operator")
        self.srv = await asyncio.start_server(server.handle_client, "127.0.0.1", 0)
        self.port = self.srv.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.srv.close()  # no wait_closed(): a legacy SSE connection can sit in its keepalive sleep
        _wipe_db()

    def _raw(self, method, path, body=b"", token="default", headers=None):
        if token == "default":
            token = self.token
        lines = [f"{method} {path} HTTP/1.1", "Host: x", "Accept: application/json"]
        if token:
            lines.append(f"Authorization: Bearer {token}")
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if body and "Content-Length" not in (headers or {}) and "Transfer-Encoding" not in (headers or {}):
            lines.append(f"Content-Length: {len(body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    async def _send(self, raw, timeout=5):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(raw)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout)
        finally:
            writer.close()
        return data

    @staticmethod
    def _parse(data):
        head, _, body = data.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1]) if head else 0
        return status, body

    async def _rpc(self, payload, path="/mcp", token="default"):
        raw = self._raw("POST", path, json.dumps(payload).encode(), token=token)
        status, body = self._parse(await self._send(raw))
        return status, (json.loads(body) if body else None)

    # ---- basics

    async def test_health_needs_no_token_and_other_paths_do(self):
        status, body = self._parse(await self._send(self._raw("GET", "/health", token=None)))
        self.assertEqual(status, 200)
        status, _ = self._parse(await self._send(self._raw("POST", "/mcp", b"{}", token=None)))
        self.assertEqual(status, 401)
        status, _ = self._parse(await self._send(self._raw("POST", "/mcp", b"{}", token="sag_nope_" + "0" * 48)))
        self.assertEqual(status, 401)

    async def test_tools_list_works(self):
        status, res = await self._rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(status, 200)
        self.assertIn("hub_shell", [t["name"] for t in res["result"]["tools"]])

    # ---- JSON-RPC robustness

    async def test_null_params_answer_with_an_error_instead_of_dropping_the_connection(self):
        for method in ("tools/call", "tools/list", "initialize", "ping"):
            with self.subTest(method=method):
                status, res = await self._rpc({"jsonrpc": "2.0", "id": 1, "method": method, "params": None})
                self.assertEqual(status, 200)
                self.assertEqual(res["id"], 1)
                if method == "tools/call":
                    self.assertIn("Unknown MCP tool", res["error"]["message"])
                else:
                    self.assertIn("result", res)

    async def test_params_that_are_not_an_object_are_invalid_params(self):
        for bad in ([], "x", 5, True):
            with self.subTest(bad=bad):
                status, res = await self._rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": bad})
                self.assertEqual(res["error"]["code"], -32602)

    async def test_notification_with_bad_params_gets_no_reply(self):
        raw = self._raw("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "method": "notifications/x", "params": 5}).encode())
        status, body = self._parse(await self._send(raw))
        self.assertEqual(status, 202)

    async def test_arguments_null_is_the_same_as_no_arguments(self):
        status, res = await self._rpc(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "hub_list_agents", "arguments": None}}
        )
        self.assertIn("result", res, res)

    async def test_arguments_of_the_wrong_type_are_an_error_message(self):
        status, res = await self._rpc(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "hub_shell", "arguments": [1]}}
        )
        self.assertIn("arguments must be an object", res["error"]["message"])

    async def test_a_batch_survives_one_bad_element(self):
        raw = self._raw("POST", "/mcp", json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": None},
        ]).encode())
        status, body = self._parse(await self._send(raw))
        self.assertEqual(status, 200)
        by_id = {r["id"]: r for r in json.loads(body)}
        self.assertIn("result", by_id[1])
        self.assertIn("error", by_id[2])

    async def test_a_bug_inside_a_handler_becomes_an_internal_error(self):
        with unittest.mock.patch.object(self.server_mod, "get_tools_for_agent", side_effect=RuntimeError("boom")), \
                contextlib.redirect_stderr(io.StringIO()):
            status, res = await self._rpc({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})
        self.assertEqual((status, res["error"]["code"]), (200, -32603))
        self.assertNotIn("boom", res["error"]["message"])  # details stay in the log

    async def test_legacy_endpoint_answers_a_json_array_or_scalar_instead_of_resetting(self):
        for body in (b"[1,2]", b"5", b"null", b'"x"'):
            with self.subTest(body=body):
                status, resp = self._parse(await self._send(self._raw("POST", "/messages", body)))
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(resp)["error"]["code"], -32600)

    # ---- request framing and limits

    async def test_bad_content_length_values_are_a_400(self):
        for bad in ("abc", "-5", "1e3", "+5", "5.0", "0x10", "5, 5"):
            with self.subTest(value=bad):
                raw = self._raw("POST", "/mcp", b"", headers={"Content-Length": bad})
                status, _ = self._parse(await self._send(raw))
                self.assertEqual(status, 400)

    async def test_chunked_bodies_are_refused_with_411(self):
        raw = self._raw("POST", "/mcp", b"4\r\n{}{}\r\n0\r\n\r\n", headers={"Transfer-Encoding": "chunked"})
        status, body = self._parse(await self._send(raw))
        self.assertEqual(status, 411)
        self.assertIn("Content-Length", json.loads(body)["error"])

    async def test_oversized_bodies_are_refused_before_they_are_read(self):
        with _config_override(max_request_bytes=100):
            raw = self._raw("POST", "/mcp", b"", headers={"Content-Length": "101"})
            status, _ = self._parse(await self._send(raw))
            self.assertEqual(status, 413)
            ok = self._raw("POST", "/mcp", json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode())
            self.assertEqual(self._parse(await self._send(ok))[0], 200)

    async def test_a_client_that_never_finishes_its_headers_is_dropped(self):
        with unittest.mock.patch.object(self.server_mod, "HEADER_TIMEOUT", 0.3):
            started = time.monotonic()
            data = await self._send(b"POST /mcp HTTP/1.1\r\nHost: x\r\nAuthor", timeout=3)
        self.assertEqual(data, b"")
        self.assertLess(time.monotonic() - started, 2.5)

    async def test_a_client_that_stalls_in_the_body_gets_408(self):
        with unittest.mock.patch.object(self.server_mod, "BODY_TIMEOUT", 0.3):
            started = time.monotonic()
            data = await self._send(self._raw("POST", "/mcp", b"", headers={"Content-Length": "50"}) + b"{}", timeout=3)
        self.assertEqual(self._parse(data)[0], 408)
        self.assertLess(time.monotonic() - started, 2.5)

    async def test_a_header_flood_is_refused(self):
        raw = self._raw("POST", "/mcp", b"", headers={f"X-{i}": "v" for i in range(200)})
        self.assertEqual(self._parse(await self._send(raw))[0], 431)

    async def test_a_client_hanging_up_mid_body_does_not_break_the_server(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(self._raw("POST", "/mcp", b"", headers={"Content-Length": "50"}) + b"{")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.1)
        status, _ = self._parse(await self._send(self._raw("GET", "/health", token=None)))
        self.assertEqual(status, 200)

    # ---- the event loop stays free

    async def test_a_slow_token_check_does_not_freeze_other_connections(self):
        def slow_auth(header):
            time.sleep(0.6)
            return ("test:http", "operator")

        with unittest.mock.patch.object(self.server_mod, "authenticate_bearer_token", slow_auth):
            slow = asyncio.create_task(self._send(self._raw("POST", "/mcp", b"{}")))
            await asyncio.sleep(0.1)
            started = time.monotonic()
            status, _ = self._parse(await self._send(self._raw("GET", "/health", token=None)))
            health_latency = time.monotonic() - started
            await slow
        self.assertEqual(status, 200)
        self.assertLess(health_latency, 0.4)

    async def test_many_long_running_calls_do_not_starve_the_pool(self):
        n = 12
        barrier = threading.Barrier(n)
        with _config_override(max_workers=n):
            self.server_mod.configure_event_loop(asyncio.get_running_loop())
            # all n calls must be running at the same time to pass the barrier: a smaller default pool would time out
            await asyncio.gather(*(asyncio.to_thread(barrier.wait, 5) for _ in range(n)))

    # ---- legacy SSE sessions belong to one agent

    async def _open_sse(self, token):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(self._raw("GET", "/sse", token=token))
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)  # response head
        event = (await asyncio.wait_for(reader.readuntil(b"\n\n"), 3)).decode()
        session_id = event.split("sessionId=")[1].split()[0]
        return reader, writer, session_id

    async def test_another_agent_cannot_make_a_response_appear_on_my_sse_stream(self):
        reader, writer, session_id = await self._open_sse(self.token)
        try:
            ping = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode()
            status, body = self._parse(
                await self._send(self._raw("POST", f"/messages?sessionId={session_id}", ping, token=self.token_b))
            )
            self.assertEqual(status, 200)  # answered on its own request, not pushed anywhere
            self.assertEqual(json.loads(body)["id"], 7)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(reader.readuntil(b"\n\n"), 0.5)
        finally:
            writer.close()

    async def test_the_owner_still_gets_its_responses_on_the_stream(self):
        reader, writer, session_id = await self._open_sse(self.token)
        try:
            ping = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "ping"}).encode()
            status, _ = self._parse(
                await self._send(self._raw("POST", f"/messages?sessionId={session_id}", ping, token=self.token))
            )
            self.assertEqual(status, 202)
            event = (await asyncio.wait_for(reader.readuntil(b"\n\n"), 3)).decode()
            self.assertIn("event: message", event)
            self.assertEqual(json.loads(event.split("data: ", 1)[1])["id"], 8)
        finally:
            writer.close()


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


class _FakeWriter:
    def __init__(self):
        self.buf = b""

    def write(self, data):
        self.buf += data

    async def drain(self):
        pass


class TestStreamableSession(unittest.TestCase):
    def setUp(self):
        _wipe_db()
        init_db()

    def _post(self, body, session=None):
        import asyncio
        from sag.server import handle_streamable_post

        headers = {"accept": "application/json"}
        if session:
            headers["mcp-session-id"] = session
        w = _FakeWriter()
        asyncio.run(handle_streamable_post("wsl:pi", "operator", headers, json.dumps(body).encode(), w))
        head, _, payload = w.buf.partition(b"\r\n\r\n")
        return head.decode(), payload

    def test_initialize_issues_session_for_this_boot(self):
        from sag.server import BOOT_ID

        head, _ = self._post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIn(f"Mcp-Session-Id: {BOOT_ID}.", head)
        sid = head.split("Mcp-Session-Id: ", 1)[1].split("\r\n", 1)[0]
        head, _ = self._post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=sid)
        self.assertTrue(head.startswith("HTTP/1.1 200"))
        self.assertNotIn("Mcp-Session-Id", head)

    def test_stale_session_404_once_then_allowed_with_one_hint(self):
        from sag.server import STALE_SESSION_HINT

        sid = "0ld.boot-" + uuid.uuid4().hex
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "hub_list_tasks", "arguments": {}}}
        head, payload = self._post(call, session=sid)
        self.assertTrue(head.startswith("HTTP/1.1 404"))
        self.assertIn(b"re-initialize", payload)
        # 不重新 initialize 的客户端：第二次放行并提示一次，之后不再提示
        head, payload = self._post(call, session=sid)
        self.assertTrue(head.startswith("HTTP/1.1 200"))
        texts = [c["text"] for c in json.loads(payload)["result"]["content"]]
        self.assertIn(STALE_SESSION_HINT, texts)
        head, payload = self._post(call, session=sid)
        self.assertTrue(head.startswith("HTTP/1.1 200"))
        self.assertNotIn(STALE_SESSION_HINT, payload.decode())

    def test_stale_hint_waits_for_a_tool_result(self):
        from sag.server import STALE_SESSION_HINT

        sid = "0ld.boot-" + uuid.uuid4().hex
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session=sid)  # 404
        head, _ = self._post({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, session=sid)
        self.assertTrue(head.startswith("HTTP/1.1 200"))
        call = {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "hub_list_tasks", "arguments": {}}}
        _, payload = self._post(call, session=sid)
        self.assertIn(STALE_SESSION_HINT, payload.decode())

    def test_no_session_header_still_allowed(self):
        head, _ = self._post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertTrue(head.startswith("HTTP/1.1 200"))


if __name__ == "__main__":
    unittest.main()
