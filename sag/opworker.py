#!/usr/bin/env python3
"""
以 operator（普通 Unix 用户）身份执行的文件操作 worker。

SAG 主进程是 root。operator 的文件类工具不能由 root 代做（那会绕过内核的权限检查），
所以主进程把请求交给这个脚本，由它在已经降权的子进程里执行：能不能读、写、删，
全部由内核按 operator 的 uid/gid/ACL 判定，这里不做任何自定义的路径白名单。

约束：
- 只用标准库，不 import sag 包（sag.config 会读 .env，operator 没权限读）。
- 以 `python3 -I opworker.py <op>` 运行；请求是 stdin 上的一行 JSON，
  restore 操作在这一行之后紧跟 tar 数据流。响应是 stdout 上的一个 JSON 对象。
- `opworker.py rm [rm 参数...]` 是 operator shell 里 rm 函数的实现：
  先把目标打成 tar 放进 spool（在 operator 自己的 home 下），再以 operator 身份删除；
  在 stderr 打印 `SAG_TRASH_SPOOL <id>`，由 root 进程收进回收站。
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import uuid

LIST_DIR_MAX = 2000


class WorkerError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def _abs_nofollow(path: str) -> str:
    """绝对路径；父目录解析符号链接，最后一段不解析（rm 一个符号链接删的是链接本身）。"""
    p = os.path.abspath(os.path.expanduser(path))
    parent, name = os.path.split(p)
    if not name:
        return p
    return os.path.join(os.path.realpath(parent), name)


def _read_text(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    if b"\x00" in raw[:8192]:
        raise WorkerError("ValueError", "binary file")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkerError("ValueError", f"not UTF-8: {exc}")


def _write_in_place(path: str, data: bytes) -> None:
    # O_TRUNC 原地写：保留 inode、属主和权限（bind mount 的配置文件依赖这一点）
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- ops


def op_read(req):
    path = os.path.realpath(req["path"])
    if not os.path.lexists(path):
        raise WorkerError("FileNotFoundError", path)
    if os.path.isdir(path):
        raise WorkerError("IsADirectoryError", path)
    text = _read_text(path)
    lines = text.splitlines(True)
    start = max(int(req.get("offset") or 1) - 1, 0)
    limit = req.get("limit")
    chunk = lines[start:] if limit is None else lines[start : start + int(limit)]
    return {"path": path, "content": "".join(chunk)}


def op_list_dir(req):
    path = os.path.realpath(req["path"])
    if not os.path.exists(path):
        raise WorkerError("FileNotFoundError", path)
    if not os.path.isdir(path):
        raise WorkerError("NotADirectoryError", path)
    names = sorted(os.listdir(path))
    truncated = len(names) > LIST_DIR_MAX
    names = names[:LIST_DIR_MAX]
    entries = []
    for name in names:
        try:
            st = os.lstat(os.path.join(path, name))
        except OSError:
            continue
        entries.append(
            {
                "name": name,
                "is_dir": stat.S_ISDIR(st.st_mode),
                "is_symlink": stat.S_ISLNK(st.st_mode),
                "size": st.st_size,
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime)),
            }
        )
    return {"path": path, "entries": entries, "truncated": truncated}


def op_mkdir(req):
    path = os.path.realpath(req["path"])
    if os.path.exists(path) and not os.path.isdir(path):
        raise WorkerError("NotADirectoryError", f"exists and is not a directory: {path}")
    existed = os.path.isdir(path)
    os.makedirs(path, exist_ok=True)
    return {"path": path, "existed": existed}


def op_write(req):
    path = os.path.realpath(req["path"])
    content = req["content"].encode("utf-8")
    existed = os.path.lexists(path)
    old = None
    if existed:
        if os.path.isdir(path):
            raise WorkerError("IsADirectoryError", path)
        try:
            with open(path, "rb") as f:
                old = f.read()
        except PermissionError:
            raise WorkerError(
                "PermissionError",
                f"cannot read existing {path} to back it up; no change made",
            )
    else:
        os.makedirs(os.path.dirname(path) or "/", exist_ok=True)
    _write_in_place(path, content)
    out = {"path": path, "existed": existed, "bytes_written": len(content)}
    if old is not None:
        out["old_b64"] = base64.b64encode(old).decode("ascii")
    return out


def op_patch(req):
    path = os.path.realpath(req["path"])
    old_string = req["old_string"]
    new_string = req["new_string"]
    replace_all = bool(req.get("replace_all"))
    if not old_string:
        raise WorkerError("ValueError", "old_string must not be empty")
    if not os.path.lexists(path):
        raise WorkerError("FileNotFoundError", path)
    if os.path.isdir(path):
        raise WorkerError("IsADirectoryError", path)
    old = _read_text(path)
    n = old.count(old_string)
    if n == 0:
        raise WorkerError("ValueError", "old_string not found")
    if n > 1 and not replace_all:
        raise WorkerError("ValueError", f"old_string matched {n} times; pass replace_all=true or make it unique")
    new = old.replace(old_string, new_string) if replace_all else old.replace(old_string, new_string, 1)
    _write_in_place(path, new.encode("utf-8"))
    return {"path": path, "replacements": n if replace_all else 1, "old": old, "new": new}


def op_access(req):
    path = req["path"]
    return {
        "path": path,
        "exists": os.path.exists(path),
        "read": os.access(path, os.R_OK),
        "write": os.access(path, os.W_OK),
        "exec": os.access(path, os.X_OK),
    }


def _tree_size_and_check(path: str) -> int:
    """统计大小，并确认 operator 能删掉整棵树（每个目录都要有 w+x）。用的是 os.access，即内核判定。"""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        if not os.access(root, os.W_OK | os.X_OK):
            raise WorkerError("PermissionError", f"cannot remove entries in {root}: Permission denied")
        for name in files + [d for d in dirs if os.path.islink(os.path.join(root, d))]:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def trash_one(path: str, spool: str, max_bytes: int, agent: str) -> dict:
    target = _abs_nofollow(path)
    if not os.path.lexists(target):
        raise WorkerError("FileNotFoundError", target)
    parent = os.path.dirname(target)
    if not os.access(parent, os.W_OK | os.X_OK):
        raise WorkerError("PermissionError", f"cannot remove '{target}': Permission denied")
    is_dir = os.path.isdir(target) and not os.path.islink(target)
    size = _tree_size_and_check(target)
    if size > max_bytes:
        raise WorkerError(
            "ValueError",
            f"'{target}' is {size // (1024 * 1024)} MB, over the recycle-bin limit; "
            "use /bin/rm to delete for real or ask for elevation",
        )
    os.makedirs(spool, mode=0o700, exist_ok=True)
    sid = uuid.uuid4().hex
    tar_path = os.path.join(spool, sid + ".tar")
    meta_path = os.path.join(spool, sid + ".json")
    try:
        with tarfile.open(tar_path, "w") as tf:
            tf.add(target, arcname="payload", recursive=True)
    except (PermissionError, OSError) as exc:
        _silent_unlink(tar_path)
        raise WorkerError("PermissionError", f"cannot back up '{target}' ({exc}); nothing deleted")
    meta = {
        "original_path": target,
        "is_dir": is_dir,
        "size_bytes": size,
        "agent": agent,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    try:
        if is_dir:
            shutil.rmtree(target)
        else:
            os.unlink(target)
    except OSError as exc:
        if not os.path.lexists(target):
            pass
        elif is_dir:
            # 部分删掉了：备份仍然保留，交给 root 收进回收站
            meta["partial"] = str(exc)
        else:
            _silent_unlink(tar_path)
            raise WorkerError(type(exc).__name__ if isinstance(exc, PermissionError) else "OSError",
                              f"cannot remove '{target}': {exc.strerror or exc}")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False)
    out = dict(meta)
    out["spool_id"] = sid
    return out


def _silent_unlink(p: str) -> None:
    try:
        os.unlink(p)
    except OSError:
        pass


def op_trash(req):
    return trash_one(req["path"], req["spool"], int(req["max_bytes"]), req.get("agent") or "")


def op_restore(req, stream):
    dest = req["dest"]
    if os.path.lexists(dest):
        raise WorkerError("FileExistsError", f"destination exists: {dest}")
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".sag-restore-", dir=parent)
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            try:
                tf.extractall(tmp, filter="tar")
            except TypeError:  # Python < 3.12 没有 filter 参数
                tf.extractall(tmp)
        src = os.path.join(tmp, "payload")
        if not os.path.lexists(src):
            raise WorkerError("ValueError", "archive has no payload")
        os.rename(src, dest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"status": "RESTORED", "path": dest}


OPS = {
    "read": op_read,
    "list_dir": op_list_dir,
    "mkdir": op_mkdir,
    "write": op_write,
    "patch": op_patch,
    "access": op_access,
    "trash": op_trash,
}


def _error_kind(exc: BaseException) -> str:
    for cls in (FileNotFoundError, FileExistsError, IsADirectoryError, NotADirectoryError, PermissionError):
        if isinstance(exc, cls):
            return cls.__name__
    if isinstance(exc, (ValueError, UnicodeError)):
        return "ValueError"
    return "OSError"


def serve(op: str) -> int:
    stream = sys.stdin.buffer
    line = stream.readline()
    try:
        req = json.loads(line.decode("utf-8") or "{}")
        if op == "restore":
            res = op_restore(req, stream)
        elif op in OPS:
            res = OPS[op](req)
        else:
            raise WorkerError("ValueError", f"unknown op {op}")
        out = {"ok": True, "result": res}
    except WorkerError as exc:
        out = {"ok": False, "kind": exc.kind, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if isinstance(exc, OSError) and exc.filename:
            msg = f"{exc.strerror}: {exc.filename}"
        out = {"ok": False, "kind": _error_kind(exc), "message": msg}
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------- rm


def rm_main(argv) -> int:
    """GNU rm 的常用子集；每个操作数进回收站 spool。"""
    recursive = force = dir_ok = False
    operands = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            operands.extend(argv[i + 1 :])
            break
        if a in ("-r", "-R", "--recursive"):
            recursive = True
        elif a in ("-f", "--force"):
            force = True
        elif a in ("-d", "--dir"):
            dir_ok = True
        elif a in ("-v", "--verbose", "-i", "-I", "--interactive=never"):
            pass
        elif a.startswith("--"):
            print(f"rm: unsupported option {a}", file=sys.stderr)
            return 1
        elif a.startswith("-") and a != "-":
            for ch in a[1:]:
                if ch in "rR":
                    recursive = True
                elif ch == "f":
                    force = True
                elif ch == "d":
                    dir_ok = True
                elif ch in "vIi":
                    pass
                else:
                    print(f"rm: unsupported option -{ch}", file=sys.stderr)
                    return 1
        else:
            operands.append(a)
        i += 1
    if not operands:
        if force:
            return 0
        print("rm: missing operand", file=sys.stderr)
        return 1
    spool = os.environ.get("SAG_TRASH_SPOOL") or os.path.expanduser("~/.cache/sag-trash-spool")
    max_bytes = int(os.environ.get("SAG_TRASH_MAX_BYTES") or 1024 * 1024 * 1024)
    agent = os.environ.get("SAG_AGENT_ID", "")
    errors = False
    for op in operands:
        target = _abs_nofollow(op)
        if not os.path.lexists(target):
            if not force:
                print(f"rm: cannot remove '{op}': No such file or directory", file=sys.stderr)
                errors = True
            continue
        if os.path.isdir(target) and not os.path.islink(target) and not recursive:
            if not (dir_ok and not os.listdir(target)):
                print(f"rm: cannot remove '{op}': Is a directory", file=sys.stderr)
                errors = True
                continue
        try:
            item = trash_one(target, spool, max_bytes, agent)
            print(f"SAG_TRASH_SPOOL {item['spool_id']}", file=sys.stderr)
            if item.get("partial"):
                print(f"rm: '{op}' only partly removed: {item['partial']}", file=sys.stderr)
                errors = True
        except WorkerError as exc:
            print(f"rm: {exc}", file=sys.stderr)
            errors = True
        except OSError as exc:
            print(f"rm: cannot remove '{op}': {exc.strerror or exc}", file=sys.stderr)
            errors = True
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: opworker.py <op> | rm [args]", file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "rm":
        sys.exit(rm_main(sys.argv[2:]))
    sys.exit(serve(sys.argv[1]))
