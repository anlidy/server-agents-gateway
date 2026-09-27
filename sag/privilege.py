"""
权限分级：admin = root；其他 agent 以普通 Unix 用户（默认 sag-operator）执行。

原则：operator 的 shell 和文件操作都在已降权的子进程里跑，权限由内核判定，
这里不写"哪些路径允许"的判断。降权失败或账户不存在时直接报错，绝不回退成 root。
"""

from __future__ import annotations

import base64
import json
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import config

WORKER = Path(__file__).resolve().parent / "opworker.py"
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SETPRIV = "/usr/bin/setpriv"
_SPOOL_ID = re.compile(r"^[0-9a-f]{32}$")


class OperatorUnavailable(PermissionError):
    pass


def is_privileged(role: str) -> bool:
    return role == "admin"


@dataclass(frozen=True)
class Identity:
    name: str
    uid: int
    gid: int
    home: str

    @property
    def spool_dir(self) -> str:
        return os.path.join(self.home, ".cache", "sag-trash-spool")

    def needs_switch(self) -> bool:
        # 测试环境里 operator 就是当前的非 root 用户，不需要（也无权）切换
        return not (self.uid == os.geteuid() and os.geteuid() != 0)


def operator_identity() -> Identity:
    name = config.operator_user
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        raise OperatorUnavailable(
            f"operator 账户 {name} 不存在，非 admin agent 暂时无法执行。"
            f"请 admin 在服务器上运行 scripts/setup_operator.sh"
        )
    if pw.pw_uid == 0:
        raise OperatorUnavailable(f"operator 账户 {name} 的 uid 是 0，拒绝使用")
    gid = pw.pw_gid
    try:
        gid = grp.getgrnam(config.operator_group).gr_gid
    except KeyError:
        pass
    home = config.operator_home or pw.pw_dir
    return Identity(name=name, uid=pw.pw_uid, gid=gid, home=home)


def operator_env(ident: Identity, agent_id: str = "", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {
        "HOME": ident.home,
        "USER": ident.name,
        "LOGNAME": ident.name,
        "SHELL": "/bin/bash",
        "PATH": SAFE_PATH,
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "TERM": "dumb",
    }
    if agent_id:
        env["SAG_AGENT_ID"] = agent_id
    if extra:
        env.update(extra)
    return env


def popen_kwargs(ident: Identity) -> Dict[str, Any]:
    kw: Dict[str, Any] = {"umask": 0o022}
    if ident.needs_switch():
        if os.geteuid() != 0:
            raise OperatorUnavailable("SAG 不是以 root 运行，无法切换到 operator 用户")
        kw.update(user=ident.uid, group=ident.gid, extra_groups=[])
    return kw


def wrap_argv(argv: List[str]) -> List[str]:
    if config.operator_no_new_privs and os.path.exists(SETPRIV):
        return [SETPRIV, "--no-new-privs", "--"] + argv
    return argv


def ensure_home(ident: Identity) -> None:
    if not os.path.isdir(ident.home):
        raise OperatorUnavailable(f"operator 的 home 不存在：{ident.home}")


# --------------------------------------------------------------------------- worker


_KIND_TO_EXC = {
    "FileNotFoundError": FileNotFoundError,
    "FileExistsError": FileExistsError,
    "IsADirectoryError": IsADirectoryError,
    "NotADirectoryError": NotADirectoryError,
    "PermissionError": PermissionError,
    "ValueError": ValueError,
}


def call_worker(op: str, req: Dict[str, Any], agent_id: str = "", stdin_file=None,
                timeout: int = 300) -> Dict[str, Any]:
    ident = operator_identity()
    ensure_home(ident)
    argv = wrap_argv([sys.executable, "-I", str(WORKER), op])
    header = json.dumps(req, ensure_ascii=False).encode("utf-8") + b"\n"
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ident.home,
        env=operator_env(ident, agent_id),
        start_new_session=True,
        **popen_kwargs(ident),
    )
    try:
        proc.stdin.write(header)
        if stdin_file is not None:
            shutil.copyfileobj(stdin_file, proc.stdin, 1 << 20)
        proc.stdin.close()
    except BrokenPipeError:
        pass
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise TimeoutError(f"operator worker '{op}' timed out after {timeout}s")
    try:
        out = json.loads(stdout.decode("utf-8"))
    except Exception:
        raise RuntimeError(
            f"operator worker failed (exit {proc.returncode}): {stderr.decode('utf-8', 'replace')[-500:]}"
        )
    if not out.get("ok"):
        exc = _KIND_TO_EXC.get(out.get("kind"), OSError)
        raise exc(out.get("message") or out.get("kind"))
    return out["result"]


# --------------------------------------------------------------------------- spool → trash


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_spool_dir(ident: Identity) -> Optional[int]:
    """逐级以 O_NOFOLLOW 打开 home/.cache/sag-trash-spool，要求 .cache 和 spool 归 operator 所有。
    operator 控制着这两级目录，按路径直接打开会被符号链接引到别处（root 会去读、去删那里的文件）。"""
    fds: List[int] = []
    try:
        fd = os.open(ident.home, _DIR_FLAGS)
        fds.append(fd)
        for name in (".cache", "sag-trash-spool"):
            fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            fds.append(fd)
            if os.fstat(fd).st_uid not in (ident.uid, 0):
                return None
        return os.dup(fds[-1])
    except OSError:
        return None
    finally:
        for f in fds:
            os.close(f)


def _open_regular_at(dir_fd: int, name: str, max_bytes: int) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > max_bytes:
        os.close(fd)
        raise ValueError(f"spool entry is not a regular file within limits: {name}")
    return fd


def ingest_spool(spool_id: str, agent_id: str, source: str, ident: Optional[Identity] = None) -> Optional[str]:
    """把 operator 放进 spool 的 tar 收进回收站（root 只读、只拷贝，不解包）。返回 trash_id。"""
    from .trash import store_tar_payload  # 避免循环 import

    if not _SPOOL_ID.match(spool_id or ""):
        return None
    ident = ident or operator_identity()
    dfd = _open_spool_dir(ident)
    if dfd is None:
        return None
    meta_name, tar_name = spool_id + ".json", spool_id + ".tar"
    try:
        mfd = _open_regular_at(dfd, meta_name, 1024 * 1024)
        with os.fdopen(mfd, "rb") as f:
            meta = json.loads(f.read().decode("utf-8"))
        tfd = _open_regular_at(dfd, tar_name, (config.operator_trash_max_mb + 64) * 1024 * 1024)
        with os.fdopen(tfd, "rb") as src:
            trash_id = store_tar_payload(
                src,
                original_path=str(meta.get("original_path") or "?"),
                is_dir=bool(meta.get("is_dir")),
                size_bytes=int(meta.get("size_bytes") or 0),
                agent_id=agent_id,
                source=source,
            )
        for name in (meta_name, tar_name):
            try:
                os.unlink(name, dir_fd=dfd)
            except OSError:
                pass
        return trash_id
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    finally:
        os.close(dfd)


def ingest_orphan_spool(max_age_seconds: int = 3600) -> int:
    """SAG 中途崩溃时 spool 里可能留下未收的条目；定期收掉，deleted_by 标成未归属。"""
    try:
        ident = operator_identity()
    except OperatorUnavailable:
        return 0
    import time

    dfd = _open_spool_dir(ident)
    if dfd is None:
        return 0
    try:
        names = os.listdir(dfd)
        stale = []
        for name in names:
            if not name.endswith(".json") or not _SPOOL_ID.match(name[:-5]):
                continue
            try:
                age = time.time() - os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mtime
            except OSError:
                continue
            if age >= max_age_seconds:
                stale.append(name[:-5])
    finally:
        os.close(dfd)
    n = 0
    for sid in stale:
        if ingest_spool(sid, f"{ident.name}(unattributed)", "operator_orphan", ident):
            n += 1
    return n


def restore_tar_as_operator(tar_file: Path, dest: str, agent_id: str) -> Dict[str, Any]:
    with open(tar_file, "rb") as f:
        return call_worker("restore", {"dest": dest}, agent_id=agent_id, stdin_file=f, timeout=1800)


def decode_old(res: Dict[str, Any]) -> Optional[bytes]:
    b = res.get("old_b64")
    return base64.b64decode(b) if b else None


# --------------------------------------------------------------------------- grants (ACL)


def setfacl_available() -> bool:
    return shutil.which("setfacl") is not None
