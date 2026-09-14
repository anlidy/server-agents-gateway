"""
Host vitals, inventory probes, status-fence refresh, trash purge.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .config import config
from .overview import (
    ensure_document,
    overview_path,
    parse_probes,
    read_overview,
    replace_status_block,
    untracked_containers,
)
from .trash import purge_expired_trash


def _run(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception:
        return -1, "", "unknown"


def probe_one(kind: str, spec: str) -> str:
    try:
        if kind == "systemd":
            unit = spec if spec.endswith(".service") else spec
            if "." not in Path(unit).name:
                unit = f"{spec}.service"
            code, out, _err = _run(["systemctl", "is-active", unit], timeout=3)
            return "up" if out.strip() == "active" else "down"
        if kind == "docker":
            code, out, _err = _run(
                ["docker", "ps", "-a", "--filter", f"name=^{spec}$", "--format", "{{.Status}}"],
                timeout=3,
            )
            if code != 0:
                return "unknown"
            line = out.strip().splitlines()[0] if out.strip() else ""
            if not line:
                return "down"
            return "up" if line.startswith("Up") else "down"
        if kind == "http":
            import urllib.error
            import urllib.request

            req = urllib.request.Request(spec, method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if 200 <= getattr(resp, "status", 200) < 400:
                        return "up"
                    return "down"
            except urllib.error.HTTPError as exc:
                if 300 <= exc.code < 400:
                    return "up"
                return "down"
            except Exception:
                return "unknown"
        if kind == "tcp":
            host, port_s = spec.rsplit(":", 1)
            port = int(port_s)
            try:
                with socket.create_connection((host, port), timeout=3):
                    return "up"
            except Exception:
                return "down"
    except Exception:
        return "unknown"
    return "unknown"


def list_docker_names() -> List[str]:
    code, out, _err = _run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=3)
    if code != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def collect_probes_and_untracked() -> Tuple[List[Dict[str, str]], List[str]]:
    text = read_overview()
    probes = []
    for p in parse_probes(text):
        state = probe_one(p["kind"], p["spec"])
        probes.append({**p, "state": state})
    names = list_docker_names()
    untracked = untracked_containers(text, names)
    return probes, untracked


def render_status_inner(probes: List[Dict[str, str]], untracked: List[str], probed_at: str) -> str:
    lines = [
        f"> probed_at: {probed_at}",
        "",
        "| id | probe | state |",
        "| --- | --- | --- |",
    ]
    for p in probes:
        lines.append(f"| {p['id']} | {p['probe']} | {p['state']} |")
    lines.append("")
    lines.append("Untracked:")
    if untracked:
        for u in untracked:
            lines.append(f"- {u}")
    else:
        lines.append("- (none)")
    return "\n".join(lines) + "\n"


def refresh_status_block() -> None:
    ensure_document()
    probed_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    probes, untracked = collect_probes_and_untracked()
    inner = render_status_inner(probes, untracked, probed_at)
    path = overview_path()
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    path.write_text(replace_status_block(text, inner), encoding="utf-8")


def _meminfo_mb() -> Tuple[Dict[str, int], Dict[str, int]]:
    info: Dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            parts = v.strip().split()
            if parts:
                info[k] = int(parts[0])
    except Exception:
        return {"total": 0, "used": 0, "available": 0}, {"total": 0, "used": 0}
    total = info.get("MemTotal", 0) // 1024
    avail = info.get("MemAvailable", 0) // 1024
    used = max(0, total - avail)
    swap_t = info.get("SwapTotal", 0) // 1024
    swap_u = max(0, swap_t - info.get("SwapFree", 0) // 1024)
    return {"total": total, "used": used, "available": avail}, {"total": swap_t, "used": swap_u}


def _loadavg() -> List[float]:
    try:
        parts = Path("/proc/loadavg").read_text(encoding="utf-8").split()[:3]
        return [float(x) for x in parts]
    except Exception:
        return [0.0, 0.0, 0.0]


def _uptime_seconds() -> int:
    try:
        return int(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]))
    except Exception:
        return 0


def _os_pretty() -> str:
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return "unknown"


def _disks() -> List[Dict[str, str]]:
    code, out, _err = _run(
        ["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"],
        timeout=2,
    )
    disks = []
    if code != 0:
        return disks
    lines = out.strip().splitlines()
    if len(lines) < 2:
        return disks
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        disks.append(
            {
                "mount": parts[6],
                "fstype": parts[1],
                "total": parts[2],
                "used": parts[3],
                "avail": parts[4],
                "pct": parts[5],
            }
        )
    return disks


def _systemd_failed() -> List[str]:
    code, out, _err = _run(
        ["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"],
        timeout=3,
    )
    if code < 0:
        return []
    names = []
    for line in out.splitlines():
        parts = line.split()
        if parts:
            names.append(parts[0])
    return names


def _docker_counts() -> Dict[str, Any]:
    code, out, _err = _run(["docker", "ps", "-a", "--format", "{{.Status}}"], timeout=3)
    if code != 0:
        return {"available": False, "running": 0, "total": 0}
    lines = [ln for ln in out.splitlines() if ln.strip()]
    running = sum(1 for ln in lines if ln.startswith("Up"))
    return {"available": True, "running": running, "total": len(lines)}


def collect_host_status() -> Dict[str, Any]:
    mem, swap = _meminfo_mb()
    uname = os.uname()
    probes, untracked = collect_probes_and_untracked()
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": {
            "hostname": socket.gethostname(),
            "os": _os_pretty(),
            "kernel": uname.release,
            "arch": uname.machine,
            "uptime_seconds": _uptime_seconds(),
            "reboot_required": Path("/run/reboot-required").exists(),
        },
        "cpu": {
            "cores": os.cpu_count() or 0,
            "loadavg": _loadavg(),
        },
        "memory_mb": mem,
        "swap_mb": swap,
        "disks": _disks(),
        "systemd_failed": _systemd_failed(),
        "docker": _docker_counts(),
        "probes": [{"id": p["id"], "probe": p["probe"], "state": p["state"]} for p in probes],
        "untracked": untracked,
    }


def reconcile() -> None:
    try:
        refresh_status_block()
    except Exception as exc:
        print(f"[reconcile] status refresh failed: {exc}")
    try:
        purge_expired_trash()
    except Exception as exc:
        print(f"[reconcile] trash purge failed: {exc}")


# Back-compat name used by older server.py if mixed
def reconcile_observed_state():
    reconcile()
