"""
SERVER_AGENTS.md: handwritten inventory + generated status fence.
"""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import config
from .db import get_db_connection

STATUS_START = "<!-- sag-status:start -->"
STATUS_END = "<!-- sag-status:end -->"

_PROBE_LINE = re.compile(r"^- probe: (.+)$")
_PROBE_VAL = re.compile(r"^(systemd|docker|http|tcp)\s+(.+)$")
_HEADING = re.compile(r"^###\s+(\S+)\s*$")


def overview_path() -> Path:
    return Path(config.overview_path)


def read_overview() -> str:
    p = overview_path()
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    lines = text.splitlines(True)
    start = None
    for i, line in enumerate(lines):
        if line.startswith(heading) and (line.strip() == heading or line.startswith(heading + "\n") or line[len(heading) : len(heading) + 1] in ("", "\n", " ", "\t")):
            if line.strip().split()[0] == heading.split()[0] and line.startswith(heading):
                start = i + 1
                break
    if start is None:
        return ""
    end = len(lines)
    for j in range(start, len(lines)):
        if lines[j].startswith("## ") and not lines[j].startswith(heading):
            end = j
            break
    return "".join(lines[start:end])


def inventory_section(text: str) -> str:
    return _section(text, "## Inventory")


def inventory_is_empty(text: str) -> bool:
    return "###" not in inventory_section(text)


def strip_status_block(text: str) -> str:
    if STATUS_START not in text or STATUS_END not in text:
        return text
    before, rest = text.split(STATUS_START, 1)
    _inner, after = rest.split(STATUS_END, 1)
    return before.rstrip() + "\n\n" + after.lstrip()


def replace_status_block(text: str, status_inner: str) -> str:
    inner = status_inner.strip() + "\n"
    block = f"{STATUS_START}\n{inner}{STATUS_END}"
    if STATUS_START in text and STATUS_END in text:
        before, rest = text.split(STATUS_START, 1)
        _old, after = rest.split(STATUS_END, 1)
        return before.rstrip() + "\n\n" + block + "\n" + after.lstrip()
    lines = text.splitlines(True)
    if lines and lines[0].startswith("#"):
        return lines[0] + "\n" + block + "\n" + "".join(lines[1:])
    return block + "\n\n" + text


def parse_probes(text: str) -> List[Dict[str, str]]:
    probes: List[Dict[str, str]] = []
    current_id: Optional[str] = None
    for raw in inventory_section(text).splitlines():
        line = raw.rstrip()
        hm = _HEADING.match(line)
        if hm:
            current_id = hm.group(1)
            continue
        pm = _PROBE_LINE.match(line.strip()) if line.strip().startswith("- probe:") else None
        if not pm:
            pm = _PROBE_LINE.match(line)
        if pm and current_id:
            vm = _PROBE_VAL.match(pm.group(1).strip())
            if vm:
                probes.append(
                    {
                        "id": current_id,
                        "kind": vm.group(1),
                        "spec": vm.group(2).strip(),
                        "probe": pm.group(1).strip(),
                    }
                )
    return probes


def untracked_containers(inventory_text: str, names: List[str]) -> List[str]:
    out = []
    for n in names:
        if n and n not in inventory_text:
            out.append(f"docker:{n}")
    return out


def _skeleton(hostname: str) -> str:
    return (
        f"# {hostname}\n\n"
        f"{STATUS_START}\n"
        f"> probed_at:\n\n"
        f"| id | probe | state |\n"
        f"| --- | --- | --- |\n\n"
        f"Untracked:\n"
        f"{STATUS_END}\n\n"
        f"## Host\n\n\n"
        f"## Inventory\n\n\n"
        f"## Conventions\n"
    )


def _export_v1_assets() -> str:
    with get_db_connection() as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        }
        if "gateway_assets" not in tables or "gateway_assets_v1" in tables:
            return ""
        rows = conn.execute("SELECT * FROM gateway_assets;").fetchall()
        if not rows:
            conn.execute("ALTER TABLE gateway_assets RENAME TO gateway_assets_v1;")
            conn.commit()
            return ""
        parts = []
        for row in rows:
            d = dict(row)
            key = d.get("key") or "item"
            title = d.get("name") or key
            sid = title.split()[0] if title else key
            if ":" in key:
                sid = key.split(":", 1)[-1]
            cat = (d.get("category") or "").lower()
            desc = d.get("description") or ""
            lines = [f"### {sid}", ""]
            if cat == "systemd":
                unit = d.get("name") or sid
                lines.append(f"- probe: systemd {unit}")
            elif cat == "docker":
                lines.append(f"- probe: docker {sid}")
            elif cat in ("web_app", "site"):
                pass
            try:
                endpoints = json.loads(d.get("endpoints_json") or "[]")
            except json.JSONDecodeError:
                endpoints = []
            try:
                paths = json.loads(d.get("config_paths_json") or "[]")
            except json.JSONDecodeError:
                paths = []
            http_url = None
            for ep in endpoints:
                if isinstance(ep, str) and ep.startswith("http"):
                    if http_url is None:
                        http_url = ep
                    lines.append(f"- url: {ep}")
                elif ep:
                    lines.append(f"- listen: {ep}")
            if cat in ("web_app", "site") and http_url:
                lines.append(f"- probe: http {http_url}")
            for p in paths:
                if p:
                    lines.append(f"- path: {p}")
            if desc:
                lines.append("")
                lines.append(desc)
            parts.append("\n".join(lines) + "\n")
        conn.execute("ALTER TABLE gateway_assets RENAME TO gateway_assets_v1;")
        conn.commit()
        return "\n".join(parts)


def ensure_document() -> None:
    p = overview_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(_skeleton(socket.gethostname()), encoding="utf-8")
    text = p.read_text(encoding="utf-8")
    if inventory_is_empty(text):
        dumped = _export_v1_assets()
        if dumped:
            if "## Inventory" in text:
                text = text.replace("## Inventory", "## Inventory\n\n" + dumped, 1)
            else:
                text += "\n## Inventory\n\n" + dumped
            p.write_text(text, encoding="utf-8")


def write_handwritten(content: str) -> None:
    """Write agent-supplied overview, stripping any status fence they included."""
    cleaned = strip_status_block(content)
    overview_path().parent.mkdir(parents=True, exist_ok=True)
    overview_path().write_text(cleaned if cleaned.endswith("\n") else cleaned + "\n", encoding="utf-8")
