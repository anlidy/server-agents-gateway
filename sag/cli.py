"""
服务器上的 root 命令行：
    sudo python3 -m sag elevation list [--all]
    sudo python3 -m sag elevation show <id>
    sudo python3 -m sag elevation approve <id> [--note 备注]
    sudo python3 -m sag elevation reject <id> [--note 备注]
    sudo python3 -m sag grant list
    sudo python3 -m sag grant add <path> [--ro] --reason 理由
    sudo python3 -m sag grant remove <path> --reason 理由
只有 root 能运行（gateway.db 本身也只有 root 可读）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

# 可在测试里替换
geteuid = os.geteuid


def _actor() -> str:
    return "cli:" + (os.environ.get("SUDO_USER") or "root")


def _print_request(r: dict, full: bool) -> None:
    print(f"{r['id']}  [{r['status']}]  {r['kind']}  申请人 {r['agent_id']}")
    print(f"  理由：{r['reason']}")
    print(f"  提交：{r['created_at']}  过期：{r['expires_at']}")
    if r.get("decided_by"):
        print(f"  处理：{r['decided_by']} @ {r['decided_at']}" + (f"（{r['decision_note']}）" if r.get("decision_note") else ""))
    print(f"  sha256：{r['payload_sha256']}")
    payload = r.get("payload") or {}
    for k, v in payload.items():
        if isinstance(v, str) and "\n" in v:
            print(f"  {k}:")
            for line in v.splitlines():
                print(f"    | {line}")
        else:
            print(f"  {k}: {v}")
    if full and r.get("result"):
        print("  结果：")
        print("    " + json.dumps(r["result"], ensure_ascii=False, indent=2).replace("\n", "\n    "))


def run_cli(argv: List[str]) -> int:
    if geteuid() != 0:
        print("只有 root 能运行：sudo python3 -m sag ...", file=sys.stderr)
        return 1
    from . import elevation, grants
    from .db import init_db

    parser = argparse.ArgumentParser(prog="python3 -m sag")
    sub = parser.add_subparsers(dest="area", required=True)
    ev = sub.add_parser("elevation", help="提权审批")
    ev_sub = ev.add_subparsers(dest="action", required=True)
    p = ev_sub.add_parser("list")
    p.add_argument("--all", action="store_true", help="包括已处理的")
    p = ev_sub.add_parser("show")
    p.add_argument("id")
    for name in ("approve", "reject"):
        p = ev_sub.add_parser(name)
        p.add_argument("id")
        p.add_argument("--note", default=None)
    gr = sub.add_parser("grant", help="operator 目录授权（ACL）")
    gr_sub = gr.add_subparsers(dest="action", required=True)
    gr_sub.add_parser("list")
    p = gr_sub.add_parser("add")
    p.add_argument("path")
    p.add_argument("--ro", action="store_true", help="只读（默认读写）")
    p.add_argument("--reason", required=True)
    p = gr_sub.add_parser("remove")
    p.add_argument("path")
    p.add_argument("--reason", required=True)
    args = parser.parse_args(argv)

    init_db()
    actor = _actor()
    try:
        if args.area == "elevation":
            if args.action == "list":
                out = elevation.list_elevations(actor, True, status="all" if args.all else "pending", limit=100)
                if not out["requests"]:
                    print("没有" + ("" if args.all else "待审批的") + "提权申请。")
                for r in out["requests"]:
                    _print_request(r, full=False)
                    print()
            elif args.action == "show":
                r = elevation.list_elevations(actor, True, request_id=args.id)["requests"][0]
                _print_request(r, full=True)
            elif args.action == "approve":
                out = elevation.approve_elevation(actor, True, args.id, note=args.note)
                print(f"{out['id']}：{out['status']}")
                print(json.dumps(out["result"], ensure_ascii=False, indent=2))
                return 0 if out["status"] == "executed" else 2
            else:
                out = elevation.reject_elevation(actor, True, args.id, note=args.note)
                print(f"{out['id']}：已拒绝")
        else:
            if args.action == "list":
                out = grants.list_grants()
                if not out["grants"]:
                    print("没有授权记录。")
                for g in out["grants"]:
                    print(f"{g['path']}  {g['access']}  by {g['granted_by']} @ {g['granted_at']}  {g['reason']}")
            elif args.action == "add":
                out = grants.grant_path(actor, True, args.path, access="ro" if args.ro else "rw", reason=args.reason)
                print(json.dumps(out, ensure_ascii=False, indent=2))
            else:
                out = grants.revoke_grant(actor, True, args.path, reason=args.reason)
                print(json.dumps(out, ensure_ascii=False, indent=2))
    except (ValueError, PermissionError, FileNotFoundError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    return run_cli(sys.argv[1:] if argv is None else argv)
