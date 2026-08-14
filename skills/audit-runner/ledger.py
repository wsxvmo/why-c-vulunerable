#!/usr/bin/env python3
"""
audit-runner / ledger.py — casefile.py CLI 封装。

消灭本次教训:
  * 编号冲突（build-flags 审计代理与协调器各 add 一次 → C-0011/C-0012 重复）:
    add 前先 search 标题关键词去重
  * log 引用了不存在的 case id
  * link 不校验目标/kind
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import config


def _casefile(args: list[str]) -> tuple[int, dict]:
    r = subprocess.run([sys.executable, str(config.resolve_casefile())] + args,
                       capture_output=True, text=True, timeout=60)
    out = {}
    try:
        out = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        out = {"raw": r.stdout}
    return r.returncode, out


def add(run_dir: str, title: str, *, bug_class: str, dedup_key: str = "",
        **fields) -> tuple[str | None, str]:
    """add 案件, 带标题去重。返回 (case_id or None, note)。"""
    if dedup_key:
        rc, out = _casefile(["search", run_dir, dedup_key])
        # casefile.py search 输出为文本行 "C-xxxx [status] title", 不是 JSON
        raw = out.get("raw") or ""
        ids = [line.split()[0] for line in raw.splitlines() if line.strip()]
        if ids:
            return None, f"跳过: 已存在同类案件 {ids[0]} (dedup_key={dedup_key})"
    argv = ["add", run_dir, "--title", title, "--bug-class", bug_class,
            "--status", "hypothesis"]
    for k, v in fields.items():
        argv += ["--field", f"{k}={v}"]
    rc, out = _casefile(argv)
    if rc != 0:
        return None, f"add 失败: {out}"
    cid = out.get("id")
    return cid, f"added {cid}" if cid else f"add 无 id: {out}"


def exists(run_dir: str, case_id: str) -> bool:
    rc, out = _casefile(["get", run_dir, case_id])
    return rc == 0 and bool(out)


def log(run_dir: str, case_id: str, stage: str, verdict: str, evidence: str,
        *, agent: str = "", artifact: str = "") -> str:
    if case_id != "run" and not exists(run_dir, case_id):
        return f"log 跳过: case {case_id} 不存在"
    argv = ["log", run_dir, case_id, "--stage", stage, "--verdict", verdict,
            "--evidence", evidence]
    if agent:
        argv += ["--agent", agent]
    if artifact:
        argv += ["--artifact", artifact]
    rc, out = _casefile(argv)
    return f"log {'ok' if rc == 0 else 'fail'}: {out}"


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="ledger")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--op", required=True, choices=["add", "exists", "log", "list"])
    ap.add_argument("--title", default="")
    ap.add_argument("--bug-class", default="other")
    ap.add_argument("--dedup-key", default="")
    ap.add_argument("--case-id", default="")
    ap.add_argument("--stage", default="HUNT")
    ap.add_argument("--verdict", default="finding")
    ap.add_argument("--evidence", default="")
    ap.add_argument("--agent", default="")
    ap.add_argument("--artifact", default="")
    args = ap.parse_args()

    if args.op == "add":
        cid, note = add(args.run_dir, args.title, bug_class=args.bug_class,
                        dedup_key=args.dedup_key)
        print(note)
        return 0 if cid else 1
    if args.op == "exists":
        print(exists(args.run_dir, args.case_id))
        return 0
    if args.op == "log":
        print(log(args.run_dir, args.case_id, args.stage, args.verdict,
                  args.evidence, agent=args.agent, artifact=args.artifact))
        return 0
    if args.op == "list":
        rc, out = _casefile(["list", args.run_dir])
        print(json.dumps(out, ensure_ascii=False) if isinstance(out, dict) else out)
        return rc
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
