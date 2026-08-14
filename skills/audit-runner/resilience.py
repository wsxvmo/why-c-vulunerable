#!/usr/bin/env python3
"""
audit-runner / resilience.py — 中间结论快照（消灭"分析完毕、结论未落地"类失败）。

本次教训:
  * 034fa573 死在"等 joern 后台作业期间会话被掐断, 结论未落地"
  * ff7ae72c 收尾 report 调用缺失 → 空关闭消息 → 误判中断

用法（协调器/子代理纪律）:
  1. 任何长等待步骤（CPG 构建、后台 job、subagent 派发）之前:
     python3 -m resilience checkpoint <run-dir> <case-or-run> <stage> '<one-line-json>'
  2. 失败后: python3 -m resilience resume <run-dir>  → 列出所有快照, 结论不丢
  3. 收尾:  python3 -m resilience done <run-dir> <case-or-run> <stage>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _snap_dir(run_dir: str) -> Path:
    d = Path(run_dir) / "artifacts" / "checkpoints"
    d.mkdir(parents=True, exist_ok=True)
    return d


def checkpoint(run_dir: str, case: str, stage: str, summary: str,
               extra: dict | None = None) -> str:
    """落盘中间结论快照。summary 应含可验证结论, 不是过程噪音。"""
    p = _snap_dir(run_dir) / f"{case}-{stage}-{datetime.now(timezone.utc).strftime('%H%M%S')}.json"
    data = {"case": case, "stage": stage, "summary": summary,
            "extra": extra or {}, "at": datetime.now(timezone.utc).isoformat()}
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    return str(p)


def resume(run_dir: str) -> list[dict]:
    """列出全部快照（按时间序）。"""
    out = []
    for p in sorted(_snap_dir(run_dir).glob("*.json")):
        out.append(json.loads(p.read_text()))
    return out


def done(run_dir: str, case: str, stage: str) -> int:
    """标记某 case+stage 快照已消费（删除）。返回删除数。"""
    n = 0
    for p in _snap_dir(run_dir).glob(f"{case}-{stage}-*.json"):
        p.unlink()
        n += 1
    return n


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="resilience")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("checkpoint")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--stage", required=True)
    p.add_argument("--summary", required=True)
    p = sub.add_parser("resume"); p.add_argument("--run-dir", required=True)
    p = sub.add_parser("done")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--stage", required=True)
    args = ap.parse_args()

    if args.cmd == "checkpoint":
        print(checkpoint(args.run_dir, args.case, args.stage, args.summary))
    elif args.cmd == "resume":
        snaps = resume(args.run_dir)
        if not snaps:
            print("无快照")
            return 0
        for s in snaps:
            print(f"[{s['at']}] {s['case']} {s['stage']}: {s['summary'][:120]}")
        return 0
    elif args.cmd == "done":
        print(f"removed {done(args.run_dir, args.case, args.stage)} snapshots")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
