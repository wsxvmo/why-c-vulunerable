#!/usr/bin/env python3
"""
audit_log.py — casefile 审计证据链记录工具（L1 决策证据 / L2 现场指针）

设计原则（人工可追溯 ≠ 过程重放）：
  L1 决策证据（~200B/条，写进 casefile.audit_log_json）：
    file:line、sink、entry、REACHABLE 路径摘要、KILL 原因、验证结果
  L2 现场指针（大块原始输出不落库，只存路径）：
    完整 sanitizer 输出 / PoC 源码 / joern 查询 → 文件留在 artifacts/ 目录
  L3 过程噪音（不记录）：模型推理、被否候选、重复查询

用法：
  # 追加一条证据
  python3 audit_log.py append <case_id> --stage TRACE --verdict REACHABLE \
      --evidence "argv[1] → strlen+1 → memcpy at conf.c:55" \
      [--artifact artifacts/trace/conf55.json] [--agent c-tracer]

  # 查看某个 case 的完整证据链（人类可读时间线）
  python3 audit_log.py view <case_id>

  # 查看全部（带 --stage 过滤）
  python3 audit_log.py list [--stage HUNT]

  # 在指定 casefile 上操作（默认向上查找 .pi/casefile.db）
  python3 audit_log.py --db /path/to/casefile.db append ...
"""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

COLUMN = "audit_log_json"
STAGES = ("RECON", "HUNT", "GAPFIL", "TRACE", "VALIDATE", "CHAIN", "REPORT", "KILL")


def find_casefile(start: str | None = None) -> str:
    """向上查找 .pi/casefile.db（与 pi-casefile 的 getCasefilePath 逻辑一致）"""
    if start and os.path.isfile(start):
        return os.path.abspath(start)  # 显式文件路径直接用
    if os.environ.get("PI_CASEFILE_PATH"):
        return os.path.abspath(os.environ["PI_CASEFILE_PATH"].strip())
    cur = os.path.abspath(start or os.getcwd())
    for _ in range(20):
        cand = os.path.join(cur, ".pi", "casefile.db")
        if os.path.exists(cand):
            return cand
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.join(cur, ".pi", "casefile.db")


def ensure_column(db: sqlite3.Connection) -> None:
    """幂等建列：官方扩展用显式列名 upsert，不会覆盖/删除我们的列"""
    cols = {r[1] for r in db.execute("PRAGMA table_info(cases)").fetchall()}
    if COLUMN not in cols:
        db.execute(f"ALTER TABLE cases ADD COLUMN {COLUMN} TEXT")
        db.commit()


def load_log(db: sqlite3.Connection, case_id: str) -> list[dict]:
    row = db.execute(f"SELECT {COLUMN} FROM cases WHERE id = ?", (case_id,)).fetchone()
    if not row or not row[0]:
        return []
    try:
        data = json.loads(row[0])
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def cmd_append(args) -> int:
    db = sqlite3.connect(find_casefile(args.db))
    ensure_column(db)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stage": args.stage,
        "agent": args.agent,
        "verdict": args.verdict,
        "evidence": args.evidence,
    }
    if args.artifact:
        entry["artifact"] = args.artifact  # L2 指针：大块原始输出只存路径
    if args.reason:
        entry["reason"] = args.reason

    log = load_log(db, args.case_id)
    log.append(entry)
    db.execute(
        f"UPDATE cases SET {COLUMN} = ?, updated_at = ? WHERE id = ?",
        (json.dumps(log, ensure_ascii=False), entry["ts"], args.case_id),
    )
    db.commit()
    n = db.total_changes
    db.close()
    print(f"[ok] {args.case_id}: +1 entry (total {len(log)})")
    return 0


def cmd_view(args) -> int:
    db = sqlite3.connect(find_casefile(args.db))
    ensure_column(db)
    log = load_log(db, args.case_id)
    if not log:
        print(f"(no audit log for {args.case_id})")
        return 0
    for e in log:
        color = {"REACHABLE": "\033[32m", "CONFIRMED": "\033[32m",
                 "KILL": "\033[31m", "killed": "\033[31m"}.get(e.get("verdict", ""), "")
        reset = "\033[0m" if color else ""
        line = f"[{e['ts']}] {e.get('stage','?'):8s} {color}{e.get('verdict','?'):10s}{reset} {e.get('evidence','')}"
        if e.get("agent"):
            line += f"  ({e['agent']})"
        if e.get("reason"):
            line += f"\n    reason: {e['reason']}"
        if e.get("artifact"):
            line += f"\n    artifact: {e['artifact']}"
        print(line)
    return 0


def cmd_list(args) -> int:
    db = sqlite3.connect(find_casefile(args.db))
    ensure_column(db)
    rows = db.execute(
        "SELECT id, status, audit_log_json FROM cases WHERE audit_log_json IS NOT NULL"
    ).fetchall()
    stage = args.stage
    total = 0
    for cid, status, raw in rows:
        try:
            log = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if stage:
            log = [e for e in log if e.get("stage") == stage]
        if log:
            total += len(log)
            print(f"{cid} [{status}]: {len(log)} entries")
    print(f"--- total: {total} entries across {len(rows)} cases ---")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="audit_log.py", description="casefile 审计证据链工具")
    p.add_argument("--db", help="casefile.db 路径（默认向上查找 .pi/casefile.db）")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("append", help="追加一条 L1 证据")
    pa.add_argument("case_id")
    pa.add_argument("--stage", required=True, choices=STAGES)
    pa.add_argument("--verdict", required=True,
                    help="REACHABLE/UNREACHABLE/CONFIRMED/KILL-1..5/finding 等")
    pa.add_argument("--evidence", required=True, help="一句话证据（file:line → sink 等）")
    pa.add_argument("--artifact", help="L2 指针：大块原始输出的文件路径")
    pa.add_argument("--reason", help="决策理由（KILL 原因等）")
    pa.add_argument("--agent", default="harness")
    pa.set_defaults(func=cmd_append)

    pv = sub.add_parser("view", help="查看某个 case 的完整证据链")
    pv.add_argument("case_id")
    pv.set_defaults(func=cmd_view)

    pl = sub.add_parser("list", help="列出有证据链的 case")
    pl.add_argument("--stage", choices=STAGES)
    pl.set_defaults(func=cmd_list)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
