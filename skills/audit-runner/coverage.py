#!/usr/bin/env python3
"""
audit-runner / coverage.py — 覆盖状态机 + GAPFIL 清单生成。

纯规则, 零判断（判断留协调器）:
  * 任何 UNCHECKED 入口 → INCOMPLETE（即使有 hypothesis）
  * UNCHECKED 空 + ≥1 hypothesis → COVERED
  * UNCHECKED 空 + 0 hypothesis → NOT_FOUND（仅此时允许）
  * 无适用面 → SKIPPED（需显式 reason）
  * INCOMPLETE 类进 GAPFIL 队列（携带 CHECKED 列表防止重蹈）

输入格式（每个审计代理一行）:
  {"cls": "buffer-overflow", "checked": ["main", "recv"], "unchecked": ["cfg-parser"],
   "hypotheses": 1, "skipped_reason": null}
"""
from __future__ import annotations

import argparse
import json
import sys

STATUS = ("COVERED", "INCOMPLETE", "SKIPPED", "NOT_FOUND")


def classify(entry: dict) -> str:
    cls = entry["cls"]
    if entry.get("skipped_reason"):
        return "SKIPPED"
    unchecked = entry.get("unchecked") or []
    hypotheses = entry.get("hypotheses", 0)
    if unchecked:
        return "INCOMPLETE"
    return "COVERED" if hypotheses else "NOT_FOUND"


def evaluate(entries: list[dict]) -> dict:
    per_class: dict[str, dict] = {}
    for e in entries:
        c = per_class.setdefault(e["cls"], {
            "checked": [], "unchecked": [], "hypotheses": 0, "status": None})
        c["checked"] += e.get("checked") or []
        c["unchecked"] += e.get("unchecked") or []
        c["hypotheses"] += e.get("hypotheses", 0)
    for c in per_class.values():
        c["unchecked"] = sorted(set(c["unchecked"]))
        c["checked"] = sorted(set(c["checked"]))
        c["status"] = "COVERED" if not c["unchecked"] and c["hypotheses"] else \
                      "INCOMPLETE" if c["unchecked"] else \
                      "NOT_FOUND"
    return per_class


def gapfill_queue(per_class: dict[str, dict]) -> list[dict]:
    """INCOMPLETE 类 → GAPFIL 任务（携带 CHECKED 列表防止重蹈）。"""
    return [{"cls": k, "unchecked": v["unchecked"], "checked": v["checked"]}
            for k, v in per_class.items() if v["status"] == "INCOMPLETE"]


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="coverage")
    ap.add_argument("--input", required=True, help="auditor entries JSON 文件")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    entries = json.load(open(args.input))
    per_class = evaluate(entries)
    gaps = gapfill_queue(per_class)
    out = {"classes": per_class, "gapfill": gaps,
           "summary": {k: v["status"] for k, v in per_class.items()}}
    print(json.dumps(out, ensure_ascii=False, indent=2) if args.json
          else _render(per_class, gaps))
    return 0


def _render(per_class: dict, gaps: list) -> str:
    lines = ["覆盖状态:"]
    for k in sorted(per_class):
        v = per_class[k]
        lines.append(f"  {v['status']:<10} {k:<28} "
                     f"(checked={len(v['checked'])}, unchecked={len(v['unchecked'])}, hyp={v['hypotheses']})")
    lines.append(f"GAPFIL 队列: {len(gaps)} 个 INCOMPLETE 类")
    for g in gaps:
        lines.append(f"  - {g['cls']}: UNCHECKED={g['unchecked']} CHECKED={g['checked']}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(_cli())
