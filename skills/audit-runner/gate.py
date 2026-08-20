#!/usr/bin/env python3
"""
audit-runner / gate.py — stage schema 门禁封装。

包装 casefile.py validate（唯一权威门禁）+ 独立快速校验。
exit: 0=PASS, 1=FAIL(字段缺失/非法), 2=输出 JSON 无法解析。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import config

REQUIRED_BY_STAGE = {
    # 2026-08-21: TRACE 已并入 HUNT — finding 直接携带可达性 trace 字段
    "finding":    ["vuln_class", "file", "line", "sink", "entry_point", "confidence", "evidence",
                   "attacker_model", "trace_result", "call_chain", "data_flow", "defenses_checked",
                   "reachability_basis"],
    "trace":      ["trace_result", "entry_point", "call_chain", "defenses_checked", "attacker_model"],
    "validation": ["finding_id", "status", "technique_used", "detection_method"],
    "chain":      ["chains", "summary"],
    "report":     ["target", "pipeline_status", "findings", "coverage", "summary"],
}


def quick_validate(output_path: str, stage: str) -> tuple[int, list[str]]:
    """不依赖 preset 的独立校验（doctor 级可用）。返回 (exit_code, errors)。"""
    try:
        data = json.load(open(output_path))
    except Exception as e:
        return 2, [f"JSON 解析失败: {e}"]
    if stage not in REQUIRED_BY_STAGE:
        return 1, [f"未知 stage: {stage}"]
    errors = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    else:
        items = [data]
    if stage == "finding":
        if not items:
            errors.append("finding 输出为空（需 findings 数组或单个 finding 对象）")
        for i, f in enumerate(items):
            for k in REQUIRED_BY_STAGE[stage]:
                if k not in f or f[k] in (None, ""):
                    errors.append(f"finding[{i}] 缺字段 {k}")
            if f.get("trace_result") == "REACHABLE" and not f.get("impact_if_reachable"):
                errors.append(f"finding[{i}] REACHABLE 缺 impact_if_reachable")
            if f.get("trace_result") == "UNREACHABLE" and not f.get("unreachable_reason"):
                errors.append(f"finding[{i}] UNREACHABLE 缺 unreachable_reason")
    else:
        for k in REQUIRED_BY_STAGE[stage]:
            if k not in data or data[k] in (None, ""):
                errors.append(f"缺字段 {k}")
    return (0, []) if not errors else (1, errors)


def authoritative_validate(run_dir: str, stage: str, output_path: str) -> tuple[int, str]:
    """casefile.py validate（硬门禁）。返回 (exit_code, summary)。"""
    casefile = config.resolve_casefile()
    r = subprocess.run(
        [sys.executable, str(casefile), "validate", run_dir, stage, output_path],
        capture_output=True, text=True, timeout=120)
    summary = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode, summary[-1] if summary else ""


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="gate")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--stage", required=True,
                    choices=sorted(REQUIRED_BY_STAGE))
    ap.add_argument("--output", required=True)
    ap.add_argument("--quick", action="store_true", help="仅独立校验, 不调 casefile")
    args = ap.parse_args()

    code, errors = quick_validate(args.output, args.stage)
    if errors:
        print("QUICK-FAIL:")
        for e in errors[:20]:
            print("  " + e)
        return code
    print("QUICK-PASS")
    if args.quick:
        return 0
    code, summary = authoritative_validate(args.run_dir, args.stage, args.output)
    print(f"AUTHORITATIVE: exit={code} {summary}")
    return code


if __name__ == "__main__":
    sys.exit(_cli())
