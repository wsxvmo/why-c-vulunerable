#!/usr/bin/env python3
"""
audit-runner / doctor.py — 迁移健康检查 CLI。

用法:
  python3 doctor.py            # 打印 5 项检查 + 修复指引, exit 0/1
  python3 doctor.py --json     # JSON 输出（供脚本消费）

迁移后的第一动作: 跑 doctor, 5 项全绿再开工。
"""
from __future__ import annotations

import json
import sys

import config


def main() -> int:
    checks = config.doctor()
    json_out = "--json" in sys.argv
    if json_out:
        print(json.dumps(checks, ensure_ascii=False, indent=2))
    else:
        print("audit-runner doctor — 迁移健康检查")
        print("=" * 60)
        for name, c in checks.items():
            mark = "OK  " if c["ok"] else "FAIL"
            print(f"[{mark}] {name}")
            print(f"      detail: {c['detail'].replace(chr(10), chr(10) + '              ')}")
            if not c["ok"]:
                print(f"      fix   : {c['fix']}")
        print("=" * 60)
        ok_count = sum(1 for c in checks.values() if c["ok"])
        print(f"{ok_count}/{len(checks)} checks passed"
              + (" — 迁移就绪" if ok_count == len(checks) else " — 见上方 fix 指引"))
    return config.doctor_exit(checks)


if __name__ == "__main__":
    sys.exit(main())
