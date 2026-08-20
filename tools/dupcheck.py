#!/usr/bin/env python3
"""dupcheck.py — 内容重复确认（确定性 md5, 供 workflow-audit 用）

在**派发前**由 RECON 用本脚本确认两份文件字节相同（md5 一致）→ 写 content_dup_of;
副本文件**不派 HUNT agent**, 聚合段由 audit-pipeline.js 脚本确定性继承 canonical findings。
判定是命令输出的确定性结论, 不依赖 agent 目测。也可人工复核。

用法:
  python3 dupcheck.py <canonical> <dup>
  python3 dupcheck.py <canonical> <dup> --json

输出:
  默认: identical:true/false canonical_md5=<...> dup_md5=<...>
  --json: {"ok":true,"identical":bool,"canonical":"<abs>","dup":"<abs>",
           "canonical_md5":"<...>","dup_md5":"<...>"}
退出码: 0=字节相同, 1=不同, 2=任一文件缺失
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def md5(p: Path) -> str:
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="内容重复复核 (md5, 确定性)")
    ap.add_argument("canonical", help="canonical 文件绝对路径")
    ap.add_argument("dup", help="副本文件绝对路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON 结论")
    args = ap.parse_args()

    a, b = Path(args.canonical), Path(args.dup)
    if not a.is_file() or not b.is_file():
        missing = [str(p) for p in (a, b) if not p.is_file()]
        if args.json:
            print(json.dumps({"ok": False, "error": "file missing", "missing": missing},
                             ensure_ascii=False))
        else:
            print(f"missing: {', '.join(missing)}")
        return 2

    ma, mb = md5(a), md5(b)
    identical = ma == mb
    if args.json:
        print(json.dumps({"ok": True, "identical": identical, "canonical": str(a),
                          "dup": str(b), "canonical_md5": ma, "dup_md5": mb},
                         ensure_ascii=False))
    else:
        print(f"identical:{str(identical).lower()} canonical_md5={ma} dup_md5={mb}")
    return 0 if identical else 1


if __name__ == "__main__":
    sys.exit(main())
