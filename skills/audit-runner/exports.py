#!/usr/bin/env python3
"""
audit-runner / exports.py — 目标本地导出面确定性枚举（"导出即入口点"底座）。

设计动机（2026-08-16）:
  * 消费者树/兄弟扫描已退役（版本漂移双向失真）。导出 API 本身就是"设计承诺的外部调用面",
    无需扫描其他组件证明可达性。本 CLI 从目标本地确定性产出 exports[]。
  * 模糊模式（绝不编译目标）→ 无 ELF 符号表, 用源码级启发式分类:
      intended   = 头文件声明（公开 API 契约）→ 设计上就存在外部调用面
      accidental = 无头文件声明但树内无调用者 → 符号表带出, 仍可达（dlsym/LD_PRELOAD）
      internal   = 无头文件声明且有树内调用者 → 树内专用, 不作为导出入口

用法:
  audit-runner exports --root <abs-target> --cpg <cpg> [--out <path>]
  依赖: cpg.py（同目录）跑 exports.sc 查询。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import cpg

# 头文件函数声明启发式: 标识符 + "("（排除控制流关键字/宏）
DECL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
SKIP_KW = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "ifdef", "ifndef", "define", "include", "case", "goto", "typeof",
}
# 明显的静态/内部关键字, 排除（静态函数不可能导出）
STATIC_RE = re.compile(r"\bstatic\b")


def _header_declared_names(root: Path) -> dict[str, str]:
    """扫描目标树全部 .h, 提取疑似公开声明的函数名 → {name: header_path}。"""
    names: dict[str, str] = {}
    for f in root.rglob("*.h"):
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        # 跳过明显的内部头（实现细节）的粗暴启发: 仍收录, 分类靠 callers 兜底
        for m in DECL_RE.finditer(text):
            name = m.group(1)
            if name in SKIP_KW or name in names:
                continue
            # 略过宏展开/函数指针 typedef 的高频噪音前缀
            if name.startswith(("std", "va_", "uint", "int", "char", "long", "size_t")):
                continue
            names[name] = os.path.relpath(f, root)
    return names


def _parse_query_lines(lines: list[str]) -> list[dict]:
    """解析 exports.sc 输出行 file\\tline\\tfullName\\tcallers → 结构化。

    2026-08-20 修复:
      * 分隔符由 ':' 改为 '\\t' —— fullName 本身含 ':'（如 "Method:void()"），
        旧 "取末三段" 启发式会错位，把 "file:Some(line)" 并进 file 字段，
        导致 1157 条畸形导出 → 段1 导出注入爆炸。
      * lineNumber 已在 exports.sc 用 .getOrElse(0) 解包，这里兼容 '34' / 'Some(34)' 两种形态。
    """
    out: list[dict] = []
    for ln in lines:
        parts = ln.split("\t")
        if len(parts) < 4:
            continue
        file, line, fullName, callers = parts[:4]
        # 兼容 Option 残留: Some(34) / None / 34
        line_s = line.strip().removeprefix("Some(").removesuffix(")")
        callers_s = callers.strip().removeprefix("Some(").removesuffix(")")
        out.append({
            "file": file,
            "line": int(line_s) if line_s.isdigit() else 0,
            "fullName": fullName,
            "callers": int(callers_s) if callers_s.isdigit() else -1,
        })
    return out


def _symbol_name(fullName: str) -> str:
    """从 Joern Method.fullName 提取方法名。

    实际格式（C++ fuzzy）: "<class>.<method>:<returnType>" 或 "<method>:<returnType>"
    例: "TestAppChooser.test_getDefaultApp:void()" → "test_getDefaultApp"
        "resource.intToResourceUrgencyEnum:resource.ResourceUrgency(int)" → "intToResourceUrgencyEnum"
        ">>:ANY(QDBusArgument&,UnitProcess&)" → ">>"

    2026-08-20 修复: 旧实现取冒号最后一段, 在 fullName 变为完整格式后返回 "void()" 等返回类型,
    导致头文件声明匹配不到、全部导出被误分为 accidental。
    """
    # 1) 去掉最末 ":<returnType>" 段（若存在）
    base = fullName.rsplit(":", 1)[0] if ":" in fullName else fullName
    # 2) 去掉类/命名空间前缀, 取方法名
    name = base.rsplit(".", 1)[-1]
    # 3) 去掉模板/重复后缀噪音（如 "main<duplicate>0"）
    return name.split("<")[0].split(">")[0].strip()


def analyze(root: Path, cpg_path: str) -> dict:
    header_decls = _header_declared_names(root)

    q = (Path(__file__).resolve().parent / "queries" / "exports.sc").read_text(encoding="utf-8")
    res = cpg.query(cpg_path, q, timeout=240)
    if not res.get("ok"):
        return {"ok": False, "error": f"exports.sc 查询失败: {res.get('error') or res.get('stderr') or 'unknown'}"}

    rows = _parse_query_lines(res.get("result_lines") or [])
    # 防脏数据兜底（2026-08-20）: 只保留目标树内真实存在的文件。
    # 历史事故: exports.sc 的 lineNumber 未解包 + ':' 分隔解析错位 → file 变成
    # "path:Some(34)" 不存在路径, 1157 条唯一假文件 → 段1 导出注入爆炸。
    valid_rows = []
    skipped_bad_files = 0
    for r in rows:
        if r["file"] and (root / r["file"]).is_file():
            valid_rows.append(r)
        else:
            skipped_bad_files += 1
    rows = valid_rows

    exports: list[dict] = []
    for r in rows:
        sym = _symbol_name(r["fullName"])
        header = header_decls.get(sym)
        callers = r["callers"]
        if header:
            kind = "intended"
        elif callers == 0:
            kind = "accidental"
        else:
            kind = "internal"
        if kind == "internal":
            continue  # 不作为导出入口记录, 省输出
        exports.append({
            "symbol": sym,
            "file": r["file"],
            "line": r["line"],
            "kind": kind,
            "declared_in_header": header is not None,
            "header": header or None,
            "in_tree_callers": max(callers, 0),
            "entry_rank": 1 if (kind == "intended" and callers == 0)
                          else (2 if kind == "accidental" else 3),
        })

    # 排序: intended+无调用者 优先（纯导出契约入口）
    exports.sort(key=lambda e: (e["entry_rank"], e["file"], e["line"]))
    return {
        "ok": True,
        "exports": exports,
        "query_rows": len(rows),
        "skipped_bad_files": skipped_bad_files,
        "header_declared": len(header_decls),
    }


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="exports")
    ap.add_argument("--root", required=True, help="目标源码绝对路径")
    ap.add_argument("--cpg", required=True, help="段1 recon 构建的 CPG 路径")
    ap.add_argument("--out", help="写入路径（可选）")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(json.dumps({"ok": False, "error": f"target not a directory: {root}"}, ensure_ascii=False))
        return 3
    if not os.path.exists(args.cpg):
        print(json.dumps({"ok": False, "error": f"cpg 不存在: {args.cpg}"}, ensure_ascii=False))
        return 3

    res = analyze(root, args.cpg)
    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        res["written_to"] = str(out)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 4


def main() -> int:
    try:
        return _cli()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
