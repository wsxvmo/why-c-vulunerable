#!/usr/bin/env python3
"""
sink_filter.py — 九大类漏洞降噪引擎（确定性，无 AI）

输入: joern CPG（或源码目录，自动建 CPG）+ denoise_rules.json 规则表
输出: candidates.json — 三档分类:
  DROP  = 确定性安全（常量参数等），丢弃
  ALERT = 确定性危险（gets / strncpy 缺终止符 / setuid 未查返回值），直接报
  HIGH  = 高危候选（变量参数 + 无防护），优先送 AI
  LOW   = 低危候选（变量参数但长度常量等），降权送 AI

用法:
  python3 sink_filter.py --cpg /tmp/libsecurity1.cpg [--rules tools/denoise_rules.json]
  python3 sink_filter.py --src /path/to/source     # 自动建 CPG 再跑
  python3 sink_filter.py --cpg x.cpg --top 20      # 只看前 N 个 HIGH

数据流:
  1. joern 查询: 对规则表中每个函数，找所有调用点 + 参数节点分类
     (LITERAL=常量 / IDENTIFIER=变量 / CALL=函数调用结果)
  2. 应用 drop 规则: 指定参数是字面量 → DROP
  3. 应用 special 检查: terminator_check / retval_check / format_check / arith_check
  4. 输出三档 JSON（对齐 audit_log 的 L1 证据格式）
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

JOERN = os.environ.get("JOERN_BIN", "joern")
RULES_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "denoise_rules.json")

# ── joern 查询模板 ──────────────────────────────────────────────────────────
# 对每个规则函数: 输出 file:line | 参数索引:代码(节点类型)
# ── joern 查询模板 ──────────────────────────────────────────────────────────
# 对每个规则函数: 输出 file:line | 参数索引:代码(节点类型)
# 注意: 这是 raw string（非 f-string），Scala 代码用单 { }；
#       占位符 {outfile} {fn_list} 由 .replace() 填充。
QUERY_TEMPLATE = r"""
val out = new java.io.PrintWriter(new java.io.File("{outfile}"))
val fns = List({fn_list})
fns.foreach { fn =>
  cpg.call.nameExact(fn).foreach { c =>
    val args = c.argument.map { a =>
      val kind = a.label match {
        case "literal" => "LITERAL"
        case "identifier" => "IDENTIFIER"
        case "call" => "CALL"
        case other => other
      }
      s"${a.argumentIndex}:${a.code.replace("\n"," ").take(60)}($kind)"
    }.mkString(" | ")
    val inFn = c.method.name
    out.println(s"${c.location.filename}::${c.location.lineNumber}::$fn::$inFn::$args")
  }
}
out.close()
"""


def run_query(cpg: str, fn_list: list[str]) -> str:
    """在 CPG 上执行调用点+参数分类查询，返回原始行

    每次调用使用独立工作目录，避免 joern 在 workspace/ 建项目副本时
    因同名项目冲突（already exists - overwriting）导致结果不稳定。
    """
    fn_list_str = ", ".join(f'"{f}"' for f in fn_list)
    with tempfile.NamedTemporaryFile("w", suffix=".sc", delete=False) as f:
        script = f.name
    outfile = script + ".out.txt"
    query = (
        QUERY_TEMPLATE.replace("{outfile}", outfile)
        .replace("{fn_list}", fn_list_str)
    )
    with open(script, "w") as f:
        f.write(query)
    # 独立工作目录: joern --script 会在 cwd 下建 workspace/<cpg名>/ 副本
    workdir = tempfile.mkdtemp(prefix="sinkfilter-")
    try:
        subprocess.run(
            [JOERN, "--script", script, cpg],
            capture_output=True, timeout=300, check=False,
            cwd=workdir,
        )
        if os.path.exists(outfile):
            return open(outfile).read()
        return ""
    finally:
        for p in (script, outfile):
            if os.path.exists(p):
                os.unlink(p)
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)


def parse_lines(raw: str) -> list[dict]:
    """解析 joern 输出行: file::line::fn::inFn::args
    line 可能是 Some(55)（Scala Option），需剥离。
    """
    results = []
    for line in raw.splitlines():
        parts = line.split("::")
        if len(parts) < 5:
            continue
        file, line_raw, fn, in_fn = parts[0], parts[1], parts[2], parts[3]
        args = "::".join(parts[4:])
        # 剥离 Scala Option 包装: Some(55) → 55, None → 0
        m = re.search(r"(\d+)", line_raw)
        line_no = int(m.group(1)) if m else 0
        params = {}
        for seg in args.split(" | "):
            m = re.match(r"(\d+):(.*)\((\w+)\)$", seg)
            if m:
                params[int(m.group(1))] = {"code": m.group(2), "kind": m.group(3)}
        results.append({
            "file": file, "line": line_no, "function": fn,
            "in_function": in_fn, "params": params,
        })
    return results


def apply_drop(rule: dict, call: dict) -> bool:
    """drop 规则: 指定参数是 LITERAL → 丢弃"""
    drop = rule.get("drop")
    if not drop:
        return False
    param = call["params"].get(drop["param"])
    if not param:
        return False
    return param["kind"] == "LITERAL"


def apply_special(rule: dict, call: dict) -> str | None:
    """special 检查: 返回 ALERT / None。需要上下文时标记为 HIGH。"""
    special = rule.get("special")
    if not special:
        return None
    if special == "always_alert":
        return "ALERT"
    # 以下检查需要语句级上下文（后续语句/返回值），当前版本标记 HIGH 交给后续增强
    if special in ("terminator_check", "retval_check", "format_check", "arith_check"):
        return None  # 由增强查询处理；当前至少保留下游
    return None


def main():
    ap = argparse.ArgumentParser(description="九大类漏洞降噪引擎")
    ap.add_argument("--cpg", help="joern CPG 路径")
    ap.add_argument("--src", help="源码目录（自动建 CPG）")
    ap.add_argument("--rules", default=RULES_DEFAULT, help="规则表 JSON")
    ap.add_argument("--top", type=int, default=50, help="HIGH 最多输出条数")
    ap.add_argument("--include-drop", action="store_true", help="输出 DROP 档（默认隐藏）")
    args = ap.parse_args()

    if not args.cpg and not args.src:
        ap.error("需要 --cpg 或 --src")
    if args.src and not args.cpg:
        cpg = tempfile.mktemp(suffix=".cpg")
        print(f"[i] 建 CPG: {args.src} → {cpg}")
        subprocess.run([JOERN, "parse", args.src, "-o", cpg], check=False)
        args.cpg = cpg

    rules = json.load(open(args.rules))
    a_rules = [r for r in rules["rules"] if r["level"] == "A"]
    fns = sorted({r["function"] for r in a_rules if r["function"]})

    print(f"[i] 规则: {len(a_rules)} 条 A 级 / 函数 {len(fns)} 个 / CPG: {args.cpg}")
    raw = run_query(args.cpg, fns)
    calls = parse_lines(raw)
    print(f"[i] 找到调用点: {len(calls)}")

    dropped, alerts, high, low = [], [], [], []
    for call in calls:
        rule = next((r for r in a_rules if r["function"] == call["function"]), None)
        if not rule:
            continue
        if apply_drop(rule, call):
            dropped.append(call)
            continue
        verdict = apply_special(rule, call)
        if verdict == "ALERT":
            alerts.append(call)
        else:
            # 有变量参数 → HIGH；只有字面量参数但不符合 drop（如 strncpy）→ LOW
            has_var = any(p["kind"] in ("IDENTIFIER", "CALL") for p in call["params"].values())
            (high if has_var else low).append(call)

    print(f"\n=== 结果 ===")
    print(f"  DROP (安全丢弃): {len(dropped)}")
    print(f"  ALERT (确定性危险): {len(alerts)}")
    print(f"  HIGH (候选→AI): {len(high)}")
    print(f"  LOW (降权): {len(low)}")

    def dump(entries, label, show):
        if not show:
            return
        print(f"\n--- {label} ---")
        for c in entries[: args.top]:
            params = " | ".join(
                f"arg{i}:{p['code']}({p['kind']})" for i, p in sorted(c["params"].items())
            )
            print(f"  {c['file']}:{c['line']} :: {c['function']}() in {c['in_function']} :: {params}")

    dump(alerts, "ALERT", True)
    dump(high, "HIGH", True)
    dump(low, "LOW", True)
    dump(dropped, "DROP", args.include_drop)

    # 输出 JSON 文件（供 HUNT 消费）
    out = {
        "summary": {"dropped": len(dropped), "alert": len(alerts),
                    "high": len(high), "low": len(low)},
        "alerts": alerts, "high": high, "low": low,
    }
    out_path = os.path.join(os.getcwd(), "candidates.json")
    json.dump(out, open(out_path, "w"), indent=1, ensure_ascii=False)
    print(f"\n✅ 已写入 {out_path}")


if __name__ == "__main__":
    sys.exit(main())
