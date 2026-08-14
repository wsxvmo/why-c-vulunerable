#!/usr/bin/env python3
"""
audit-runner / cpg.py — CPG 生命周期管理（消灭本次 3 个失败根因）。

教训来源:
  * build_cpg 相对路径/无 --out → 失败; 绝对 root + 显式 --out 才行
  * 中断构建产物（空 overlays + cpg.bin.tmp）被误当可用 → 必须 cpg_status 验证
  * joern 从目标仓库 cwd 跑 → workspace/ 污染 + 误导性 stderr → 必须干净 cwd
  * query_cpg 尾表达式不输出 → 查询模板强制 println 包裹
  * 查询超时/空输出应转 grep 兜底, 不重试白等

CLI:
  python3 -m cpg doctor
  python3 -m cpg build  --root <abs> [--force]
  python3 -m cpg query  --cpg <abs> --file <query.sc> [--timeout 240]
  python3 -m cpg clean  --root <abs>          # 清理目标树内 workspace/ 污染
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import config

AUDIT_TOOLS = "audit-tools"


def _run(cmd: list, timeout: int = 300) -> dict:
    """调 audit-tools 或裸命令, 统一返回 dict。"""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {"ok": r.returncode == 0, "exit": r.returncode,
            "stdout": r.stdout, "stderr": r.stderr}


def _audit_tools(args: list, timeout: int = 300) -> dict:
    env = dict(os.environ)
    env["AUDIT_TOOLS_CACHE"] = str(config.audit_tools_cache())
    r = subprocess.run([AUDIT_TOOLS] + args, capture_output=True, text=True,
                       timeout=timeout, env=env)
    out = {}
    try:
        out = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        out = {"ok": r.returncode == 0, "exit": r.returncode,
               "stdout": r.stdout, "stderr": r.stderr}
    return out


def cache_path_for(root: str) -> Path:
    """复刻 audit-tools 的缓存键（root_abs + mtime）。"""
    root_abs = os.path.abspath(root)
    key = "%s-%d" % (root_abs.replace(os.sep, "_").strip("_"),
                     int(os.path.getmtime(root_abs)) if os.path.exists(root_abs) else 0)
    return config.audit_tools_cache() / ("%s.cpg" % key)


def build(root: str, force: bool = False, out: str | None = None) -> dict:
    """构建/复用 CPG。绝对 root + 显式输出路径 + 结果验证。"""
    root_abs = os.path.abspath(root)
    if not os.path.isdir(root_abs):
        return {"ok": False, "error": f"root 不存在: {root_abs}"}

    config.audit_tools_cache().mkdir(parents=True, exist_ok=True)
    target = out or str(cache_path_for(root_abs))

    res = _audit_tools(["cli", "build_cpg", "--root", root_abs,
                        "--out", target] + (["--force"] if force else []),
                       timeout=600)
    # 验证产物真实可用（防中断产物）
    if res.get("ok") and os.path.exists(target) and os.path.getsize(target) > 0:
        return {"ok": True, "cpg": target, "cached": res.get("cached", False),
                "elapsed": res.get("elapsed")}
    return {"ok": False, "error": f"CPG 构建失败/产物无效: {target}",
            "stderr": (res.get("stderr") or "")[-500:]}


def query(cpg: str, script_text: str, timeout: int = 240) -> dict:
    """执行 joern 查询。script_text 会被强制 println 包裹（若未包含）。"""
    if not os.path.exists(cpg):
        return {"ok": False, "error": f"cpg 不存在: {cpg}", "timeout": False}

    # 教训: 尾表达式不输出 → 确保以 println 输出结果
    stripped = script_text.strip()
    if "println(" not in stripped:
        script_text = f"println(({stripped}))"

    # 教训: joern 会往 cwd 写 workspace/ → 从干净 scratch 目录跑
    scratch = config.scratch_dir()
    scratch.mkdir(parents=True, exist_ok=True)
    fd, script_path = tempfile.mkstemp(suffix=".sc", dir=str(scratch))
    os.write(fd, script_text.encode("utf-8"))
    os.close(fd)

    env = dict(os.environ)
    env["AUDIT_TOOLS_CACHE"] = str(config.audit_tools_cache())
    try:
        r = subprocess.run(
            [AUDIT_TOOLS, "cli", "query_cpg", "--cpg", cpg,
             "--query", script_text, "--timeout", str(timeout)],
            capture_output=True, text=True, timeout=timeout + 30, env=env,
            cwd=str(scratch))
        out = {}
        try:
            out = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            out = {"ok": r.returncode == 0, "exit": r.returncode,
                   "stdout": r.stdout, "stderr": r.stderr}
        # 教训: ok:true 但 stdout 只有 INFO 行 = 空结果 → 标记, 供调用方转 grep
        stdout = out.get("stdout") or ""
        lines = [l for l in stdout.splitlines()
                 if not l.startswith("[INFO") and not l.startswith("Creating")
                 and not l.startswith("Project") and not l.startswith("Loading")
                 and not l.startswith("Overlay") and not l.startswith("The graph")
                 and not l.startswith("closing")]
        out["result_lines"] = lines
        out["empty_result"] = not lines
        return out
    finally:
        os.unlink(script_path)


def clean_workspace(root: str) -> list:
    """清理 joern 在目标树内留下的 workspace/ 污染。"""
    removed = []
    for ws in [Path(root) / "workspace"]:
        if ws.is_dir():
            shutil.rmtree(ws, ignore_errors=True)
            removed.append(str(ws))
    return removed


def fork(src: str, n: int, out_dir: str) -> dict:
    """把 CPG 复制成 n 份独立副本（每个子代理一份 → 真并行, 无锁竞争）。

    背景: 同一 CPG 的 joern 查询被 flock 串行化（每查询 ~13s, 8 agent 排队）。
    小 CPG（MB 级）复制成本毫秒级, 分区后每个 agent 用私有副本, 从构造上
    消除共享资源竞争 — 互斥锁不再需要（保留作纵深防御）。
    大 CPG（数百 MB）按 n 复制有磁盘/时间成本, 由调用方决定是否 fork
    （建议阈值: >100MB 用共享+锁, ≤100MB 用 fork）。
    """
    src_path = Path(src)
    if not src_path.is_file():
        return {"ok": False, "error": f"src 不是文件: {src}"}
    out_dir_path = Path(out_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)
    forks = []
    for i in range(n):
        dst = out_dir_path / f"fork-{i}.cpg"
        shutil.copy2(src_path, dst)
        forks.append(str(dst))
    return {"ok": True, "src": str(src_path), "forks": forks,
            "size": src_path.stat().st_size, "n": n}


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="cpg")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build"); p.add_argument("--root", required=True)
    p.add_argument("--force", action="store_true"); p.add_argument("--out")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("query"); p.add_argument("--cpg", required=True)
    p.add_argument("--file", required=True); p.add_argument("--timeout", type=int, default=240)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("clean"); p.add_argument("--root", required=True)

    p = sub.add_parser("fork"); p.add_argument("--src", required=True)
    p.add_argument("--n", type=int, required=True); p.add_argument("--dir", required=True)

    args = ap.parse_args()
    if args.cmd == "build":
        res = build(args.root, args.force, args.out)
    elif args.cmd == "query":
        res = query(args.cpg, Path(args.file).read_text(), args.timeout)
    elif args.cmd == "clean":
        res = {"ok": True, "removed": clean_workspace(args.root)}
    elif args.cmd == "fork":
        res = fork(args.src, args.n, args.dir)
    else:
        return 2

    print(json.dumps(res, ensure_ascii=False, indent=2) if getattr(args, "json", False)
          else json.dumps({k: v for k, v in res.items()
                           if k != "stderr"}, ensure_ascii=False))
    if args.cmd == "query" and res.get("empty_result"):
        print("[cpg] 空结果(仅 INFO 行) — 建议转 grep 兜底, 勿重试", file=sys.stderr)
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(_cli())
