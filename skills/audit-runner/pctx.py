#!/usr/bin/env python3
"""
audit-runner / pctx.py — 权限上下文确定性探测器（privilege context analysis）。

设计动机（2026-08-16）:
  * 权限上下文从"RECON 模型口头判断"升级为确定性 CLI —— 单一事实源, 0 LLM token。
  * 吸收 unified-audit detect-privilege-context.sh 的信号维度, 但**改为 C/守护进程导向**
    （去掉 K8s/manifest 类, 补 SUID/特权 API/端口<1024/root daemon 形态）。
  * 输出 privilege_context(high|low|unknown) + trigger_context + signals[],
    喂给段2 TRACE(attacker_model) / 段3 REPORT(CVSS)。

用法:
  audit-runner pctx --root <abs-target> [--out <path>] [--json]
  退出码: 0 成功; 2 参数错误; 3 目标目录不存在。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# 强高权限信号（weight=2, 决定 privilege_context=high）: 目标自身形态即高权限
HIGH = 2
# 弱证据信号（weight=0, 只记录不参与判定）: 库调用 syslog//var 写入等不具决定性
EVIDENCE = 0
# 明确低权限信号（weight=-1）
LOW = -1

PRIVILEGED_API_RE = re.compile(
    r"\b(setuid\s*\(\s*0\s*\)|setreuid|seteuid|setresuid|setfsuid"
    r"|cap_setuid|CAP_SYS_ADMIN|capset|prctl\s*\(\s*PR_SET_(DUMPABLE|NO_NEW_PRIVS)"
    r"|init_module|finit_module|reboot\s*\(|kexec_load|mount\s*\(|unshare\s*\(\s*CLONE_NEW)"
)
DAEMONIZE_RE = re.compile(
    r"\b(daemon\s*\(\s*0\s*,\s*0\s*\)|setsid\s*\(|double\s*fork|setpgrp\s*\()"
)
SYSLOG_RE = re.compile(r"\b(syslog\s*\(|openlog\s*\()")
VAR_WRITE_RE = re.compile(r"/var/(run|log|lib)|/etc/")
LOW_PORT_RE = re.compile(r"\bhtons\s*\(\s*(\d{1,5})\s*\)")
BIND_RE = re.compile(r"\bbind\s*\(")


def _grep_files(root: Path, pattern: re.Pattern, *globs: str) -> list[dict]:
    """rg 扫描目标树源码, 返回 {file, line} 命中列表; rg 不可用时回退 find+grep。"""
    hits: list[dict] = []
    if shutil.which("rg"):
        # 用 -g 传 glob（subprocess 不走 shell, 位置参数不展开; rg 会把裸 glob 当路径报错）
        cmd = ["rg", "-n", "--no-heading"]
        for g in globs:
            cmd += ["-g", g]
        cmd += [pattern.pattern, "."]
        r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=120)
        if r.returncode in (0, 1):  # 1 = 无命中, 非错误
            for line in r.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    hits.append({"file": parts[0], "line": parts[1]})
        return hits
    # 回退: find + grep
    try:
        files = subprocess.run(
            ["find", str(root), "-type", "f", "(", "-name", "*.c", "-o", "-name", "*.h",
             "-o", "-name", "*.cpp", "-o", "-name", "*.sh", "-o", "-name", "Makefile*",
             "-o", "-name", "CMakeLists.txt", ")"],
            capture_output=True, text=True, timeout=60).stdout.splitlines()
    except subprocess.TimeoutExpired:
        return hits
    for f in files:
        try:
            with open(f, "r", errors="replace") as fh:
                for i, text in enumerate(fh, 1):
                    if pattern.search(text):
                        hits.append({"file": os.path.relpath(f, root), "line": str(i)})
        except OSError:
            continue
    return hits


def _find_setuid(root: Path) -> list[str]:
    """目标树内带 setuid/setgid 位的二进制/脚本（高权限信号）。"""
    out: list[str] = []
    try:
        r = subprocess.run(
            ["find", str(root), "-type", "f", "-perm", "/6000"],
            capture_output=True, text=True, timeout=60)
        for f in r.stdout.splitlines():
            if f.strip():
                out.append(os.path.relpath(f, root))
    except (subprocess.TimeoutExpired, OSError):
        pass
    return out


def _find_systemd_units(root: Path) -> list[dict]:
    """systemd unit 文件中的 User= 指令（*.service/*.socket/*.timer, 不限目录）。"""
    units: list[dict] = []
    for pat in ("*.service", "*.socket", "*.timer"):
        for f in root.rglob(pat):
            if not f.is_file():
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            rel = os.path.relpath(f, root)
            if re.search(r"(?m)^User\s*=\s*root\s*$", text):
                units.append({"file": rel, "line": "User=root"})
            elif not re.search(r"(?m)^User\s*=", text):
                units.append({"file": rel, "line": "无 User 指令(默认 root)"})
    return units


def _find_install_paths(root: Path) -> list[dict]:
    """Makefile/CMake install 目标指向系统特权路径。"""
    hits: list[dict] = []
    priv_paths = ("/usr/bin", "/usr/sbin", "/sbin", "/usr/lib", "/lib", "/etc", "/usr/local/bin")
    pat = re.compile(r"(install|DESTDIR).*(" + "|".join(re.escape(p) for p in priv_paths) + ")")
    for glob in ("Makefile", "Makefile.in", "CMakeLists.txt", "*.mk"):
        for f in root.rglob(glob):
            if not f.is_file():
                continue
            try:
                for i, text in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if pat.search(text):
                        hits.append({"file": os.path.relpath(f, root), "line": str(i)})
                        break
            except OSError:
                continue
    return hits


def _detect_port_binding(root: Path) -> list[dict]:
    """bind() + htons(<1024) 的低端口监听（root 才可绑 <1024）。"""
    hits: list[dict] = []
    for h in _grep_files(root, BIND_RE, "*.c", "*.cpp", "*.h"):
        try:
            with open(root / h["file"], "r", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        start = max(0, int(h["line"]) - 3)
        for i in range(start, min(len(lines), int(h["line"]) + 3)):
            m = LOW_PORT_RE.search(lines[i])
            if m and 0 < int(m.group(1)) < 1024:
                hits.append({"file": h["file"], "line": str(i + 1), "port": m.group(1)})
                break
    return hits


def analyze(root: Path) -> dict:
    signals: list[dict] = []

    # 1. SUID/SGID
    for f in _find_setuid(root):
        signals.append({"signal": "setuid/setgid 位", "evidence": f, "weight": HIGH})

    # 2. systemd units
    for u in _find_systemd_units(root):
        signals.append({"signal": "systemd unit", "evidence": f"{u['file']}:{u['line']}",
                        "weight": HIGH if u["line"] == "User=root" else LOW})

    # 3. install 到特权路径
    for h in _find_install_paths(root):
        signals.append({"signal": "install 到特权路径", "evidence": f"{h['file']}:{h['line']}", "weight": HIGH})

    # 4. 特权 API 调用
    for h in _grep_files(root, PRIVILEGED_API_RE, "*.c", "*.cpp", "*.h"):
        signals.append({"signal": "特权 API", "evidence": f"{h['file']}:{h['line']}", "weight": HIGH})

    # 5. daemon 化（强）: daemon(0,0)/setsid/fork 守护 → 高权限守护进程形态
    for h in _grep_files(root, DAEMONIZE_RE, "*.c", "*.cpp", "*.h"):
        signals.append({"signal": "daemon 化", "evidence": f"{h['file']}:{h['line']}", "weight": HIGH})

    # 6. syslog 形态（弱证据, 不参与判定）: 库也可能用 syslog, 不具决定性
    for h in _grep_files(root, SYSLOG_RE, "*.c", "*.cpp", "*.h"):
        signals.append({"signal": "syslog 形态", "evidence": f"{h['file']}:{h['line']}", "weight": EVIDENCE})

    # 7. 系统目录写入（弱证据, 不参与判定）
    for h in _grep_files(root, VAR_WRITE_RE, "*.c", "*.cpp", "*.h", "*.sh"):
        signals.append({"signal": "系统目录写入(/var//etc)", "evidence": f"{h['file']}:{h['line']}", "weight": EVIDENCE})

    # 8. 低端口绑定（强）
    for h in _detect_port_binding(root):
        signals.append({"signal": "绑定特权端口(<1024)", "evidence": f"{h['file']}:{h['line']} port={h['port']}",
                        "weight": HIGH})

    # 9. 容器打包（轻量, 存在才计）
    docker = root / "Dockerfile"
    if docker.is_file():
        try:
            text = docker.read_text(errors="replace")
            if re.search(r"(?m)^USER\s+root\s*$", text):
                signals.append({"signal": "Dockerfile USER root", "evidence": "Dockerfile", "weight": HIGH})
            elif re.search(r"(?m)^USER\s+", text):
                signals.append({"signal": "Dockerfile USER 非 root", "evidence": "Dockerfile", "weight": LOW})
        except OSError:
            pass

    # ── 判定 ──────────────────────────────────────────────
    # 规则（可辩护）: 任一强高权限信号 → high（目标自身形态即高权限）;
    # 无强信号但有明确低权限信号 → low; 否则 unknown（库/CLI 无固有权限, 交由调用方上下文）
    strong_high = any(s["weight"] >= 2 for s in signals)
    explicit_low = any(s["weight"] <= -1 for s in signals)
    if strong_high:
        privilege_context = "high"
    elif explicit_low:
        privilege_context = "low"
    else:
        privilege_context = "unknown"

    # trigger_context 推断（确定性启发式）
    trigger_context = "unknown"
    unit_files = [s for s in signals if s["signal"] == "systemd unit"]
    setuid_files = [s for s in signals if s["signal"] == "setuid/setgid 位"]
    port_files = [s for s in signals if s["signal"] == "绑定特权端口(<1024)"]
    if port_files or unit_files:
        trigger_context = "unprivileged_user"     # 服务/网络监听: 远程或低权用户可触发
    elif setuid_files:
        trigger_context = "local_user"            # setuid 二进制: 需本地账户触发
    elif privilege_context == "low":
        trigger_context = "local_user"
    if trigger_context == "unknown" and any(s["signal"] == "特权 API" for s in signals):
        trigger_context = "admin_only"            # 特权原语但非守护/网络形态 → 高权限操作

    n_sig = len(signals)
    evidence_confidence = "high" if n_sig >= 3 else ("medium" if n_sig >= 1 else "low")

    return {
        "privilege_context": privilege_context,
        "trigger_context": trigger_context,
        "signals": signals,
        "evidence_confidence": evidence_confidence,
    }


def _cli() -> int:
    ap = argparse.ArgumentParser(prog="pctx")
    ap.add_argument("--root", required=True, help="目标源码绝对路径")
    ap.add_argument("--out", help="写入路径（可选, 缺省只打印）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(json.dumps({"error": f"target not a directory: {root}"}, ensure_ascii=False))
        return 3

    res = analyze(root)
    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        res["written_to"] = str(out)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    try:
        return _cli()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
