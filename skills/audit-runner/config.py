#!/usr/bin/env python3
"""
audit-runner / config.py — 迁移优先的路径与工具链解析层。

设计原则（迁移三大雷区的对策）:
  1. 零绝对路径硬编码: 一切相对本文件位置解析, 外部依赖用环境变量覆盖。
  2. 接口级耦合: 只通过 CLI/JSON 调用 casefile.py / schemas, 不 import 其内部。
  3. 工具链运行时探测: joern/gcc 装在哪由 `which` 决定, 不写死在配置里。

迁移 = 拷贝整个 skills/audit-runner/ 目录 + 设 VDH_PRESET 环境变量（若默认值不对）。
迁移后先跑 `python3 doctor.py` 验证 5 项全绿。
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ── 本技能根目录（随技能树走, 迁移后自动正确）──────────────────────────
SKILL_ROOT = Path(__file__).resolve().parent          # .../skills/audit-runner
SKILLS_ROOT = SKILL_ROOT.parent                       # .../skills/  (catalog root)


def _first_existing(*paths: Path) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


def resolve_preset_dir() -> Path:
    """vuln-hunter preset（casefile.py + schemas 所在）。env 覆盖 > 常见默认位置。"""
    env = os.environ.get("VDH_PRESET")
    if env:
        return Path(env).expanduser().resolve()
    found = _first_existing(
        SKILLS_ROOT / ".." / ".dsh" / ".agent-presets" / "vuln-hunter",
        Path.home() / ".dsh" / ".agent-presets" / "vuln-hunter",
        Path("/home/xvmo/.dsh/.agent-presets/vuln-hunter"),
    )
    if found is None:
        raise RuntimeError(
            "preset 目录未找到: 请设置环境变量 VDH_PRESET=/path/to/vuln-hunter"
        )
    return found


def resolve_schemas_dir() -> Path:
    """stage schema 目录。env 覆盖 > preset/schemas > 技能旁路 schemas。"""
    env = os.environ.get("VDH_SCHEMAS")
    if env:
        return Path(env).expanduser().resolve()
    found = _first_existing(
        resolve_preset_dir() / "schemas",
        SKILLS_ROOT / ".." / "schemas",
        Path("/home/xvmo/why-c-vulunerable/schemas"),
    )
    if found is None:
        raise RuntimeError("schemas 目录未找到: 请设置 VDH_SCHEMAS")
    return found


def resolve_casefile() -> Path:
    """casefile.py 路径。env 覆盖 > preset/tools/casefile.py。"""
    env = os.environ.get("VDH_CASEFILE")
    if env:
        return Path(env).expanduser().resolve()
    found = _first_existing(resolve_preset_dir() / "tools" / "casefile.py")
    if found is None:
        raise RuntimeError(
            "casefile.py 未找到: 请检查 VDH_PRESET（应为含 tools/casefile.py 的目录）"
            "或直接设置 VDH_CASEFILE"
        )
    return found


def audit_tools_cache() -> Path:
    """audit-tools CPG 缓存目录。env 覆盖 > ~/.cache/audit-tools。
    注意: 若沙箱只允许 workspace 写入, 应把此 env 指到工作区内。"""
    env = os.environ.get("AUDIT_TOOLS_CACHE")
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".cache" / "audit-tools"


def scratch_dir() -> Path:
    """joern 干净工作目录（避免把 workspace/ 污染进目标仓库）。"""
    env = os.environ.get("VDH_SCRATCH")
    if env:
        return Path(env).expanduser().resolve()
    return Path("/tmp") / "audit-runner-scratch"


@dataclass
class Toolchain:
    """工具链运行时探测结果。"""
    present: Dict[str, Optional[str]] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)

    def all_present(self) -> bool:
        return not self.missing


def probe_toolchain(*names: str) -> Toolchain:
    tc = Toolchain()
    for n in names:
        p = shutil.which(n)
        if p:
            tc.present[n] = p
        else:
            tc.missing.append(n)
    return tc


# 核心工具清单（joern 家族 + 编排 + sanitizer）
CORE_TOOLS = (
    "joern", "joern-parse", "joern-scan",
    "audit-tools", "codebase-memory-mcp",
    "gcc", "valgrind", "python3",
)


def doctor() -> Dict[str, dict]:
    """5 项健康检查。返回 {check_name: {ok, detail, fix}}。"""
    out: Dict[str, dict] = {}

    # 1. 技能树本身
    out["skill-tree"] = {
        "ok": SKILL_ROOT.is_dir() and (SKILL_ROOT / "SKILL.md").exists(),
        "detail": str(SKILL_ROOT),
        "fix": "拷贝整个 skills/audit-runner/ 目录",
    }

    # 2. preset（casefile.py）
    try:
        preset = resolve_preset_dir()
        casefile = resolve_casefile()
        out["preset"] = {
            "ok": casefile.is_file(),
            "detail": f"preset={preset}\ncasefile={casefile}",
            "fix": "export VDH_PRESET=/path/to/vuln-hunter（含 tools/casefile.py）",
        }
    except RuntimeError as e:
        out["preset"] = {"ok": False, "detail": str(e), "fix": "export VDH_PRESET=..."}

    # 3. schemas（5 个 stage schema 文件）
    try:
        schemas = resolve_schemas_dir()
        need = {"finding", "trace", "validation", "chain", "report"}
        have = {s.name.replace("stage-", "").replace(".json", "") for s in schemas.glob("stage-*.json")}
        missing = need - have
        out["schemas"] = {
            "ok": not missing,
            "detail": f"dir={schemas} missing={sorted(missing) or 'none'}",
            "fix": "export VDH_SCHEMAS=/path/to/schemas（需含 5 个 stage-*.json）",
        }
    except RuntimeError as e:
        out["schemas"] = {"ok": False, "detail": str(e), "fix": "export VDH_SCHEMAS=..."}

    # 4. 工具链
    tc = probe_toolchain(*CORE_TOOLS)
    out["toolchain"] = {
        "ok": tc.all_present(),
        "detail": "; ".join(f"{k}={v}" for k, v in tc.present.items())
        + ("  MISSING: " + ",".join(tc.missing) if tc.missing else ""),
        "fix": "安装缺失工具, 或 export PATH 指向 joern/audit-tools 所在目录",
    }

    # 5. 缓存目录可写（audit-tools CPG 缓存）
    cache = audit_tools_cache()
    try:
        cache.mkdir(parents=True, exist_ok=True)
        probe = cache / ".audit-runner-write-probe"
        probe.write_text("ok")
        probe.unlink()
        writable = True
    except OSError:
        writable = False
    out["cache"] = {
        "ok": writable,
        "detail": str(cache),
        "fix": "export AUDIT_TOOLS_CACHE=<可写目录>（沙箱内则指向工作区）",
    }

    # 6. 阶段机顺序一致性（agent 提示词漂移检测 — 教训: harness.md 曾把
    #    VALIDATE 排在 GAPFIL 前, 与规范顺序相反且多文件重复声明, 漂移无人察觉）
    out["stage-order"] = _check_stage_order()

    # 7. codebase-memory 功能检查（不只是存在性）: 试索引微型目录。
    #    RECON 首选 codebase-memory 图枚举入口; 索引不可用(phase=dump 崩溃)时
    #    回退 joern CPG 图 — 该回退已在 RECON gate 文本中文档化。
    out["codebase-memory"] = _check_codebase_memory()

    return out


# 规范阶段机顺序（单一事实源）
CANONICAL_STAGES = ["RECON", "HUNT", "GAPFIL", "TRACE", "VALIDATE", "CHAIN", "REPORT"]

# 需要一致性检测的 agent 提示词文件: persona + 角色简报 + skills 清单
def _prompt_files() -> List[Path]:
    files: List[Path] = []
    try:
        files.append(resolve_preset_dir() / "agent.cordis.yml")
        roles = resolve_preset_dir() / "roles"
        files += sorted(roles.glob("*.md"))
    except RuntimeError:
        pass
    files += sorted(SKILLS_ROOT.glob("*/SKILL.md"))
    return files


def _extract_stage_seq(text: str) -> Optional[List[str]]:
    """从文本中提取箭头链里的阶段名序列（RECON...REPORT 窗口, ≤500 字符）。"""
    m = re.search(r"RECON\s*(?:→|->)\s*HUNT.{0,500}?REPORT", text, re.S)
    if not m:
        return None
    return re.findall(r"\b(RECON|HUNT|GAPFIL|TRACE|VALIDATE|CHAIN|REPORT)\b", m.group(0))


def _check_stage_order() -> dict:
    bad: List[str] = []
    checked = 0
    for f in _prompt_files():
        if not f.exists():
            continue
        text = f.read_text(errors="ignore")
        seq = _extract_stage_seq(text)
        if seq is None:
            continue
        checked += 1
        if seq != CANONICAL_STAGES:
            bad.append(f"{f.name}: {' → '.join(seq)}")
    if not checked:
        return {"ok": False, "detail": "未发现任何阶段机声明（扫描范围异常）",
                "fix": "检查 _prompt_files() 路径是否可访问"}
    if bad:
        return {"ok": False,
                "detail": f"阶段机顺序漂移 ({len(bad)}/{checked} 声明不一致): "
                          + "; ".join(bad),
                "fix": "修正为规范顺序: RECON → HUNT → GAPFIL → TRACE → VALIDATE → CHAIN → REPORT"}
    return {"ok": True, "detail": f"{checked} 处阶段机声明全部与规范一致",
            "fix": ""}


def _check_codebase_memory() -> dict:
    """第 7 项: codebase-memory 功能检查 — 试索引微型目录判定可用性。

    RECON 首选 codebase-memory 图; 索引不可用(phase=dump 崩溃)时回退
    joern CPG 图（RECON gate 已文档化该回退）。存在性检测不足以暴露
    服务/worker 崩溃 — 本项做一次 ~10s 的真实索引试跑。
    """
    import subprocess
    import tempfile

    if not shutil.which("codebase-memory-mcp"):
        return {"ok": False, "detail": "codebase-memory-mcp 未安装",
                "fix": "安装或 export PATH; RECON 将回退 joern CPG 图"}
    with tempfile.TemporaryDirectory(prefix="cbm-check-") as td:
        (Path(td) / "tiny.c").write_text(
            "int foo(int x){return x+1;}\nint main(){return foo(1);}\n")
        try:
            r = subprocess.run(
                ["codebase-memory-mcp", "cli", "index_repository",
                 "--repo-path", td, "--name", "cbm-doctor-probe", "--mode", "fast"],
                capture_output=True, text=True, timeout=45)
            raw = r.stdout + r.stderr
            import re as _re
            if _re.search(r'"status"\s*:\s*"error"', raw):
                return {"ok": False,
                        "detail": "索引功能异常(phase=dump 崩溃): RECON 将回退 joern CPG 图",
                        "fix": "排查 codebase-memory-mcp 服务/日志; 回退路径已文档化"}
            return {"ok": True, "detail": "功能正常（微型索引试跑通过）, RECON 可用其图枚举入口",
                    "fix": ""}
        except subprocess.TimeoutExpired:
            return {"ok": False, "detail": "索引试跑超时(45s): RECON 将回退 joern CPG 图",
                    "fix": "排查服务状态"}
        except Exception as e:  # pragma: no cover
            return {"ok": False, "detail": f"索引试跑异常({e}): RECON 将回退 joern CPG 图",
                    "fix": ""}


def doctor_exit(checks: Dict[str, dict]) -> int:
    """0=全绿, 1=有失败, 2=仅警告（当前无警告项, 预留）。"""
    return 1 if any(not c["ok"] for c in checks.values()) else 0


if __name__ == "__main__":
    # 独立自检: python3 config.py
    for name, c in doctor().items():
        print(f"[{'OK ' if c['ok'] else 'FAIL'}] {name}: {c['detail']}")
    sys.exit(doctor_exit(doctor()))
