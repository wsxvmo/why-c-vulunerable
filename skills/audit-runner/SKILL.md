---
name: audit-runner
description: Migration-first scaffold layer for the VDH/VVS audit pipeline — deterministic orchestration that codifies the failure lessons of the libkylin-ai-base run: CPG lifecycle (build/verify/cache/clean-cwd), joern query templates with println enforcement, schema gate wrapper, coverage state machine + gapfill queue, ledger dedup, and intermediate-conclusion checkpoints. Judgment (hunt semantics, trace hops, kill taxonomy, PoC design) stays with the agent; this skill only automates the 100%-replaceable procedures. Run `python3 doctor.py` after migration (5 health checks).
---

# audit-runner

VDH/VVS 流水线的**迁移优先脚手架层**：把本次 libkylin-ai-base 审计中踩过的、可确定性的坑固化成代码，把"判断"留给 agent。

## 为什么存在（本次审计的失败样本）

| 失败/摩擦 | 根因 | 本技能对应模块 |
|---|---|---|
| 3 个子代理失败/绕路 | CPG 状态混乱（中断产物、相对路径、缓存缺失） | `cpg.py` |
| 8/15 代理白跑查询 | query_cpg 不输出尾表达式（需 println）、引号转义、workspace 噪音 | `cpg.py` 查询模板 + 降级规则 |
| 收尾结论丢失（假中断） | 长等待步骤前未落盘中间结论、收尾 report 缺失 | `resilience.py` |
| 重复案件（C-0012） | 人工登记编号冲突 | `ledger.py` 封装 |
| 绝对路径断链 | 技能/preset/缓存硬编码路径 | `config.py` + `doctor.py` |

## 迁移指南（3 步）

1. 拷贝整个 `skills/audit-runner/` 目录到新环境的技能树。
2. `export VDH_PRESET=/path/to/vuln-hunter`（若默认路径不对；内含 casefile.py + schemas）。
3. `python3 doctor.py` — 5 项全绿即就绪；FAIL 项会给出 fix 指引。

可选 env：`VDH_SCHEMAS`（schema 目录）、`AUDIT_TOOLS_CACHE`（CPG 缓存，沙箱内指向工作区）、`VDH_SCRATCH`（joern 干净工作目录）、`VDH_CASEFILE`。

## 模块图

```
audit-runner/
├── SKILL.md      # 本文件
├── config.py     # 路径/env/工具链解析（迁移根, 零绝对路径）
├── doctor.py     # python3 doctor.py — 迁移健康检查 CLI
├── cpg.py        # CPG 生命周期: build/verify/cache/clean-cwd/workspace-清理
├── gate.py       # stage schema 门禁封装（casefile.py validate 包装 + 独立校验）
├── coverage.py   # CHECKED/UNCHECKED → COVERED/INCOMPLETE/SKIPPED 状态机 + GAPFIL 清单
├── ledger.py     # casefile.py CLI 封装（add 编号回显/去重/superseded）
├── resilience.py # 中间结论快照 checkpoint / resume（消灭空关闭消息丢结论）
└── queries/      # joern *.sc 查询模板（println 强制 + 降级规则文档）
```

## 边界（不做什么）

- **不做判断**：HUNT 语义验证、TRACE 逐跳、KILL-3/4 裁定、PoC 设计、CHAIN 因果 —— 这些留 agent。
- **不 import preset 内部**：只通过 CLI/JSON 调用 casefile.py 与 schemas，preset 可独立迁移。
- **不假设固定环境**：工具链运行时 `which` 探测；缺失降级（joern 超时 → grep 兜底）。

## 使用（协调器视角）

```bash
python3 doctor.py                                  # 迁移后第一件事
python3 -m cpg build --root <abs-target>           # CPG 构建+缓存+干净 cwd（须从本目录运行, 或改用绝对路径）
python3 /abs/path/to/audit-runner/cpg.py query --cpg <cpg> --file q.sc   # 绝对路径形式（任意 cwd 可用）
python3 -m gate validate <run-dir> <stage> <out>   # schema 门禁
python3 -m coverage report <auditor-outputs.json>  # 覆盖状态机 + GAPFIL 清单
python3 -m resilience checkpoint <case> <stage> <summary>  # 中间结论落盘
```

> 注: `python3 -m cpg` 依赖 audit-runner 在 PYTHONPATH/当前目录; 子代理环境里请用**绝对路径**调用（`python3 /home/xvmo/why-c-vulunerable/skills/audit-runner/cpg.py ...`）。
