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
├── pctx.py       # 权限上下文确定性探测器（2026-08-16）: C/守护进程信号集 → privilege_context/trigger_context
├── exports.py    # 目标本地导出面枚举（2026-08-16）: exports.sc + 头文件交叉 → intended/accidental/internal
└── queries/      # joern *.sc 查询模板（println 强制 + 降级规则文档; 含 exports.sc）
```

## 边界（不做什么）

- **不做判断**：HUNT 语义验证、TRACE 逐跳、KILL-3/4 裁定、PoC 设计、CHAIN 因果 —— 这些留 agent。
- **不 import preset 内部**：只通过 CLI/JSON 调用 casefile.py 与 schemas，preset 可独立迁移。
- **不假设固定环境**：工具链运行时 `which` 探测；缺失降级（joern 超时 → grep 兜底）。
- **不扫兄弟组件**（2026-08-16）：pctx/exports 均**目标本地**；导出即入口点由目标自身决定，不做任何外部消费扫描。

## 使用（协调器视角）

```bash
python3 doctor.py                                  # 迁移后第一件事
audit-runner cpg build --root <abs-target>           # CPG 构建+缓存+干净 cwd（须从本目录运行, 或改用绝对路径）
python3 audit-runner cpg query --cpg <cpg> --file q.sc   # 绝对路径形式（任意 cwd 可用）
python3 audit-runner cpg fork --src <cpg> --n <N> --dir <forks/>  # 每子代理一份私有副本
audit-runner gate validate <run-dir> <stage> <out>   # schema 门禁
audit-runner coverage report <auditor-outputs.json>  # 覆盖状态机 + GAPFIL 清单
audit-runner resilience checkpoint <case> <stage> <summary>  # 中间结论落盘
audit-runner pctx --root <abs-target> --out <path>   # 权限上下文（preflight, 单一事实源）
audit-runner exports --root <abs-target> --cpg <cpg> --out <path>  # 导出面枚举（导出即入口点）
```

> 注: `audit-runner cpg` 依赖 audit-runner 在 PYTHONPATH/当前目录; 子代理环境里请用**绝对路径**调用（`audit-runner cpg ...`）。

## 并发策略（HUNT 多代理并行）

**并发上限：一次最多同时派 6 个子代理**（实测依据见下）。

1. **小 CPG（≤100MB, 推荐）**: 派发前 `cpg.py fork --n <并发数≤6>` 一次, 把 `fork-i.cpg` 路径写进第 i 个代理的提示词 → 每代理私有副本, 真并行, 无锁竞争。
2. **大 CPG（>100MB）**: 共享一份 + audit-tools flock 串行化（正确性优先, 后到排队）。
3. 锁（`_cpg_lock`）保留为纵深防御: 即使误用共享路径也不会损坏。

**实测（12 核 / 7.7GB RAM, joern 查询, 2026-08）**:

| 并发 | 总耗时 | 峰值总 JVM RSS | 结论 |
|---|---|---|---|
| 1 | 10s | 369 MB | 基线 |
| 3 | 15s | 1,608 MB | 甜点区 |
| 6 | 37s | 1,695 MB | 甜点区, 内存可控 |
| 8+ | 收益递减 | ~4.3GB(推算) | CPU 抢核, 内存线性涨 |

- 内存 ≈ **370-570 MB/并发查询**（JVM + CPG 加载）; 6 并发 ≈ 1.7GB 峰值。
- 瓶颈是 **CPU 核数**非内存: 6 并发 37s vs 串行 ~78s（省一半）, 8+ 并发收益递减。
- 派发纪律: 一次最多 6 个; 更多任务分批（先 6 后补）, 避免与 codebase-memory 服务（预算 ~1.9GB）抢内存。
