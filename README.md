# pi-xpi-c — C/C++/Shell/Python 代码审计流水线

基于 pi-xpi（XPI）架构改造的 **静态代码审计流水线**，面向 C/C++、Shell、Python 源码。保留原架构的 5-agent 分工、schema 硬门禁、PoC 沙箱确认、覆盖追踪机制，但把 Web 渗透语义替换为代码审计语义：

- **验证手段**：本地 sanitizer 复现（ASAN/UBSAN/valgrind），不编译目标项目、不打线上目标
- **分析引擎**：Joern（CPG，fuzzy 模式，无需编译）+ codebase-memory-mcp（tree-sitter 图谱）+ clangd/pi-lsp（语义验证）
- **无 CPG/CodeQL 之外的第三方依赖**：不用 CodeQL，Web 工具（httpx/ffuf/nuclei）全部移除

## 安装

### ⚡ 一键安装（推荐）

```bash
cd ~/why-c-vulunerable
bash bootstrap.sh
```

自动完成：工具链检测 → 5 个 c-* agents 安装 → pi 包注册（skills + case-context 扩展）→ 验证。

```bash
bash bootstrap.sh --check   # 只查工具链 + 安装状态
bash bootstrap.sh --force   # 强制重新注册包
```

安装后：给协调器（c-harness）一句"对 <目标> 跑代码审计流水线"即可；审计技能（codeaudit-pipeline / audit-runner / code-audit / audit-tools）由 agent 按需加载。

### 手动安装（分步）

```bash
# 方式一：本地路径安装（推荐，独立包名不与原 pi-xpi 冲突）
pi install /home/xvmo/why-c-vulunerable

# 方式二：仅安装 agents（独立命名空间，不覆盖原 xpi agents）
bash install-c.sh
```

### 依赖环境

| 依赖 | 用途 | 检查 |
|------|------|------|
| joern / joern-parse / joern-scan | CPG 构建 + 污点查询 + querydb 扫描 | `command -v joern` |
| codebase-memory-mcp | 全库图谱、调用链追踪 | `command -v codebase-memory-mcp` |
| audit-tools | Joern/codebase-memory 硬封装（禁裸 joern） | `command -v audit-tools` |
| audit-runner (skills/audit-runner/) | 确定性编排层（CPG 生命周期/门禁/覆盖/账本/快照） | `python3 doctor.py` |
| pi-lsp（clangd） | C/C++ 语义级验证（可选用 `clangd --check`；缺失时用 read/grep 兜底） | `command -v clangd`（可选） |
| gcc/clang + valgrind | sanitizer 复现（VALIDATE 阶段） | `command -v gcc valgrind` |

**不依赖**：CodeQL、Joern 以外的重型分析器、任何 Web 渗透工具、目标项目编译能力。

## 工具

| 工具 | 用途 |
|------|------|
| `casefile.py`（preset 内置）| 案件台账 + 证据日志 + schema 硬门禁（`validate` 权威校验，sandbox 内 PoC exit 0 才确认）|
| `audit-runner`（skills/audit-runner/）| 确定性编排层：`ledger.py`（去重登记/log）、`gate.py`（门禁）、`coverage.py`（覆盖状态机）、`resilience.py`（中间快照）、`cpg.py`（CPG 生命周期）、`doctor.py`（健康检查）|
| `audit-tools`（extensions/）| Joern/codebase-memory 硬封装（禁裸 joern）|
| read / grep / `clangd --check` | 逐跳语义验证（本环境无 pi `lsp_*` 工具，用 read/grep 兜底）|

> 注：pi 时代的 Case*/PromoteFinding/lsp_* 工具在本环境不存在 — persona 与角色简报已改用上述真实工具。

## 快速开始

```
告诉 harness 目标即可，例如：
"对 ~/exploit-src/libsecurity1 跑一次完整代码审计流水线"
```

Skills（`skills/pipeline` → skill 名 `codeaudit-pipeline`、`skills/code-audit`）自动加载进 agent 上下文。无需斜杠命令 — 直接让 agent 开猎即可。

### workflow 模式（无主-agent 流水线，推荐用于完整审计）

`skills/workflow-audit/`（skill 名 `workflow-audit`）把同一套流水线改成 **DSH `workflow` 工具驱动的无主-agent 作业**：主 agent 只发一次调用，各阶段在新鲜上下文的子 agent 中执行，消灭主 agent 的"会话长寿税"（实测基线 32.1M tokens 中 31.8M 是历史重发；workflow 模式主 agent 单轮 ~1 万量级）。

```
段1 audit-pipeline.js   RECON → HUNT → GAPFIL        → {findings[](含 trace 字段), coverage}
段2 validate.js         VALIDATE                     → {confirmed[], killed[], env_blocked[], unreachable[]}
段3 chain-report.js     CHAIN → REPORT               → {report}
```

调用方式：`read skills/workflow-audit/<段脚本>` → `workflow({meta, script: <内容>, args: {target, ...}})`，详见 SKILL.md。

## 流水线阶段机

```
RECON → HUNT(+可达性) → GAPFIL(循环) → VALIDATE → CHAIN → REPORT
  ↑___________________|                     |
  └────── FEEDBACK ────┘                   FIX (可选)
```
> TRACE 阶段已并入 HUNT（2026-08-21）：auditor 直接产出 finding + 可达性 trace 字段；VALIDATE 作为独立第二视角先否证再 PoC。

| 阶段 | 做什么 | 门禁 |
|------|--------|------|
| RECON | 入口点清单 + 工具链验证 + CPG 构建（fuzzy）| 目标/工具链记录 |
| HUNT | 按 CWE 类×文件聚合审计；Joern 强制引擎；**产出 finding + 可达性 trace 字段**（TRACE 已并入） | stage-finding.json（合并契约） |
| GAPFIL | INCOMPLETE 类补查（按入口点粒度）| 覆盖追踪 |
| VALIDATE | 独立否证 HUNT 可达性 + 自包含 repro + sanitizer 触发（不编译目标）| stage-validation.json + exit 0 |
| CHAIN | 已确认漏洞组合链（cwe_id/cvss）| stage-chain.json |
| REPORT | KVE 模板对接报告（cwe_id/cvss_vector/cvss_score）| stage-report.json |

## 核心规则

1. **绝不编译目标项目**。只编译从目标提取的自包含 repro 文件。
2. **Joern/clangd 输出 = 候选**，每个 finding 必须 hop-by-hop 证据（entry → sink）。
3. **确认 = sanitizer 真实触发**（ASAN heap-buffer-overflow / UAF / valgrind invalid read…），不是静态推理。
4. **Shell 文件**走 codebase-memory + bash-language-server 通道（Joern 无 shell 前端）。
5. 无 OOB、无限速、无 HTTP 探测 — 这是本地代码审计，不是 Web 渗透。

## 自动注入（case-context 扩展）

包内 `extensions/case-context.ts` 在每次会话开始时自动注入：
1. **Code Audit Workflow 纪律**（案件生命周期状态机 + 5 条硬门禁 + kill checklist）
2. **活动案件列表**（`<casefile_context>`：confirmed/investigating/hypothesis + nextStep）

与 pi-casefile 的 `/xp`（web 渗透工作流，opt-in）不同：这是代码审计专用且**始终开启** — 技能作为包加载，案件意识也应常驻。无需 `/xp on`。

## audit-runner（迁移优先脚手架层）

`skills/audit-runner/` 是本流水线的**确定性编排层**：把审计中反复踩到的、100% 可脚本化的过程固化成代码，agent 预算只花在判断上。由 libkylin-ai-base 实盘审计的失败样本驱动（CPG 状态混乱 ×3、joern println 契约 ×8、重复案件 ×2、结论未落地 ×2）。

| 模块 | 功能 | 命令 |
|------|------|------|
| `doctor.py` | 迁移健康检查（5 项：skill-tree/preset/schemas/toolchain/cache），FAIL 自带 fix 指引 | `python3 doctor.py` |
| `config.py` | 路径/env/工具链解析（零绝对路径，`VDH_PRESET`/`VDH_SCHEMAS`/`AUDIT_TOOLS_CACHE`/`VDH_SCRATCH` 可覆盖） | `python3 config.py` |
| `cpg.py` | CPG 生命周期：绝对 root 构建 + 缓存命中 + 干净 cwd + 查询模板（自动 println 包裹 + 空结果降级标记） | `python3 -m cpg build/query/clean` |
| `gate.py` | stage schema 门禁（quick-validate + casefile.py 权威校验） | `python3 -m gate --run-dir ... --stage ... --output ...` |
| `coverage.py` | 覆盖状态机（CHECKED/UNCHECKED → COVERED/INCOMPLETE/SKIPPED/NOT_FOUND）+ GAPFIL 队列 | `python3 -m coverage --input entries.json` |
| `ledger.py` | 案件账本封装（add 自动去重 / log 校验 case 存在 / list） | `python3 -m ledger --run-dir ... --op add --dedup-key ...` |
| `resilience.py` | 中间结论快照（长等待步骤前落盘，防"分析完毕结论未落地"） | `python3 -m resilience checkpoint/resume/done` |
| `queries/` | joern 查询模板（sinks/entry/error_deref，全部 println 强制） | `python3 -m cpg query --file queries/sinks.sc` |

**使用纪律（pipeline skill §Skills to load）**：`audit-runner` 每次运行前必加载；不用它的确定性过程不算"走流水线"——CPG 构建/查询、schema 门禁、覆盖统计、账本登记、中间快照必须经脚手架，判断（kill 税、边界、语义、PoC 设计）留在 agent。

**迁移指南（3 步）**：
```bash
# 1. 拷贝整个 skills/audit-runner/ 到新环境技能树
# 2. 按需 export VDH_PRESET / VDH_SCHEMAS / AUDIT_TOOLS_CACHE（默认路径不匹配时）
# 3. python3 doctor.py   # 5/5 全绿即就绪；FAIL 项有 fix 指引
```

## 目录结构

```
why-c-vulunerable/
├── agents/                  # c-harness, c-auditor, c-exploit, c-chain（c-tracer 已 ARCHIVED, 2026-08-21 并入 c-auditor）
├── skills/
│   ├── pipeline/SKILL.md    # 阶段机编排（代码审计版）+ 技能加载清单
│   ├── audit-runner/        # 迁移优先脚手架层（doctor/cpg/gate/coverage/ledger/resilience + queries/）
│   ├── audit-tools/SKILL.md # Joern/codebase-memory 硬封装
│   ├── code-audit/SKILL.md  # C/C++/Shell/Python CWE 方法论（替代 web-pentest）
│   └── tricks/SKILL.md      # 卡住时的思考框架 + kill 分类
├── schemas/                 # stage-finding/trace/validation/chain/report（CWE 语义）
├── extensions/              # audit-tools.py / case-context.ts
├── tools/                   # audit_log.py / sink_filter.py / denoise_rules.json
├── tests/                   # test-audit-tools.sh
├── install-c.sh             # 安装 agents 到独立命名空间（不覆盖原 xpi）
└── package.json             # 独立包名 pi-xpi-c
```
