# why-c-vulunerable

> C/C++/Shell/Python 静态代码审计流水线 · 面向本地源码，不编译目标、不打线上目标。
> 包名 `pi-xpi-c`，fork 自 `@xaccefy/pi-xpi`，将 Web 渗透语义替换为代码审计语义。

本项目把「探索 → 猎杀 → 可达性 → 验证 → 链式分析 → 报告」的完整审计流程固化为可复用的技能包：

- **验证靠本地 sanitizer**（ASAN / UBSAN / valgrind），不依赖目标项目可编译
- **分析引擎**：Joern（CPG，fuzzy 模式）+ codebase-memory-mcp（tree-sitter 图谱）
- **无重型第三方依赖**：不用 CodeQL，不依赖任何 Web 渗透工具（httpx/ffuf/nuclei 已移除）

## 特性

- 🔍 **RECON 目标本地化**：确定性枚举导出面（`exports`）、权限上下文（`pctx`）、威胁推导（`threats`），导出 API 即入口点
- 🎯 **HUNT 文件聚合分组**：按 `(class × file)` 派发，≤6 并发/轮，产出 finding + 可达性 trace 字段
- ✅ **VALIDATE 独立否证**：不盲信 HUNT，先独立走 entry→sink 链否证，再写自包含 repro + sanitizer 确认
- 🔗 **CHAIN + REPORT**：组合攻击链、CWE/CVSS 富化报告
- 📋 **LEDGER 台账**：casefile 案件登记、证据日志、可读报告
- 🧩 **无主-agent workflow 模式**：DSH `workflow` 驱动，主 agent 只持紧凑 JSON，消灭“会话长寿税”（实测主会话单轮从 29.3 万 tokens 降到 ~1 万量级）

## 快速开始

### 安装

```bash
cd ~/why-c-vulunerable

# 一键安装（推荐）：检测工具链 → 安装 agents → 注册 pi 包 → 验证
bash bootstrap.sh

# 可选参数
bash bootstrap.sh --check   # 只检查工具链与安装状态
bash bootstrap.sh --force   # 强制重新注册包
```

手动安装：

```bash
pi install /home/xvmo/why-c-vulunerable   # 方式一：本地路径安装
bash install-c.sh                          # 方式二：仅安装 agents（独立命名空间）
```

### 依赖环境

| 依赖 | 用途 | 检查 |
|------|------|------|
| joern / joern-parse / joern-scan | CPG 构建、污点查询、querydb 扫描 | `command -v joern` |
| codebase-memory-mcp | 全库图谱、调用链追踪 | `command -v codebase-memory-mcp` |
| audit-tools | Joern/codebase-memory 硬封装（禁裸 joern） | `command -v audit-tools` |
| audit-runner | 确定性编排层（CPG 生命周期/门禁/覆盖/台账/快照） | `python3 skills/audit-runner/doctor.py` |
| gcc/clang + valgrind | sanitizer 复现（VALIDATE 阶段） | `command -v gcc valgrind` |
| clangd（可选） | C/C++ 语义级验证；缺失时用 read/grep 兜底 | `command -v clangd` |

**不依赖**：CodeQL、目标项目编译能力、任何 Web 渗透工具。

## 使用方式

### 方式一：harness 对话式（简单）

安装后直接让协调器开猎：

```
对 ~/exploit-src/libsecurity1 跑一次完整代码审计流水线
```

### 方式二：workflow 无主-agent 流水线（推荐，完整审计）

`skills/workflow-audit/`（skill 名 `workflow-audit`）把同一套流水线改成 DSH `workflow` 驱动的三段式作业：

```
段1  audit-pipeline.js   RECON → HUNT → GAPFIL    → {findings[](含 trace 字段), coverage}
段2  validate.js         VALIDATE                 → {confirmed[], killed[], env_blocked[], unreachable[]}
段3  chain-report.js     CHAIN → REPORT → LEDGER  → {report, ledger}
```

调用方式：`read skills/workflow-audit/<段脚本>` → `workflow({meta, script: <内容>, args: {target, ...}})`。完整契约见 `skills/workflow-audit/SKILL.md`。

## 流水线阶段

```
RECON → HUNT(+可达性) → GAPFIL(循环) → VALIDATE → CHAIN → REPORT
  ↑___________________|                     |
  └────── FEEDBACK ────┘                   FIX (可选)
```

> TRACE 已并入 HUNT（2026-08-21）：HUNT 直接产出 finding + 可达性 trace 字段；VALIDATE 作为独立第二视角先否证再 PoC。

| 阶段 | 做什么 | 门禁 |
|------|--------|------|
| RECON | 入口点清单 + 工具链验证 + CPG 构建（fuzzy）+ 导出面/权限上下文/威胁推导 | 目标/工具链记录 |
| HUNT | 按 CWE 类 × 文件聚合审计；Joern 强制引擎；产出 finding + 可达性 trace | `stage-finding.json`（合并契约） |
| GAPFIL | INCOMPLETE 类补查（按入口点粒度） | 覆盖追踪 |
| VALIDATE | 独立否证 HUNT 可达性 + 自包含 repro + sanitizer 触发（不编译目标） | `stage-validation.json` + exit 0 |
| CHAIN | 已确认漏洞组合链（cwe_id/cvss） | `stage-chain.json` |
| REPORT | 报告富化（cwe_id / cvss_vector / cvss_score） | `stage-report.json` |
| LEDGER | casefile 案件台账落账（init / add / log / report） | — |

## 核心规则

1. **绝不编译目标项目**。只编译从目标提取的自包含 repro 文件。
2. **Joern/clangd 输出 = 候选**，每个 finding 必须 hop-by-hop 证据（entry → sink）。
3. **确认 = sanitizer 真实触发**（ASAN heap-buffer-overflow / UAF / valgrind invalid read…），不是静态推理。
4. **Shell 文件**走 codebase-memory + bash-language-server 通道（Joern 无 shell 前端）。
5. **导出即入口点**：导出契约 API 默认存在消费者，且消费者可能是高权限中介（全通纪律）。
6. 无 OOB、无限速、无 HTTP 探测 — 这是本地代码审计，不是 Web 渗透。

## 目录结构

```
why-c-vulunerable/
├── agents/                  # c-harness / c-auditor / c-exploit / c-chain（c-tracer 已 ARCHIVED，并入 c-auditor）
├── skills/
│   ├── pipeline/SKILL.md    # 阶段机编排（代码审计版）+ 技能加载清单
│   ├── workflow-audit/      # DSH workflow 无主-agent 流水线（RECON→HUNT→GAPFIL→VALIDATE→CHAIN→REPORT→LEDGER）
│   ├── audit-runner/        # 确定性编排层（doctor/cpg/gate/coverage/ledger/resilience + queries/）
│   ├── audit-tools/SKILL.md # Joern/codebase-memory 硬封装
│   ├── code-audit/SKILL.md  # C/C++/Shell/Python CWE 方法论
│   └── tricks/SKILL.md      # 卡住时的思考框架 + kill 分类
├── schemas/                 # stage-finding/validation/chain/report（CWE 语义）
├── extensions/              # audit-tools.py / case-context.ts / ledger-manager
├── tools/                   # audit_log.py / sink_filter.py / dupcheck.py / denoise_rules.json
├── tests/                   # test-audit-tools.sh
├── workflow/                # TASK-SUMMARY.md（流水线设计交接文档）
├── bootstrap.sh             # 一键安装
├── install-c.sh             # 仅安装 agents
├── package.json             # pi 包声明（pi-xpi-c）
└── LICENSE                  # MIT
```

## 相关文档

- `skills/workflow-audit/SKILL.md` — 无主-agent 流水线完整契约与踩坑记录
- `skills/audit-runner/` — 确定性编排层文档（doctor.py 自带健康检查与 fix 指引）
- `workflow/TASK-SUMMARY.md` — 流水线设计交接文档

## License

[MIT](LICENSE)
