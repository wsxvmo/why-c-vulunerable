---
name: codeaudit-pipeline
description: Full pipeline orchestration skill for C/C++/Shell/Python source code audit. Teaches the c-harness agent how to run stages with state tracking, schema validation, reachability trace, gapfill, and structured reporting. No compilation of the target required; no CPG/CodeQL dependency.
---

# Pipeline Orchestration Skill

## Skills to load (before orchestrating, 必读)

| Skill | 作用 | 加载时机 |
|---|---|---|
| **`audit-runner`** | **确定性编排层（本流水线的工具底座）**: `doctor.py`（迁移健康检查）、`cpg.py`（CPG 生命周期+查询模板）、`gate.py`（schema 门禁）、`coverage.py`（覆盖状态机+GAPFIL）、`ledger.py`（账本去重）、`resilience.py`（中间结论快照） | **每次运行前必加载**（RECON 之前） |
| `code-audit` | 每 CWE 类方法论：checklist / detection / confirmation / false-positive elimination | HUNT/GAPFIL 派发前 |
| `audit-tools` | Joern/codebase-memory 硬封装（禁裸 joern） | HUNT/VALIDATE 引擎调用时 |
| `tricks` | 卡住时的思考框架、kill 分类、证据质量阶梯 | 任意阶段陷入困境时 |
| `c-harness` / `c-auditor` / `c-exploit` / `c-chain` | 流水线角色简报（`c-tracer` 2026-08-21 并入 `c-auditor`，标 ARCHIVED） | 对应阶段派发子代理前 |

> 铁律：**不用 audit-runner 的确定性过程不算"走流水线"** —— CPG 构建/查询、schema 门禁、覆盖统计、账本登记、中间快照必须经 `doctor.py`/`cpg.py`/`gate.py`/`coverage.py`/`ledger.py`/`resilience.py`，手工重做一遍不产生额外覆盖，只增加错误面（本次审计的失败样本: CPG 状态混乱 ×3、println 契约 ×8、重复案件 ×2、结论未落地 ×2）。

## Stage Machine

```
RECON → HUNT(+reachability) → GAPFIL(loop) → VALIDATE → CHAIN → REPORT
  ↑___________________|                          |
  └────── FEEDBACK ────┘                          |
         (traces into new hunts)                  |
                                                  ↓
                                            FIX (optional)
```

> **2026-08-21**：TRACE 阶段已并入 HUNT —— auditor 直接产出 finding + 可达性 trace 字段；VALIDATE 负责独立否证 + PoC。本 skill 是 legacy 编排参考，实际运行以 `skills/workflow-audit`（无主-agent 三段式）为准。

Finish coverage (hunt + gapfill) before spending validation budget. Validate only the REACHABLE hypotheses that survived a complete hunt.

Each stage produces a structured output. The next stage validates it before starting. If validation fails, the stage retries with repair guidance.

## Prerequisites — check before starting a run

The pipeline assumes the target codebase is **in scope** and the toolchain is available. Before dispatching the first auditor, verify:

1. **Target is defined.** Record the repo path + language distribution in the pipeline-run case `target` + `assumptions`. Every analysis must stay inside this codebase.
2. **Toolchain is present.** Static analysis relies on `codebase-memory-mcp` (graph) + `grep`/`read` + `audit-runner`. Sanitizer validation relies on `gcc`/`clang` with `-fsanitize=address,undefined`, `valgrind`. Run `audit-runner doctor` at run start — 5 项健康检查（skill-tree/preset/schemas/toolchain/cache），FAIL 项自带 fix 指引。Record what's available.
3. **Joern is available.** The pipeline uses Joern (fuzzy mode, no compilation needed) as a mandatory analysis engine for HUNT (joern-scan querydb + taint propagation queries; TRACE 已并入 HUNT). doctor.py 的 toolchain 检查覆盖 `joern joern-parse joern-scan audit-tools codebase-memory-mcp`。If missing, ask the user before starting.
4. **Target indexed in codebase-memory-mcp.** Run `codebase-memory-mcp cli index_repository --repo-path <target>` (with extension-completion pre-step for extensionless files) if not already indexed. Record the project name. CPG 构建用 `audit-runner cpg build --root <abs-target>`（绝对 root + 显式输出 + 缓存命中 + 干净 cwd）。
5. **Input surface identified.** Enumerate entry points in RECON **with a graph, not by hand** — hand/grep enumeration is the #1 source of blind spots (missing submodules → INCOMPLETE coverage). 首选 **codebase-memory 图**（索引可用性由 doctor.py 第 7 项判定）; 索引不可用时**文档化回退 joern CPG 图**（cpg.py query + queries/entry.sc）。两种都是图基枚举; 工具分层: RECON 用 codebase-memory 找攻击面, HUNT/TRACE 用 joern 深挖 sink/污点。Use codebase-memory queries to get the full candidate list, then confirm semantics with the model:
   ```bash
   # 未被任何函数调用的 Function = 入口候选（main/回调/导出/信号/dbus 注册）
   codebase-memory-mcp cli search_graph --project <proj> --label Function \
     --exclude-entry-points false
   # 按安全敏感命名模式发现回调/处理器/分发器
   codebase-memory-mcp cli search_graph --project <proj> --name-pattern \
     "(handle_|on_|dispatch_|callback|vtable|signal_|process_|parse_|recv|accept).*" --label Function
   # 按语言入口模式（C: main; Rust: fn main/fn run; Python: __main__/routes; Shell: 顶层调用）
   ```
   For each candidate the model confirms semantics (dbus registration / socket callback / export table / exec entry / signal handler) and records the confirmed entry-point list in the pipeline-run case. The graph gives completeness; the model gives semantics.
6. **Privilege context recorded.** Is the target setuid? runs as root? system daemon? This determines how deep `privilege-mgmt` / `permission-assignment` hunting goes.
7. **tricks 经验注入（前馈, 必做）.** 按目标类型从 `skills/tricks/SKILL.md` 的"章节→适用场景映射"选择相关章节, 提炼成 ≤200 字经验注入块（格式见 tricks §使用方式）, 前置到**每个**派发的 auditor 提示词开头（TRACE 已并入 HUNT, 2026-08-21）。目的: 子代理开局即带方向感（身份可伪造性/补丁兄弟漏修/否证纪律）, 而非卡住才自救。这是把历史复盘沉淀的经验在 RECON 阶段前馈注入 — 经验库(tricks) → RECON 选择 → 注入块 → 子代理。

**No compilation of the target is required or assumed.** The target may not build (missing deps, cross-compile). Static analysis (codebase-memory + clangd) and Joern fuzzy parsing never compile the target. Sanitizer repros (VALIDATE) compile only self-contained PoC files extracted from the target — never the full project.

**No out-of-band channel, no rate limits, no auth tokens, no HTTP probing.** This is a local code audit pipeline, not a web pentest.

If any prerequisite is missing, record it in the pipeline-run case and either ask the user or scope the run to what's possible.

## Stage Config

Each stage has:
- **model** — which model class to dispatch on (hunt = standard + reachability, validate = different/stronger than hunt for deliberate disagreement; tracer 已并入 HUNT)
- **tools** — what tools the agent gets (trace has no write tools)
- **output schema** — what shape the stage must emit
- **max_turns** — when to terminate a stuck agent
- **concurrency** — how many parallel agents to run

## State Tracking via Casefile

Track pipeline state in the casefile ledger (engine `casefile.py`, wrapper `ledger.py` — 用 wrapper 自动去重/校验 case 存在). 流水线运行案件在 `casefile.py init` 时建立:

```
casefile.py init <run-dir> --title "Pipeline: <target> <timestamp>" --target "<target>"
```

Record per-stage progress:
- 发现登记: `audit-runner ledger --run-dir <run-dir> --op add --title "<short>" --bug-class <class> --dedup-key <kw>` (自动去重, 防重复案件)
- 状态推进: `casefile.py update <run-dir> <case-id> --status ... --field key=value`
- 证据留痕: `audit-runner ledger --run-dir <run-dir> --op log --case-id <id> --stage <S> --verdict <V> --evidence "<one-line>"` (自动校验 case 存在)
- 中间结论快照: `audit-runner resilience checkpoint --run-dir <run-dir> --case <id> --stage <S> --summary '<one-line>'` — 长等待步骤前必做, 防"分析完毕结论未落地"
- `nextStep: "stage: recon complete, findings: 3, moving to validate"` after each stage (run.json)
- `assumptions: ["COVERED: buffer-overflow, use-after-free | SKIPPED: unsafe-deserialization | NOT_FOUND: command-injection"]` for coverage (由 `coverage.py` 状态机产出)

This gives you resume capability: on restart, `casefile.py list <run-dir>` + `resilience.py resume` shows previous runs and their last recorded stage.

## Schema Validation at Stage Boundaries

Every stage output must conform to its schema before the next stage begins. **用 `audit-runner gate --run-dir <run-dir> --stage <finding|trace|validation|chain|report> --output <output.json>` 校验** — quick-validate（必需字段独立检查）+ casefile.py validate（权威门禁）。

### Stage Schemas (in `schemas/`, 路径由 audit-runner/config.py 解析):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `schemas/stage-finding.json` | vuln_class, language, file, line, sink, entry_point, confidence, evidence |
| **TRACE** | `schemas/stage-trace.json` | trace_result, entry_point, call_chain, data_flow, defenses_checked, attacker_model |
| **VALIDATE** | `schemas/stage-validation.json` | finding_id, status, technique_used, detection_method |
| **CHAIN** | `schemas/stage-chain.json` | chains[], summary |
| **REPORT** | `schemas/stage-report.json` | target, pipeline_status, findings, coverage, summary |

**Validation procedure:**
```
1. audit-runner gate --run-dir <run-dir> --stage <stage> --output <output.json>
2. QUICK-PASS + AUTHORITATIVE exit=0 → 通过; 否则回退给产出代理修复
3. 若缺字段/畸形 → 回退: "Your output is missing: <fields>. Please fix."
4. Re-validate after repair. Max 2 repair attempts per stage.
```

If the agent cannot produce valid output after 2 repair attempts:
- Record the stage state as `failed` in the pipeline-run case
- Log the failure reason
- Decide: skip to next stage? retry with different agent? abort?

## Agent Dispatch Patterns

### HUNT: One auditor per CWE class × language

**HUNT analysis MUST be dispatched to c-auditor subagents. The harness NEVER performs hunt analysis itself.** This is not a suggestion — it is a hard rule with no exceptions and no judgment call:

- Every CWE class / subsystem is assigned to a `subagent({agent: "c-auditor", ...})` dispatch.
- The harness's own `read`/`grep`/`bash` tools are for **orchestration only**: RECON, schema validation, coverage bookkeeping, result review. They are never used to hunt.
- There is NO "codebase is small" / "value is concentrated" / "I can do it faster inline" exemption. If you believe an exemption is warranted, dispatch the auditor anyway and record the reasoning in the pipeline-run case — the user decides, not you.
- A HUNT that was performed inline (by the harness) is not a valid HUNT. Coverage cannot be marked COVERED/NOT_FOUND based on inline work.

Spawn multiple auditor agents concurrently, one per CWE-family class (grouped by language where useful):

```
Spawn multiple auditor agents concurrently:
  subagent({agent: "c-auditor",
    task: "[RECON 经验注入 · 来自 tricks] <按目标类型选取的注入块>
           Hunt for <cwe-class> vulnerabilities in <target/subsystem>. ..."})
```

> 注入块在 RECON 阶段生成（pipeline §Prerequisites-7），每个派发任务必须前置；不要省略——它是历史复盘经验进入本轮审计的唯一通道。

Suggested class partitions (adjust to target's language mix):
- C/C++ memory safety: buffer-overflow, out-of-bounds-read, use-after-free, double-free, integer-overflow, null-deref, uninitialized-use, format-string
- C/C++ injection & paths: command-injection, path-traversal, symlink-follow, unsafe-temp-file
- Privilege & access (C/C++ setuid/daemons, DBus services): access-control, privilege-mgmt, permission-assignment
- Shell: shell-injection, command-injection, path-traversal, unsafe-temp-file, race-condition
- Python: eval-injection, unsafe-deserialization, command-injection, path-traversal, race-condition
- Cross-cutting: toctou, race-condition, resource-leak, memory-leak, crypto-weakness, info-disclosure

**Every auditor MUST run the Joern engine as part of hunting** (经 audit-runner/audit-tools, 禁止裸 joern):
```
# 1. Build CPG once per target (fuzzy mode — no compilation of the target):
audit-runner cpg build --root <abs-target>          # 绝对 root; 缓存命中; 干净 cwd
# 2. Run the querydb sweep (100+ built-in CVE queries):
audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>
# 3. For the assigned class, run targeted queries (模板在 skills/audit-runner/queries/):
audit-runner cpg query --cpg <cpg> --file queries/sinks.sc --timeout 240
#    println 已强制; 空结果(仅 INFO 行) → 转 grep 兜底, 不重试白等
# Joern output = candidate list. Every candidate still needs read/grep 逐跳验证
# + evidence — Joern never confirms anything by itself.
```
Joern candidates that survive `clangd`/read verification become hypotheses. Joern-only hits that cannot be verified semantically are dropped or marked low confidence.

> **2026-08-21（TRACE 并入 HUNT）**：每个 auditor 对每个 emitted finding 必须额外产出可达性 trace 字段（`trace_result`、`call_chain`、`data_flow`、`defenses_checked`、`reachability_basis`，以及条件 `impact_if_reachable`/`unreachable_reason`），契约见 `schemas/stage-finding.json`。导出契约入口（无树内调用方的 intended/accidental 导出）默认 `REACHABLE`/`export-contract`。独立的 TRACE 阶段已删除。

Coverage rule: check at least 3 entry points per class. After all auditors return, aggregate coverage. Coverage is per-entry-point, not a single tri-state — a class is only `NOT_FOUND` when every entry point identified in recon was actually examined:
```
COVERED:    class examined across all identified entry points (≥1 hypothesis OR each entry point ruled out with reason)
INCOMPLETE: class examined partially — some entry points never checked (stays in gapfill)
SKIPPED:    class not applicable (no surface, documented why)
NOT_FOUND:  class examined across ALL entry points and produced zero hypotheses (only when no entry point is unchecked)
```
A class with any unchecked entry point is `INCOMPLETE`, never `NOT_FOUND`. `INCOMPLETE` classes stay in the gapfill loop until every entry point is checked or explicitly ruled out.

### HUNT: Algorithm validation

For functions containing loops with string/array manipulation (especially with multiple index variables like `i`, `j`, `p`, `q`), do not rely on static reading alone. Run quick input-output tests:

```bash
# 提取关键逻辑，编译执行，验证三组输入输出
# 不需要完整项目编译 — 只需要复制出循环体 + 测试数据
echo '#include <stdio.h>
...' | gcc -x c - -o /tmp/quick_test && /tmp/quick_test
```

Checklist:
1. Identify all functions with loops + ≥2 index variables
2. For each, prepare 3 input-output pairs (normal, edge, invalid)
3. Run test — if actual ≠ expected, it's a logic bug
4. Document the test in the finding's `poc` field

### HUNT: Loop multi-variable tracing rule

Any loop with two or more independently-managed index variables (`i`/`j`, `p`/`q`, `read_idx`/`write_idx`, etc.) risks index desynchronization causing buffer holes, overlaps, or truncation.

**Mandatory procedure before marking a finding NOT_FOUND:**

1. Trace at least 5 iterations manually (on paper or in comments), recording every variable change
2. Verify that every write to a buffer is matched by a corresponding index advance
3. Verify that every skip/mismatch branch also preserves index consistency
4. If the trace reveals an off-by-one or null-byte hole → it's a finding

```c
// Example trace format for security_config_module_remove loop:
// i=0,j=0 → write 'k' → i=1,j=1
// i=1,j=1 → write 'y' → i=2,j=2
// ...
// i=5,j=5 → skip ',' (no write!) → i=6,j=6  ← j advanced, value[5] stays 0!
```

\`\`\`
COVERED:    class examined across all identified entry points (≥1 hypothesis OR each entry point ruled out with reason)

### TRACE: ARCHIVED (2026-08-21, 已并入 HUNT)

**独立的 TRACE 阶段已删除。** 可达性证明现在是 `c-auditor` 的职责：HUNT 输出 finding 时直接携带 `trace_result/call_chain/data_flow/defenses_checked/reachability_basis`（见 `schemas/stage-finding.json` 合并契约）。导出契约入口默认 `REACHABLE`（`reachability_basis=export-contract`）。

保留给补丁重攻击/legacy 参考：若要派独立可达性复核，可用 `agents/tracer.md`（已标 ARCHIVED）配合 `schemas/stage-trace.json`。VALIDATE（`c-exploit`）现在是流水线的独立第二视角：必须独立挑战 HUNT 的可达性判定（disconfirmation-first），再写确认 PoC。

Only findings with `trace_result: REACHABLE` advance to exploit.

### VALIDATE: One agent per REACHABLE finding

```
For each reachable finding:
  subagent({agent: "c-exploit", task: "Phase 1: EXPLOIT"})
  Run through PromoteFinding.
```

**Validation = local repro + sanitizer, never a live target:**
```
# Exploit agent writes a SELF-CONTAINED repro (extracted from the target, not the whole project):
#   C/C++:  gcc -fsanitize=address,undefined -g repro.c -o repro && ./repro
#   Python: python3 repro.py (or pytest)
#   Shell:  bash repro.sh with deterministic input
# Confirmation = sanitizer/runtime error pointing at the sink:
#   ASAN heap-buffer-overflow / use-after-free / valgrind invalid read / UBSAN shift exponent
# Record build_config + sanitizer_result in the validation output.
# The target project itself is NEVER compiled. Compiling the self-contained repro is allowed.
```
**Disconfirmation is mandatory, not optional:** every hypothesis must have a written disconfirmation path — a script or deterministic argument that tries to prove the trigger CANNOT fire (reachability failure, kernel/LSM hook order, language semantics, existing equivalent mechanism, already-fixed version).
- Write the disconfirmation BEFORE the confirmation PoC where possible (it is cheaper).
- `PromoteFinding` must be called with a `disconfirmation_path`; if the disconfirmation exits 0 (finding disproven), the promotion is blocked — record the result as KILL-5 disproven.
- A validation that only ever tries to confirm, never to disprove, is not a validation — it is confirmation bias.

Sanitizer repros run through `PromoteFinding` in the sandbox (exit 0 = triggered). If the language/class cannot be repro'd locally (e.g. needs hardware, kernel, or network peer), record the finding as `INCOMPLETE: blocked: no sanitizer trigger` — do not kill it.

### GAPFIL: Re-queue INCOMPLETE classes (targeted at the gap)

```
For each CWE class with "INCOMPLETE" coverage:
  audit-runner coverage --input <auditor-entries.json>   # 生成 GAPFIL 队列（含 CHECKED 列表）
  subagent({agent: "c-auditor",
    task: "Hunt for <class> in <target>. Previous hunts found nothing.
             These entry points are ALREADY CHECKED — do not re-tread them: <checked list>.
             These entry points are UNCHECKED — examine each one: <unchecked list>.
             Query the local CWE pattern library (skills/code-audit/SKILL.md) for this class."})
```

The loop terminates when every class is COVERED, SKIPPED, or NOT_FOUND (i.e. zero `INCOMPLETE` remain), or after 2 iterations as a safety cap. Do NOT freeze a class as `NOT_FOUND` while unchecked entry points remain — if the cap hits with `INCOMPLETE` classes, report them as `INCOMPLETE` in coverage, not `NOT_FOUND`.

### FEEDBACK: Convert traces into new hunt tasks

```
For each TRACE that revealed a new attack surface (a subsystem touched by the call chain
that wasn't previously audited):
  subagent({agent: "c-auditor", task: "Audit this subsystem: <subsystem>. The trace revealed it as untested attack surface."})
```

## Coverage Tracking

Coverage is the pipeline's self-check. It answers: "what did we actually test vs what did we skip or miss?"

After the hunt + gapfill stages, emit a coverage summary in the pipeline-run case. **把各审计代理的 CHECKED/UNCHECKED 条目喂给 `audit-runner coverage --input <auditor-entries.json>`**（状态机: UNCHECKED 空+有假设 → COVERED; UNCHECKED 非空 → INCOMPLETE; 空+0 假设 → NOT_FOUND; 显式 reason → SKIPPED）:

```
auditor entries (每代理一行):
  {"cls": "buffer-overflow", "checked": ["main","recv"], "unchecked": ["cfg-parser"],
   "hypotheses": 1}
coverage.py 输出:
  覆盖状态 + GAPFIL 队列（INCOMPLETE 类带 checked 列表, 直接喂 gapfill 派发）
```

This feeds the gapfill loop. `INCOMPLETE` classes get re-queued with their unchecked list. `NOT_FOUND` is only valid when no entry point is unchecked.

## Dedup

Before running trace or validation, deduplicate hypotheses:

1. **Trivial dedup** (no model call): same file + vuln_class + lines within 10 = same finding. Keep the earlier one, kill the later.
2. **Semantic dedup**: if two findings describe the same root cause from different entry points, keep the one with the shorter/simpler attack path.

### LIVE-VALIDATE: optional end-to-end confirmation (before CHAIN/REPORT)

Static + sanitizer confirmation is the baseline. When the target environment is reachable (test VM, dev machine, staging), an optional LIVE-VALIDATE stage sharply raises report credibility and vendor acceptance. It is OPTIONAL — never block the pipeline on it; if the environment is unavailable, report with the sanitizer evidence only and note live confirmation as pending.
```
For each CONFIRMED finding (or the top-severity subset):
  subagent({agent: "c-exploit",
    task: "On the live environment, run the real end-to-end trigger
           (dbus-send, crafted input, real binary) and capture:
           (1) the actual system artifact (file written, output, crash log),
           (2) before/after state, (3) cleanup."})
```

Rules:
- The live run proves the REAL BINARY path, not a self-contained repro — record which binary/version/service was exercised and that it matches the audited build.
- Prefer evidence that survives scrutiny: real file contents, return codes from the real service, kernel logs — not script-printed success.
- When the chain is local-user → root, show the unprivileged trigger actually succeeding.
- Clean up all test artifacts afterwards (VM snapshot restore, temp files, injected policy).
- Record results in the finding (evidence field) as `LIVE CONFIRMED` / `LIVE NOT-TRIGGERED`; a live failure does NOT automatically kill a sanitizer-confirmed finding — investigate why (environment mismatch, wrong version) before deciding.

## Run Artifacts: 证据链留痕（casefile log + resilience checkpoint）

人工可追溯 ≠ 过程重放。留 **L1 决策证据**（能验证结论的），留 **L2 现场指针**（大块输出只存路径），删 **L3 过程噪音**（推理/被否候选/重复查询）。

**每 stage 结束时追加一条 `ledger.py log`**（机器调用，不是模型写报告；自动校验 case 存在）：

```bash
audit-runner ledger --run-dir <run-dir> --op log --case-id <case-id> --stage <STAGE> \
    --verdict <REACHABLE|UNREACHABLE|CONFIRMED|KILL-1..5|finding> \
    --evidence "<一句话证据，file:line → sink>" \
    [--artifact <L2 指针路径>] [--agent <agent名>]
```

**长等待步骤前（CPG 构建/后台 job/子代理派发）先落盘中间结论**（防"分析完毕结论未落地"式失败）:

```bash
audit-runner resilience checkpoint --run-dir <run-dir> --case <case-id> --stage <STAGE> \
    --summary '<one-line 可验证结论>'      # resume 列出全部快照
```

**各 stage 留什么 / 不留什么：**

| Stage | L1 留（写 evidence） | L2 留指针（artifact） | L3 删（不写） |
|---|---|---|---|
| HUNT | file:line, sink, entry, 证据一句话 | joern 查询原文（如需） | 模型推理过程、被否候选 |
| TRACE | entry→hop→sink 路径摘要, 每跳验证方式 | 完整 data_flow JSON | 每跳代码片段全文 |
| VALIDATE | exit code, sanitizer 类型, PoC 路径 | 完整 ASAN/valgrind 输出 | 多次试错的中间版本 |
| KILL | KILL-x 编号 + 一句话原因 | 否证脚本路径 | 失败尝试清单 |
| CHAIN | 链步骤 + 每步依赖 | 链推理 JSON | 备选链分析 |

**判断标准**：这个细节"能验证某条结论"就留；只是"记录我做过"就删。~200B/条，一个 case 全程 20-40 条 ≈ 4-8KB，不膨胀。

查看：`audit-runner ledger --run-dir <run-dir> --op list`（案件时间线）或 `python3 /home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py logview <run-dir> <case-id>`。

### CHAIN: One agent per pipeline run

After all validations pass, spawn the chain analyst:

```
subagent({agent: "c-chain",
  task: "Analyze confirmed findings for pipeline run <pipeline-case-id>.
           Tag: <pipeline-tag>. Target: <target>.
           Find exploit chains across ALL confirmed findings.
           Prefer local-privilege-escalation chains (e.g. info-disclosure + buffer-overflow in setuid binary)."})
```

Validate chain output against `schemas/stage-chain.json`:
- Must have chains[] with title, severity, steps, narrative
- Each chain must have ≥2 steps
- chains carry cwe_id + cvss_vector + cvss_score (KVE template fields)
- Record chains in casefile via CaseLink

If chain analysis fails, don't block the pipeline — emit report without chains.

## Report

Final output must conform to `schemas/stage-report.json`. Required coverage and findings arrays.

Each finding in the report carries: vuln_class, language, cwe_id, cvss_vector, cvss_score, poc_path, severity. The cwe_id/cvss fields map directly to the KVE report template (见 preset 报告要求)。

## Token Tracking

After each subagent completes, record token usage in the pipeline-run case:

```
casefile.py update <run-dir> <pipeline-case-id> --field nextStep="stage: <stage> complete — <n> findings tokens: <input> in / <output> out"
```

Target token budgets per stage (cumulative input+output):
- HUNT: ~50K tokens per class
- TRACE: ~20K per finding
- VALIDATE: ~30K per finding (exploit phase)
- CHAIN: ~20K total
- PATCH: ~40K per finding

If any single agent exceeds 200K tokens, consider it stuck and terminate.

### Turn Budgets

Set turn budgets on subagent calls to prevent runaway agents:

```
subagent({agent: "c-auditor",
  task: "...",
  turnBudget: {maxTurns: 20, graceTurns: 2}})
```

| Agent | maxTurns | notes |
|-------|----------|-------|
| auditor | 20 | 25 with gapfill；含可达性证明（TRACE 已并入） |

### Task sizing (hard lesson from production runs)

Subagent tasks that run > 8-10 minutes get interrupted (user Esc / message arrival aborts the whole dispatch via AbortSignal → SIGTERM, extension `subagent/index.ts:413`). This is NOT a timeout — it is session interruption. **Keep every dispatched task under ~3 minutes of work:**

1. **One CWE class per auditor dispatch** — never bundle 3+ classes into one task. If a class has many entry points, split by entry point ("audit recv handler only", "audit config parser only").
2. **Prove timing before parallelizing** — run ONE c-auditor on a small slice first, measure, then decide concurrency (parallel dispatch multiplies wall-clock, not latency).
3. **并发上限 6** — 一次最多同时派 6 个子代理（实测: 12 核/7.7GB 机器上 6 并发 ≈ 1.7GB 峰值 JVM RSS 且耗时 37s; 8+ 并发 CPU 抢核收益递减、内存线性涨至 ~4.3GB）。>6 个任务分两批（先 6 后补）。
3. **Cap per-task scope explicitly in the task text**: "examine at most 3 entry points, then emit INCOMPLETE with the unchecked list" — the auditor's exhaustion contract already caps at 8.
4. **Never hunt inline** — the coordinator's own read/grep tools are for orchestration only (see HUNT hard rule). Even a 200-line file gets a c-auditor dispatch; the dispatch is the audit, and inline work is not valid coverage.
5. **Never dispatch without turnBudget** — a missing budget means the subagent runs until the model decides to stop, which is exactly the 9-10 min window that gets aborted.
| exploit (phase 1) | 15 | PoC writing + refine |
| exploit (phase 2) | 20 | patch + verify + re-attack |
| chain | 8 | lightweight analysis |
