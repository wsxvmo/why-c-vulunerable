---
name: workflow-audit
description: Leaderless C/C++/Shell/Python code audit pipeline driven by the DSH workflow tool. Use for full-pipeline audits (RECON→HUNT→GAPFIL→TRACE→VALIDATE→CHAIN→REPORT) that must NOT hold a long-lived coordinator session — the script audit-pipeline.js is read from disk and passed as the workflow script parameter each call, every stage runs as a fresh workflow subagent, and the caller only holds compact JSON between segments. Keeps all audit discipline (audit-runner/audit-tools enforcement, schema gates, sanitizer confirmation) from skills/pipeline (codeaudit-pipeline) while eliminating the coordinator's session-longevity token tax.
---

# workflow-audit — DSH workflow 无主-agent 审计流水线

## 何时用 / 何时不用

**用**：对完整目标跑全流水线审计（RECON→HUNT→GAPFIL→TRACE→VALIDATE→CHAIN→REPORT）。主 agent 只发一次 `workflow` 调用、只持有紧凑 JSON 中间产物；各阶段在**新鲜上下文的子 agent** 中执行，不共享会话历史。

**不用**：单文件/单函数快速判断（直接 read/grep 或普通 subagent 即可）；两三个 agent 能解决的小任务（workflow 是重编排工具）。

## 为什么存在（背景）

原 `skills/pipeline`（codeaudit-pipeline）是层级式：主 agent（c-harness）活过 7 阶段 × 60+ 轮，每轮重发全部会话历史——实测 32.1M tokens 中 **31.8M 是 cacheReadTokens 的"会话长寿税"**，真实分析成本仅 1.5M。改造目标：调度/状态/校验/汇总等确定性逻辑搬进 workflow 脚本（0 token），LLM 只花在判断上。

## 三段式（每段 = 一次 workflow 调用）

```
段1 workflow: RECON → HUNT → GAPFIL          ← audit-pipeline.js（v1 已实现）
     ↓ return {findings[], coverage}          ← 主 agent 过目/干预点
段2 workflow: TRACE → VALIDATE               ← trace-validate.js（v2 已实现）
     ↓ return {confirmed[], killed[]}
段3 workflow: CHAIN → REPORT                 ← chain-report.js（v2 已实现）
     ↓ return {report}                       ← 最终交付
```

> 合并而非一阶段一段的原因：脚本内 JS 变量传递阶段产物 = 0 token；拆成独立调用则每段数据要穿过主 agent 中转，确定性编排税重新出现。分三段保留 3 个可中断/可续跑/可人工干预的检查点。

## Model 分层（deliberate disagreement）

workflow 的 `agent(prompt, {model})` 支持 per-agent 模型覆盖（plain subagent 做不到）。默认分层（可经 `args.models` 覆盖，见下）：

| 阶段 | 默认模型 | 理由 |
|---|---|---|
| HUNT | deepseek-v4-flash | 标准模型，广撒网 |
| TRACE | deepseek-v4-pro | 更强模型做逐跳验证 |
| VALIDATE | deepseek-v4-pro | 与 HUNT 不同，避免共享盲点 |
| CHAIN/REPORT | deepseek-v4-flash | 轻量分析 |

## 调用方式（段1）

主 agent 每次调用前 **read 脚本文件**，内容作为 `script` 参数传入：

```
1. read skills/workflow-audit/audit-pipeline.js      # 拿到脚本全文
2. workflow({
     meta: {name: "code-audit-segment1",
            description: "RECON→HUNT→GAPFIL 审计段1",
            phases: [{title:"recon"},{title:"hunt"},{title:"gapfill"}]},
     script: <脚本全文>,
     args: {
       target: "<目标源码绝对路径>",
       runDir: "<产物目录, 建议 workspace/runs/<名>-<时间戳>>",   // 可选
       skillRoot: "/home/xvmo/why-c-vulunerable",                // 可选
       classes: ["buffer-overflow", "command-injection"]         // 可选, 跑通后扩展
     }
   })
3. 把返回值中的 findings/coverage 落盘（如 workspace/runs/<名>/segment1.json），
   供段2/段3 或人工过目使用
```

**args 契约**：

| 键 | 必填 | 说明 |
|---|---|---|
| `target` | ✅ | 目标源码绝对路径 |
| `runDir` | 可选 | 子 agent 写产物的目录；默认 `${skillRoot}/workspace/runs/audit-<名>` |
| `skillRoot` | 可选 | 本仓库根；默认 `/home/xvmo/why-c-vulunerable` |
| `classes` | 可选 | 段1：CWE 类列表；默认 `["buffer-overflow","command-injection"]`，跑通后按 code-audit 章节扩展 |
| `findings` | 段2 必填 | 段1 返回的 `findings[]`（脚本自动分配 id F1..Fn） |
| `cpg_path` | 段2 必填 | 段1 recon 构建的 CPG 路径 |
| `confirmed` | 段3 必填 | 段2 返回的 `confirmed[]` |
| `coverage` | 段3 可选 | 段1 返回的 `coverage[]`，补进报告 |
| `models` | 可选 | `{hunt?, trace?, validate?, chain?, report?}` 模型覆盖 |

### 段2/段3 追加契约

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| TRACE | parallel, 每 finding 1 个（KILL 税前置内置） | ≤6 并发 | 每 finding `{finding_id, trace_result: REACHABLE\|UNREACHABLE\|KILLED, entry_point, call_chain[], data_flow, defenses_checked[], attacker_model, impact_if_reachable?, unreachable_reason?, kill_reason?}` |
| VALIDATE | parallel, 每 REACHABLE finding 1 个（否证优先 + sanitizer） | ≤6 并发 | 每 finding `{finding_id, status: confirmed\|killed, technique_used, detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?, kill_reason?}` |
| CHAIN | 1 个 agent（仅 confirmed>0 时） | 1 | `{chains[], summary}` |
| REPORT | confirmed>0 时 1 个 report agent 补 CVSS；否则纯脚本聚合 | 0-1 | `{findings[], summary}` |

**脚本内条件门禁**（段2）：confirmed → poc_path/run_log/evidence_extracted 必填；killed → kill_reason 必填；不合格 repair ≤2 次重派。

## 段1 阶段契约

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| RECON | 1 个 agent | 1 | `{languages, entry_points[], cpg_path, toolchain, assumptions[]}` + `runDir/recon/recon.json` |
| HUNT | parallel, 每 CWE 类 1 个 | ≤6 并发 | 每类 `{cls, findings[], checked[], unchecked[], notes?}` + `runDir/hunt/<cls>/` |
| GAPFIL | 最小循环（对 INCOMPLETE 类补查 1 轮） | ≤6 并发 | 同上（替换原结果） |

**finding 必填字段**（与 `schemas/stage-finding.json` 对齐）：`vuln_class, file, line(整数), sink, entry_point, confidence(low|medium|high), evidence(entry→sink)`。

**脚本内门禁**：`agent()` schema 只校验子集（type/properties/required/items/enum），深度校验（字段缺失、line 非整数、条件必填）在脚本聚合段做，不合格的 finding 列入 `gate.invalid` 返回，不静默丢弃。

## 纪律块（每个 agent prompt 内置, 与 pipeline skill 一致）

1. **绝不编译目标项目**；只用 read/grep/静态查询/CPG。
2. **禁裸 joern / codebase-memory**，必须经封装（分工见下）。
3. 空结果（仅 INFO 行）→ 转 grep 兜底，不重试白等。
4. 产物写 runDir 对应子目录。
5. 自限：单 agent 最多查 3 个入口点，超出列入 `unchecked` 交回。

### 工具分工（audit-runner 与 audit-tools 是分层关系，不是重复）

| 用途 | 命令 | 归属 |
|---|---|---|
| CPG 构建 | `audit-runner cpg build --root <abs>` | audit-runner（底层调 audit-tools，加产物验证/缓存） |
| CPG 目标查询 | `audit-runner cpg query --cpg <cpg> --file <q.sc>` | audit-runner（println 强制/干净 cwd/空结果降级） |
| querydb 全库扫描 | `audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>` | 仅 audit-tools 有 |
| codebase-memory | `audit-tools cli codebase_query --tool <t> <args...>` | 仅 audit-tools 有 |

audit-runner 不在 PATH 时用绝对路径 `/home/xvmo/.local/bin/audit-runner`。

## 验收标准（对齐 workflow/TASK-SUMMARY.md）

- [x] `skills/workflow-audit/` 存在，SKILL.md 可读
- [x] `audit-pipeline.js` 语法通过（引擎同款 async 包装 node --check）
- [x] 段1 冒烟跑通：ksaf-dynamic-uid 3 agent 全通，gate 0 无效（2025-08-15，详见 `workspace/runs/ksaf-dynamic-uid-smoke/`）
- [x] 调用方只发一次 workflow 调用、只持有紧凑 JSON 中间产物
- [x] token 对比记录：主会话单轮 < 10 万（实测 ~1 万量级，基线 29.3 万；`workspace/runs/ksaf-dynamic-uid-smoke/token-comparison.md`）
- [x] **三段式端到端**：ksaf-init 纯净源码 段1(2 假设) → 段2(双 UNREACHABLE, pro 否证 hunter 粘滞位误读) → 段3(干净报告)，见 `workspace/runs/ksaf-init-clean-2025-08-15/E2E-SUMMARY.md`
- [ ] **VALIDATE sanitizer 分支**：代码完整但无 finding 到达（本轮全被 TRACE 否掉）— 需已知漏洞 fixture 补验
- [ ] **casefile/ledger 对接**：确定性 CLI（ledger add/log）由 agent 调用，待接入

## 状态

- **v1（完成）**：段1（RECON→HUNT→GAPFIL）已实现并冒烟通过（ksaf-dynamic-uid，3 agent，token 对比记录在 `workspace/runs/ksaf-dynamic-uid-smoke/token-comparison.md`）。
- **v2（完成）**：段2（TRACE+VALIDATE，KILL 税前置 + 否证优先 + 条件门禁）+ 段3（CHAIN+REPORT，CVSS 富化）+ model 分层（trace/validate=pro, hunt/chain/report=flash）。端到端验证（ksaf-init 纯净源码）见 `workspace/runs/ksaf-init-clean-2025-08-15/E2E-SUMMARY.md`。
- **待办**：
  1. VALIDATE sanitizer 分支补验（用已知漏洞 fixture 触发一次 confirmed 路径）
  2. casefile/ledger 对接（ledger add/log 确定性 CLI 由 agent 调用）
  3. 扩展 CWE 类（`classes` 参数按 code-audit 章节逐类加）

## 相关路径

| 项 | 路径 |
|---|---|
| 脚本 | `skills/workflow-audit/audit-pipeline.js` |
| 交接文档 | `workflow/TASK-SUMMARY.md` |
| 原层级式编排 | `skills/pipeline/SKILL.md` |
| 确定性编排层 | `skills/audit-runner/` |
| 底层硬封装 | `extensions/audit-tools.py`（PATH: `audit-tools`） |
| CWE 方法论 | `skills/code-audit/SKILL.md` |
| 角色简报 | `agents/harness.md` / `auditor.md` / `tracer.md` / `exploit.md` / `chain.md` |
