---
name: codeaudit-pipeline
description: Full pipeline orchestration skill for C/C++/Shell/Python source code audit. Teaches the c-harness agent how to run stages with state tracking, schema validation, reachability trace, gapfill, and structured reporting. No compilation of the target required; no CPG/CodeQL dependency.
---

# Pipeline Orchestration Skill

## Stage Machine

```
RECON → HUNT → GAPFIL(loop) → TRACE → VALIDATE → CHAIN → REPORT
  ↑___________________|                    |
  └────── FEEDBACK ────┘                    |
         (traces into new hunts)            |
                                            ↓
                                      FIX (optional)
```

Finish coverage (hunt + gapfill) before spending trace budget. Trace only the hypotheses that survived a complete hunt, then validate the reachable ones.

Each stage produces a structured output. The next stage validates it before starting. If validation fails, the stage retries with repair guidance.

## Prerequisites — check before starting a run

The pipeline assumes the target codebase is **in scope** and the toolchain is available. Before dispatching the first auditor, verify:

1. **Target is defined.** Record the repo path + language distribution in the pipeline-run case `target` + `assumptions`. Every analysis must stay inside this codebase.
2. **Toolchain is present.** Static analysis relies on `codebase-memory-mcp` (graph) + `lsp_*` tools (pi-lsp/clangd for C/C++/Shell semantics) + `grep`/`read`. Sanitizer validation relies on `gcc`/`clang` with `-fsanitize=address,undefined`, `valgrind`, `cppcheck`. Check with `bash("command -v gcc clang valgrind cppcheck clang-tidy")` at run start and record what's available.
3. **Joern is available.** The pipeline uses Joern (fuzzy mode, no compilation needed) as a mandatory analysis engine for HUNT (joern-scan querydb) and TRACE (taint propagation queries). Verify with `bash("command -v joern joern-parse joern-scan")`. If missing, ask the user before starting.
4. **Target indexed in codebase-memory-mcp.** Run `codebase-memory-mcp cli index_repository --repo-path <target>` (with extension-completion pre-step for extensionless files) if not already indexed. Record the project name.
5. **Input surface identified.** Enumerate entry points in RECON **with the indexed graph, not by hand** — hand/grep enumeration is the #1 source of blind spots (missing submodules → INCOMPLETE coverage). Use codebase-memory queries to get the full candidate list, then confirm semantics with the model:
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

**No compilation of the target is required or assumed.** The target may not build (missing deps, cross-compile). Static analysis (codebase-memory + clangd) and Joern fuzzy parsing never compile the target. Sanitizer repros (VALIDATE) compile only self-contained PoC files extracted from the target — never the full project.

**No out-of-band channel, no rate limits, no auth tokens, no HTTP probing.** This is a local code audit pipeline, not a web pentest.

If any prerequisite is missing, record it in the pipeline-run case and either ask the user or scope the run to what's possible.

## Stage Config

Each stage has:
- **model** — which model class to dispatch on (hunt = standard, trace = strong, validate = different than hunt for deliberate disagreement)
- **tools** — what tools the agent gets (trace has no write tools)
- **output schema** — what shape the stage must emit
- **max_turns** — when to terminate a stuck agent
- **concurrency** — how many parallel agents to run

## State Tracking via Casefile

Track pipeline state in the casefile ledger. Use a dedicated pipeline-run case:

```
CaseAdd(
  title: "Pipeline: <target> <timestamp>",
  status: hypothesis,
  bugClass: "pipeline-run",
  target: "<target>",
  tags: ["pipeline"]
)
```

Record per-stage progress with `CaseUpdate`:
- Add `nextStep: "stage: recon complete, findings: 3, moving to validate"` after each stage
- Add `assumptions: ["COVERED: buffer-overflow, use-after-free | SKIPPED: unsafe-deserialization | NOT_FOUND: command-injection"]` for coverage
- Tag findings with the pipeline run ID for cross-referencing

This gives you resume capability: on restart, `CaseList(tag: "pipeline")` shows previous runs and their last recorded stage.

## Schema Validation at Stage Boundaries

Every stage output must conform to its schema before the next stage begins. Validate by reading the schema file and checking each required field.

### Stage Schemas (in `schemas/`):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `schemas/stage-finding.json` | vuln_class, language, file, line, sink, entry_point, confidence, evidence |
| **TRACE** | `schemas/stage-trace.json` | trace_result, entry_point, call_chain, data_flow, defenses_checked, attacker_model |
| **VALIDATE** | `schemas/stage-validation.json` | finding_id, status, technique_used, detection_method |
| **CHAIN** | `schemas/stage-chain.json` | chains[], summary |
| **REPORT** | `schemas/stage-report.json` | target, pipeline_status, findings, coverage, summary |

**Validation procedure:**
```
1. Read the schema file: read("schemas/stage-finding.json")
2. For each output, check every required field exists and has non-null content
3. If missing or malformed → return to the stage agent with "Your output is missing: <fields>. Please fix."
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
    task: "Hunt for <cwe-class> vulnerabilities in <target/subsystem>. ..."})
```

Suggested class partitions (adjust to target's language mix):
- C/C++ memory safety: buffer-overflow, out-of-bounds-read, use-after-free, double-free, integer-overflow, null-deref, uninitialized-use, format-string
- C/C++ injection & paths: command-injection, path-traversal, symlink-follow, unsafe-temp-file
- Privilege & access (C/C++ setuid/daemons, DBus services): access-control, privilege-mgmt, permission-assignment
- Shell: shell-injection, command-injection, path-traversal, unsafe-temp-file, race-condition
- Python: eval-injection, unsafe-deserialization, command-injection, path-traversal, race-condition
- Cross-cutting: toctou, race-condition, resource-leak, memory-leak, crypto-weakness, info-disclosure

**Every auditor MUST run the Joern engine as part of hunting:**
```
# 1. Build CPG once per target (fuzzy mode — no compilation of the target):
joern-parse <target-root> --out /tmp/<target>.cpg
# 2. Run the querydb sweep (100+ built-in CVE queries):
joern-scan /tmp/<target>.cpg
# 3. For the assigned class, run targeted queries (e.g. sink discovery via
#    cpg.call.name("memcpy|strcpy|sprintf|system|popen|eval|exec") ...)
# Joern output = candidate list. Every candidate still needs codebase-memory/
# clangd verification + evidence — Joern never confirms anything by itself.
```
Joern candidates that survive `clangd`/read verification become hypotheses. Joern-only hits that cannot be verified semantically are dropped or marked low confidence.

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

### TRACE: One agent per finding

**Pre-trace gate (30 seconds, do not skip):** before spending a TRACE budget, apply the kill taxonomy (code-audit §10) — any finding that fails one of these is killed here, not traced:
1. Does a caller outside the attacker's own process reach the sink with attacker-controlled data? (else KILL-1 unreachable / KILL-4 self-attack)
2. Is the fix already in the shipped version (BUG#/changelog/patched diff)? (else KILL-2 already-fixed)
3. Does the outcome cross a privilege/trust boundary the attacker lacks? (else KILL-3 no-gain)
4. Is the authorization identity forgeable (argv/cmdline/env/cache-key)? (if yes, escalate priority — spoofable-identity class, code-audit §3.1a)

Only findings that pass the gate advance to a full trace. Record the gate result in the pipeline-run case (`nextStep: "gate: killed N as KILL-x"`) so gapfill does not re-queue them.

```
For each hypothesis that passed validation:
  subagent({agent: "c-tracer",
    task: "Trace whether attacker input reaches the sink at <file:line>. ..."})
```

**Tracer MUST use the Joern taint engine as the primary path-finder:**
```
# 1. Run taint query on the CPG built during HUNT (or rebuild if missing):
joern --script /tmp/taint.sc --param sink=<sink> --param source=<entry>
# or interactively: cpg.call.name("<sink>").reachableBy(cpg.method.name("<entry>").parameter)
# 2. Joern output = candidate data-flow path (expression-level, cross-procedure)
# 3. Verify each hop with clangd/pi-lsp (lsp_definition / lsp_references) + read:
#    confirm the symbols are real, no name collision, types match
# 4. Record the value-level path in the trace output's `data_flow` field
#    (e.g. argv[1] → strlen(x)+1 → memcpy(dst,src,n))
```
Joern output is a **candidate** — never a verdict. Only paths verified hop-by-hop with clangd + read become REACHABLE. If Joern is unavailable for the target's language (e.g. Shell), fall back to codebase-memory `trace_path --mode data_flow` + manual hop verification.

Only findings with `TRACE RESULT: REACHABLE` advance to exploit.

### VALIDATE: One agent per traced finding

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
  Read the class's checked/unchecked entry-point list from the pipeline-run case.
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

After the hunt + gapfill stages, emit a coverage summary in the pipeline-run case. Each class line must list the entry points checked so gapfill can target the gaps:

```
assumptions: [
  "COVERED: buffer-overflow (c) — checked main(argv), network recv handler, config parser; memcpy/strcpy sinks verified via Joern + clangd",
  "COVERED: use-after-free (c) — checked all free() call sites reachable from network input; no double-path found",
  "SKIPPED: unsafe-deserialization (no pickle/yaml.load in target)",
  "NOT_FOUND: command-injection (shell) — checked all system()/popen()/eval() sites; all args are compile-time constants",
  "COVERED: access-control — checked all DBus method handlers for credential checks; 2 handlers lack sd_bus_creds_get_uid → hypothesis",
  "INCOMPLETE: privilege-mgmt — checked setuid drop in main; UNCHECKED: signal handlers, config reload path"
]
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

## Run Artifacts: 证据链留痕（audit_log）

人工可追溯 ≠ 过程重放。留 **L1 决策证据**（能验证结论的），留 **L2 现场指针**（大块输出只存路径），删 **L3 过程噪音**（推理/被否候选/重复查询）。

**每 stage 结束时追加一条 `tools/audit_log.py append`**（机器调用，不是模型写报告）：

```bash
python3 /opt/audit/tools/audit_log.py append <case_id> --stage <STAGE> \
    --verdict <REACHABLE|UNREACHABLE|CONFIRMED|KILL-1..5|finding> \
    --evidence "<一句话证据，file:line → sink>" \
    [--artifact <L2 指针路径>] [--reason <KILL 原因/决策理由>] [--agent <agent名>]
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

查看：`python3 /opt/audit/tools/audit_log.py view <case_id>`（人类可读时间线）或 `list --stage HUNT`。

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

Each finding in the report carries: vuln_class, language, cwe_id, cvss_vector, cvss_score, poc_path, severity. The cwe_id/cvss fields map directly to the KVE report template (`~/.pi/agent/skills/exploit_dig_ways/SKILL.md`).

## Token Tracking

After each subagent completes, record token usage in the pipeline-run case:

```
CaseUpdate(<pipeline-case-id>, {
  nextStep: "stage: <stage> complete — <n> findings
             tokens: <input> in / <output> out"
})
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
| auditor | 20 | 25 with gapfill |
| tracer | 12 | read-only, should be fast |

### Task sizing (hard lesson from production runs)

Subagent tasks that run > 8-10 minutes get interrupted (user Esc / message arrival aborts the whole dispatch via AbortSignal → SIGTERM, extension `subagent/index.ts:413`). This is NOT a timeout — it is session interruption. **Keep every dispatched task under ~3 minutes of work:**

1. **One CWE class per auditor dispatch** — never bundle 3+ classes into one task. If a class has many entry points, split by entry point ("audit recv handler only", "audit config parser only").
2. **Prove timing before parallelizing** — run ONE c-auditor on a small slice first, measure, then decide concurrency (parallel dispatch multiplies wall-clock, not latency).
3. **Cap per-task scope explicitly in the task text**: "examine at most 3 entry points, then emit INCOMPLETE with the unchecked list" — the auditor's exhaustion contract already caps at 8.
4. **Never hunt inline** — the coordinator's own read/grep tools are for orchestration only (see HUNT hard rule). Even a 200-line file gets a c-auditor dispatch; the dispatch is the audit, and inline work is not valid coverage.
5. **Never dispatch without turnBudget** — a missing budget means the subagent runs until the model decides to stop, which is exactly the 9-10 min window that gets aborted.
| exploit (phase 1) | 15 | PoC writing + refine |
| exploit (phase 2) | 20 | patch + verify + re-attack |
| chain | 8 | lightweight analysis |
