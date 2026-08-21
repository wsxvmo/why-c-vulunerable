// skills/workflow-audit/audit-pipeline.js — 段1: RECON → HUNT → GAPFIL
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段1（无 fs 调度脚本，纯编排）
// 2026-08-21: TRACE 已并入 HUNT —— HUNT/GAPFIL 每个 finding 直接产出
//   trace_result/call_chain/data_flow/defenses_checked/reachability_basis。
//
// 调用方式（主 agent 每次 read 本文件后作为 script 参数传入）:
//   workflow({
//     meta: {name: "code-audit-segment1",
//            description: "RECON→HUNT→GAPFIL 审计段1",
//            phases: [{title:"recon"},{title:"hunt"},{title:"gapfill"}]},
//     script: <本文件内容>,
//     args: {target, runDir?, skillRoot?, classes?}
//   })
//
// args 契约:
//   target     [必填] 目标源码绝对路径
//   runDir     [可选] 产物目录（agents 写入; 默认 ${skillRoot}/workspace/runs/audit-<名>）
//   skillRoot  [可选] 本仓库根（默认 /home/xvmo/why-c-vulunerable）
//   models     [可选] {recon?, hunt?, gapfil?} 模型覆盖（缺省 = 继承主 agent 模型）
//   classes    [已废除 2026-08-15] 不再生效——类选择仅听从 RECON recommended_classes
//   classesMode [已废除 2026-08-15] 不再生效——merge/pin 语义已从代码移除
//
// 设计要点（详见 workflow/TASK-SUMMARY.md 与 skills/workflow-audit/SKILL.md）:
//   * 脚本无 fs/网络——所有文件工作由子 agent 完成, 阶段间只传内存 JSON
//   * 角色简报/方法论留文件, prompt 指示 agent 自己 read（单一事实源）
//   * 纪律块内置: audit-runner/audit-tools 分工, 禁裸 joern, 自限契约
//   * agent() schema 只支持子集; 条件必填/深度校验在脚本内做（gate 段）
// ============================================================================

const SKILL_ROOT = args.skillRoot || "/home/xvmo/why-c-vulunerable";
const AUDIT_RUNNER_FALLBACK = "/home/xvmo/.local/bin/audit-runner";
const BRIEFS = {
  harness: `${SKILL_ROOT}/agents/harness.md`,
  auditor: `${SKILL_ROOT}/agents/auditor.md`,
};
const CODE_AUDIT = `${SKILL_ROOT}/skills/code-audit/SKILL.md`;
const QUERIES = `${SKILL_ROOT}/skills/audit-runner/queries`;
const TRICKS = `${SKILL_ROOT}/skills/tricks/SKILL.md`;

// 统一策略(2026-08-18): 全阶段缺省继承主 agent 模型(不传 model 即继承);
// 可经 args.models.recon/hunt/gapfil 显式覆盖(需要更强/不同模型时再指定)
// 2026-08-20: 支持 args.models.provider 覆盖 provider —— 子代理默认走 ark-coing-plan
// 配额 429 时, 主 agent 可传 provider=deepseek-official model=deepseek-v4-flash 绕过。
const MODELS = {
  provider: (args.models && args.models.provider) || null,
  recon: (args.models && args.models.recon) || null,
  hunt: (args.models && args.models.hunt) || null,
  gapfil: (args.models && args.models.gapfil) || null,
};

const target = args.target;
if (!target) throw new Error("args.target 必填: 目标源码绝对路径");
const runDir = args.runDir || (() => {
  const base = (target.split("/").filter(Boolean).pop() || "audit").replace(/[^A-Za-z0-9._-]/g, "_");
  return `${SKILL_ROOT}/workspace/runs/audit-${base}`;
})();

// 类选择: RECON 唯一权威（2026-08-15 硬性收紧）。
// args.classes / args.classesMode 已从代码上废除——调用方不得追加或 pin 覆盖
// RECON 的 recommended_classes（历史教训: 调用方传 23 类覆盖 RECON 7 类, 范围漂移）。
// 仅保留确定性兜底: 语言剪枝 + DEFAULT_CLASSES（见下方 A+B 段注释）。
const DEFAULT_CLASSES = ["buffer-overflow", "command-injection"];

// 语言兼容性剪枝（A）: 类 → 所需语言（目标缺失该语言则剪掉, 防白跑; 未列出 = 全语言适用）
const CLASS_LANG = {
  "buffer-overflow": ["c", "cpp"],
  "out-of-bounds-read": ["c", "cpp"],
  "use-after-free": ["c", "cpp"],
  "double-free": ["c", "cpp"],
  "format-string": ["c", "cpp"],
  "null-deref": ["c", "cpp"],
  "uninitialized-use": ["c", "cpp"],
  "integer-overflow": ["c", "cpp"],
  "shell-injection": ["shell"],
  "eval-injection": ["python"],
  "unsafe-deserialization": ["python"],
};

function pruneByLanguage(classes, languages) {
  const text = (languages || []).join(" ").toLowerCase();
  const has = (t) => text.includes(t);
  return classes.filter((cls) => {
    const need = CLASS_LANG[cls];
    return !need || need.some(has);
  });
}

// code-audit 技能章节映射（prompt 指路用）
const CLASS_SECTIONS = {
  "buffer-overflow": "§1.1 buffer-overflow (CWE-120/121/122/787)",
  "out-of-bounds-read": "§1.2 out-of-bounds-read (CWE-125)",
  "use-after-free": "§1.3 use-after-free (CWE-416)",
  "double-free": "§1.4 double-free (CWE-415)",
  "integer-overflow": "§1.5 integer-overflow (CWE-190/191)",
  "null-deref": "§1.6 null-deref (CWE-476)",
  "uninitialized-use": "§1.7 uninitialized-use (CWE-457)",
  "format-string": "§1.8 format-string (CWE-134)",
  "command-injection": "§2.1 command-injection (CWE-78)",
  "path-traversal": "§2.2 path-traversal (CWE-22/23)",
  "symlink-follow": "§2.3 symlink-follow (CWE-59)",
  "unsafe-temp-file": "§2.4 unsafe-temp-file (CWE-377/378/379)",
  "race-condition": "§2.5 race-condition / toctou (CWE-362/367)",
  "access-control": "§3.1 access-control (CWE-284/862/863)",
  "privilege-mgmt": "§3.2 privilege-mgmt (CWE-250/269/271/272/273)",
  "permission-assignment": "§3.3 permission-assignment (CWE-732/276)",
  "spoofable-identity": "§3.1a spoofable-identity (CWE-287/269) — identity trust boundary; bump priority on hit",
  "shell-injection": "§5.1 shell-injection (CWE-78)",
  "eval-injection": "§6.1 eval-injection (CWE-95/94)",
  "unsafe-deserialization": "§6.2 unsafe-deserialization (CWE-502)",
  "toctou": "§2.5 race-condition / toctou (CWE-362/367) — separate key, shares methodology with race-condition",
  "memory-leak": "§7.1 resource-leak / memory-leak (CWE-401/404/775)",
  "resource-leak": "§7.1 resource-leak / memory-leak (CWE-401/404/775)",
  "crypto-weakness": "§7.2 crypto-weakness (CWE-327/328)",
  "info-disclosure": "§7.3 info-disclosure (CWE-200)",
};

const discipline = `## Non-Negotiables (iron rules)
1. NEVER compile the target project itself; use only read/grep/static queries/CPG.
2. Raw joern / joern-scan / codebase-memory-mcp are BANNED — go through the wrappers (prevents hangs / footguns):
   - CPG build:      audit-runner cpg build --root <abs>
   - CPG query:      audit-runner cpg query --cpg <cpg> --file <q.sc>   (println/fallback built in)
   - querydb scan:   audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>
   - codebase-memory: audit-tools cli codebase_query --tool <t> <args...>
   - If audit-runner is not on PATH, use the absolute path: ${AUDIT_RUNNER_FALLBACK}
3. Empty result (INFO-only lines) -> fall back to grep; do not retry and idle-wait.
4. Write artifacts under ${runDir} subdirectories (mkdir -p first).
5. Self-limit: check at most 3 entry points per agent; put the rest in unchecked and hand them back — never expand without bound.`;

// ---- 简化内联 schema（agent() 只支持 type/properties/required/items/enum/const/oneOf）----
const RECON_SCHEMA = {
  type: "object",
  required: ["languages", "entry_points", "cpg_path", "toolchain", "assumptions", "recommended_classes", "tricks_injection", "threats"],
  properties: {
    languages: { type: "array", items: { type: "string" } },
    entry_points: { type: "array", items: { type: "string" } },
    cpg_path: { type: "string" },
    toolchain: { type: "object" },
    assumptions: { type: "array", items: { type: "string" } },
    recommended_classes: {
      type: "array",
      items: { type: "string", enum: [...Object.keys(CLASS_SECTIONS), "business-logic"] },
      description: "RECON 基于语言/目标类型/权限上下文推荐的猎杀类清单",
    },
    tricks_injection: {
      type: "string",
      description: "按目标类型从 skills/tricks/SKILL.md 提炼的 ≤200 字经验前馈注入块, 前置到每个 HUNT/GAPFIL auditor 提示词",
    },
    exclude_files: {
      type: "array",
      items: { type: "string" },
      description: "目标树内发现的非源码产物/基准文件清单（report/poc/disconf/START-HERE/审计输出等）, HUNT 将显式禁用",
    },
    candidate_hits: {
      type: "array",
      items: {
        type: "object",
        required: ["file", "line", "class"],
        properties: {
          file: { type: "string" },
          line: { type: "integer" },
          class: { type: "string" },
          cwe: { type: "array", items: { type: "string" } },
          tier: { type: "string", enum: ["ALERT", "HIGH", "LOW", "HIT"] },
          content_dup_of: { type: "string", description: "内容重复指针: 本文件与 canonical 文件字节相同(md5 一致), 不重复列点, 值=canonical 文件路径" },
          md5: { type: "string", description: "本文件 md5（content_dup_of 存在时必填, 供副本组 HUNT 复核）" },
        },
      },
      description: "候选池扫描命中（sinks.sc / scan_cpg / sink_filter.py 确定性产出）: 每条 {file, line, class, cwe[], tier, content_dup_of?, md5?}",
    },
    class_file_map: {
      type: "array",
      items: {
        type: "object",
        required: ["class", "file"],
        properties: {
          class: { type: "string" },
          file: { type: "string" },
          line: { type: "integer" },
          note: { type: "string" },
        },
      },
      description: "无 sink 候选类的审计点标注（权限/授权类）: {class, file, line, note}",
    },
    group_priority: {
      type: "array",
      items: {
        type: "object",
        required: ["file"],
        properties: {
          file: { type: "string" },
          rank: { type: "integer" },
        },
      },
      description: "可选: RECON 看过源码后的组优先级覆盖（rank 越小越先查）; 缺省用确定性排序",
    },
    privilege_ctx: {
      type: "object",
      required: ["privilege_context", "trigger_context"],
      properties: {
        privilege_context: { type: "string", enum: ["high", "low", "unknown"] },
        trigger_context: { type: "string" },
        signals: { type: "array", items: { type: "object" } },
        evidence_confidence: { type: "string" },
      },
      description: "权限上下文（preflight 的 audit-runner pctx 确定性产出, 单一事实源）: 目标自身运行权限 + 触发者标签",
    },
    exports: {
      type: "array",
      items: {
        type: "object",
        required: ["symbol", "file", "kind"],
        properties: {
          symbol: { type: "string" },
          file: { type: "string" },
          line: { type: "integer" },
          kind: { type: "string", enum: ["intended", "accidental", "internal"] },
          declared_in_header: { type: "boolean" },
          header: { type: "string" },
          in_tree_callers: { type: "integer" },
        },
      },
      description: "目标本地导出面（audit-runner exports 确定性产出）: 导出即入口点, kind=intended(头文件声明)/accidental(符号表带出)/internal(树内专用)",
    },
    threats: {
      type: "array",
      items: {
        type: "object",
        required: ["entry_point", "threat", "mapped_classes"],
        properties: {
          entry_point: { type: "string" },
          threat: { type: "string" },
          mapped_classes: { type: "array", items: { type: "string" } },
          rationale: { type: "string" },
          same_as: { type: "string", description: "内容重复指针: 本入口点文件与某 canonical 入口点字节相同, 不重复写威胁全文, 值=canonical entry_point 字符串" },
        },
      },
      description: "威胁推导纪律（每入口点 ≥1 threat, 类选择的输入）: 导出契约入口必映射威胁",
    },
  },
};

const FINDING_ITEM_SCHEMA = {
  type: "object",
  required: ["vuln_class", "file", "line", "sink", "entry_point", "confidence", "evidence",
             "attacker_model", "trace_result", "call_chain", "data_flow", "defenses_checked",
             "reachability_basis"],
  properties: {
    vuln_class: { type: "string" },
    file: { type: "string" },
    line: { type: "integer" },
    sink: { type: "string" },
    entry_point: { type: "string" },
    confidence: { type: "string", enum: ["low", "medium", "high"] },
    evidence: { type: "string" },
    subsystem: { type: "string" },
    attacker_model: { type: "string" },
    trace_result: { type: "string", enum: ["REACHABLE", "UNREACHABLE"] },
    call_chain: { type: "array", items: { type: "string" } },
    data_flow: { type: "string" },
    defenses_checked: {
      type: "array",
      items: {
        type: "object",
        required: ["defense", "location", "verdict"],
        properties: {
          defense: { type: "string" },
          location: { type: "string" },
          verdict: { type: "string", enum: ["bypassed", "blocked", "not-present"] },
        },
      },
    },
    reachability_basis: { type: "string", enum: ["in-tree", "export-contract", "external-context"] },
    impact_if_reachable: { type: "string" },
    unreachable_reason: { type: "string" },
  },
};

const HUNT_SCHEMA = {
  type: "object",
  required: ["cls", "findings", "checked", "unchecked"],
  properties: {
    cls: { type: "string" },
    findings: { type: "array", items: FINDING_ITEM_SCHEMA },
    checked: { type: "array", items: { type: "string" } },
    unchecked: { type: "array", items: { type: "string" } },
    notes: { type: "string" },
  },
};

// 2026-08-21: TRACE 并入 HUNT — finding 必含结构化可达性 trace 字段
const REQUIRED_FIELDS = ["vuln_class", "file", "line", "sink", "entry_point", "confidence", "evidence",
                         "attacker_model", "trace_result", "call_chain", "data_flow", "defenses_checked",
                         "reachability_basis"];

// ============================================================================
// Phase 1: RECON — 1 个 agent
// ============================================================================
phase("recon");
log(`RECON: ${target}`);

const recon = await agent(`You are the RECON coordinator (code audit pipeline, segment 1).

## Glossary
- all-pass: exported API surfaces are assumed to have consumers by default (possibly privileged intermediaries).
- export-as-entry (export = commitment): exported symbols (intended/accidental, no in-tree callers) are designed external call surfaces -> default REACHABLE.
- consumer: external code that calls an exported API.

## Output contract (return this JSON; shown first on purpose)
{languages: string[], entry_points: string[], cpg_path: string,
 toolchain: {doctor: string, joern: string, ...}, assumptions: string[],
 privilege_ctx: {privilege_context: high|low|unknown, trigger_context: string, signals: [], evidence_confidence: string},
 exports: [{symbol, file, line, kind: intended|accidental|internal, declared_in_header, in_tree_callers}],
 threats: [{entry_point, threat, mapped_classes[], rationale}],
 recommended_classes: string[], tricks_injection: string, exclude_files: string[],
 candidate_hits: [{file, line, class, cwe[], tier}], class_file_map: [{class, file, line, note}],
 group_priority: [{file, rank}]}

## Setup
First read ${BRIEFS.harness} and the Prerequisites section of ${SKILL_ROOT}/skills/pipeline/SKILL.md, then proceed.

Target: ${target}
Artifact directory: ${runDir}/recon/  (mkdir -p first)

${discipline}

## Core tasks (mandatory)
1. Run audit-runner doctor (5 health checks: skill-tree/preset/schemas/toolchain/cache); record toolchain availability.
2. Build the CPG: audit-runner cpg build --root ${target} (fuzzy mode, NEVER compile the target; reuse cache on hit).
3. **Deterministic export-surface enumeration (mandatory; the basis of "export = entry point")**: run
   audit-runner exports --root ${target} --cpg <cpg> --out ${runDir}/recon/exports.json
   (deterministic CLI: header declarations x no-caller function query -> exports[]{symbol, file, line, kind, declared_in_header, in_tree_callers}).
   Also enumerate **in-tree explicit entry points** (main/callbacks/signals/dbus registrations/exec entries) with entry.sc / search_graph, confirming semantics per candidate via read/grep.
   Note: export-contract entries (kind in {intended,accidental} and in_tree_callers==0) are injected into entry_points automatically by the script — do not re-enumerate them.
   **Output discipline (prevents output overrun)**: exports.json is already written to disk by the CLI; for the exports field in the returned JSON:
   - if the export count is <=200 -> return the full exports array;
   - if >200 -> return **empty array []** (the main agent reads the full list from ${runDir}/recon/exports.json
     and re-injects it via args.exports; do NOT stuff the full list into your return, or output overrun makes recon=null).
   Before returning, confirm exports.json was written (ls -l check).
4. Pollution scan (prevent "hinted verification"): walk the target tree and identify **non-source benchmark/acceptance/audit artifacts**
   (START-HERE*, *REPORT*.md, VULN-FINDINGS*, THREAT_MODEL*, CALL-CHAINS*, poc_*/disconf_*,
   *exploit*, *.rpm/*.cpio/*.tar.gz, .pi/, workspace/, *.cpg, etc.); list all of them in exclude_files.
   **These files must never be used as audit evidence or influence any conclusion**; if you find suspicious benchmark files, state that honestly in assumptions.
5. **Privilege context (produced deterministically by preflight — do NOT re-derive)**: read ${runDir}/recon/privilege_ctx.json,
   reference its privilege_context/trigger_context conclusion (high|low|unknown + trigger label) in assumptions,
   and use it to tune your value judgment of entry points/classes; if the file is absent, fall back to unknown and note it in assumptions.
6. **Threat-derivation discipline (mandatory; input to class selection)**: for every entry point (in-tree explicit + export-contract), give at least 1 threat
   mapped to hunt classes, producing threats: [{entry_point, threat, mapped_classes[], rationale}].
   **Every export-contract entry point must map to at least one threat** (export = commitment: an external call surface exists by design).
   **Content-dup pointer (uniform convention)**: if an entry point's file is byte-identical to another entry point's (confirm with cmp/md5sum),
   do not repeat the full threat text for the latter; set same_as=<canonical entry_point string> and write a one-line threat
   (e.g. "content identical to <canonical>, same attack surface, not re-analyzed").
7. **Recommended hunt classes (derived from threats)**: aggregate mapped_classes from step 6,
   combined with language distribution / target type / privilege context; pick classes actually applicable to THIS target, at least 3, each with a one-line rationale chained to a threat.
   - no python -> drop eval-injection/unsafe-deserialization; no shell -> drop shell-injection;
   - pure C/C++ target -> prefer memory-safety classes; library target -> consider access-control/privilege classes (exported API surface);
   - root daemon / DBus service -> prefer race-condition/toctou/access-control (combined with pctx from step 5).
8. **Candidate-pool scan (mandatory, deterministic engine — produces HUNT's targeted candidates)**:
   - **For every class selected in step 7, run its pre-written query asset** (path ${SKILL_ROOT}/skills/audit-runner/queries/classes/,
     asset file names are classes/<class>.sc or classes/<class>.grep; all 25 classes have assets):
      each .sc asset via audit-runner cpg query --cpg <cpg> --file ${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.sc --timeout 200;
      .grep assets (shell-injection/eval-injection/unsafe-deserialization) via **cd ${target} then**
      rg -n -f ${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.grep scripts/
      (assets use scripts/-relative paths — run from the target root, not runDir);
      **hard rule: .sc assets only via cpg query, .grep assets only via rg — never mix them**
      (cpg query on a .grep file reports NonForkingScriptRunner: it only accepts joern Scala assets; feeding a .grep absolute path to cpg query is also blocked by cpg.py's guard);
      grep over scripts/ will hit byte-identical copies (same hit repeated across files): expected — dedupe by content when aggregating (see the dedup step below);
      if an asset file is missing, fall back to the generic sinks.sc (${QUERIES}/) + scan_cpg --tags <that class's cwe> + grep;
      also run the generic assets: entry.sc / sinks.sc / error_deref.sc (under ${QUERIES}/);
   - Empty result (INFO-only lines) -> run the grep fallback noted in the asset's header comment once to confirm; do not retry joern;
   - audit-tools cli scan_cpg --cpg <cpg> --tags <cwe> (querydb full-db sweep as a fallback supplement);
   - if ${SKILL_ROOT}/tools/sink_filter.py exists, run python3 sink_filter.py --cpg <cpg> --out ${runDir}/recon/candidates.json for the ALERT/HIGH/LOW tiers (write artifacts to runDir);
   - aggregate into candidate_hits: [{file, line, class, cwe[], tier: ALERT|HIGH|LOW|HIT}], each entry = one real candidate point;
   - **Content dedup (mandatory, uniform convention)**: after aggregation, compare interpreted-language files (sh/py) sharing the same class with cmp/md5sum;
     if two files are byte-identical (e.g. init-bottom/security_set vs security_set.sh byte-identical copies), the canonical file keeps all real candidate points,
     the copy keeps only 1 pointer entry {file, line: 0, class, content_dup_of: <canonical file>, md5: <value>} — do NOT duplicate points;
     downstream does NOT dispatch a HUNT agent for copy groups: the aggregation stage deterministically re-stamps the canonical group's findings onto this file path
     (RECON's md5 is the pre-dispatch re-check; the audit snapshot is read-only and won't drift mid-run, so no re-audit).
   - **Language split**: interpreted files (.sh/.py) have no C-sink candidates -> do not force line numbers; mark their candidates in class_file_map as whole-file audits;
   - **Zero hits must be recorded too** (a class with no candidates -> the script marks it SKIPPED, no agent dispatched).
   - **Note**: scan scope = the classes recommended in step 7 (RECON decides; not forced to the full set); recommended classes MUST run their per-class assets,
     do not just satisfy with the generic sinks.sc (per-class assets are more precise than generic regexes).
9. class_file_map (audit-point annotation, mandatory, **the primary source for semantic audit points**): for classes with no sink candidates
   (authorization classes like access-control/privilege-mgmt/permission-assignment/spoofable-identity — classes that only hold if "something is missing"),
   give real audit points [{class, file, line, note}], with note stating the audit direction
   (e.g. "exported API lacks an authorization primitive; check getuid/ownership/validation").
   Other candidate-less classes (injection/memory/robustness) are auto-backfilled with default audit points by the script's "export = entry point" rule (covers all recommended classes).
   **Note**: every recommended class without sink candidates MUST get at least 1 real candidate point in class_file_map;
   not giving one = the script sees no audit point, marks it SKIPPED, and dispatches no agent (recommending without a point is recorded as a RECON omission warning).
   Default candidate points may be filled from export-contract entries.
10. group_priority (optional override): the script computes a deterministic default ordering by "threat value x pctx weight"
    (default: scripts/ root-exec > lib/*.c privileged-write > other .c > tests/); only if RECON judges a file's priority differs from the default,
    provide [{file, rank}], smaller rank = checked first.
11. tricks feed-forward (mandatory): read the scenario-mapping section of ${TRICKS} (the "章节 -> 适用场景映射" part),
    pick 2-4 relevant sections by target type (e.g. daemon/DBus -> §2 identity trust boundary + §4 deep-dive;
    library -> §5 diff-index; setuid -> §1 attack-surface priority; patch-dense -> §3 patch-as-map),
    distill a <=200-char ACTIONABLE injection block into tricks_injection (concrete check directions, not generalities).
12. Write recon.json (all the fields above) to ${runDir}/recon/recon.json.

Return the JSON contract shown at the top.
`,
  { label: "recon", phase: "recon", schema: RECON_SCHEMA, ...(MODELS.recon ? { model: MODELS.recon } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) });

if (!recon || !Array.isArray(recon.entry_points) || !recon.cpg_path) {
  log("RECON 失败或产物不完整, 中止段1");
  return {
    pipeline: "code-audit-segment1",
    status: "failed",
    reason: "RECON failed or incomplete",
    target,
    recon: recon || null,
    runDir,
  };
}
log(`RECON 完成: ${recon.languages.join("/")}, ${recon.entry_points.length} 个入口点, CPG=${recon.cpg_path}, 推荐 ${(recon.recommended_classes || []).length} 类`);

// 类选择: RECON 唯一权威（2026-08-15 硬性收紧, 杜绝调用方范围漂移）
//   历史教训: 调用方曾传 23 类, 覆盖 RECON 的 7 类推荐, 把审计范围带偏。
//   现在 args.classes / args.classesMode 在代码上完全失效——RECON（看过源码）
//   的 recommended_classes 是唯一猎杀清单来源, 调用方无法追加或 pin 覆盖。
//   保留的确定性兜底（非人工输入）:
//     - 语言剪枝 pruneByLanguage: 目标无该语言则剪掉（防白跑）
//     - RECON 未推荐或全被剪 → DEFAULT_CLASSES
const reconRec = (recon.recommended_classes || []).filter(Boolean);
if (args.classes || args.classesMode) {
  log(`警告: args.classes/classesMode 已废除（类选择仅听从 RECON）, 忽略传入值`);
}
const requested = reconRec.length > 0 ? [...reconRec] : [...DEFAULT_CLASSES];
const prunedList = pruneByLanguage(requested, recon.languages);
const effectiveClasses = prunedList.length > 0 ? prunedList : ["command-injection", "race-condition"];
const prunedClasses = requested.filter((c) => !prunedList.includes(c));
const classesMode = "recon-only";
log(`HUNT 类选择[${classesMode}]: ${effectiveClasses.join(", ")}${prunedClasses.length ? `（剪掉: ${prunedClasses.join(", ")}）` : ""}`);

// 污染控制: RECON 标注的非源码产物文件 → HUNT/GAPFIL 提示词显式禁用
const exclusionBlock = (recon.exclude_files && recon.exclude_files.length)
  ? `\n## Pollution Control (prevent benchmark leakage)\nThe following files inside the target tree are non-source artifacts/benchmark files — DO NOT read them, DO NOT reference them, DO NOT use them as audit evidence:\n${recon.exclude_files.map((f) => `- ${f}`).join("\n")}\nViolating this invalidates the audit.`
  : "";

// 经验前馈: RECON 提炼的 tricks 注入块 → 前置到每个 auditor 提示词（原框架硬规则）
const tricksBlock = recon.tricks_injection
  ? `\n## Experience Feed-Forward (injected from past post-mortems; read first, prioritize these directions)\n${recon.tricks_injection}`
  : "";

// CPG 私有副本（fork, 必做）: scan_cpg 无锁且 --overwrite 原地重写共享 CPG,
// 并行 HUNT 必须私有副本防损坏; 小 CPG(≤100MB) fork 毫秒级, 大 CPG 降级共享+flock
const forkBlock = `\n## Private CPG copy (fork, mandatory, prevents concurrent corruption)\nShared CPG: ${recon.cpg_path}\nCheck its size first (ls -l / stat): if <=100MB, run\n  audit-runner cpg fork --src ${recon.cpg_path} --n 1 --dir ${runDir}/cpg-forks/\nand use the returned private copy for ALL of this agent's cpg queries and scan_cpg afterwards; if >100MB, use the shared CPG directly (flock-serialized, correctness first); if fork fails, fall back to the shared CPG.`;

// ============================================================================
// Phase 2: 候选池构建 → 文件聚合分组 → 排序 → 分批派发 HUNT（≤6/轮）
// 2026-08-15 改造: 探索按 25 方法论类(RECON), 派发按代码文件聚合(脚本确定性分组)。
//   .c/.cpp → 组 = 文件(组内聚合全部类候选点); .h 并入引用它的 .c 组(不独立分发);
//   .sh/.py 等解释型 → 组 = 文件本身, 整文件审计(候选由 class_file_map/入口点标注);
//   零候选类 → SKIPPED(引擎证据), 不派。
// ============================================================================
phase("hunt");

// ---- 2.0 候选池构建: RECON 扫描命中 ∪ class_file_map 标注（入口点注入已废除）----
// 2026-08-15 修正: 废除"入口点注入"。历史: 原逻辑对每个入口点文件 × 每个权限类强注入
// ENTRY 候选, 把只属于 security_conf.c/security_set.sh 的权限类审计方向复印到全部文件
// （lib/libsecurity.c、tests/*.c 无真实候选却拿到 access-control/permission-assignment
//  → 空转 0 findings 或牵强 finding）。新语义（RECON 唯一权威）: 类候选点唯一来源
// 是 RECON class_file_map + 引擎 candidate_hits; RECON 推荐了该类但无 map 候选 = 由
// 2.0b 的"导出即入口点"回填缺省审计点（2026-08-18 起覆盖全部推荐类, 见下）。
const CWE_RE = /\(CWE-([^)]+)\)/;
function classCwes(cls) {
  const m = CWE_RE.exec(CLASS_SECTIONS[cls] || "");
  return m ? m[1].split("/").map((s) => "CWE-" + s.trim()).filter(Boolean) : [];
}

const candPool = [];
for (const h of (recon.candidate_hits || [])) {
  // 内容重复指针条目(line:0 + content_dup_of)也要入池, 保证副本文件有组可派发、覆盖不丢
  if (h && h.file && h.class && (h.line || h.content_dup_of)) {
    candPool.push({ file: h.file, line: Number(h.line || 0), class: h.class,
                    cwe: Array.isArray(h.cwe) && h.cwe.length ? h.cwe : classCwes(h.class),
                    tier: h.tier || "HIT", src: "scan",
                    ...(h.content_dup_of ? { content_dup_of: h.content_dup_of, md5: h.md5 || "" } : {}) });
  }
}
for (const m of (recon.class_file_map || [])) {
  if (m && m.class && m.file) {
    candPool.push({ file: m.file, line: Number(m.line || 0), class: m.class,
                    cwe: classCwes(m.class), tier: "MAP", src: "map", note: m.note || "" });
  }
}
// ---- 2.0b 结构性规则: 导出即入口点（2026-08-16 新增; 2026-08-18 全通化, 覆盖全部推荐类）----
// 背景: 兄弟组件扫描因版本漂移双向失真已整体退役。导出 API 本身就是"设计承诺的外部调用面"
// （intended=头文件声明 / accidental=符号表带出, 均可达）→ kind∈{intended,accidental} 且
// 无树内调用者的导出符号自动注入候选池, 作为**无候选类的缺省审计点**（导出即承诺对所有类生效,
// 不限于权限类——权限面=导出 API 面, 注入/内存/健壮性类的面同样=导出 API 面）。
// 注: 只回填 RECON 推荐了但无候选点的类（已有候选不重复注入）; 与旧"入口点注入"的区别:
//   旧坑是"对每文件×每权限类强注入"（复印导致空转/牵强 finding）; 现在是"对每无候选类×导出文件
//   注入缺省审计点", 补覆盖缺口而不是复印, 与"导出即承诺"语义一致。
// 2026-08-20 硬化: 导出回填按文件去重 + 排除测试目录。
// 背景: kylin-process-manager 修复 exports 解析后仍有 1371 条导出/130 文件,
//       若逐条注入会把 3 个无候选类复印到 130 个组(含 autotests), HUNT 再次膨胀。
// 语义不变: 组本来就是按文件聚合, 每文件只需 1 个缺省审计点; 测试文件不是交付攻击面。
// 2026-08-20 新增: 主 agent 可预跑确定性 CLI 注入全量 exports（args.exports），
// 避免 RECON 把 1371 条导出全量回传导致 agent 输出超限失败（recon=null）。
const reconExports = (args.exports && Array.isArray(args.exports)) ? args.exports : (recon.exports || []);
const seenExportFile = new Set();
const exportEntries = [];
for (const e of (reconExports)) {
  if (!e || !e.kind || e.kind === "internal" || Number(e.in_tree_callers || 0) !== 0) continue;
  if (/(^|\/)(tests?|autotests)\//.test(e.file || "")) continue;
  if (seenExportFile.has(e.file)) continue;
  seenExportFile.add(e.file);
  exportEntries.push({ file: e.file, line: Number(e.line || 0), symbol: e.symbol, kind: e.kind });
}
if (exportEntries.length) {
  log(`导出即入口点: ${exportEntries.length} 个生产导出文件（去重后, 排除 tests/autotests）自动注入候选池`);
}
// HUNT 提示词注入块: 组文件命中的导出契约条目 + 全通语义（2026-08-21 TRACE 并入 HUNT 后,
// 可达性判定在 HUNT 完成, 必须把"导出即入口点默认 REACHABLE"规则传给 auditor）
function exportBlockForHunt(g) {
  const rel = g && g.file ? g.file : "";
  const hits = exportEntries.filter((e) => e.file === rel);
  const lines = [];
  if (hits.length) {
    lines.push(`\n## Export-contract entries for this group (RECON output; export = entry point)\n${hits.map((e) => `- ${e.symbol} @ ${e.file}:${e.line} (kind=${e.kind})`).join("\n")}\nThese symbols have no in-tree callers and form a "designed external call surface": **default REACHABLE**, reachability_basis=export-contract.`);
  } else if (exportEntries.length) {
    lines.push(`\n## Export-contract hint (RECON output)\nThis group has no export-contract entry; if a sink symbol appears in the global export surface, judge it under the export-contract rule (consumers default to existing, possibly privileged intermediaries).`);
  }
  if (exportEntries.length) {
    lines.push(`**All-pass semantics**: export-contract entries are assumed to have consumers by default, and those consumers may be privileged intermediaries (e.g. a root daemon forwarding unprivileged requests). Do NOT mark a finding unreachable or downgrade its attacker_model on the grounds of "no consumer / unprivileged direct / file-mode gate / no-gain".`);
  }
  return lines.join("\n");
}
for (const cls of effectiveClasses) {
  if (candPool.some((c) => c.class === cls)) continue; // 已有候选, 不重复注入
  for (const ee of exportEntries) {
    candPool.push({ file: ee.file, line: ee.line, class: cls,
                    cwe: classCwes(cls), tier: "ENTRY", src: "export",
                    note: `导出契约入口 ${ee.symbol}（${ee.kind}）, ${cls} 缺省审计点（导出即承诺）` });
  }
}
// 一致性警告: RECON 推荐了某类却连导出回填后仍无候选点 → 该类将被 SKIPPED
for (const cls of effectiveClasses) {
  if (!candPool.some((c) => c.class === cls)) {
    log(`警告: RECON 推荐类 ${cls} 但候选池无点（含导出回填）→ SKIPPED 不派; 若该类本应适用则是 RECON 遗漏`);
  }
}
const seenCand = new Set();
const cands = [];
for (const c of candPool) {
  const k = `${c.file}|${c.line}|${c.class}`;
  if (seenCand.has(k)) continue;
  seenCand.add(k);
  cands.push(c);
}
log(`候选池: ${cands.length} 个 (file,line,class) 点`);

// ---- 2.1 路径归一化: .h 并入实现它的 .c 组 ----
// 规则: ① 同名 .c(header.h → header.c)存在 → 并入; ② 否则并入候选点最多的实现 .c
//       (头文件多与主实现同名不同前缀, 如 libsecurity_conf.h → security_conf.c)
const baseOf = (f) => String(f).split("/").pop();
for (const c of cands) {
  if (!baseOf(c.file).endsWith(".h")) continue;
  const cBase = baseOf(c.file).replace(/\.h$/, ".c");
  let host = cands.find((x) => baseOf(x.file) === cBase && x.src !== "entry");
  if (!host) {
    const cnt = new Map();
    for (const x of cands) {
      if (x.src !== "entry" && !baseOf(x.file).endsWith(".h")) cnt.set(x.file, (cnt.get(x.file) || 0) + 1);
    }
    let best = null, bestN = -1;
    for (const [f, n] of cnt) if (n > bestN) { best = f; bestN = n; }
    host = best ? { file: best } : null;
  }
  if (host) c.file = host.file;   // 头文件候选并入宿主 .c 组
}

// ---- 2.2 分组: 组 = 文件, 组内聚合类清单 + 候选点 ----
const groupMap = new Map();
for (const c of cands) {
  if (!groupMap.has(c.file)) groupMap.set(c.file, { file: c.file, cls: new Set(), points: new Set(), tiers: new Set(), entry_lines: new Set() });
  const g = groupMap.get(c.file);
  g.cls.add(c.class);
  if (c.line > 0) g.points.add(c.line);
  if (c.tier) g.tiers.add(c.tier);
  if (c.src === "entry") g.entry_lines.add(c.line);
}
let groups = [...groupMap.values()].map((g) => ({
  file: g.file,
  cls_list: [...g.cls].sort(),
  points: [...g.points].sort((a, b) => a - b),
  tiers: [...g.tiers].sort(),
  entry_lines: [...g.entry_lines].sort((a, b) => a - b),
}));

// ---- 2.1b 内容重复映射（2026-08-18, 口径统一）: candidate_hits 的 content_dup_of → 组级 dup_of ----
// 副本组不再重复完整审计: HUNT 用 dupcheck.py 复核 md5 一致 → 聚合段继承 canonical 组 findings。
const dupOf = new Map();
for (const c of cands) {
  if (c.content_dup_of && c.file) dupOf.set(c.file, c.content_dup_of);
}
for (const g of groups) {
  if (dupOf.has(g.file)) g.dup_of = dupOf.get(g.file);
}

// 切分兜底: 组内唯一行 > 60 → 按类拆成 (file×class) 子组（防单 agent 上下文爆炸）
if (groups.some((g) => g.points.length > 60)) {
  const split = [];
  for (const g of groups) {
    if (g.points.length > 60) {
      for (const cls of g.cls_list) split.push({ ...g, cls_list: [cls], _split: true });
    } else split.push(g);
  }
  groups = split;
}

// ---- 2.3 排序: 文件特权上下文(确定性默认) + RECON group_priority 覆盖 ----
function defaultFileRank(f) {
  if (/^scripts\//.test(f)) return 0;                    // root 执行
  if (/^lib\/.+\.c$/.test(f)) return 1;                  // 特权配置写
  if (/(^|\/)tests?\//.test(f)) return 3;                // 测试(不发货)
  if (f.endsWith(".c") || f.endsWith(".cpp")) return 2;  // 其他 C/C++
  return 4;                                              // 头/其他
}
const prioMap = new Map((recon.group_priority || []).map((p) => [p.file, p.rank]));
groups.sort((a, b) => {
  const ra = prioMap.has(a.file) ? prioMap.get(a.file) : defaultFileRank(a.file);
  const rb = prioMap.has(b.file) ? prioMap.get(b.file) : defaultFileRank(b.file);
  if (ra !== rb) return ra - rb;
  return b.points.length - a.points.length;              // 组内按候选点数降序
});

// 零候选类 → SKIPPED（在 effectiveClasses 中但无任何组涉及, 引擎已确认无候选）
const groupedCls = new Set(groups.flatMap((g) => g.cls_list));
const skippedCls = effectiveClasses.filter((c) => !groupedCls.has(c));
if (skippedCls.length) log(`零候选类(→SKIPPED 不派): ${skippedCls.join(", ")}`);

log(`HUNT 分组: ${groups.length} 组 → ${Math.ceil(groups.length / 6)} 轮(≤6/轮)`);

// ---- 2.4 分批派发（≤6/轮, 按优先级顺序） ----
const huntResults = [];
const BATCH = 6;
// 内容重复副本组不派 HUNT agent: RECON 已在派发前用 dupcheck/md5sum 确认字节相同(content_dup_of),
// 审计只读快照不会中途漂移 → 聚合段由脚本确定性继承 canonical findings（2026-08-18）。
const dispatchGroups = groups.filter((g) => !g.dup_of);
const totalBatches = Math.ceil(dispatchGroups.length / BATCH);
for (let bi = 0; bi < dispatchGroups.length; bi += BATCH) {
  const batch = dispatchGroups.slice(bi, bi + BATCH);
  log(`HUNT 批次 ${bi / BATCH + 1}/${totalBatches}: ${batch.map((g) => g.file).join(", ")}${
    groups.length !== dispatchGroups.length ? `（${groups.length - dispatchGroups.length} 个内容重复副本组由脚本继承, 不派 agent）` : ""}`);
  const res = await parallel(batch.map((g) => () =>
    agent(`You are a c-auditor (HUNT stage, code audit pipeline, segment 1, file-aggregated group).

## Glossary
- all-pass: exported API surfaces are assumed to have consumers by default (possibly privileged intermediaries).
- export-contract reachability: the sink is an export symbol (intended/accidental, no in-tree callers) -> default REACHABLE.
- reachability_basis: in-tree | export-contract | external-context.

## Output contract (return this JSON; shown first on purpose)
{cls: "<group id: ${g.file}>", findings: [{vuln_class, file, line(integer), sink, entry_point,
  confidence: low|medium|high, evidence(entry->sink one line + code snippet), subsystem?, attacker_model,
  trace_result: REACHABLE|UNREACHABLE, call_chain: string[], data_flow,
  defenses_checked: [{defense, location, verdict: bypassed|blocked|not-present}],
  reachability_basis: in-tree|export-contract|external-context,
  impact_if_reachable?, unreachable_reason?}],
 checked: string[], unchecked: string[], notes?: string}

## Setup
First read ${BRIEFS.auditor}; for each class in the group read the corresponding section of ${CODE_AUDIT}:
${g.cls_list.map((c) => `- ${c}: ${CLASS_SECTIONS[c] || c}`).join("\n")}
${tricksBlock}

Target: ${target}
Audit file (group): ${g.file}
Classes in group: ${g.cls_list.join(", ")}
Candidate point lines in group: ${g.points.length ? g.points.join(", ") : "(no C-sink candidates -> whole-file audit)"}
Authorization audit-point entry lines: ${g.entry_lines.length ? g.entry_lines.join(", ") : "(none)"}
RECON global entry points: ${JSON.stringify(recon.entry_points)}
CPG: ${recon.cpg_path}
Artifact directory: ${runDir}/hunt/${g.file.replace(/[^A-Za-z0-9._-]/g, "_")}/  (mkdir -p first)

${discipline}
${forkBlock}
${exclusionBlock}
${exportBlockForHunt(g)}

## Tasks
1. **Use RECON's candidate pool directly — do not re-run assets**: RECON already ran the per-class assets
   (${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.sc) and produced candidate_hits
   (the "candidate point lines" above are engine hits). You do NOT need to run any classes/*.sc again —
   verify directly on the candidate points (a group dispatches only if it has candidates; zero-candidate classes were marked SKIPPED by the script and never reach HUNT).
2. Verify each candidate point hop-by-hop with read/grep (entry->sink really exists, no name collision, types match, defenses bypassable or not);
   **verification lens**: don't stop at "is memory bounded" (no OOB != no bug) — also check **whether the value semantics written are correct**
   (string handling: substring mis-match? index desync causing truncation/holes? do boundary inputs corrupt data structures?);
   classes without candidate points (authorization classes) are audited by entry point for "what is missing" (authorization primitive/identity check/ownership check); interpreted files (sh/py) get whole-file audits.
3. **Reachability verdict is HUNT's job**: for every emitted finding, produce the structured trace fields — after hop-by-hop verification decide trace_result:
   - sink is an export-contract entry (the export block above matches; kind in {intended,accidental} and no in-tree callers) -> **default REACHABLE**, reachability_basis="export-contract";
   - in-tree path verified hop-by-hop -> REACHABLE, reachability_basis="in-tree";
   - the whole chain is blocked by a real, non-bypassable defense -> do NOT emit the finding (record it in checked), or emit UNREACHABLE + unreachable_reason (audit trail; segment 2 will not validate it);
   - REACHABLE requires impact_if_reachable; UNREACHABLE requires unreachable_reason.
4. Emit only findings with an evidence chain (vuln_class must be the actual class, not the group id); record the result of each candidate/entry point in checked;
   anything not finished goes into unchecked (self-limit: at most 3 entry points per agent; beyond that -> unchecked).
5. Write findings.json + evidence snippets to ${runDir}/hunt/${g.file.replace(/[^A-Za-z0-9._-]/g, "_")}/.
6. **Schema gate**: after writing findings.json, run the authoritative check:
   audit-runner gate --stage finding --run-dir ${runDir} --output ${runDir}/hunt/${g.file.replace(/[^A-Za-z0-9._-]/g, "_")}/findings.json
   (uses the merged schemas/stage-finding.json; needs QUICK-PASS + AUTHORITATIVE PASS; on failure fix the missing fields, rewrite findings.json, and re-run gate; if audit-runner is not on PATH use ${AUDIT_RUNNER_FALLBACK}).

Return the JSON contract shown at the top.
`,
      { label: `hunt:${g.file.replace(/[^A-Za-z0-9._-]/g, "_")}`, phase: "hunt", schema: HUNT_SCHEMA, ...(MODELS.hunt ? { model: MODELS.hunt } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) })
  ));
  res.forEach((rr, i) => { if (rr) rr._group = batch[i]; });
  huntResults.push(...res.filter(Boolean));
}

// ============================================================================
// Phase 3: GAPFIL — 最小循环: 对 INCOMPLETE 组(有 unchecked)补查 1 轮, 同分组规则
// ============================================================================
phase("gapfill");

let results = huntResults.filter(Boolean);
const gapfillRounds = 1;
let roundsDone = 0;
let gapfillAgents = 0;

const incompleteFirst = results.filter((r) => r.unchecked && r.unchecked.length > 0);
if (incompleteFirst.length > 0 && roundsDone < gapfillRounds) {
  roundsDone++;
  gapfillAgents += incompleteFirst.length;
  log(`GAPFIL 第 1 轮: ${incompleteFirst.map((r) => r.cls).join(", ")} (${gapfillAgents} 个 agent)`);
  const gap = await parallel(incompleteFirst.map((r) => () => {
    const g = r._group || {};
    return agent(`You are a c-auditor (GAPFIL re-check of ${r.cls}, code audit pipeline, segment 1).

## Glossary
- all-pass: exported API surfaces are assumed to have consumers by default (possibly privileged intermediaries).
- export-contract reachability: the sink is an export symbol (intended/accidental, no in-tree callers) -> default REACHABLE.

## Output contract (return this JSON; same contract as HUNT)
{cls: string, findings: [{vuln_class, file, line, sink, entry_point, confidence, evidence,
  attacker_model, trace_result: REACHABLE|UNREACHABLE, call_chain: string[], data_flow,
  defenses_checked: [{defense, location, verdict}], reachability_basis, impact_if_reachable?,
  unreachable_reason?}], checked: string[], unchecked: string[], notes?: string}

## Setup
First read ${BRIEFS.auditor}; group class sections:
${(g.cls_list || []).map((c) => `- ${c}: ${CLASS_SECTIONS[c] || c}`).join("\n") || "(reuse the previous round's class list)"}
${tricksBlock}

Target: ${target}
CPG: ${recon.cpg_path}
Artifact directory: ${runDir}/hunt/${String(r.cls).replace(/[^A-Za-z0-9._-]/g, "_")}/  (append)

${discipline}
${forkBlock}
${exclusionBlock}
${exportBlockForHunt(g)}

Previous coverage (group ${r.cls}):
- Already checked (do NOT repeat): ${JSON.stringify(r.checked || [])}
- Not checked (check each one): ${JSON.stringify(r.unchecked || [])}

Reachability verdict is the same as HUNT: every emitted finding must carry
trace_result/call_chain/data_flow/defenses_checked/reachability_basis; REACHABLE requires
impact_if_reachable, UNREACHABLE requires unreachable_reason; export-contract entries are default REACHABLE.

**Schema gate**: after writing the re-check result to ${runDir}/hunt/${String(r.cls).replace(/[^A-Za-z0-9._-]/g, "_")}/findings.json, run
audit-runner gate --stage finding --run-dir ${runDir} --output ${runDir}/hunt/${String(r.cls).replace(/[^A-Za-z0-9._-]/g, "_")}/findings.json
(needs QUICK-PASS + AUTHORITATIVE PASS; on failure fix the missing fields and re-run; if audit-runner is not on PATH use ${AUDIT_RUNNER_FALLBACK}).

Return the JSON contract shown at the top.
`,
      { label: `gapfill:${String(r.cls).replace(/[^A-Za-z0-9._-]/g, "_")}`, phase: "gapfill", schema: HUNT_SCHEMA, ...(MODELS.gapfil ? { model: MODELS.gapfil } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) });
  }));
  results = results.map((old) => {
    const gx = gap.find((x) => x && x.cls === old.cls);
    return gx ? { ...gx, _group: old._group } : old;
  });
}

// ---- 内容重复副本组: 脚本确定性继承（2026-08-18, 不派 HUNT agent）----
// RECON 已在派发前用 dupcheck/md5sum 确认字节相同(content_dup_of); 审计只读快照不会中途漂移 →
// 副本组直接由脚本把 canonical 组 findings 重贴路径并入(零 agent), 覆盖保持 COVERED;
// 无 canonical 审计结果(如 canonical 为 SKIPPED)则跳过合成 → 副本组自然显示为 SKIPPED, 不产生空洞。
for (const g of groups) {
  if (!g.dup_of) continue;
  const canon = results.find((x) => x._group && x._group.file === g.dup_of);
  if (!canon) { log(`内容重复继承跳过(无 canonical 审计结果): ${g.file} ← ${g.dup_of}`); continue; }
  const inherited = (canon.findings || []).map((f) => ({
    ...f, file: g.file, inherited_from: g.dup_of, cls: f.vuln_class || canon.cls,
  }));
  const synth = {
    cls: g.file,
    findings: inherited,
    checked: [...new Set([...(canon.checked || []), `content-dup: identical to ${g.dup_of} (RECON md5, 脚本继承)`])],
    unchecked: [...(canon.unchecked || [])],
    notes: `content_dup_of=${g.dup_of} (脚本继承, 无 HUNT agent)`,
    _group: g,
  };
  results.push(synth);
  log(`内容重复继承(无agent): ${g.file} ← ${g.dup_of} (${inherited.length} 条 findings 重贴路径)`);
}

// ============================================================================
// 聚合 + 结构门禁（agent() schema 之外的深度校验在脚本内做）
// ============================================================================
// findings 的 cls 用实际漏洞类(vuln_class), 不用组标识 — 组标识只在 coverage/groups 呈现
const findings = results.flatMap((r) => (r.findings || []).map((f) => ({ ...f, cls: f.vuln_class || r.cls })));

const valid = [];
const invalid = [];
for (const f of findings) {
  const missing = REQUIRED_FIELDS.filter((k) => f[k] === undefined || f[k] === null || f[k] === "");
  // schema 类型/枚举门禁（2026-08-21 恢复, 对齐 schemas/stage-finding.json 合并契约）
  const typeIssues = [];
  if (f.trace_result !== undefined && !["REACHABLE", "UNREACHABLE"].includes(f.trace_result)) {
    typeIssues.push("trace_result 非 REACHABLE/UNREACHABLE");
  }
  if (f.reachability_basis !== undefined && !["in-tree", "export-contract", "external-context"].includes(f.reachability_basis)) {
    typeIssues.push("reachability_basis 非法");
  }
  if (f.confidence !== undefined && !["low", "medium", "high"].includes(f.confidence)) {
    typeIssues.push("confidence 非法");
  }
  if (f.call_chain !== undefined && !Array.isArray(f.call_chain)) typeIssues.push("call_chain 需数组");
  if (f.defenses_checked !== undefined && !Array.isArray(f.defenses_checked)) typeIssues.push("defenses_checked 需数组");
  if (Array.isArray(f.defenses_checked)) {
    for (const d of f.defenses_checked) {
      if (!d || !d.defense || !d.location || !["bypassed", "blocked", "not-present"].includes(d.verdict)) {
        typeIssues.push("defenses_checked 项缺 defense/location/verdict 或 verdict 非法");
        break;
      }
    }
  }
  if (missing.length === 0 && typeIssues.length) {
    invalid.push({ finding: f, missing: typeIssues });
    continue;
  }
  if (missing.length === 0) {
    // 可达性条件必填（2026-08-21 TRACE 并入 HUNT）
    const traceMissing = f.trace_result === "REACHABLE"
      ? (f.impact_if_reachable ? [] : ["impact_if_reachable"])
      : f.trace_result === "UNREACHABLE"
        ? (f.unreachable_reason ? [] : ["unreachable_reason"])
        : ["trace_result(非 REACHABLE/UNREACHABLE)"];
    if (traceMissing.length) {
      invalid.push({ finding: f, missing: traceMissing });
      continue;
    }
    // 规范化 line 为整数（模型偶发返回字符串）
    const line = Number(f.line);
    if (Number.isInteger(line) && line >= 1) {
      valid.push({ ...f, line });
    } else {
      invalid.push({ finding: f, missing: ["line(非整数)"] });
    }
  } else {
    invalid.push({ finding: f, missing });
  }
}

// coverage: per-class 聚合视图（覆盖单位为 (class × file) 组, 类条目聚合其涉及组）
//   - 类无任何涉及组（零候选）→ SKIPPED（引擎证据, 不派 agent）
//   - 涉及组有 unchecked → INCOMPLETE; 全查完 → hypotheses>0 ? COVERED : NOT_FOUND
// 2026-08-15: checked/unchecked 全局去重 — 同一组(如 security_conf.c)出现在多个类的
// involved 时, 其 checked 条目只归属首个涉及的类(复盘坑9: 9 类复制同一份 13 项 → 体积膨胀致截断)。
const globalChecked = new Set();
const globalUnchecked = new Set();
const coverage = effectiveClasses.map((cls) => {
  const involved = results.filter((r) =>
    (r._group && r._group.cls_list.includes(cls)) ||
    (r.findings || []).some((f) => f.vuln_class === cls));
  const checked = [...new Set(involved.flatMap((r) => r.checked || []))]
    .filter((c) => !globalChecked.has(c) && (globalChecked.add(c), true));
  const unchecked = [...new Set(involved.flatMap((r) => r.unchecked || []))]
    .filter((c) => !globalUnchecked.has(c) && (globalUnchecked.add(c), true));
  const hypotheses = involved.reduce(
    (n, r) => n + (r.findings || []).filter((f) => f.vuln_class === cls).length, 0);
  let status;
  if (involved.length === 0) status = "SKIPPED";
  else if (unchecked.length > 0) status = "INCOMPLETE";
  else status = hypotheses > 0 ? "COVERED" : "NOT_FOUND";
  return {
    cls,
    status,
    checked,
    unchecked,
    hypotheses,
    files: [...new Set(involved.map((r) => r.cls))],
  };
});

// 组级状态（返回明细, 供段3/人工评审）
const groupStatus = new Map(results.map((r) => [
  r.cls,
  r.unchecked && r.unchecked.length ? "INCOMPLETE"
    : (r.findings && r.findings.length ? "COVERED" : "NOT_FOUND"),
]));
const groupsMeta = groups.map((g) => ({
  file: g.file,
  cls_list: g.cls_list,
  points: g.points,
  tiers: g.tiers,
  entry_lines: g.entry_lines,
  dup_of: g.dup_of || null,
  status: groupStatus.get(g.file) || "NOT_DISPATCHED",
}));

// C: 跨类同根因去重 — 同一 file+sink(行距≤10) 视为同一根因（如 ksaf-init 同根因双视角）,
// 保留证据最全/置信度最高者, 记录合并来源, 防段2/段3 重复 trace/validate
const DEDUP_WINDOW = 10;
const dedupedFindings = [];
for (const f of valid) {
  const dup = dedupedFindings.find((d) => d.file === f.file && d.sink === f.sink && Math.abs(d.line - f.line) <= DEDUP_WINDOW);
  if (!dup) {
    dedupedFindings.push({ ...f, cls_all: [f.cls] });
  } else {
    dup.cls_all = [...new Set([...dup.cls_all, f.cls])];
    dup.merged_from = [...new Set([...(dup.merged_from || []), f.vuln_class])];
    if ((f.evidence || "").length > (dup.evidence || "").length) dup.evidence = f.evidence;
    if (f.confidence === "high") dup.confidence = "high";
    if (f.attacker_model && !dup.attacker_model) dup.attacker_model = f.attacker_model;
    // 2026-08-21 TRACE 并入 HUNT: 同根因冲突时优先保留 REACHABLE 的 trace 字段
    if (dup.trace_result !== "REACHABLE" && f.trace_result === "REACHABLE") {
      dup.trace_result = f.trace_result;
      dup.call_chain = f.call_chain;
      dup.data_flow = f.data_flow;
      dup.defenses_checked = f.defenses_checked;
      dup.reachability_basis = f.reachability_basis;
      dup.impact_if_reachable = f.impact_if_reachable;
      dup.unreachable_reason = f.unreachable_reason;
    }
  }
}
const mergedCount = valid.length - dedupedFindings.length;
if (mergedCount > 0) log(`去重: ${valid.length} → ${dedupedFindings.length}（合并 ${mergedCount} 个同根因）`);

log(`段1完成: ${dedupedFindings.length} 个有效 finding（${mergedCount} 个同根因合并）, ${invalid.length} 个未过门禁, 覆盖: ${coverage.map((c) => `${c.cls}=${c.status}`).join(", ")}`);

return {
  pipeline: "code-audit-segment1",
  status: "complete",
  target,
  runDir,
  findings: dedupedFindings,
  coverage,
  // 类选择元数据: RECON 唯一权威; 调用方 classes/classesMode 已废除
  classes: {
    mode: classesMode,
    requested: requested,
    recommended: reconRec,
    effective: effectiveClasses,
    pruned: prunedClasses,
  },
  // 文件聚合组明细（2026-08-15 改造）: 组 = 文件, 含类清单/候选点/入口行/状态
  groups: groupsMeta,
  // 经验前馈注入块 — 段2 VALIDATE 提示词需要, 调用方转发给 validate.js 的 args.tricks_injection
  tricks_injection: recon.tricks_injection || "",
  // 目标本地导出面（RECON step 3 产出）— 段2 的"导出即入口点"判定输入
  exports: reconExports,
  // 威胁推导纪律（RECON step 6 产出）— 段2/段3 的威胁上下文输入
  threats: recon.threats || [],
  // 权限上下文（preflight pctx 确定性产出, 单一事实源）— 段2 attacker_model / 段3 CVSS 输入
  privilege_ctx: recon.privilege_ctx || { privilege_context: "unknown", trigger_context: "unknown", signals: [], evidence_confidence: "low" },
  gate: {
    required: REQUIRED_FIELDS,
    invalid_count: invalid.length,
    invalid: invalid.map((i) => ({
      file: i.finding.file,
      vuln_class: i.finding.vuln_class,
      missing: i.missing,
    })),
  },
  agents: {
    recon: 1,
    hunt: huntResults.length,
    gapfill: gapfillAgents,
    started: 1 + huntResults.length + gapfillAgents,
  },
};
