// skills/workflow-audit/validate.js — 段2: VALIDATE（TRACE 已并入段1 HUNT）
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段2（无 fs 调度脚本，纯编排）
//
// 2026-08-21: TRACE 阶段并入 HUNT —— HUNT/GAPFIL 的 finding 已直接携带
//   trace_result/call_chain/data_flow/defenses_checked/reachability_basis。
//   段2 不再派 c-tracer；只对 REACHABLE finding 派 c-exploit（VALIDATE）,
//   UNREACHABLE finding 汇入 unreachable[]（审计留痕，不验证）。
//
// 调用方式（主 agent read 本文件后作为 script 参数传入）:
//   workflow({
//     meta: {name: "code-audit-segment2",
//            description: "VALIDATE 审计段2",
//            phases: [{title:"validate"}]},
//     script: <本文件内容>,
//     args: {target, findings, cpg_path, runDir?, skillRoot?, models?}
//   })
//
// args 契约:
//   target        [必填] 目标源码绝对路径（与段1一致）
//   findings      [必填] 段1 返回的 findings[]（每个含 vuln_class/file/line/sink/entry_point/
//                        confidence/evidence/attacker_model/cls + 可达性 trace 字段）
//   cpg_path      [必填] 段1 recon 构建的 CPG 路径
//   exports       [可选] 段1 返回的 exports[]（目标本地导出面, 导出即入口点）
//   privilege_ctx [可选] 段1 返回的 privilege_ctx（preflight pctx 确定性产出）
//   external_context [可选] 审计员显式生态知识（→ VALIDATE/REPORT 校准输入）
//   tricks_injection [可选] 段1 返回的经验前馈注入块
//   runDir        [可选] 产物目录（建议与段1相同 runDir，子目录区分）
//   skillRoot     [可选] 本仓库根
//   models        [可选] {validate?} 模型覆盖（deliberate disagreement:
//                        缺省 = 继承主 agent 模型; 需要更强/不同模型时显式传入）
//
// 设计要点:
//   * VALIDATE: 每 REACHABLE finding 1 agent, 独立否证 + 自包含 repro + sanitizer
//   * 独立第二视角（2026-08-21 合并补偿）: VALIDATE 不盲信 HUNT 的 trace 字段,
//     先独立走 entry→sink 链否证（机制不可触发/防御不可绕过/实际不可达 → killed）,
//     否证通过后再写确认 PoC。
//   * 条件必填（confirmed→poc_path 等）在脚本内二次检查, repair ≤2
// ============================================================================

const SKILL_ROOT = args.skillRoot || "/home/xvmo/why-c-vulunerable";
const AUDIT_RUNNER_FALLBACK = "/home/xvmo/.local/bin/audit-runner";
const BRIEFS = {
  exploit: `${SKILL_ROOT}/agents/exploit.md`,
};
const CODE_AUDIT = `${SKILL_ROOT}/skills/code-audit/SKILL.md`;
const QUERIES = `${SKILL_ROOT}/skills/audit-runner/queries`;

const target = args.target;
if (!target) throw new Error("args.target 必填");
const findings = args.findings;
if (!Array.isArray(findings) || findings.length === 0) {
  return { pipeline: "code-audit-segment2", status: "skipped", reason: "无 findings 输入", target };
}
const cpg = args.cpg_path;
if (!cpg) throw new Error("args.cpg_path 必填（段1 recon 产物）");
const runDir = args.runDir || `${SKILL_ROOT}/workspace/runs/audit-seg2`;

// 段1 RECON 产出的目标本地导出面（2026-08-16: 导出即入口点, 消费者树/兄弟扫描已退役）
//   kind=intended(头文件声明, 设计公开 API) / accidental(符号表带出, 仍可达) / internal(树内专用)
const exports_ = args.exports || [];
const privilegeCtx = args.privilege_ctx || { privilege_context: "unknown", trigger_context: "unknown", signals: [], evidence_confidence: "low" };
const externalContext = args.external_context || "";
const exportEntries = exports_.filter((e) => e && e.kind && e.kind !== "internal" && Number(e.in_tree_callers || 0) === 0);
const exportsBlock = (() => {
  const lines = [];
  if (exportEntries.length) {
    lines.push(`\n## Target export surface (RECON output; export = entry point)\nThe following exported symbols have no in-tree callers and form a "designed external call surface" (kind=intended public API / accidental exported via symbol table):\n${exportEntries.map((e) => `- ${e.symbol} @ ${e.file}:${e.line} (kind=${e.kind})`).join("\n")}`);
  } else if (exports_.length) {
    lines.push(`\n## Target export surface (RECON output)\n${exports_.length} exported symbols, all with in-tree callers or internal-only (if this finding touches an exported API, judge it by the in-tree path).`);
  }
  // 全通纪律（2026-08-18）: "默认消费者树全通"的结构化语义 — 导出契约入口默认存在消费者,
  // 且消费者可能是高权限中介（root 守护进程转发非特权用户请求）。这条必须传给 VALIDATE,
  // 否则 VALIDATE 会回退到"非特权直连/无消费者"的保守模型, 与全通相悖（F3 实证）。
  if (exportEntries.length) {
    lines.push(`\n## All-pass semantics (default consumer-tree all-pass)\nThe export symbols above are treated as a "designed external call surface": **consumers default to existing, and they may be privileged intermediaries** (e.g. a root daemon forwarding unprivileged user requests). The attacker_model must NOT fall back to "needs an out-of-tree privileged consumer"; without external_context you must NOT downgrade the attacker model or kill on the grounds of "no consumer / unprivileged direct" (see VALIDATE rules and the script gate).`);
  }
  lines.push(`\n## Privilege context (deterministic preflight pctx output, single source of truth)\nprivilege_context=${privilegeCtx.privilege_context} (trigger=${privilegeCtx.trigger_context || "unknown"}, confidence=${privilegeCtx.evidence_confidence || "low"})`);
  if (externalContext) {
    lines.push(`\n## External ecosystem knowledge (explicitly provided by the auditor; NOT a scan result)\n${externalContext}`);
  }
  return lines.join("\n");
})();

// 段1 RECON 提炼的经验前馈注入块（调用方从段1 返回的 tricks_injection 转发）
const tricksInjection = args.tricks_injection || "";
const tricksBlock = tricksInjection
  ? `\n## Experience Feed-Forward (injected from past post-mortems; read first, prioritize these directions)\n${tricksInjection}`
  : "";

// 段1 findings 无 id — 分配稳定 id（F1..Fn），validate 以 finding_id 关联
const items = findings.map((f, i) => ({ ...f, id: f.id || `F${i + 1}` }));

// 2026-08-20 健壮化: 不依赖 agent() schema（schema 会诱发子代理 structured_output 工具,
// 且限速/代码块会导致 null）。改为取最终文本后脚本内解析 JSON（兼容 ```json 围栏）。
// 2026-08-21 schema 门禁恢复: 脚本内 schemaGate() 按 VALIDATION_SCHEMA 做类型/枚举/条件校验,
// 与 checkValidation 合并进 repair 循环; 同时 VALIDATE agent 自跑 audit-runner gate --stage validation。
function parseAgentJson(text) {
  if (!text) return null;
  let s = String(text).trim();
  // strip markdown code fences
  s = s.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try { return JSON.parse(s.slice(start, end + 1)); }
  catch (e) { return null; }
}

// deliberate disagreement: VALIDATE 缺省**继承主 agent 模型**（不传 model 即继承）;
// 可经 args.models.validate 显式覆盖（需要更强/不同模型时再指定）
// 2026-08-20: 支持 args.models.provider 覆盖 provider（绕过 ark-coing-plan 配额 429）。
const MODELS = {
  provider: (args.models && args.models.provider) || null,
  validate: (args.models && args.models.validate) || null,
};

const discipline = `## Non-Negotiables (iron rules)
1. NEVER compile the target project; compile only self-contained repro files extracted from the target.
2. Raw joern / joern-scan / codebase-memory-mcp are BANNED — go through the wrappers:
   - CPG query:  audit-runner cpg query --cpg <cpg> --file <q.sc>
   - taint template: cpg.call.name("<sink>").reachableBy(cpg.method.name("<entry>").parameter)
   - If audit-runner is not on PATH, use the absolute path: ${AUDIT_RUNNER_FALLBACK}
3. Empty result (INFO-only lines) -> fall back to grep; do not retry and idle-wait.
4. Write artifacts under ${runDir} subdirectories (mkdir -p first).
5. Every conclusion must be verified hop-by-hop: read/grep to confirm each hop is real, no name collisions, types match.
6. Private CPG copy (fork, parallel to avoid serialization): check the CPG size; if <=100MB run
   audit-runner cpg fork --src ${cpg} --n 1 --dir ${runDir}/cpg-forks/ for a private copy,
   then use it for all cpg queries (parallel VALIDATE avoids flock queuing); if >100MB or fork fails, use the shared CPG.`;

// ---- 简化内联 schema（VALIDATE 返回仍走 parseAgentJson + 脚本内 schemaGate 门禁）----
const VALIDATION_SCHEMA = {
  type: "object",
  required: ["finding_id", "status", "technique_used", "detection_method"],
  properties: {
    finding_id: { type: "string" },
    // status: confirmed=实证确认; killed=机制被否证/无实际影响(硬 kill); env_blocked=环境/内核/部署无法本地复现
    // （≠ 硬 kill, 段2 返回独立 env_blocked[], 不进 killed[], 供段3/人工/LIVE 确认）
    status: { type: "string", enum: ["confirmed", "killed", "env_blocked"] },
    technique_used: { type: "string", enum: ["asan", "ubsan", "valgrind", "minimal-repro", "manual-review"] },
    detection_method: { type: "string" },
    build_config: { type: "string" },
    sanitizer_result: { type: "string" },
    poc_path: { type: "string" },
    run_log: { type: "string" },
    evidence_extracted: { type: "string" },
    // killed → kill_reason 必填(脚本门禁); 对 export-contract finding, kill_reason/detection_method/
    // evidence 若命中全通禁止类别(无消费者/非特权直连/文件权限门/no-gain), 脚本门禁 repair ≤2 拦截
    kill_reason: { type: "string" },
    // 可选: killed 的分类标签, 便于段3/台账区分 kill 类型
    kill_category: { type: "string", enum: ["mechanism_disproven", "no_real_impact", "unreachable_confirmed", "other"] },
    refinement_attempts: { type: "integer" },
  },
};

// ============================================================================
// Phase: VALIDATE — 每 REACHABLE finding 1 个 agent（否证优先 + sanitizer）
//   TRACE 已并入 HUNT（2026-08-21）; UNREACHABLE findings 直接进 unreachable[], 不派 VALIDATE
// ============================================================================
phase("validate");

const reachable = items.filter((f) => f.trace_result === "REACHABLE");
const unreachable = items.filter((f) => f.trace_result === "UNREACHABLE");
log(`VALIDATE: ${reachable.length} 个 REACHABLE finding（UNREACHABLE=${unreachable.length} 不验证）, 模型=${MODELS.validate || "继承主agent"}`);

// ============================================================================
// VALIDATE 分组派发（2026-08-21 v3.1）:
//   按 (file, vuln_class) 聚合, 组大小 2-3（>3 按行号切块）, 单条不进组。
//   组内每条 finding 独立实证（validations[] 契约），复用 HUNT 的按文件聚合思路，
//   但保留"每个漏洞独立 PoC/证据"纪律。
// ============================================================================
function buildValidateGroups(list) {
  const byKey = new Map();
  for (const f of list) {
    const key = `${f.file || "?"}::${f.vuln_class || "?"}`;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(f);
  }
  const groups = [];
  for (const arr of byKey.values()) {
    arr.sort((a, b) => (a.line || 0) - (b.line || 0));
    for (let i = 0; i < arr.length; i += 3) groups.push(arr.slice(i, i + 3));
  }
  return groups; // 保序: 按 reachable 首次出现顺序
}
const validateGroups = buildValidateGroups(reachable);
log(`VALIDATE 分组: ${validateGroups.length} 组（${reachable.length} 个 finding）`);

// 组提示词构造: 单条返回单对象(兼容旧契约/repair/retry), 多条返回 {validations: []}
function validatePrompt(group) {
  const single = group.length === 1;
  const fids = group.map((x) => x.id);
  const fidLabel = fids.join("_");
  const payload = single
    ? JSON.stringify({ finding: group[0] }, null, 2)
    : JSON.stringify({ findings: group }, null, 2);
  const outputContract = single
    ? `{finding_id, status: confirmed|killed|env_blocked, technique_used: asan|ubsan|valgrind|minimal-repro|manual-review,
 detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?,
 kill_reason?, kill_category?, refinement_attempts?}`
    : `{validations: [{finding_id, status: confirmed|killed|env_blocked, technique_used: asan|ubsan|valgrind|minimal-repro|manual-review,
   detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?,
   kill_reason?, kill_category?, refinement_attempts?}, ...]}`;
  return `You are a c-exploit (VALIDATE stage Phase 1: EXPLOIT, code audit pipeline, segment 2; deliberate disagreement).

## Glossary
- deliberate disagreement: you are the pipeline's independent second opinion on HUNT's trace fields — treat them as hypotheses to challenge, not verdicts.
- all-pass: exported API surfaces are assumed to have consumers by default (possibly privileged intermediaries).
- export-contract: reachability_basis=export-contract => default REACHABLE; you may NOT kill on "no consumer / unprivileged direct / file-mode gate / no-gain".

## Output contract (return this JSON; shown first on purpose)
${outputContract}

## Input
${single ? "Finding to validate (HUNT REACHABLE, carries structured trace fields):" : "Findings in group to validate (HUNT REACHABLE, carry structured trace fields); validate each finding **independently**:"}
${payload}
Target: ${target}
Artifact directories: ${fids.map((fid) => `${runDir}/validate/${fid}/`).join(" / ")}  (mkdir -p first)

## Setup
First read ${BRIEFS.exploit} and §6 of ${CODE_AUDIT} (confirmation & disconfirmation discipline), then start.

${discipline}
${exportsBlock}
${tricksBlock}

## Execution order (iron rules)
1) **Independent reachability challenge (mandatory)**:
   HUNT's trace_result/call_chain/data_flow/defenses_checked/reachability_basis are hypotheses, not conclusions.
   As VALIDATE you are the pipeline's only independent second view — do NOT trust HUNT's trace fields blindly:
   read the sink yourself, walk entry->sink independently, and check every hop and defense yourself (audit-runner cpg query / grep fallback OK).
   Focus disconfirmation on "can the mechanism actually fire" (do inputs/defenses/environment prerequisites hold?).
   - if you find the chain mislabeled by HUNT (actually unreachable) -> status=killed, kill_category=unreachable_confirmed,
     kill_reason=<specific mechanism disproof, e.g. "HUNT chain hop N has no real call relation / input truncated by a constant">;
   - if the mechanism is statically/deterministically untriggerable within the target (path-constant swap doesn't affect real deployment, sink has no data flow,
     a real non-bypassable defense exists, the target's own write path cannot produce that input) -> status=killed, kill_category=mechanism_disproven;
   - **All-pass discipline (mandatory)**: for findings with reachability_basis=export-contract, the following are FORBIDDEN as disconfirmation preconditions or kill reasons —
     they re-introduce the "consumer absent / unprivileged direct" assumption and contradict default consumer-tree all-pass:
     - "no out-of-tree consumer / no in-tree caller / no privileged consumer / requires out-of-tree consumer"
       (the consumer side is an external fact; HUNT already marked export-contract REACHABLE — consumers default to existing);
     - "unprivileged direct -> file-mode gate EACCES -> trigger impossible" (caller identity is decided by the consumer; a privileged intermediary
       (e.g. a root daemon forwarding unprivileged requests) bypasses the file-mode gate with its euid, so a library missing auth checks is a real bug);
     - "no-gain / can write directly" (only holds when the caller already has write privilege equal to the sink;
       under all-pass the unprivileged user has no write privilege — the intermediary holds it and trusts the library -> no-gain does not hold);
${single ? "" : "   **Per-item independence within a group**: same file != same root cause — each finding must independently go through the reachability challenge/disproof/repro,\n   must not cross-reference another item's evidence or merge multiple items into one conclusion; write artifacts to separate validate/<fid>/ dirs."}
2) Disproof script exits 0 (finding disproven) -> status: killed + kill_reason: <specific reason>
3) Then write a SELF-CONTAINED repro (extract only from the target; NEVER compile the whole project):
   C/C++: gcc -g -fsanitize=address,undefined repro.c -o repro && ./repro
   Python: python3 repro.py / Shell: bash repro.sh (interpreted, no gcc)
4) Confirmation = sanitizer/runtime error pointing at the sink: ASAN heap-buffer-overflow / use-after-free /
   valgrind invalid read / UBSAN shift exponent ...
5) Record build_config (full compile command) + sanitizer_result (raw output snippet) + run_log (exit code) +
   evidence_extracted (crash backtrace / leaked data / privilege change)
6) Write artifacts to ${fids.map((fid) => `${runDir}/validate/${fid}/`).join(" / ")} (per-finding dir: repro source + compiled artifact + output log)
7) Authoritative check: for each finding run audit-runner gate --stage validation --run-dir ${runDir} --output ${runDir}/validate/<fid>/validation.json
   (casefile.py validate wrapper; needs AUTHORITATIVE PASS; if audit-runner is not on PATH use ${AUDIT_RUNNER_FALLBACK})
8) Cannot reproduce locally (needs hardware/kernel/network peer/specific deployment) -> status: env_blocked + kill_reason: <blocking reason>
   (environment-blocked, NOT a hard kill: segment 2 returns a separate env_blocked[] for segment 3/human/LIVE confirmation; it never goes into killed[]);
   note: for export-contract findings, "cannot reproduce in this local environment" is env_blocked, not killed — do not disconfirm on that basis.

Return the JSON contract shown at the top.
${single ? "" : "The validations array must cover every finding_id in the group, exactly one element each; order irrelevant."}
**Output format rule**: the final reply must be ONE bare JSON object — no markdown code fences (\`\`\`json ... \`\`\`), no prefix/suffix prose.
**Output mechanism rule**: do NOT call structured_output / output_schema / any JSON-output tool; the final assistant message must be a directly JSON.parse-able bare JSON object.`;
}

function normalizeValidationRaw(raw) {
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.validations)) return raw.validations;
  if (raw && raw.finding_id) return [raw];
  return null;
}

// 主派发: 每组合并 1 个 agent
const groupResults = await parallel(validateGroups.map((group) => {
  const fids = group.map((x) => x.id);
  const fidLabel = fids.join("_");
  return () => agent(validatePrompt(group),
    { label: `validate:${fidLabel}`, phase: "validate", ...(MODELS.validate ? { model: MODELS.validate } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) }).then(parseAgentJson);
}));

// 扁平化 + 覆盖校验 + 降级重派
const flatValidations = [];
const failedGroups = [];
const missingRetry = [];
for (let gi = 0; gi < validateGroups.length; gi++) {
  const group = validateGroups[gi];
  const raw = groupResults[gi];
  const arr = normalizeValidationRaw(raw);
  if (!arr) { failedGroups.push(group); continue; }
  const foundIds = new Set();
  for (const v of arr) {
    if (v && v.finding_id) {
      foundIds.add(v.finding_id);
      flatValidations.push(v);
    }
  }
  for (const f of group) {
    if (!foundIds.has(f.id)) missingRetry.push(f);
  }
}
let retries = 0;
if (failedGroups.length || missingRetry.length) {
  const seen = new Set();
  const targets = [].concat(...failedGroups, ...missingRetry)
    .filter((f) => f && f.id && !seen.has(f.id) && (seen.add(f.id), true));
  if (targets.length) {
    retries++;
    log(`VALIDATE 降级重派: ${targets.length} 个 finding（整组 null=${failedGroups.length}, 漏项=${missingRetry.length}）`);
    const retryResults = await parallel(targets.map((f) => () =>
      agent(validatePrompt([f]),
        { label: `validate-retry:${f.id}`, phase: "validate", ...(MODELS.validate ? { model: MODELS.validate } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) }).then(parseAgentJson)
    ));
    for (const raw of retryResults) {
      const arr = normalizeValidationRaw(raw);
      if (arr) flatValidations.push(...arr);
    }
  }
}

// 对齐 reachable 顺序（保持 positional 兜底有效）+ 按 finding_id 去重（防组内重复返回）
const reachableIdx = new Map(reachable.map((f, i) => [f.id, i]));
flatValidations.sort((a, b) => (reachableIdx.get(a.finding_id) ?? 1e9) - (reachableIdx.get(b.finding_id) ?? 1e9));
const seenVal = new Set();
const validateResults = flatValidations.filter((v) => v && v.finding_id && !seenVal.has(v.finding_id) && (seenVal.add(v.finding_id), true));

// ============================================================================
// 条件门禁（agent() schema 不支持 if/then — 脚本内二次检查 + repair ≤2）
// ============================================================================
// 全通禁止的 kill 推理（2026-08-18, 违背"默认消费者树全通"）:
//   对 reachability_basis=export-contract 的 finding, 以下理由全部重新引入
//   "消费者不存在/非特权直连"假设, 与导出契约默认存在消费者相悖（F3 实证）:
//   - 无消费者类: 无树外消费者 / 无 in-tree 调用者 / 无特权消费者 / requires out-of-tree consumer
//   - 非特权直连类: 非特权直连 → 文件权限门(EACCES) → 触发不可能
//     （存在高权限中介时权限门被中介 euid 绕过, 库缺鉴权校验即真漏洞）
//   - no-gain 类: KILL-3 / 能写就直改（仅当调用者已具备 sink 同等写权限才成立）
// 命中 → 记入 gate 问题, repair 重派, 让 agent 在全通语义下重写 kill_reason 或转 env_blocked。
const ALL_PASS_FORBIDDEN = [
  // 全通禁止的 kill 推理（中文 + 英文词条, 兼容中英文模型输出）:
  // 消费者缺失类
  "无树外消费者", "无 in-tree 调用者", "无特权消费者", "无消费者",
  "no external consumer", "no in-tree caller", "no privileged consumer", "no consumer",
  "no out-of-tree consumer", "requires out-of-tree consumer", "requires external consumer",
  // 非特权直连类
  "非特权直连", "unprivileged direct", "non-privileged direct", "unprivileged connection",
  // 文件权限门类
  "文件权限门", "file-mode gate", "file permission gate", "EACCES", "permission denied",
  // no-gain / 能写就直改类
  "no-gain", "KILL-3", "能写就直改", "can write directly", "direct write", "write directly",
];

function allPassViolation(v, pair) {
  if (!v || v.status !== "killed") return [];
  // pair 是 REACHABLE finding 对象（TRACE 已并入 HUNT, 2026-08-21）
  if (!pair || pair.reachability_basis !== "export-contract") return [];
  const surface = `${v.kill_reason || ""} ${v.detection_method || ""} ${v.evidence_extracted || ""}`;
  const hits = ALL_PASS_FORBIDDEN.filter((t) => surface.includes(t));
  if (!hits.length) return [];
  return [`kill_reason 违背全通(导出契约入口默认存在消费者): 命中 "${hits.join('","')}" — 不得用"无消费者/非特权直连/文件权限门/no-gain"做 kill; 若机制被否证请改写 kill_reason 聚焦机制本身; 若仅环境无法复现用 status=env_blocked`];
}

// schema 门禁（2026-08-21 恢复, 适配合并后契约）:
//   workflow agent() 的 schema 选项会诱发 structured_output 导致 null, 段2 不传 schema,
//   改为脚本内 schemaGate + parseAgentJson 双保险; 同时 VALIDATE agent 自跑
//   audit-runner gate --stage validation（schemas/stage-validation.json）做权威校验。
function schemaGate(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return ["agent 输出非对象"];
  const issues = [];
  for (const k of ["finding_id", "status", "technique_used", "detection_method"]) {
    if (v[k] === undefined || v[k] === null || v[k] === "") issues.push(`缺字段 ${k}`);
  }
  if (v.status !== undefined && !["confirmed", "killed", "env_blocked"].includes(v.status)) {
    issues.push(`status 非法: ${v.status}`);
  }
  if (v.technique_used !== undefined && !["asan", "ubsan", "valgrind", "minimal-repro", "manual-review"].includes(v.technique_used)) {
    issues.push(`technique_used 非法: ${v.technique_used}`);
  }
  if (v.kill_category !== undefined && !["mechanism_disproven", "no_real_impact", "unreachable_confirmed", "other"].includes(v.kill_category)) {
    issues.push(`kill_category 非法: ${v.kill_category}`);
  }
  if (v.refinement_attempts !== undefined && (!Number.isInteger(v.refinement_attempts) || v.refinement_attempts < 1)) {
    issues.push("refinement_attempts 需为 ≥1 整数");
  }
  return issues;
}

function checkValidation(v, pair) {
  if (!v) return ["agent 失败(返回 null)"];
  const issues = schemaGate(v);
  if (issues.length) return issues;
  if (v.status === "confirmed") {
    const missing = ["poc_path", "run_log", "evidence_extracted"].filter((k) => !v[k]);
    return missing.length ? missing.map((k) => `confirmed 缺 ${k}`) : [];
  }
  if (v.status === "killed") {
    if (!v.kill_reason) issues.push("killed 缺 kill_reason");
    issues.push(...allPassViolation(v, pair));
    return issues;
  }
  if (v.status === "env_blocked") return v.kill_reason ? [] : ["env_blocked 缺 kill_reason(阻断原因)"];
  return [`未知 status: ${v.status}`];
}

// pair 查找: 先按 finding_id, 失败按序兜底（与聚合段一致）
const pairOf = (v) => reachable.find((p) => p.id === v.finding_id || p.finding_id === v.finding_id) || {};

let validations = validateResults.filter(Boolean);
let repairs = 0;
const MAX_REPAIRS = 2;

while (repairs < MAX_REPAIRS) {
  const bad = validations.filter((v) => checkValidation(v, pairOf(v)).length > 0);
  if (bad.length === 0) break;
  repairs++;
  log(`VALIDATE repair #${repairs}: ${bad.map((v) => v.finding_id).join(", ")}`);
  const fixed = await parallel(bad.map((v) => () =>
    agent(`Your VALIDATE output did not pass the conditional gate (gaps: ${checkValidation(v, pairOf(v)).join("; ")}).
Fill in the missing fields (re-run the repro for evidence if needed; don't rewrite artifacts already written); if you hit an "all-pass forbidden" kill, rewrite
kill_reason under "default consumer-tree all-pass" semantics (focus on the mechanism itself) or switch to status=env_blocked:
${JSON.stringify(v, null, 2)}
Return the same contract JSON (confirmed -> poc_path/run_log/evidence_extracted; killed -> kill_reason;
      env_blocked -> kill_reason blocking reason).
**Output format rule**: final reply must be ONE bare JSON object — no markdown code fences, no prefix/suffix prose.
**Output mechanism rule**: do NOT call structured_output / output_schema / any JSON-output tool; the final assistant message must be a directly JSON.parse-able bare JSON object.`,
      { label: `validate-repair:${v.finding_id}`, phase: "validate", ...(MODELS.validate ? { model: MODELS.validate } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) }).then(parseAgentJson)
  ));
  validations = validations.map((old) => {
    const fx = fixed.find((x) => x && x.finding_id === old.finding_id);
    return fx || old;
  });
}

const gateFail = validations.filter((v) => checkValidation(v, pairOf(v)).length > 0);
const confirmed = [];
const killed = [];
const envBlocked = [];
for (let k = 0; k < validations.length; k++) {
  const v = validations[k];
  // 先按 finding_id 匹配, 失败则按序兜底（validateResults 与 reachable 同序, repair 保序）
  const pair = reachable.find((p) => p.id === v.finding_id || p.finding_id === v.finding_id) || reachable[k] || {};
  const entry = {
    finding: pair || { id: v.finding_id },
    validation: v,
  };
  if (v.status === "confirmed") confirmed.push(entry);
  else if (v.status === "env_blocked") envBlocked.push(entry);
  else killed.push(entry);
}

log(`段2完成: confirmed=${confirmed.length}, killed=${killed.length}, env_blocked=${envBlocked.length}, unreachable=${unreachable.length}, gateFail=${gateFail.length}`);

// 产物落盘契约(复盘坑1/3/4: 返回截断/手工抄大 JSON/丢字段):
//   每个 validate 子 agent 已写 runDir/validate/<fid>/ (repro 源 + 输出日志)。
//   段2 返回只给"摘要 + 产物路径索引", 主 agent 段3 从 runDir 读盘重建 confirmed 全量,
//   不再手工抄返回值。
const indexArtifacts = (entries) => entries.map((e) => {
  const f = e.finding || {};
  const v = e.validation || null;
  const fid = v ? v.finding_id : (f.id || f.finding_id || "?");
  return {
    finding_id: fid,
    vuln_class: f.vuln_class ?? null,
    file: f.file ?? null,
    line: f.line ?? null,
    sink: (f.sink || "").slice(0, 120) ?? null,
    entry_point: (f.entry_point || "").slice(0, 150) ?? null,
    attacker_model: (f.attacker_model || "").slice(0, 150) ?? null,
    status: v ? v.status : (f.trace_result || "unreachable"),
    trace_result: f.trace_result ?? null,
    reachability_basis: f.reachability_basis ?? null,
    impact: (f.impact_if_reachable || "").slice(0, 200) ?? null,
    evidence: v ? (v.evidence_extracted || v.detection_method || "").slice(0, 200) : null,
    technique_used: v ? v.technique_used : null,
    kill_reason: v ? v.kill_reason : null,
    kill_category: v ? v.kill_category : null,
    validate_dir: v ? `${runDir}/validate/${String(fid).replace(/[^A-Za-z0-9._:-]/g, "_")}/` : null,
    poc_path: v ? v.poc_path : null,
  };
});

return {
  pipeline: "code-audit-segment2",
  status: "complete",
  target,
  runDir,
  confirmed: indexArtifacts(confirmed),
  killed: indexArtifacts(killed),
  // env_blocked（2026-08-18 新增）: 环境/内核/部署无法本地复现的结论 — ≠ 硬 kill, 供段3/人工/LIVE 确认,
  // 段3 不得把它们当"已否证"处理
  env_blocked: indexArtifacts(envBlocked),
  // unreachable（2026-08-21 新增, 原 killed_by_gate 替代）: HUNT 判 UNREACHABLE 的 finding,
  // 段2 不验证, 原样返回供审计留痕/人工复核
  unreachable: indexArtifacts(unreachable.map((f) => ({ finding: f }))),
  gate: {
    repairs,
    gate_fail_count: gateFail.length,
    gate_fail: gateFail.map((v) => ({ finding_id: v.finding_id, issues: checkValidation(v, pairOf(v)) })),
    all_pass_forbidden: ALL_PASS_FORBIDDEN,
  },
  stats: { reachable: reachable.length, unreachable: unreachable.length, groups: validateGroups.length, confirmed: confirmed.length, killed: killed.length, env_blocked: envBlocked.length, requires_external_verify: 0 },
  agents: { validate: validations.length, started: validateGroups.length + retries + repairs },
};
