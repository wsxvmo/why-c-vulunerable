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
    lines.push(`\n## 目标导出面（RECON 产出, 导出即入口点）\n以下导出符号无树内调用方, 属"设计承诺的外部调用面"（kind=intended 公开 API / accidental 符号表带出）:\n${exportEntries.map((e) => `- ${e.symbol} @ ${e.file}:${e.line} (kind=${e.kind})`).join("\n")}`);
  } else if (exports_.length) {
    lines.push(`\n## 目标导出面（RECON 产出）\n${exports_.length} 个导出符号, 均已有树内调用方或有 internal 限定（本 finding 若触及导出 API 按树内路径判定）。`);
  }
  // 全通纪律（2026-08-18）: "默认消费者树全通"的结构化语义 — 导出契约入口默认存在消费者,
  // 且消费者可能是高权限中介（root 守护进程转发非特权用户请求）。这条必须传给 VALIDATE,
  // 否则 VALIDATE 会回退到"非特权直连/无消费者"的保守模型, 与全通相悖（F3 实证）。
  if (exportEntries.length) {
    lines.push(`\n## 全通语义（默认消费者树全通, 2026-08-18）\n上述导出符号按"设计承诺的外部调用面"处理: **默认存在消费者, 且消费者可能是高权限中介**（如 root 守护进程转发非特权用户请求）。attacker_model 不得回退为"需要 out-of-tree 特权消费者"; 无 external_context 时亦不得以"无消费者/非特权直连"降级攻击者模型、不得以此类推理 kill（详见 VALIDATE 纪律与脚本门禁）。`);
  }
  lines.push(`\n## 权限上下文（preflight pctx 确定性产出, 单一事实源）\nprivilege_context=${privilegeCtx.privilege_context} (trigger=${privilegeCtx.trigger_context || "unknown"}, confidence=${privilegeCtx.evidence_confidence || "low"})`);
  if (externalContext) {
    lines.push(`\n## 外部生态知识（审计员显式提供, 非扫描结果）\n${externalContext}`);
  }
  return lines.join("\n");
})();

// 段1 RECON 提炼的经验前馈注入块（调用方从段1 返回的 tricks_injection 转发）
const tricksInjection = args.tricks_injection || "";
const tricksBlock = tricksInjection
  ? `\n## 经验前馈（历史复盘注入, 先读再干, 按此方向优先排查）\n${tricksInjection}`
  : "";

// 段1 findings 无 id — 分配稳定 id（F1..Fn），validate 以 finding_id 关联
const items = findings.map((f, i) => ({ ...f, id: f.id || `F${i + 1}` }));

// 2026-08-20 健壮化: 不依赖 agent() schema（schema 会诱发子代理 structured_output 工具,
// 且限速/代码块会导致 null）。改为取最终文本后脚本内解析 JSON（兼容 ```json 围栏）。
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

const discipline = `## 铁律（不可违反）
1. 绝不编译目标项目本身; 只编译从目标提取的自包含 repro 文件。
2. 禁用裸 joern / joern-scan / codebase-memory-mcp, 必须经封装:
   - CPG 查询: audit-runner cpg query --cpg <cpg> --file <q.sc>
   - taint 模板: cpg.call.name("<sink>").reachableBy(cpg.method.name("<entry>").parameter)
   - 若 audit-runner 不在 PATH, 用绝对路径: ${AUDIT_RUNNER_FALLBACK}
3. 空结果（仅 INFO 行）→ 转 grep 兜底, 不重试白等。
4. 产物写到 ${runDir} 下对应子目录（先 mkdir -p）。
5. 结论必须逐跳验证: read/grep 确认每跳真实存在、无同名碰撞、类型匹配。
6. CPG 私有副本（fork, 并行防串行）: 先查 CPG 大小, 若 ≤100MB 运行
   audit-runner cpg fork --src ${cpg} --n 1 --dir ${runDir}/cpg-forks/ 取私有副本,
   之后所有 cpg query 一律用私有副本（并行 VALIDATE 免 flock 排队）; >100MB 或 fork 失败用共享 CPG。`;

// ---- 简化内联 schema（VALIDATE 返回仍走 parseAgentJson, schema 仅作文档/对照）----
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

const validateResults = await parallel(reachable.map((f) => () => {
  const fid = f.id;
  return agent(`你是 c-exploit（VALIDATE 阶段 Phase 1: EXPLOIT, 代码审计流水线段2, 模型 deliberate disagreement）。

先 read ${BRIEFS.exploit} 与 ${CODE_AUDIT} §6 确认与否证纪律, 再开始。

finding 待验证（HUNT REACHABLE, 含结构化 trace 字段）:
${JSON.stringify({ finding: f }, null, 2)}
目标: ${target}
产物目录: ${runDir}/validate/${fid}/ （先 mkdir -p）

${discipline}
${exportsBlock}
${tricksBlock}

执行顺序（铁律）:
1) **独立可达性挑战（2026-08-21 TRACE 并入 HUNT 后的补偿, 必做）**:
   HUNT 的 trace_result/call_chain/data_flow/defenses_checked/reachability_basis 是**待挑战假设**,
   不是定论。VALIDATE 是流水线唯一的独立第二视角——**不要盲信 HUNT 的 trace 字段**:
   自己 read sink、独立走一遍 entry→sink 链、独立检查每跳与防御（可用 audit-runner cpg query / grep 兜底）。
   否证**聚焦"机制能否真触发"**（输入/防御/环境前置是否成立）;
   - 若发现链被 HUNT 标错（实际不可达）→ status=killed, kill_category=unreachable_confirmed,
     kill_reason=<具体机制否证, 如 "HUNT 链第 N 跳实际无调用关系/输入被常量截断">;
   - 若机制本身在目标内静态/确定性不可触发（路径常量对调不影响实际部署、sink 无数据流、
     防御真实存在且不可绕过、目标自身写路径无法产出该输入）→ status=killed,
     kill_category=mechanism_disproven;
   - **全通纪律（不可违反, 2026-08-18）**: 对 reachability_basis=export-contract 的 finding,
     **禁止**以下列事实做否证前置或 kill 理由——它们都在重新引入"消费者不存在/非特权直连"假设,
     与"默认消费者树全通"相悖（F3 实证）:
     - "无树外消费者 / 无 in-tree 调用者 / 无特权消费者 / requires out-of-tree consumer"
       （消费方是外部事实, HUNT 已按 export-contract 判 REACHABLE, 默认存在消费者）;
     - "非特权直连 → 文件权限门 EACCES → 触发不可能"（调用者身份由消费者决定; 存在高权限中介
       （如 root 守护进程转发非特权请求）时, 文件权限门被中介 euid 绕过, 库缺鉴权校验即真漏洞）;
     - "no-gain / KILL-3 / 能写就直改"（仅当**调用者已具备与 sink 同等的写权限**时才成立;
       全通模型下非特权用户无写权限, 写权限在中介手里而中介信任库 → no-gain 不成立）;
2) 否证脚本 exit 0（finding 被证伪）→ status: killed + kill_reason: <具体原因>
3) 再写 SELF-CONTAINED repro（只提取自目标, 绝不编译整个项目）:
   C/C++: gcc -g -fsanitize=address,undefined repro.c -o repro && ./repro
   Python: python3 repro.py / Shell: bash repro.sh（解释执行, 无需 gcc）
4) 确认 = sanitizer/runtime 错误指向 sink: ASAN heap-buffer-overflow / use-after-free /
   valgrind invalid read / UBSAN shift exponent ...
5) 记录 build_config（完整编译命令）+ sanitizer_result（原始输出片段）+ run_log（exit code）+
   evidence_extracted（崩溃回溯/泄漏数据/权限变化）
6) 产物写 ${runDir}/validate/${fid}/（repro 源 + 编译产物 + 输出日志）
7) 权威校验: audit-runner gate --stage validation 对输出校验（casefile.py validate 包装）
8) 无法本地复现（需硬件/内核/网络对端/特定部署）→ status: env_blocked + kill_reason: <阻断原因>
   （**环境 blocked, 区别于硬 KILL**: 段2 返回独立 env_blocked[] 供段3/人工/LIVE 确认, 不进 killed）;
   注意: 对 export-contract finding, "本机/本环境无法复现"是 env_blocked 而非 killed, 不得据此否证。

返回 JSON（严格按契约）:
{finding_id, status: confirmed|killed|env_blocked, technique_used: asan|ubsan|valgrind|minimal-repro|manual-review,
 detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?,
 kill_reason?, kill_category?, refinement_attempts?}
条件: confirmed → poc_path/run_log/evidence_extracted 必填; killed → kill_reason 必填;
      env_blocked → kill_reason(阻断原因) 必填。
**输出格式铁律（2026-08-20, 违反即判失败）**: 最终回复必须是**一个裸 JSON 对象**——不要 Markdown 代码块围栏（\`\`\`json ... \`\`\`），不要 \`\`\` 或 \`\`\`json 包裹，不要前后缀说明文字。
**输出机制铁律（2026-08-20）**: 不要调用 structured_output / output_schema / JSON 输出工具，不要使用任何工具来输出结果；最终一条 assistant 消息必须是可直接 JSON.parse 的裸 JSON 对象。`,
    { label: `validate:${fid}`, phase: "validate", ...(MODELS.validate ? { model: MODELS.validate } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) }).then(parseAgentJson);
}));

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
  "无树外消费者", "无 in-tree 调用者", "无特权消费者", "no in-tree consumer",
  "no consumer", "requires out-of-tree consumer", "非特权直连", "unprivileged direct",
  "no-gain", "KILL-3", "能写就直改", "文件权限门", "file-mode gate",
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

function checkValidation(v, pair) {
  if (!v) return ["agent 失败(返回 null)"];
  if (v.status === "confirmed") {
    const missing = ["poc_path", "run_log", "evidence_extracted"].filter((k) => !v[k]);
    return missing.length ? missing.map((k) => `confirmed 缺 ${k}`) : [];
  }
  if (v.status === "killed") {
    const issues = [];
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
    agent(`你的 VALIDATE 输出未过条件门禁（缺口: ${checkValidation(v, pairOf(v)).join("; ")}）。
补上缺失字段（必要时重跑 repro 补证据, 已写产物勿重写）; 若命中"全通禁止"类 kill, 请在
"默认消费者树全通"语义下重写 kill_reason（聚焦机制本身）或改 status=env_blocked:
${JSON.stringify(v, null, 2)}
返回同一契约 JSON（confirmed → poc_path/run_log/evidence_extracted; killed → kill_reason;
      env_blocked → kill_reason 阻断原因）。
**输出格式铁律（2026-08-20, 违反即判失败）**: 最终回复必须是**一个裸 JSON 对象**——不要 Markdown 代码块围栏（\`\`\`json ... \`\`\`），不要 \`\`\` 或 \`\`\`json 包裹，不要前后缀说明文字。
**输出机制铁律（2026-08-20）**: 不要调用 structured_output / output_schema / JSON 输出工具，不要使用任何工具来输出结果；最终一条 assistant 消息必须是可直接 JSON.parse 的裸 JSON 对象。`,
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
  stats: { reachable: reachable.length, unreachable: unreachable.length, confirmed: confirmed.length, killed: killed.length, env_blocked: envBlocked.length, requires_external_verify: 0 },
  agents: { validate: validations.length, started: reachable.length + repairs },
};
