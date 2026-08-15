// skills/workflow-audit/trace-validate.js — 段2: TRACE → VALIDATE
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段2（无 fs 调度脚本，纯编排）
//
// 调用方式（主 agent read 本文件后作为 script 参数传入）:
//   workflow({
//     meta: {name: "code-audit-segment2",
//            description: "TRACE→VALIDATE 审计段2",
//            phases: [{title:"trace"},{title:"validate"}]},
//     script: <本文件内容>,
//     args: {target, findings, cpg_path, runDir?, skillRoot?, models?}
//   })
//
// args 契约:
//   target     [必填] 目标源码绝对路径（与段1一致）
//   findings   [必填] 段1 返回的 findings[]（每个含 vuln_class/file/line/sink/entry_point/
//                    confidence/evidence/subsystem/attacker_model/cls）
//   cpg_path   [必填] 段1 recon 构建的 CPG 路径
//   runDir     [可选] 产物目录（建议与段1相同 runDir，子目录区分）
//   skillRoot  [可选] 本仓库根
//   models     [可选] {trace?, validate?} 模型覆盖（deliberate disagreement:
//                    trace=deepseek-v4-pro, validate=deepseek-v4-pro 默认）
//
// 设计要点:
//   * KILL 税（code-audit §10）作为 TRACE agent 的第一步内置, 不额外派 agent
//   * TRACE: 每 finding 1 agent, cpg taint 查询 → 逐跳验证 → data_flow 值级路径
//   * VALIDATE: 每 REACHABLE finding 1 agent, 否证优先 + 自包含 repro + sanitizer
//   * 条件必填（confirmed→poc_path 等）在脚本内二次检查, repair ≤2
// ============================================================================

const SKILL_ROOT = args.skillRoot || "/home/xvmo/why-c-vulunerable";
const AUDIT_RUNNER_FALLBACK = "/home/xvmo/.local/bin/audit-runner";
const BRIEFS = {
  tracer: `${SKILL_ROOT}/agents/tracer.md`,
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

// 段1 findings 无 id — 分配稳定 id（F1..Fn），trace/validate 以 finding_id 关联
const items = findings.map((f, i) => ({ ...f, id: f.id || `F${i + 1}` }));

// deliberate disagreement: trace/validate 用更强/不同模型（可经 args 覆盖）
const MODELS = {
  trace: (args.models && args.models.trace) || "deepseek-v4-pro",
  validate: (args.models && args.models.validate) || "deepseek-v4-pro",
};

const discipline = `## 铁律（不可违反）
1. 绝不编译目标项目本身; 只编译从目标提取的自包含 repro 文件。
2. 禁用裸 joern / joern-scan / codebase-memory-mcp, 必须经封装:
   - CPG 查询: audit-runner cpg query --cpg <cpg> --file <q.sc>
   - taint 模板: cpg.call.name("<sink>").reachableBy(cpg.method.name("<entry>").parameter)
   - 若 audit-runner 不在 PATH, 用绝对路径: ${AUDIT_RUNNER_FALLBACK}
3. 空结果（仅 INFO 行）→ 转 grep 兜底, 不重试白等。
4. 产物写到 ${runDir} 下对应子目录（先 mkdir -p）。
5. 结论必须逐跳验证: read/grep 确认每跳真实存在、无同名碰撞、类型匹配。`;

// ---- 简化内联 schema ----
const TRACE_SCHEMA = {
  type: "object",
  required: ["finding_id", "trace_result", "entry_point", "call_chain", "data_flow", "defenses_checked", "attacker_model"],
  properties: {
    finding_id: { type: "string" },
    trace_result: { type: "string", enum: ["REACHABLE", "UNREACHABLE", "KILLED"] },
    entry_point: { type: "string" },
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
    attacker_model: { type: "string" },
    impact_if_reachable: { type: "string" },
    unreachable_reason: { type: "string" },
    kill_reason: { type: "string" },
  },
};

const VALIDATION_SCHEMA = {
  type: "object",
  required: ["finding_id", "status", "technique_used", "detection_method"],
  properties: {
    finding_id: { type: "string" },
    status: { type: "string", enum: ["confirmed", "killed"] },
    technique_used: { type: "string", enum: ["asan", "ubsan", "valgrind", "minimal-repro", "manual-review"] },
    detection_method: { type: "string" },
    build_config: { type: "string" },
    sanitizer_result: { type: "string" },
    poc_path: { type: "string" },
    run_log: { type: "string" },
    evidence_extracted: { type: "string" },
    kill_reason: { type: "string" },
    refinement_attempts: { type: "integer" },
  },
};

// ============================================================================
// Phase 1: TRACE — 每 finding 1 个 agent（含 KILL 税前置门禁）
// ============================================================================
phase("trace");
log(`TRACE: ${findings.length} 个 finding, 模型=${MODELS.trace}`);

const traceResults = await parallel(items.map((f) => () => {
  const fid = `${f.file}:${f.line}:${f.sink}`.replace(/[^A-Za-z0-9._:-]/g, "_");
  return agent(`你是 c-tracer（TRACE 阶段, 代码审计流水线段2, 模型 deliberate disagreement）。

先 read ${BRIEFS.tracer} 与 ${SKILL_ROOT}/skills/pipeline/SKILL.md 的 TRACE 部分, 再开始。

finding 待追踪（finding_id 用本对象 id 字段的值, 原样返回）:
${JSON.stringify(f, null, 2)}
CPG: ${cpg}
产物目录: ${runDir}/trace/${fid}/ （先 mkdir -p）

${discipline}

执行顺序:
0) KILL 税前置门禁（30 秒, 不跳过）— 先于任何 trace 预算:
   KILL-1 攻击者进程外的调用者无法以攻击者可控数据到达 sink?（不可达/自攻击）
   KILL-2 已发布版本已修复（BUG#/changelog/补丁 diff）?
   KILL-3 结果不跨攻击者缺乏的权限/信任边界?（无收益）
   KILL-4 授权身份可伪造（argv/cmdline/env/cache-key）?（若是, 升优先级, 不是 kill）
   任一命中 KILL-1/2/3 → 返回 {finding_id, trace_result: "KILLED", kill_reason: "KILL-x: <一句话>"}, 不花 trace 预算。
1) 未 kill → 跑 taint 查询（经 audit-runner, 禁裸 joern）:
   audit-runner cpg query --cpg ${cpg} --file <taint.sc> --timeout 240
   taint 模板: cpg.call.name("<sink>").reachableBy(cpg.method.name("<entry>").parameter)
2) Joern 输出仅候选 — 每跳 read/grep 逐符号验证（真实存在/无同名碰撞/类型匹配）;
   记录 data_flow 值级路径（如 argv[1] → strlen(x)+1 → memcpy(dst,src,n)）。
3) 检查路径上每个防御（长度检查/沙箱/LSM 顺序/已有等价机制）, 记入 defenses_checked。
4) 产物写 ${runDir}/trace/${fid}/trace.json。

返回 JSON（严格按契约）:
{finding_id, trace_result: REACHABLE|UNREACHABLE|KILLED, entry_point, call_chain: string[],
 data_flow, defenses_checked: [{defense, location, verdict: bypassed|blocked|not-present}],
 attacker_model, impact_if_reachable?, unreachable_reason?, kill_reason?}
条件: REACHABLE → impact_if_reachable 必填; UNREACHABLE → unreachable_reason 必填; KILLED → kill_reason 必填。`,
    { label: `trace:${fid}`, phase: "trace", schema: TRACE_SCHEMA, model: MODELS.trace });
}));

const traced = traceResults.filter(Boolean);
const reachable = traced.filter((t) => t.trace_result === "REACHABLE");
const unreachable = traced.filter((t) => t.trace_result === "UNREACHABLE");
const killedByGate = traced.filter((t) => t.trace_result === "KILLED");
log(`TRACE 完成: REACHABLE=${reachable.length}, UNREACHABLE=${unreachable.length}, KILLED=${killedByGate.length}`);

// ============================================================================
// Phase 2: VALIDATE — 每 REACHABLE finding 1 个 agent（否证优先 + sanitizer）
// ============================================================================
phase("validate");
log(`VALIDATE: ${reachable.length} 个 REACHABLE finding, 模型=${MODELS.validate}`);

const validateResults = await parallel(reachable.map((t) => () => {
  const f = items.find((x) => x.id === t.finding_id) || { finding_id: t.finding_id };
  const fid = t.finding_id;
  return agent(`你是 c-exploit（VALIDATE 阶段 Phase 1: EXPLOIT, 代码审计流水线段2, 模型 deliberate disagreement）。

先 read ${BRIEFS.exploit} 与 ${CODE_AUDIT} §6 确认与否证纪律, 再开始。

finding 待验证（TRACE REACHABLE）:
${JSON.stringify({ finding: f, trace: t }, null, 2)}
目标: ${target}
产物目录: ${runDir}/validate/${fid}/ （先 mkdir -p）

${discipline}

执行顺序（铁律）:
1) 先写 DISCONFIRMATION 路径（比确认 PoC 便宜）— 证明触发"不可能"的脚本/确定性论证;
   若否证脚本 exit 0（finding 被证伪）→ status: killed + kill_reason: <KILL-5 或具体原因>
2) 再写 SELF-CONTAINED repro（只提取自目标, 绝不编译整个项目）:
   C/C++: gcc -g -fsanitize=address,undefined repro.c -o repro && ./repro
   Python: python3 repro.py / Shell: bash repro.sh（解释执行, 无需 gcc）
3) 确认 = sanitizer/runtime 错误指向 sink: ASAN heap-buffer-overflow / use-after-free /
   valgrind invalid read / UBSAN shift exponent ...
4) 记录 build_config（完整编译命令）+ sanitizer_result（原始输出片段）+ run_log（exit code）+
   evidence_extracted（崩溃回溯/泄漏数据/权限变化）
5) 产物写 ${runDir}/validate/${fid}/（repro 源 + 编译产物 + 输出日志）
6) 权威校验: audit-runner gate --stage validation 对输出校验（casefile.py validate 包装）
7) 无法本地复现（需硬件/内核/网络对端）→ status: killed + kill_reason: sanitizer_no_trigger
   （环境 blocked, 区别于硬 KILL; 在聚合报告里单列）

返回 JSON（严格按契约）:
{finding_id, status: confirmed|killed, technique_used: asan|ubsan|valgrind|minimal-repro|manual-review,
 detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?,
 kill_reason?, refinement_attempts?}
条件: confirmed → poc_path/run_log/evidence_extracted 必填; killed → kill_reason 必填。`,
    { label: `validate:${fid}`, phase: "validate", schema: VALIDATION_SCHEMA, model: MODELS.validate });
}));

// ============================================================================
// 条件门禁（agent() schema 不支持 if/then — 脚本内二次检查 + repair ≤2）
// ============================================================================
function checkValidation(v) {
  if (!v) return ["agent 失败(返回 null)"];
  if (v.status === "confirmed") {
    const missing = ["poc_path", "run_log", "evidence_extracted"].filter((k) => !v[k]);
    return missing.length ? missing.map((k) => `confirmed 缺 ${k}`) : [];
  }
  if (v.status === "killed") return v.kill_reason ? [] : ["killed 缺 kill_reason"];
  return [`未知 status: ${v.status}`];
}

let validations = validateResults.filter(Boolean);
let repairs = 0;
const MAX_REPAIRS = 2;

while (repairs < MAX_REPAIRS) {
  const bad = validations.filter((v) => checkValidation(v).length > 0);
  if (bad.length === 0) break;
  repairs++;
  log(`VALIDATE repair #${repairs}: ${bad.map((v) => v.finding_id).join(", ")}`);
  const fixed = await parallel(bad.map((v) => () =>
    agent(`你的 VALIDATE 输出未过条件门禁（缺口: ${checkValidation(v).join("; ")}）。
补上缺失字段（必要时重跑 repro 补证据, 已写产物勿重写）:
${JSON.stringify(v, null, 2)}
返回同一契约 JSON（confirmed → poc_path/run_log/evidence_extracted; killed → kill_reason）。`,
      { label: `validate-repair:${v.finding_id}`, phase: "validate", schema: VALIDATION_SCHEMA, model: MODELS.validate })
  ));
  validations = validations.map((old) => {
    const fx = fixed.find((x) => x && x.finding_id === old.finding_id);
    return fx || old;
  });
}

const gateFail = validations.filter((v) => checkValidation(v).length > 0);
const confirmed = [];
const killed = [];
for (const v of validations) {
  const t = reachable.find((x) => x.finding_id === v.finding_id);
  const f = findings.find((x) => x.id === v.finding_id) || { finding_id: v.finding_id };
  const entry = { finding: f, trace: t, validation: v };
  if (v.status === "confirmed") confirmed.push(entry);
  else killed.push(entry);
}

log(`段2完成: confirmed=${confirmed.length}, killed=${killed.length}, gateFail=${gateFail.length}`);

return {
  pipeline: "code-audit-segment2",
  status: "complete",
  target,
  confirmed,
  killed,
  gate: {
    repairs,
    gate_fail_count: gateFail.length,
    gate_fail: gateFail.map((v) => ({ finding_id: v.finding_id, issues: checkValidation(v) })),
  },
  stats: { traced: traced.length, reachable: reachable.length, unreachable: unreachable.length, killed_by_gate: killedByGate.length },
  agents: { trace: traced.length, validate: validations.length, started: traceResults.length + validations.length + repairs },
};
