// skills/workflow-audit/chain-report.js — 段3: CHAIN → REPORT
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段3（无 fs 调度脚本，纯编排）
//
// 2026-08-21 v3: 适配 auditor+tracer 合并与 VALIDATE 分组 —— confirmed[] 是段2 返回的
//   扁平索引（finding 内含 trace 字段）, 没有独立 trace 对象 / trace_path; 直接消费
//   finding_id/vuln_class/file/line/sink/entry_point/attacker_model/impact/evidence/
//   reachability_basis/poc_path。
//
// 调用方式（主 agent read 本文件后作为 script 参数传入）:
//   workflow({
//     meta: {name: "code-audit-segment3",
//            description: "CHAIN→REPORT 审计段3",
//            phases: [{title:"chain"},{title:"report"}]},
//     script: <本文件内容>,
//     args: {target, confirmed, coverage?, runDir?, skillRoot?, models?}
//   })
//
// args 契约:
//   target          [必填] 目标源码绝对路径
//   confirmed       [必填] 段2 返回的 confirmed[]（扁平索引, 每个含 finding（内含 HUNT trace 字段）+validation, 无独立 trace 对象）
//   coverage        [可选] 段1 返回的 coverage[]（补进报告）
//   privilege_ctx   [可选] 段1 返回的 privilege_ctx（CVSS/severity 的确定性权限输入, 单一事实源）
//   external_context [可选] 审计员显式提供的生态知识（跨包链才启用, 非扫描）
//   runDir          [可选] 产物目录
//   skillRoot       [可选] 本仓库根
//   models          [可选] {chain?, report?} 模型覆盖（缺省 = 继承主 agent 模型; 需要更强/不同模型时显式传入）
//
// 设计要点:
//   * CHAIN: 1 个 agent 跨 confirmed 找组合链（≥2 步, 偏好本地提权链）;
//     默认只做树内链, 跨包链仅在有 external_context 时启用
//   * REPORT: 有 confirmed 时派 1 个 report agent 补 cwe_id/cvss（判断留 agent）;
//     CVSS 推导以 privilege_ctx 的 privilege/trigger 标签为确定性输入;
//     无 confirmed 时纯脚本聚合（零额外 token）
// ============================================================================

const SKILL_ROOT = args.skillRoot || "/home/xvmo/why-c-vulunerable";
const BRIEFS = { chain: `${SKILL_ROOT}/agents/chain.md` };
// 统一策略(2026-08-18): 全阶段缺省继承主 agent 模型(不传 model 即继承);
// 可经 args.models.chain/report 显式覆盖(需要更强/不同模型时再指定)
// 2026-08-20: 支持 args.models.provider 覆盖 provider（绕过 ark-coing-plan 配额 429）。
const MODELS = {
  provider: (args.models && args.models.provider) || null,
  chain: (args.models && args.models.chain) || null,
  report: (args.models && args.models.report) || null,
};

const target = args.target;
if (!target) throw new Error("args.target 必填");
const confirmed = args.confirmed || [];
const coverage = args.coverage || [];
const runDir = args.runDir || `${SKILL_ROOT}/workspace/runs/audit-seg3`;

// 权限上下文（preflight pctx 确定性产出）— CVSS/severity 的确定性输入; external_context 为审计员显式生态知识
const privilegeCtx = args.privilege_ctx || { privilege_context: "unknown", trigger_context: "unknown", signals: [], evidence_confidence: "low" };
const externalContext = args.external_context || "";
const pctxBlock = `## Privilege context (deterministic preflight pctx output, single source of truth)\nprivilege_context=${privilegeCtx.privilege_context} (trigger=${privilegeCtx.trigger_context || "unknown"}, confidence=${privilegeCtx.evidence_confidence || "low"})\n## All-pass semantics\nExport-contract entries (reachability_basis=export-contract) **default to having consumers, possibly privileged intermediaries** (a root daemon forwarding unprivileged requests). pctx=unknown is NOT evidence of "no consumer" — it only means the target itself has no fixed runtime privilege; for exported-API findings, do NOT conservatively downgrade severity because of pctx=unknown (see REPORT rules).`;
const externalBlock = externalContext
  ? `\n## External ecosystem knowledge (explicitly provided by the auditor; NOT a scan result)\n${externalContext}`
  : "";

// ---- 简化内联 schema ----
const CHAIN_SCHEMA = {
  type: "object",
  required: ["chains", "summary"],
  properties: {
    chains: {
      type: "array",
      items: {
        type: "object",
        required: ["title", "severity", "steps", "narrative"],
        properties: {
          title: { type: "string" },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          steps: { type: "array", items: { type: "string" } },
          narrative: { type: "string" },
          cwe_id: { type: "array", items: { type: "string" } },
          cvss_vector: { type: "string" },
          cvss_score: { type: "number" },
          blocked_by: { type: "array", items: { type: "string" } },
        },
      },
    },
    summary: { type: "string" },
  },
};

const REPORT_SCHEMA = {
  type: "object",
  required: ["findings", "summary"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "vuln_class", "file", "severity"],
        properties: {
          id: { type: "string" },
          vuln_class: { type: "string" },
          file: { type: "string" },
          severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
          language: { type: "string" },
          cwe_id: { type: "array", items: { type: "string" } },
          cvss_vector: { type: "string" },
          cvss_score: { type: "number" },
          poc_path: { type: "string" },
          summary: { type: "string" },
        },
      },
    },
    summary: { type: "string" },
  },
};

// ============================================================================
// Phase 1: CHAIN — 1 个 agent（仅在有 confirmed 时）
// ============================================================================
phase("chain");

let chainResult = { chains: [], summary: "no-confirmed-findings: 无已确认 finding, 无链分析" };
if (confirmed.length > 0) {
  log(`CHAIN: ${confirmed.length} 个 confirmed finding, 模型=${MODELS.chain || "继承主agent"}`);
  const brief = confirmed.map((c) => ({
    // 段2 返回的是产物索引(扁平字段, 复盘坑3/4: 不再手工抄大 JSON)
    id: c.finding_id,
    vuln_class: c.vuln_class,
    file: c.file,
    line: c.line,
    sink: c.sink,
    entry_point: c.entry_point,
    attacker_model: c.attacker_model,
    impact: c.impact,
    evidence: c.evidence,
    poc_path: c.poc_path,
    reachability_basis: c.reachability_basis || "",
    status: c.status,
  }));

  const chainRaw = await agent(`You are a c-chain (CHAIN stage, code audit pipeline, segment 3).

## Output contract (return this JSON; shown first on purpose)
{chains: [{title, severity: low|medium|high|critical, steps: string[](>=2), narrative,
           cwe_id?, cvss_vector?, cvss_score?, blocked_by?}], summary: string}

## Setup
First read ${BRIEFS.chain}, then start.

Target: ${target}
Confirmed findings (from VALIDATE, with sanitizer evidence):
${JSON.stringify(brief, null, 2)}
${pctxBlock}
${externalBlock}
Artifact directory: ${runDir}/chain/  (mkdir -p first, write chains.json)

## Tasks
1. Analyze combined attack chains across ALL confirmed findings (>=2 steps);
2. Prefer local privilege-escalation chains (e.g. info-disclosure + buffer-overflow in a setuid/root daemon);
   severity escalation of an LPE chain is judged against pctx's privilege_context (root/setuid high-privilege context -> higher chain value);
3. **Default in-tree chains + export-contract chains**: combine in-tree findings within the component; for confirmed findings with
   reachability_basis=export-contract, include their **external consumption path as an assumed chain step**
   (annotate reachability_basis=export-contract / specific consumer pending LIVE confirmation), do NOT drop the whole chain for lack of external_context —
   "export = committed external call surface", consumers default to existing; only when external_context is provided, refine
   concrete cross-package/cross-component consumer knowledge (never scan other components' source yourself);
4. Each chain: title / severity (escalated after combination) / steps (case ids in exploit order) / narrative /
   cwe_id / cvss_vector / cvss_score / blocked_by (production blockers; empty array if none);
5. Chain-analysis failure must not block — return empty chains + explanation.

Return the JSON contract shown at the top.`,
    { label: "chain", phase: "chain", schema: CHAIN_SCHEMA, ...(MODELS.chain ? { model: MODELS.chain } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) });
  if (chainRaw && Array.isArray(chainRaw.chains)) {
    chainResult = chainRaw;
  } else {
    chainResult = { chains: [], summary: "chain agent 失败或输出无效, 不阻塞报告" };
  }
}

// ============================================================================
// Phase 2: REPORT — 有 confirmed 派 report agent 补 CVSS; 无则纯聚合
// ============================================================================
phase("report");

let reportFindings;
let reportSummary;

if (confirmed.length > 0) {
  log(`REPORT: ${confirmed.length} 个 confirmed finding, 模型=${MODELS.report || "继承主agent"}`);
  const base = confirmed.map((c) => ({
    id: c.finding_id,
    vuln_class: c.vuln_class,
    file: c.file,
    line: c.line,
    sink: c.sink,
    language: (c.file || "").endsWith(".py") ? "python" : (c.file || "").endsWith(".sh") ? "shell" : "c",
    reachability_basis: c.reachability_basis || "",
    evidence: c.evidence,
    poc_path: c.poc_path,
    technique: c.technique_used || (c.status === "confirmed" ? "asan" : "manual-review"),
  }));
  const rep = await agent(`You are a REPORT analyst (code audit pipeline, segment 3).

## Output contract (return this JSON; shown first on purpose)
{findings: [{id, vuln_class, file, severity, language?, cwe_id?[], cvss_vector?, cvss_score?,
             poc_path?, summary?}], summary: string(overall)}

## Input
For the following sanitizer-confirmed findings, output report entries (fill in cwe_id/cvss_vector/cvss_score/severity/summary):
${JSON.stringify(base, null, 2)}
Target: ${target}
${pctxBlock}
Chain analysis: ${JSON.stringify(chainResult.chains, null, 2)}
Artifact directory: ${runDir}/report/  (mkdir -p first, write report.json)

## Rules
- cwe_id: precise CWE ids (e.g. CWE-787, CWE-416), possibly multiple
- cvss_vector: CVSS 3.1 vector (derived from attacker_model/entry_point/impact);
  **AV/PR/UI etc. use pctx's privilege_context/trigger_context as the deterministic input**:
  target high_privilege (root/setuid) -> PR usually L, even no prerequisite privilege; trigger=unprivileged_user -> AV leans N/L, else narrower.
  **All-pass discipline (mandatory)**: for findings with reachability_basis=export-contract,
  when pctx=unknown do NOT conservatively take PR:H (exported surfaces default to having consumers, possibly privileged intermediaries; pctx=unknown only
  means the target itself has no fixed runtime privilege, not "no consumer"). Take PR:L (the exported surface is reachable by an assumed consumer by default) or
  PR:N/A (pending external consumer knowledge); only findings with reachability_basis=in-tree / external-context use the actual in-tree/known caller for PR.
- severity: rate from cvss + context (info|low|medium|high|critical)
- summary: one sentence per finding (bug essence + trigger condition + impact)
- findings must map 1:1 with confirmed, ids unchanged

Return the JSON contract shown at the top.`,
    { label: "report", phase: "report", schema: REPORT_SCHEMA, ...(MODELS.report ? { model: MODELS.report } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) });
  if (rep && Array.isArray(rep.findings)) {
    reportFindings = rep.findings;
    reportSummary = rep.summary || "";
  } else {
    reportFindings = base.map((b) => ({ id: b.id, vuln_class: b.vuln_class, file: b.file, severity: "high" }));
    reportSummary = "report agent 失败, 输出降级为未富化的 confirmed 列表";
  }
} else {
  reportFindings = [];
  reportSummary = "无 confirmed finding — 本段无漏洞可报告";
}

// ---- 聚合最终报告 ----
const report = {
  target,
  pipeline_status: confirmed.length > 0 ? "complete" : "no-confirmed-findings",
  findings: reportFindings,
  coverage,
  chains: chainResult.chains,
  summary: reportSummary,
  generated_at: new Date().toISOString(),
};

// ============================================================================
// Phase 3: LEDGER（B 收尾落账）— 1 个 agent 把最终结果一次性写入 casefile 台账
//   不做全程状态机: 编号在收尾时一次性分配, 无跨段接力链
// ============================================================================
phase("ledger");

const CASEFILE_PY = "/home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py";
const LEDGER_SCHEMA = {
  type: "object",
  required: ["casefile_initialized", "report_path", "case_ids"],
  properties: {
    casefile_initialized: { type: "boolean" },
    report_path: { type: "string" },
    case_ids: { type: "array", items: { type: "string" } },
    notes: { type: "string" },
  },
};

const ledgerEntries = reportFindings.map((f) => ({
  id: f.id,
  title: `${f.vuln_class} @ ${f.file}:${f.line ?? ""}`.slice(0, 120),
  bug_class: f.vuln_class,
  file: f.file,
  line: f.line,
  severity: f.severity || "medium",
  evidence: (f.summary || f.cwe_id || f.cvss_vector || "").slice(0, 200),
  poc: f.poc_path || "",
}));

const ledger = await agent(`You are a ledger finisher (code audit pipeline, segment 3, one-shot bookkeeping).

## Output contract (return this JSON; shown first on purpose)
{casefile_initialized: bool, report_path: string("" if absent), case_ids: string[],
 notes?: string}

## Setup
Write the final audit results into the casefile ledger (${runDir}). casefile.py path: ${CASEFILE_PY}
(if absent, just report; do not block the pipeline.)

Target: ${target}
confirmed findings: ${JSON.stringify(ledgerEntries, null, 2)}
coverage: ${JSON.stringify(coverage, null, 2)}
chains: ${JSON.stringify(chainResult.chains, null, 2)}

## Steps (all via absolute-path python3; skip on failure, never block)
1. init (idempotent; skip if exists): python3 ${CASEFILE_PY} init ${runDir} --title "Pipeline: ${target}" --target "${target}"
2. add one case per confirmed finding:
   python3 ${CASEFILE_PY} add ${runDir} --title "<title>" --status confirmed --bug-class "<vuln_class>" \
     --target "${target}" --evidence "<evidence one line>" --field file=<file> --field line=<line> --field severity=<severity>
   (prefer the dedup wrapper: audit-runner ledger --run-dir ${runDir} --op add --title ... --bug-class ... --dedup-key <file>:<line>:<vuln_class>; it prints the case id);
   record each case id.
3. append an evidence log entry per case:
   python3 ${CASEFILE_PY} log ${runDir} <case_id> --stage REPORT --verdict confirmed --evidence "<one-line evidence>" [--artifact <poc path>]
4. at 0 confirmed: still init + log one summary entry (case_id "RUN", --stage REPORT --verdict done --evidence "no confirmed findings; coverage: <each cls=status>")
5. generate a readable report: python3 ${CASEFILE_PY} report ${runDir} --out ${runDir}/report/casefile-report.md

Return the JSON contract shown at the top.`,
  { label: "ledger", phase: "ledger", schema: LEDGER_SCHEMA, ...(MODELS.report ? { model: MODELS.report } : {}), ...(MODELS.provider ? { provider: MODELS.provider } : {}) });

log(`段3完成: chains=${chainResult.chains.length}, report findings=${reportFindings.length}, ledger=${ledger ? "ok" : "skipped"}`);

return {
  pipeline: "code-audit-segment3",
  status: "complete",
  target,
  report,
  ledger: ledger || { casefile_initialized: false, report_path: "", case_ids: [], notes: "ledger agent 失败, 台账未写" },
  agents: { chain: confirmed.length > 0 ? 1 : 0, report: confirmed.length > 0 ? 1 : 0, ledger: ledger ? 1 : 0 },
};
