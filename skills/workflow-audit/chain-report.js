// skills/workflow-audit/chain-report.js — 段3: CHAIN → REPORT
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段3（无 fs 调度脚本，纯编排）
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
//   target     [必填] 目标源码绝对路径
//   confirmed  [必填] 段2 返回的 confirmed[]（每个含 finding+trace+validation）
//   coverage   [可选] 段1 返回的 coverage[]（补进报告）
//   runDir     [可选] 产物目录
//   skillRoot  [可选] 本仓库根
//   models     [可选] {chain?, report?} 模型覆盖（chain 默认 deepseek-v4-flash）
//
// 设计要点:
//   * CHAIN: 1 个 agent 跨 confirmed 找组合链（≥2 步, 偏好本地提权链）
//   * REPORT: 有 confirmed 时派 1 个 report agent 补 cwe_id/cvss（判断留 agent）;
//             无 confirmed 时纯脚本聚合（零额外 token）
// ============================================================================

const SKILL_ROOT = args.skillRoot || "/home/xvmo/why-c-vulunerable";
const BRIEFS = { chain: `${SKILL_ROOT}/agents/chain.md` };
const MODELS = {
  chain: (args.models && args.models.chain) || "deepseek-v4-flash",
  report: (args.models && args.models.report) || "deepseek-v4-flash",
};

const target = args.target;
if (!target) throw new Error("args.target 必填");
const confirmed = args.confirmed || [];
const coverage = args.coverage || [];
const runDir = args.runDir || `${SKILL_ROOT}/workspace/runs/audit-seg3`;

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
  log(`CHAIN: ${confirmed.length} 个 confirmed finding, 模型=${MODELS.chain}`);
  const brief = confirmed.map((c) => ({
    id: c.validation.finding_id,
    vuln_class: c.finding.vuln_class,
    file: c.finding.file,
    line: c.finding.line,
    sink: c.finding.sink,
    entry_point: c.finding.entry_point,
    attacker_model: c.finding.attacker_model,
    impact: c.trace && c.trace.impact_if_reachable,
    evidence: c.validation.evidence_extracted || c.validation.detection_method,
    poc_path: c.validation.poc_path,
  }));

  const chainRaw = await agent(`你是 c-chain（CHAIN 阶段, 代码审计流水线段3）。

先 read ${BRIEFS.chain}, 再开始。

目标: ${target}
已确认 finding 列表（来自 VALIDATE, 含 sanitizer 证据）:
${JSON.stringify(brief, null, 2)}
产物目录: ${runDir}/chain/ （先 mkdir -p, 写 chains.json）

本任务:
1. 分析所有 confirmed finding 间的组合攻击链（跨 finding, ≥2 步）;
2. 偏好本地提权链（如 info-disclosure + buffer-overflow in setuid/root daemon）;
3. 每条链: title / severity(组合后升级) / steps(按利用顺序的 case id) / narrative /
   cwe_id / cvss_vector / cvss_score / blocked_by(生产环境阻断项, 无则空数组);
4. 链分析失败不阻塞 — 返回空 chains + 说明即可。

返回 JSON（严格按契约）:
{chains: [{title, severity: low|medium|high|critical, steps: string[](≥2), narrative,
           cwe_id?, cvss_vector?, cvss_score?, blocked_by?}], summary: string}`,
    { label: "chain", phase: "chain", schema: CHAIN_SCHEMA, model: MODELS.chain });
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
  log(`REPORT: ${confirmed.length} 个 confirmed finding, 模型=${MODELS.report}`);
  const base = confirmed.map((c) => ({
    id: c.validation.finding_id,
    vuln_class: c.finding.vuln_class,
    file: c.finding.file,
    line: c.finding.line,
    sink: c.finding.sink,
    language: c.finding.language || (c.finding.file.endsWith(".py") ? "python" : c.finding.file.endsWith(".sh") ? "shell" : "c"),
    evidence: c.validation.evidence_extracted || c.validation.sanitizer_result || c.validation.detection_method,
    poc_path: c.validation.poc_path,
    technique: c.validation.technique_used,
  }));
  const rep = await agent(`你是 REPORT 分析师（代码审计流水线段3）。

对以下 sanitizer-confirmed finding 输出报告条目（补 cwe_id/cvss_vector/cvss_score/severity/summary）:
${JSON.stringify(base, null, 2)}
目标: ${target}
链分析: ${JSON.stringify(chainResult.chains, null, 2)}
产物目录: ${runDir}/report/ （先 mkdir -p, 写 report.json）

规则:
- cwe_id: 精确 CWE 标识（如 CWE-787, CWE-416）, 可多个
- cvss_vector: CVSS 3.1 向量（按 attacker_model/entry_point/impact 推导）
- severity: 按 cvss 与上下文定级 (info|low|medium|high|critical)
- summary: 每 finding 一句话（漏洞本质 + 触发条件 + 影响）
- findings 与 confirmed 一一对应, id 不变

返回 JSON（严格按契约）:
{findings: [{id, vuln_class, file, severity, language?, cwe_id?[], cvss_vector?, cvss_score?,
             poc_path?, summary?}], summary: string(整体总结)}`,
    { label: "report", phase: "report", schema: REPORT_SCHEMA, model: MODELS.report });
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

const ledger = await agent(`你是 ledger 收尾员（代码审计流水线段3, 一次性落账）。

把最终审计结果写入 casefile 台账（${runDir}）。casefile.py 路径: ${CASEFILE_PY}
（若不存在, 报告即可; 不阻塞流水线。）

目标: ${target}
confirmed findings: ${JSON.stringify(ledgerEntries, null, 2)}
coverage: ${JSON.stringify(coverage, null, 2)}
链: ${JSON.stringify(chainResult.chains, null, 2)}

步骤（全部用绝对路径 python3 调用, 失败就跳过继续, 不阻塞）:
1. init（幂等, 已存在则跳过）: python3 ${CASEFILE_PY} init ${runDir} --title "Pipeline: ${target}" --target "${target}"
2. 每个 confirmed finding add 一条案件:
   python3 ${CASEFILE_PY} add ${runDir} --title "<title>" --status confirmed --bug-class "<vuln_class>" \\
     --target "${target}" --evidence "<evidence 一行>" --field file=<file> --field line=<line> --field severity=<severity>
   （推荐用包装器自动去重: audit-runner ledger --run-dir ${runDir} --op add --title ... --bug-class ... --dedup-key <file>:<line>:<vuln_class>, 它会打印 case id）;
   记录每个 case id。
3. 每 case 追加证据日志:
   python3 ${CASEFILE_PY} log ${runDir} <case_id> --stage REPORT --verdict confirmed --evidence "<一句话证据>" [--artifact <poc 路径>]
4. 0 confirmed 时: 也 init + log 一条 summary 记录（case_id 用 "RUN", --stage REPORT --verdict done --evidence "no confirmed findings; coverage: <各 cls=status>"）
5. 生成可读报告: python3 ${CASEFILE_PY} report ${runDir} --out ${runDir}/report/casefile-report.md

返回 JSON（严格按契约）:
{casefile_initialized: bool, report_path: string(不存在则空串), case_ids: string[],
 notes?: string}`,
  { label: "ledger", phase: "ledger", schema: LEDGER_SCHEMA, model: MODELS.report });

log(`段3完成: chains=${chainResult.chains.length}, report findings=${reportFindings.length}, ledger=${ledger ? "ok" : "skipped"}`);

return {
  pipeline: "code-audit-segment3",
  status: "complete",
  target,
  report,
  ledger: ledger || { casefile_initialized: false, report_path: "", case_ids: [], notes: "ledger agent 失败, 台账未写" },
  agents: { chain: confirmed.length > 0 ? 1 : 0, report: confirmed.length > 0 ? 1 : 0, ledger: ledger ? 1 : 0 },
};
