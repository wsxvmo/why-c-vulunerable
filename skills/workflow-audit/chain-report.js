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
const pctxBlock = `## 权限上下文（preflight pctx 确定性产出, 单一事实源）\nprivilege_context=${privilegeCtx.privilege_context} (trigger=${privilegeCtx.trigger_context || "unknown"}, confidence=${privilegeCtx.evidence_confidence || "low"})\n## 全通语义（2026-08-18）\n导出契约入口（reachability_basis=export-contract）**默认存在消费者, 且消费者可能是高权限中介**（root 守护进程转发非特权请求）。pctx=unknown **不构成"无消费者"证据**——它只说明目标自身无固定运行权限; 对导出 API finding, 严重度不得因 pctx=unknown 保守降级（见 REPORT 规则）。`;
const externalBlock = externalContext
  ? `\n## 外部生态知识（审计员显式提供, 非扫描结果）\n${externalContext}`
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

  const chainRaw = await agent(`你是 c-chain（CHAIN 阶段, 代码审计流水线段3）。

先 read ${BRIEFS.chain}, 再开始。

目标: ${target}
已确认 finding 列表（来自 VALIDATE, 含 sanitizer 证据）:
${JSON.stringify(brief, null, 2)}
${pctxBlock}
${externalBlock}
产物目录: ${runDir}/chain/ （先 mkdir -p, 写 chains.json）

本任务:
1. 分析所有 confirmed finding 间的组合攻击链（跨 finding, ≥2 步）;
2. 偏好本地提权链（如 info-disclosure + buffer-overflow in setuid/root daemon）;
   本地提权链的严重性升级判断以 pctx 的 privilege_context 为基准（root/setuid 高权限上下文 → 链价值更高）;
3. **默认树内链 + 导出契约链（2026-08-18）**: 树内链按组件内 finding 组合; 对
   reachability_basis=export-contract 的 confirmed finding, 其**外部消费路径作为假设链步纳入**
   （标注 reachability_basis=export-contract / 具体消费者待 LIVE 确认）, **不因缺 external_context
   整条丢弃**——"导出即承诺外部调用面", 消费者默认存在; 仅当 external_context 提供时才细化
   具体跨包/跨组件消费者知识（不得自行扫描其他组件源码）;
4. 每条链: title / severity(组合后升级) / steps(按利用顺序的 case id) / narrative /
   cwe_id / cvss_vector / cvss_score / blocked_by(生产环境阻断项, 无则空数组);
5. 链分析失败不阻塞 — 返回空 chains + 说明即可。

返回 JSON（严格按契约）:
{chains: [{title, severity: low|medium|high|critical, steps: string[](≥2), narrative,
           cwe_id?, cvss_vector?, cvss_score?, blocked_by?}], summary: string}`,
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
  const rep = await agent(`你是 REPORT 分析师（代码审计流水线段3）。

对以下 sanitizer-confirmed finding 输出报告条目（补 cwe_id/cvss_vector/cvss_score/severity/summary）:
${JSON.stringify(base, null, 2)}
目标: ${target}
${pctxBlock}
链分析: ${JSON.stringify(chainResult.chains, null, 2)}
产物目录: ${runDir}/report/ （先 mkdir -p, 写 report.json）

规则:
- cwe_id: 精确 CWE 标识（如 CWE-787, CWE-416）, 可多个
- cvss_vector: CVSS 3.1 向量（按 attacker_model/entry_point/impact 推导）;
  **AV/PR/UI 等维度以 pctx 的 privilege_context/trigger_context 为确定性输入**:
  目标 high_privilege（root/setuid）→ PR 通常取 L 甚至无需先决权限; trigger=unprivileged_user → AV 偏 N/L, 反之收窄
  **全通纪律（2026-08-18, 不可违反）**: 对 reachability_basis=export-contract 的 finding,
  pctx=unknown 时 **不得保守取 PR:H**（导出契约默认存在消费者, 可能高权限中介; pctx=unknown 只是
  目标自身无固定运行权限, 不是"无消费者"证据）。取 PR:L（导出面默认可由已存在消费者到达）或
  PR:N/A（待外部消费者知识确认后定）; 仅 reachability_basis=in-tree / external-context 的 finding
  才按实际树内/已知调用者定 PR。
- severity: 按 cvss 与上下文定级 (info|low|medium|high|critical)
- summary: 每 finding 一句话（漏洞本质 + 触发条件 + 影响）
- findings 与 confirmed 一一对应, id 不变

返回 JSON（严格按契约）:
{findings: [{id, vuln_class, file, severity, language?, cwe_id?[], cvss_vector?, cvss_score?,
             poc_path?, summary?}], summary: string(整体总结)}`,
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
