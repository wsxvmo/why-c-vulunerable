// skills/workflow-audit/audit-pipeline.js — 段1: RECON → HUNT → GAPFIL
// ============================================================================
// DSH workflow 无主-agent 审计流水线 · 段1（无 fs 调度脚本，纯编排）
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
//   classes    [可选] CWE 类列表（默认 ["buffer-overflow","command-injection"]）
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

const target = args.target;
if (!target) throw new Error("args.target 必填: 目标源码绝对路径");
const runDir = args.runDir || (() => {
  const base = (target.split("/").filter(Boolean).pop() || "audit").replace(/[^A-Za-z0-9._-]/g, "_");
  return `${SKILL_ROOT}/workspace/runs/audit-${base}`;
})();

// 骨架默认 2 类, 跑通后由调用方传入更多
const classes = (args.classes && args.classes.length)
  ? args.classes
  : ["buffer-overflow", "command-injection"];

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
};

const discipline = `## 铁律（不可违反）
1. 绝不编译目标项目本身; 只用 read/grep/静态查询/CPG。
2. 禁用裸 joern / joern-scan / codebase-memory-mcp 命令, 必须经封装（防挂起/防踩坑）:
   - CPG 构建:      audit-runner cpg build --root <绝对路径>
   - CPG 查询:      audit-runner cpg query --cpg <cpg> --file <q.sc>   （println/降级已内置）
   - querydb 扫描:  audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>
   - codebase-memory: audit-tools cli codebase_query --tool <t> <args...>
   - 若 audit-runner 不在 PATH, 用绝对路径: ${AUDIT_RUNNER_FALLBACK}
3. 空结果（仅 INFO 行）→ 转 grep 兜底, 不重试白等。
4. 产物写到 ${runDir} 下对应子目录（先 mkdir -p）。
5. 自限: 单 agent 最多查 3 个入口点, 超出部分列入 unchecked 交回, 绝不无限扩展。`;

// ---- 简化内联 schema（agent() 只支持 type/properties/required/items/enum/const/oneOf）----
const RECON_SCHEMA = {
  type: "object",
  required: ["languages", "entry_points", "cpg_path", "toolchain", "assumptions"],
  properties: {
    languages: { type: "array", items: { type: "string" } },
    entry_points: { type: "array", items: { type: "string" } },
    cpg_path: { type: "string" },
    toolchain: { type: "object" },
    assumptions: { type: "array", items: { type: "string" } },
  },
};

const FINDING_ITEM_SCHEMA = {
  type: "object",
  required: ["vuln_class", "file", "line", "sink", "entry_point", "confidence", "evidence"],
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

const REQUIRED_FIELDS = ["vuln_class", "file", "line", "sink", "entry_point", "confidence", "evidence"];

// ============================================================================
// Phase 1: RECON — 1 个 agent
// ============================================================================
phase("recon");
log(`RECON: ${target}`);

const recon = await agent(`你是 RECON 协调员（代码审计流水线段1）。

先 read ${BRIEFS.harness} 与 ${SKILL_ROOT}/skills/pipeline/SKILL.md 的 Prerequisites 部分, 再执行。

目标: ${target}
产物目录: ${runDir}/recon/ （先 mkdir -p）

${discipline}

本任务:
1. 跑 audit-runner doctor（5 项健康检查: skill-tree/preset/schemas/toolchain/cache）, 记录 toolchain 可用性;
2. 构建 CPG: audit-runner cpg build --root ${target} （fuzzy 模式, 绝不编译目标; 缓存命中则复用）;
3. 图基枚举入口点（禁手工 grep 全库枚举）:
   首选 audit-tools cli codebase_query --tool search_graph（若 codebase-memory 已索引该目标）;
   否则 audit-runner cpg query --cpg <cpg> --file ${QUERIES}/entry.sc;
   对每个候选, 用 read/grep 确认语义（main/回调/信号/dbus 注册/导出表/exec 入口）, 记录最终入口点列表;
4. 记录语言分布（c/cpp/shell/python）与权限上下文（是否 setuid/root 守护进程）。
5. 把 recon.json（上述字段）写到 ${runDir}/recon/recon.json。

返回 JSON（严格按契约）:
{languages: string[], entry_points: string[], cpg_path: string,
 toolchain: {doctor: string, joern: string, ...}, assumptions: string[]}`,
  { label: "recon", phase: "recon", schema: RECON_SCHEMA });

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
log(`RECON 完成: ${recon.languages.join("/")}, ${recon.entry_points.length} 个入口点, CPG=${recon.cpg_path}`);

// ============================================================================
// Phase 2: HUNT — 每 CWE 类 1 个 agent, parallel 并发 ≤6
// ============================================================================
phase("hunt");

const huntResults = await parallel(classes.map((cls) => () =>
  agent(`你是 c-auditor（HUNT 阶段, 代码审计流水线段1）。

先 read ${BRIEFS.auditor} 与 ${CODE_AUDIT} 的 ${CLASS_SECTIONS[cls] || cls} 章节, 再开始猎杀。

目标: ${target}
猎杀类: ${cls}
RECON 认定的入口点: ${JSON.stringify(recon.entry_points)}
CPG: ${recon.cpg_path}
产物目录: ${runDir}/hunt/${cls}/ （先 mkdir -p）

${discipline}

本任务（自限: 最多查 3 个入口点）:
1. 引擎（必跑, 经封装）:
   - audit-runner cpg query --cpg ${recon.cpg_path} --file ${QUERIES}/sinks.sc 取候选;
   - audit-tools cli scan_cpg --cpg ${recon.cpg_path} --tags <该类对应 cwe>（querydb 全库扫描）;
2. 每个候选必须 read/grep 逐跳验证（entry→sink 真实存在、无同名碰撞、类型匹配、防御绕过与否）;
3. 只输出有证据链的 finding; 每个入口点的检查结果记入 checked/unchecked;
4. 把 findings.json + 证据片段写到 ${runDir}/hunt/${cls}/。

返回 JSON（严格按契约）:
{cls: string, findings: [{vuln_class, file, line(整数), sink, entry_point,
  confidence: low|medium|high, evidence(entry→sink 一句话+代码片段), subsystem?, attacker_model?}],
 checked: string[], unchecked: string[], notes?: string}`,
    { label: `hunt:${cls}`, phase: "hunt", schema: HUNT_SCHEMA })
));

// ============================================================================
// Phase 3: GAPFIL — 最小循环: 对 INCOMPLETE 类补查 1 轮
// ============================================================================
phase("gapfill");

let results = huntResults.filter(Boolean);
const gapfillRounds = 1;
let roundsDone = 0;

const incompleteFirst = results.filter((r) => r.unchecked && r.unchecked.length > 0);
if (incompleteFirst.length > 0 && roundsDone < gapfillRounds) {
  roundsDone++;
  log(`GAPFIL 第 1 轮: ${incompleteFirst.map((r) => r.cls).join(", ")}`);
  const gap = await parallel(incompleteFirst.map((r) => () =>
    agent(`你是 c-auditor（GAPFIL 补查 ${r.cls}, 代码审计流水线段1）。

先 read ${BRIEFS.auditor} 与 ${CODE_AUDIT} 的 ${CLASS_SECTIONS[r.cls] || r.cls} 章节。

目标: ${target}
CPG: ${recon.cpg_path}
产物目录: ${runDir}/hunt/${r.cls}/ （追加写入）

${discipline}

上一轮覆盖情况:
- 已检查（勿重复）: ${JSON.stringify(r.checked || [])}
- 未检查（逐一检查）: ${JSON.stringify(r.unchecked || [])}

返回 JSON（严格按契约, 同 HUNT）:
{cls: string, findings: [...], checked: string[], unchecked: string[], notes?: string}`,
      { label: `gapfill:${r.cls}`, phase: "gapfill", schema: HUNT_SCHEMA })
  ));
  // 合并: 用补查结果替换原结果
  results = results.map((old) => {
    const g = gap.find((x) => x && x.cls === old.cls);
    return g || old;
  });
}

// ============================================================================
// 聚合 + 结构门禁（agent() schema 之外的深度校验在脚本内做）
// ============================================================================
const findings = results.flatMap((r) => (r.findings || []).map((f) => ({ ...f, cls: r.cls })));

const valid = [];
const invalid = [];
for (const f of findings) {
  const missing = REQUIRED_FIELDS.filter((k) => f[k] === undefined || f[k] === null || f[k] === "");
  if (missing.length === 0) {
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

const coverage = results.map((r) => {
  const hasUnchecked = r.unchecked && r.unchecked.length > 0;
  const hypotheses = (r.findings || []).length;
  return {
    cls: r.cls,
    status: hasUnchecked ? "INCOMPLETE" : (hypotheses > 0 ? "COVERED" : "NOT_FOUND"),
    checked: r.checked || [],
    unchecked: r.unchecked || [],
    hypotheses,
  };
});

log(`段1完成: ${valid.length} 个有效 finding, ${invalid.length} 个未过门禁, 覆盖: ${coverage.map((c) => `${c.cls}=${c.status}`).join(", ")}`);

return {
  pipeline: "code-audit-segment1",
  status: "complete",
  target,
  runDir,
  findings: valid,
  coverage,
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
    gapfill: roundsDone,
    started: 1 + huntResults.length + roundsDone,
  },
};
