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
  "spoofable-identity": "§3.1a spoofable-identity (CWE-287/269) — 身份信任边界, 命中即升优先级",
  "shell-injection": "§5.1 shell-injection (CWE-78)",
  "eval-injection": "§6.1 eval-injection (CWE-95/94)",
  "unsafe-deserialization": "§6.2 unsafe-deserialization (CWE-502)",
  "toctou": "§2.5 race-condition / toctou (CWE-362/367) — 独立键, 与 race-condition 共享方法论",
  "memory-leak": "§7.1 resource-leak / memory-leak (CWE-401/404/775)",
  "resource-leak": "§7.1 resource-leak / memory-leak (CWE-401/404/775)",
  "crypto-weakness": "§7.2 crypto-weakness (CWE-327/328)",
  "info-disclosure": "§7.3 info-disclosure (CWE-200)",
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

const recon = await agent(`你是 RECON 协调员（代码审计流水线段1）。

先 read ${BRIEFS.harness} 与 ${SKILL_ROOT}/skills/pipeline/SKILL.md 的 Prerequisites 部分, 再执行。

目标: ${target}
产物目录: ${runDir}/recon/ （先 mkdir -p）

${discipline}

本任务:
1. 跑 audit-runner doctor（5 项健康检查: skill-tree/preset/schemas/toolchain/cache）, 记录 toolchain 可用性;
2. 构建 CPG: audit-runner cpg build --root ${target} （fuzzy 模式, 绝不编译目标; 缓存命中则复用）;
3. **导出面确定性枚举（必做, "导出即入口点"的底座）**: 跑
   audit-runner exports --root ${target} --cpg <cpg> --out ${runDir}/recon/exports.json
   （确定性 CLI: 头文件声明 × 无调用者函数查询 → exports[]{symbol, file, line, kind, declared_in_header, in_tree_callers}）。
   同时用 entry.sc / search_graph 枚举**树内显式入口点**（main/回调/信号/dbus 注册/exec 入口）, 每个候选 read/grep 确认语义。
   注意: 导出契约入口（kind∈{intended,accidental} 且 in_tree_callers==0）由脚本自动注入 entry_points, 你无需重复枚举。
   **输出纪律（2026-08-20 防超限）**: exports.json 已由 CLI 落盘; 返回 JSON 里 exports 字段:
   - 若导出条数 ≤200 → 返回完整 exports 数组;
   - 若 >200 → 返回 **空数组 []**（完整导出由主 agent 从 ${runDir}/recon/exports.json 读盘,
     经 args.exports 注入本脚本, 不要在 agent 返回里硬塞全量, 否则输出超限导致 recon=null）。
   返回前确认 exports.json 已写盘（ls -l 检查）。
4. 污染源排查（防"带提示的验证"）: 遍历目标树, 识别**非源码的基准/验收/审计产物**文件
   （START-HERE*、*REPORT*.md、VULN-FINDINGS*、THREAT_MODEL*、CALL-CHAINS*、poc_*/disconf_*、
   *exploit*、*.rpm/*.cpio/*.tar.gz、.pi/、workspace/、*.cpg 等）, 全部列入 exclude_files;
   **这些文件不得作为审计依据, 不得影响任何结论**; 若发现疑似基准文件, 在 assumptions 里如实标注。
5. **权限上下文（preflight 已确定性产出, 不要重新推导）**: read ${runDir}/recon/privilege_ctx.json,
   在 assumptions 里引用其 privilege_context/trigger_context 结论（high|low|unknown + 触发者标签）,
   并据此微调入口点/类的价值判断; 文件不存在则用 unknown 兜底并在 assumptions 注明。
6. **威胁推导纪律（必做, 类选择的输入）**: 对每个入口点（树内显式入口 + 导出契约入口）给出至少 1 个 threat,
   映射到猎杀类, 产出 threats: [{entry_point, threat, mapped_classes[], rationale}];
   **每个导出契约入口点必须至少映射一个威胁**（导出即承诺: 设计上就存在外部调用面）。
   **内容重复指针（口径统一）**: 若某入口点的文件与另一入口点**字节相同（用 cmp/md5sum 确认）**,
   后者不重复写威胁全文, 改设 same_as=<canonical entry_point 字符串> 且 threat 只写一句指针
   （如 "内容与 <canonical> 重复, 同一攻击面, 不再重复分析"）。
7. **推荐猎杀类清单 recommended_classes（B, 从 threats 推导）**: 基于第 6 步 threats 的 mapped_classes 聚合,
   结合语言分布/目标类型/权限上下文, 选**该目标实际适用**的类, 至少 3 个, 每类附一句话 rationale 链到某 threat;
   - 无 python → 不推 eval-injection/unsafe-deserialization; 无 shell → 不推 shell-injection;
   - 纯 C/C++ 目标 → 推内存安全类为主; 库目标 → 考虑 access-control/权限类（导出 API 面）;
   - root 守护进程/DBus 服务 → 推 race-condition/toctou/access-control（结合第 5 步 pctx）。
8. **候选池扫描（必做, 确定性引擎, 产出 HUNT 的定向候选）**:
   - **对第 7 步选中的每个类, 跑对应的预写查询资产**（路径 ${SKILL_ROOT}/skills/audit-runner/queries/classes/,
     文件名为 classes/<class>.sc 或 classes/<class>.grep, 25 类全部有资产）:
     每个 .sc 资产用 audit-runner cpg query --cpg <cpg> --file ${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.sc --timeout 200 调用;
     .grep 资产（shell-injection/eval-injection/unsafe-deserialization）**cd ${target} 后**跑
     rg -n -f ${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.grep scripts/
     （资产内是 scripts/ 相对路径, 必须从目标根跑才解析, 勿在 runDir 跑）;
     **硬规则: .sc 资产只走 cpg query, .grep 资产只走 rg——绝不互相混用**
     （cpg query 对 .grep 报 NonForkingScriptRunner 错: 它只接受 joern Scala 资产; .grep 用绝对路径喂 cpg query 也会被 cpg.py 护栏拒绝）;
     grep 扫 scripts/ 会命中逐字节相同副本（同一命中在多个文件重复出现）: 属预期, 汇总时按内容去重（见下方去重步）;
     资产文件不存在时回退: 通用 sinks.sc（${QUERIES}/）+ scan_cpg --tags <该类 cwe> + grep 兜底;
     通用资产也跑: entry.sc / sinks.sc / error_deref.sc（${QUERIES}/ 下）;
   - 空结果（仅 INFO 行）→ 按资产文件头注释的 grep 兜底模式跑一次 rg 确认, 不重试 joern;
   - audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>（querydb 全库扫描, 兜底补充）;
   - 若 ${SKILL_ROOT}/tools/sink_filter.py 存在, 跑 python3 sink_filter.py --cpg <cpg> --out ${runDir}/recon/candidates.json 取 ALERT/HIGH/LOW 三档（产物写 runDir, 纪律块 L113）;
   - 汇总为 candidate_hits: [{file, line, class, cwe[], tier: ALERT|HIGH|LOW|HIT}], 每条 = 一个真实候选点;
   - **内容去重（必做, 口径统一, 2026-08-18）**: 汇总后对**共享同一类**的解释型文件（sh/py）用 cmp/md5sum 比对;
     若两份文件字节相同（如 init-bottom/security_set 与 security_set.sh 逐字节副本）, canonical 文件保留全部真实候选点,
     副本文件只留 1 条指针 {file, line: 0, class, content_dup_of: <canonical 文件>, md5: <值>}, **不重复列点**;
     下游**不派副本组 HUNT agent**: 聚合段由脚本确定性把 canonical 组 findings 重贴为本文件路径并入
     （RECON 的 md5 即派发前复核; 审计只读快照不会中途漂移, 不再重复完整审计）。
   - **语言分流**: .sh/.py 等解释型文件无 C sink 候选 → 不强行造行号, 其候选由 class_file_map 标注整文件审计;
   - **零命中也要记录**（该 class 无候选 → 脚本标记 SKIPPED, 不派 agent）。
   - **注意**: 扫描范围 = 第 7 步推荐的类（RECON 取舍为准, 不强制全量）; 推荐的类必须跑对应资产,
     不得只用通用 sinks.sc 应付（per-class 资产比通用正则更准）。
9. class_file_map（审计点标注, 必做, **语义审计点的首选来源**）: 对无 sink 候选的类
   （权限/授权类 access-control/privilege-mgmt/permission-assignment/spoofable-identity 等
   "缺某样东西"才成立的类）给出真实审计点 [{class, file, line, note}], note 写清审计方向
   （如 "导出 API 无授权原语, 检查 getuid/属主/校验"）; 其余无候选类（注入/内存/健壮性类）由脚本
   2.0b 的"导出即入口点"自动回填缺省审计点（2026-08-18 起覆盖全部推荐类）。
   **注意**: 每个你推荐了但无 sink 候选的权限类, **必须**在 class_file_map 里给出至少 1 个真实候选点;
   没给 = 脚本判定该类无审计点, SKIPPED 不派 agent（推荐了却不给点, 会被记录为 RECON 遗漏警告）。
   缺省候选点可由导出契约入口补齐。
10. group_priority: 脚本会按"threat 价值 × pctx 权重"给文件排序出确定性默认; 若 RECON 判断某文件优先级与默认不同
    （默认: scripts/root 执行 > lib/*.c 特权写 > 其他 .c > tests/）, 给出 [{file, rank}], rank 越小越先查。
11. tricks 经验前馈（原框架硬规则, 必做）: read ${TRICKS} 的"章节 → 适用场景映射"部分,
    按目标类型选 2-4 个相关章节（如守护进程/DBus → §2 身份信任边界 + §4 深挖技巧;
    库目标 → §5 差分索引; setuid → §1 攻击面优先级; 补丁密集 → §3 补丁即地图）,
    提炼 ≤200 字**可操作**的注入块写入 tricks_injection（给出具体检查方向, 不是泛泛而谈）。
12. 把 recon.json（上述字段）写到 ${runDir}/recon/recon.json。

返回 JSON（严格按契约）:
{languages: string[], entry_points: string[], cpg_path: string,
 toolchain: {doctor: string, joern: string, ...}, assumptions: string[],
 privilege_ctx: {privilege_context: high|low|unknown, trigger_context: string, signals: [], evidence_confidence: string},
 exports: [{symbol, file, line, kind: intended|accidental|internal, declared_in_header, in_tree_callers}],
 threats: [{entry_point, threat, mapped_classes[], rationale}],
 recommended_classes: string[], tricks_injection: string, exclude_files: string[],
 candidate_hits: [{file, line, class, cwe[], tier}], class_file_map: [{class, file, line, note}],
 group_priority: [{file, rank}]}`,
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
  ? `\n## 污染控制（防基准泄漏）\n以下文件是目标树内的非源码产物/基准文件, **不得读取、不得引用、不得作为审计依据**:\n${recon.exclude_files.map((f) => `- ${f}`).join("\n")}\n违反即审计无效。`
  : "";

// 经验前馈: RECON 提炼的 tricks 注入块 → 前置到每个 auditor 提示词（原框架硬规则）
const tricksBlock = recon.tricks_injection
  ? `\n## 经验前馈（历史复盘注入, 先读再干, 按此方向优先排查）\n${recon.tricks_injection}`
  : "";

// CPG 私有副本（fork, 必做）: scan_cpg 无锁且 --overwrite 原地重写共享 CPG,
// 并行 HUNT 必须私有副本防损坏; 小 CPG(≤100MB) fork 毫秒级, 大 CPG 降级共享+flock
const forkBlock = `\n## CPG 私有副本（fork, 必做, 防并发损坏）\n共享 CPG: ${recon.cpg_path}\n先查 CPG 大小（ls -l / stat）: 若 ≤100MB, 运行\n  audit-runner cpg fork --src ${recon.cpg_path} --n 1 --dir ${runDir}/cpg-forks/\n取回私有副本路径, 之后本 agent 所有 cpg query 与 scan_cpg **一律用私有副本**; 若 >100MB 直接用共享 CPG（flock 串行, 正确性优先）; fork 失败降级共享 CPG。`;

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
    lines.push(`\n## 本组导出契约入口（RECON 产出, 导出即入口点）\n${hits.map((e) => `- ${e.symbol} @ ${e.file}:${e.line} (kind=${e.kind})`).join("\n")}\n这些符号无树内调用方, 属"设计承诺的外部调用面": **默认 REACHABLE**, reachability_basis=export-contract。`);
  } else if (exportEntries.length) {
    lines.push(`\n## 导出契约提示（RECON 产出）\n本组无导出契约入口; 若 sink 对应符号出现在全局导出面中, 按 export-contract 规则判定（默认存在消费者, 可能高权限中介）。`);
  }
  if (exportEntries.length) {
    lines.push(`**全通语义（2026-08-18）**: 导出契约入口默认存在消费者, 且消费者可能是高权限中介（root 守护进程转发非特权请求）。不得以"无消费者/非特权直连/文件权限门/no-gain"判不可达或降级 attacker_model。`);
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
    agent(`你是 c-auditor（HUNT 阶段, 代码审计流水线段1, 文件聚合组）。

先 read ${BRIEFS.auditor}; 组内每个类 read ${CODE_AUDIT} 对应章节:
${g.cls_list.map((c) => `- ${c}: ${CLASS_SECTIONS[c] || c}`).join("\n")}
${tricksBlock}

目标: ${target}
审计文件(组): ${g.file}
组内类清单: ${g.cls_list.join(", ")}
组内候选点行号: ${g.points.length ? g.points.join(", ") : "(无 C sink 候选 → 整文件审计)"}
权限类审计点入口行: ${g.entry_lines.length ? g.entry_lines.join(", ") : "(无)"}
RECON 全局入口点: ${JSON.stringify(recon.entry_points)}
CPG: ${recon.cpg_path}
产物目录: ${runDir}/hunt/${g.file.replace(/[^A-Za-z0-9._-]/g, "_")}/ （先 mkdir -p）

${discipline}
${forkBlock}
${exclusionBlock}
${exportBlockForHunt(g)}

本任务:
1. **引擎结果直接用 RECON 候选池, 不重跑资产**: RECON 已对每个类跑过预写资产
   （${SKILL_ROOT}/skills/audit-runner/queries/classes/<class>.sc）并产出 candidate_hits
   （上方"组内候选点行号"即引擎命中）。你**不需要再跑任何 classes/*.sc**——直接在候选点上做验证
   （本组能派发即已有候选点; 零候选类已被脚本标记 SKIPPED, 不会到 HUNT）。
2. 对组内候选点逐个 read/grep 逐跳验证（entry→sink 真实存在、无同名碰撞、类型匹配、防御绕过与否）;
   **验证视角**: 不止看"内存是否有界"（无 OOB ≠ 无 bug）, 还要看**写出的值语义是否正确**
   （字符串处理逻辑: 子串误匹配? 索引不同步导致截断/空洞? 边界输入是否破坏数据结构?）;
   无候选点的类(权限类)按入口点审计"缺什么"(授权原语/身份校验/属主检查); 解释型文件(sh/py)整文件审计;
3. **可达性判定是 HUNT 职责（2026-08-21 TRACE 并入 HUNT）**: 对每个 emitted finding,
   必须产出结构化 trace 字段 —— 逐跳验证后判定 trace_result:
   - sink 是导出契约入口（上方 exportBlock 命中, kind∈{intended,accidental} 且树内无调用方）→
     **默认 REACHABLE**, reachability_basis="export-contract";
   - 树内路径逐跳证实 → REACHABLE, reachability_basis="in-tree";
   - 整条链被真实防御阻断（不可绕过）→ 不 emit 该 finding（记入 checked）, 或 emit
     UNREACHABLE + unreachable_reason（审计留痕, 段2 不会验证）;
   - REACHABLE 必填 impact_if_reachable; UNREACHABLE 必填 unreachable_reason。
4. 只输出有证据链的 finding（vuln_class 必须填实际类, 不是组标识）; 每个候选点/入口点的检查结果记入 checked;
   查不完的记入 unchecked 交回（自限: 单 agent 最多查 3 个入口点, 超出列入 unchecked）;
5. 把 findings.json + 证据片段写到 ${runDir}/hunt/<组名>/。

返回 JSON（严格按契约）:
{cls: "<组标识: ${g.file}>", findings: [{vuln_class, file, line(整数), sink, entry_point,
  confidence: low|medium|high, evidence(entry→sink 一句话+代码片段), subsystem?, attacker_model,
  trace_result: REACHABLE|UNREACHABLE, call_chain: string[], data_flow,
  defenses_checked: [{defense, location, verdict: bypassed|blocked|not-present}],
  reachability_basis: in-tree|export-contract|external-context,
  impact_if_reachable?, unreachable_reason?}],
 checked: string[], unchecked: string[], notes?: string}`,
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
    return agent(`你是 c-auditor（GAPFIL 补查 ${r.cls}, 代码审计流水线段1）。

先 read ${BRIEFS.auditor}; 组内类章节:
${(g.cls_list || []).map((c) => `- ${c}: ${CLASS_SECTIONS[c] || c}`).join("\n") || "（沿用上一轮类清单）"}
${tricksBlock}

目标: ${target}
CPG: ${recon.cpg_path}
产物目录: ${runDir}/hunt/${String(r.cls).replace(/[^A-Za-z0-9._-]/g, "_")}/ （追加写入）

${discipline}
${forkBlock}
${exclusionBlock}
${exportBlockForHunt(g)}

上一轮覆盖情况（组 ${r.cls}）:
- 已检查（勿重复）: ${JSON.stringify(r.checked || [])}
- 未检查（逐一检查）: ${JSON.stringify(r.unchecked || [])}

可达性判定同 HUNT（2026-08-21 TRACE 并入 HUNT）: 每个 emitted finding 必含
trace_result/call_chain/data_flow/defenses_checked/reachability_basis; REACHABLE 必填
impact_if_reachable, UNREACHABLE 必填 unreachable_reason; 导出契约入口默认 REACHABLE。

返回 JSON（严格按契约, 同 HUNT）:
{cls: string, findings: [{vuln_class, file, line, sink, entry_point, confidence, evidence,
  attacker_model, trace_result: REACHABLE|UNREACHABLE, call_chain: string[], data_flow,
  defenses_checked: [{defense, location, verdict}], reachability_basis, impact_if_reachable?,
  unreachable_reason?}], checked: string[], unchecked: string[], notes?: string}`,
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
