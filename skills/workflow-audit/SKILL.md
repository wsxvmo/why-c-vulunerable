---
name: workflow-audit
description: Leaderless C/C++/Shell/Python code audit pipeline driven by the DSH workflow tool. Use for full-pipeline audits (RECON→HUNT→GAPFIL→VALIDATE→CHAIN→REPORT; TRACE merged into HUNT, 2026-08-21) that must NOT hold a long-lived coordinator session — the script audit-pipeline.js is read from disk and passed as the workflow script parameter each call, every stage runs as a fresh workflow subagent, and the caller only holds compact JSON between segments. RECON is fully target-local: privilege context (pctx) and export surface (exports) come from deterministic CLIs, threat modeling is a compact threats[] discipline, and the consumer-tree/sibling scan is retired (export = entry point). Keeps all audit discipline (audit-runner/audit-tools enforcement, schema gates, sanitizer confirmation) while eliminating the coordinator's session-longevity token tax.
---

# workflow-audit — DSH workflow 无主-agent 审计流水线

## 何时用 / 何时不用

**用**：对完整目标跑全流水线审计（RECON→HUNT→GAPFIL→VALIDATE→CHAIN→REPORT；TRACE 已并入 HUNT）。主 agent 只发一次 `workflow` 调用、只持有紧凑 JSON 中间产物；各阶段在**新鲜上下文的子 agent** 中执行，不共享会话历史。

**不用**：单文件/单函数快速判断（直接 read/grep 或普通 subagent 即可）；两三个 agent 能解决的小任务（workflow 是重编排工具）。

## 为什么存在（背景）

原 `skills/pipeline`（codeaudit-pipeline）是层级式：主 agent（c-harness）活过 7 阶段 × 60+ 轮，每轮重发全部会话历史——实测 32.1M tokens 中 **31.8M 是 cacheReadTokens 的"会话长寿税"**，真实分析成本仅 1.5M。改造目标：调度/状态/校验/汇总等确定性逻辑搬进 workflow 脚本（0 token），LLM 只花在判断上。

## 三段式（每段 = 一次 workflow 调用）

```
段1 workflow: RECON → HUNT → GAPFIL          ← audit-pipeline.js（v1 已实现; HUNT 产出 finding+trace）
     ↓ return {findings[], coverage}          ← 主 agent 过目/干预点
段2 workflow: VALIDATE                       ← validate.js（v3 已实现; TRACE 已并入段1 HUNT）
     ↓ return {confirmed[], killed[], env_blocked[], unreachable[]}
段3 workflow: CHAIN → REPORT → LEDGER        ← chain-report.js（v2 已实现）
     ↓ return {report, ledger}               ← 最终交付 + casefile 台账
```

> 合并而非一阶段一段的原因：脚本内 JS 变量传递阶段产物 = 0 token；拆成独立调用则每段数据要穿过主 agent 中转，确定性编排税重新出现。分三段保留 3 个可中断/可续跑/可人工干预的检查点。

## Model 分层（deliberate disagreement）

workflow 的 `agent(prompt, {model})` 支持 per-agent 模型覆盖（plain subagent 做不到）。**统一策略（2026-08-18）：全阶段缺省继承主 agent 模型**（不传 `model` 即继承）；需要更强/不同模型时经 `args.models` 显式覆盖。

| 阶段 | 默认模型 | 理由 |
|---|---|---|
| RECON | **继承主 agent**（`args.models.recon` 可覆盖） | 与主 agent 同模型 |
| HUNT | **继承主 agent**（`args.models.hunt` 可覆盖） | 与主 agent 同模型，广撒网 + 可达性证明 |
| GAPFIL | **继承主 agent**（`args.models.gapfil` 可覆盖） | 与主 agent 同模型 |
| VALIDATE | **继承主 agent**（`args.models.validate` 可覆盖） | 与主 agent 同模型；**可覆盖为更强/不同模型**，独立否定 HUNT 的可达性判定（deliberate disagreement） |
| CHAIN/REPORT | **继承主 agent**（`args.models.chain/report` 可覆盖） | 与主 agent 同模型，轻量分析 |

## 审计启动前置（主 agent 每次跑审计前必做）

台账功能与流水线的绑定点：**由主 agent（不是 workflow 子 agent）在发起段1 前完成**。主 agent 有 cordis 工具与 bash；workflow 子 agent 是独立会话、未必有 cordis 工具，所以不派给 RECON。

**① 台账插件就绪检查/恢复（每进程一次）**：
```
1. cordis_inspect_self（不传参）列出当前插件 → 找 ledger-manager
2. 不存在则恢复:
   read extensions/ledger-manager/host.js      → 作为 code.host
   read extensions/ledger-manager/client.js    → 作为 code.client
   cordis_define({plugin:{kind:"new", idPrefix:"ledg"}, name:"ledger-manager",
                  purpose:"审计台账管理面板：输入框工具行按钮+锚定弹出面板+Run 卡片常驻",
                  code.host:<host.js>, code.client:<client.js>})
   cordis_run → GUI 审批一次（单勾）→ 主 agent 提示用户强刷页面
3. 已存在（本进程已恢复过）→ 跳过
```
插件是进程级 + 浏览器应用级的：一个进程内所有会话共用，**进程重启后才需要重做 ①**。

**② run 台账初始化（每 run 一次, 幂等）**：
```bash
python3 /home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py init <runDir> \
  --title "Pipeline: <target> <时间戳>" --target "<target>"
```
→ 该 run 从开始就有台账骨架（run_meta.json），ledger-manager 面板立即可见；段3 LEDGER 阶段收尾落账时 init 幂等跳过。已有 runDir 台账则跳过（续跑场景）。

> 目的：台账不是"跑完才有"，而是"审计一开始就可见、结束时填满"——ledger-manager 面板在整条流水线期间都能实时看该 run 的案件/证据进展。

**③ 权限上下文确定性化（每 run 一次, 幂等, 2026-08-16 新增）**：
```bash
audit-runner pctx --root <target> --out <runDir>/recon/privilege_ctx.json
```
→ 主 agent 把产物作为段1 `args.privilege_ctx` 传入；RECON **不重新推导**（直接 read 引用）。
信号集 C/守护进程导向（setuid/systemd User=root/特权 API/daemon 化/低端口绑定等），
输出 `privilege_context(high|low|unknown)` + `trigger_context` + `signals[]` + `evidence_confidence`。
pctx 是权限上下文的**单一事实源**：段2 VALIDATE 用它喂 attacker_model，段3 REPORT 用它推导 CVSS 的 AV/PR/UI。

## 调用方式（段1）

主 agent 每次调用前 **read 脚本文件**，内容作为 `script` 参数传入：

```
1. read skills/workflow-audit/audit-pipeline.js      # 拿到脚本全文
2. workflow({
     meta: {name: "code-audit-segment1",
            description: "RECON→HUNT→GAPFIL 审计段1",
            phases: [{title:"recon"},{title:"hunt"},{title:"gapfill"}]},
     script: <脚本全文>,
     args: {
       target: "<目标源码绝对路径>",
       runDir: "<产物目录, 建议 workspace/runs/<名>-<时间戳>>",   // 可选
       skillRoot: "/home/xvmo/why-c-vulunerable",                // 可选
       classes: ["buffer-overflow", "command-injection"]         // 可选, 跑通后扩展
     }
   })
3. 把返回值中的 findings/coverage 落盘（如 workspace/runs/<名>/segment1.json），
   供段2/段3 或人工过目使用
```

**args 契约**：

| 键 | 必填 | 说明 |
|---|---|---|
| `target` | ✅ | 目标源码绝对路径 |
| `runDir` | 可选 | 子 agent 写产物的目录；默认 `${skillRoot}/workspace/runs/audit-<名>` |
| `skillRoot` | 可选 | 本仓库根；默认 `/home/xvmo/why-c-vulunerable` |
| `classes` | 已废除 | **2026-08-15 起不再生效**（类选择仅听从 RECON `recommended_classes`）；传入会被忽略并打警告。禁止再通过 `classes`/`classesMode` 追加或覆盖猎杀类 |
| `privilege_ctx` | 段1 可选 | **preflight `audit-runner pctx` 确定性产出**（权限上下文单一事实源）；RECON 引用不重推。段2/段3 亦转发 |
| `findings` | 段2 必填 | 段1 返回的 `findings[]`（脚本自动分配 id F1..Fn；**每项含 HUNT 产出的可达性 trace 字段**） |
| `exports` | 段2 可选 | 段1 返回的 `exports[]`（目标本地导出面，导出即入口点） |
| `threats` | 段2 可选 | 段1 返回的 `threats[]`（威胁推导纪律） |
| `cpg_path` | 段2 必填 | 段1 recon 构建的 CPG 路径 |
| `tricks_injection` | 段2 可选 | 段1 返回的 `tricks_injection`（经验前馈注入块），原样转发 |
| `confirmed` | 段3 必填 | 段2 返回的 `confirmed[]` |
| `coverage` | 段3 可选 | 段1 返回的 `coverage[]`，补进报告 |
| `external_context` | 段2/段3 可选 | 审计员显式提供的生态知识（非扫描；**默认"消费者树全通"已让导出 API 默认可达**，此字段用于校准 PR、确认具体消费者身份与跨包链；缺省无，但全通默认仍然生效） |
| `models` | 可选 | `{hunt?, gapfil?, validate?, chain?, report?}` 模型覆盖（TRACE 已并入 HUNT，不再有 `trace`） |

> **已退役（2026-08-16）**：`siblings_root` / 兄弟组件扫描 / 消费者树——版本漂移使"有引用(陈旧误报)/无引用(采样空洞假阴性)"双向失真，负期望价值。导出 API 本身即"设计承诺的外部调用面"（intended/accidental 均可达），由结构性规则"导出即入口点"处理，无需扫描其他组件。

### 段2/段3 追加契约

> **2026-08-21：TRACE 已并入段1 HUNT** —— HUNT/GAPFIL 的每个 finding 直接携带
> `trace_result: REACHABLE\|UNREACHABLE`、`call_chain[]`、`data_flow`、`defenses_checked[]`、
> `attacker_model`、`reachability_basis: in-tree\|export-contract\|external-context`，
> 以及条件必填 `impact_if_reachable?` / `unreachable_reason?`。段2 不再派 c-tracer。

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| VALIDATE | parallel, 每 REACHABLE finding 1 个（独立否证 + sanitizer） | ≤6 并发 | 每 finding `{finding_id, status: confirmed\|killed\|env_blocked, technique_used, detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?, kill_reason?, kill_category?}` |
| CHAIN | 1 个 agent（仅 confirmed>0 时；默认树内链 + 导出契约链步，跨包链在有 `external_context` 时细化） | 1 | `{chains[], summary}` |
| REPORT | confirmed>0 时 1 个 report agent 补 CVSS；否则纯脚本聚合 | 0-1 | `{findings[], summary}` |

**脚本内条件门禁**（段2）：confirmed → poc_path/run_log/evidence_extracted 必填；killed → kill_reason 必填，且 **export-contract 的 kill 不得命中全通禁止类别**（无消费者/非特权直连/文件权限门/no-gain，命中则 repair ≤2 重派）；env_blocked → kill_reason(阻断原因) 必填；不合格 repair ≤2 次重派。

**段2 返回契约**：`confirmed[]`（每项含完整 finding（含 HUNT trace 字段）+validation）、`killed[]`（VALIDATE 级 kill）、`env_blocked[]`（环境/内核/部署无法本地复现，**≠ 硬 kill**，供段3/人工/LIVE 确认，2026-08-18 新增）、`unreachable[]`（HUNT 判 UNREACHABLE 的 finding，段2 不验证，审计留痕；2026-08-21 替代原 `killed_by_gate[]`）、`gate`、`stats`、`agents`。finding_id 偏差有 positional 兜底，不会丢 finding 字段。

**段1 去重（C）**：同一 `file+sink`（行距 ≤10）的跨类同根因 finding 合并为一条（保留证据最全/置信度最高者，`cls_all` 记录全部来源类），防段2 重复 trace/validate。

**可达性规则（2026-08-16，替代消费者树；2026-08-21 起由 HUNT 产出）**：sink 是导出符号（kind∈{intended,accidental}）且 `in_tree_callers==0` → **默认 REACHABLE**（`reachability_basis="export-contract"`），不再 requires_external_verify；树内路径证实 → `"in-tree"`；审计员显式生态知识 → `"external-context"`。HUNT/VALIDATE 不得重扫兄弟组件（具体外部调用路径属 PoC 阶段）。

**全通纪律（2026-08-18，修正与"默认消费者树全通"相悖的设计点）**："导出即入口点 → 默认 REACHABLE"即**默认消费者树全通**——导出契约入口默认存在消费者，且消费者可能是高权限中介（root 守护进程转发非特权请求）。据此纪律从"只标 REACHABLE"延伸到整条流水线：

1. **VALIDATE 禁止用"调用者身份/特权中介缺失"做否证前置或 kill 理由**：`无树外消费者 / 无 in-tree 调用者 / 无特权消费者 / requires out-of-tree consumer / 非特权直连→文件权限门 EACCES→触发不可能 / no-gain(KILL-3 能写就直改)` 全部重新引入"消费者不存在/非特权直连"假设，与全通相悖。可用的否证方向只剩**机制本身在目标内静态/确定性不可触发**（路径常量对调不影响实际部署、sink 无数据流、防御真实存在不可绕过、目标自身写路径无法产出该输入）。
2. **kill_reason 类别门禁**：export-contract 的 kill 若命中上述禁止类别，脚本门禁 repair ≤2 拦截重写（不再像 F3 那样让违背全通的 kill 畅通过 gate）。
3. **env_blocked 独立状态**（2026-08-18 新增）：环境/内核/部署无法本地复现 ≠ 硬 kill → `status=env_blocked`，段2 返回独立 `env_blocked[]`，供段3/人工/LIVE 确认，不进 `killed[]`（F6 实证：本机 securityfs 555 判"环境不成立"应归 env_blocked 而非 killed）。
4. **REPORT 的 PR 不得因 pctx=unknown 保守取 H**：export-contract finding 在 pctx=unknown 时取 PR:L（导出面默认可达）或 PR:N/A（待外部消费者知识），pctx=unknown 只是"目标自身无固定运行权限"，不是"无消费者"证据。
5. **导出回填覆盖全部推荐类**（2.0b 改造）：`exports[]` 缺省审计点不再限于权限类——注入/内存/健壮性类同样以导出 API 面为缺省审计点（F3 实证：NULL 参数属 null-deref 类，未推荐→导出 API 健壮性面盲区）。
6. **CHAIN 默认含导出契约链步**：export-contract 的 confirmed finding 其"外部消费路径"作为假设链步纳入（标注待 LIVE 确认），不因缺 external_context 整条丢弃。
7. **全通语义结构化传递**：`exportsBlock` 内置"默认存在消费者（可能高权限中介）"，注入 HUNT **与 VALIDATE** 提示词；attacker_model 不得回退为"需要 out-of-tree 特权消费者"。

**段3 LEDGER（B 收尾落账）**：末尾 1 个 agent 把最终 confirmed+coverage 一次性写入 casefile 台账（`runDir` 下：init → add 每 case（`audit-runner ledger --op add --dedup-key` 自动去重）→ log 证据 → `casefile.py report --out runDir/report/casefile-report.md`）。不做全程状态机——编号收尾一次性分配，无跨段接力链。返回 `ledger: {casefile_initialized, report_path, case_ids}`。casefile 的"状态机约束 agent"职责在无主 agent 模型下已由脚本门禁接管（见上），台账保留"记录+索引+人工时间线"价值。

## 段1 阶段契约

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| RECON | 1 个 agent（确定性底座: doctor + cpg build + **pctx** + **exports** + 候选池） | 1 | `{languages, entry_points[], cpg_path, toolchain, assumptions[], privilege_ctx, exports[], threats[], recommended_classes[], tricks_injection, exclude_files[], candidate_hits[], class_file_map[], group_priority[]}` + `runDir/recon/recon.json` |
| HUNT | **文件聚合组, 每文件组 1 个**, ≤6 并发/轮分批 | ≤6/轮 | 每组 `{cls: 组标识, findings[], checked[], unchecked[], notes?}` + `runDir/hunt/<组>/`；**findings 含可达性 trace 字段** |
| GAPFIL | 对 INCOMPLETE 组补查 1 轮, 同分组规则 | ≤6 并发 | 同上（替换原结果） |

### 经验前馈（tricks 注入, 原框架硬规则）

RECON 按目标类型从 `skills/tricks/SKILL.md` 选 2-4 个相关章节（守护进程/DBus → §2 身份信任边界+§4 深挖；库目标 → §5 差分索引；setuid → §1 攻击面优先级），提炼 ≤200 字可操作注入块 → `tricks_injection`，脚本**前置到每个 HUNT/GAPFIL auditor 提示词**，并经段1 返回值转发给段2（`args.tricks_injection`）注入每个 VALIDATE 提示词。这是"历史复盘经验进入本轮审计"的通道（libsecurity1 那次 RECON 即兴生成该字段但编排层未转发的缺口已补上）。

### 技能加载分层（audit-runner/audit-tools）

- **RECON**：read `audit-runner/SKILL.md` 与 `audit-tools/SKILL.md` **全量一次**（跑 doctor/建 CPG/生命周期与 fork 策略，一次值回票价）。
- **执行 agent（HUNT/GAPFIL/VALIDATE）**：只带脚本内置纪律块（禁裸 joern/println/降级/干净 cwd/工具分工），**不重读全量 SKILL.md**（内容重叠+稀释注意力）；遇到纪律块未覆盖的边界情况时条件引用（如 CPG 并发排队 → read `audit-runner/SKILL.md` §并发策略）。
- **待办**：CPG fork 优化——RECON 产出 `fork_paths[]`（每并发 agent 一份私有 CPG 副本），脚本分配给各 auditor，替代共享 CPG + flock 串行。

### 类选择机制（RECON 唯一权威 + 威胁推导纪律 — 2026-08-16）

1. **RECON 是唯一权威**：`recommended_classes`（必填，RECON 模型推荐 ≥3 类）是猎杀清单的**唯一**来源。**调用方 `classes`/`classesMode` 已从代码上废除**（`audit-pipeline.js` 不再读取），传了也会被忽略并打警告——因为调用方往往不如看过源码的 RECON 了解目标，历史上曾发生调用方传 23 类覆盖 RECON 7 类导致范围漂移。
2. **威胁推导纪律（2026-08-16 新增，类选择的输入）**：RECON 对每个入口点（树内显式入口 + **导出契约入口**）给出 ≥1 个 threat，映射到类，产出 `threats[]: {entry_point, threat, mapped_classes[], rationale}`。**每个导出契约入口必须映射至少一个威胁**（导出即承诺）。`recommended_classes` 从 `threats[]` 的 mapped_classes 聚合推导（每类附 rationale 链到某 threat），不再凭经验拍。
3. **语言剪枝（确定性兜底，非人工输入）**：最终按 `recon.languages` 剪掉不适用类——无 python 剔 `eval-injection`/`unsafe-deserialization`，无 shell 剔 `shell-injection`，非 C/C++ 剔内存安全 8 类；剪光则落 `["command-injection","race-condition"]`。
4. **RECON 空推荐兜底**：`recommended_classes` 为空或全被剪时落 `DEFAULT_CLASSES`（`["buffer-overflow","command-injection"]`）。
5. **防静默漏检**：返回 `classes: {mode:"recon-only", requested, recommended, effective, pruned}`——调用方能看见"RECON 推荐了哪些、实际跑了哪些、剪了哪些"。coverage 只覆盖 effective 类，不等于全类审计。

### 文件聚合分组派发（2026-08-15 改造 + 2026-08-16 导出回填）

**探索按方法论类（RECON 25 类），派发按代码文件聚合（脚本确定性分组）**——两级不同维度，各取所长：

1. **RECON 产出候选池（确定性引擎，非模型拍脑袋）**：
   - `candidate_hits[]`：sinks.sc / scan_cpg / sink_filter.py 的命中 `{file, line, class, cwe[], tier: ALERT|HIGH|LOW|HIT}`；
   - `class_file_map[]`：无 sink 候选的类（权限/授权类）标注审计点 `{class, file, line, note}`（**权限类候选点的唯一来源**；2026-08-15 起废除旧的"入口点注入到所有权限类"——历史把它复印到全部文件导致空转）；
   - **导出即入口点（2026-08-16 新增；2026-08-18 全通化）**：`exports[]` 中 `kind∈{intended,accidental}` 且 `in_tree_callers==0` 的符号自动注入候选池，作为**无候选类的缺省审计点**（库的导出 API 面 = 该类的攻击面，不再限于权限类；注入/内存/健壮性类同样适用）；不重复注入已有候选的类。
2. **脚本分组（0 token，确定性）**：
   - `.c/.cpp` → 组 = 文件（组内聚合全部类候选点）；
   - `.h` → **不独立分发**，并入实现它的 .c 组（同名 .c 优先，否则并入候选最多的实现 .c）；
   - `.sh/.py` 等解释型 → 组 = 文件本身，整文件审计（sink 行号提取对 shell 失效，不强行造行号）；
   - 零候选类 → **SKIPPED**（引擎证据，不派 agent）。
3. **排序（确定性 + RECON 覆盖）**：默认 `scripts/(root 执行) > lib/*.c(特权写) > 其他 .c > tests/`，组内按候选点数降序；脚本先按"threat 价值 × pctx 权重"出确定性默认，`recon.group_priority[]` 覆盖。
4. **分批派发**：排序后每批 ≤6 个组，多批串行循环（高优先先出结果）。
5. **覆盖单位 = (class × file) 组**：COVERED / INCOMPLETE（→GAPFIL 同组补查）/ SKIPPED / NOT_FOUND；返回 `groups[]` 明细（组状态 + 类清单 + 候选点行号）。
6. **防大组爆炸**：组内唯一行 > 60 → 按类拆成 (file×class) 子组（兜底，非默认）。

**finding 必填字段**（与 `schemas/stage-finding.json` 合并契约对齐，2026-08-21）：`vuln_class, file, line(整数), sink, entry_point, confidence(low|medium|high), evidence(entry→sink), attacker_model, trace_result(REACHABLE|UNREACHABLE), call_chain[], data_flow, defenses_checked[], reachability_basis(in-tree|export-contract|external-context)`；条件必填 `impact_if_reachable`（REACHABLE）/ `unreachable_reason`（UNREACHABLE）。

**脚本内门禁**：`agent()` schema 只校验子集（type/properties/required/items/enum），深度校验（字段缺失、line 非整数、条件必填）在脚本聚合段做，不合格的 finding 列入 `gate.invalid` 返回，不静默丢弃。

## 纪律块（每个 agent prompt 内置, 与 pipeline skill 一致）

1. **绝不编译目标项目**；只用 read/grep/静态查询/CPG。
2. **禁裸 joern / codebase-memory**，必须经封装（分工见下）。
3. 空结果（仅 INFO 行）→ 转 grep 兜底，不重试白等。
4. 产物写 runDir 对应子目录。
5. 自限：单 agent 最多查 3 个入口点，超出列入 `unchecked` 交回。

### 工具分工（audit-runner 与 audit-tools 是分层关系，不是重复）

| 用途 | 命令 | 归属 |
|---|---|---|
| CPG 构建 | `audit-runner cpg build --root <abs>` | audit-runner（底层调 audit-tools，加产物验证/缓存） |
| CPG 目标查询 | `audit-runner cpg query --cpg <cpg> --file <q.sc>` | audit-runner（println 强制/干净 cwd/空结果降级） |
| 权限上下文（**2026-08-16 新增**） | `audit-runner pctx --root <abs> --out <path>` | audit-runner（C/守护进程信号集，preflight 跑，单一事实源） |
| 导出面枚举（**2026-08-16 新增**） | `audit-runner exports --root <abs> --cpg <cpg> --out <path>` | audit-runner（exports.sc 查询 + 头文件交叉，导出即入口点） |
| querydb 全库扫描 | `audit-tools cli scan_cpg --cpg <cpg> --tags <cwe>` | 仅 audit-tools 有 |
| codebase-memory | `audit-tools cli codebase_query --tool <t> <args...>` | 仅 audit-tools 有 |

audit-runner 不在 PATH 时用绝对路径 `/home/xvmo/.local/bin/audit-runner`。

## 污染控制（盲测完整性）

1. **验收基准（oracle）必须放在被测目标树之外**（同级目录或单独验收目录）。基准放回目标树内 = "带提示的验证"（hinted verification），审计独立性作废。
2. **RECON 识别污染源**：`exclude_files` 字段列出目标树内所有非源码产物/基准文件（START-HERE*、*REPORT*.md、VULN-FINDINGS*、poc_*/disconf_*、*.rpm/*.cpio、.pi/、workspace/、*.cpg 等），并在 assumptions 如实标注。
3. **HUNT/GAPFIL 显式禁用**：RECON 的 `exclude_files` 注入每个 auditor 提示词（"不得读取、不得引用、不得作为审计依据"），从结构上关闭 HUNT skim 基准文件的通道。
4. **如实记录**：审计报告标注本次是 blind 还是 hinted（若 RECON 发现基准文件残留）。

## 验收标准（对齐 workflow/TASK-SUMMARY.md）

- [x] `skills/workflow-audit/` 存在，SKILL.md 可读
- [x] `audit-pipeline.js` 语法通过（引擎同款 async 包装 node --check）
- [x] 段1 冒烟跑通：ksaf-dynamic-uid 3 agent 全通，gate 0 无效（2025-08-15，详见 `workspace/runs/ksaf-dynamic-uid-smoke/`）
- [x] 调用方只发一次 workflow 调用、只持有紧凑 JSON 中间产物
- [x] token 对比记录：主会话单轮 < 10 万（实测 ~1 万量级，基线 29.3 万；`workspace/runs/ksaf-dynamic-uid-smoke/token-comparison.md`）
- [x] **三段式端到端**：ksaf-init 纯净源码 段1(2 假设) → 段2(双 UNREACHABLE, pro 否证 hunter 粘滞位误读) → 段3(干净报告)，见 `workspace/runs/ksaf-init-clean-2025-08-15/E2E-SUMMARY.md`
- [x] **VALIDATE sanitizer 分支**：libsecurity1 F1/F2/F3 均 sanitizer/repro 确认 ✅
- [x] **pctx 确定性化**（2026-08-16）：同目标两次输出一致；ksaf-audit-daemon → high(系统 User=root)，libsecurity1 → unknown(库固有权限未知) ✅
- [x] **exports 导出面枚举**（2026-08-16）：libsecurity1-clean 新鲜 CPG 实测 7 行（6 intended 公开 API + main accidental），intended/accidental 分类正确 ✅
- [x] **消费者树/兄弟扫描退役**（2026-08-16）：三脚本 consumers 引用清零，`siblings_root` 从契约移除 ✅
- [x] **全通纪律落地**（2026-08-18）：VALIDATE 禁调用者身份 kill 前置 + kill_reason 全通门禁 + env_blocked 独立状态 + REPORT 全通 PR + 导出回填全类 + CHAIN 导出契约链步；三脚本 `node --check` 通过 ✅
- [x] **auditor+tracer 合并**（2026-08-21）：HUNT 产出 finding+trace 合并契约；段2 改名 validate.js（TRACE 阶段删除）；VALIDATE 独立可达性挑战；`stage-finding.json`/gate.py 同步；`tracer.md`/`stage-trace.json` 标 ARCHIVED；三脚本 `node --check` 通过 ✅
- [ ] **casefile/ledger 对接**：确定性 CLI（ledger add/log）由 agent 调用，待接入
- [ ] **段1 冒烟复跑（新 RECON 双层）**：ksaf-dynamic-uid 用 pctx+exports+threats 契约重跑，gate 0 无效，token 对比更新

## 查看台账索引（vuln-hunter 模式下三种方式）

跑完段3 后，台账落在 `<runDir>/`（`casefile.py report` 产物在 `<runDir>/report/casefile-report.md`）。vuln-hunter 模式下查看：

1. **直接问 agent（最方便）**：在 DSH 会话里说"查看 `<runDir>` 的案件台账"或"运行 casefile report"——vuln-hunter preset 人设已内置 casefile 用法，agent 会执行 `casefile.py list/logview/report` 并把结果回给你。
2. **自己开终端跑 CLI**：
   ```bash
   python3 /home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py list <runDir>
   python3 /home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py logview <runDir> <case-id>
   python3 /home/xvmo/.dsh/.agent-presets/vuln-hunter/tools/casefile.py report <runDir>   # 或 --out 输出到文件
   ```
3. **台账管理面板（ledger-manager 动态插件）**：输入框工具行"台账"按钮弹出面板（扫描 run → 案件表/状态筛选/类过滤/CSV/时间线，10s 自动刷新）；插件 Run 卡片内常驻同款面板。

## ledger-manager 插件踩坑记录（DSH 动态插件开发）

开发"台账管理"动态插件（`ledg-47`，Host fs 直读 + Client 面板）时踩的坑，供后续插件开发复用：

| 坑 | 结论 |
|---|---|
| `shell.overlay` 浮动面板不可见 | 该 overlay 层在本构建里渲染 occupant 异常（`position:absolute/fixed` 均不可见）——**不要依赖它做业务面板** |
| `conversation.input.dock` 不可见 | 同理，某些 additive slot 位在当前构建未渲染 |
| 侧栏 `sidebar.footer.action` 按钮被截断/点击无效 | rail 模式需 cordis 式 `rail` 变体（36px 圆）适配；且该位在本环境有兼容问题 |
| **最终可行方案** | 触发器放 `conversation.input.left`（输入框工具行，与访问模式控件并列）；面板用 **absolute 锚定**在触发器上方（`position:absolute; bottom:calc(100%+8px)`），普通流锚定不碰 fixed/overlay |
| `tool.view.cordis`（key `self`） | **官方保证渲染**的插件交互区——Run 卡片内常驻面板，永远兜底可见 |
| 面板头部滚动消失 | `position:sticky; top:-12px; margin:-12px` 覆盖容器 padding 的技巧，关闭按钮 `margin-left:auto` 钉右上角 |
| Client 无 `document`/`window` | 禁用下载 API/scrollIntoView；CSV 用 textarea 全选复制 |

插件是**动态的（进程局部）**：重启后需重新定义/运行；如需跨会话常驻，升级为宿主 cordis.yml 静态插件。

## 流水线踩坑记录（2026-08-15 libsecurity1-clean 复盘, 12 坑四组）

> 每次跑全流水线前重读。前两类已修进脚本, 后两类是纪律/语义。

### 一、数据中转类（段间最重, 已修①②）
1. **workflow 大返回值必截断且位置不可控** → 段2 已改为返回"摘要+产物路径索引"(confirmed/killed 只给扁平字段+ trace_path), 全量从 runDir 读。段1 findings 保留全量(实测不截断, 且脚本无 fs 无法落盘聚合产物)。
2. **spill 文件非纯 JSON**（strict 拒控制字符 / strict=False 遇裸换行）→ 不要解析 spill, 直接读 runDir 子 agent 落盘产物。
3. **主 agent 手工重构造 args**（段1→2→3 抄大 JSON）→ 段2 起改为读盘重建(见①), 段1→2 的 findings 中转是脚本内存产物, 无法避免, 但字段契约稳定。
4. **中转丢字段**（段3 曾丢 line）→ 段2 索引已含 file/line/sink/evidence/poc_path 全字段, 段3 直接消费不再精简。

### 二、工具 API 类（语义纪律, 未改脚本）
5. **casefile.py update 把 run id 当 case** → run.json 的 id 不是 case; 更新 run 元数据用 python3 -c json.dump 直改文件, 不走 CLI。
6. **audit-runner ledger --op add 打印 case id 失败 exit 1**（add 无 id 解析怪癖）→ 双路径: wrapper 失败用 raw engine(casefile.py add) 补偿。
7. **gate 校验产物不是生成器** → 先确保 output 文件存在再跑; 忘 --run-dir 报 usage, 给不存在路径报 No such file。
8. **node --check 顶层 return 必报 Illegal return** → 用 async 包装 `(async()=>{...})()` 或替换顶层 await 后检查。

### 三、输出膨胀类（已修②）
9. **coverage 每类携带完整 checked, 同组跨类复制 N 遍** → 已改全局去重(globalChecked/globalUnchecked), 每条 checked 只归属首个涉及的类。
10. **finding id 生命周期分裂**（段1 无 id, 段2 才分配 F1..Fn）→ 契约: id 由段2 分配, 段2 索引是 id 唯一持有者, 段3 用 finding_id 关联。

### 四、判断重复/盲区类（纪律）
11. **树外 D-Bus 面被多 agent 独立确认（2026-08-15）** → 当时定为 RECON consumers[] 唯一事实源；**2026-08-16 起消费者树/兄弟扫描整体退役**（版本漂移双向失真），替代为确定性 `exports[]` + 结构性规则"导出即入口点"（export-contract → 默认 REACHABLE）。HUNT/VALIDATE 一律不重查树外。
12. **"有界"误判为"无 bug"**（remove 循环 j<=i<=63 no OOB → NOT_FOUND, 漏了值语义损坏）→ HUNT 验证视角已加"写出的值语义是否正确"(子串误匹配/索引不同步/数据结构破坏)。
13. **兄弟组件版本漂移（2026-08-16 新增）**：兄弟包引用目标 API 时可能已是旧契约 → "有引用"=陈旧误报、"无引用"=采样空洞假阴性，双向失真 → 不再以兄弟扫描做可达性依据；导出即入口点由目标本地 `exports[]` 决定。

## 状态

- **v1（完成）**：段1（RECON→HUNT→GAPFIL）已实现并冒烟通过（ksaf-dynamic-uid，3 agent，token 对比记录在 `workspace/runs/ksaf-dynamic-uid-smoke/token-comparison.md`）。
- **v2.1（完成）**：段1 派发改造——**文件聚合分组**（RECON 候选池 `candidate_hits`/`class_file_map` → 脚本按文件分组：.c 文件组、.h 并入 .c、.sh 整文件；零候选类 SKIPPED；≤6/轮分批；排序 = 特权上下文 + RECON `group_priority` 覆盖）。test-libsecurity1-workflow 实测模拟：23 类制 28 agent → 文件聚合 6 agent/1 轮（RECON 7 类 35 候选点 → 5 组）。
- **v2（完成）**：段2（TRACE+VALIDATE，KILL 税前置 + 否证优先 + 条件门禁）+ 段3（CHAIN+REPORT，CVSS 富化）+ model 分层（trace/validate=pro, hunt/chain/report=flash）。端到端验证（ksaf-init 纯净源码）见 `workspace/runs/ksaf-init-clean-2025-08-15/E2E-SUMMARY.md`。独立会话在 libsecurity1 上复现历史漏洞（CWE-78 注入 + CWE-476 NULL 解引用，均真实 repro 确认）。
- **v2.2（完成，2026-08-16）**：RECON 全面目标本地化——
  - **消费者树/兄弟扫描退役**：三脚本 consumers 清零，`siblings_root` 移除；
  - **导出即入口点**：`exports` CLI（exports.sc + 头文件交叉 → intended/accidental/internal）+ 结构性规则（无树内调用方的导出默认 REACHABLE，`reachability_basis` 标注），validate.js 的 consumersBlock → exportsBlock；
  - **权限上下文确定性化**：`pctx` CLI（C/守护进程信号集）preflight 产出 `privilege_ctx`，单一事实源，喂 VALIDATE attacker_model 与 REPORT CVSS；
  - **威胁推导纪律**：RECON 产出 `threats[]`（每入口点 ≥1 threat → 映射类），`recommended_classes` 从 threats 聚合推导；
  - 已实测：pctx 确定性（ksaf-audit-daemon=high / libsecurity1=unknown）；exports 分类正确（libsecurity1 6 intended + main accidental）。
- **v2.3（完成，2026-08-18）**：**全通纪律落地**——修正与"默认消费者树全通"相悖的 7 处设计（libsecurity1-pure 复盘）：
  - VALIDATE 禁止"调用者身份/特权中介缺失"做否证前置（F3 实证：非特权直连→文件权限门→EACCES 的 kill 违背全通）；
  - kill_reason 全通类别门禁（export-contract 命中禁止类别 → repair 拦截）；
  - `env_blocked` 独立状态，不进 `killed[]`（F6 实证：环境性结论不再当硬 kill）；
  - REPORT 全通 PR 规则（pctx=unknown 的导出 API 不保守取 H）；
  - 导出回填扩展到全部推荐类（2.0b 改造，F3 实证：null-deref 未推荐→导出 API 健壮性面盲区）；
  - CHAIN 默认含导出契约链步；
  - exportsBlock 全通语义结构化传给 HUNT+VALIDATE。
- **v3（完成，2026-08-21）**：**auditor+tracer 合并**——
  - HUNT/GAPFIL 每个 finding 直接产出可达性 trace 字段（trace_result/call_chain/data_flow/defenses_checked/reachability_basis），TRACE 阶段删除；
  - 段2 改名 `validate.js`：只对 REACHABLE finding 派 c-exploit；UNREACHABLE 进 `unreachable[]`；
  - VALIDATE 增加"独立可达性挑战"（不盲信 HUNT trace，先独立否证再 PoC），补偿合并丢失的第二视角；
  - `schemas/stage-finding.json` 升级为 finding+trace 合并契约；`gate.py` 同步；`tracer.md`/`stage-trace.json` 标 ARCHIVED；
  - 全通纪律从 TRACE 平移至 HUNT 判定（导出契约入口默认 REACHABLE 仍成立）。
- **类空间（已补全 25 键）**：`CLASS_SECTIONS` 覆盖 schema 枚举全部类（除 other）——内存安全 8 + 注入/路径 5（含 shell-injection）+ 权限 4（含 spoofable-identity）+ Python 2（eval-injection/unsafe-deserialization）+ 交叉 5（toctou/race-condition/memory-leak/resource-leak/crypto-weakness/info-disclosure）。RECON 按目标实际适用性从中选 ≥3 类；**不要再传 `classes: [全部键]`**（已废除）。
- **待办**：
  1. VALIDATE sanitizer 分支已在 libsecurity1 验证（F1/F2/F3 均 sanitizer/repro 确认）✅
  2. casefile/ledger 对接（ledger add/log 确定性 CLI 由 agent 调用）
  3. ~~RECON 对库目标把导出 API 注册为入口点~~ → **已由 exports CLI + 导出即入口点结构规则解决**（v2.2）✅

## 相关路径

| 项 | 路径 |
|---|---|
| 脚本 | `skills/workflow-audit/audit-pipeline.js` / `validate.js` / `chain-report.js` |
| 交接文档 | `workflow/TASK-SUMMARY.md` |
| 原层级式编排 | `skills/pipeline/SKILL.md` |
| 确定性编排层 | `skills/audit-runner/` |
| 底层硬封装 | `extensions/audit-tools.py`（PATH: `audit-tools`） |
| CWE 方法论 | `skills/code-audit/SKILL.md` |
| 角色简报 | `agents/harness.md` / `auditor.md` / `exploit.md` / `chain.md`；`tracer.md` 标 ARCHIVED（2026-08-21 并入 auditor） |
