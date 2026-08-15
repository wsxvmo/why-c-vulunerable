---
name: workflow-audit
description: Leaderless C/C++/Shell/Python code audit pipeline driven by the DSH workflow tool. Use for full-pipeline audits (RECON→HUNT→GAPFIL→TRACE→VALIDATE→CHAIN→REPORT) that must NOT hold a long-lived coordinator session — the script audit-pipeline.js is read from disk and passed as the workflow script parameter each call, every stage runs as a fresh workflow subagent, and the caller only holds compact JSON between segments. Keeps all audit discipline (audit-runner/audit-tools enforcement, schema gates, sanitizer confirmation) from skills/pipeline (codeaudit-pipeline) while eliminating the coordinator's session-longevity token tax.
---

# workflow-audit — DSH workflow 无主-agent 审计流水线

## 何时用 / 何时不用

**用**：对完整目标跑全流水线审计（RECON→HUNT→GAPFIL→TRACE→VALIDATE→CHAIN→REPORT）。主 agent 只发一次 `workflow` 调用、只持有紧凑 JSON 中间产物；各阶段在**新鲜上下文的子 agent** 中执行，不共享会话历史。

**不用**：单文件/单函数快速判断（直接 read/grep 或普通 subagent 即可）；两三个 agent 能解决的小任务（workflow 是重编排工具）。

## 为什么存在（背景）

原 `skills/pipeline`（codeaudit-pipeline）是层级式：主 agent（c-harness）活过 7 阶段 × 60+ 轮，每轮重发全部会话历史——实测 32.1M tokens 中 **31.8M 是 cacheReadTokens 的"会话长寿税"**，真实分析成本仅 1.5M。改造目标：调度/状态/校验/汇总等确定性逻辑搬进 workflow 脚本（0 token），LLM 只花在判断上。

## 三段式（每段 = 一次 workflow 调用）

```
段1 workflow: RECON → HUNT → GAPFIL          ← audit-pipeline.js（v1 已实现）
     ↓ return {findings[], coverage}          ← 主 agent 过目/干预点
段2 workflow: TRACE → VALIDATE               ← trace-validate.js（v2 已实现）
     ↓ return {confirmed[], killed[]}
段3 workflow: CHAIN → REPORT → LEDGER        ← chain-report.js（v2 已实现）
     ↓ return {report, ledger}               ← 最终交付 + casefile 台账
```

> 合并而非一阶段一段的原因：脚本内 JS 变量传递阶段产物 = 0 token；拆成独立调用则每段数据要穿过主 agent 中转，确定性编排税重新出现。分三段保留 3 个可中断/可续跑/可人工干预的检查点。

## Model 分层（deliberate disagreement）

workflow 的 `agent(prompt, {model})` 支持 per-agent 模型覆盖（plain subagent 做不到）。默认分层（可经 `args.models` 覆盖，见下）：

| 阶段 | 默认模型 | 理由 |
|---|---|---|
| HUNT | deepseek-v4-flash | 标准模型，广撒网 |
| TRACE | deepseek-v4-pro | 更强模型做逐跳验证 |
| VALIDATE | deepseek-v4-pro | 与 HUNT 不同，避免共享盲点 |
| CHAIN/REPORT | deepseek-v4-flash | 轻量分析 |

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
| `classes` | 可选 | 段1：CWE 类列表。**默认并入 RECON 推荐（RECON 为主要方向）**；传 `classesMode:"pin"` 时仅用此清单 |
| `findings` | 段2 必填 | 段1 返回的 `findings[]`（脚本自动分配 id F1..Fn） |
| `cpg_path` | 段2 必填 | 段1 recon 构建的 CPG 路径 |
| `tricks_injection` | 段2 可选 | 段1 返回的 `tricks_injection`（经验前馈注入块），原样转发 |
| `confirmed` | 段3 必填 | 段2 返回的 `confirmed[]` |
| `coverage` | 段3 可选 | 段1 返回的 `coverage[]`，补进报告 |
| `models` | 可选 | `{hunt?, trace?, validate?, chain?, report?}` 模型覆盖 |

### 段2/段3 追加契约

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| TRACE | parallel, 每 finding 1 个（KILL 税前置内置） | ≤6 并发 | 每 finding `{finding_id, trace_result: REACHABLE\|UNREACHABLE\|KILLED, entry_point, call_chain[], data_flow, defenses_checked[], attacker_model, impact_if_reachable?, unreachable_reason?, kill_reason?}` |
| VALIDATE | parallel, 每 REACHABLE finding 1 个（否证优先 + sanitizer） | ≤6 并发 | 每 finding `{finding_id, status: confirmed\|killed, technique_used, detection_method, build_config?, sanitizer_result?, poc_path?, run_log?, evidence_extracted?, kill_reason?}` |
| CHAIN | 1 个 agent（仅 confirmed>0 时） | 1 | `{chains[], summary}` |
| REPORT | confirmed>0 时 1 个 report agent 补 CVSS；否则纯脚本聚合 | 0-1 | `{findings[], summary}` |

**脚本内条件门禁**（段2）：confirmed → poc_path/run_log/evidence_extracted 必填；killed → kill_reason 必填；不合格 repair ≤2 次重派。

**段2 返回契约**：`confirmed[]`（每项含完整 finding+trace+validation）、`killed[]`（VALIDATE 级 kill）、`killed_by_gate[]`（TRACE 级 KILL 税拦截，含完整 trace 对象）、`gate`、`stats`、`agents`。finding 与 trace 按序绑定（pair），finding_id 偏差有 positional 兜底，不会丢 finding 字段。

**段1 去重（C）**：同一 `file+sink`（行距 ≤10）的跨类同根因 finding 合并为一条（保留证据最全/置信度最高者，`cls_all` 记录全部来源类），防段2 重复 trace/validate。

**段3 LEDGER（B 收尾落账）**：末尾 1 个 agent 把最终 confirmed+coverage 一次性写入 casefile 台账（`runDir` 下：init → add 每 case（`audit-runner ledger --op add --dedup-key` 自动去重）→ log 证据 → `casefile.py report --out runDir/report/casefile-report.md`）。不做全程状态机——编号收尾一次性分配，无跨段接力链。返回 `ledger: {casefile_initialized, report_path, case_ids}`。casefile 的"状态机约束 agent"职责在无主 agent 模型下已由脚本门禁接管（见上），台账保留"记录+索引+人工时间线"价值。

## 段1 阶段契约

| 阶段 | 形态 | agent 数 | 输出 |
|---|---|---|---|
| RECON | 1 个 agent | 1 | `{languages, entry_points[], cpg_path, toolchain, assumptions[], recommended_classes[], tricks_injection, exclude_files[]}` + `runDir/recon/recon.json` |
| HUNT | parallel, 每 CWE 类 1 个 | ≤6 并发 | 每类 `{cls, findings[], checked[], unchecked[], notes?}` + `runDir/hunt/<cls>/` |
| GAPFIL | 最小循环（对 INCOMPLETE 类补查 1 轮） | ≤6 并发 | 同上（替换原结果） |

### 经验前馈（tricks 注入, 原框架硬规则）

RECON 按目标类型从 `skills/tricks/SKILL.md` 选 2-4 个相关章节（守护进程/DBus → §2 身份信任边界+§4 深挖；库目标 → §5 差分索引；setuid → §1 攻击面优先级），提炼 ≤200 字可操作注入块 → `tricks_injection`，脚本**前置到每个 HUNT/GAPFIL auditor 提示词**，并经段1 返回值转发给段2（`args.tricks_injection`）注入每个 TRACE 提示词。这是"历史复盘经验进入本轮审计"的通道（libsecurity1 那次 RECON 即兴生成该字段但编排层未转发的缺口已补上）。

### 技能加载分层（audit-runner/audit-tools）

- **RECON**：read `audit-runner/SKILL.md` 与 `audit-tools/SKILL.md` **全量一次**（跑 doctor/建 CPG/生命周期与 fork 策略，一次值回票价）。
- **执行 agent（HUNT/GAPFIL/TRACE/VALIDATE）**：只带脚本内置纪律块（禁裸 joern/println/降级/干净 cwd/工具分工），**不重读全量 SKILL.md**（内容重叠+稀释注意力）；遇到纪律块未覆盖的边界情况时条件引用（如 CPG 并发排队 → read `audit-runner/SKILL.md` §并发策略）。
- **待办**：CPG fork 优化——RECON 产出 `fork_paths[]`（每并发 agent 一份私有 CPG 副本），脚本分配给各 auditor，替代共享 CPG + flock 串行。

### 类选择机制（A+B — RECON 为主要方向）

1. **RECON 是主要方向**：`recommended_classes`（必填，RECON 模型按语言/目标类型/权限上下文推荐 ≥3 类）永远是猎杀清单的基础。**调用方的 `classes` 默认只是并入（并集追加），不会顶掉 RECON 的判断**——因为调用方往往不如看过源码的 RECON 了解目标。
2. **人工 pin 覆盖**：传 `classesMode: "pin"` 时，猎杀清单 = 仅调用方 `classes`（冒烟压成本/已知目标定范围/人为指定重点）。
3. **语言剪枝（确定性兜底）**：无论 merge/pin，最终按 `recon.languages` 剪掉不适用类——无 python 剔 `eval-injection`/`unsafe-deserialization`，无 shell 剔 `shell-injection`，非 C/C++ 剔内存安全 8 类；剪光则落 `["command-injection","race-condition"]`。
4. **防静默漏检**：返回 `classes: {mode, requested, recommended, effective, pruned}`——调用方能看见"RECON 推荐了哪些、调用方加了哪些、实际跑了哪些、剪了哪些"。coverage 只覆盖 effective 类，不等于全类审计。

**finding 必填字段**（与 `schemas/stage-finding.json` 对齐）：`vuln_class, file, line(整数), sink, entry_point, confidence(low|medium|high), evidence(entry→sink)`。

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
- [ ] **VALIDATE sanitizer 分支**：代码完整但无 finding 到达（本轮全被 TRACE 否掉）— 需已知漏洞 fixture 补验
- [ ] **casefile/ledger 对接**：确定性 CLI（ledger add/log）由 agent 调用，待接入

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

## 状态

- **v1（完成）**：段1（RECON→HUNT→GAPFIL）已实现并冒烟通过（ksaf-dynamic-uid，3 agent，token 对比记录在 `workspace/runs/ksaf-dynamic-uid-smoke/token-comparison.md`）。
- **v2（完成）**：段2（TRACE+VALIDATE，KILL 税前置 + 否证优先 + 条件门禁）+ 段3（CHAIN+REPORT，CVSS 富化）+ model 分层（trace/validate=pro, hunt/chain/report=flash）。端到端验证（ksaf-init 纯净源码）见 `workspace/runs/ksaf-init-clean-2025-08-15/E2E-SUMMARY.md`。独立会话在 libsecurity1 上复现历史漏洞（CWE-78 注入 + CWE-476 NULL 解引用，均真实 repro 确认）。
- **类空间（已补全 25 键）**：`CLASS_SECTIONS` 覆盖 schema 枚举全部类（除 other）——内存安全 8 + 注入/路径 5（含 shell-injection）+ 权限 4（含 spoofable-identity）+ Python 2（eval-injection/unsafe-deserialization）+ 交叉 5（toctou/race-condition/memory-leak/resource-leak/crypto-weakness/info-disclosure）。完整审计传 `classes: [全部键]`。
- **待办**：
  1. VALIDATE sanitizer 分支已在 libsecurity1 验证（F1/F2/F3 均 sanitizer/repro 确认）✅
  2. casefile/ledger 对接（ledger add/log 确定性 CLI 由 agent 调用）
  3. RECON 对库目标把导出 API 注册为入口点（§6c C ABI Export Surface——libsecurity1 F4 KILL-1 教训）

## 相关路径

| 项 | 路径 |
|---|---|
| 脚本 | `skills/workflow-audit/audit-pipeline.js` |
| 交接文档 | `workflow/TASK-SUMMARY.md` |
| 原层级式编排 | `skills/pipeline/SKILL.md` |
| 确定性编排层 | `skills/audit-runner/` |
| 底层硬封装 | `extensions/audit-tools.py`（PATH: `audit-tools`） |
| CWE 方法论 | `skills/code-audit/SKILL.md` |
| 角色简报 | `agents/harness.md` / `auditor.md` / `tracer.md` / `exploit.md` / `chain.md` |
