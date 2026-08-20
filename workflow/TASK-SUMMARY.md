# 任务总结：把 why-c-vulnerable 审计 skill 改造成 DSH workflow 流水线

> 给接手 agent 的交接文档。本文自包含，无需依赖任何会话记忆。
> 最后更新：2025-08-15

## 一句话任务

把现有的 `skills/pipeline`（c-harness 协调器模式的审计流水线）改造成 **DSH `workflow` 工具驱动的无主-agent 流水线**：脚本文件永久保存、每次调用传入执行，主 agent 只发起一次、不再持有全阶段会话历史。

## 背景（为什么做）

现状是"层级式"：一个主 agent（c-harness）活过全部 7 个阶段 × 60+ 轮，每轮把整个会话历史重发给模型。实测一个 ksaf-init 审计会话：

- 主 agent 累计 token：**32.1M**（其中 **31.8M 是 cacheReadTokens**——每轮重发历史前缀的累加，即"会话长寿税"）
- 子 agent 合计：仅 **1.5M**（真实分析成本，省不掉）
- 当前单轮上下文：**~29.3 万 tokens**（窗口 100 万）

结论：主 agent 里 90% 的工作（调度/状态/校验/汇总）是确定性逻辑，不需要 LLM 持有一个长寿会话来做。用户决定：改成流水线式作业（无主 agent），阶段间只通过产物/状态传递。

## 已确认的事实（带证据，接手者无需重新验证）

### DSH workflow 工具
- **存在且可用**：`@deepseek-ai/dsh-tool-workflow` + `workflow-worker-thread`，在 `standard` preset 中注册（`agent.cordis.yml` L226-227），当前会话 `agentPreset: "standard"`，**实测连通性通过**（最小 echo 测试返回 WORKFLOW_OK）。
- **GUI 看不到它**：web 端没有为 workflow 做专门 UI 面板——它是"模型可调用、界面不展示"的工具。这不是禁用，是 UI 未覆盖。
- 调用方式：`workflow({meta: {name, description, whenToUse?, phases?}, script: "<JS>", args: {...}})`。脚本是**每次调用时的字符串参数**，支持 top-level await，结尾 `return <json>`。

### workflow 的能力边界（重要约束）
- `agent(prompt, opts)` 的 opts **只支持**：`label` / `phase` / `schema`(简单子集) / `provider` / `model`。
- **`effort` / `isolation` / `agentType` 会被显式拒绝**（worker.cjs L512-513 报 `UNSUPPORTED_OPTION`）。
- **不能 per-agent 自定义工具/权限**：子 agent 工具集 = 宿主会话 standard preset 全量工具。工具隔离只能靠 DSH 配置层（自定义 preset/profile），workflow 工具层无口子。
- 引擎注入：`["tools", "workflowEngine", "systemPrompt"]`；运行记录会以 `tool-workflow/agent-start|end` 追加进会话（durable record，仅运行日志，非可调用模板）。
- 无 CLI 子命令、无 registry/模板/文件加载机制。

### workflow 保存机制
- **不能注册保存**：脚本是调用参数，跑完即散（只留运行记录）。
- **可行方案（用户已认可方向）**：脚本写成文件，每次调用时 `read` 文件 → 内容作为 `script` 参数传入。文件即"永久保存"，可进 git。
- 推荐形态：打包成 **skill**（`skills/workflow-audit/`），SKILL.md 说明用法 + 脚本文件放目录内。

### 为什么 tool/插件隔离先不做
用户明确指示：**先不着急做工具/插件隔离**，先把 skill 做成 workflow。工具隔离（每阶段不同 preset）留到 workflow 骨架跑通之后。

## 目标产物

```
skills/workflow-audit/
├── SKILL.md          # 用法说明：何时用、怎么调用、阶段划分、输入输出契约
└── audit-pipeline.js # workflow 脚本本体（永久保存，每次 read 后传入 workflow 工具）
```

脚本内部结构（最小骨架起，逐步扩展）：
- 接 `args.target`（目标源码路径）
- `phase("recon")` / `phase("hunt")` / `phase("report")` 分阶段
- 每阶段 `agent(prompt, {phase, model?})` 派独立 agent（可用不同 model 实现 deliberate disagreement）
- 阶段间只通过结构化值/文件传递，不共享会话上下文
- 结尾 `return` 汇总结果（JSON）

## 下一步行动（接手者从这里继续）

1. 建 `skills/workflow-audit/` 目录（skill 需要 __init__ 或按现有技能树约定，参考 `skills/audit-tools/` 的结构）
2. 写**最小可用**脚本 `audit-pipeline.js`：RECON（入口枚举）→ HUNT（1-2 个 CWE）→ REPORT 四阶段，跑通即可
3. 用真实数据验证：对 `exp-audit/` 或任意小目标跑一次，确认 token 对比（目标：主 agent 参与降到一次调用）
4. SKILL.md 写调用说明
5. 逐步加 GAPFIL/TRACE/VALIDATE/CHAIN 阶段 + casefile 对接（`audit-runner` 的 ledger/gate/coverage 都是确定性 CLI，可被脚本内 agent 调用）

## 关键路径速查

| 项 | 路径 |
|---|---|
| 现有流水线 skill | `/home/xvmo/why-c-vulunerable/skills/pipeline/SKILL.md` |
| 确定性编排层 | `/home/xvmo/why-c-vulunerable/skills/audit-runner/`（doctor/cpg/gate/coverage/ledger/resilience CLI） |
| audit-runner 修复（已做） | `config.py` 的 `_check_codebase_memory()` 改为唯一探测名防缓存假阳性 |
| 实验产物（token 账单/报告） | `/home/xvmo/exploit-src/ksaf-init-1.0.1-08.ky11.src/exp-audit/REPORT.md` |
| workflow 工具实现 | `/home/xvmo/.npm/_npx/1e7f6d9597241db0/node_modules/@deepseek-ai/dsh-tool-workflow/lib/index.js` |
| workflow agent 启动参数 | `/home/xvmo/.npm/_npx/1e7f6d9597241db0/node_modules/@deepseek-ai/dsh-workflow-worker-thread/lib/index.js` L478-496 |
| 会话 token 统计 | `/home/xvmo/.dsh/storages/session_projcache.json`（`tables.sessions.<id>.rows.tokenUsage.val.totals`） |
| 当前主会话 id | `session-8eb9ec34-b153-46bf-84aa-fdff75b91447` |

## 2026-08-16 变更：RECON 全面目标本地化（v2.2）

设计收敛（多轮讨论结论，全部已落代码）：

1. **消费者树/兄弟扫描整体退役**：版本漂移使"有引用=陈旧误报 / 无引用=采样空洞假阴性"双向失真，负期望价值。三脚本 consumers 引用清零，`siblings_root` 从契约移除。
2. **导出即入口点**：新增 `audit-runner exports`（`queries/exports.sc` + 头文件交叉 → `intended/accidental/internal`）。结构规则：`kind∈{intended,accidental}` 且 `in_tree_callers==0` 的导出 → 自动注入候选池（权限类缺省审计点）；TRACE 中该 sink 默认 **REACHABLE**（`reachability_basis="export-contract"`），不再 requires_external_verify。`trace-validate.js` 的 consumersBlock → exportsBlock。
3. **权限上下文确定性化**：新增 `audit-runner pctx`（C/守护进程信号集）——preflight 产出 `privilege_ctx`，单一事实源；RECON 引用不重推；喂 TRACE attacker_model + REPORT CVSS（AV/PR/UI）。
4. **威胁推导纪律**：RECON 产出 `threats[]`（每入口点 ≥1 threat → 映射类），`recommended_classes` 从 threats 聚合推导；`group_priority` 有"threat 价值 × pctx 权重"的确定性默认。

实测：pctx 确定性（ksaf-audit-daemon=high/User=root，libsecurity1=unknown，ksaf-dynamic-uid=low）；exports 分类正确（libsecurity1 6 intended + main accidental）。

## 验收标准

- [ ] `skills/workflow-audit/` 存在，SKILL.md 可读
- [ ] `audit-pipeline.js` 跑通最小骨架（RECON→HUNT→REPORT），对真实目标有输出
- [ ] 调用方（主 agent）只发一次 workflow 调用，不持有阶段中间产物
- [ ] token 对比记录：主 agent 上下文税显著下降（目标：单轮 < 10 万）
