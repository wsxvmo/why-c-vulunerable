# joern 查询模板（audit-runner/queries/）

使用纪律（来自 15 份复盘）:
1. **每条查询必须以 println 结尾**（本模板已内置）—— 尾表达式不会自动输出。
2. 输出行无 `[INFO]` 前缀; 若查询结果为空（只有 INFO 行）, **先 `.size` 探针区分"真无数据"与"静默空", 再转 grep 兜底, 不重试**。
3. **并发**：同一 CPG 的 joern 查询已由 audit-tools 的 `_cpg_lock`（flock）串行化 + 每次调用唯一工作目录 —— 多 agent 并发查同一 CPG 不再有 workspace 竞态（静默空结果/overwriting）。若绕过 audit-tools 直跑 joern, 必须自行串行 + 唯一 cwd。
4. 方法面枚举用 `fullName.contains(...)`, 不要 `method.name("(Class)::.*")`（joern name 不带类前缀）。
5. Location 是值对象: 只能取 filename/lineNumber, 没有 .code/.method。
6. 转义: 查询写成 .sc 文件再传入, 避免 shell 引号链。

新增模板时保持同风格（println + 注释教训来源）。
