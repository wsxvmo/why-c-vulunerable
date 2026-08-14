# joern 查询模板（audit-runner/queries/）

使用纪律（来自 15 份复盘）:
1. **每条查询必须以 println 结尾**（本模板已内置）—— 尾表达式不会自动输出。
2. 输出行无 `[INFO]` 前缀; 若查询结果为空（只有 INFO 行）, **转 grep 兜底, 不重试**。
3. 从干净 cwd 跑（`python3 -m cpg query` 已自动处理）。
4. 方法面枚举用 `fullName.contains(...)`, 不要 `method.name("(Class)::.*")`（joern name 不带类前缀）。
5. Location 是值对象: 只能取 filename/lineNumber, 没有 .code/.method。
6. 转义: 查询写成 .sc 文件再传入, 避免 shell 引号链。

新增模板时保持同风格（println + 注释教训来源）。
