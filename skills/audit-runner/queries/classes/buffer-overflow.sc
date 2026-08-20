// buffer-overflow.sc — 缓冲区溢出 (CWE-120/121/122/787)
// ============================================================================
// 依据: code-audit §1.1 + sinks.sc 正则表(memcpy|strcpy|strcat|sprintf|gets|scanf...)
//   sinks.sc 只列调用点; 本资产补"长度可控性"维度: 拷贝/格式化调用的大小参数
//   是否来自未限界输入(而非 sizeof/字面量)。
// 权限/触发上下文: src/长度来自攻击者可控输入 → trigger 取决于入口;
//   栈/堆溢出 → 本地提权面, privilege_context 继承调用进程。
// ============================================================================

// 主查询1: 经典拷贝 sink 全部调用点(与 sinks.sc 一致, 供逐个人工核对长度)
println(cpg.call.name("(memcpy|memmove|strcpy|strcat|sprintf|vsprintf|gets|scanf|strncpy|strncat|snprintf).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 主查询2: 拷贝/格式化调用的长度或目标参数含非 sizeof 表达式(候选: 未限界)
println(cpg.call.name("(memcpy|memmove|strncpy|strncat|snprintf|vsnprintf).*")
  .filter(c => c.argument.code(".*\\b(len|size|n|count|buflen|length|remaining)\\b.*").size > 0)
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: 固定栈缓冲(数组) + 写调用 — 目标缓冲区容量 vs 写入长度对比
// println(cpg.local.filter(l => l.code.matches(".*\\b(char|unsigned char|uint8_t)\\s+\\w+\\s*\\[[^]]+\\].*")).map(l => s"${l.location.filename}:${l.location.lineNumber}:${l.method.fullName} ${l.code.take(50)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "memcpy\(|strcpy\(|strcat\(|sprintf\(|snprintf\(|gets\(|scanf\(" <files>
//   对每个命中: 核对长度参数是否 ≤ 目标缓冲区容量; 来自 strlen(未限界输入) → 候选
