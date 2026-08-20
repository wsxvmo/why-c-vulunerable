// out-of-bounds-read.sc — 越界读 (CWE-125)
// ============================================================================
// 依据: code-audit §1.2
//   Checklist: 攻击者可控索引(含负索引); 循环 off-by-one (<= vs <, len vs len-1);
//   strlen 结果当索引读越 NUL; memcmp/memchr/read 的 n 过大。
// 权限/触发上下文: 索引来自攻击者可控输入(库 API 参数/配置值) → trigger_context
//   取决于调用入口; 无内核凭据参与, privilege_context 继承调用进程。
// ============================================================================

// 主查询1: 数组/指针索引访问 + 关联的 strlen/strnlen 长度(候选: 长度驱动索引)
println(cpg.call.name("(strlen|strnlen|strlen_s).*").map { c =>
  s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}"
}.l.distinct.sorted.mkString("\n"))

// 主查询2: indirectIndexAccess(数组下标)中索引表达式非字面量 — 人工核对上界
println(cpg.call.name("<operator>.indirectIndexAccess")
  .filter(c => !c.argument(1).code.matches("[0-9]+"))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} idx=${c.argument(1).code.take(40)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: memcmp/memchr/read 等 n 参数来自变量
// println(cpg.call.name("(memcmp|memchr|memcpy|read|recv).*").filter(c => !c.argument.l.last.code.matches("[0-9]+")).map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} n=${c.argument.l.last.code.take(40)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "strlen\(|strnlen\(|\[[A-Za-z_][A-Za-z0-9_]*\]" <files>
//   rg -n "memcmp\(|memchr\(|memcpy\(|read\(" <files>
