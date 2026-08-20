// info-disclosure.sc — 信息泄露 (CWE-200)
// ============================================================================
// 依据: code-audit §7.3
//   Checklist: 栈回溯/调试输出含敏感数据(路径/指针/env); 错误消息泄露文件存在性/
//   用户存在性/内部路径; world-readable 文件含机密(与 permission-assignment 交互);
//   日志记录密码/token。
// 权限/触发上下文: 泄露本身多为 low, 但常作为提权链第一步(info-disclosure + 漏洞
//   → 本地提权链); CHAIN 阶段高价值。
// ============================================================================

// 主查询: 敏感值写入日志/输出(fprintf/syslog/printf 含指针/路径/env 变量)
println(cpg.call.name("(fprintf|syslog|printf|dprintf|fputs|puts).*")
  .filter(c => c.argument.code(".*(%p|%x|%s|%d).*").size > 0 && c.code.matches(".*(path|file|env|key|token|password|secret|ptr|buf|dir).*"))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: 错误消息泄露内部路径/敏感文件名
// println(cpg.call.name("(perror|strerror).*").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "fprintf\(|syslog\(|printf\(|perror\(" <files>
//   rg -ni "(password|token|secret|key|passwd).*(log|print|printf|syslog)" <files>
//   rg -n "%p|%x" <files>   # 指针/地址泄露
