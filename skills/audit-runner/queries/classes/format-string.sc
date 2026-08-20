// format-string.sc — 格式化字符串漏洞 (CWE-134)
// ============================================================================
// 依据: code-audit §1.8
//   Checklist: printf/fprintf/sprintf/snprintf/syslog 的 format 参数非常量(变量/
//   函数参数/配置值); %n 写原语(攻击者控制 format)。false positives: 字面量格式串;
//   "%s", var 正确的两参形式。
// 注意参数索引: printf→arg1; syslog→arg1; fprintf→arg2; snprintf/sprintf→arg3
//   (arg2 是 size/buffer)。旧版曾用错索引 → 12 FP, 此处已修正。
// 权限/触发上下文: format 来自攻击者输入 → 栈泄露/写; trigger 取决于入口。
// ============================================================================

// 主查询1: 全部 printf 族调用点(供人工核对 format 是否字面量)
println(cpg.call.name("(printf|fprintf|sprintf|snprintf|vsprintf|vsnprintf|syslog|dprintf).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 主查询2: format 参数非常量的调用(粗筛: 排除整串字面量)
println(cpg.call.name("(printf|fprintf|sprintf|snprintf|vsprintf|vsnprintf|syslog|dprintf).*")
  .filter(c => !c.code.matches(".*%s[\"'].*") || c.argument.size >= 2)
  .filter(c => c.argument.l.headOption.exists(a => !a.code.matches("^\"[^\"]*\"$")))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "printf\(|fprintf\(|sprintf\(|snprintf\(|syslog\(" <files>
//   对每个命中: 检查 format 参数是否字面量; 非字面量 → 候选
