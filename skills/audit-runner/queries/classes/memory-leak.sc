// memory-leak.sc — 内存泄漏 (CWE-401)
// ============================================================================
// 依据: code-audit §7.1
//   Checklist: malloc 在错误/早退路径无匹配 free; open/fdopen 全路径无 close;
//   循环内泄漏句柄。确认(functional): valgrind leak summary definite loss。
// 注意: joern 静态判定"泄漏"需路径分析, fuzzy CPG 不可靠 → 本资产以
//   "分配调用 + 函数内是否有 free" 做候选池, 人工核对错误路径。
// 权限/触发上下文: 泄漏多为 DoS(内存耗尽); 影响有限, 非提权面。
// ============================================================================

// 主查询1: malloc 族分配, 所在方法体无 free(候选: 泄漏或跨函数所有权转移)
println(cpg.method
  .filter(m => m.call.name("(malloc|calloc|realloc|strdup|strndup|asprintf|vasprintf).*").size > 0 && m.call.name("free").size == 0)
  .flatMap(m => m.call.name("(malloc|calloc|realloc|strdup|strndup|asprintf|vasprintf).*")
    .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} (方法内无 free)"))
  .l.distinct.sorted.mkString("\n"))

// 主查询2: open/fdopen 无 close(句柄泄漏)
println(cpg.method
  .filter(m => m.call.name("(open|openat|fopen|fdopen|creat).*").size > 0 && m.call.name("(close|fclose).*").size == 0)
  .flatMap(m => m.call.name("(open|openat|fopen|fdopen|creat).*")
    .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} (方法内无 close)"))
  .l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "malloc\(|calloc\(|strdup\(|asprintf\(" <files>
//   rg -n "open\(|fopen\(|fdopen\(" <files>
//   对每个分配/打开: 所有返回路径都有 free/close 吗? 错误路径最易漏
