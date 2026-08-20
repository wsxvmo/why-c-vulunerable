// integer-overflow.sc — 整型溢出 (CWE-190/191)
// ============================================================================
// 依据: code-audit §1.5
//   Checklist: size_t/int 算术喂 malloc/memcpy/数组索引 (n*m, n+1, len-1);
//   有符号/无符号混用、截断 (long→int, size_t→int); strlen(x)+1 先于分配/拷贝;
//   循环计数器溢出。false positives: 前置校验已限界 (if (n > 100) return)。
// 权限/触发上下文: 算术输入来自攻击者可控长度 → trigger 取决于入口; 溢出喂分配
//   → privilege_context 继承调用进程(库内无提权, 影响为内存破坏)。
// ============================================================================

// 主查询1: malloc/calloc/realloc 的大小参数含算术表达式(非字面量/非单变量)
println(cpg.call.name("(malloc|calloc|realloc|alloca).*")
  .filter(c => c.argument.l.headOption.exists(a => a.code.matches(".*[+\\-*/%<<>>].*")))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} size=${c.argument(1).code.take(60)}")
  .l.distinct.sorted.mkString("\n"))

// 主查询2: 移位/算术表达式(候选: 参与索引/长度计算的累加器)
println(cpg.call.name("(<operator>.shiftLeft|<operator>.shiftRight|<operator>.addition|<operator>.subtraction|<operator>.multiplication).*")
  .filter(c => c.argument.size >= 2 && (c.argument(1).code.matches("[A-Za-z_]\\w*") || c.argument(2).code.matches("[A-Za-z_]\\w*")))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(60)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: strlen+1 直接喂 memcpy/strcpy(空输入 off-by-one)
// println(cpg.call.name("(memcpy|strcpy|strncpy).*").filter(c => c.argument.code(".*strlen.*\\+\\s*1.*").size > 0).map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "malloc\(|calloc\(|realloc\(" <files>
//   rg -n "strlen\(.*\)\s*\+|len\s*\*\s*|size\s*\*\s*" <files>
