// double-free.sc — 双重释放 (CWE-415)
// ============================================================================
// 依据: code-audit §1.4
//   Checklist: 两条路径都到达 free(p)(错误处理+正常路径); 循环内 free + 循环后 free;
//   realloc 失败模式: p = realloc(p,..) 失败时 p 仍有效 → 后续 double free。
// 权限/触发上下文: 触发需要攻击者影响执行路径(错误路径/循环计数) → trigger 取决于入口。
// ============================================================================

// 主查询: 同函数内同一变量被 free ≥2 次
println(cpg.method.filter(m => m.call.name("free").size >= 2).map { m =>
  val frees = m.call.name("free").argument.l.map(a => a.code.replaceAll("[\\(\\)\\*&\\s]", "")).filter(_.matches("[A-Za-z_]\\w*"))
  frees.groupBy(identity).collect { case (v, l) if l.size >= 2 => s"${m.location.filename}:${m.location.lineNumber}:${m.name} double-free=${v}" }
}.l.flatten.distinct.sorted.mkString("\n"))

// 变体: free 在循环内 + 循环后(候选: 循环提前 break 后仍 free)
// println(cpg.method.filter(m => m.call.name("free").size >= 2).map(m => s"${m.location.filename}:${m.location.lineNumber}:${m.name} frees=${m.call.name("free").size}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "free\(" <files>          # 全部释放点(人工核对同一变量多条路径)
//   rg -n "realloc\(" <files>       # realloc 失败 → 双重释放候选
