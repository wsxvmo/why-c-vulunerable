// use-after-free.sc — 释放后使用 (CWE-416)
// ============================================================================
// 依据: code-audit §1.3
//   Checklist: 所有 free() 调用点 — 指针之后是否被使用(同函数/经存储引用);
//   一条路径释放另一条路径使用(错误路径/refcount bug); 全局/静态指向已释放内存;
//   双重所有权(两个结构指向同一堆块, 一个释放)。
// 注意: joern fuzzy CPG 对"跨函数经存储引用使用"不可见 → 主查询只抓同函数,
//       跨函数/全局指针靠 grep 兜底 + 人工。false positives: 函数末尾 free 后无使用。
// 权限/触发上下文: 同函数使用 → 攻击者触发释放路径; 跨函数 → 依赖调用方。
// ============================================================================

// 主查询: 同函数内 free(x) 后 x 再次出现在参数/解引用中
println(cpg.method.filter(m => m.call.name("free").size > 0 && m.call.name("free").argument.code(".*\\w+.*").size > 0).map { m =>
  val freed = m.call.name("free").argument.l.map(a => a.code.replaceAll("[\\(\\)\\*&\\s]", "")).filter(_.matches("[A-Za-z_]\\w*")).distinct
  val after = m.call.nameNot("free").argument.code(".*").l.map(_.code).mkString("|")
  freed.filter(f => after.contains(f)).map(f => s"${m.location.filename}:${m.location.lineNumber}:${m.name} freed=${f}")
}.l.flatten.distinct.sorted.mkString("\n"))

// 变体1: 全部 free 调用点(供人工核对释放后路径)
// println(cpg.call.name("free").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.argument(1).code}").l.distinct.sorted.mkString("\n"))

// 变体2: 全局/静态指针 = 释放候选(跨函数 UAF 高危面)
// println(cpg.method.filter(m => m.call.name("free").size > 0).flatMap(m => m.call.name("free").map(c => c.argument(1).code)).l.filter(_.matches("(g_|global_|static_)?[A-Za-z_].*")).distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "free\(" <files>          # 全部释放点
//   rg -n "(g_|global_|static_).*=" <files>   # 全局指针(跨函数 UAF)
