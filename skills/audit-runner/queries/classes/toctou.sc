// toctou.sc — 检查-使用竞态 (CWE-362/367, TOCTOU 独立键)
// ============================================================================
// 依据: code-audit §2.5(与 race-condition 共享方法论, 独立键聚焦 check-then-use)
//   Checklist: access(path) 后 open(path); stat 后 write; 检查权限后操作可被
//   替换的路径(symlink/rename 交换)。验证: 循环竞态 rename/symlink 交换。
// 权限/触发上下文: 检查在非特权上下文、使用在特权上下文(如 root 检查后写) →
//   trigger_context=unprivileged_user + privilege_context=high_privilege = 提权面。
// ============================================================================

// 主查询: 同函数内 检查(access/stat/lstat/faccessat) 与 使用(open/write/rename/unlink) 并存
println(cpg.method
  .filter { m =>
    val calls = m.call.name.l
    calls.exists(c => c.matches("(access|stat|lstat|faccessat|statfs|fstat).*")) &&
    calls.exists(c => c.matches("(open|openat|fopen|creat|rename|unlink|remove|write|fwrite).*"))
  }
  .flatMap(m => m.call.name("(access|stat|lstat|open|openat|fopen|creat|rename|unlink|remove).*")
    .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name}"))
  .l.distinct.sorted.mkString("\n"))

// 变体: 检查与使用分离在不同函数(跨函数 TOCTOU) — 需调用图人工核对
//   思路: 找 access(path) 的调用者, 看调用链上是否随后 open(path) 且路径可变。

// grep 兜底模式:
//   rg -n "access\(|stat\(|lstat\(|faccessat\(" <files>
//   rg -n "open\(|fopen\(|rename\(|unlink\(" <files>
//   对每个 access/stat 命中: 同函数/调用链上是否对该路径做 open/write? 中间路径可换? → 候选
