// unsafe-temp-file.sc — 不安全临时文件 (CWE-377/378/379)
// ============================================================================
// 依据: code-audit §2.4
//   Checklist: tmpnam/mktemp/tempnam(不安全) 而非 mkstemp/mkdtemp; /tmp 固定路径 +
//   fopen("w"); 临时文件以 0666/0777 创建且无 umask。
// 权限/触发上下文: /tmp 可被任何本地用户预置符号链接 → trigger_context=unprivileged_user;
//   以 root 写可预测路径 → 任意文件覆写, privilege_context=high_privilege。
// ============================================================================

// 主查询: 不安全临时名生成器 + 可预测 /tmp 路径写
println(cpg.call.name("(mktemp|tmpnam|tempnam).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(60)}")
  .l.distinct.sorted.mkString("\n"))

// 主查询2: /tmp 固定路径写(可预测文件名 → 符号链接攻击)
println(cpg.call.name("(fopen|open|openat|creat).*")
  .filter(c => c.argument.code(".*(/tmp|/var/tmp|/dev/shm).*").size > 0)
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: mkstemp 使用正确性(返回值未检查/路径被拼接覆盖)
// println(cpg.call.name("(mkstemp|mkdtemp).*").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(60)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "mktemp\(|tmpnam\(|tempnam\(|mkstemp\(|mkdtemp\(" <files>
//   rg -n '"/tmp/|"/var/tmp/|"/dev/shm/' <files>   # 可预测临时路径
