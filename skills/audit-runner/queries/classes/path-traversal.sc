// path-traversal.sc — 路径遍历 (CWE-22/23)
// ============================================================================
// 依据: code-audit §2.2
//   Checklist: open/fopen/openat/rename/unlink 路径由攻击者输入构造; 缺 .. / 绝对
//   路径净化; chroot 未 chdir(chroot 逃逸经典)。
// 注意: libconfig 类库把"路径"抽象为配置树 key(snprintf "%s.%s") → 非文件系统路径,
//       需人工区分; 本资产以文件打开调用 + 路径拼接为候选池。
// 权限/触发上下文: 写路径攻击者可控 → 任意文件写/读; privilege 继承调用进程。
// ============================================================================

// 主查询: 文件打开/操作调用, 路径参数含变量或拼接(非常量路径)
println(cpg.call.name("(open|openat|fopen|creat|rename|unlink|remove|stat|lstat|access|chmod|chown).*")
  .filter(c => !c.argument.code.l.exists(x => x.matches("^\"[^\"]*\"$")))
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: 路径拼接(snprintf 拼路径 + 后续文件操作) — 跨语句人工核对
// println(cpg.call.name("(snprintf|sprintf|strcat|strcpy).*").filter(c => c.code.matches(".*(path|dir|file|name).*")).map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "open\(|fopen\(|openat\(|rename\(|unlink\(|creat\(" <files>
//   rg -n "snprintf\([^)]*(path|dir|file)|strcat\([^)]*(path|dir|file)" <files>   # 路径拼接
