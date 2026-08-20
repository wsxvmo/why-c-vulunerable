// command-injection.sc — 命令注入 (CWE-78)
// ============================================================================
// 依据: code-audit §2.1
//   Checklist: system/popen/execl* 命令串非常量; 命令由字符串拼接组装
//   (snprintf(cmd,"%s %s",prog,user_input)); shell 元字符可达 (; | & $ ` 换行)。
// 权限/触发上下文: 命令串含攻击者可控输入 → 以调用进程权限执行命令;
//   root daemon 调用 → privilege_context=high_privilege, 命令注入=提权。
// ============================================================================

// 主查询: system/popen/exec 族调用 — 全部调用点(供人工核对命令串来源)
println(cpg.call.name("(system|popen|execl|execlp|execv|execvp|execve|posix_spawn).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(80)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: 命令串拼接(snprintf/sprintf 拼命令变量) — 跨语句需人工
// println(cpg.call.name("(snprintf|sprintf).*").filter(c => c.code.matches(".*(cmd|command|buf|argv).*")).map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "system\(|popen\(|execl|execv|posix_spawn" <files>
//   rg -n "snprintf\([^)]*(cmd|command)|sprintf\([^)]*(cmd|command)" <files>   # 命令拼接
