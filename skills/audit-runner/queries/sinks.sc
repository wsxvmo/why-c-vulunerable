// 危险 sink 扫描 — 强制 println; 结果在 stdout, 无 INFO 前缀行
println(cpg.call.name("(memcpy|memmove|strcpy|strcat|sprintf|vsprintf|gets|scanf|system|popen|execl|execlp|execv|execvp|alloca|free|g_free|dlopen|setuid|seteuid|setgid|chmod|fchmod|mkstemp|mktemp|tmpnam|g_dbus_connection_new_for_address_sync).*")
  .location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}")
  .sorted.mkString("\n"))
