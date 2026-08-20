// race-condition.sc — 读-改-写(RMW)无锁序列 / TOCTOU (CWE-362/367)
// ============================================================================
// 依据: code-audit §2.5 + libsecurity1 复盘 case_7a3a04c5fe
//   (4 个 config API 均 config_read_file → 内存修改 → config_write_file, 无 flock,
//   并发调用丢失更新 + 中断写撕裂文件)
// 权限/触发上下文: 触发者为能调用导出 API 的并发进程(常为 root daemon 多连接),
//   trigger_context 取决于调用入口; 写目标若为特权配置文件 → privilege_context=high_privilege。
// ============================================================================

// 主查询1: 读-改-写对(同函数内 read_file + write_file 同一路径, 无 lock 调用)
println(
  cpg.method
    .filter { m =>
      val calls = m.call.name.l
      val hasRead = calls.exists(c => c.matches(".*(read_file|fread|read|fopen|open|fgets|fscanf).*"))
      val hasWrite = calls.exists(c => c.matches(".*(write_file|fwrite|fprintf|write|fopen|open|rename|remove|unlink).*"))
      val hasLock = calls.exists(c => c.matches(".*(flock|fcntl|lockf|mutex_lock|pthread_mutex).*"))
      hasRead && hasWrite && !hasLock
    }
    .flatMap(m => m.call.name("(read_file|write_file|fopen|open|fread|fwrite|fprintf|rename|remove|unlink).*")
      .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name}"))
    .l.distinct.sorted.mkString("\n")
)

// 主查询2: TOCTOU — access/stat 检查后跟 open/write(检查与使用分离)
println(
  cpg.method
    .filter { m =>
      val calls = m.call.name.l
      calls.exists(c => c.matches("(access|stat|lstat|faccessat|statfs).*")) &&
      calls.exists(c => c.matches("(open|openat|fopen|creat|rename|unlink|remove).*"))
    }
    .flatMap(m => m.call.name("(access|stat|lstat|open|openat|fopen|creat|rename|unlink|remove).*")
      .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name}"))
    .l.distinct.sorted.mkString("\n")
)

// 变体: 写文件但无临时文件+rename 原子替换(撕裂写) — 查直接 write 到最终路径
// println(cpg.call.name("(fopen|open|creat).*").where(c => c.argument.code(".*\"/.*\"").size > 0 && !c.code(".*\\.tmp.*").size > 0).location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}").sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "(config_read_file|fopen|fread).*|(config_write_file|fwrite|fprintf)" <files>
//   rg -n "access\(|stat\(|lstat\(" <files>   # TOCTOU 检查点
