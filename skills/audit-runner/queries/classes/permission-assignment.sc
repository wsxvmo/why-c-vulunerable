// permission-assignment.sc — 文件/资源权限分配缺陷 (CWE-732/276)
// ============================================================================
// 依据: code-audit §3.3 + libsecurity1 复盘
//   (config_write_file 直写 /etc/kysec/kysec.conf, libconfig fopen(path,"w") 用 0666&~umask,
//   无显式 mode、无 umask 硬化、无属主设置; 若创建进程 umask 宽松 → world-writable)
// 权限/触发上下文: 写目标为特权配置 → privilege_context=high_privilege;
//   world-writable 后任何本地用户可写 → trigger_context=unprivileged_user。
// ============================================================================

// 主查询1: fopen/open 写模式调用 — 检查是否有显式 mode 参数或 umask/chmod 配套
println(
  cpg.call
    .name("(fopen|open|openat|creat|mkstemp|mktemp|tmpfile|fchmod|chmod|umask).*")
    .map { c =>
      val hasMode = c.argument.size >= 3 || c.code.matches(".*0[0-7]{3}.*") // open 3参 / 八进制mode
      val m = c.method
      val hasUmask = m.call.name("umask").size > 0
      val hasChmod = m.call.name("(chmod|fchmod)").size > 0
      s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} mode=${if (hasMode) "explicit" else "umask-dep"} umaskInFunc=${hasUmask} chmodInFunc=${hasChmod}"
    }
    .l.distinct.sorted.mkString("\n")
)

// 主查询2: 创建文件路径(写模式)所在方法 — 无 umask/chmod/属主设置 的候选
println(
  cpg.method
    .filter { m =>
      val creates = m.call.name("(fopen|open|openat|creat|mkstemp|config_write_file).*").size > 0
      val harden = m.call.name("(umask|chmod|fchmod|chown|fchown|setfsuid).*").size > 0
      creates && !harden
    }
    .flatMap(m => m.call.name("(fopen|open|openat|creat|mkstemp|config_write_file).*")
      .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} (无 umask/chmod/属主)"))
    .l.distinct.sorted.mkString("\n")
)

// 变体: 临时文件安全 — mkstemp/mktemp/tmpnam 混用(不安全生成器 + 可预测路径)
// println(cpg.call.name("(mktemp|tmpnam|tempnam).*").location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}").sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "fopen\(|open\(|creat\(|mkstemp\(|umask\(|chmod\(|fchmod\(" <files>
