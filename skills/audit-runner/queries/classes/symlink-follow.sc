// symlink-follow.sc — 符号链接跟随写 (CWE-59)
// ============================================================================
// 依据: code-audit §2.3 + libsecurity1 复盘
//   (config_write_file 写 /etc/kysec/kysec.conf 无 O_NOFOLLOW/lstat 前置检查;
//   若 /etc/kysec 可被低权用户写或配置文件被替换为符号链接 → root 上下文覆写任意文件)
// 权限/触发上下文: 写路径在特权目录 → privilege_context=high_privilege;
//   目录可被非特权写(如 /tmp、world-writable 子目录) → trigger_context=unprivileged_user。
// ============================================================================

// 主查询: open/fopen 写模式(非 O_NOFOLLOW) — 文件创建/覆写路径候选
println(
  cpg.call
    .name("(fopen|open|openat|creat).*")
    .filter(c => c.argument.code(".*(\"w\"|\"a\"|O_WRONLY|O_CREAT|O_TRUNC|O_RDWR).*").size > 0)
    .map { c =>
      val hasNoFollow = c.argument.code(".*O_NOFOLLOW.*").size > 0
      val m = c.method
      val hasLstat = m.call.name("(lstat|fstatat|readlink).*").size > 0
      s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.code.take(60)} nofollow=${hasNoFollow} lstatInFunc=${hasLstat}"
    }
    .l.distinct.sorted.mkString("\n")
)

// 变体: 写路径来自字符串拼接(可能被替换为符号链接的路径)
// println(cpg.call.name("(fopen|open|openat).*").where(c => c.argument.code(".*\\+.*|\".*%s.*\"").size > 0).location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}").sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "fopen\(|open\(|openat\(|creat\(" <files>
//   rg -n "O_NOFOLLOW|lstat\(|readlink\(" <files>   # 防护原语存在性对照
