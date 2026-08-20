// access-control.sc — 敏感操作无鉴权 (CWE-284/862/863)
// ============================================================================
// 依据: code-audit §3.1 + libsecurity1 复盘 KILL-1 误杀教训
//   (导出 API 写 /etc/kysec/kysec.conf 无 uid/capability 校验; 树内 grep 不到调用方 ≠ 不可达:
//   真实攻击面 = 导出 ABI × 树外特权消费方(root daemon / D-Bus 服务) × 该消费者输入面)
// 权限/触发上下文(本类资产的核心价值):
//   - 候选命中 = 敏感写/特权操作点, 必须评估: 谁调用? 以什么权限? 攻击者可控输入能否到达?
//   - 若库/服务被 root 消费且非特权可触发 → trigger_context=unprivileged_user,
//     privilege_context=high_privilege → KILL-1 不得轻率适用(见 README 使用纪律)。
// ============================================================================

// 主查询1: 导出 API(无调用者)内对特权路径的写 — 库目标攻击面
//   提示: 无调用者 ≠ 不可达; 对共享库, 调用者在树外(链接该 .so 的 daemon/工具)。
println(
  cpg.method
    .filter(m => m.caller.size == 0 && !m.name.matches("(main|<global>|.*_test.*)"))
    .flatMap { m =>
      m.call.name("(fopen|open|openat|creat|write|fwrite|fprintf|rename|remove|unlink|chmod|fchmod|setuid|seteuid|setgid|config_write_file|system|popen|exec).*")
        .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} -> ${c.name}")
    }
    .l.distinct.sorted.mkString("\n")
)

// 主查询2: 全库敏感写点 + 所在方法是否有任何鉴权原语(getuid/geteuid/capget/access 校验)
println(
  cpg.method
    .filter { m =>
      val writes = m.call.name("(fopen|open|openat|creat|config_write_file|chmod|setuid|system|popen).*").size > 0
      val authz = m.call.name("(getuid|geteuid|getgid|capget|access|faccessat|authenticate|check_permission|authorize).*").size > 0
      writes && !authz
    }
    .flatMap(m => m.call.name("(fopen|open|openat|creat|config_write_file|chmod|setuid|system|popen).*")
      .map(c => s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} (无鉴权原语)"))
    .l.distinct.sorted.mkString("\n")
)

// 变体: 入口点文件(entry.sc 输出)中每个导出函数的权限面 — 需先跑 entry.sc 取入口列表
//   对每个入口 ep: 读函数体, 检查是否有 getuid/属主/权限校验; 无 → access-control 候选。

// grep 兜底模式(joern 对宏/包装不可见时):
//   rg -n "config_write_file|fopen\(|open\(.*O_WRONLY|chmod\(|setuid\(" <files>
//   rg -n "getuid|geteuid|capget|faccessat" <files>   # 鉴权原语存在性对照
