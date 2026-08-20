// privilege-mgmt.sc — 权限管理缺陷 (CWE-250/269/271/272/273)
// ============================================================================
// 依据: code-audit §3.2
//   Checklist: setuid/setgid/seteuid/setresuid **返回值未检查**(CWE-273 最常见);
//   处理攻击者输入前未降权(CWE-250/272); 降权后恢复(saved uid 保留, seteuid 回提);
//   root daemon 本可跑 nobody 却跑 root。
// 权限/触发上下文: 本类 = 权限上下文本身; 命中即 privilege_context=high_privilege,
//   trigger 取决于调用者身份。KILL-1 判定时必须携带本类上下文。
// ============================================================================

// 主查询: 权限变更调用 + 是否检查返回值
println(cpg.call.name("(setuid|seteuid|setresuid|setgid|setegid|setresgid|setgroups|initgroups|capset|prctl).*")
  .map { c =>
    val m = c.method
    val checked = m.ast.isCall.code(s".*${java.util.regex.Pattern.quote(c.code)}.*==.*").size > 0 ||
                  m.ast.isCall.code(".*if\\s*\\(.*").size > 0
    s"${c.location.filename}:${c.location.lineNumber}:${m.fullName} ${c.name} ret-checked=${checked}"
  }
  .l.distinct.sorted.mkString("\n"))

// 变体: 降权后是否处理输入(函数内 setuid 后仍有读用户输入/文件操作) — 人工核对顺序
// println(cpg.method.filter(m => m.call.name("(setuid|seteuid|setresuid|setgid).*").size > 0).map(m => s"${m.location.filename}:${m.location.lineNumber}:${m.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "setuid\(|seteuid\(|setresuid\(|setgid\(|setegid\(|setresgid\(|capset\(|prctl\(" <files>
//   对每个命中: 返回值检查了吗? 永久降权(setuid)还是临时(seteuid)? 之后跑了什么?
