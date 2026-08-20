// null-deref.sc — 解引用前无 NULL 守卫 (CWE-476)
// ============================================================================
// 依据: code-audit §1.6 + libsecurity1 复盘 case_980634f45a
//   (security_config_module_add/remove/set 未做 NULL 检查 → strstr(NULL) SIGSEGV;
//   同族 status_get 有 NULL 检查, 证明开发者意图处理 NULL → 差分即证据)
// 权限/触发上下文: 导出的库 API 若被 root daemon 经 D-Bus 调用且非特权可触发,
//   trigger_context=unprivileged_user, privilege_context=high_privilege → severity 提升。
// ============================================================================

// 主查询1: 已知 nonnull 语义的外部库调用点(候选 = 需人工核对参数是否可能为 NULL)
println(cpg.call.name("(strstr|strncmp|strcmp|strlen|strcpy|strcat|sprintf|snprintf|memcpy|strchr|strrchr|strtok|strdup|strndup|atoi|strtol|config_setting_get_member|config_lookup).*").location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}").sorted.mkString("\n"))

// 主查询2: 导出 API(无调用者) — 库目标攻击面候选, 逐个人工核对 NULL 守卫
//   重点: 同族函数中"有的有 NULL 检查、有的没有" = 差分证据(如 status_get 有, add/remove/set 无)
//   输出 (方法名:定义行号) 成对 — 定义行号供下游聚合归属函数, 不得只输出裸方法名
println(cpg.method.filter(m => m.caller.size == 0 && !m.name.matches("(main|<global>|.*test.*)"))
  .map(m => s"${m.location.filename}:${m.lineNumber.getOrElse(0)}:${m.name}")
  .l.distinct.sorted.mkString("\n"))

// grep 兜底模式(joern 查不到 NULL 语义时):
//   rg -n "strstr\(|strncmp\(|config_setting_get_member\(" <files>
//   对每个命中函数: 检查函数入口是否有 if (param == NULL) 守卫; 无 → 候选
