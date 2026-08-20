// spoofable-identity.sc — 可伪造身份信任 (CWE-287/269)
// ============================================================================
// 依据: code-audit §3.1a(身份信任边界, 本地审计最高产出类)
//   身份来源可伪造性: argv[0]/cmdline/prctl(PR_SET_NAME)/comm/env(LD_PRELOAD等)/
//   D-Bus well-known name 竞态 → 调用方可伪造; pid/uid/gid/真实路径 → 内核所有不可伪造。
//   "任何授权决策信任了调用方可控数据" = 本类命中。命中即升优先级。
// 权限/触发上下文: 本类 = 身份边界分析; 命中时 trigger_context 必填, 若高权限服务
//   信任可伪造身份 → 提权链入口。KILL-1 判定: 命中本类不得按"无权限边界"杀。
// ============================================================================

// 主查询: 可伪造身份源的使用点(cmdline/argv/env/progname)
println(cpg.call.name("(getenv|getprogname|getexecname|prctl).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 主查询2: argv 相关引用(argv[0]/optarg/程序名解析) — 授权决策若基于此 → 候选
println(cpg.call.name("(getopt|getopt_long|argp_parse).*")
  .map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.code.take(70)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: D-Bus well-known name 竞态/name squatting — 查请求者身份判断是否用 sender 而非 name
// println(cpg.call.name("(sd_bus_query_sender_creds|sd_bus_creds_get_uid|dbus_message_get_sender).*").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式(本类以 grep 为主, joern 只能列使用点):
//   rg -n "cmdline|argv\[0\]|getprogname|__progname|prctl\(.*PR_SET_NAME|comm\b" <files>
//   rg -n "LD_PRELOAD|LD_LIBRARY_PATH|PATH" <files>
//   rg -n "dbus_message_get_sender|sd_bus_creds|NameAcquire|well-known" <files>
//   对每个命中: 该值是否被授权决策信任? 信任了可伪造源 → 候选(高优先)
