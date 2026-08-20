// resource-leak.sc — 资源泄漏 (CWE-404/775)
// ============================================================================
// 依据: code-audit §7.1(memory-leak 的广义版: 文件描述符/DBus 连接/线程/锁)
//   Checklist: DBus 连接/pthread/文件句柄在循环中泄漏; 加锁未解锁路径;
//   Python: 未关闭文件句柄、subprocess 管道未排空。
// 权限/触发上下文: fd/连接耗尽 → DoS; 锁泄漏 → 死锁(可用性)。
// ============================================================================

// 主查询: 打开/加锁原语所在方法无对应释放 — fd/锁句柄候选
println(cpg.method
  .filter(m => m.call.name("(open|openat|fopen|fdopen|socket|accept|pthread_mutex_lock|dbus_connection_open|g_dbus_connection_new).*").size > 0)
  .map { m =>
    val opens = m.call.name("(open|openat|fopen|fdopen|socket|accept|pthread_mutex_lock|dbus_connection_open|g_dbus_connection_new).*").size
    val closes = m.call.name("(close|fclose|shutdown|pthread_mutex_unlock|dbus_connection_close|g_object_unref).*").size
    if (opens > closes) Some(s"${m.location.filename}:${m.location.lineNumber}:${m.fullName} open=${opens} close=${closes} (可能泄漏)")
    else None
  }
  .l.flatten.distinct.sorted.mkString("\n"))

// 变体: 循环内打开(每次迭代分配, 循环外释放?) — 需人工核对循环边界
// println(cpg.method.filter(m => m.call.name("(fopen|open|malloc).*").size > 0 && m.ast.isControlStructure.controlStructureType("(For|While|Do).*").size > 0).map(m => s"${m.location.filename}:${m.location.lineNumber}:${m.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "fopen\(|open\(|socket\(|accept\(|pthread_mutex_lock|dbus_connection" <files>
//   rg -n "fclose\(|close\(|pthread_mutex_unlock|dbus_connection_close" <files>   # 释放对照
