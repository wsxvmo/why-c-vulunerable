// error->message 未守卫解引用扫描（判别 GLib 吸收 vs 真崩溃的关键查询）
println(cpg.call.code(".*error->message.*").location.l.map(l => s"${l.filename}:${l.lineNumber}")
  .sorted.mkString("\n"))
