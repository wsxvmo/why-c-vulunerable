// 入口候选（无调用者的函数）— 用 fullName.contains 匹配类前缀, 不要 method.name("Class::")
println(cpg.method.filter(m => m.caller.size == 0 && m.name != "<global>")
  .location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}")
  .sorted.mkString("\n"))
