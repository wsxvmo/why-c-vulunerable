// uninitialized-use.sc — 未初始化使用 (CWE-457)
// ============================================================================
// 依据: code-audit §1.7
//   Checklist: 栈变量声明后条件初始化再读; 结构体字段未清零 (calloc vs malloc);
//   部分初始化的结构体传给读全部字段的函数。
// 注意: joern 无法可靠判"条件初始化后读" → 本资产以"无初始化器局部声明"做候选池,
//       高噪声, 全部 tier=LOW, 必须人工核对(或 clangd -Wmaybe-uninitialized 佐证)。
// 权限/触发上下文: 无初始化读 → 信息泄露(栈内容)/UB; trigger 取决于调用入口。
// ============================================================================

// 主查询: 无初始化器的局部变量声明(候选池, 高噪声, LOW)
println(cpg.local
  .filter(l => !l.code.matches(".*=.*") && l.code.matches(".*\\b(int|char|long|short|float|double|size_t|ssize_t|void\\s*\\*|struct\\s+\\w+)\\b.*"))
  .map(l => s"${l.location.filename}:${l.location.lineNumber}:${l.method.fullName} ${l.code.take(50)}")
  .l.distinct.sorted.mkString("\n"))

// 变体: malloc(非 calloc)的结构体分配 — 字段未清零候选
// println(cpg.call.name("malloc.*").filter(c => !c.code.matches(".*calloc.*")).map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "^\s*(int|char|long|size_t|struct)\s+\w+;" <files>   # 无初始化器声明
//   clangd 佐证: clangd --check 产生 -Wmaybe-uninitialized 诊断时优先采用
