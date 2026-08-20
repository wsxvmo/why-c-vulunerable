// 导出面枚举候选 — 所有用户方法 + 调用者数 + 位置。
// 输出行: <filename>\t<lineNumber>\t<methodFullName>\t<callerCount>
// 用途: audit-runner exports（导出即入口点, 2026-08-16）
//   - callers==0 且头文件声明 → intended（设计公开 API）
//   - callers==0 且无头文件声明 → accidental（符号表带出, 仍可达）
//   - callers>0 且无头文件声明 → internal（树内专用, 非导出入口）
// 注意:
//   * lineNumber 是 Option, 必须 .getOrElse(0) 解包 —— 否则 println 会输出 "Some(76)"
//     （2026-08-20 修复: 曾导致 exports.py 把 "file:Some(line)" 并进 file 字段,
//       1157 条畸形导出 → 段1 "导出即入口点"注入爆炸, 单文件拆出几十个 HUNT 组）。
//   * 分隔符用 \t 而非 ':' —— fullName 本身含 ':'（如 "Method:void()"）,
//     用 ':' 分隔会让按末段取字段的解析错位。
println(cpg.method
  .filter(m => !m.isExternal && m.name != "<global>" && !m.name.startsWith("<"))
  .map(m => { val l = m.location;
              s"${l.filename}\t${l.lineNumber.getOrElse(0)}\t${m.fullName}\t${m.caller.size}" })
  .sorted.mkString("\n"))
