# Per-Class Query Assets（25 类查询资产）

> 2026-08-15 建立。依据: libsecurity1 v2 审计复盘 —— 0 confirmed 的根因之一是
> "每类查什么" 依赖 HUNT agent 临场把 code-audit 散文方法论翻译成 joern 查询,
> 导致类级漏检(V1 推 8 类 vs V2 推 5 类)与深度不均。本目录把方法论
> **预编译成确定性查询资产**: 每类 = Sources/Sinks 表 + joern .sc + grep 模式 +
> 权限/触发上下文标注。设计思想借鉴 unified-audit(hydrid: 图深度 × grep 广度交叉、
> privilege_context / trigger_context 维度、威胁驱动 focus)。

## 使用纪律

1. HUNT/GAPFIL agent 拿到类后, **优先跑本目录对应 <class>.sc**(joern)与
   `<class>.grep`(rg 模式)双轨; 双轨命中同一候选点 → 置信度上调(hybrid 交叉验证)。
2. 输出 = 候选列表(仅候选, 非结论)。每条候选仍需 read/grep/clangd 逐跳验证。
3. 空结果(仅 INFO 行) → 转 grep 兜底, 不重试白等(audit-runner 纪律)。
4. 查询必须 println 结尾; 经 `audit-runner cpg query --cpg <cpg> --file <q.sc>` 调用。
5. 候选输出附 权限/触发上下文标注 字段(见各文件头部注释), 供 TRACE/KILL-1 判定。

## 类 → 资产 映射（进度）

| # | 类 | CWE | 状态 | 资产文件 |
|---|---|---|---|---|
| 1.1 | buffer-overflow | 120/121/122/787 | ✅ 已写 | classes/buffer-overflow.sc |
| 1.2 | out-of-bounds-read | 125 | ✅ 已写 | classes/out-of-bounds-read.sc |
| 1.3 | use-after-free | 416 | ✅ 已写 | classes/use-after-free.sc |
| 1.4 | double-free | 415 | ✅ 已写 | classes/double-free.sc |
| 1.5 | integer-overflow | 190/191 | ✅ 已写 | classes/integer-overflow.sc |
| 1.6 | null-deref | 476 | ✅ 样板 | classes/null-deref.sc |
| 1.7 | uninitialized-use | 457 | ✅ 已写 | classes/uninitialized-use.sc |
| 1.8 | format-string | 134 | ✅ 已写 | classes/format-string.sc |
| 2.1 | command-injection | 78 | ✅ 已写 | classes/command-injection.sc |
| 2.2 | path-traversal | 22/23 | ✅ 已写 | classes/path-traversal.sc |
| 2.3 | symlink-follow | 59 | ✅ 样板 | classes/symlink-follow.sc |
| 2.4 | unsafe-temp-file | 377/378/379 | ✅ 已写 | classes/unsafe-temp-file.sc |
| 2.5 | race-condition / toctou | 362/367 | ✅ 样板 | classes/race-condition.sc + classes/toctou.sc |
| 3.1 | access-control | 284/862/863 | ✅ 样板 | classes/access-control.sc |
| 3.1a | spoofable-identity | 287/269 | ✅ 已写 | classes/spoofable-identity.sc |
| 3.2 | privilege-mgmt | 250/269/271/272/273 | ✅ 已写 | classes/privilege-mgmt.sc |
| 3.3 | permission-assignment | 732/276 | ✅ 样板 | classes/permission-assignment.sc |
| 5.1 | shell-injection | 78 | ✅ 样板 | classes/shell-injection.grep |
| 6.1 | eval-injection (py) | 95/94 | ✅ 已写 | classes/eval-injection.grep |
| 6.2 | unsafe-deserialization (py) | 502 | ✅ 已写 | classes/unsafe-deserialization.grep |
| 7.1 | resource-leak / memory-leak | 401/404/775 | ✅ 已写 | classes/resource-leak.sc + classes/memory-leak.sc |
| 7.2 | crypto-weakness | 327/328 | ✅ 已写 | classes/crypto-weakness.sc |
| 7.3 | info-disclosure | 200 | ✅ 已写 | classes/info-disclosure.sc |

**状态: 25/25 类全部有资产(2026-08-15 补全)。** 每个 .sc 资产在 libsecurity1 的
fuzzy CPG 上冒烟测试通过(语法 + 真实命中); .grep 资产为 rg 模式 + 语义检查纪律。

> toctou 与 race-condition 共享方法论(§2.5), toctou.sc 聚焦 check-then-use 独立键。
> memory-leak 与 resource-leak 同为 §7.1, 分开建资产(内存 vs 句柄/锁)。
> DBus/IPC 专项(§4)与 C ABI Export Surface(§6c)是审计面而非类, 不在此列。

## 样板类(先做 6 个, 验证形态)

## 设计原则(每个资产文件必须带)

1. **Sources 表**(攻击者可控输入): CLI/argv、env、网络/D-Bus、文件内容、配置。
2. **Sinks 表**(危险操作): 内存拷贝/写文件/命令执行/权限变更/解引用。
3. **joern .sc**: 一个主查询(println 结尾) + 注释里附 2-3 个变体查询。
4. **grep 模式**: rg 一行, 覆盖 joern 扫不到的(宏/函数指针/shell)。
5. **权限/触发上下文标注**: 候选附带 privilege_context(high/low/unknown) 与
   trigger_context(unprivileged/authenticated/local/admin) —— KILL-1 判定依据。
