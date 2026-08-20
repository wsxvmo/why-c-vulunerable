// crypto-weakness.sc — 密码学弱点 (CWE-327/328)
// ============================================================================
// 依据: code-audit §7.2
//   Checklist: 安全用途使用 MD5/SHA1(非校验和); 硬编码密钥/密码/盐;
//   rand()/random 用于安全决策(需 CSPRNG: getrandom/arc4random); ECB 模式/零 IV/
//   弱 KDF(单轮 SHA 存密码)。
// 权限/触发上下文: 弱加密 → 凭据/会话可被破解/伪造; 硬编码密钥 → 全局妥协。
// ============================================================================

// 主查询: 弱哈希/弱随机/硬编码密钥痕迹
println(
  (cpg.call.name("(MD5|MD5_Init|SHA1|SHA1_Init|rand|random|srand|srandom).*").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.name}")
    ++ cpg.call.name("(EVP_EncryptInit_ex|EVP_DecryptInit_ex|AES_set_encrypt_key|DES_set_key).*").map(c => s"${c.location.filename}:${c.location.lineNumber}:${c.method.fullName} ${c.name}"))
  .l.distinct.sorted.mkString("\n"))

// 变体: 密钥/密码字面量(硬编码)
// println(cpg.literal.code(".*(password|passwd|secret|key|salt|token).*").map(l => s"${l.location.filename}:${l.location.lineNumber} ${l.code.take(50)}").l.distinct.sorted.mkString("\n"))

// grep 兜底模式:
//   rg -n "MD5|SHA1|rand\(|random\(|srand\(|EVP_Encrypt|DES_set_key" <files>
//   rg -ni "(password|passwd|secret|api[_-]?key|salt)\s*=\s*[\"'][^\"']{4,}[\"']" <files>   # 硬编码
//   rg -n "getrandom|arc4random|RAND_bytes|EVP_BytesToKey" <files>   # CSPRNG 对照
