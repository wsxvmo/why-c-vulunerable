---
name: audit-tools
description: Safe, non-blocking Joern/codebase-memory tooling for C/C++/Shell/Python static code audit. Use for 'build the CPG', 'scan with joern', 'query the CPG', 'trace data flow', 'find sinks'. Replaces the fragile raw joern commands (which hang on stdin) with hardened, parameterized, timeout-protected calls.
---

# audit-tools

Hardened wrappers around **joern / joern-scan / codebase-memory-mcp** for code-audit.
Every call is **non-interactive and timeout-protected** — they can never hang the agent
on stdin (which is what raw `joern --script /dev/stdin` does).

## Why this exists

`c-auditor`'s older methodology told agents to run `joern-parse --out …` (wrong flag for
current joern — fails) and `joern --script /dev/stdin` (blocks on stdin forever — agent
hangs 30+ min until killed). `audit-tools` hardens these calls:

- correct flag (`joern-parse -o`, never `--out`)
- **never** `/dev/stdin` — the query is written to a temp file, then `joern --script <tmp> <cpg>`
- hard timeout + process-group kill on expiry
- structured JSON output `{ok, exit, stdout, stderr, elapsed, timeout, ...}`
- CPG cache reuse (keyed on root + mtime)

## Binary

`audit-tools` on PATH (symlinked from `extensions/audit-tools.py`).
Two interfaces (same engine):

- `audit-tools cli <tool> --flag value …` — bash-friendly, for agents/skills
- `audit-tools mcp` — stdio MCP server (for MCP clients)

## Tools

| Tool | Purpose | Key args |
|------|---------|----------|
| `build_cpg` | Build (or reuse) a Joern CPG for a source tree | `--root <dir>` `--language c` `--out <cpg>` `--force` |
| `scan_cpg` | Scan a cpg/src with the joern query database (CVE patterns) | `--cpg` or `--src`, `--names <csv>`, `--tags <csv>` (e.g. `cwe-78`) |
| `query_cpg` | Run a Joern query script against a built cpg (non-interactive) | `--cpg`, `--query '<script>'`, `--timeout` |
| `cpg_status` | Is a cached cpg available for a root? | `--root` |
| `codebase_query` | Pass-through to `codebase-memory-mcp cli` (search_graph / trace_path / get_code_snippet) | `--tool <cbm-tool>` `--project <name>` + that tool's flags |

Get help: `audit-tools --help`.

## Standard audit flow (per target)

Resolve all paths relative to the skill directory (parent of this SKILL.md) only when
the task references a relative path here; otherwise use the absolute target path.

```bash
ROOT=/abs/path/to/source
PROJ=$(basename "$ROOT")          # codebase-memory project name (indexed separately)

# 0. (optional) index for the graph — once per target
codebase-memory-mcp cli index_repository --repo-path "$ROOT" --name "$PROJ" --mode fast

# 1. Build/reuse the CPG  (~7-60s, cached)
audit-tools cli build_cpg --root "$ROOT" --language c --force

# 2. Sweep the query database, filter by CWE tag
audit-tools cli scan_cpg --src "$ROOT" --tags cwe-78

# 3. Targeted sink discovery (returns rows you then verify by hand)
audit-tools cli query_cpg --cpg "$ROOT.cpg" \
  --query 'cpg.call.name("(system|popen|execl|execvp|strcpy|memcpy|free|setuid|sprintf|gets|alloca)").location.l.map(l => s"${l.filename}:${l.lineNumber}").l' \
  --timeout 180

# 4. Graph-based data-flow trace (hop-by-hop verification)
audit-tools cli codebase_query --tool trace_path --project "$PROJ" --mode data_flow --parameter-name <arg>
```

### Joern query snippets (drop into `--query`)

```
# all calls to dangerous sinks, with file:line
cpg.call.name("(system|popen|execl|execlp|execv|execvp|strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove|alloca|free|setuid|seteuid|setgid|dlopen)")
  .location.l.map(l => s"${l.filename}:${l.lineNumber}:${l.methodFullName}").l

# unchecked malloc/calloc/strdup (call whose result flows into a deref w/o a null-check) — candidate CWE-690
cpg.call.name("(malloc|calloc|strdup|realloc)").whereNot(_.inAst.isControlStructure).location.l

# user-controlled index into fixed array — heuristics
cpg.call.name("<operator>.indexAccess").location.l
```

Remember: Joern output is a **candidate list**. Every candidate must be verified
hop-by-hop (read the code + `codebase_query trace_path`) before it becomes a finding.

## Output contract

Every tool returns JSON. The fields agents care about:

```
{ "ok": bool, "exit": int, "stdout": "...", "stderr": "...",
  "elapsed": 9.36, "timeout": false, "cpg": "...", "cached": true }
```

- `timeout: true` → the call was hard-killed; do NOT retry the same query unchanged.
- `ok: false` with `exit: 1` and a Scala syntax error in `stderr` → your `--query` is
  wrong; fix the script. It did NOT hang.

## Do NOT (these are what audit-tools replaces)

- `joern-parse … --out …`        → use `build_cpg` (correct flag is `-o`)
- `joern --script /dev/stdin …`  → use `query_cpg` (temp file, never stdin)
- `joern <cpg>` interactive REPL  → use `query_cpg` (non-interactive)
- raw `joern-scan` without timeout → use `scan_cpg`

If you ever find yourself typing a bare `joern`/`joern-parse`/`joern-scan` command in
bash, stop and use the corresponding `audit-tools cli …` tool instead.

## 接口选择（实战纪律）

- **bash CLI 是首选主通道**（`audit-tools cli ...`）：全文输出、已验证稳定，协调器/子代理一律用它。
- **MCP 接口**（`audit_*` 工具）可用但：① 响应被裁剪为紧凑有界值（stdout/stderr ≤20KB，大输出走 CLI 拿全文）；② **升级 audit-tools 代码后，已启动的 MCP 服务进程不会热加载新代码** —— 长会话遇到 `value is not lossless JSON` 类错误，先重启会话/重连 MCP 让服务进程重生，再不行就全程走 CLI。
