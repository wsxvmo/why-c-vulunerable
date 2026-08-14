#!/usr/bin/env python3
"""
audit-tools — safe, non-blocking wrappers around joern / joern-scan /
codebase-memory-mcp for code-audit pipelines.

WHY THIS EXISTS
---------------
c-auditor's methodology told agents to run joern commands like
`joern-parse --out …` (wrong flag for this joern version -> immediate failure)
and `joern --script /dev/stdin` (blocks on stdin forever -> agent hangs for
30+ minutes until the user kills it). This binary hardens those calls so they
can NEVER block on stdin:

  * correct flags        (joern-parse -o, not --out)
  * non-interactive       (joern --script <tempfile> <cpg>, never /dev/stdin)
  * hard timeout + kill   (subprocess timeout, whole process group killed)
  * structured JSON out   ({ok, exit, stdout, stderr, elapsed, timeout, ...})
  * cpg cache reuse       (keyed on root + mtime, avoids repeated 40s builds)

TWO INTERFACES (same engine, like codebase-memory-mcp):
  audit-tools cli <tool> --flag value ...   # bash-friendly, for agents/skills
  audit-tools mcp                           # stdio MCP server (JSON-RPC)

TOOLS
  build_cpg      --root <dir> [--language c] [--out <cpg>] [--force]
  scan_cpg       --cpg <cpg> [--src <dir>] [--names <csv>] [--tags <csv>]
  query_cpg      --cpg <cpg> --query <script> [--timeout <s>]
  cpg_status     --root <dir>
  codebase_query -- <args passed through to `codebase-memory-mcp cli`>

No third-party deps. Python 3 stdlib only.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── defaults ────────────────────────────────────────────────────────────────
DEFAULT_BUILD_TIMEOUT = 600      # joern-parse can take a while on big trees
DEFAULT_SCAN_TIMEOUT = 600
DEFAULT_QUERY_TIMEOUT = 180
DEFAULT_CODEBASE_TIMEOUT = 120
CPG_CACHE_DIR = Path(os.environ.get("AUDIT_TOOLS_CACHE", str(Path.home() / ".cache" / "audit-tools")))


# ── helpers ──────────────────────────────────────────────────────────────────
def _resolve_bin(name: str) -> str | None:
    p = shutil.which(name)
    return p


def _run(cmd: list[str], timeout: int, input_bytes: bytes | None = None) -> dict:
    """Run a subprocess with a hard timeout, kill the whole group on expiry.

    Always returns a structured dict — never raises, never blocks past timeout.
    stdin is closed ( DEVNULL ) so interactive REPLs cannot hang waiting on it.
    """
    start = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,          # new process group -> kill the tree
        )
    except FileNotFoundError:
        return {"ok": False, "error": "binary not found: %s" % cmd[0], "cmd": cmd}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "error": "spawn failed: %s" % e, "cmd": cmd}

    try:
        out, err = proc.communicate(input=input_bytes, timeout=timeout)
        rc = proc.returncode
        return {
            "ok": rc == 0,
            "exit": rc,
            "stdout": out.decode("utf-8", "replace"),
            "stderr": err.decode("utf-8", "replace"),
            "elapsed": round(time.time() - start, 2),
            "timeout": False,
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired:
        # kill the whole process group (JVM children too)
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except ProcessLookupError:
            pass
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
        return {
            "ok": False,
            "exit": -1,
            "stdout": out.decode("utf-8", "replace") if out else "",
            "stderr": (err.decode("utf-8", "replace") if err else "") + "\n[audit-tools] hard timeout (%ss), process killed" % timeout,
            "elapsed": round(time.time() - start, 2),
            "timeout": True,
            "cmd": cmd,
        }


def _cpg_cache_path(root: str) -> Path:
    root_abs = os.path.abspath(root)
    key = "%s-%d" % (root_abs.replace(os.sep, "_").strip("_"), int(os.path.getmtime(root_abs)) if os.path.exists(root_abs) else 0)
    return CPG_CACHE_DIR / ("%s.cpg" % key)


# ── tools ───────────────────────────────────────────────────────────────────
def tool_build_cpg(args: dict) -> dict:
    root = args.get("root")
    if not root or not os.path.isdir(root):
        return {"ok": False, "error": "root is required and must be a directory"}
    joern_parse = _resolve_bin("joern-parse")
    if not joern_parse:
        return {"ok": False, "error": "joern-parse not found in PATH"}

    out = args.get("out")
    cached = False
    if not out:
        out = str(_cpg_cache_path(root))
        if os.path.exists(out) and not args.get("force"):
            # verify it's non-empty and fresh
            if os.path.getsize(out) > 0:
                return {"ok": True, "cpg": out, "cached": True, "elapsed": 0.0}
    out = os.path.abspath(out)

    lang = args.get("language")
    cmd = [joern_parse, root, "-o", out]
    if lang:
        cmd += ["--language", lang]
    if args.get("force") and os.path.exists(out):
        try:
            os.remove(out)
        except OSError:
            pass

    res = _run(cmd, timeout=int(args.get("timeout", DEFAULT_BUILD_TIMEOUT)))
    res["cpg"] = out if res.get("ok") else None
    res["cached"] = cached
    # trim huge stdout
    if len(res.get("stdout", "")) > 20000:
        res["stdout"] = res["stdout"][-20000:]
    return res


def tool_scan_cpg(args: dict) -> dict:
    # joern-scan builds its own cpg if given a src dir; or scans an existing cpg.
    js = _resolve_bin("joern-scan")
    if not js:
        return {"ok": False, "error": "joern-scan not found in PATH"}
    cmd = [js]
    cpg = args.get("cpg")
    src = args.get("src")
    if cpg:
        cmd += [cpg, "--overwrite"]
    elif src:
        cmd += [src, "--overwrite"]
    else:
        return {"ok": False, "error": "either --cpg or --src is required"}
    if args.get("names"):
        cmd += ["--names", args["names"]]
    if args.get("tags"):
        cmd += ["--tags", args["tags"]]
    res = _run(cmd, timeout=int(args.get("timeout", DEFAULT_SCAN_TIMEOUT)))
    # trim: joern-scan prints a lot; keep findings + last lines
    return res


def tool_query_cpg(args: dict) -> dict:
    cpg = args.get("cpg")
    query = args.get("query")
    if not cpg or not query:
        return {"ok": False, "error": "--cpg and --query are required"}
    if not os.path.exists(cpg):
        return {"ok": False, "error": "cpg not found: %s (run build_cpg first)" % cpg}
    joern = _resolve_bin("joern")
    if not joern:
        return {"ok": False, "error": "joern not found in PATH"}

    # ALWAYS write the query to a temp file — NEVER /dev/stdin (that blocks).
    fd, script_path = tempfile.mkstemp(suffix=".sc")
    try:
        os.write(fd, query.encode("utf-8"))
        os.close(fd)
        cmd = [joern, "--script", script_path, cpg]
        res = _run(cmd, timeout=int(args.get("timeout", DEFAULT_QUERY_TIMEOUT)))
        return res
    finally:
        try:
            os.remove(script_path)
        except OSError:
            pass


def tool_cpg_status(args: dict) -> dict:
    root = args.get("root")
    if not root:
        return {"ok": False, "error": "--root is required"}
    cached = _cpg_cache_path(root)
    if os.path.exists(cached):
        return {"ok": True, "cpg": str(cached), "exists": True, "size": os.path.getsize(cached)}
    # also check explicit out
    return {"ok": True, "exists": False, "cpg": None}


def tool_codebase_query(args: dict) -> dict:
    """Pass-through to `codebase-memory-mcp cli <tool> ...`.

    args = {"tool": "<cbm tool>", "args": {"--flag": value, ...}}  OR
    args = {"tool": "search_graph", "project": "...", "name-pattern": "..."}  (flat convenience)
    """
    cbm = _resolve_bin("codebase-memory-mcp")
    if not cbm:
        return {"ok": False, "error": "codebase-memory-mcp not found in PATH"}
    tool = args.get("tool")
    if not tool:
        return {"ok": False, "error": "codebase_query needs a 'tool' field (e.g. search_graph)"}
    cmd = [cbm, "cli", tool]
    # flat convenience fields -> flags
    passthrough = args.get("args") if isinstance(args.get("args"), dict) else {
        k: v for k, v in args.items() if k not in ("tool", "args")
    }
    for k, v in passthrough.items():
        flag = k if k.startswith("--") else "--" + k.lstrip("-")
        cmd += [flag, str(v)]
    return _run(cmd, timeout=int(args.get("timeout", DEFAULT_CODEBASE_TIMEOUT)))


TOOLS = {
    "build_cpg": tool_build_cpg,
    "scan_cpg": tool_scan_cpg,
    "query_cpg": tool_query_cpg,
    "cpg_status": tool_cpg_status,
    "codebase_query": tool_codebase_query,
}

# tool -> (summary, input schema as {name: {type, desc, required}})
SCHEMAS = {
    "build_cpg": (
        "Build a Joern Code Property Graph for a source tree (cached). Returns the cpg path.",
        {
            "root": {"type": "string", "desc": "source root directory", "required": True},
            "language": {"type": "string", "desc": "e.g. c, csharp, java (optional, joern auto-detects)"},
            "out": {"type": "string", "desc": "explicit cpg output path (default: cache)"},
            "force": {"type": "boolean", "desc": "rebuild even if cached"},
            "timeout": {"type": "integer", "desc": "seconds (default 600)"},
        },
    ),
    "scan_cpg": (
        "Scan a cpg (or source dir) with the joern query database. Returns findings.",
        {
            "cpg": {"type": "string", "desc": "path to a built cpg"},
            "src": {"type": "string", "desc": "source dir (joern-scan builds cpg itself)"},
            "names": {"type": "string", "desc": "comma-separated query names filter"},
            "tags": {"type": "string", "desc": "comma-separated tag filter (e.g. cwe-78)"},
            "timeout": {"type": "integer", "desc": "seconds (default 600)"},
        },
    ),
    "query_cpg": (
        "Run a Joern query script against a built cpg. Non-interactive (script written to a temp file). Returns rows.",
        {
            "cpg": {"type": "string", "desc": "path to a built cpg", "required": True},
            "query": {"type": "string", "desc": "Joern script, e.g. cpg.call.name(\"(system|popen)\").l", "required": True},
            "timeout": {"type": "integer", "desc": "seconds (default 180)"},
        },
    ),
    "cpg_status": (
        "Check whether a cached cpg exists for a source root.",
        {"root": {"type": "string", "desc": "source root directory", "required": True}},
    ),
    "codebase_query": (
        "Pass-through to codebase-memory-mcp cli (search_graph / trace_path / get_code_snippet ...).",
        {
            "tool": {"type": "string", "desc": "codebase-memory-mcp tool name", "required": True},
            "project": {"type": "string", "desc": "indexed project name"},
            "timeout": {"type": "integer", "desc": "seconds (default 120)"},
        },
    ),
}


# ── cli mode ─────────────────────────────────────────────────────────────────
def _parse_kv(flags: list[str]) -> dict:
    """Parse --key value / --key=value / --flag (bool) into a dict."""
    out: dict = {}
    i = 0
    while i < len(flags):
        f = flags[i]
        if f.startswith("--"):
            key = f[2:]
            if "=" in key:
                k, v = key.split("=", 1)
                out[k] = v
                i += 1
                continue
            if i + 1 < len(flags) and not flags[i + 1].startswith("--"):
                out[key] = flags[i + 1]
                i += 2
            else:
                out[key] = True
                i += 1
        else:
            i += 1
    return out


def cli_main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("\nTOOLS:")
        for name, (summary, schema) in SCHEMAS.items():
            print("  %s — %s" % (name, summary))
            for pn, ps in schema.items():
                req = " (required)" if ps.get("required") else ""
                print("      --%s <%s>%s  %s" % (pn, ps["type"], req, ps["desc"]))
        return 0
    if argv[0] == "mcp":
        return mcp_main()
    if argv[0] == "cli":
        argv = argv[1:]
    tool = argv[0] if argv else None
    if tool not in TOOLS:
        print("unknown tool: %s\nrun 'audit-tools --help'" % tool, file=sys.stderr)
        return 2
    args = _parse_kv(argv[1:])
    try:
        # best-effort int/bool coercion for typed fields
        for k, v in list(args.items()):
            if v is True or v is False:
                continue
            if isinstance(v, str) and v.lower() in ("true", "false"):
                args[k] = v.lower() == "true"
            elif isinstance(v, str) and v.isdigit():
                args[k] = int(v)
    except Exception:
        pass
    result = TOOLS[tool](args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


# ── mcp mode (stdio JSON-RPC) ───────────────────────────────────────────────
def _mcp_tools_block() -> dict:
    tools = []
    for name, (summary, schema) in SCHEMAS.items():
        props = {}
        required = []
        for pn, ps in schema.items():
            props[pn] = {"type": ps["type"], "description": ps["desc"]}
            if ps.get("required"):
                required.append(pn)
        tools.append({
            "name": name,
            "description": summary,
            "inputSchema": {"type": "object", "properties": props, "required": required},
        })
    return {"tools": tools}


def mcp_main() -> int:
    """Minimal MCP stdio server (JSON-RPC 2.0) over stdin/stdout."""
    # logging to stderr so it doesn't corrupt the stdout protocol
    def log(msg: str) -> None:
        sys.stderr.write("[audit-tools mcp] %s\n" % msg)

    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        msgid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if method == "initialize":
            resp = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "audit-tools", "version": "0.1.0"}}
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = _mcp_tools_block()
        elif method == "tools/call":
            tname = params.get("name")
            targs = params.get("arguments") or {}
            if tname in TOOLS:
                try:
                    resp = TOOLS[tname](targs)
                    resp = {"content": [{"type": "text", "text": json.dumps(resp, ensure_ascii=False, indent=2)}], "isError": not resp.get("ok", False)}
                except Exception as e:
                    resp = {"content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(e)})}], "isError": True}
            else:
                resp = {"content": [{"type": "text", "text": "unknown tool: %s" % tname}], "isError": True}
        else:
            resp = None
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msgid, "error": {"code": -32601, "message": "method not found: %s" % method}}) + "\n")
            sys.stdout.flush()
            continue
        if resp is not None and msgid is not None:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msgid, "result": resp}) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(cli_main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
