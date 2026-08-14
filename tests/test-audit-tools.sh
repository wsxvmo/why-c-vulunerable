#!/usr/bin/env bash
# Minimal smoke test for audit-tools.
# Builds a tiny C file with a known system() sink, runs build_cpg + query_cpg,
# and asserts the sink is found -- all within per-step timeouts (no hangs).
#
# Usage:  tests/test-audit-tools.sh
# Exit:   0 = pass, non-zero = fail
set -u

AT="${AUDIT_TOOLS:-audit-tools}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── 1. prerequisites ─────────────────────────────────────────────
command -v "$AT" >/dev/null 2>&1 || { echo "FAIL: $AT not on PATH"; exit 2; }
command -v joern-parse >/dev/null 2>&1 || { echo "SKIP: joern-parse not installed"; exit 0; }

# ── 2. tiny target with a known system() sink ───────────────────
cat > "$TMP/vuln.c" <<'C'
#include <stdlib.h>
#include <string.h>
int run(char *cmd) { return system(cmd); }   /* sink: line 3 */
int main(void) { char b[8]; strcpy(b, getenv("X")); return run(b); } /* sink: strcpy line 5 */
C

echo "[1/4] build_cpg ..."
out="$("$AT" cli build_cpg --root "$TMP" --language c --force 2>&1)"
echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("     ok=%s elapsed=%ss cached=%s"%(d["ok"],d["elapsed"],d.get("cached")))'
echo "$out" | python3 -c 'import sys,json;sys.exit(0 if json.load(sys.stdin)["ok"] else 1)' || { echo "FAIL: build_cpg"; exit 1; }

CPG="$(echo "$out" | python3 -c 'import sys,json;print(json.load(sys.stdin)["cpg"])')"
[ -f "$CPG" ] || { echo "FAIL: cpg not found at $CPG"; exit 1; }

echo "[2/4] query_cpg system() sink ..."
out="$("$AT" cli query_cpg --cpg "$CPG" \
  --query 'cpg.call.name("system").lineNumber.l.foreach(println)' --timeout 120 2>&1)"
echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("     ok=%s elapsed=%ss"%(d["ok"],d["elapsed"]))'
echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if d["ok"] and any(l.strip().isdigit() for l in d["stdout"].splitlines()) else 1)' \
  || { echo "FAIL: did not find system() sink"; exit 1; }
echo "     found system() sink"

echo "[3/4] query_cpg strcpy sink ..."
out="$("$AT" cli query_cpg --cpg "$CPG" \
  --query 'cpg.call.name("strcpy").lineNumber.l.foreach(println)' --timeout 120 2>&1)"
echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if d["ok"] and any(l.strip().isdigit() for l in d["stdout"].splitlines()) else 1)' \
  || { echo "FAIL: did not find strcpy sink"; exit 1; }
echo "     found strcpy() sink"

echo "[4/4] cache reuse ..."
out="$("$AT" cli build_cpg --root "$TMP" --language c 2>&1)"
echo "$out" | python3 -c 'import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get("cached") else 1)' \
  || { echo "FAIL: second build_cpg should hit cache"; exit 1; }
echo "     cache hit"

echo ""
echo "PASS: audit-tools build_cpg + query_cpg + cache all working, no hangs."
exit 0
