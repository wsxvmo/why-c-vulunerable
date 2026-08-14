#!/bin/bash
# =============================================================================
# pi-xpi-c — one-shot bootstrap installer
#
# Runs EVERYTHING needed to use the code-audit pipeline in a fresh environment:
#   1. Detect external toolchain (joern, codebase-memory-mcp, gcc, sanitizers)
#   2. Install c-* agents into ~/.pi/agent/agents/ (independent namespace)
#   3. Register the package with pi (skills + case-context extension)
#   4. Verify everything loads
#
# Usage:
#   bash bootstrap.sh          # install + verify
#   bash bootstrap.sh --check  # only check toolchain + current install state
#   bash bootstrap.sh --force  # re-register package even if already present
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_PATH="$SCRIPT_DIR"
ONLY_CHECK=0
FORCE=0

for arg in "$@"; do
  case "$arg" in
    --check) ONLY_CHECK=1 ;;
    --force) FORCE=1 ;;
  esac
done

echo "════════════════════════════════════════════════════════"
echo "  pi-xpi-c bootstrap — C/C++/Shell/Python code audit"
echo "════════════════════════════════════════════════════════"

# ── 1. Toolchain check ──────────────────────────────────────────────────────
echo ""
echo "[1/4] Toolchain check"
MISSING=0
check() {
  local name="$1" required="$2" extra="$3"
  if command -v "$name" >/dev/null 2>&1; then
    echo "  ✅ $name: $(command -v "$name")"
  else
    echo "  ❌ $name: MISSING — $extra"
    [ "$required" = "1" ] && MISSING=1
  fi
}
check joern               1 "required for HUNT (joern-scan) + TRACE (taint). Install: https://github.com/joernio/joern"
check joern-parse         1 "required (comes with joern)"
check joern-scan          1 "required (comes with joern)"
check codebase-memory-mcp 0 "recommended for whole-repo graph. Install: npm i -g codebase-memory-mcp"
check gcc                 1 "required for sanitizer repros (VALIDATE)"
check clang               0 "alternative to gcc for ASAN/UBSAN repros"
check valgrind            0 "optional (ASAN covers most cases)"
check rust-analyzer       0 "needed only if auditing Rust targets"

if [ "$MISSING" = "1" ]; then
  echo ""
  echo "  ⚠️  Required toolchain missing. Install the items above, then re-run."
  [ "$ONLY_CHECK" = "1" ] && exit 1
fi

# pi itself
PI_BIN="$(command -v pi 2>/dev/null)"
if [ -z "$PI_BIN" ]; then
  echo "  ❌ pi: not found in PATH — install pi first (npm i -g @earendil-works/pi-coding-agent)"
  exit 1
fi
echo "  ✅ pi: $PI_BIN"

[ "$ONLY_CHECK" = "1" ] && { echo ""; echo "Check complete."; exit 0; }

# ── 2. Agents ───────────────────────────────────────────────────────────────
echo ""
echo "[2/4] Installing c-* agents (independent namespace)"
mkdir -p ~/.pi/agent/agents
for f in "$SCRIPT_DIR"/agents/*.md; do
  base="$(basename "$f")"
  expected="c-${base%.md}"
  actual="$(grep '^name:' "$f" | head -1 | sed 's/^name:[[:space:]]*//' | tr -d '\r')"
  if [ "$actual" != "$expected" ]; then
    echo "  WARN: $base frontmatter name='$actual' != expected '$expected' — fixing"
    sed -i "s/^name:.*/name: $expected/" "$f"
  fi
  cp -f "$f" ~/.pi/agent/agents/"${base}"
  echo "  ✅ installed ${base} (name: $expected)"
done

# ── 3. Register package with pi ─────────────────────────────────────────────
echo ""
echo "[3/4] Registering package with pi (skills + case-context extension)"
SETTINGS="$HOME/.pi/agent/settings.json"
ALREADY=0
if [ -f "$SETTINGS" ]; then
  if python3 -c "
import json,sys
d=json.load(open('$SETTINGS'))
pkgs=d.get('packages',[])
print(1 if any('$PKG_PATH' in p for p in pkgs) else 0)
" 2>/dev/null | grep -q 1; then
    ALREADY=1
  fi
fi

if [ "$ALREADY" = "1" ] && [ "$FORCE" != "1" ]; then
  echo "  ✅ package already registered in settings.json"
else
  echo "  → pi install $PKG_PATH"
  (cd "$HOME" && pi install "$PKG_PATH" 2>&1 | tail -2)
  echo "  ✅ registered"
fi

# ── 4. Verify ───────────────────────────────────────────────────────────────
echo ""
echo "[4/4] Verification"
echo "  agents: $(ls ~/.pi/agent/agents/c-*.md 2>/dev/null | wc -l | tr -d ' ') c-* files installed"
echo "  skills: $SCRIPT_DIR/skills/pipeline/SKILL.md + skills/code-audit/SKILL.md"
echo "  extension: $SCRIPT_DIR/extensions/case-context.ts (registerCommand /audit)"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Done! Run /reload in pi (or restart), then:"
echo "    /audit on     → enable audit context injection"
echo "    tell the agent: \"run the code audit pipeline on <target>\""
echo "════════════════════════════════════════════════════════"
