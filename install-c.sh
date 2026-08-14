#!/bin/bash
# Install pi-xpi-c agents into an independent namespace (~/.pi/agent/agents/c-*.md)
# Does NOT overwrite the original pi-xpi agents (auditor.md, tracer.md, ...).
# Does NOT install third-party extensions (pi-codex-goal, pi-mcp-adapter, fff).
if [ -n "$PI_XPI_C_INSTALLING" ]; then exit 0; fi
export PI_XPI_C_INSTALLING=1

PI_BIN="$(command -v pi 2>/dev/null)"
if [ -z "$PI_BIN" ]; then
  echo "pi not found in PATH - skipping agent install"
  exit 0
fi

echo "Installing pi-xpi-c agents (c-* namespace)..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p ~/.pi/agent/agents ~/.local/bin

# Copy with c- prefix so the original xpi agents are never touched
for f in "$SCRIPT_DIR"/agents/*.md; do
  base="$(basename "$f")"
  name_line="$(grep '^name:' "$f" | head -1)"
  expected="c-${base%.md}"
  actual="$(echo "$name_line" | sed 's/^name:[[:space:]]*//' | tr -d '\r')"
  if [ "$actual" != "$expected" ]; then
    echo "  WARN: $base frontmatter name='$actual' != expected '$expected' - fixing"
    sed -i "s/^name:.*/name: $expected/" "$f"
  fi
  cp -f "$f" ~/.pi/agent/agents/"${base}"
  echo "  installed ${base} (name: $expected)"
done

# ── audit-tools binary (hardened, non-blocking joern/codebase-memory wrapper) ──
# Zero third-party deps (Python stdlib). Provides `audit-tools cli <tool>` and
# `audit-tools mcp`. c-auditor.md Step 2 mandates this instead of bare joern
# (which hangs on stdin via `joern --script /dev/stdin`).
AT_SRC="$SCRIPT_DIR/extensions/audit-tools.py"
if [ -f "$AT_SRC" ]; then
  chmod +x "$AT_SRC"
  ln -sf "$AT_SRC" ~/.local/bin/audit-tools
  if command -v audit-tools >/dev/null 2>&1; then
    echo "  installed audit-tools -> $(command -v audit-tools)"
  else
    # ~/.local/bin may not be on PATH in non-interactive shells
    case ":$PATH:" in
      *":$HOME/.local/bin:"*) echo "  installed audit-tools -> ~/.local/bin/audit-tools (not on PATH yet?)" ;;
      *) ln -sf "$AT_SRC" /usr/local/bin/audit-tools 2>/dev/null && echo "  installed audit-tools -> /usr/local/bin/audit-tools" || echo "  WARN: could not place audit-tools on PATH" ;;
    esac
  fi
else
  echo "  WARN: extensions/audit-tools.py not found - skipping audit-tools"
fi

echo ""
echo "pi-xpi-c agents installed. Skills:"
echo "  skills/pipeline    -> stages machine (code audit edition)"
echo "  skills/code-audit  -> C/C++/Shell/Python CWE methodology"
echo "  skills/audit-tools -> hardened joern/codebase-memory tooling (non-blocking)"
echo ""
echo "Prerequisites check:"
command -v audit-tools >/dev/null && echo "  audit-tools: OK" || echo "  audit-tools: MISSING (required for non-blocking joern)"
command -v joern >/dev/null && echo "  joern: OK" || echo "  joern: MISSING (required for HUNT/TRACE)"
command -v codebase-memory-mcp >/dev/null && echo "  codebase-memory-mcp: OK" || echo "  codebase-memory-mcp: MISSING (recommended)"
command -v gcc >/dev/null && echo "  gcc: OK (for sanitizer repros)" || echo "  gcc: MISSING (VALIDATE repros need it)"
command -v valgrind >/dev/null && echo "  valgrind: OK" || echo "  valgrind: MISSING (optional)"
