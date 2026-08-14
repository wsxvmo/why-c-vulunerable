#!/bin/bash
# =============================================================================
# audit-box build script — 构建国内网络友好的代码审计环境镜像
#
# 用途：把本机 joern + why-c-vulnerable 框架打进 Docker 镜像
# 关键点：joern 不联网下载（本地 COPY），apt/npm/pip 全部走国内源
#
# 用法：
#   bash docker/build.sh                     # 默认构建（本地 joern + 全量 frontends）
#   bash docker/build.sh --minimal           # 只保留 C/Rust/Python/Java/Go 前端（瘦身 ~2G）
#   bash docker/build.sh --joern-dir /path   # 指定 joern-cli 目录（默认自动探测）
#   bash docker/build.sh --base <image>      # 自定义基础镜像（如内网 registry）
#   bash docker/build.sh --tag audit-box:dev # 自定义镜像标签
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/.build"
TAG="audit-box:latest"
BASE_IMAGE="ubuntu:24.04"
MINIMAL=0
JOERN_DIR=""

# ── Docker Hub 可达性检测：不可达时自动换国内加速器基础镜像 ──────────────
# （Docker Hub 在国内常被墙。注意：不能靠 docker pull 探测——本地镜像缓存
#   会误判为“可达”。用 curl 直接探测 auth.docker.io（构建 FROM 实际依赖））
HUB_OK=0
if command -v curl >/dev/null 2>&1; then
  if timeout 6 curl -s -o /dev/null "https://auth.docker.io/token" 2>/dev/null; then
    HUB_OK=1
  fi
fi
if [ "$HUB_OK" != "1" ] && [ -z "${BASE_IMAGE_OVERRIDE:-}" ]; then
  echo "ℹ️  Docker Hub 直连不可达（国内网络），基础镜像自动切换为 daocloud 加速器"
  BASE_IMAGE="docker.m.daocloud.io/library/ubuntu:24.04"
fi

# ── 参数解析 ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --minimal)       MINIMAL=1; shift ;;
    --joern-dir)     JOERN_DIR="$2"; shift 2 ;;
    --base)          BASE_IMAGE="$2"; shift 2 ;;
    --tag)           TAG="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1 (--help 查看用法)"; exit 1 ;;
  esac
done

# ── 0. 前置检查 ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "❌ docker 不在 PATH（WSL 需启用 Docker Desktop 集成）"; exit 1; }
docker info >/dev/null 2>&1 || { echo "❌ docker daemon 未运行"; exit 1; }

# ── 1. 定位本机 joern-cli（优先 --joern-dir，其次常见路径）──────────────────
if [ -z "$JOERN_DIR" ]; then
  for cand in \
    "$HOME/.local/share/joern/joern-cli" \
    "/mnt/d/joren/joern-cli" \
    "/opt/joern/joern-cli" \
    "$(command -v joern >/dev/null 2>&1 && dirname "$(readlink -f "$(command -v joern)")")" \
  ; do
    if [ -n "$cand" ] && [ -f "$cand/joern" ] && [ -d "$cand/bin" ]; then
      JOERN_DIR="$cand"; break
    fi
  done
fi
[ -n "$JOERN_DIR" ] && [ -f "$JOERN_DIR/joern" ] || { echo "❌ 找不到本机 joern-cli（可用 --joern-dir 指定）"; exit 1; }
echo "✅ 使用本机 joern: $JOERN_DIR ($(du -sh "$JOERN_DIR" 2>/dev/null | cut -f1))"

# ── 2. 准备构建上下文 ───────────────────────────────────────────────────────
echo ""
echo "[1/3] 准备构建上下文 (.build/)"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 2a. joern-cli：rsync 保留权限；排除 workspace（构建产物）与不必要的 Windows 批处理
EXCLUDES=(--exclude workspace --exclude '*.bat' --exclude '*.dll' --exclude '*.exe')
if [ "$MINIMAL" = "1" ]; then
  echo "  --minimal: 只保留 c/rust/python/java/go 前端"
  EXCLUDES+=(
    --exclude frontends/abap2cpg --exclude frontends/csharpsrc2cpg
    --exclude frontends/ghidra2cpg --exclude frontends/swiftsrc2cpg
    --exclude frontends/jssrc2cpg --exclude frontends/kotlin2cpg
    --exclude frontends/rubysrc2cpg --exclude frontends/php2cpg
    --exclude frontends/jimple2cpg
  )
fi
rsync -a "${EXCLUDES[@]}" "$JOERN_DIR/" "$BUILD_DIR/joern-cli/"
echo "  ✅ joern-cli → .build/joern-cli ($(du -sh "$BUILD_DIR/joern-cli" | cut -f1))"

# 2b. audit 框架：排除 .git/.build/node_modules 等
rsync -a --delete \
  --exclude .git --exclude node_modules --exclude docker/.build \
  --exclude .poc --exclude pocs --exclude tests \
  "$PROJECT_DIR/" "$BUILD_DIR/audit/"
echo "  ✅ why-c-vulnerable → .build/audit"

# 2c. .dockerignore（确保 .build 自身不被递归拷贝）
cat > "$BUILD_DIR/.dockerignore" <<'EOF'
.build
.git
node_modules
*.db
EOF

# ── 3. 构建 ─────────────────────────────────────────────────────────────────
echo ""
echo "[2/3] docker build (base: $BASE_IMAGE, tag: $TAG)"
docker build \
  --build-arg BASE_IMAGE="$BASE_IMAGE" \
  -f "$SCRIPT_DIR/Dockerfile" \
  -t "$TAG" \
  "$BUILD_DIR" 2>&1 | tee "$SCRIPT_DIR/.build-log.txt" | tail -30

echo ""
echo "[3/3] 构建完成 ✅"
echo "  镜像: $TAG"
echo "  大小: $(docker images --format '{{.Size}}' "$TAG" | head -1)"
echo ""
echo "运行（交互，挂载你的审计目录 + casefile + docker.sock）:"
echo "  docker run -it --rm \\"
echo "    -v ~/.pi:/root/.pi \\"
echo "    -v \$PWD:/work \\"
echo "    -v /var/run/docker.sock:/var/run/docker.sock \\"
echo "    $TAG"
echo ""
echo "批量（headless，输出 JSON）:"
echo "  docker run --rm -v ~/.pi:/root/.pi -v \$PWD:/work $TAG \\"
echo "    pi --print --mode json \"对 /work/xxx 跑完整审计流水线\""
