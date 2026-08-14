#!/bin/bash
# =============================================================================
# push.sh — 把 audit-box 镜像推送到阿里云 ACR（路径 C：团队一键拉取）
#
# 前置条件（一次性）：
#   1. 注册阿里云账号 → 容器镜像服务 ACR（个人版免费）
#   2. 创建命名空间（如 audit）和镜像仓库（如 audit-box，类型选"本地仓库"）
#   3. 获取登录凭证：ACR 控制台 → 访问凭证 → 设置固定密码
#
# 用法：
#   bash docker/push.sh                        # 交互式输入账号/仓库地址
#   export ACR_REGISTRY=registry.cn-hangzhou.aliyuncs.com
#   export ACR_NAMESPACE=your-namespace
#   export ACR_REPO=audit-box
#   export ACR_USERNAME=你的阿里云账号
#   bash docker/push.sh                        # 非交互（从环境变量读）
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_TAG="${LOCAL_TAG:-audit-box:latest}"

# ── 读取配置（环境变量优先，否则交互输入）─────────────────────────────────
read_conf() {
  local var="$1" prompt="$2"
  if [ -n "${!var:-}" ]; then
    echo "$prompt: ${!var}"
  else
    read -rp "$prompt: " "$var"
    export "$var"
  fi
}

REGISTRY="${ACR_REGISTRY:-}"
NAMESPACE="${ACR_NAMESPACE:-}"
REPO="${ACR_REPO:-audit-box}"
USERNAME="${ACR_USERNAME:-}"

[ -z "$REGISTRY" ] && read_conf REGISTRY "阿里云 ACR 地域地址（如 registry.cn-hangzhou.aliyuncs.com）"
[ -z "$NAMESPACE" ] && read_conf NAMESPACE "ACR 命名空间"
[ -z "$USERNAME" ] && read_conf USERNAME "阿里云账号（登录名）"

# 密码：优先环境变量，否则交互输入（不回显）
if [ -z "${ACR_PASSWORD:-}" ]; then
  read -rsp "ACR 访问凭证密码（固定密码，不回显）: " ACR_PASSWORD
  echo ""
fi

REMOTE_TAG="$REGISTRY/$NAMESPACE/$REPO:latest"

# ── 前置检查 ────────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "❌ docker 不在 PATH"; exit 1; }
if ! docker image inspect "$LOCAL_TAG" >/dev/null 2>&1; then
  echo "❌ 本地镜像 $LOCAL_TAG 不存在 —— 先运行: bash docker/build.sh"
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  推送 audit-box → 阿里云 ACR"
echo "  本地镜像:  $LOCAL_TAG"
echo "  远端地址:  $REMOTE_TAG"
echo "════════════════════════════════════════════════"

# ── 登录 → 打标 → 推送 ──────────────────────────────────────────────────────
echo ""
echo "[1/3] docker login $REGISTRY"
echo "$ACR_PASSWORD" | docker login "$REGISTRY" --username "$USERNAME" --password-stdin

echo ""
echo "[2/3] docker tag $LOCAL_TAG → $REMOTE_TAG"
docker tag "$LOCAL_TAG" "$REMOTE_TAG"

echo ""
echo "[3/3] docker push $REMOTE_TAG"
docker push "$REMOTE_TAG"

echo ""
echo "✅ 推送完成！"
echo ""
echo "团队拉取（目标机）:"
echo "  docker pull $REMOTE_TAG"
echo "  docker run -it --rm \\"
echo "    -v ~/.pi:/root/.pi \\"
echo "    -v \$PWD:/work \\"
echo "    -v /var/run/docker.sock:/var/run/docker.sock \\"
echo "    $REMOTE_TAG"
echo ""
echo "⚠️  目标机首次拉取同样需要先登录（或把仓库设为公开/企业内网拉取）:"
echo "  docker login $REGISTRY --username $USERNAME"
