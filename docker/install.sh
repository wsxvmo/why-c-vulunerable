#!/bin/bash
# =============================================================================
# audit-box 一键安装脚本（目标机器使用）
#
# 自动完成（除 api-key 外全部自动化）：
#   1. 检测 docker（缺失时提示安装，或 --install-docker 自动 apt 装）
#   2. 配置 docker 国内镜像加速器（daemon.json → docker.m.daocloud.io）
#   3. docker login 阿里云 ACR（用户名交互输入/环境变量，密码不回显不落盘）
#   4. docker pull audit-box 镜像
#   5. 准备 ~/.pi/agent 目录，检测 auth.json（缺失时给模板提示）
#   6. 生成 ~/.local/bin/audit-box 启动命令（一键挂载当前目录进入审计环境）
#   7. 验证镜像可用（pi/joern 版本探测）
#
# 用法：
#   bash install.sh                     # 交互输入 ACR 用户名/密码
#   ACR_USERNAME=xxx ACR_PASSWORD=xxx bash install.sh   # 非交互（CI 用）
#   bash install.sh --install-docker    # 顺便自动安装 docker（需要 sudo）
#   bash install.sh --mirror-off        # 跳过 docker 加速器配置
# =============================================================================
set -euo pipefail

REGISTRY="crpi-wtfs3dnj6nfe83gi.cn-hangzhou.personal.cr.aliyuncs.com"
NAMESPACE="pi-audit-whitebox"
REPO="why-c-vulunerable"
TAG="latest"
IMAGE="$REGISTRY/$NAMESPACE/$REPO:$TAG"
MIRROR="https://docker.m.daocloud.io"
# ACR 登录用户名（固定，团队共用；密码仍需交互输入或 ACR_PASSWORD 环境变量）
ACR_USERNAME_DEFAULT="aliyun5340523928"

INSTALL_DOCKER=0
MIRROR_ON=1
for arg in "$@"; do
  case "$arg" in
    --install-docker) INSTALL_DOCKER=1 ;;
    --mirror-off)     MIRROR_ON=0 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

say()  { echo -e "\033[1;32m[✓]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
fail() { echo -e "\033[1;31m[✗]\033[0m $*"; }

echo "════════════════════════════════════════════════════"
echo "  audit-box 一键安装 — 代码审计环境"
echo "  镜像: $IMAGE"
echo "════════════════════════════════════════════════════"

# ── 1. docker 检测/安装 ─────────────────────────────────────────────────────
echo ""
echo "[1/7] docker 检查"
if command -v docker >/dev/null 2>&1; then
  say "docker: $(command -v docker)"
else
  if [ "$INSTALL_DOCKER" = "1" ]; then
    warn "未找到 docker，尝试 apt 安装（需 sudo）..."
    sudo apt-get update && sudo apt-get install -y docker.io
    sudo systemctl enable --now docker 2>/dev/null || true
    say "docker 已安装"
  else
    fail "未找到 docker。请先安装："
    echo "     Linux:   sudo apt-get install -y docker.io   （或加 --install-docker 自动装）"
    echo "     WSL:     启用 Docker Desktop 的 WSL 集成"
    echo "     macOS:   安装 Docker Desktop"
    exit 1
  fi
fi

# daemon 可用性（免 sudo 检测，失败提示加 docker 组）
if ! docker info >/dev/null 2>&1; then
  warn "docker daemon 不可达。若刚装完，尝试: sudo usermod -aG docker \$USER && 重新登录"
  warn "或当前用户需 sudo 执行 docker（本脚本其余步骤请加 sudo 或换用户）"
fi

# ── 2. docker 国内加速器（best-effort，失败不阻塞）─────────────────────────
if [ "$MIRROR_ON" = "1" ]; then
  echo ""
  echo "[2/7] docker 镜像加速器配置"
  if [ -f /etc/docker/daemon.json ] && grep -q "$MIRROR" /etc/docker/daemon.json 2>/dev/null; then
    say "加速器已配置: $MIRROR"
  else
    # 合并现有 daemon.json（如有），追加 registry-mirrors
    # root 直接写；非 root 用 sudo（若存在）；都没有则降级为手动提示
    CAN_SUDO=0
    if [ "$(id -u)" = "0" ]; then CAN_SUDO=1
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then CAN_SUDO=1; fi
    if [ "$CAN_SUDO" = "1" ]; then
      RUN_ROOT=""
      [ "$(id -u)" != "0" ] && RUN_ROOT=sudo
      TMP=$(mktemp)
      if [ -f /etc/docker/daemon.json ]; then
        python3 - "$MIRROR" <<'PYEOF' > "$TMP"
import json, sys
mirror = sys.argv[1]
try:
    d = json.load(open('/etc/docker/daemon.json'))
except Exception:
    d = {}
mirrors = d.get('registry-mirrors', [])
if mirror not in mirrors:
    mirrors.append(mirror)
d['registry-mirrors'] = mirrors
json.dump(d, sys.stdout, indent=2)
PYEOF
        $RUN_ROOT cp "$TMP" /etc/docker/daemon.json
      else
        echo "{\"registry-mirrors\": [\"$MIRROR\"]}" | $RUN_ROOT tee /etc/docker/daemon.json >/dev/null
      fi
      rm -f "$TMP"
      $RUN_ROOT systemctl restart docker 2>/dev/null || $RUN_ROOT service docker restart 2>/dev/null || \
        warn "请手动重启 docker 使加速器生效（Docker Desktop: Settings → Docker Engine）"
      say "加速器已写入 /etc/docker/daemon.json"
    else
      warn "无权限配置加速器，跳过。可手动执行:"
      echo "     sudo tee /etc/docker/daemon.json <<< '{\"registry-mirrors\": [\"$MIRROR\"]}' && sudo systemctl restart docker"
    fi
  fi
fi

# ── 3. ACR 登录 ─────────────────────────────────────────────────────────────
echo ""
echo "[3/7] 阿里云 ACR 登录 ($REGISTRY)"
USERNAME="${ACR_USERNAME:-$ACR_USERNAME_DEFAULT}"
PASSWORD="${ACR_PASSWORD:-}"
if [ -z "$USERNAME" ]; then
  read -rp "ACR 用户名（阿里云账号，默认 $ACR_USERNAME_DEFAULT）: " USERNAME
  [ -z "$USERNAME" ] && USERNAME="$ACR_USERNAME_DEFAULT"
fi
if [ -z "$PASSWORD" ]; then
  read -rsp "ACR 固定密码（不回显）: " PASSWORD
  echo ""
fi
if ! echo "$PASSWORD" | docker login "$REGISTRY" --username "$USERNAME" --password-stdin 2>&1; then
  fail "ACR 登录失败（检查用户名/固定密码，或 ACR 控制台→访问凭证→重置固定密码）"
  exit 1
fi
unset PASSWORD   # 立即从内存清除，不落盘

# ── 4. 拉取镜像 ─────────────────────────────────────────────────────────────
echo ""
echo "[4/7] 拉取镜像 $IMAGE"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  say "镜像已存在，跳过拉取"
else
  docker pull "$IMAGE"
fi

# ── 5. ~/.pi 准备 + auth.json 检测 ─────────────────────────────────────────
echo ""
echo "[5/7] pi 凭证目录 (~/.pi/agent)"
mkdir -p "$HOME/.pi/agent"
if [ -f "$HOME/.pi/agent/auth.json" ]; then
  say "auth.json 已存在（模型凭证 OK）"
else
  warn "未找到 $HOME/.pi/agent/auth.json —— 这是唯一需要手动配置的项："
  echo "     把模型 API key 放到: $HOME/.pi/agent/auth.json"
  echo "     参考格式（按你的模型提供商）:"
  echo "     {\"providers\": {\"google\": {\"apiKey\": \"...\"}}}"
  echo "     或从已有 pi 环境复制该文件过来。"
fi

# ── 6. 生成启动命令 ~/.local/bin/audit-box ─────────────────────────────────
echo ""
echo "[6/7] 生成启动命令"
mkdir -p "$HOME/.local/bin"
LAUNCHER="$HOME/.local/bin/audit-box"
cat > "$LAUNCHER" <<EOF
#!/bin/bash
# audit-box — 一键进入审计环境（用法: audit-box [源码目录]，默认当前目录）
DIR="\${1:-\$(pwd)}"
exec docker run -it --rm \\
  -v "\$HOME/.pi:/root/.pi" \\
  -v "\$DIR":/work \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  $IMAGE
EOF
chmod +x "$LAUNCHER"
# 确保 ~/.local/bin 在 PATH
case ":$PATH:" in
  *":$HOME/.local/bin:"*) : ;;
  *) warn "~/.local/bin 不在 PATH，本次会话执行: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
say "启动命令: $LAUNCHER"

# ── 7. 验证 ────────────────────────────────────────────────────────────────
echo ""
echo "[7/7] 验证"
if docker run --rm "$IMAGE" bash -c 'command -v pi >/dev/null && command -v joern >/dev/null' 2>/dev/null; then
  say "镜像可用（pi + joern 就绪）"
else
  warn "镜像验证失败——尝试: docker run --rm $IMAGE bash -c 'ls /opt/audit'"
fi

echo ""
echo "════════════════════════════════════════════════════"
echo "  安装完成！使用方法："
echo ""
echo "  1. 确保 $HOME/.pi/agent/auth.json 已配置（模型 API key）"
echo "  2. 进入源码目录，启动审计环境:"
echo "       cd /你的源码目录"
echo "       audit-box"
echo "  3. 容器内:"
echo "       /audit on"
echo "       pi"
echo "       → \"对 /work/xxx 跑完整代码审计流水线\""
echo ""
echo "  指定其他源码目录:  audit-box /任意/源码/路径"
echo "════════════════════════════════════════════════════"
