# =============================================================================
# why-c-vulnerable audit-box — 国内网络友好的代码审计环境镜像
#
# 注意：不使用 # syntax=docker/dockerfile:1 指令（它会从 docker.io 拉 frontend
# 镜像，国内被墙；默认内置 frontend 已支持全部用到的语法）。
#
# 设计原则（国内可构建、可运行）：
#   1. joern 不联网下载 —— 构建时从本机 COPY（build.sh 负责准备 .build/joern-cli）
#   2. apt 换清华源     —— 系统包不碰国外源
#   3. node 从 npmmirror 二进制镜像下载，npm registry 换 npmmirror
#   4. pip 换清华 PyPI 源
#   5. 基础镜像通过 ARG 可替换（加速器/内网 registry），默认 ubuntu:24.04
# =============================================================================
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

# ── 0. apt 换国内源（清华 TUNA，用 http 避开 ca-certificates 依赖）──────
RUN sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu|http://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      -e 's|http://security.ubuntu.com/ubuntu|http://mirrors.tuna.tsinghua.edu.cn/ubuntu|g' \
      /etc/apt/sources.list.d/ubuntu.sources \
      /etc/apt/sources.list 2>/dev/null || true

# ── 1. 基础系统包（openjdk 供 joern，gcc/clang/valgrind 供 sanitizer 复现）──
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      openjdk-21-jre-headless \
      gcc g++ clang valgrind \
      python3 python3-pip python3-venv \
      curl git unzip xz-utils \
      docker.io \
      locales \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Node.js 22（从 npmmirror 二进制镜像下载，避开 nodejs.org）───────────
ARG NODE_VERSION=22.22.1
RUN curl -fsSL "https://registry.npmmirror.com/-/binary/node/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      -o /tmp/node.tar.xz \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && node --version && npm --version

# ── 3. npm registry 换 npmmirror + 安装 pi 与 codebase-memory-mcp ──────────
RUN npm config set registry https://registry.npmmirror.com \
    && npm install -g @earendil-works/pi-coding-agent codebase-memory-mcp \
    && npm cache clean --force

# ── 4. pip 换清华源（框架本身零依赖，这里为将来扩展预留）──────────────────
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    && pip3 config set global.trusted-host pypi.tuna.tsinghua.edu.cn

# ── 5. joern —— 本地 COPY，零网络（build.sh 已准备 .build/joern-cli）───────
COPY joern-cli/ /opt/joern/
ENV PATH="/opt/joern:${PATH}"
# joern 各 frontend 顶层脚本需可执行（rsync 保留权限，这里兜底）
RUN find /opt/joern -maxdepth 1 -type f ! -name "*.bat" ! -name "*.md" -exec chmod +x {} \; 2>/dev/null || true

# ── 6. why-c-vulnerable 审计框架 ────────────────────────────────────────────
COPY audit/ /opt/audit/
WORKDIR /opt/audit
# bootstrap 会检测工具链 + 安装 c-* agents + 注册 pi 包（全部本地操作）
RUN bash /opt/audit/bootstrap.sh 2>&1 | tail -20 || true

# ── 7. 审计工作区 + 入口 ────────────────────────────────────────────────────
RUN mkdir -p /work && locale-gen en_US.UTF-8 2>/dev/null || true
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
WORKDIR /work

# 容器内 PromoteFinding 沙箱需要宿主 docker（运行时挂载 /var/run/docker.sock）
# 交互模式：docker run -it --rm -v ~/.pi:/root/.pi -v $PWD:/work audit-box
CMD ["/bin/bash"]
