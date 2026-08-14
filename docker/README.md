# audit-box — Docker 镜像（国内网络友好）

把本机 joern + why-c-vulnerable 框架打成 Docker 镜像，**构建与运行全程不依赖国外网络**。

## 目标机器一键安装（推荐）

其他机器拿到本目录的 `install.sh` 后，一条命令完成除 api-key 外的全部配置：

```bash
# 交互式（推荐）——用户名已内置，只需输入 ACR 固定密码（不回显、不落盘）
bash install.sh

# 非交互（CI/脚本）——用户名已内置，只需密码
ACR_PASSWORD=xxx bash install.sh

# 覆盖用户名（可选）
ACR_USERNAME=xxx ACR_PASSWORD=xxx bash install.sh

# 选项
bash install.sh --install-docker   # 顺便自动安装 docker（需 sudo）
bash install.sh --mirror-off       # 跳过 docker 加速器配置
```

脚本自动完成：docker 检测 → 国内加速器配置 → ACR 登录 → 拉镜像 → `~/.pi/agent` 准备（auth.json 检测+提示）→ 生成 `~/.local/bin/audit-box` 启动命令 → 验证。

安装后使用：

```bash
cd /你的源码目录
audit-box          # 一键进入审计环境（自动挂载当前目录 → /work）
# 容器内: /audit on → pi → "对 /work/xxx 跑完整代码审计流水线"
# 指定目录: audit-box /任意/源码/路径
```

> 唯一手动项：`~/.pi/agent/auth.json`（模型 API key）——脚本会检测并给模板。

## 设计要点（为什么国内能构建）

| 依赖 | 处理方式 | 网络 |
|---|---|---|
| joern (v4.0.579, 本机) | 构建时从本机 rsync 进镜像，**不下载** | 零网络 |
| Ubuntu 基础镜像 | `--base` 可换加速器/内网 registry 地址 | 见下 |
| apt 系统包 (openjdk/gcc/clang/valgrind) | Dockerfile 内 sed 换清华源 | 🇨🇳 清华 TUNA |
| Node.js 22 | 从 npmmirror 二进制镜像下载 | 🇨🇳 npmmirror |
| pi + codebase-memory-mcp | npm registry 换 npmmirror | 🇨🇳 npmmirror |
| pip (预留) | 换清华 PyPI 源 | 🇨🇳 清华 TUNA |

## 构建

```bash
# 前置：docker 可用（WSL 需启用 Docker Desktop 集成）+ 本机已有 joern-cli
# 默认：全量 frontends（~2.6G joern）
bash docker/build.sh

# 瘦身：只保留 C/Rust/Python/Java/Go 前端（joern 减到 ~1G）——推荐
bash docker/build.sh --minimal

# 指定 joern 目录 / 基础镜像 / 标签
bash docker/build.sh --minimal --joern-dir /path/to/joern-cli --tag audit-box:dev

# 基础镜像不可达时（Docker Hub 被墙/内网环境），指定加速器或内网地址：
bash docker/build.sh --base docker.m.daocloud.io/library/ubuntu:24.04
# 或写入 /etc/docker/daemon.json 的 registry-mirrors（推荐，一劳永逸）
```

## 运行

### 交互模式（日常审计，TUI）

```bash
docker run -it --rm \
  -v ~/.pi:/root/.pi \                       # casefile + 模型 auth + settings 持久化
  -v $PWD:/work \                            # 审计目标目录
  -v /var/run/docker.sock:/var/run/docker.sock \  # PromoteFinding 沙箱（PoC 在宿主 docker 里跑）
  audit-box
# 容器内：
#   /audit on
#   pi  → 告诉 agent "对 /work/xxx 跑完整审计流水线"
```

### 批处理模式（CI / 脚本，headless）

```bash
docker run --rm \
  -v ~/.pi:/root/.pi -v $PWD:/work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  audit-box pi --print --mode json "对 /work/xxx 跑完整审计流水线"
```

### 分发到其他机器

**推荐：推送到阿里云 ACR（团队一键拉取）**

```bash
# 一次性准备：阿里云 ACR 个人版（免费）→ 创建命名空间 + 仓库
bash docker/build.sh --minimal          # 先构建（Docker Hub 不可达时自动切 daocloud 加速器）
bash docker/push.sh                     # 交互输入 ACR 配置并推送
# 或非交互：
# ACR_REGISTRY=registry.cn-hangzhou.aliyuncs.com ACR_NAMESPACE=audit ACR_REPO=audit-box \
#   ACR_USERNAME=xxx ACR_PASSWORD=xxx bash docker/push.sh
```

目标机一键拉取运行：

```bash
docker pull registry.cn-hangzhou.aliyuncs.com/audit/audit-box:latest
# 若仓库为私有：docker login registry.cn-hangzhou.aliyuncs.com --username xxx
```

**备选：离线 save/load（无网环境）**

```bash
docker save audit-box | gzip > audit-box.tar.gz   # ~2-3G
# 目标机器：docker load < audit-box.tar.gz        # 无需网络，开箱即用
```

## 注意事项

1. **~/.pi 挂载是必须的**：casefile.db、`agent/auth.json`（模型 API key）、settings.json 都在里面，不挂载每次都是全新会话且没有模型凭证
2. **docker.sock 挂载有安全含义**：容器内 pi 的 PromoteFinding 用宿主 docker 跑 PoC 沙箱。仅用于可信审计环境；不挂载时 PromoteFinding 会失败（其余功能正常）
3. **镜像较大**（~3-4G，joern 占大头）。`--minimal` 可减 ~1.5G，代价是放弃 ABAP/C#/Ghidra/Swift/JS/Kotlin/Ruby/PHP 语言的 CPG 构建（C/Rust/Python 审计不受影响）
4. **joern 版本锁定**：镜像内嵌的是构建时本机版本（当前 v4.0.579），与框架验证过的版本一致，比下载最新版更可控
