#!/bin/bash
# ═══ 猎杀对决 · 资产浏览器 一键启动 (v1.9) ═══
# 只读浏览, 绝不动游戏文件。
cd "$(dirname "$0")"

ORIGIN="https://github.com/204343414/Hunt1896PAK.git"

# 公开仓走 HTTPS, 不需要 SSH 私钥。有 id_huntview 才启用 SSH(维护端推送用)。
if [ -f "$PWD/id_huntview" ]; then
    chmod 600 "$PWD/id_huntview" 2>/dev/null
    export GIT_SSH_COMMAND="ssh -i \"$PWD/id_huntview\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    ORIGIN="git@github.com:204343414/Hunt1896PAK.git"
fi

# 半残 .git(无 commit / HEAD 字面量) → 丢掉重建
if [ -d .git ] && command -v git >/dev/null 2>&1; then
    if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
        echo "↻ 本地 git 半残, 重建…"
        rm -rf .git
    fi
fi

sync_gh() {
    git remote remove origin >/dev/null 2>&1 || true
    git remote add origin "$ORIGIN" >/dev/null 2>&1 || git remote set-url origin "$ORIGIN"
    git fetch --depth 1 origin main && git reset --hard FETCH_HEAD
}

# zip 解压版 / 重建后: 接管为 git 工作树
if [ ! -d .git ] && command -v git >/dev/null 2>&1 && [ -f huntview.py ]; then
    echo "↻ 首次接管为 GitHub 同步版…"
    git init -q
    git checkout -q -b main 2>/dev/null || true
    if sync_gh >/dev/null 2>&1; then
        echo "✓ 已接入 GitHub 自动更新(v$(cat VERSION 2>/dev/null))"
    else
        echo "(接管失败, 本次按本地文件跑)"
    fi
fi

# 已有 git → 同步最新
if [ -d .git ] && command -v git >/dev/null 2>&1 && git rev-parse --verify HEAD >/dev/null 2>&1; then
    git remote get-url origin >/dev/null 2>&1 || git remote add origin "$ORIGIN"
    git remote set-url origin "$ORIGIN" >/dev/null 2>&1
    OLD=$(git rev-parse HEAD 2>/dev/null)
    V0=$(cat VERSION 2>/dev/null)
    if git fetch -q origin main 2>/dev/null && git merge --ff-only -q FETCH_HEAD 2>/dev/null; then
        NEW=$(git rev-parse HEAD 2>/dev/null)
        V1=$(cat VERSION 2>/dev/null)
        if [ "$OLD" != "$NEW" ]; then
            echo "⬆ 已从 GitHub 更新: ${V0:-?} → ${V1:-?}"
            git diff --name-only "$OLD" "$NEW" | grep -q '^start\.sh$' && \
                echo "⚠ 启动器自己也更新了, 建议退出重跑一次: bash start.sh"
        else
            echo "✓ 版本 ${V1:-?} (已是最新)"
        fi
    else
        echo "(同步失败/离线, 用当前版本 ${V0:-?} 继续)"
    fi
fi

need() { python3 -c "import Crypto, zstandard" 2>/dev/null; }

# 1) 依赖: 先试 apt, 不行退化 pip 用户级
if ! need; then
    echo "首次运行, 尝试 apt 安装依赖…"
    sudo apt-get update -qq && sudo apt-get install -y python3-pycryptodome python3-zstandard
fi
if ! need; then
    echo "apt 路线没成, 改用 pip 用户级安装…"
    pip3 install --user --break-system-packages pycryptodome zstandard 2>/dev/null \
        || pip3 install --user pycryptodome zstandard
fi
if ! need; then
    echo "❌ 依赖还是没装上。请把下面命令的完整报错发出来:"
    echo "   sudo apt-get install python3-pycryptodome python3-zstandard"
    echo "   或: pip3 install --user pycryptodome zstandard"
    exit 1
fi

# 2) 找游戏目录
GAME="$HOME/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common/Hunt Showdown 1896"
[ -d "$GAME" ] || GAME="$HOME/.steam/steam/steamapps/common/Hunt Showdown 1896"
[ -d "$GAME" ] || GAME="$HOME/.local/share/Steam/steamapps/common/Hunt Showdown 1896"
if [ ! -d "$GAME" ]; then
    echo "❌ 没找到游戏目录, 请手动:  bash start.sh \"/你的/Hunt Showdown 1896\""
    exit 1
fi

echo "游戏目录: $GAME"
echo "(默认跳过 地图光影包/本地化/着色器缓存 等浏览用不上的; 全量: HUNT_SKIP='' bash start.sh)"

# 可执行权限(zip 解压后可能丢)
chmod +x ww2ogg huntdd 2>/dev/null

python3 huntview.py "$GAME" "${1:-8796}"
