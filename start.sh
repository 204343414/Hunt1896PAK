#!/bin/bash
# ═══ 猎杀对决 · 资产浏览器 一键启动 (v1.4) ═══
# 只读浏览, 绝不动游戏文件。
cd "$(dirname "$0")"

# 0) 如果这份是 git 克隆来的 → 运行前同步 GitHub 最新版(版本不同就整包覆盖)
if [ -d .git ] && command -v git >/dev/null 2>&1; then
    K="$PWD/id_huntview"
    [ -f "$K" ] && chmod 600 "$K" 2>/dev/null
    export GIT_SSH_COMMAND="ssh -i \"$K\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    git remote get-url origin 2>/dev/null | grep -q git@ || \
        git remote set-url origin git@github.com:204343414/Hunt1896PAK.git 2>/dev/null
    OLD=$(git rev-parse HEAD 2>/dev/null)
    V0=$(cat VERSION 2>/dev/null)
    if git pull --ff-only -q origin main 2>/dev/null; then
        NEW=$(git rev-parse HEAD 2>/dev/null)
        V1=$(cat VERSION 2>/dev/null)
        if [ "$OLD" != "$NEW" ]; then
            echo "⬆ 已从 GitHub 更新: ${V0:-?} → ${V1:-?}"
            git -C . diff --name-only "$OLD" "$NEW" | grep -q '^start\.sh$' && \
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
