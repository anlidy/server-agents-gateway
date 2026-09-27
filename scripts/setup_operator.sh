#!/bin/bash
# 权限分级的一次性准备（可重复运行）：
#   1. 建普通用户 sag-operator（主组 sag-operators，无密码、nologin、不在任何特权组、无 sudoers 规则）
#   2. 把 SAG 自己（代码、data/、.env、systemd 单元）改成只有 root 能写，gateway.db 与 .env 为 root 600
# 用法：sudo bash scripts/setup_operator.sh [/opt/server-agents-gateway]
set -euo pipefail

ROOT="${1:-/opt/server-agents-gateway}"
USER_NAME="${GATEWAY_OPERATOR_USER:-sag-operator}"
GROUP_NAME="${GATEWAY_OPERATOR_GROUP:-sag-operators}"
HOME_DIR="/home/${USER_NAME}"
UNIT="/etc/systemd/system/server-agents-gateway.service"

if [ "$(id -u)" != 0 ]; then
    echo "需要 root：sudo bash $0" >&2
    exit 1
fi

# ---- 1. operator 用户
getent group "$GROUP_NAME" >/dev/null || groupadd --system "$GROUP_NAME"
if ! id "$USER_NAME" >/dev/null 2>&1; then
    useradd --system --gid "$GROUP_NAME" --create-home --home-dir "$HOME_DIR" \
        --shell /usr/sbin/nologin --comment "SAG operator agents" "$USER_NAME"
fi
usermod -L "$USER_NAME"                       # 锁密码，su 不进去
chown "$USER_NAME:$GROUP_NAME" "$HOME_DIR"
chmod 700 "$HOME_DIR"
for g in sudo admin wheel adm docker lxd systemd-journal disk shadow; do
    if id -nG "$USER_NAME" | tr ' ' '\n' | grep -qx "$g"; then
        gpasswd -d "$USER_NAME" "$g" >/dev/null
    fi
done
if [ "$(id -u "$USER_NAME")" = 0 ]; then
    echo "错误：$USER_NAME 的 uid 是 0" >&2
    exit 1
fi
if sudo -l -U "$USER_NAME" 2>/dev/null | grep -q "may run the following"; then
    echo "错误：sudoers 里有 $USER_NAME 能用的规则，请先删掉：" >&2
    sudo -l -U "$USER_NAME" >&2
    exit 1
fi

# ---- 2. SAG 自身只让 root 写
chown -R root:root "$ROOT"
chmod -R go-w "$ROOT"
chmod 700 "$ROOT/data"
[ -f "$ROOT/.env" ] && chmod 600 "$ROOT/.env"
find "$ROOT/data" -maxdepth 1 -type f -exec chmod 600 {} +
if [ -f "$UNIT" ]; then
    chown root:root "$UNIT"
    chmod 644 "$UNIT"
fi

echo "operator：$(id "$USER_NAME")"
echo "SAG 目录：$(stat -c '%U:%G %a' "$ROOT")  data：$(stat -c '%U:%G %a' "$ROOT/data")"
[ -f "$ROOT/data/gateway.db" ] && echo "gateway.db：$(stat -c '%U:%G %a' "$ROOT/data/gateway.db")"
[ -f "$ROOT/.env" ] && echo ".env：$(stat -c '%U:%G %a' "$ROOT/.env")"
echo "完成。"
