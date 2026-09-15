#!/usr/bin/env bash
# bootstrap 镜像入口：首次启动缺 config 时自动初始化，再拉起 wist-gateway。
set -euo pipefail

CONFIG="${WIST_GATEWAY_CONFIG:-/wist-gateway/wist-gateway.toml}"
INIT_SCRIPT="/usr/local/bin/init-gateway.sh"

if [[ ! -f "${CONFIG}" ]]; then
  echo "config 缺失（${CONFIG}），执行首次初始化..."
  "${INIT_SCRIPT}" "$(dirname "${CONFIG}")"
  # 容器内必须监听 0.0.0.0，否则端口映射不进来
  sed -i 's|^listen_addr = .*|listen_addr = "0.0.0.0:3000"|' "${CONFIG}"
fi

exec wist-gateway "$@"
