#!/bin/sh
# wist-approve 安装脚本（由网关按平台渲染）。
#
# 三条与 agent 安装脚本同源的口径：
#   1. 下载走 `-k`（管理面是自签 CA，新机器还不信任它），**完整性由内嵌 sha256 保证** ——
#      TLS 在这里只当传输层；
#   2. 装到**用户目录**（`$HOME/bin`）—— 与 `gx` 的 `_pub_local` 同一约定（`~/bin` 通常已在 PATH 上）；
#      要装系统级就 `WIST_PREFIX=/usr/local`（= `/usr/local/bin`）；
#      `WIST_BIN_DIR` 可直指任意目录。不需要 sudo。
#      私钥 / token / 网关 CA 仍在 `$HOME/.wist`（`WIST_CONF_DIR` 可改）。
#   3. 顺手放好网关 CA（0644）并打印下一步，不替用户生成私钥 —— 私钥必须在审批人自己的机器上生成。
set -eu

PLATFORM="{{PLATFORM}}"
PACKAGE_URL="{{PACKAGE_URL}}"
PACKAGE_SHA256="{{PACKAGE_SHA256}}"
# 二进制放 `$HOME/bin`：与 `gx` 的 `_pub_local` 同一约定，而且 `~/bin` 通常**已经在 PATH 上**
# —— 早先默认装 `$HOME/.wist/bin`，装完直接 `wist-approve` 就 command not found。
# `WIST_PREFIX=/usr/local` 保留为旧用法（= `/usr/local/bin`）。
# 私钥 / token / 网关 CA 仍放 `$HOME/.wist`（CLI 的默认 token 路径就在那里）。
if [ -n "${WIST_BIN_DIR:-}" ]; then
  BIN_DIR="$WIST_BIN_DIR"
elif [ -n "${WIST_PREFIX:-}" ]; then
  BIN_DIR="$WIST_PREFIX/bin"
else
  BIN_DIR="$HOME/bin"
fi
CONF_DIR="${WIST_CONF_DIR:-$HOME/.wist}"

note() { printf '  %s\n' "$*"; }

# 平台对不上就别装（装上了也是跑不起来的一坨）。
#
# 三个 triple 必须与网关分发白名单完全一致（`src/api/install_package.rs` 的 PLATFORM_*
# 常量，审批分发面复用它）：白名单外的 triple 在路由层就被挡成 404，走不到这里。
# Linux 制品是静态 musl，所以这里按机器架构判定，不看发行版/glibc 版本。
OS_NAME="$(uname -s)"
HOST_ARCH="$(uname -m)"
case "$PLATFORM" in
  x86_64-unknown-linux-musl) EXPECT="Linux:x86_64" ;;
  aarch64-unknown-linux-musl) EXPECT="Linux:aarch64" ;;
  aarch64-apple-darwin) EXPECT="Darwin:arm64" ;;
  *) echo "不认识的平台 ${PLATFORM}：已中止，未做任何改动。" >&2; exit 1 ;;
esac
if [ "${OS_NAME}:${HOST_ARCH}" != "$EXPECT" ]; then
  printf '%s\n' "这份安装命令是给 ${PLATFORM} 的，但本机是 ${OS_NAME} ${HOST_ARCH} —— 已中止，未做任何改动。" >&2
  exit 1
fi

# 摘要工具：两个平台底线内各有一个（与 agent 安装脚本保持一致）。
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else echo "缺少 sha256sum / shasum：无法校验安装包，已中止" >&2; exit 1; fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "==> 下载 wist-approve（${PLATFORM}）"
if ! curl -fsSLk "$PACKAGE_URL" -o "$TMP_DIR/wist-approve"; then
  echo "下载失败：${PACKAGE_URL}" >&2
  exit 1
fi

echo "==> 校验摘要"
ACTUAL="$(sha256_of "$TMP_DIR/wist-approve")"
if [ "$ACTUAL" != "$PACKAGE_SHA256" ]; then
  echo "摘要不匹配：期望 ${PACKAGE_SHA256}，实际 ${ACTUAL} —— 已中止，未安装" >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$CONF_DIR"
cp "$TMP_DIR/wist-approve" "$BIN_DIR/wist-approve"
chmod 0755 "$BIN_DIR/wist-approve"

# 网关 CA（公开信息）：CLI 用 `--ca-file` 校验管理面 TLS。
cat > "$CONF_DIR/gateway-ca.crt.pem" <<'CA_EOF'
{{TRUST_BUNDLE}}
CA_EOF
chmod 0644 "$CONF_DIR/gateway-ca.crt.pem"

# 旧版装到 `$HOME/.wist/bin`；留着这份陈旧副本只会让 `which` 指到旧二进制。
STALE="$HOME/.wist/bin/wist-approve"
if [ "$STALE" != "$BIN_DIR/wist-approve" ] && [ -f "$STALE" ]; then
  note "注意：$STALE 是旧版装的位置，可以删掉（现在用 $BIN_DIR/wist-approve）"
fi

echo
echo "已安装：$BIN_DIR/wist-approve"
echo "网关 CA：$CONF_DIR/gateway-ca.crt.pem"
echo
echo "下一步（三步都在审批人自己的机器上）："
case ":${PATH}:" in
  *":${BIN_DIR}:"*) note "1) $BIN_DIR 已在 PATH 上，直接敲 wist-approve 即可" ;;
  *) note "1) 把 $BIN_DIR 加进 PATH：export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
note "2) 生成审批钥匙（私钥只留在这台机器）：wist-approve key generate --out $CONF_DIR/approver.key"
note "3) 打印 key_id 与指纹，交给管理员登记到网关：wist-approve key show --key $CONF_DIR/approver.key"
echo
echo "调用示例："
note "wist-approve --gateway {{BASE_URL}} --ca-file $CONF_DIR/gateway-ca.crt.pem \\"
note "             --token-file <approver token 文件> list"
echo
echo "注意：这份安装包是公开的，**不含任何凭据**。审批用的 token 必须由管理员单独签发。"
