#!/usr/bin/env bash
# 生成 wist-gateway 运行所需的配置与密钥（宿主机 / 容器内通用，幂等）。
#
# 用法：
#   ./init-gateway.sh <target-dir>     # target-dir 默认 configs/gateway
#
# 可覆盖环境变量：
#   WIST_GATEWAY_BIN   wist-gateway 二进制（默认 PATH 里的 wist-gateway）
#   CERT_CN            自签证书 CN（默认 localhost）
#   CERT_DAYS          证书有效期天数（默认 365）
#
# 生成内容：
#   <target-dir>/wist-gateway.toml                                # 配置（含 admin token）
#   <target-dir>/state/install-script-signing-ed25519.pkcs8.pem   # 签名私钥（init-config 生成）
#   <target-dir>/state/admin-tls.crt.pem / admin-tls.key.pem      # TLS 自签证书/私钥
set -euo pipefail

TARGET_DIR="${1:-configs/gateway}"
WIST_GATEWAY_BIN="${WIST_GATEWAY_BIN:-wist-gateway}"
CERT_CN="${CERT_CN:-localhost}"
CERT_DAYS="${CERT_DAYS:-365}"

mkdir -p "${TARGET_DIR}"
TARGET_DIR="$(cd "${TARGET_DIR}" && pwd)"
CONFIG="${TARGET_DIR}/wist-gateway.toml"
STATE_DIR="${TARGET_DIR}/state"

if ! command -v "${WIST_GATEWAY_BIN}" >/dev/null 2>&1; then
  echo "wist-gateway 二进制不存在: ${WIST_GATEWAY_BIN}" >&2
  echo "请先构建（cargo build --release）或通过 WIST_GATEWAY_BIN 指定路径" >&2
  exit 1
fi

# 1. 配置 + 签名密钥（init-config 会重写 config，故仅在 config 不存在时执行）
admin_token=""
if [[ ! -f "${CONFIG}" ]]; then
  init_output="$("${WIST_GATEWAY_BIN}" init-config "${CONFIG}")"
  echo "${init_output}"
  admin_token="$(printf '%s\n' "${init_output}" | sed -n 's/^admin api token: //p')"
else
  echo "config 已存在，跳过生成: ${CONFIG}"
fi
mkdir -p "${STATE_DIR}"

# 2. TLS 自签证书/私钥（幂等）
if [[ ! -f "${STATE_DIR}/admin-tls.crt.pem" || ! -f "${STATE_DIR}/admin-tls.key.pem" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    echo "缺少 openssl，无法生成 TLS 证书" >&2
    exit 1
  fi
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${STATE_DIR}/admin-tls.key.pem" \
    -out "${STATE_DIR}/admin-tls.crt.pem" \
    -days "${CERT_DAYS}" -subj "/CN=${CERT_CN}" \
    -addext "subjectAltName=DNS:${CERT_CN},IP:127.0.0.1" >/dev/null 2>&1
  echo "已生成 TLS 证书/私钥: ${STATE_DIR}/admin-tls.{crt,key}.pem"
else
  echo "TLS 证书已存在，跳过生成: ${STATE_DIR}"
fi

echo
echo "初始化完成："
echo "  config : ${CONFIG}"
echo "  state  : ${STATE_DIR}"
if [[ -n "${admin_token}" ]]; then
  echo "  admin token: ${admin_token}"
fi
echo "  注意：容器运行时把 listen_addr 改为 0.0.0.0:3000，并配置 public_base_url / victoria_metrics_url / package_file"
