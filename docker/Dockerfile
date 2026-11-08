# ===========================================================================
# wist-gateway — Runtime Docker Image (Multi-arch)
#
# 采用「预编译二进制 + 最小运行时」的方式（与 warp-parse 一致）：
# 二进制由 release 流水线按架构交叉编译，build context 下按 amd64/ arm64/
# 分目录提供，Dockerfile 只负责打包成运行镜像。
#
# 配置 / TLS 证书 / 签名密钥 / store / agent 包均为环境相关，通过卷挂载，
# 不烘焙进镜像。启动时用 WIST_GATEWAY_CONFIG 指向配置文件（或放入工作目录）。
#
# ⚠ **最终阶段不许出现 `RUN`**：它会在目标架构下执行，`linux/arm64` 那一侧
#   只能靠 QEMU 模拟（一次 `apt-get` 就是几分钟）。需要执行的东西全部放到
#   `--platform=$BUILDPLATFORM` 的阶段里，在 runner 原生架构上跑一次，再 COPY 过来。
# ===========================================================================

# 根证书：网关走 rustls（不依赖系统 openssl），只需要一份 Mozilla CA bundle。
# 用 alpine 的 apk 取（原生架构，几秒），比在 ubuntu 里 apt-get 快两个数量级。
# 路径与 Debian/Ubuntu 的 `ca-certificates` 一致，rustls-native-certs 照常读。
FROM --platform=$BUILDPLATFORM alpine:3 AS cacerts
RUN apk add --no-cache ca-certificates

FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-gateway"
LABEL org.opencontainers.image.description="Control-plane gateway for the wist agent fleet"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=cacerts /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# 预编译二进制（build context 按架构提供：amd64/wist-gateway、arm64/wist-gateway）
COPY --chown=999:999 ${TARGETARCH}/wist-gateway /usr/local/bin/wist-gateway

WORKDIR /wist-gateway

# 运行期以固定的 999 身份跑（与 wist-gateway-stack 的 compose `user: "999:999"` 同值）。
# 以前这里的 `useradd -r -s /bin/false wist` 建的是另一个 uid，compose 一覆盖就没人用；
# 现在直接用数值 uid，镜像与栈一致，也不需要那一层 apt。
USER 999:999

# HTTPS 控制面端口
EXPOSE 3000

ENTRYPOINT ["wist-gateway"]
CMD []
