# ===========================================================================
# wist-gateway — Runtime Docker Image (Multi-arch)
#
# 采用「预编译二进制 + 最小运行时」的方式（与 warp-parse 一致）：
# 二进制由 release 流水线按架构交叉编译，build context 下按 amd64/ arm64/
# 分目录提供，Dockerfile 只负责打包成运行镜像。
#
# 配置 / TLS 证书 / 签名密钥 / store / agent 包均为环境相关，通过卷挂载，
# 不烘焙进镜像。启动时用 WIST_GATEWAY_CONFIG 指向配置文件（或放入工作目录）。
# ===========================================================================

FROM ubuntu:24.04

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-gateway"
LABEL org.opencontainers.image.description="Control-plane gateway for the wist agent fleet"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 运行时依赖：wist-gateway 使用 rustls（不依赖系统 openssl），仅保留根证书。
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false wist

# 预编译二进制（build context 按架构提供：amd64/wist-gateway、arm64/wist-gateway）
COPY ${TARGETARCH}/wist-gateway /usr/local/bin/wist-gateway

# 运行期目录：config / state（证书、签名密钥、store）由卷挂载到 /wist-gateway
RUN mkdir -p /wist-gateway/state && chown -R wist:wist /wist-gateway

USER wist
WORKDIR /wist-gateway

# HTTPS 控制面端口
EXPOSE 3000

ENTRYPOINT ["wist-gateway"]
CMD []
