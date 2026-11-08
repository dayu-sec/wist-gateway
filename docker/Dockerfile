# ===========================================================================
# wist-gateway — Runtime Docker Image (Multi-arch)
#
# 采用「预编译二进制 + 最小运行时」的方式（与 warp-parse 一致）：
# 二进制由 release 流水线按架构交叉编译，build context 下按 amd64/ arm64/
# 分目录提供，Dockerfile 只负责打包成运行镜像。
#
# 配置 / TLS 证书 / 签名密钥 / store / agent 包均为环境相关，通过卷挂载，
# 不烘焙进镜像。启动时用 `WIST_GATEWAY_CONFIG` 指向配置文件（或放入工作目录）。
#
# ⚠ **整个 Dockerfile 不许出现 `RUN`**：它会在目标架构下执行，`linux/arm64` 那一侧
#   只能靠 QEMU 模拟（一次 `apt-get` 就是几分钟，而且没有缓存，每发一个 tag 重付一次）。
#   需要执行的东西要么在 CI 上做完（二进制就是），要么挑自带依赖的基础镜像。
#
# 为什么是 distroless **cc**/debian13（而不是 base / debian12 / alpine）：
#   · 二进制是 **glibc 动态链接**（`-unknown-linux-gnu`），最高需要 `GLIBC_2.38`；
#     debian12 的 2.36 不够，alpine 是 musl 更不行，debian13 的 glibc 2.41 满足。
#   · **必须是 `cc` 而不是 `base`**：Rust 产物动态链接了 `libgcc_s.so.1`（panic 展开用），
#     `base` 变体不含它 —— 容器起来就是
#     `error while loading shared libraries: libgcc_s.so.1`（退出码 127，无限重启）。
#     实测 `cc` 只比 `base` 大 1.1 MB（压缩后 20.3 vs 19.2 MB），不值得为省这点去静态链接 libgcc。
#   · `cc` 自带 ca-certificates（走 rustls 只需要这一份根证书），因此不需要 apt/apk，
#     镜像里也一个 `RUN` 都不需要。
#   · 代价：**镜像里没有 shell**。gateway 的排障脚本（`show-wparse-state.sh` /
#     `diagnose-wparse-drift.sh`）都 `docker exec` 到 **wparse** 容器，不是这个镜像。
# ===========================================================================

FROM gcr.io/distroless/cc-debian13:nonroot

ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/dayu-sec/wist-gateway"
LABEL org.opencontainers.image.description="Control-plane gateway for the wist agent fleet"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# 预编译二进制（build context 按架构提供：amd64/wist-gateway、arm64/wist-gateway）
COPY --chown=999:999 ${TARGETARCH}/wist-gateway /usr/local/bin/wist-gateway

WORKDIR /wist-gateway

# 运行期以固定的 999 身份跑（与 wist-gateway-stack 的 compose `user: "999:999"` 同值）。
USER 999:999

# HTTPS 控制面端口
EXPOSE 3000

ENTRYPOINT ["wist-gateway"]
CMD []
